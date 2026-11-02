//! A fail-closed `mod_rewrite` implementation.
//!
//! Supported: server and per-directory rules, `RewriteBase`,
//! `RewriteOptions Inherit`, regex/comparison/file-test conditions,
//! `RewriteCond expr`, `RewriteMap` (`txt`, `rnd`, `prg`, `int`), and the
//! common rule flags including `[L]`, `[END]`, `[R]`, `[P]`, `[F]`, `[G]`,
//! `[C]`, `[S]`, `[N]`, `[QSA]`, `[QSD]`, `[QSL]`, `[B]`, `[BNE]`, `[BCTLS]`,
//! `[BNP]`, `[CO]`, `[E]`, `[H]`, `[T]`, `[NE]`, `[PT]`,
//! `[UnsafeAllow3F]`, and `[UnsafePrefixStat]`.  Unsupported syntax is
//! rejected while parsing the configuration rather than silently skipped;
//! `[DPI]` and `[NS]` are rejected until their path-info and internal-
//! subrequest semantics are implemented.
//!
//! Round semantics (F67/F68): a `[PT]` substitution stays in URL space and is
//! re-resolved by the dispatcher on the next round instead of being promoted
//! to a filesystem target, an absolute non-`[PT]` substitution only becomes a
//! filesystem target when the producing rule reaches the target construction,
//! and each successful rule replaces (rather than merely optionally sets) the
//! round's filesystem override — only the final target is ever applied.
//! `[UnsafePrefixStat]` remains parsed and deliberately inert (the F32
//! remediation), with a load-time warning in the main config.

use crate::config::{
    RequestEnvironment, RewriteCond, RewriteMap, RewriteProgram, RewriteRule, Scope,
};
use crate::http::Request;
use crate::scope_policy::Originated;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const PRG_MAP_TIMEOUT: Duration = Duration::from_secs(2);
const PRG_MAP_MAX_OUTPUT: usize = 8 * 1024;
/// Eight program lookups consume the complete per-request policy-work budget.
/// Spawning a process is orders of magnitude more expensive than a byte or
/// matcher cell and must not be represented as constant-cost string lookup.
const PRG_MAP_WORK_COST: u64 = 2 * 1024 * 1024;
const MAX_CONCURRENT_PRG_MAPS: usize = 8;
const MAX_PRG_MAPS_PER_SECOND: usize = 64;
static ACTIVE_PRG_MAPS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_PRG_MAP_CLIENTS: OnceLock<Mutex<HashMap<std::net::IpAddr, usize>>> = OnceLock::new();
static PRG_MAP_RATE: OnceLock<Mutex<PrgMapRate>> = OnceLock::new();
const MAX_REWRITE_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Default)]
struct PrgMapRate {
    window_started: Option<Instant>,
    used: usize,
    clients: HashMap<std::net::IpAddr, usize>,
}

impl PrgMapRate {
    fn admit_at(&mut self, client: Option<std::net::IpAddr>, now: Instant) -> bool {
        if self
            .window_started
            .is_none_or(|start| now.saturating_duration_since(start) >= Duration::from_secs(1))
        {
            self.window_started = Some(now);
            self.used = 0;
            self.clients.clear();
        }
        let client_used = client
            .and_then(|client| self.clients.get(&client).copied())
            .unwrap_or(0);
        if !vapache_verified::connection_admit(self.used as u64, MAX_PRG_MAPS_PER_SECOND as u64) {
            return false;
        }
        if client.is_some()
            && !vapache_verified::connection_admit(
                client_used as u64,
                (MAX_PRG_MAPS_PER_SECOND / 4) as u64,
            )
        {
            return false;
        }
        self.used += 1;
        if let Some(client) = client {
            self.clients.insert(client, client_used + 1);
        }
        true
    }
}

struct PrgMapLease {
    client: Option<std::net::IpAddr>,
}

impl Drop for PrgMapLease {
    fn drop(&mut self) {
        ACTIVE_PRG_MAPS.fetch_sub(1, Ordering::AcqRel);
        if let Some(client) = self.client {
            let mut clients = ACTIVE_PRG_MAP_CLIENTS
                .get_or_init(|| Mutex::new(HashMap::new()))
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(count) = clients.get_mut(&client) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    clients.remove(&client);
                }
            }
        }
    }
}

fn try_prg_map() -> Option<PrgMapLease> {
    let client = crate::resource::current_expensive_client();
    let mut active = ACTIVE_PRG_MAPS.load(Ordering::Acquire);
    loop {
        if !vapache_verified::connection_admit(active as u64, MAX_CONCURRENT_PRG_MAPS as u64) {
            return None;
        }
        match ACTIVE_PRG_MAPS.compare_exchange_weak(
            active,
            active.saturating_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(observed) => active = observed,
        }
    }
    if let Some(client) = client {
        let mut clients = ACTIVE_PRG_MAP_CLIENTS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let count = clients.entry(client).or_default();
        if !vapache_verified::connection_admit(*count as u64, (MAX_CONCURRENT_PRG_MAPS / 4) as u64)
        {
            ACTIVE_PRG_MAPS.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        *count += 1;
    }
    let lease = PrgMapLease { client };
    let admitted = PRG_MAP_RATE
        .get_or_init(|| Mutex::new(PrgMapRate::default()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .admit_at(client, Instant::now());
    admitted.then_some(lease)
}

fn append_rewrite_output(out: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    if !vapache_verified::bounded_expansion_append_admit(
        out.len() as u64,
        value.len() as u64,
        MAX_REWRITE_OUTPUT_BYTES as u64,
    ) {
        return Err("rewrite expansion exceeds 64 KiB".into());
    }
    out.extend_from_slice(value);
    Ok(())
}

pub struct Context<'a> {
    pub url_path: &'a str,
    pub fs_path: &'a Path,
    pub docroot: &'a Path,
    pub server_root: &'a Path,
    pub query: &'a [u8],
    pub peer: IpAddr,
    pub port: u16,
    pub https: bool,
    pub server_name: &'a str,
}

impl<'a> Context<'a> {
    /// Build the rewrite context from the same immutable plan dispatch used
    /// for mapping and access-file collection.
    pub fn for_plan(
        plan: &'a crate::request_plan::RequestPlan,
        server_root: &'a Path,
        query: &'a [u8],
        peer: IpAddr,
        port: u16,
        https: bool,
        server_name: &'a str,
    ) -> Self {
        Self {
            url_path: plan.url_path(),
            fs_path: plan.fs_path(),
            docroot: plan.root(),
            server_root,
            query,
            peer,
            port,
            https,
            server_name,
        }
    }
}

/// Side effects of the rewrite rules that matched during a pass.  These are
/// deliberately kept separate from the URL rewrite itself: the caller applies
/// them to the effective scope of the *final* target after all rewrite rounds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Effects {
    /// Server-scope `[E=NAME:VALUE]` / `[E=!NAME]`, visible before authz.
    pub env: Vec<(String, Option<Vec<u8>>)>,
    /// Directory/htaccess rewrite environment, produced in fixups after
    /// authorization. The origin tag survives merging and final sink
    /// filtering; `None` means unset.
    pub late_env: Vec<Originated<(String, Option<Vec<u8>>)>>,
    /// Fully constructed `Set-Cookie` header values from `[CO=...]`.
    pub cookies: Vec<String>,
    /// `[H=handler]`
    pub handler: Option<String>,
    /// `[T=content-type]`
    pub content_type: Option<String>,
    /// Request header names referenced by matching rewrite conditions, used
    /// to emit `Vary` without adding unrelated headers.
    pub vary: Vec<String>,
}

impl Effects {
    pub fn is_empty(&self) -> bool {
        self.env.is_empty()
            && self.late_env.is_empty()
            && self.cookies.is_empty()
            && self.handler.is_none()
            && self.content_type.is_none()
            && self.vary.is_empty()
    }

    pub fn merge(&mut self, other: Effects) {
        self.env.extend(other.env);
        self.late_env.extend(other.late_env);
        self.cookies.extend(other.cookies);
        if other.handler.is_some() {
            self.handler = other.handler;
        }
        if other.content_type.is_some() {
            self.content_type = other.content_type;
        }
        for name in other.vary {
            if !self.vary.iter().any(|v| v.eq_ignore_ascii_case(&name)) {
                self.vary.push(name);
            }
        }
    }
}

struct EscapeSpec {
    custom: Option<Vec<u8>>,
    controls: bool,
    preserve: Vec<u8>,
    no_plus: bool,
}

fn escape_spec(flags: &crate::config::RewriteFlags) -> Option<EscapeSpec> {
    if !flags.escape_backrefs {
        return None;
    }
    Some(EscapeSpec {
        custom: if flags.escape_chars.is_empty() {
            None
        } else {
            Some(flags.escape_chars.as_bytes().to_vec())
        },
        controls: flags.escape_controls,
        preserve: if flags.noescape_backrefs {
            if flags.noescape_chars.is_empty() {
                b"&".to_vec()
            } else {
                flags.noescape_chars.as_bytes().to_vec()
            }
        } else {
            Vec::new()
        },
        no_plus: flags.backref_no_plus,
    })
}

fn escape_backref_value(value: &[u8], spec: &EscapeSpec) -> Vec<u8> {
    // The [B]/[BNE]/[BCTLS]/[BNP] family all refine to the one verified
    // percent-encoding loop: build the escape mask from the flag set
    // (custom chars, control bytes, preserved chars) and encode.  A masked
    // space becomes `+` unless [BNP] set `no_plus`.
    let mut mask = [false; 256];
    for b in 0..=255u8 {
        let escaped = if spec.preserve.contains(&b) {
            false
        } else if let Some(custom) = &spec.custom {
            custom.contains(&b) || (spec.controls && (b <= b' ' || b == 0x7f))
        } else if spec.controls {
            b <= b' ' || b == 0x7f
        } else {
            !b.is_ascii_alphanumeric()
        };
        mask[b as usize] = escaped;
    }
    vapache_verified::percent_encode(value, &mask, !spec.no_plus)
}

/// Build an Apache-shaped `Set-Cookie` value for `[CO=name:value:domain:
/// lifetime:path:secure:httponly:samesite]`.  The caller has already expanded
/// backreferences in the raw flag text.
///
/// The colon-split field layout follows Apache, but the fields are validated
/// so a capture can never inject further attributes: the name must be an RFC
/// 6265 `token`, value and Domain/Path text must stay within the cookie-octet
/// visible set (attribute separators `;`, `,` and `"` excluded), and the
/// `secure`/`httponly`/`samesite` slots accept exactly their documented
/// tokens.
fn build_cookie(raw: &str) -> Result<String, String> {
    let fields: Vec<&str> = if let Some(rest) = raw.strip_prefix(';') {
        rest.split(';').collect()
    } else {
        raw.splitn(8, ':').collect()
    };
    let name = fields.first().copied().unwrap_or("").trim();
    if name.is_empty() {
        return Err("RewriteRule [CO] cookie has an empty name".into());
    }
    if !is_cookie_name(name) {
        return Err(format!(
            "invalid RewriteRule [CO] cookie name '{name}' (must be an RFC 6265 token)"
        ));
    }
    let value = fields.get(1).copied().unwrap_or("");
    if !is_cookie_value(value) {
        return Err(format!(
            "invalid RewriteRule [CO] cookie value '{value}' (cookie-octets only)"
        ));
    }
    let mut out = format!("{name}={value}");
    if let Some(domain) = fields.get(2).map(|v| v.trim()).filter(|v| !v.is_empty()) {
        if !is_cookie_value(domain) {
            return Err(format!(
                "invalid RewriteRule [CO] domain '{domain}' (cookie-octets only)"
            ));
        }
        out.push_str("; Domain=");
        out.push_str(domain);
    }
    if let Some(lifetime) = fields.get(3).map(|v| v.trim()).filter(|v| !v.is_empty()) {
        let minutes: i64 = lifetime
            .parse()
            .map_err(|_| format!("invalid RewriteRule [CO] lifetime '{lifetime}'"))?;
        if minutes > 0 {
            out.push_str("; Max-Age=");
            out.push_str(&(minutes.saturating_mul(60)).to_string());
        } else if minutes < 0 {
            out.push_str("; Max-Age=0");
        }
    }
    if let Some(path) = fields.get(4).map(|v| v.trim()).filter(|v| !v.is_empty()) {
        if !is_cookie_value(path) {
            return Err(format!(
                "invalid RewriteRule [CO] path '{path}' (cookie-octets only)"
            ));
        }
        out.push_str("; Path=");
        out.push_str(path);
    }
    if let Some(secure) = fields.get(5) {
        let secure = secure.trim();
        if !secure.is_empty() {
            if !matches!(
                secure.to_ascii_lowercase().as_str(),
                "secure" | "true" | "1"
            ) {
                return Err(format!(
                    "invalid RewriteRule [CO] secure flag '{secure}' (expected secure, true or 1)"
                ));
            }
            out.push_str("; Secure");
        }
    }
    if let Some(http_only) = fields.get(6) {
        let http_only = http_only.trim();
        if !http_only.is_empty() {
            if !matches!(
                http_only.to_ascii_lowercase().as_str(),
                "httponly" | "true" | "1"
            ) {
                return Err(format!(
                    "invalid RewriteRule [CO] httponly flag '{http_only}' (expected httponly, true or 1)"
                ));
            }
            out.push_str("; HttpOnly");
        }
    }
    if let Some(same_site) = fields.get(7).map(|v| v.trim()).filter(|v| !v.is_empty()) {
        if !matches!(
            same_site.to_ascii_lowercase().as_str(),
            "lax" | "strict" | "none"
        ) {
            return Err(format!(
                "invalid RewriteRule [CO] SameSite '{same_site}' (expected lax, strict or none)"
            ));
        }
        out.push_str("; SameSite=");
        out.push_str(same_site);
    }
    if out.chars().any(|c| c.is_control()) {
        // Every interpolated field is validated as a cookie octet or parsed as
        // an integer above; retain this final invariant check as defense in depth.
        return Err("control character in RewriteRule [CO] cookie".into()); // coverage:ignore-line
    }
    Ok(out)
}

/// RFC 6265 `token` for a cookie-name: 1*tchar (`;`, `,`, `=`, whitespace and
/// control bytes are separators and cannot appear).
fn is_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Lenient cookie-octet set for values and attribute text: visible ASCII plus
/// the space traditionally tolerated, but never the attribute separators
/// `;`, `,`, `"`, control bytes (or DEL), and no non-ASCII bytes.
fn is_cookie_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| (b == b' ' || b.is_ascii_graphic()) && !matches!(b, b';' | b',' | b'"'))
}

fn rule_effects(
    rule: &RewriteRule,
    caps: &[Vec<u8>],
    cond_caps: &[Vec<u8>],
    req: &Request,
    ctx: &Context<'_>,
    path: &str,
    query: &[u8],
    maps: &[(String, RewriteMap)],
    env: &[(String, Vec<u8>)],
) -> Result<Effects, String> {
    let mut effects = Effects::default();
    for (name, value) in &rule.flags.env {
        let name = expand_backrefs(
            name, caps, cond_caps, req, ctx, path, query, maps, env, true, None,
        )?;
        if name.is_empty() {
            return Err("RewriteRule [E] has an empty variable name".into());
        }
        let value = match value {
            Some(v) => Some(expand_backrefs_bytes(
                v, caps, cond_caps, req, ctx, path, query, maps, env, true, None,
            )?),
            None => None,
        };
        if rule.per_dir {
            effects.late_env.push(if rule.access_file {
                Originated::access((name, value))
            } else {
                Originated::main((name, value))
            });
        } else {
            effects.env.push((name, value));
        }
    }
    for cookie in &rule.flags.cookies {
        let cookie = expand_backrefs(
            cookie, caps, cond_caps, req, ctx, path, query, maps, env, true, None,
        )?;
        effects.cookies.push(build_cookie(&cookie)?);
    }
    if let Some(handler) = &rule.flags.handler {
        effects.handler = Some(expand_backrefs(
            handler, caps, cond_caps, req, ctx, path, query, maps, env, true, None,
        )?);
    }
    if let Some(content_type) = &rule.flags.content_type {
        effects.content_type = Some(expand_backrefs(
            content_type,
            caps,
            cond_caps,
            req,
            ctx,
            path,
            query,
            maps,
            env,
            true,
            None,
        )?);
    }
    Ok(effects)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    None,
    Internal {
        path: String,
        query: Vec<u8>,
        /// `[END]` was used: the caller should not start another rewrite pass.
        final_pass: bool,
        effects: Effects,
        /// An absolute filesystem path selected by a prefix-stat rewrite.
        /// When present the caller serves this file instead of resolving the
        /// URL path under the document root.
        filesystem: Option<PathBuf>,
    },
    Redirect {
        status: u16,
        /// Either an absolute URL or an absolute path beginning with `/`.
        location: String,
        effects: Effects,
    },
    /// `[P]`: proxy the request to an absolute URL.
    Proxy {
        url: String,
        effects: Effects,
    },
    Forbidden,
    Gone,
    Error(String),
}

fn rewrite_no_match_index(chain_flags: &[bool], next_index: usize, rule: &RewriteRule) -> usize {
    match vapache_verified::rewrite_match_action(
        chain_flags,
        next_index,
        false,
        rule.flags.chain,
        rule.flags.forbidden,
        rule.flags.gone,
        rule.substitution == "-",
    ) {
        vapache_verified::RewriteMatchAction::Continue { index } => index,
        _ => unreachable!("an unmatched rewrite rule can only continue"), // coverage:ignore-line - proved by rewrite_unmatched_rule_has_no_terminal_effect
    }
}

pub fn process(scope: &Scope, req: &Request, ctx: &Context<'_>) -> Outcome {
    if scope.rewrite_policy.rewrite_engine != Some(true)
        || scope.rewrite_policy.rewrite_rules.is_empty()
    {
        return Outcome::None;
    }
    let mut path = ctx.url_path.to_string();
    let mut query = ctx.query.to_vec();
    let mut changed = false;
    let mut final_pass = false;
    let mut cond_caps: Vec<Vec<u8>> = Vec::new();
    let mut effects = Effects::default();
    let mut filesystem_override: Option<PathBuf> = None;
    let mut env: RequestEnvironment = scope.authorization_env(req, ctx.url_path, ctx.peer);
    if req.policy_budget_failed() {
        return Outcome::Error("request policy expansion limit exceeded".into());
    }
    let mut vary: Vec<String> = Vec::new();
    let mut idx = 0usize;
    let chain_flags: Vec<bool> = scope
        .rewrite_policy
        .rewrite_rules
        .iter()
        .map(|rule| rule.flags.chain)
        .collect();
    let mut loops = 0u64;

    while idx < scope.rewrite_policy.rewrite_rules.len() {
        let rule = &scope.rewrite_policy.rewrite_rules[idx];
        idx += 1;
        vary.clear();
        let subject = subject_for(rule, &path, ctx.fs_path);
        if !vapache_verified::htaccess_rewrite_subject_admit(
            rule.per_dir && rule.subject_dir.is_some(),
            subject.is_some(),
        ) {
            // An access-file layer whose filesystem subject cannot be derived
            // must not silently skip its rewrite deny rules (F58/I58).
            return Outcome::Error(
                "cannot derive per-directory rewrite subject for access layer".into(),
            );
        }
        let Some(subject) = subject else {
            idx = rewrite_no_match_index(&chain_flags, idx, rule);
            continue;
        };
        if req
            .charge_policy_work(
                (rule.pattern.as_str().len() as u64)
                    .saturating_add(subject.len() as u64)
                    .saturating_add(rule.conditions.len() as u64)
                    .saturating_add(1),
            )
            .is_err()
        {
            return Outcome::Error("request policy work limit exceeded".into());
        }
        let conds = match conditions_match(
            rule,
            req,
            ctx,
            &path,
            &query,
            &mut cond_caps,
            &scope.rewrite_policy.rewrite_maps,
            &env,
            &mut vary,
        ) {
            Ok(v) => v,
            Err(e) => return Outcome::Error(e),
        };
        if !conds {
            idx = rewrite_no_match_index(&chain_flags, idx, rule);
            continue;
        }
        let caps = rule.pattern.captures(subject.as_bytes());
        let cap_strings: Vec<Vec<u8>> = if rule.negated {
            if caps.is_some() {
                idx = rewrite_no_match_index(&chain_flags, idx, rule);
                continue;
            }
            Vec::new()
        } else {
            match caps {
                Some(c) => c
                    .iter()
                    .map(|m| m.map(|m| m.as_bytes().to_vec()).unwrap_or_default())
                    .collect(),
                None => {
                    idx = rewrite_no_match_index(&chain_flags, idx, rule);
                    continue;
                }
            }
        };

        for name in vary.drain(..) {
            if !effects.vary.iter().any(|v| v.eq_ignore_ascii_case(&name)) {
                effects.vary.push(name);
            }
        }
        match rule_effects(
            rule,
            &cap_strings,
            &cond_caps,
            req,
            ctx,
            &path,
            &query,
            &scope.rewrite_policy.rewrite_maps,
            &env,
        ) {
            Ok(e) => {
                for (name, value) in &e.env {
                    env.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
                    if let Some(value) = value {
                        env.push((name.clone(), value.clone()));
                    }
                }
                for entry in &e.late_env {
                    let (name, value) = &entry.value;
                    env.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
                    if let Some(value) = value {
                        env.push((name.clone(), value.clone()));
                    }
                }
                effects.merge(e);
            }
            Err(e) => return Outcome::Error(e),
        }

        match vapache_verified::rewrite_match_action(
            &chain_flags,
            idx,
            true,
            rule.flags.chain,
            rule.flags.forbidden,
            rule.flags.gone,
            rule.substitution == "-",
        ) {
            vapache_verified::RewriteMatchAction::Forbidden => return Outcome::Forbidden,
            vapache_verified::RewriteMatchAction::Gone => return Outcome::Gone,
            vapache_verified::RewriteMatchAction::NoSubstitution => {
                if rule.flags.qsd {
                    query.clear();
                }
                match vapache_verified::rewrite_advance(
                    idx,
                    chain_flags.len(),
                    rule.flags.skip.is_some(),
                    rule.flags.skip.unwrap_or(0),
                    rule.flags.next,
                    rule.flags.last,
                    rule.flags.end,
                    loops,
                    10,
                ) {
                    vapache_verified::RewriteAdvance::Continue { index } => idx = index,
                    vapache_verified::RewriteAdvance::Restart { completed } => {
                        loops = completed;
                        idx = 0;
                    }
                    vapache_verified::RewriteAdvance::Stop { final_pass: final_ } => {
                        final_pass = final_;
                        break;
                    }
                    vapache_verified::RewriteAdvance::RestartLimit => {
                        return Outcome::Error("rewrite [N] loop limit exceeded".into());
                    }
                }
                continue;
            }
            vapache_verified::RewriteMatchAction::Expand => {}
            vapache_verified::RewriteMatchAction::Continue { .. } => {
                // coverage:ignore-start - executable verified action is called with matched=true
                unreachable!("a matched rewrite rule cannot take the no-match transition")
                // coverage:ignore-stop
            }
        }

        let spec = escape_spec(&rule.flags);
        let expanded = match expand_backrefs(
            &rule.substitution,
            &cap_strings,
            &cond_caps,
            req,
            ctx,
            &path,
            &query,
            &scope.rewrite_policy.rewrite_maps,
            &env,
            rule.flags.unsafe_allow_3f,
            spec.as_ref(),
        ) {
            Ok(v) => v,
            Err(e) => return Outcome::Error(e),
        };
        if expanded.chars().any(|c| c.is_control()) {
            return Outcome::Error("control character in rewrite substitution".into());
        }
        let (mut new_path, new_query, has_target_query) = if rule.flags.qslast {
            match expanded.rsplit_once('?') {
                Some((path, query)) => (path.to_string(), query.to_string(), true),
                None => (expanded.clone(), String::new(), false),
            }
        } else {
            match expanded.split_once('?') {
                Some((path, query)) => (path.to_string(), query.to_string(), true),
                None => (expanded.clone(), String::new(), false),
            }
        };
        let mut new_query = new_query.into_bytes();
        if rule.flags.qslast {
            let encoded = vapache_verified::rewrite_backref_no_qmark(new_path.as_bytes());
            new_path = String::from_utf8_lossy(&encoded).into_owned();
        }
        if new_path.is_empty() {
            return Outcome::Error("empty rewrite substitution".into());
        }
        let mut external = is_external_url(&new_path);
        if external && rule.flags.redirect.is_none() && !rule.flags.proxy {
            if let Some(internal) = same_host_internal(ctx, req, &new_path) {
                new_path = internal;
                external = false;
            }
        }
        let joined = if external {
            new_path
        } else if new_path.starts_with('/') {
            new_path
        } else if rule.per_dir {
            format!("{}{}", rule.base, new_path)
        } else {
            format!("/{new_path}")
        };
        if joined.len() > MAX_REWRITE_OUTPUT_BYTES {
            return Outcome::Error("rewritten target exceeds 64 KiB".into());
        }
        match vapache_verified::rewrite_query_action(
            has_target_query,
            rule.flags.qsa,
            rule.flags.qsd,
            !query.is_empty(),
        ) {
            vapache_verified::RewriteQueryAction::Append => {
                if !new_query.is_empty() {
                    if new_query.len() >= MAX_REWRITE_OUTPUT_BYTES {
                        return Outcome::Error("rewritten query exceeds 64 KiB".into());
                    }
                    new_query.push(b'&');
                }
                if !vapache_verified::bounded_expansion_append_admit(
                    new_query.len() as u64,
                    query.len() as u64,
                    MAX_REWRITE_OUTPUT_BYTES as u64,
                ) {
                    return Outcome::Error("rewritten query exceeds 64 KiB".into());
                }
                new_query.extend_from_slice(&query);
            }
            vapache_verified::RewriteQueryAction::Preserve => {
                // Apache copies the original query string when the
                // substitution does not contain a replacement query string.
                if query.len() > MAX_REWRITE_OUTPUT_BYTES {
                    return Outcome::Error("rewritten query exceeds 64 KiB".into());
                }
                new_query = query.clone();
            }
            vapache_verified::RewriteQueryAction::Replace
            | vapache_verified::RewriteQueryAction::Discard => {}
        }
        if new_query.iter().any(|byte| byte.is_ascii_control())
            || std::str::from_utf8(&new_query)
                .is_ok_and(|query| query.chars().any(char::is_control))
        {
            return Outcome::Error("control character in rewrite query".into());
        }
        if new_query.len() > MAX_REWRITE_OUTPUT_BYTES {
            return Outcome::Error("rewritten query exceeds 64 KiB".into());
        }

        // A [PT] substitution maps back through URL space (it is re-resolved
        // by the dispatcher next round), so it must never be promoted to a
        // filesystem target (F67). The flag stays accepted and inert-legal.
        let absolute = Path::new(&joined).is_absolute();
        let filesystem = if vapache_verified::rewrite_filesystem_shape_admit(
            external,
            rule.flags.passthrough,
            absolute,
        ) {
            let candidate = fs::canonicalize(&joined).ok();
            let docroot = fs::canonicalize(ctx.docroot).ok();
            match (candidate, docroot) {
                (Some(candidate), Some(docroot)) => {
                    // `UnsafePrefixStat` may relax what the rule is allowed to
                    // stat, but it must never relax the base used to authorize
                    // and serve the result.  A rewrite names one file inside
                    // the current root, not a new root.
                    if vapache_verified::rewrite_filesystem_candidate_admit(
                        external,
                        rule.flags.passthrough,
                        absolute,
                        candidate.is_file(),
                        vapache_verified::path_under_base(
                            candidate.as_os_str().as_encoded_bytes(),
                            docroot.as_os_str().as_encoded_bytes(),
                        ),
                    ) {
                        Some(candidate)
                    } else {
                        None
                    }
                }
                _ => None,
            }
        } else {
            None
        };
        // Only the substitution this rule just produced may become a
        // filesystem target: assigning unconditionally drops any target an
        // earlier rule in this round selected (F68). Rules that match nothing
        // or rewrite to `-` `continue` before this point, so they cannot
        // clear an override either.
        filesystem_override = filesystem;

        match vapache_verified::rewrite_sink(
            rule.flags.proxy,
            external,
            rule.flags.redirect.is_some(),
        ) {
            vapache_verified::RewriteSink::Proxy => {
                let mut url = joined;
                if !new_query.is_empty() {
                    let Ok(new_query) = std::str::from_utf8(&new_query) else {
                        return Outcome::Error("non-UTF-8 query in proxy rewrite".into());
                    };
                    url.push(if url.contains('?') { '&' } else { '?' });
                    url.push_str(new_query);
                }
                return Outcome::Proxy { url, effects };
            }
            vapache_verified::RewriteSink::Redirect => {
                let status = rule.flags.redirect.unwrap_or(302);
                let mut location = joined;
                if !new_query.is_empty() {
                    let Ok(new_query) = std::str::from_utf8(&new_query) else {
                        return Outcome::Error("non-UTF-8 query in redirect rewrite".into());
                    };
                    location.push(if location.contains('?') { '&' } else { '?' });
                    location.push_str(new_query);
                }
                if !rule.flags.noescape {
                    location = escape_redirect_location(&location);
                }
                return Outcome::Redirect {
                    status,
                    location,
                    effects,
                };
            }
            vapache_verified::RewriteSink::Internal => {}
        }

        path = new_path_from_joined(&joined);
        query = new_query;
        changed = true;
        match vapache_verified::rewrite_advance(
            idx,
            chain_flags.len(),
            rule.flags.skip.is_some(),
            rule.flags.skip.unwrap_or(0),
            rule.flags.next,
            rule.flags.last,
            rule.flags.end,
            loops,
            10,
        ) {
            vapache_verified::RewriteAdvance::Continue { index } => idx = index,
            vapache_verified::RewriteAdvance::Restart { completed } => {
                loops = completed;
                idx = 0;
                continue;
            }
            vapache_verified::RewriteAdvance::Stop { final_pass: final_ } => {
                final_pass = final_;
                break;
            }
            vapache_verified::RewriteAdvance::RestartLimit => {
                return Outcome::Error("rewrite [N] loop limit exceeded".into());
            }
        }
    }

    if changed || query != ctx.query || !effects.is_empty() {
        Outcome::Internal {
            path,
            query,
            final_pass,
            effects,
            filesystem: filesystem_override,
        }
    } else {
        Outcome::None
    }
}

fn new_path_from_joined(joined: &str) -> String {
    // The caller re-canonicalizes this.  Keep a single leading slash and
    // preserve a meaningful trailing slash.
    let out = vapache_verified::rewrite_internal_path(joined.as_bytes());
    String::from_utf8_lossy(&out).into_owned()
}

fn subject_for<'a>(
    rule: &RewriteRule,
    path: &'a str,
    fs_path: &'a Path,
) -> Option<std::borrow::Cow<'a, str>> {
    if rule.per_dir {
        // Access-file layers carry the directory whose filesystem-relative
        // path is Apache's per-directory rewrite subject.  This remains
        // sound when the target is deeper than the URL mount or when the
        // layer is above the alias/document-root mapping root (F58/I58).
        if let Some(dir) = rule.subject_dir.as_deref() {
            return crate::request_plan::layer_subject(dir, fs_path, path)
                .map(std::borrow::Cow::Owned);
        }
        let rel = path.strip_prefix(&rule.match_base)?;
        Some(std::borrow::Cow::Borrowed(rel.trim_start_matches('/')))
    } else {
        Some(std::borrow::Cow::Borrowed(path))
    }
}

fn conditions_match(
    rule: &RewriteRule,
    req: &Request,
    ctx: &Context<'_>,
    path: &str,
    query: &[u8],
    cond_caps: &mut Vec<Vec<u8>>,
    maps: &[(String, RewriteMap)],
    env: &[(String, Vec<u8>)],
    vary: &mut Vec<String>,
) -> Result<bool, String> {
    if rule.conditions.is_empty() {
        return Ok(true);
    }
    // `[OR]` joins the current condition with the next one.  Groups of
    // OR-linked conditions are ANDed with the other groups, so evaluate each
    // group separately instead of folding left-to-right (which would make
    // `A, B[OR], C` mean `(A && B) || C`).
    let mut matches: Vec<bool> = Vec::with_capacity(rule.conditions.len());
    let mut ors: Vec<bool> = Vec::with_capacity(rule.conditions.len());
    let mut matched_headers: Vec<String> = Vec::new();
    for cond in &rule.conditions {
        if let Some(expr) = &cond.expr {
            // F63/I63: bind the filesystem path for `%{REQUEST_FILENAME}`/
            // `%{SCRIPT_FILENAME}`.  A per-directory layer binds the real
            // filesystem path of the request; a server-context rule runs
            // during URL translation, where the mapped path is the rewrite
            // subject itself.
            let mut ectx = crate::expr::Context::new(req, env, ctx.peer, ctx.docroot, path)
                .with_fs_path(if rule.per_dir {
                    Some(ctx.fs_path)
                } else {
                    Some(Path::new(path))
                });
            let r = expr
                .eval(&mut ectx)
                .map(|value| value.truthy())
                .map_err(|error| format!("RewriteCond expr failed closed: {error}"))?;
            matches.push(r);
            ors.push(cond.flags.or);
            continue;
        }
        let value = expand_vars_bytes(&cond.test, req, ctx, path, query, cond_caps, maps, env)?;
        req.charge_policy_work(
            (cond.pattern.len() as u64)
                .saturating_add(value.len() as u64)
                .saturating_add(1),
        )
        .map_err(str::to_string)?;
        let r = eval_cond(cond, &value, ctx, cond_caps)?;
        if r {
            if let Some(name) = condition_header(&cond.test) {
                if !name.eq_ignore_ascii_case("host")
                    && !matched_headers
                        .iter()
                        .any(|v| v.eq_ignore_ascii_case(&name))
                {
                    matched_headers.push(name);
                }
            }
        }
        matches.push(r);
        ors.push(cond.flags.or);
    }
    let overall = vapache_verified::cond_chain_eval(&matches, &ors);
    if overall {
        for name in matched_headers {
            if !vary.iter().any(|v| v.eq_ignore_ascii_case(&name)) {
                vary.push(name);
            }
        }
    }
    Ok(overall)
}

fn condition_header(test: &str) -> Option<String> {
    let mut rest = test;
    while let Some(start) = rest.find("%{HTTP") {
        let after = &rest[start + 2..];
        let end = after.find('}')?;
        let inner = &after[..end];
        let name = if let Some(name) = inner.strip_prefix("HTTP:") {
            name
        } else if let Some(name) = inner.strip_prefix("HTTP_") {
            name
        } else {
            rest = &after[end + 1..];
            continue;
        };
        if !name.is_empty() {
            let name = name.replace('_', "-");
            return Some(
                name.split('-')
                    .map(|part| {
                        let mut chars = part.chars();
                        match chars.next() {
                            Some(first) => {
                                first.to_ascii_uppercase().to_string()
                                    + &chars.as_str().to_ascii_lowercase()
                            }
                            None => String::new(),
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("-"),
            );
        }
        rest = &after[end + 1..];
    }
    None
}

fn eval_cond(
    cond: &RewriteCond,
    value: impl AsRef<[u8]>,
    ctx: &Context<'_>,
    cond_caps: &mut Vec<Vec<u8>>,
) -> Result<bool, String> {
    let value = value.as_ref();
    let (negated, pattern) = match cond.pattern.strip_prefix('!') {
        Some(p) => (true, p),
        None => (false, cond.pattern.as_str()),
    };
    let text_value = || {
        std::str::from_utf8(value)
            .map_err(|_| "non-UTF-8 RewriteCond input is only valid for regex matching".to_string())
    };
    let result = if let Some(rest) = pattern.strip_prefix("-f") {
        rest.is_empty() && file_test(text_value()?, ctx, |_, real| real.is_file())
    } else if let Some(rest) = pattern.strip_prefix("-d") {
        rest.is_empty() && file_test(text_value()?, ctx, |_, real| real.is_dir())
    } else if let Some(rest) = pattern.strip_prefix("-s") {
        rest.is_empty()
            && file_test(text_value()?, ctx, |_, real| {
                fs::metadata(real).map(|m| m.len() > 0).unwrap_or(false)
            })
    } else if let Some(rest) = pattern.strip_prefix("-l") {
        rest.is_empty()
            && file_test(text_value()?, ctx, |p, _| {
                fs::symlink_metadata(p)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
            })
    } else if let Some(rest) = pattern.strip_prefix(">=") {
        compare_cond(text_value()?, rest, cond.flags.nocase) != std::cmp::Ordering::Less
    } else if let Some(rest) = pattern.strip_prefix("<=") {
        compare_cond(text_value()?, rest, cond.flags.nocase) != std::cmp::Ordering::Greater
    } else if let Some(rest) = pattern.strip_prefix('>') {
        compare_cond(text_value()?, rest, cond.flags.nocase) == std::cmp::Ordering::Greater
    } else if let Some(rest) = pattern.strip_prefix('<') {
        compare_cond(text_value()?, rest, cond.flags.nocase) == std::cmp::Ordering::Less
    } else if let Some(rest) = pattern.strip_prefix('=') {
        let value = text_value()?;
        if cond.flags.nocase {
            value.eq_ignore_ascii_case(rest)
        } else {
            value == rest
        }
    } else if let Some(rest) = pattern.strip_prefix('!') {
        let value = text_value()?;
        if cond.flags.nocase {
            !value.eq_ignore_ascii_case(rest)
        } else {
            value != rest
        }
    } else {
        let re = cond
            .regex
            .as_ref()
            .ok_or_else(|| "internal error: RewriteCond regex was not compiled".to_string())?;
        let caps: Vec<Vec<u8>> = re
            .captures(value)
            .map(|c| {
                c.iter()
                    .map(|m| m.map(|m| m.as_bytes().to_vec()).unwrap_or_default())
                    .collect()
            })
            .unwrap_or_default();
        if caps.is_empty() {
            cond_caps.clear();
            false
        } else {
            *cond_caps = caps;
            true
        }
    };
    Ok(if negated { !result } else { result })
}

fn compare_cond(value: &str, expected: &str, nocase: bool) -> std::cmp::Ordering {
    if let (Ok(a), Ok(b)) = (value.parse::<i64>(), expected.parse::<i64>()) {
        return a.cmp(&b);
    }
    if nocase {
        value
            .to_ascii_lowercase()
            .cmp(&expected.to_ascii_lowercase())
    } else {
        value.cmp(expected)
    }
}

fn file_test(value: &str, ctx: &Context<'_>, test: impl Fn(&Path, &Path) -> bool) -> bool {
    let p = PathBuf::from(value);
    let p = if p.is_absolute() {
        p
    } else {
        ctx.docroot.join(p)
    };
    // A condition can be fed an attacker-controlled value such as
    // `%{REQUEST_URI}`.  Never let a file test probe paths outside this
    // request's document/alias root, and reject lexical traversal before
    // touching the filesystem.
    if !p.starts_with(ctx.docroot)
        || p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return false;
    }
    // Lexical containment is not enough: a symlink inside the document root
    // can point at an outside file and turn `-f`/`-d`/`-s` into a metadata
    // oracle.  Canonicalize both sides and reuse the verified component-aware
    // containment kernel (with its reflexivity/transitivity lemmas) before
    // the metadata test.  The test closure receives both spellings: `-l`
    // inspects the lexical link itself, while `-f`/`-d`/`-s` inspect the
    // canonicalized target so the probe cannot race back through a symlink.
    let Ok(root) = fs::canonicalize(ctx.docroot) else {
        return false;
    };
    let Ok(real) = fs::canonicalize(&p) else {
        return false;
    };
    if !vapache_verified::path_under_base(
        real.as_os_str().as_encoded_bytes(),
        root.as_os_str().as_encoded_bytes(),
    ) {
        return false;
    }
    test(&p, &real)
}

fn expand_vars_bytes(
    test: &str,
    req: &Request,
    ctx: &Context<'_>,
    path: &str,
    query: &[u8],
    cond_caps: &[Vec<u8>],
    maps: &[(String, RewriteMap)],
    env: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(test.len());
    let mut i = 0;
    let bytes = test.as_bytes();
    while i < bytes.len() {
        match vapache_verified::rewrite_expand_token(bytes, i) {
            vapache_verified::RewriteExpandToken::Variable => {
                if let Some(end) = test[i + 2..].find('}') {
                    let name = String::from_utf8(expand_caps_bytes(
                        &test[i + 2..i + 2 + end],
                        &[],
                        cond_caps,
                    )?)
                    .map_err(|_| "RewriteCond variable name is not valid UTF-8".to_string())?;
                    append_rewrite_output(
                        &mut out,
                        &variable_value_bytes(&name, req, ctx, path, query, maps, env)?,
                    )?;
                    i += 2 + end + 1;
                    continue;
                }
            }
            vapache_verified::RewriteExpandToken::ConditionCapture { index } => {
                if let Some(v) = cond_caps.get(index as usize) {
                    append_rewrite_output(&mut out, v)?;
                }
                i += 2;
                continue;
            }
            vapache_verified::RewriteExpandToken::Literal
            | vapache_verified::RewriteExpandToken::RuleCapture { .. } => {}
        }
        append_rewrite_output(&mut out, &bytes[i..i + 1])?;
        i += 1;
    }
    Ok(out)
}

#[cfg(test)]
fn expand_vars(
    test: &str,
    req: &Request,
    ctx: &Context<'_>,
    path: &str,
    query: &[u8],
    cond_caps: &[Vec<u8>],
    maps: &[(String, RewriteMap)],
    env: &[(String, Vec<u8>)],
) -> Result<String, String> {
    String::from_utf8(expand_vars_bytes(
        test, req, ctx, path, query, cond_caps, maps, env,
    )?)
    .map_err(|_| "expanded RewriteCond value is not valid UTF-8".to_string())
}

fn variable_value_bytes(
    name: &str,
    req: &Request,
    ctx: &Context<'_>,
    path: &str,
    query: &[u8],
    maps: &[(String, RewriteMap)],
    env: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, String> {
    if let Some(raw) = name.strip_prefix("ENV:") {
        return Ok(env
            .iter()
            .rev()
            .find(|(key, _)| key.eq_ignore_ascii_case(raw))
            .map(|(_, value)| value.clone())
            .unwrap_or_default());
    }
    if name == "QUERY_STRING" {
        return Ok(query.to_vec());
    }
    if name == "HTTP_HOST" {
        return Ok(req
            .header("host")
            .map(vapache_verified::guard_header_bytes)
            .unwrap_or_else(|| ctx.server_name.as_bytes().to_vec()));
    }
    if let Some(raw) = name.strip_prefix("HTTP_") {
        let header = raw.replace('_', "-").to_ascii_lowercase();
        return Ok(req
            .header(&header)
            .map(vapache_verified::guard_header_bytes)
            .unwrap_or_default());
    }
    if let Some(raw) = name.strip_prefix("HTTP:") {
        return Ok(req
            .header(&raw.to_ascii_lowercase())
            .map(vapache_verified::guard_header_bytes)
            .unwrap_or_default());
    }
    Ok(variable_value(name, req, ctx, path, query, maps, env)?.into_bytes())
}

/// Reverse lookup gives the child map precedence after merge appended child
/// entries to the parent list.
fn rewrite_map_lookup<'a>(maps: &'a [(String, RewriteMap)], name: &str) -> Option<&'a RewriteMap> {
    maps.iter()
        .rev()
        .find(|(map_name, _)| map_name == name)
        .map(|(_, map)| map)
}

fn map_value(map: Option<&RewriteMap>, key: &str) -> String {
    match map {
        Some(RewriteMap::Txt(m)) => m.get(key).cloned().unwrap_or_default(),
        Some(RewriteMap::Rnd(m)) => m
            .get(key)
            .and_then(|choices| {
                choices.get(key.bytes().map(|b| b as usize).sum::<usize>() % choices.len().max(1))
            })
            .cloned()
            .unwrap_or_default(),
        Some(RewriteMap::Prg(program)) => run_prg_map(program, key),
        Some(RewriteMap::Int(function)) => int_map(function, key),
        None => String::new(),
    }
}

fn variable_value(
    name: &str,
    req: &Request,
    ctx: &Context<'_>,
    path: &str,
    query: &[u8],
    maps: &[(String, RewriteMap)],
    env: &[(String, Vec<u8>)],
) -> Result<String, String> {
    Ok(match name {
        n if n.starts_with("ENV:") => String::from_utf8(
            env.iter()
                .rev()
                .find(|(k, _)| k.eq_ignore_ascii_case(&n[4..]))
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
        )
        .map_err(|_| format!("environment variable '{}' is not valid UTF-8", &n[4..]))?,
        // Apache's REQUEST_URI is the canonical URL path (r->uri).  The query
        // string is a separate variable and must never be appended here;
        // `path` is the dispatcher's decoded, normalized rewrite path (F57).
        "REQUEST_URI" => path.to_string(),
        "REQUEST_FILENAME" | "SCRIPT_FILENAME" => ctx.fs_path.to_string_lossy().into_owned(),
        "DOCUMENT_ROOT" => ctx.docroot.to_string_lossy().into_owned(),
        // Raw request-target bytes may fail UTF-8; fail closed instead of
        // conflating distinct byte strings through the replacement character.
        "QUERY_STRING" => String::from_utf8(query.to_vec())
            .map_err(|_| "QUERY_STRING is not valid UTF-8".to_string())?,
        "HTTP_HOST" => match req.header("host") {
            Some(value) => String::from_utf8(value.to_vec())
                .map_err(|_| "Host header is not valid UTF-8".to_string())?,
            None => ctx.server_name.to_string(),
        },
        "REMOTE_ADDR" => ctx.peer.to_string(),
        "SERVER_PORT" => ctx.port.to_string(),
        "HTTPS" => if ctx.https { "on" } else { "off" }.to_string(),
        "REQUEST_METHOD" => req.method.clone(),
        "SERVER_NAME" => ctx.server_name.to_string(),
        "REQUEST_SCHEME" => if ctx.https { "https" } else { "http" }.to_string(),
        "SERVER_PROTOCOL" => req.version.as_str().to_string(),
        n if n.starts_with("HTTP_") => {
            let header = n[5..].replace('_', "-").to_ascii_lowercase();
            String::from_utf8(req.header(&header).unwrap_or_default().to_vec())
                .map_err(|_| format!("header '{header}' is not valid UTF-8"))?
        }
        n if n.starts_with("HTTP:") => {
            let header = n[5..].to_ascii_lowercase();
            String::from_utf8(req.header(&header).unwrap_or_default().to_vec())
                .map_err(|_| format!("header '{header}' is not valid UTF-8"))?
        }
        n if n.contains(':')
            && rewrite_map_lookup(maps, n.split_once(':').unwrap().0).is_some() =>
        {
            let (map_name, key) = n.split_once(':').unwrap();
            let map = rewrite_map_lookup(maps, map_name);
            if matches!(map, Some(RewriteMap::Prg(_))) {
                req.charge_policy_work(PRG_MAP_WORK_COST)
                    .map_err(str::to_string)?;
            }
            map_value(map, key)
        }
        "THE_REQUEST" => format!(
            "{} {} {}",
            req.method,
            String::from_utf8(req.target.clone())
                .map_err(|_| "request target is not valid UTF-8".to_string())?,
            req.version.as_str()
        ),
        _ => return Err(format!("unsupported mod_rewrite variable '%{{{name}}}'")),
    })
}

fn int_map(function: &str, key: &str) -> String {
    match function {
        "tolower" => key.to_lowercase(),
        "toupper" => key.to_uppercase(),
        "escape" => {
            // The int:escape map refines to the same verified
            // percent-encoding loop as rewrite backreference escaping:
            // alphanumerics and `-._~/` stay raw, a space becomes `+`
            // (form-urlencoded), everything else is `%xx`.
            let mut mask = [false; 256];
            for b in 0..=255u8 {
                mask[b as usize] = !(b.is_ascii_alphanumeric() || b"-._~/".contains(&b));
            }
            let out = vapache_verified::percent_encode(key.as_bytes(), &mask, true);
            String::from_utf8_lossy(&out).into_owned()
        }
        "unescape" => {
            let bytes = key.as_bytes();
            let mut out = Vec::with_capacity(bytes.len());
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' && i + 2 < bytes.len() {
                    let hex = |b: u8| -> Option<u8> {
                        match b {
                            b'0'..=b'9' => Some(b - b'0'),
                            b'a'..=b'f' => Some(b - b'a' + 10),
                            b'A'..=b'F' => Some(b - b'A' + 10),
                            _ => None,
                        }
                    };
                    if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                        out.push(hi * 16 + lo);
                        i += 3;
                        continue;
                    }
                }
                if bytes[i] == b'+' {
                    out.push(b' ');
                } else {
                    out.push(bytes[i]);
                }
                i += 1;
            }
            String::from_utf8_lossy(&out).into_owned()
        }
        _ => String::new(),
    }
}

fn write_prg_key(stdin: &mut impl Write, key: &str) -> bool {
    stdin.write_all(key.as_bytes()).is_ok() && stdin.write_all(b"\n").is_ok()
}

fn run_prg_map(program: &RewriteProgram, key: &str) -> String {
    if !program.binding_intact() {
        return String::new();
    }
    // A prg lookup creates both a helper process and a stdout reader thread.
    // Give it a dedicated concurrency/rate boundary in addition to the shared
    // expensive-operation budget so fast helpers cannot become a fork storm.
    let Some(_prg) = try_prg_map() else {
        return String::new();
    };
    let Some(_expensive) = crate::resource::try_expensive() else {
        return String::new();
    };
    run_prg_map_timeout(program, key, PRG_MAP_TIMEOUT)
}

fn run_prg_map_timeout(program: &RewriteProgram, key: &str, timeout: Duration) -> String {
    if !program.binding_intact() {
        return String::new();
    }
    let exec_fd = program.file.as_raw_fd();
    let mut command = Command::new(format!("/proc/self/fd/{exec_fd}"));
    command
        .args(&program.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // A separate process group lets the timeout close stdout held by a
    // helper's descendants as well as terminating the direct child. Clear
    // CLOEXEC only in the forked child: script interpreters must be able to
    // reopen /proc/self/fd/N, while unrelated parent-side spawns must never
    // inherit the retained program descriptor.
    // coverage:ignore-start - runs in the forked child before coverage can flush
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(exec_fd, libc::F_GETFD);
            if flags < 0
                || libc::fcntl(exec_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                || libc::setpgid(0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // coverage:ignore-stop
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return String::new(), // coverage:ignore-line -- fork/exec kernel failure
    };
    let stdin = child.stdin.take();
    finish_prg_map(child, stdin, key, timeout)
}

fn finish_prg_map(
    mut child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    key: &str,
    timeout: Duration,
) -> String {
    let Some(mut stdin) = stdin else {
        return wait_prg_output(child, timeout);
    };
    if !write_prg_key(&mut stdin, key) {
        return abort_prg_map(child);
    }
    drop(stdin);
    wait_prg_output(child, timeout)
}

fn abort_prg_map(mut child: std::process::Child) -> String {
    let pid = child.id() as i32;
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
    String::new()
}

fn wait_prg_output(mut child: std::process::Child, timeout: Duration) -> String {
    let Some(stdout) = child.stdout.take() else {
        return abort_prg_map(child);
    };
    let (tx, rx) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let _ = tx.send(read_prg_line(stdout));
    });
    let received = rx.recv_timeout(timeout);
    let completed_before_deadline = received.is_ok();
    let (line, complete) = received.unwrap_or_default();
    let admitted = vapache_verified::rewrite_map_result_admit(
        completed_before_deadline,
        complete,
        line.len() as u64,
        PRG_MAP_MAX_OUTPUT as u64,
    );
    let running = child.try_wait().ok().flatten().is_none();
    if running {
        let pid = child.id() as i32;
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        let _ = child.kill();
    }
    let status = child.wait().ok();
    let _ = reader.join();
    if !admitted || (status.is_some_and(|status| !status.success()) && !running) {
        return String::new();
    }
    String::from_utf8_lossy(&line)
        .trim_end_matches('\r')
        .to_string()
}

fn read_prg_line(mut input: impl Read) -> (Vec<u8>, bool) {
    let mut line = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    let mut complete = false;
    while line.len() <= PRG_MAP_MAX_OUTPUT {
        match input.read(&mut byte) {
            Ok(0) => {
                complete = true;
                break;
            }
            Ok(_) if byte[0] == b'\n' => {
                complete = true;
                break;
            }
            Ok(_) => line.push(byte[0]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    (line, complete)
}

fn expand_caps_bytes(
    name: &str,
    caps: &[Vec<u8>],
    cond_caps: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let b = name.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let token = vapache_verified::rewrite_expand_token(b, i);
        if let vapache_verified::RewriteExpandToken::RuleCapture { index }
        | vapache_verified::RewriteExpandToken::ConditionCapture { index } = token
        {
            let pool = if matches!(
                token,
                vapache_verified::RewriteExpandToken::ConditionCapture { .. }
            ) {
                cond_caps
            } else {
                caps
            };
            if let Some(v) = pool.get(index as usize) {
                append_rewrite_output(&mut out, v)?;
            }
            i += 2;
        } else {
            append_rewrite_output(&mut out, &b[i..i + 1])?;
            i += 1;
        }
    }
    Ok(out)
}

fn expand_backrefs_bytes(
    s: &str,
    caps: &[Vec<u8>],
    cond_caps: &[Vec<u8>],
    req: &Request,
    ctx: &Context<'_>,
    path: &str,
    query: &[u8],
    maps: &[(String, RewriteMap)],
    env: &[(String, Vec<u8>)],
    allow_3f: bool,
    escape: Option<&EscapeSpec>,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match vapache_verified::rewrite_expand_token(bytes, i) {
            vapache_verified::RewriteExpandToken::Variable => {
                if let Some(end) = s[i + 2..].find('}') {
                    let name = String::from_utf8(expand_caps_bytes(
                        &s[i + 2..i + 2 + end],
                        caps,
                        cond_caps,
                    )?)
                    .map_err(|_| "rewrite variable name is not valid UTF-8".to_string())?;
                    let value = variable_value_bytes(&name, req, ctx, path, query, maps, env)?;
                    if let Some(spec) = escape {
                        append_rewrite_output(&mut out, &escape_backref_value(&value, spec))?;
                    } else if allow_3f {
                        append_rewrite_output(&mut out, &value)?;
                    } else {
                        append_rewrite_output(
                            &mut out,
                            &vapache_verified::rewrite_backref_no_qmark(&value),
                        )?;
                    }
                    i += 2 + end + 1;
                    continue;
                }
            }
            token @ (vapache_verified::RewriteExpandToken::RuleCapture { .. }
            | vapache_verified::RewriteExpandToken::ConditionCapture { .. }) => {
                let (index, pool) = match token {
                    vapache_verified::RewriteExpandToken::RuleCapture { index } => (index, caps),
                    vapache_verified::RewriteExpandToken::ConditionCapture { index } => {
                        (index, cond_caps)
                    }
                    _ => unreachable!(), // coverage:ignore-line - outer pattern admits only capture variants
                };
                if let Some(v) = pool.get(index as usize) {
                    if let Some(spec) = escape {
                        append_rewrite_output(&mut out, &escape_backref_value(v, spec))?;
                    } else if !allow_3f {
                        append_rewrite_output(
                            &mut out,
                            &vapache_verified::rewrite_backref_no_qmark(v),
                        )?;
                    } else {
                        append_rewrite_output(&mut out, v)?;
                    }
                }
                i += 2;
                continue;
            }
            vapache_verified::RewriteExpandToken::Literal => {}
        }
        append_rewrite_output(&mut out, &bytes[i..i + 1])?;
        i += 1;
    }
    Ok(out)
}

fn expand_backrefs(
    s: &str,
    caps: &[Vec<u8>],
    cond_caps: &[Vec<u8>],
    req: &Request,
    ctx: &Context<'_>,
    path: &str,
    query: &[u8],
    maps: &[(String, RewriteMap)],
    env: &[(String, Vec<u8>)],
    allow_3f: bool,
    escape: Option<&EscapeSpec>,
) -> Result<String, String> {
    String::from_utf8(expand_backrefs_bytes(
        s, caps, cond_caps, req, ctx, path, query, maps, env, allow_3f, escape,
    )?)
    .map_err(|_| "rewrite expansion is not valid UTF-8".to_string())
}

fn escape_redirect_location(value: &str) -> String {
    // Redirect Location values refine to the same verified percent-encoding
    // loop.  Besides the control/DEL/dangerous-visible set this also escapes
    // every non-ASCII byte: the old loop pushed such bytes as Latin-1 chars,
    // which re-encoded as mojibake UTF-8 in the Location header.
    let mut mask = [false; 256];
    for b in 0..=255u8 {
        mask[b as usize] = b <= b' '
            || b >= 0x7f
            || matches!(
                b,
                b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}'
            );
    }
    let out = vapache_verified::percent_encode(value.as_bytes(), &mask, false);
    String::from_utf8_lossy(&out).into_owned()
}

fn same_host_internal(ctx: &Context<'_>, req: &Request, url: &str) -> Option<String> {
    let (target_tls, rest) = if let Some(rest) = url.strip_prefix("//") {
        (ctx.https, rest)
    } else {
        let (scheme, rest) = url.split_once("://")?;
        if scheme.eq_ignore_ascii_case("http") {
            (false, rest)
        } else if scheme.eq_ignore_ascii_case("https") {
            (true, rest)
        } else {
            return None;
        }
    };
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    let host = req
        .header_str("host")
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}:{}", ctx.server_name, ctx.port));
    let target_default = if target_tls { 443 } else { 80 };
    let request_default = if ctx.https { 443 } else { 80 };
    let (target_host, target_port) =
        crate::util::parse_http_authority(authority.as_bytes(), target_default)?;
    let (request_host, request_port) =
        crate::util::parse_http_authority(host.as_bytes(), request_default)?;
    if vapache_verified::authority_endpoint_equal(
        target_host.as_bytes(),
        target_port,
        target_tls,
        request_host.as_bytes(),
        request_port,
        ctx.https,
    ) {
        Some(path)
    } else {
        None
    }
}

fn is_external_url(s: &str) -> bool {
    vapache_verified::rewrite_target_external(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{normalize_rewrite_base, parse_rewrite_cond, parse_rewrite_rule};

    fn req() -> Request {
        Request {
            method: "GET".into(),
            target: b"/old.html?x=1".to_vec(),
            raw_path: b"/old.html".to_vec(),
            query: b"x=1".to_vec(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn ctx<'a>(path: &'a str, fs: &'a Path, root: &'a Path) -> Context<'a> {
        Context {
            url_path: path,
            fs_path: fs,
            docroot: root,
            server_root: root,
            query: b"x=1",
            peer: "127.0.0.1".parse().unwrap(),
            port: 80,
            https: false,
            server_name: "localhost",
        }
    }

    #[test]
    fn rewrite_env_is_visible_to_later_conditions() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope
            .rewrite_policy
            .rewrite_maps
            .push(("lower".into(), RewriteMap::Int("tolower".into())));
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &[
                    "^/old$".into(),
                    "-".into(),
                    "[C,E=MAPTYPE:${lower:ABC}]".into(),
                ],
                "/",
                false,
            )
            .unwrap(),
        );
        let mut rule = parse_rewrite_rule(
            &["^/old$".into(), "/mapped".into(), "[L]".into()],
            "/",
            false,
        )
        .unwrap();
        rule.conditions
            .push(parse_rewrite_cond(&["%{ENV:MAPTYPE}".into(), "^abc$".into()]).unwrap());
        scope.rewrite_policy.rewrite_rules.push(rule);
        let r = req();
        let root = Path::new("/tmp");
        match process(&scope, &r, &ctx("/old", &root.join("old"), root)) {
            Outcome::Internal { path, effects, .. } => {
                assert_eq!(path, "/mapped");
                assert_eq!(effects.env[0].0, "MAPTYPE");
                assert_eq!(effects.env[0].1.as_deref(), Some(b"abc".as_slice()));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rewrite_condition_backrefs_preserve_raw_header_bytes() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        let mut rule =
            parse_rewrite_rule(&["^/old$".into(), "-".into(), "[F]".into()], "/", false).unwrap();
        rule.conditions
            .push(parse_rewrite_cond(&["%{HTTP:X-Test}".into(), "^(.)sqlmap$".into()]).unwrap());
        // This second condition only matches if %1 is the exact 0xff byte;
        // replacement-character or empty-string projections both fail it.
        rule.conditions
            .push(parse_rewrite_cond(&["%1".into(), "^.$".into()]).unwrap());
        scope.rewrite_policy.rewrite_rules.push(rule);

        let mut request = req();
        request.headers.insert("x-test", b"\xffsqlmap".to_vec());
        let root = Path::new("/tmp");
        assert!(matches!(
            process(&scope, &request, &ctx("/old", &root.join("old"), root)),
            Outcome::Forbidden
        ));
    }

    #[test]
    fn qslast_and_unsafe_3f_flags_work() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/x/(.*)$".into(), "/$1?".into(), "[R,QSA,QSL]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        let xdir = root.join("x");
        let mut c = ctx("/x/foo/?bar/", &xdir, root);
        c.query = b"preserve-me";
        match process(&scope, &r, &c) {
            Outcome::Redirect { location, .. } => {
                assert_eq!(location, "/foo/%3fbar/?preserve-me")
            }
            other => panic!("unexpected {other:?}"),
        }

        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/bad/(.*)$".into(), "/bad$1".into(), "[PT]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        let bad = root.join("bad");
        let mut bad_ctx = ctx("/bad/?theval", &bad, root);
        bad_ctx.query = b"";
        match process(&scope, &r, &bad_ctx) {
            Outcome::Internal { path, query, .. } => {
                assert_eq!(path, "/bad%3ftheval");
                assert!(query.is_empty());
            }
            other => panic!("unexpected {other:?}"),
        }

        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &[
                    "^/bad/(.*)$".into(),
                    "/bad$1".into(),
                    "[PT,UnsafeAllow3F]".into(),
                ],
                "/",
                false,
            )
            .unwrap(),
        );
        let mut bad_ctx = ctx("/bad/?theval", &bad, root);
        bad_ctx.query = b"";
        match process(&scope, &r, &bad_ctx) {
            Outcome::Internal { path, query, .. } => {
                assert_eq!(path, "/bad");
                assert_eq!(query, b"theval");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rewrite_condition_or_groups_are_folded_by_verified_chain() {
        assert!(vapache_verified::cond_chain_eval(
            &[true, false, true],
            &[false, true, false]
        ));
        assert!(!vapache_verified::cond_chain_eval(
            &[true, false, false],
            &[false, true, false]
        ));
        assert!(vapache_verified::cond_chain_eval(
            &[false, true, false],
            &[true, true, false]
        ));
        assert!(vapache_verified::cond_chain_eval(&[], &[]));
    }

    #[test]
    fn verified_rewrite_decisions_cover_flag_truth_tables() {
        use vapache_verified::{
            RewriteAdvance, RewriteExpandToken, RewriteMatchAction, RewriteQueryAction, RewriteSink,
        };

        for proxy in [false, true] {
            for external in [false, true] {
                for redirect in [false, true] {
                    let expected = if proxy {
                        RewriteSink::Proxy
                    } else if external || redirect {
                        RewriteSink::Redirect
                    } else {
                        RewriteSink::Internal
                    };
                    assert_eq!(
                        vapache_verified::rewrite_sink(proxy, external, redirect),
                        expected
                    );
                }
            }
        }

        for has_target_query in [false, true] {
            for append in [false, true] {
                for discard in [false, true] {
                    for original_present in [false, true] {
                        let expected = if has_target_query {
                            if append && !discard && original_present {
                                RewriteQueryAction::Append
                            } else {
                                RewriteQueryAction::Replace
                            }
                        } else if discard {
                            RewriteQueryAction::Discard
                        } else {
                            RewriteQueryAction::Preserve
                        };
                        assert_eq!(
                            vapache_verified::rewrite_query_action(
                                has_target_query,
                                append,
                                discard,
                                original_present,
                            ),
                            expected
                        );
                    }
                }
            }
        }

        for external in [false, true] {
            for passthrough in [false, true] {
                for absolute in [false, true] {
                    for is_file in [false, true] {
                        for under_base in [false, true] {
                            assert_eq!(
                                vapache_verified::rewrite_filesystem_candidate_admit(
                                    external,
                                    passthrough,
                                    absolute,
                                    is_file,
                                    under_base,
                                ),
                                !external && !passthrough && absolute && is_file && under_base
                            );
                        }
                    }
                }
            }
        }

        for completed in 0..=11 {
            assert_eq!(
                vapache_verified::rewrite_restart_admit(completed, 10),
                completed < 10
            );
        }

        let token_cases: &[(&[u8], RewriteExpandToken)] = &[
            (b"literal", RewriteExpandToken::Literal),
            (b"${name}", RewriteExpandToken::Variable),
            (b"%{name}", RewriteExpandToken::Variable),
            (b"$7", RewriteExpandToken::RuleCapture { index: 7 }),
            (b"\\2", RewriteExpandToken::RuleCapture { index: 2 }),
            (b"%4", RewriteExpandToken::ConditionCapture { index: 4 }),
        ];
        for (input, expected) in token_cases {
            assert_eq!(vapache_verified::rewrite_expand_token(input, 0), *expected);
            assert_eq!(
                vapache_verified::rewrite_template_static(input),
                *expected == RewriteExpandToken::Literal
            );
        }

        let chained = [false, true, false, false];
        assert_eq!(
            vapache_verified::rewrite_match_action(&chained, 1, false, true, true, true, true),
            RewriteMatchAction::Continue { index: 3 }
        );
        assert_eq!(
            vapache_verified::rewrite_match_action(&chained, 1, true, false, true, true, true),
            RewriteMatchAction::Forbidden
        );
        assert_eq!(
            vapache_verified::rewrite_match_action(&chained, 1, true, false, false, true, true),
            RewriteMatchAction::Gone
        );
        assert_eq!(
            vapache_verified::rewrite_match_action(&chained, 1, true, false, false, false, true),
            RewriteMatchAction::NoSubstitution
        );
        assert_eq!(
            vapache_verified::rewrite_match_action(&chained, 1, true, true, false, false, false),
            RewriteMatchAction::Expand
        );

        assert_eq!(
            vapache_verified::rewrite_advance(1, 4, true, 2, false, false, false, 0, 10),
            RewriteAdvance::Continue { index: 3 }
        );
        assert_eq!(
            vapache_verified::rewrite_advance(3, 4, true, usize::MAX, false, false, false, 0, 10),
            RewriteAdvance::Continue { index: 4 }
        );
        assert_eq!(
            vapache_verified::rewrite_advance(1, 4, true, 2, true, true, true, 3, 10),
            RewriteAdvance::Restart { completed: 4 }
        );
        assert_eq!(
            vapache_verified::rewrite_advance(1, 4, false, 0, true, false, false, 10, 10),
            RewriteAdvance::RestartLimit
        );
        assert_eq!(
            vapache_verified::rewrite_advance(1, 4, false, 0, false, true, true, 0, 10),
            RewriteAdvance::Stop { final_pass: true }
        );
    }

    #[test]
    fn rewrite_authority_comparison_handles_case_and_ports() {
        assert!(vapache_verified::rewrite_authority_equal(
            b"LOCALHOST:80",
            b"localhost:80"
        ));
        assert!(!vapache_verified::rewrite_authority_equal(
            b"localhost:80",
            b"localhost:443"
        ));
        assert!(!vapache_verified::rewrite_authority_equal(
            b"other.test:80",
            b"localhost:80"
        ));
        assert!(!vapache_verified::rewrite_authority_equal(
            b"[::1]:443",
            b"[::2]:443"
        ));
    }

    #[test]
    fn same_host_absolute_url_is_internal() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/old$".into(), "http://localhost/new".into(), "[L]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        match process(&scope, &r, &ctx("/old", &root.join("old"), root)) {
            Outcome::Internal { path, query, .. } => {
                assert_eq!(path, "/new");
                assert_eq!(query, b"x=1");
            }
            other => panic!("unexpected {other:?}"),
        }

        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &[
                    "^/old$".into(),
                    "http://other.test/new".into(),
                    "[L]".into(),
                ],
                "/",
                false,
            )
            .unwrap(),
        );
        assert!(matches!(
            process(&scope, &r, &ctx("/old", &root.join("old"), root)),
            Outcome::Redirect { status: 302, .. }
        ));
    }

    #[test]
    fn proxy_flag_produces_a_proxy_outcome() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &[
                    "^/old$".into(),
                    "http://127.0.0.1:9/new?x=1".into(),
                    "[P,L]".into(),
                ],
                "/",
                false,
            )
            .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        match process(&scope, &r, &ctx("/old", &root.join("old"), root)) {
            Outcome::Proxy { url, .. } => assert_eq!(url, "http://127.0.0.1:9/new?x=1"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn query_string_variable_fails_closed_on_invalid_utf8() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/q$".into(), "%{QUERY_STRING}".into(), "[L]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        let subject = root.join("q");
        let bad_query: &[u8] = b"\xff\xfe";
        let mut c = ctx("/q", &subject, root);
        c.query = bad_query;
        // Lossy decoding would silently rewrite every invalid query to the
        // same replacement string; the engine instead fails the request.
        assert!(matches!(
            process(&scope, &r, &c),
            Outcome::Error(ref e) if e.contains("not valid UTF-8")
        ));
    }

    #[test]
    fn qsa_keeps_substitution_query_first() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/old$".into(), "/new?foo=bar".into(), "[QSA,L]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        let old = root.join("old");
        let mut c = ctx("/old", &old, root);
        c.query = b"bloo=blar";
        match process(&scope, &r, &c) {
            Outcome::Internal { path, query, .. } => {
                assert_eq!(path, "/new");
                assert_eq!(query, b"foo=bar&bloo=blar");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn original_query_is_copied_by_default() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(&["^/old$".into(), "/new".into(), "[L]".into()], "/", false)
                .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        match process(&scope, &r, &ctx("/old", &root.join("old"), root)) {
            Outcome::Internal { path, query, .. } => {
                assert_eq!(path, "/new");
                assert_eq!(query, b"x=1");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn comparison_conditions_work() {
        let r = req();
        let root = Path::new("/tmp");
        for (query, expected) in [(&b"7"[..], Outcome::Gone), (&b"5"[..], Outcome::None)] {
            let mut scope = Scope::default();
            scope.rewrite_policy.rewrite_engine = Some(true);
            let mut rule =
                parse_rewrite_rule(&["^/old$".into(), "-".into(), "[G]".into()], "/", false)
                    .unwrap();
            rule.conditions
                .push(parse_rewrite_cond(&["%{QUERY_STRING}".into(), ">6".into()]).unwrap());
            scope.rewrite_policy.rewrite_rules.push(rule);
            let old = root.join("old");
            let mut c = ctx("/old", &old, root);
            c.query = query;
            assert_eq!(process(&scope, &r, &c), expected);
        }
    }

    #[test]
    fn passthrough_targets_are_never_promoted_to_filesystem() {
        let base = std::env::temp_dir().join(format!("vp-rewrite-pt-{}", std::process::id()));
        let docroot = base.join("www");
        fs::create_dir_all(&docroot).unwrap();
        let target = docroot.join("tool.cgi");
        fs::write(&target, "inside").unwrap();
        let query = target.to_string_lossy().as_bytes().to_vec();
        let r = req();

        let run = |flag: &str| {
            let mut scope = Scope::default();
            scope.rewrite_policy.rewrite_engine = Some(true);
            scope.rewrite_policy.rewrite_rules.push(
                parse_rewrite_rule(
                    &["^/q$".into(), "%{QUERY_STRING}".into(), flag.into()],
                    "/",
                    false,
                )
                .unwrap(),
            );
            let c = Context {
                url_path: "/q",
                fs_path: &docroot,
                docroot: &docroot,
                server_root: &base,
                query: &query,
                peer: "127.0.0.1".parse().unwrap(),
                port: 80,
                https: false,
                server_name: "localhost",
            };
            process(&scope, &r, &c)
        };
        // Without [PT] the absolute substitution is a filesystem target.
        assert!(matches!(
            run("[L]"),
            Outcome::Internal {
                filesystem: Some(p),
                ..
            } if p == target
        ));
        // With [PT] the same substitution stays in URL space (F67): no
        // filesystem override, and the dispatcher re-maps the URL next round.
        assert!(matches!(
            run("[PT,L]"),
            Outcome::Internal {
                filesystem: None,
                ref path,
                ..
            } if path.ends_with("/www/tool.cgi")
        ));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_later_rule_replaces_an_earlier_filesystem_target() {
        let base = std::env::temp_dir().join(format!("vp-rewrite-sticky-{}", std::process::id()));
        let docroot = base.join("www");
        fs::create_dir_all(&docroot).unwrap();
        let hit = docroot.join("a.txt");
        fs::write(&hit, "hit").unwrap();
        let query = hit.to_string_lossy().as_bytes().to_vec();
        let r = req();

        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        // Rule 1 without [L]: rewrites /q onto the file path and keeps going,
        // which used to make the file target stick across this round (F68).
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/q$".into(), "%{QUERY_STRING}".into(), "".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        // Rule 2 with [L]: an ordinary URL rewrite with no filesystem target.
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^".into(), "/rewrite-remapped-url".into(), "[L]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        let c = Context {
            url_path: "/q",
            fs_path: &docroot,
            docroot: &docroot,
            server_root: &base,
            query: &query,
            peer: "127.0.0.1".parse().unwrap(),
            port: 80,
            https: false,
            server_name: "localhost",
        };
        // Only the final rule's target may be applied: this round's outcome is
        // the URL rewrite, with no filesystem override carried from rule 1.
        assert!(matches!(
            process(&scope, &r, &c),
            Outcome::Internal {
                filesystem: None,
                ref path,
                ..
            } if path == "/rewrite-remapped-url"
        ));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn prefix_stat_filesystem_override_never_changes_the_authorization_base() {
        let base = std::env::temp_dir().join(format!("vp-prefix-{}", std::process::id()));
        let docroot = base.join("www");
        let conf = base.join("conf");
        fs::create_dir_all(&docroot).unwrap();
        fs::create_dir_all(&conf).unwrap();
        let inside = docroot.join("index.html");
        let outside = conf.join("core.conf");
        fs::write(&inside, "inside").unwrap();
        fs::write(&outside, "outside").unwrap();
        let inside_query = inside.to_string_lossy().as_bytes().to_vec();
        let outside_query = outside.to_string_lossy().as_bytes().to_vec();
        let r = req();

        let run = |query: &[u8], flag: &str| {
            let mut scope = Scope::default();
            scope.rewrite_policy.rewrite_engine = Some(true);
            scope.rewrite_policy.rewrite_rules.push(
                parse_rewrite_rule(
                    &["^/q$".into(), "%{QUERY_STRING}".into(), flag.into()],
                    "/",
                    false,
                )
                .unwrap(),
            );
            let c = Context {
                url_path: "/q",
                fs_path: &docroot,
                docroot: &docroot,
                server_root: &base,
                query,
                peer: "127.0.0.1".parse().unwrap(),
                port: 80,
                https: false,
                server_name: "localhost",
            };
            process(&scope, &r, &c)
        };
        assert!(matches!(
            run(&inside_query, "[L]"),
            Outcome::Internal { filesystem: Some(path), .. } if path == inside
        ));
        assert!(matches!(
            run(&outside_query, "[L]"),
            Outcome::Internal {
                filesystem: None,
                ..
            }
        ));
        // The compatibility flag must not re-root the request at the target's
        // parent directory.  Authorization always remains below the current
        // document/alias root.
        assert!(matches!(
            run(&outside_query, "[L,UnsafePrefixStat]"),
            Outcome::Internal {
                filesystem: None,
                ..
            }
        ));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn backref_filesystem_targets_stay_below_the_current_root() {
        let base = std::env::temp_dir().join(format!("vp-rewrite-fs-{}", std::process::id()));
        let docroot = base.join("www");
        let conf = base.join("conf");
        fs::create_dir_all(&docroot).unwrap();
        fs::create_dir_all(&conf).unwrap();
        fs::write(docroot.join("inside.txt"), "inside").unwrap();
        fs::write(conf.join("secret.txt"), "secret").unwrap();

        let outside_rel = conf.join("secret.txt");
        let outside_rel = outside_rel
            .to_string_lossy()
            .trim_start_matches('/')
            .to_string();
        let path = format!("/q/{outside_rel}");
        let r = req();
        let c = Context {
            url_path: &path,
            fs_path: &docroot,
            docroot: &docroot,
            server_root: &base,
            query: b"",
            peer: "127.0.0.1".parse().unwrap(),
            port: 80,
            https: false,
            server_name: "localhost",
        };
        let run = |flags: &str| {
            let mut scope = Scope::default();
            scope.rewrite_policy.rewrite_engine = Some(true);
            scope.rewrite_policy.rewrite_rules.push(
                parse_rewrite_rule(
                    &["^/q/(.*)$".into(), "/$1".into(), flags.into()],
                    "/",
                    false,
                )
                .unwrap(),
            );
            process(&scope, &r, &c)
        };
        assert!(matches!(
            run("[L]"),
            Outcome::Internal {
                filesystem: None,
                ..
            }
        ));
        assert!(matches!(
            run("[L,UnsafePrefixStat]"),
            Outcome::Internal {
                filesystem: None,
                ..
            }
        ));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn more_than_nine_captures_are_memory_safe() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &[
                    "^(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)(l)$".into(),
                    "/$1".into(),
                    "[L]".into(),
                ],
                "/",
                true,
            )
            .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        match process(&scope, &r, &ctx("/abcdefghijkl", &root.join("x"), root)) {
            Outcome::Internal { path, .. } => assert_eq!(path, "/a"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn expr_false_is_not_treated_as_true() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        let mut rule =
            parse_rewrite_rule(&["^/old$".into(), "-".into(), "[G]".into()], "/", false).unwrap();
        rule.conditions
            .push(parse_rewrite_cond(&["expr".into(), "false".into()]).unwrap());
        scope.rewrite_policy.rewrite_rules.push(rule);
        let r = req();
        let root = Path::new("/tmp");
        assert_eq!(
            process(&scope, &r, &ctx("/old", &root.join("old"), root)),
            Outcome::None
        );
    }

    #[test]
    fn backreference_question_mark_is_encoded_unless_unsafe_flag_is_set() {
        let run = |flags: &str, query: &[u8]| {
            let mut scope = Scope::default();
            scope.rewrite_policy.rewrite_engine = Some(true);
            scope.rewrite_policy.rewrite_rules.push(
                parse_rewrite_rule(
                    &["^/x$".into(), "/out?%{QUERY_STRING}".into(), flags.into()],
                    "/",
                    false,
                )
                .unwrap(),
            );
            let r = req();
            let root = Path::new("/tmp");
            let fs = root.join("x");
            let mut c = ctx("/x", &fs, root);
            c.query = query;
            process(&scope, &r, &c)
        };
        match run("[L]", b"a?b") {
            Outcome::Internal { path, query, .. } => {
                assert_eq!(path, "/out");
                assert_eq!(query, b"a%3fb");
            }
            other => panic!("unexpected {other:?}"),
        }
        match run("[L,UnsafeAllow3F]", b"a?b") {
            Outcome::Internal { path, query, .. } => {
                assert_eq!(path, "/out");
                assert_eq!(query, b"a?b");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(run("[L]", b"a\r\nb"), Outcome::Error(_)));
    }

    #[test]
    fn lookahead_rewrite_variables_fail_closed() {
        assert!(parse_rewrite_cond(&["%{LA-U:HTTP:Host}".into(), "^x$".into()]).is_err());
        assert!(parse_rewrite_rule(
            &["^/x$".into(), "/%{LA-U:HTTP:Host}".into(), "[L]".into()],
            "/",
            false
        )
        .is_err());
    }

    #[test]
    fn chain_failure_skips_the_entire_trailing_chain() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/none$".into(), "/bad".into(), "[C,L]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/old$".into(), "/middle".into(), "[C]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/old$".into(), "/escaped".into(), "[L]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(&["^/old$".into(), "/good".into(), "[L]".into()], "/", false)
                .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        match process(&scope, &r, &ctx("/old", &root.join("old"), root)) {
            Outcome::Internal { path, .. } => assert_eq!(path, "/good"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn next_flag_restarts_rule_processing() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(&["^/old$".into(), "/new".into(), "[N]".into()], "/", false)
                .unwrap(),
        );
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/new$".into(), "/final".into(), "[L]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        match process(&scope, &r, &ctx("/old", &root.join("old"), root)) {
            Outcome::Internal { path, .. } => assert_eq!(path, "/final"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn header_conditions_add_vary() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        let mut rule =
            parse_rewrite_rule(&["^/old$".into(), "/new".into(), "[L]".into()], "/", false)
                .unwrap();
        rule.conditions.push(
            parse_rewrite_cond(&["%{HTTP:Accept}".into(), "directory-accept".into()]).unwrap(),
        );
        scope.rewrite_policy.rewrite_rules.push(rule);
        let mut r = req();
        r.headers.insert("accept", "directory-accept");
        let root = Path::new("/tmp");
        match process(&scope, &r, &ctx("/old", &root.join("old"), root)) {
            Outcome::Internal { effects, .. } => assert_eq!(effects.vary, vec!["Accept"]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn effects_are_collected_for_dash_rules() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &[
                    "^/old$".into(),
                    "-".into(),
                    "[E=FOO:bar,E=!OLD,CO=NAME:VAL:localhost:86400:/:secure:httponly:none,H=server-status,T=text/plain]"
                        .into(),
                ],
                "/",
                false,
            )
            .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        match process(&scope, &r, &ctx("/old", &root.join("old"), root)) {
            Outcome::Internal { effects, .. } => {
                assert_eq!(
                    effects.env,
                    vec![("FOO".into(), Some("bar".into())), ("OLD".into(), None)]
                );
                assert_eq!(
                    effects.cookies,
                    vec!["NAME=VAL; Domain=localhost; Max-Age=5184000; Path=/; Secure; HttpOnly; SameSite=none"]
                );
                assert_eq!(effects.handler.as_deref(), Some("server-status"));
                assert_eq!(effects.content_type.as_deref(), Some("text/plain"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn b_flags_escape_backreferences() {
        let run = |flags: &str, path: &str| {
            let mut scope = Scope::default();
            scope.rewrite_policy.rewrite_engine = Some(true);
            scope.rewrite_policy.rewrite_rules.push(
                parse_rewrite_rule(
                    &["^/x/(.*)$".into(), "/x/$1".into(), flags.into()],
                    "/",
                    false,
                )
                .unwrap(),
            );
            let r = req();
            let root = Path::new("/tmp");
            match process(&scope, &r, &ctx(path, &root.join("x"), root)) {
                Outcome::Internal { path, .. } => path,
                other => panic!("unexpected {other:?}"),
            }
        };
        assert_eq!(run("[B]", "/x/a/b c\r"), "/x/a%2fb+c%0d");
        assert_eq!(run("[B,BNE=/]", "/x/a/b c\r"), "/x/a/b+c%0d");
        assert_eq!(run("[BNE=/]", "/x/a/b c\r"), "/x/a/b+c%0d");
        assert_eq!(run("[BCTLS]", "/x/a/b c\r"), "/x/a/b+c%0d");
        assert_eq!(run("[B=/]", "/x/a/b c"), "/x/a%2fb c");
        assert_eq!(run("[B,BNP]", "/x/a b"), "/x/a%20b");
    }

    #[test]
    fn internal_rule_rewrites_path() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^old\\.html$".into(), "new.html".into(), "[L]".into()],
                "/",
                true,
            )
            .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        let out = process(&scope, &r, &ctx("/old.html", &root.join("old.html"), root));
        assert!(matches!(out, Outcome::Internal { path, .. } if path == "/new.html"));
    }

    #[test]
    fn redirect_and_forbidden_flags() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^old$".into(), "/new".into(), "[R=301,L]".into()],
                "/",
                true,
            )
            .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        let out = process(&scope, &r, &ctx("/old", &root.join("old"), root));
        assert!(
            matches!(out, Outcome::Redirect { status: 301, location, .. } if location == "/new?x=1")
        );

        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(&["^old$".into(), "-".into(), "[F]".into()], "/", true).unwrap(),
        );
        assert_eq!(
            process(&scope, &r, &ctx("/old", &root.join("old"), root)),
            Outcome::Forbidden
        );
    }

    #[test]
    fn condition_and_query_preservation() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        let cond = parse_rewrite_cond(&["%{QUERY_STRING}".into(), "^x=1$".into()]).unwrap();
        let mut rule =
            parse_rewrite_rule(&["^old$".into(), "new".into(), "[L,QSA]".into()], "/", true)
                .unwrap();
        rule.conditions.push(cond);
        scope.rewrite_policy.rewrite_rules.push(rule);
        let r = req();
        let root = Path::new("/tmp");
        let out = process(&scope, &r, &ctx("/old", &root.join("old"), root));
        assert!(
            matches!(out, Outcome::Internal { path, query, .. } if path == "/new" && query == b"x=1")
        );
    }

    #[test]
    fn internal_rewrites_preserve_non_utf8_query_bytes() {
        let root = Path::new("/tmp");
        let mut request = req();
        request.query = b"raw=\xff\xfe".to_vec();

        let old = root.join("old");
        let mut preserve = ctx("/old", &old, root);
        preserve.query = &request.query;
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(&["^/old$".into(), "/new".into(), "[L]".into()], "/", false)
                .unwrap(),
        );
        assert!(matches!(
            process(&scope, &request, &preserve),
            Outcome::Internal { path, query, .. }
                if path == "/new" && query == b"raw=\xff\xfe"
        ));

        let mut append_scope = Scope::default();
        append_scope.rewrite_policy.rewrite_engine = Some(true);
        append_scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/old$".into(), "/new?fixed=1".into(), "[QSA,L]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        assert!(matches!(
            process(&append_scope, &request, &preserve),
            Outcome::Internal { query, .. } if query == b"fixed=1&raw=\xff\xfe"
        ));
    }

    #[test]
    fn condition_or_groups_are_anded() {
        let r = req();
        let root = Path::new("/tmp");
        let old = root.join("old");

        // A false, B true [OR], C true must be false: A && (B || C).
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        let mut rule =
            parse_rewrite_rule(&["^old$".into(), "new".into(), "[L]".into()], "/", true).unwrap();
        rule.conditions = vec![
            parse_rewrite_cond(&["%{QUERY_STRING}".into(), "^nope$".into()]).unwrap(),
            parse_rewrite_cond(&["%{QUERY_STRING}".into(), "^x=1$".into(), "[OR]".into()]).unwrap(),
            parse_rewrite_cond(&["%{QUERY_STRING}".into(), "^x=1$".into()]).unwrap(),
        ];
        scope.rewrite_policy.rewrite_rules.push(rule);
        assert_eq!(process(&scope, &r, &ctx("/old", &old, root)), Outcome::None);

        // A true, B false [OR], C true is true: A && (B || C).
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        let mut rule =
            parse_rewrite_rule(&["^old$".into(), "new".into(), "[L]".into()], "/", true).unwrap();
        rule.conditions = vec![
            parse_rewrite_cond(&["%{QUERY_STRING}".into(), "^x=1$".into()]).unwrap(),
            parse_rewrite_cond(&["%{QUERY_STRING}".into(), "^nope$".into(), "[OR]".into()])
                .unwrap(),
            parse_rewrite_cond(&["%{QUERY_STRING}".into(), "^x=1$".into()]).unwrap(),
        ];
        scope.rewrite_policy.rewrite_rules.push(rule);
        assert!(matches!(
            process(&scope, &r, &ctx("/old", &old, root)),
            Outcome::Internal { path, .. } if path == "/new"
        ));
    }

    #[test]
    fn engine_off_backrefs_and_external_redirects() {
        let r = req();
        let root = Path::new("/tmp");
        let item = root.join("item/a");
        let c = ctx("/item/a", &item, root);
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(false);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^item/(.*)$".into(), "show/$1".into(), "[L]".into()],
                "/",
                true,
            )
            .unwrap(),
        );
        assert_eq!(process(&scope, &r, &c), Outcome::None);

        scope.rewrite_policy.rewrite_engine = Some(true);
        assert!(matches!(
            process(&scope, &r, &c),
            Outcome::Internal { path, .. } if path == "/show/a"
        ));

        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &[
                    "^item/(.*)$".into(),
                    "https://example.test/$1".into(),
                    "[R=301,L]".into(),
                ],
                "/",
                true,
            )
            .unwrap(),
        );
        let out = process(&scope, &r, &c);
        assert!(
            matches!(
                &out,
                Outcome::Redirect { status: 301, location, .. }
                    if location == "https://example.test/a?x=1"
            ),
            "{out:?}"
        );
    }

    #[test]
    fn file_conditions_are_confined_to_the_document_root() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        let mut rule =
            parse_rewrite_rule(&["^.*$".into(), "new".into(), "[L]".into()], "/", true).unwrap();
        rule.conditions
            .push(parse_rewrite_cond(&["%{REQUEST_URI}".into(), "-f".into()]).unwrap());
        scope.rewrite_policy.rewrite_rules.push(rule);
        let r = req();
        let root = Path::new("/tmp/not-the-document-root");
        let out = process(
            &scope,
            &r,
            &ctx("/etc/passwd", Path::new("/etc/passwd"), root),
        );
        assert_eq!(out, Outcome::None);
    }

    #[test]
    fn rewrite_map_uses_capture_keys() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_maps.push((
            "txt".into(),
            RewriteMap::Txt([("old".into(), "mapped".into())].into_iter().collect()),
        ));
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/(old)$".into(), "/${txt:$1}".into(), "[L]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        match process(&scope, &r, &ctx("/old", &root.join("old"), root)) {
            Outcome::Internal { path, .. } => assert_eq!(path, "/mapped"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn skip_and_qsd_flags_work() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/old$".into(), "/first".into(), "[S=1]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/first$".into(), "/skip".into(), "[L]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &["^/first$".into(), "/last".into(), "[QSD,L]".into()],
                "/",
                false,
            )
            .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        let out = process(&scope, &r, &ctx("/old", &root.join("old"), root));
        match out {
            Outcome::Internal { path, query, .. } => {
                assert_eq!(path, "/last");
                assert!(query.is_empty(), "QSD should discard the original query");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn expr_conditions_are_evaluated() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        let mut rule =
            parse_rewrite_rule(&["^/old$".into(), "-".into(), "[G]".into()], "/", false).unwrap();
        rule.conditions
            .push(parse_rewrite_cond(&["expr".into(), "true".into()]).unwrap());
        scope.rewrite_policy.rewrite_rules.push(rule);
        let r = req();
        let root = Path::new("/tmp");
        assert_eq!(
            process(&scope, &r, &ctx("/old", &root.join("old"), root)),
            Outcome::Gone
        );

        let mut per_dir_scope = Scope::default();
        per_dir_scope.rewrite_policy.rewrite_engine = Some(true);
        let mut per_dir_rule =
            parse_rewrite_rule(&["^old$".into(), "-".into(), "[G]".into()], "/", true).unwrap();
        per_dir_rule
            .conditions
            .push(parse_rewrite_cond(&["expr".into(), "true".into()]).unwrap());
        per_dir_scope
            .rewrite_policy
            .rewrite_rules
            .push(per_dir_rule);
        assert_eq!(
            process(&per_dir_scope, &r, &ctx("/old", &root.join("old"), root)),
            Outcome::Gone
        );
    }

    #[test]
    fn malformed_conditions_and_flags_are_rejected() {
        assert!(parse_rewrite_cond(&["%{REQUEST_URI}".into(), "[".into()]).is_err());
        assert!(parse_rewrite_cond(&["%{NOT_A_REWRITE_VAR}".into(), "^$".into()]).is_ok());
        assert!(parse_rewrite_rule(&["^x$".into(), "y".into(), "[C]".into()], "/", true).is_ok());
        assert!(
            parse_rewrite_rule(&["^x$".into(), "y".into(), "[UNKNOWN]".into()], "/", true).is_err()
        );

        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        let mut rule =
            parse_rewrite_rule(&["^old$".into(), "new".into(), "[L]".into()], "/", true).unwrap();
        rule.conditions
            .push(parse_rewrite_cond(&["%{NOT_A_REWRITE_VAR}".into(), "^$".into()]).unwrap());
        scope.rewrite_policy.rewrite_rules.push(rule);
        let r = req();
        let root = Path::new("/tmp");
        assert!(matches!(
            process(&scope, &r, &ctx("/old", &root.join("old"), root)),
            Outcome::Error(_)
        ));
    }

    #[test]
    fn substitution_variables_are_expanded() {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules.push(
            parse_rewrite_rule(
                &[
                    "^old$".into(),
                    "https://%{HTTP_HOST}/new".into(),
                    "[R=301,L]".into(),
                ],
                "/",
                true,
            )
            .unwrap(),
        );
        let r = req();
        let root = Path::new("/tmp");
        assert!(matches!(
            process(&scope, &r, &ctx("/old", &root.join("old"), root)),
            Outcome::Redirect { status: 301, location, .. } if location == "https://localhost/new?x=1"
        ));
    }

    #[test]
    fn base_normalization_and_negation() {
        assert_eq!(normalize_rewrite_base("sub"), "/sub/");
        let rule = parse_rewrite_rule(&["!^keep$".into(), "x".into()], "/", true).unwrap();
        assert!(rule.negated);
    }

    #[test]
    fn access_layer_subject_is_filesystem_relative_and_keeps_directory_slash() {
        let mut rule = parse_rewrite_rule(
            &["^wallet/public/private/$".into(), "-".into(), "[F]".into()],
            "/",
            true,
        )
        .unwrap();
        rule.subject_dir = Some(PathBuf::from("/srv/www"));
        assert_eq!(
            subject_for(
                &rule,
                "/wallet/private/",
                Path::new("/srv/www/wallet/public/private")
            )
            .as_deref(),
            Some("wallet/public/private/")
        );
        assert_eq!(
            subject_for(
                &rule,
                "/wallet/private",
                Path::new("/srv/www/wallet/public/private")
            )
            .as_deref(),
            Some("wallet/public/private")
        );
        // A layer above the mapping root has the same subject shape.
        rule.subject_dir = Some(PathBuf::from("/srv"));
        assert_eq!(
            subject_for(
                &rule,
                "/wallet/private/",
                Path::new("/srv/www/wallet/public/private")
            )
            .as_deref(),
            Some("www/wallet/public/private/")
        );
        assert!(subject_for(
            &rule,
            "/wallet/private/",
            Path::new("/other/wallet/public/private")
        )
        .is_none());

        // A malformed layer must fail closed rather than skip its rules.
        let r = req();
        let c = ctx(
            "/wallet/private/",
            Path::new("/other/wallet/public/private"),
            Path::new("/srv"),
        );
        let scope = scope_with(vec![rule]);
        assert!(matches!(
            process(&scope, &r, &c),
            Outcome::Error(message) if message.contains("rewrite subject")
        ));
    }

    fn parsed_rule(
        pattern: &str,
        sub: &str,
        flags: &str,
        base: &str,
        per_dir: bool,
    ) -> RewriteRule {
        parse_rewrite_rule(&[pattern.into(), sub.into(), flags.into()], base, per_dir).unwrap()
    }

    fn scope_with(rules: Vec<RewriteRule>) -> Scope {
        let mut scope = Scope::default();
        scope.rewrite_policy.rewrite_engine = Some(true);
        scope.rewrite_policy.rewrite_rules = rules;
        scope
    }

    #[test]
    fn cookie_escape_and_effect_helpers() {
        let mut flags = crate::config::RewriteFlags::default();
        flags.escape_backrefs = true;
        flags.noescape_backrefs = true;
        let spec = escape_spec(&flags).unwrap();
        assert_eq!(escape_backref_value(b"a&b c", &spec), b"a&b+c");

        flags.noescape_backrefs = false;
        flags.escape_controls = true;
        flags.escape_chars = " .".into();
        flags.backref_no_plus = true;
        let spec = escape_spec(&flags).unwrap();
        assert_eq!(escape_backref_value(b"a b.c", &spec), b"a%20b%2ec");

        // The whole backreference-escape family refines to the verified
        // percent_encode loop; the [BNP] plus-suppression and [B] custom
        // sets keep their exact per-byte semantics.
        let mut flags = crate::config::RewriteFlags::default();
        flags.escape_backrefs = true;
        let spec = escape_spec(&flags).unwrap();
        assert_eq!(escape_backref_value(b"a b.c", &spec), b"a+b%2ec");

        // Redirect Location escaping is the same verified loop and now
        // percent-encodes non-ASCII bytes instead of emitting Latin-1
        // mojibake, while keeping the query separator raw.
        assert_eq!(escape_redirect_location("/new/a b?q=1"), "/new/a%20b?q=1");
        assert_eq!(escape_redirect_location("/new/\u{e9}"), "/new/%c3%a9");

        assert_eq!(
            build_cookie("name:value:example.test:10:/:secure:httponly:lax").unwrap(),
            "name=value; Domain=example.test; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=lax"
        );
        assert_eq!(
            build_cookie("name:value:example.test:-1:/:true:1:None").unwrap(),
            "name=value; Domain=example.test; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=None"
        );
        assert_eq!(
            build_cookie(";name;value;example.test;10;/;secure;httponly;lax").unwrap(),
            "name=value; Domain=example.test; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=lax"
        );
        assert_eq!(
            build_cookie("name:value:example.test:1:/:1:true:Strict").unwrap(),
            "name=value; Domain=example.test; Max-Age=60; Path=/; Secure; HttpOnly; SameSite=Strict"
        );
        assert!(build_cookie(":value").is_err());
        assert!(build_cookie("name:value:example.test:nope").is_err());
        assert!(build_cookie("name=bad\u{1}value").is_err());
        // The [CO] cookie fields parse under a strict RFC 6265 grammar: a
        // capture cannot inject attributes, and flag slots accept only their
        // documented tokens.
        assert!(build_cookie("na;me:value").is_err());
        assert!(build_cookie("name:va;ue").is_err());
        assert!(build_cookie("name:value:\"injected\"").is_err());
        assert!(build_cookie("name:value:ev;il.test").is_err());
        assert!(build_cookie("name:value:example.test:10:/:pa;th").is_err());
        assert!(build_cookie("name:value:example.test:10:/bad,path").is_err());
        assert!(build_cookie("name:value:example.test:10:/:yes").is_err());
        assert!(build_cookie("name:value:example.test:10:/:secure:yes").is_err());
        assert!(build_cookie("name:value:example.test:10:/:secure:httponly:foo").is_err());
        assert!(build_cookie("name:value:example.test:10:/:secure:httponly:0").is_err());
        // Canonical accepted shapes, case-insensitive.
        assert_eq!(
            build_cookie("name:value:example.test:10:/").unwrap(),
            "name=value; Domain=example.test; Max-Age=600; Path=/"
        );
        assert_eq!(
            build_cookie("n:v::0:/:SECURE:True:LAX").unwrap(),
            "n=v; Path=/; Secure; HttpOnly; SameSite=LAX"
        );
        assert_eq!(
            build_cookie("a!z09:$&'()+-./^_`|~").unwrap(),
            "a!z09=$&'()+-./^_`|~"
        );

        let r = req();
        let root = Path::new("/tmp");
        let old_path = root.join("old");
        let c = ctx("/old", &old_path, root);
        let rule = parsed_rule(
            "^/old$",
            "-",
            "[E=FOO:bar,CO=name:value:example.test:1:/:secure:httponly:lax,H=handler,T=text/plain]",
            "/",
            false,
        );
        let e = rule_effects(&rule, &[], &[], &r, &c, "/old", b"", &[], &[]).unwrap();
        assert_eq!(e.env, vec![("FOO".into(), Some("bar".into()))]);
        assert_eq!(e.cookies.len(), 1);
        assert_eq!(e.handler.as_deref(), Some("handler"));
        assert_eq!(e.content_type.as_deref(), Some("text/plain"));

        let mut bad = rule.clone();
        bad.flags.env.push((String::new(), Some("x".into())));
        assert!(rule_effects(&bad, &[], &[], &r, &c, "/old", b"", &[], &[]).is_err());
        bad.flags.env.clear();
        bad.flags.cookies.push(":value".into());
        assert!(rule_effects(&bad, &[], &[], &r, &c, "/old", b"", &[], &[]).is_err());

        for which in 0..5 {
            let mut broken = rule.clone();
            broken.flags.env.clear();
            broken.flags.cookies.clear();
            broken.flags.handler = None;
            broken.flags.content_type = None;
            match which {
                0 => broken.flags.env.push(("${UNKNOWN}".into(), None)),
                1 => broken
                    .flags
                    .env
                    .push(("X".into(), Some("${UNKNOWN}".into()))),
                2 => broken.flags.cookies.push("${UNKNOWN}".into()),
                3 => broken.flags.handler = Some("${UNKNOWN}".into()),
                _ => broken.flags.content_type = Some("${UNKNOWN}".into()),
            }
            assert!(rule_effects(&broken, &[], &[], &r, &c, "/old", b"", &[], &[]).is_err());
        }

        let mut left = Effects::default();
        left.env.push(("A".into(), Some("1".into())));
        let mut right = Effects::default();
        right.handler = Some("h".into());
        right.content_type = Some("text/plain".into());
        right.vary = vec!["X-A".into(), "X-A".into()];
        left.merge(right);
        assert!(!left.is_empty());
        assert_eq!(left.handler.as_deref(), Some("h"));
        assert_eq!(left.content_type.as_deref(), Some("text/plain"));
        assert_eq!(left.vary, vec!["X-A"]);
    }

    #[test]
    fn condition_evaluation_and_header_extraction() {
        let dir = std::env::temp_dir().join(format!("vapache-rewrite-cond-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("file.txt"), "content").unwrap();
        fs::write(dir.join("empty.txt"), "").unwrap();
        std::os::unix::fs::symlink("file.txt", dir.join("link.txt")).unwrap();
        let r = req();
        let x_path = dir.join("x");
        let c = ctx("/x", &x_path, &dir);
        let mut caps = Vec::new();

        assert!(eval_cond(
            &parse_rewrite_cond(&["x".into(), "-f".into()]).unwrap(),
            "file.txt",
            &c,
            &mut caps
        )
        .unwrap());
        assert!(eval_cond(
            &parse_rewrite_cond(&["x".into(), "-d".into()]).unwrap(),
            "sub",
            &c,
            &mut caps
        )
        .unwrap());
        assert!(eval_cond(
            &parse_rewrite_cond(&["x".into(), "-s".into()]).unwrap(),
            "file.txt",
            &c,
            &mut caps
        )
        .unwrap());
        assert!(!eval_cond(
            &parse_rewrite_cond(&["x".into(), "-s".into()]).unwrap(),
            "empty.txt",
            &c,
            &mut caps
        )
        .unwrap());
        assert!(eval_cond(
            &parse_rewrite_cond(&["x".into(), "-l".into()]).unwrap(),
            "link.txt",
            &c,
            &mut caps
        )
        .unwrap());
        for (pattern, value, expected) in [
            (">=10", "10", true),
            ("<=10", "10", true),
            (">9", "10", true),
            ("<11", "10", true),
            ("=abc", "abc", true),
            ("!def", "abc", true),
            ("!^/no$", "/yes", true),
            ("!^/no$", "/no", false),
        ] {
            assert_eq!(
                eval_cond(
                    &parse_rewrite_cond(&["x".into(), pattern.into()]).unwrap(),
                    value,
                    &c,
                    &mut caps
                )
                .unwrap(),
                expected,
                "{pattern}"
            );
        }
        let nocase_eq = parse_rewrite_cond(&["x".into(), "=ABC".into(), "[NC]".into()]).unwrap();
        assert!(eval_cond(&nocase_eq, "abc", &c, &mut caps).unwrap());
        let nocase_ne = parse_rewrite_cond(&["x".into(), "!ABC".into(), "[NC]".into()]).unwrap();
        assert!(!eval_cond(&nocase_ne, "abc", &c, &mut caps).unwrap());
        let double_ne = parse_rewrite_cond(&["x".into(), "!!ABC".into()]).unwrap();
        assert!(!eval_cond(&double_ne, "abc", &c, &mut caps).unwrap());
        assert!(eval_cond(&double_ne, "ABC", &c, &mut caps).unwrap());
        let double_ne_nc =
            parse_rewrite_cond(&["x".into(), "!!ABC".into(), "[NC]".into()]).unwrap();
        assert!(eval_cond(&double_ne_nc, "abc", &c, &mut caps).unwrap());
        assert!(!eval_cond(&double_ne_nc, "abd", &c, &mut caps).unwrap());
        let regex = parse_rewrite_cond(&["x".into(), "^(a)(b)$".into()]).unwrap();
        assert!(eval_cond(&regex, "ab", &c, &mut caps).unwrap());
        assert_eq!(caps, vec![b"ab".to_vec(), b"a".to_vec(), b"b".to_vec()]);
        assert!(!eval_cond(&regex, "zz", &c, &mut caps).unwrap());

        // P16-B/C: RewriteCond regexes use Apache's ASCII class semantics and
        // receive raw header bytes, including obs-text that is not UTF-8.
        let boundary = parse_rewrite_cond(&["%{HTTP:X-Test}".into(), r"\badmin\b".into()]).unwrap();
        assert!(eval_cond(&boundary, "éadmin".as_bytes(), &c, &mut caps).unwrap());
        let raw = parse_rewrite_cond(&["%{HTTP:X-Test}".into(), "sqlmap".into()]).unwrap();
        assert!(eval_cond(&raw, b"\xffsqlmap", &c, &mut caps).unwrap());
        let allow = parse_rewrite_cond(&["%{HTTP:X-Test}".into(), r"^\w+$".into()]).unwrap();
        assert!(!eval_cond(&allow, "é".as_bytes(), &c, &mut caps).unwrap());
        let mut raw_req = req();
        raw_req
            .headers
            .insert("x-test", [vec![0xff], b"sqlmap".to_vec()].concat());
        assert_eq!(
            expand_vars_bytes("%{HTTP:X-Test}", &raw_req, &c, "/path", b"", &[], &[], &[],)
                .unwrap(),
            b"\xffsqlmap"
        );
        assert!(caps.is_empty());

        assert_eq!(compare_cond("10", "9", false), std::cmp::Ordering::Greater);
        assert_eq!(compare_cond("ABC", "abc", true), std::cmp::Ordering::Equal);
        assert_eq!(compare_cond("ABC", "abc", false), std::cmp::Ordering::Less);
        assert!(file_test("file.txt", &c, |_, real| real.is_file()));
        assert!(file_test(
            &dir.join("file.txt").to_string_lossy(),
            &c,
            |_, real| real.is_file()
        ));
        assert!(!file_test("../etc/passwd", &c, |_, _| true));
        assert!(!file_test("/etc/passwd", &c, |_, _| true));
        let outside = std::env::temp_dir().join(format!(
            "vapache-rewrite-outside-{}-{}",
            std::process::id(),
            "file_test"
        ));
        fs::write(&outside, "outside").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("escape.txt")).unwrap();
        assert!(!file_test("escape.txt", &c, |_, _| true));
        // A symlink that stays inside the root still works normally.
        assert!(file_test("link.txt", &c, |_, real| real.is_file()));
        // Missing probed paths and missing roots fail closed at canonicalize.
        assert!(!file_test("missing.txt", &c, |_, _| true));
        let missing_root = dir.join("missing-root");
        let missing_target = missing_root.join("x");
        let c_missing = ctx("/x", &missing_target, &missing_root);
        assert!(!file_test("file.txt", &c_missing, |_, _| true));
        let _ = fs::remove_file(&outside);

        assert_eq!(
            condition_header("x %{HTTP_X_TEST} y").as_deref(),
            Some("X-Test")
        );
        assert_eq!(condition_header("%{HTTP:host}").as_deref(), Some("Host"));
        assert_eq!(
            condition_header("%{HTTP:}%{ENV:X}%{HTTP:X-A}").as_deref(),
            Some("X-A")
        );
        assert_eq!(
            condition_header("%{HTTPX}%{HTTP_X_TEST}").as_deref(),
            Some("X-Test")
        );
        assert_eq!(condition_header("%{HTTP_X__Y}").as_deref(), Some("X--Y"));
        assert_eq!(condition_header("plain"), None);

        assert_eq!(
            expand_vars(
                "${REQUEST_URI}-%{REQUEST_URI}-%1-é",
                &r,
                &c,
                "/path",
                b"q=1",
                &[b"zero".to_vec(), b"cap".to_vec()],
                &[],
                &[],
            )
            .unwrap(),
            "/path-/path-cap-é"
        );
        assert!(expand_vars("%{NOPE}", &r, &c, "/path", b"", &[], &[], &[]).is_err());
        assert_eq!(
            expand_vars("${unterminated", &r, &c, "/", b"", &[], &[], &[]).unwrap(),
            "${unterminated"
        );
        assert_eq!(
            expand_vars("%{unterminated", &r, &c, "/", b"", &[], &[], &[]).unwrap(),
            "%{unterminated"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn maps_backrefs_and_url_helpers() {
        use std::collections::HashMap;
        let r = req();
        let root = Path::new("/tmp");
        let old_path = root.join("old");
        let c = ctx("/old", &old_path, root);
        let mut txt = HashMap::new();
        txt.insert("key".into(), "value".to_string());
        let mut rnd = HashMap::new();
        rnd.insert("key".into(), vec!["a".into(), "b".into()]);
        let maps = vec![
            ("txt".into(), RewriteMap::Txt(txt)),
            ("rnd".into(), RewriteMap::Rnd(rnd)),
            (
                "prg".into(),
                RewriteMap::Prg(RewriteProgram::bind("/bin/cat".into(), Vec::new()).unwrap()),
            ),
            ("int".into(), RewriteMap::Int("toupper".into())),
        ];
        assert_eq!(
            variable_value(
                "ENV:FOO",
                &r,
                &c,
                "/old",
                b"",
                &[],
                &[("FOO".into(), "bar".into())]
            )
            .unwrap(),
            "bar"
        );
        assert_eq!(
            variable_value("REQUEST_URI", &r, &c, "/old", b"q=1", &[], &[]).unwrap(),
            "/old"
        );
        assert_eq!(
            variable_value("REQUEST_FILENAME", &r, &c, "/old", b"", &[], &[]).unwrap(),
            root.join("old").to_string_lossy()
        );
        assert_eq!(
            variable_value("HTTP_HOST", &r, &c, "/old", b"", &[], &[]).unwrap(),
            "localhost"
        );
        assert_eq!(
            variable_value("HTTP_X_TEST", &r, &c, "/old", b"", &[], &[]).unwrap(),
            ""
        );
        assert_eq!(
            variable_value("txt:key", &r, &c, "/old", b"", &maps, &[]).unwrap(),
            "value"
        );
        assert_eq!(
            variable_value("txt:missing", &r, &c, "/old", b"", &maps, &[]).unwrap(),
            ""
        );
        assert!(["a", "b"].contains(
            &variable_value("rnd:key", &r, &c, "/old", b"", &maps, &[])
                .unwrap()
                .as_str()
        ));
        assert_eq!(
            variable_value("rnd:missing", &r, &c, "/old", b"", &maps, &[]).unwrap(),
            ""
        );
        assert_eq!(
            variable_value("prg:abc", &r, &c, "/old", b"", &maps, &[]).unwrap(),
            "abc"
        );
        for _ in 1..crate::resource::MAX_POLICY_WORK_UNITS / PRG_MAP_WORK_COST {
            assert_eq!(
                variable_value("prg:abc", &r, &c, "/old", b"", &maps, &[]).unwrap(),
                "abc"
            );
        }
        assert!(variable_value("prg:abc", &r, &c, "/old", b"", &maps, &[]).is_err());
        assert_eq!(
            variable_value("int:abc", &r, &c, "/old", b"", &maps, &[]).unwrap(),
            "ABC"
        );
        assert_eq!(
            variable_value("THE_REQUEST", &r, &c, "/old", b"", &[], &[]).unwrap(),
            "GET /old.html?x=1 HTTP/1.1"
        );
        assert!(variable_value("UNKNOWN", &r, &c, "/old", b"", &[], &[]).is_err());

        assert_eq!(int_map("tolower", "ABC"), "abc");
        assert_eq!(int_map("toupper", "abc"), "ABC");
        assert_eq!(int_map("escape", "a b/%"), "a+b/%25");
        assert_eq!(int_map("unescape", "a+b%2f%zz"), "a b/%zz");
        assert_eq!(int_map("unknown", "x"), "");
        assert!(RewriteProgram::bind(PathBuf::new(), Vec::new()).is_err());
        assert!(RewriteProgram::bind("no-such-program-xyz".into(), Vec::new()).is_err());
        let cat_program = RewriteProgram::bind("/bin/cat".into(), Vec::new()).unwrap();
        let false_program = RewriteProgram::bind("/bin/false".into(), Vec::new()).unwrap();
        assert_eq!(run_prg_map(&cat_program, "abc"), "abc");
        assert_eq!(run_prg_map(&false_program, "abc"), "");
        struct InterruptedThenError(u8);
        impl Read for InterruptedThenError {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                self.0 += 1;
                if self.0 == 1 {
                    Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
                } else {
                    Err(std::io::Error::other("reader failed"))
                }
            }
        }
        assert_eq!(read_prg_line(InterruptedThenError(0)), (Vec::new(), false));
        assert_eq!(map_value(None, "key"), "");
        let mut bad = ErrorWriter;
        assert!(!write_prg_key(&mut bad, "x"));
        let mut dead = Command::new("/bin/true")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let dead_stdin = dead.stdin.take();
        assert_eq!(
            finish_prg_map(dead, dead_stdin, "x", Duration::from_millis(100)),
            ""
        );
        let no_stdin = Command::new("/bin/true")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert_eq!(
            finish_prg_map(no_stdin, None, "x", Duration::from_millis(100)),
            ""
        );
        let sleeping = Command::new("/bin/sleep")
            .arg("5")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert_eq!(abort_prg_map(sleeping), "");
        let mut killed = Command::new("/bin/sleep")
            .arg("5")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let killed_stdin = killed.stdin.take();
        let _ = killed.kill();
        let _ = killed.wait();
        assert_eq!(
            finish_prg_map(killed, killed_stdin, "x", Duration::from_millis(100)),
            ""
        );

        let timeout_script =
            std::env::temp_dir().join(format!("vapache-prg-timeout-{}", std::process::id()));
        fs::write(&timeout_script, "#!/bin/sh\nsleep 5\n").unwrap();
        let mut mode = fs::metadata(&timeout_script).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        mode.set_mode(0o700);
        fs::set_permissions(&timeout_script, mode).unwrap();
        let timeout_program = RewriteProgram::bind(timeout_script.clone(), Vec::new()).unwrap();
        assert_eq!(
            run_prg_map_timeout(&timeout_program, "x", Duration::from_millis(20),),
            ""
        );

        let overflow_script =
            std::env::temp_dir().join(format!("vapache-prg-overflow-{}", std::process::id()));
        fs::write(&overflow_script, "#!/bin/sh\nprintf '%09000d' 0\n").unwrap();
        let mut mode = fs::metadata(&overflow_script).unwrap().permissions();
        mode.set_mode(0o700);
        fs::set_permissions(&overflow_script, mode).unwrap();
        let overflow_program = RewriteProgram::bind(overflow_script.clone(), Vec::new()).unwrap();
        assert_eq!(
            run_prg_map_timeout(&overflow_program, "x", Duration::from_secs(1),),
            ""
        );
        let no_stdout = Command::new("/bin/true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert_eq!(wait_prg_output(no_stdout, Duration::from_millis(100)), "");
        let _ = fs::remove_file(timeout_script);
        let _ = fs::remove_file(overflow_script);

        let caps = vec![b"zero".to_vec(), b"one".to_vec()];
        let cond = vec![b"condzero".to_vec(), b"cond".to_vec()];
        assert_eq!(
            expand_caps_bytes("$0/$1/%0/\\1/$9", &caps, &cond).unwrap(),
            b"zero/one/condzero/one/"
        );
        assert_eq!(
            expand_backrefs(
                "${REQUEST_URI}-%{REQUEST_URI}-$1-%1-\\1",
                &caps,
                &cond,
                &r,
                &c,
                "/old",
                b"q=1",
                &[],
                &[],
                false,
                None,
            )
            .unwrap(),
            "/old-/old-one-cond-one"
        );
        let spec = EscapeSpec {
            custom: None,
            controls: false,
            preserve: vec![],
            no_plus: false,
        };
        assert_eq!(
            expand_backrefs(
                "$1 $9",
                &caps,
                &cond,
                &r,
                &c,
                "/old",
                b"",
                &[],
                &[],
                true,
                Some(&spec),
            )
            .unwrap(),
            "one "
        );
        assert!(expand_backrefs(
            "${REQUEST_URI}",
            &caps,
            &cond,
            &r,
            &c,
            "/old",
            b"q=1",
            &[],
            &[],
            true,
            Some(&spec),
        )
        .unwrap()
        .contains("%2f"));
        assert!(expand_backrefs(
            "%{REQUEST_URI}",
            &caps,
            &cond,
            &r,
            &c,
            "/old",
            b"q=1",
            &[],
            &[],
            true,
            Some(&spec),
        )
        .unwrap()
        .contains("%2f"));
        assert_eq!(
            expand_backrefs(
                "${unterminated %{unterminated",
                &caps,
                &cond,
                &r,
                &c,
                "/old",
                b"",
                &[],
                &[],
                true,
                None,
            )
            .unwrap(),
            "${unterminated %{unterminated"
        );
        assert_eq!(
            escape_redirect_location("a b\"<>\\^`{|}"),
            "a%20b%22%3c%3e%5c%5e%60%7b%7c%7d"
        );

        let mut host_req = req();
        host_req.headers.push("Host", "localhost:80");
        assert_eq!(
            same_host_internal(&c, &host_req, "//localhost:80/path").as_deref(),
            Some("/path")
        );
        assert_eq!(
            same_host_internal(&c, &host_req, "http://localhost:80").as_deref(),
            Some("/")
        );
        assert!(same_host_internal(&c, &host_req, "https://localhost:80/path").is_none());
        assert!(same_host_internal(&c, &host_req, "http://localhost:443/path").is_none());
        assert!(same_host_internal(&c, &host_req, "http://other.test/x").is_none());
        let no_host = req();
        assert!(same_host_internal(&c, &no_host, "http://localhost:80/x").is_some());
    }

    #[test]
    fn program_rewrite_map_rate_is_finite_and_refills() {
        let now = Instant::now();
        let mut rate = PrgMapRate::default();
        for _ in 0..MAX_PRG_MAPS_PER_SECOND {
            assert!(rate.admit_at(None, now));
        }
        assert!(!rate.admit_at(None, now));
        assert!(rate.admit_at(None, now + Duration::from_secs(1)));
    }

    #[test]
    fn program_rewrite_map_rate_reserves_capacity_for_other_clients() {
        let now = Instant::now();
        let first = Some(std::net::IpAddr::from([192, 0, 2, 1]));
        let second = Some(std::net::IpAddr::from([198, 51, 100, 1]));
        let mut rate = PrgMapRate::default();
        for _ in 0..MAX_PRG_MAPS_PER_SECOND / 4 {
            assert!(rate.admit_at(first, now));
        }
        assert!(!rate.admit_at(first, now));
        assert!(rate.admit_at(second, now));
    }

    #[test]
    fn rewrite_program_replacement_fails_closed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("vapache-prg-binding-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("worker");
        let displaced = dir.join("trusted-worker");
        fs::write(
            &path,
            "#!/bin/sh\nread key\nprintf 'trusted:%s\\n' \"$key\"\n",
        )
        .unwrap();
        let mut mode = fs::metadata(&path).unwrap().permissions();
        mode.set_mode(0o700);
        fs::set_permissions(&path, mode.clone()).unwrap();

        let program = RewriteProgram::bind(path.clone(), Vec::new()).unwrap();
        assert!(program.file.set_len(0).is_err(), "snapshot must be sealed");
        assert_eq!(run_prg_map(&program, "value"), "trusted:value");

        fs::rename(&path, &displaced).unwrap();
        assert!(!program.binding_intact());
        assert_eq!(run_prg_map(&program, "value"), "");
        fs::write(&path, "#!/bin/sh\nprintf 'attacker\\n'\n").unwrap();
        fs::set_permissions(&path, mode.clone()).unwrap();
        assert!(!program.binding_intact());
        assert_eq!(run_prg_map(&program, "value"), "");

        let mutable = dir.join("mutable-worker");
        fs::write(
            &mutable,
            "#!/bin/sh\nread key\nprintf 'trusted:%s\\n' \"$key\"\n",
        )
        .unwrap();
        fs::set_permissions(&mutable, mode).unwrap();
        let mutable_program = RewriteProgram::bind(mutable.clone(), Vec::new()).unwrap();
        fs::write(&mutable, "#!/bin/sh\nprintf 'attacker\\n'\n").unwrap();
        assert!(!mutable_program.binding_intact());
        assert_eq!(run_prg_map(&mutable_program, "value"), "");

        let invalid = dir.join("invalid-worker");
        fs::write(&invalid, "not an executable format\n").unwrap();
        fs::set_permissions(&invalid, std::fs::Permissions::from_mode(0o700)).unwrap();
        let invalid_program = RewriteProgram::bind(invalid, Vec::new()).unwrap();
        assert_eq!(run_prg_map(&invalid_program, "value"), "");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rewrite_expansion_is_capped_before_round_amplification() {
        let r = req();
        let root = Path::new("/tmp");
        let old_path = root.join("old");
        let c = ctx("/old", &old_path, root);
        let caps = vec![Vec::new(), vec![b'a'; MAX_REWRITE_OUTPUT_BYTES + 1]];
        assert!(
            expand_backrefs("$1", &caps, &[], &r, &c, "/old", b"", &[], &[], true, None,).is_err()
        );

        let repeated = "$1".repeat(100);
        let small_capture = vec![Vec::new(), vec![b'a'; 1024]];
        assert!(expand_backrefs(
            &repeated,
            &small_capture,
            &[],
            &r,
            &c,
            "/old",
            b"",
            &[],
            &[],
            true,
            None,
        )
        .is_err());
    }

    struct ErrorWriter;
    impl Write for ErrorWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn process_flag_and_error_branches() {
        let r = req();
        let root = Path::new("/tmp");
        let x_path = root.join("x");
        let c = ctx("/x", &x_path, root);

        // Subject mismatch and condition failure both honor [C].
        let chain_subject = scope_with(vec![
            parsed_rule("^x$", "/y", "[C]", "/dir/", true),
            parsed_rule("^/x$", "/hit", "[L]", "/", false),
        ]);
        assert_eq!(process(&chain_subject, &r, &c), Outcome::None);
        let mut cond_rule = parsed_rule("^/x$", "/hit", "[C]", "/", false);
        cond_rule
            .conditions
            .push(parse_rewrite_cond(&["%{REQUEST_METHOD}".into(), "^POST$".into()]).unwrap());
        let chain_cond = scope_with(vec![
            cond_rule,
            parsed_rule("^/x$", "/hit", "[L]", "/", false),
        ]);
        assert_eq!(process(&chain_cond, &r, &c), Outcome::None);

        // Negated pattern match with [C], and negated non-match applies.
        let neg_skip = scope_with(vec![
            parsed_rule("!^/x$", "/hit", "[C]", "/", false),
            parsed_rule("^/x$", "/later", "[L]", "/", false),
        ]);
        assert_eq!(process(&neg_skip, &r, &c), Outcome::None);
        let neg_apply = scope_with(vec![parsed_rule("!^/other$", "/hit", "[L]", "/", false)]);
        assert!(matches!(
            process(&neg_apply, &r, &c),
            Outcome::Internal { path, .. } if path == "/hit"
        ));

        // [QSD], skip and [L] on a dash substitution.
        let dash = scope_with(vec![
            parsed_rule("^/x$", "-", "[QSD]", "/", false),
            parsed_rule("^/x$", "/skipme", "[L]", "/", false),
        ]);
        match process(&dash, &r, &c) {
            Outcome::Internal { query, .. } => assert!(query.is_empty()),
            other => panic!("unexpected {other:?}"),
        }
        let dash_skip = scope_with(vec![
            parsed_rule("^/x$", "-", "[S=2]", "/", false),
            parsed_rule("^/x$", "/one", "[L]", "/", false),
            parsed_rule("^/x$", "/two", "[L]", "/", false),
        ]);
        assert_eq!(process(&dash_skip, &r, &c), Outcome::None);
        let dash_last = scope_with(vec![parsed_rule("^/x$", "-", "[L]", "/", false)]);
        assert_eq!(process(&dash_last, &r, &c), Outcome::None);
        let dash_end = scope_with(vec![parsed_rule(
            "^/x$",
            "-",
            "[E=ENDED:1,END]",
            "/",
            false,
        )]);
        assert!(matches!(
            process(&dash_end, &r, &c),
            Outcome::Internal {
                final_pass: true,
                ..
            }
        ));

        // The [N] loop limit is enforced for both dash and substituted rules.
        for sub in ["-", "/x"] {
            let next = scope_with(vec![parsed_rule("^/x$", sub, "[N]", "/", false)]);
            assert!(matches!(process(&next, &r, &c), Outcome::Error(_)));
        }

        let bad_expand = scope_with(vec![parsed_rule("^/x$", "${UNKNOWN}", "[L]", "/", false)]);
        assert!(matches!(process(&bad_expand, &r, &c), Outcome::Error(_)));

        let mut bad_effect = parsed_rule("^/x$", "/y", "[L]", "/", false);
        bad_effect.flags.env.push((String::new(), Some("x".into())));
        assert!(matches!(
            process(&scope_with(vec![bad_effect]), &r, &c),
            Outcome::Error(_)
        ));

        let qsl_no_query = scope_with(vec![parsed_rule("^/x$", "/new", "[QSL,L]", "/", false)]);
        match process(&qsl_no_query, &r, &c) {
            Outcome::Internal { path, query, .. } => {
                assert_eq!(path, "/new");
                assert_eq!(query, b"x=1");
            }
            other => panic!("unexpected {other:?}"),
        }

        let mut empty_rule = parsed_rule("^/x$", "/tmp", "[L]", "/", false);
        empty_rule.substitution.clear();
        assert!(matches!(
            process(&scope_with(vec![empty_rule]), &r, &c),
            Outcome::Error(_)
        ));

        let relative = scope_with(vec![parsed_rule("^/x$", "new", "[L]", "/", false)]);
        assert!(matches!(
            process(&relative, &r, &c),
            Outcome::Internal { path, .. } if path == "/new"
        ));

        let control_path = root.join("x");
        let mut control_ctx = ctx("/x", &control_path, root);
        control_ctx.query = b"bad\x01";
        let clean = scope_with(vec![parsed_rule("^/x$", "/new", "[L]", "/", false)]);
        assert!(matches!(
            process(&clean, &r, &control_ctx),
            Outcome::Error(_)
        ));
    }
}
