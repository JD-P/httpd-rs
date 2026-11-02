//! Access control (`mod_authz_core`, `mod_authz_host`, `mod_access_compat`).
//!
//! Security rule: every path through this module is fail-closed.  A `Require`
//! provider we do not understand denies access, and any malformed
//! directive is rejected at configuration time.

use crate::config::{AuthPolicy, Order, Require, RequireNode, Satisfy, Scope};
use crate::http::Request;
use crate::verified::{
    combine_and, combine_or, ipv4_in_net, ipv6_in_net, require_none_multi, PolicyResult,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Identity {
    pub user: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Allowed,
    Denied,
    AuthRequired,
    Misconfigured,
}

/// The concrete object and request context covered by an access decision.
///
/// A grant for `/public/file` cannot be reused to serve `/private/file`, a
/// different proxy target, or a cache entry for another request.  Paths are
/// canonical strings here; the opened file descriptor/proxy target still has
/// to be checked by the sink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceKey {
    pub vhost: usize,
    pub method: String,
    pub url_path: String,
    pub fs_path: Option<PathBuf>,
    pub proxy_url: Option<String>,
    pub cache_host: Option<String>,
    pub cache_path: Option<String>,
    /// Raw request-query bytes, for resource identity only.  Distinct
    /// invalid-UTF-8 byte strings must not conflate on the replacement
    /// character, so this is deliberately bytes and not a lossy String.
    pub cache_query: Option<Vec<u8>>,
    pub identity: Option<String>,
    pub file_dev: Option<u64>,
    pub file_ino: Option<u64>,
    pub backend_target: Option<String>,
    pub policy_fingerprint: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
struct ProxyRepresentationBinding {
    witness: vapache_verified::ProxyRepresentationWitness,
    backend_target: String,
}

impl ProxyRepresentationBinding {
    fn matches_stored_key(&self, key: &ResourceKey) -> bool {
        key.backend_target.as_deref() == Some(self.backend_target.as_str())
            && vapache_verified::proxy_representation_witness_matches(
                &self.witness,
                key.url_path.as_bytes(),
                self.witness.upstream_path.as_slice(),
            )
    }

    fn matches_target(
        &self,
        key: &ResourceKey,
        host: &str,
        port: u16,
        tls: bool,
        upstream_path: &str,
    ) -> bool {
        let target = vapache_verified::proxy_target_key(
            host.as_bytes(),
            port,
            tls,
            upstream_path.as_bytes(),
        );
        let target: String = target.iter().map(|byte| format!("{byte:02x}")).collect();
        target == self.backend_target
            && key.backend_target.as_deref() == Some(target.as_str())
            && vapache_verified::proxy_representation_witness_matches(
                &self.witness,
                key.url_path.as_bytes(),
                upstream_path.as_bytes(),
            )
    }
}

fn vhost_id(vhost: Option<&crate::config::VHost>) -> usize {
    vhost
        .map(|v| v as *const crate::config::VHost as usize)
        .unwrap_or(0)
}

impl ResourceKey {
    pub fn request(
        vhost: Option<&crate::config::VHost>,
        req: &Request,
        url_path: &str,
        fs_path: Option<&Path>,
        proxy_url: Option<&str>,
    ) -> Self {
        Self {
            vhost: vhost_id(vhost),
            method: req.method.clone(),
            url_path: url_path.to_string(),
            fs_path: fs_path.map(Path::to_path_buf),
            proxy_url: proxy_url.map(str::to_string),
            cache_host: None,
            cache_path: None,
            cache_query: None,
            identity: None,
            file_dev: None,
            file_ino: None,
            backend_target: None,
            policy_fingerprint: None,
        }
    }

    pub fn cache(
        vhost: Option<&crate::config::VHost>,
        req: &Request,
        host: &str,
        path: &str,
    ) -> Self {
        Self {
            vhost: vhost_id(vhost),
            method: req.method.clone(),
            url_path: path.to_string(),
            fs_path: None,
            proxy_url: None,
            cache_host: Some(host.to_string()),
            cache_path: Some(path.to_string()),
            cache_query: Some(req.query.clone()),
            identity: None,
            file_dev: None,
            file_ino: None,
            backend_target: None,
            policy_fingerprint: None,
        }
    }

    pub fn cache_policy(
        vhost: Option<&crate::config::VHost>,
        req: &Request,
        host: &str,
        path: &str,
        policy_fingerprint: [u8; 32],
    ) -> Self {
        let mut key = Self::cache(vhost, req, host, path);
        key.policy_fingerprint = Some(policy_fingerprint);
        key
    }
}

/// Capability proving that the effective scope authorized a particular
/// resource for this request.  The key is checked by every body/tunnel sink.
#[derive(Debug)]
pub struct AccessGrant {
    key: ResourceKey,
    pipeline: vapache_verified::TransformCapability,
    /// Exact front-end/upstream path pair witnessed when a proxy target is
    /// bound. A boolean pipeline bit alone cannot prevent reuse after a
    /// retarget, so the sink checks this concrete evidence as well.
    proxy_representation: Option<ProxyRepresentationBinding>,
    /// Test-only grants are intentionally wildcard; production grants are
    /// always constructed with a concrete key.
    wildcard: bool,
}

impl AccessGrant {
    pub fn require(&self, key: &ResourceKey) -> bool {
        self.wildcard || &self.key == key
    }

    pub fn key(&self) -> &ResourceKey {
        &self.key
    }

    /// Universal transform-to-sink gate.  Exact resource equality prevents a
    /// grant minted before a retarget from reaching the new object; the
    /// verified capability additionally enforces the sink-specific inode,
    /// backend and cache-policy bindings.
    pub fn require_sink(&self, key: &ResourceKey, sink: vapache_verified::TransformSink) -> bool {
        let exact_representation = sink != vapache_verified::TransformSink::Proxy
            || self
                .proxy_representation
                .as_ref()
                .is_some_and(|binding| binding.matches_stored_key(key));
        exact_representation
            && vapache_verified::transform_sink_admit(self.require(key), self.pipeline, sink)
    }

    /// Proxy-specific final sink gate. In addition to the stored resource key,
    /// compare the concrete endpoint and upstream path about to be used. This
    /// keeps a later target variable from drifting away from the witnessed
    /// representation even when the grant itself is unchanged.
    pub(crate) fn require_proxy_sink(
        &self,
        key: &ResourceKey,
        host: &str,
        port: u16,
        tls: bool,
        upstream_path: &str,
    ) -> bool {
        self.require_sink(key, vapache_verified::TransformSink::Proxy)
            && self
                .proxy_representation
                .as_ref()
                .is_some_and(|binding| binding.matches_target(key, host, port, tls, upstream_path))
    }

    /// Bind a grant that already covers `resource` to the exact outbound
    /// backend target selected by the proxy/FastCGI layer.
    pub(crate) fn bind_backend(
        &self,
        resource: &ResourceKey,
        backend_target: String,
    ) -> Option<AccessGrant> {
        if !self.require(resource) {
            return None;
        }
        let mut key = resource.clone();
        key.backend_target = Some(backend_target);
        Some(AccessGrant {
            key,
            pipeline: vapache_verified::transform_bind_backend(self.pipeline),
            proxy_representation: self.proxy_representation.clone(),
            wildcard: self.wildcard,
        })
    }

    /// Bind the exact proxy endpoint and the exact authorized/upstream path
    /// pair as one operation. Endpoint binding alone is insufficient because
    /// some upstream frameworks reinterpret path-parameter delimiters.
    pub(crate) fn bind_proxy(
        &self,
        resource: &ResourceKey,
        host: &str,
        port: u16,
        tls: bool,
        upstream_path: &str,
    ) -> Option<AccessGrant> {
        if !self.require(resource) {
            return None;
        }
        let witness = vapache_verified::proxy_representation_witness(
            resource.url_path.as_bytes(),
            upstream_path.as_bytes(),
        )?;
        let target = vapache_verified::proxy_target_key(
            host.as_bytes(),
            port,
            tls,
            upstream_path.as_bytes(),
        );
        let backend_target: String = target.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut key = resource.clone();
        key.backend_target = Some(backend_target.clone());
        Some(AccessGrant {
            key,
            pipeline: vapache_verified::transform_bind_representation(
                vapache_verified::transform_bind_backend(self.pipeline),
            ),
            proxy_representation: Some(ProxyRepresentationBinding {
                witness,
                backend_target,
            }),
            wildcard: self.wildcard,
        })
    }

    /// Bind a grant that already covers `resource` to the opened inode.
    pub(crate) fn bind_file(
        &self,
        resource: &ResourceKey,
        meta: &std::fs::Metadata,
    ) -> Option<AccessGrant> {
        if !self.require(resource) {
            return None;
        }
        let mut key = resource.clone();
        key.file_dev = Some(meta.dev());
        key.file_ino = Some(meta.ino());
        Some(AccessGrant {
            key,
            pipeline: vapache_verified::transform_bind_inode(self.pipeline),
            proxy_representation: self.proxy_representation.clone(),
            wildcard: self.wildcard,
        })
    }
}

fn authorized_pipeline(key: &ResourceKey) -> vapache_verified::TransformCapability {
    vapache_verified::transform_authorize(key.policy_fingerprint.is_some())
}

pub(crate) fn grant_if_allowed(access: Access, key: ResourceKey) -> Option<AccessGrant> {
    match access {
        Access::Allowed => Some(AccessGrant {
            pipeline: authorized_pipeline(&key),
            key,
            proxy_representation: None,
            wildcard: false,
        }),
        _ => None,
    }
}

#[cfg(test)]
pub fn test_grant() -> AccessGrant {
    AccessGrant {
        key: ResourceKey {
            vhost: 0,
            method: String::new(),
            url_path: String::new(),
            fs_path: None,
            proxy_url: None,
            cache_host: None,
            cache_path: None,
            cache_query: None,
            identity: None,
            file_dev: None,
            file_ino: None,
            backend_target: None,
            policy_fingerprint: None,
        },
        // Unit tests deliberately use a fully-bound wildcard capability to
        // exercise downstream protocol behavior without reproducing access
        // evaluation in every fixture.
        pipeline: vapache_verified::TransformCapability {
            target_bound: true,
            authorized: true,
            inode_bound: true,
            backend_bound: true,
            representation_bound: true,
            policy_bound: true,
        },
        proxy_representation: None,
        wildcard: true,
    }
}

pub(crate) fn check_grant(
    scope: &Scope,
    req: &Request,
    peer: IpAddr,
    identity: Option<&Identity>,
    url_path: &str,
    fs_path: Option<&Path>,
    key: ResourceKey,
) -> Result<AccessGrant, Access> {
    match check(scope, req, peer, identity, url_path, fs_path) {
        Access::Allowed => Ok(AccessGrant {
            pipeline: authorized_pipeline(&key),
            key,
            proxy_representation: None,
            wildcard: false,
        }),
        other => Err(other),
    }
}

pub fn check(
    scope: &Scope,
    req: &Request,
    peer: IpAddr,
    identity: Option<&Identity>,
    url_path: &str,
    fs_path: Option<&Path>,
) -> Access {
    if scope.conditional_error {
        return Access::Misconfigured;
    }
    if !vapache_verified::authz_configuration_admit(
        scope.authorization.auth_type.is_some(),
        scope.authorization.requires.is_some(),
    ) {
        return Access::Misconfigured;
    }
    let host = scope
        .authorization
        .legacy
        .as_ref()
        .map(|_| legacy_check(scope, peer, &req.method));
    // Compiled configurations always bind the effective document root. Keep
    // synthetic scopes useful for non-filesystem authorization tests, but
    // give their expression evaluator an empty relative sentinel: file tests
    // then fail confinement instead of widening to the filesystem root.
    let docroot = scope
        .content_policy
        .document_root
        .as_deref()
        .unwrap_or_else(|| Path::new(""));
    let auth = check_requires(scope, req, peer, identity, docroot, url_path, fs_path);
    let satisfy = scope
        .authorization
        .legacy
        .as_ref()
        .map(|legacy| legacy.method_satisfy(&req.method))
        .unwrap_or(Satisfy::All);

    match satisfy {
        // Satisfy All (the default): the host-level check and the
        // authentication/authorization check must both pass.
        Satisfy::All => {
            if host == Some(Access::Denied) {
                Access::Denied
            } else {
                auth
            }
        }
        // Satisfy Any: a passing host check suppresses authentication.
        // Otherwise authorization may still grant access.
        Satisfy::Any => {
            if host != Some(Access::Denied) {
                Access::Allowed
            } else {
                auth
            }
        }
    }
}

/// Evaluate `<Require>` rules.  Rules are an implicit `RequireAny`; a rule
/// limited to another method is skipped.  If every rule was skipped, Apache's
/// root authorization section is itself method-limited and grants access.
fn check_requires(
    scope: &Scope,
    req: &Request,
    peer: IpAddr,
    identity: Option<&Identity>,
    docroot: &Path,
    url_path: &str,
    fs_path: Option<&Path>,
) -> Access {
    if req.policy_budget_failed() {
        return Access::Denied;
    }
    let Some(policy) = &scope.authorization.requires else {
        return Access::Allowed;
    };
    let env = scope.authorization_env(req, url_path, peer);
    if req.policy_budget_failed() {
        return Access::Denied;
    }
    match eval_policy(
        policy, req, peer, identity, &env, true, docroot, url_path, fs_path,
    ) {
        PolicyResult::Granted => Access::Allowed,
        // At the root, Apache treats a neutral authorization result as a
        // failure (403), never as an implicit grant.
        PolicyResult::Denied | PolicyResult::Neutral => Access::Denied,
        PolicyResult::AuthRequired => Access::AuthRequired,
    }
}

/// Evaluate an authorization policy.  `parent_and` mirrors Apache's section
/// logic: a method-limited section that does not apply is `GRANTED` under an
/// AND parent and `NEUTRAL` under an OR parent.
fn eval_policy(
    policy: &AuthPolicy,
    req: &Request,
    peer: IpAddr,
    identity: Option<&Identity>,
    env: &[(String, Vec<u8>)],
    parent_and: bool,
    docroot: &Path,
    url_path: &str,
    fs_path: Option<&Path>,
) -> PolicyResult {
    match policy {
        AuthPolicy::List(entries) => {
            let mut matched = false;
            let mut auth_required = false;
            for entry in entries {
                if !entry.applies(&req.method) {
                    continue;
                }
                matched = true;
                match eval_node(
                    &entry.node,
                    req,
                    peer,
                    identity,
                    env,
                    docroot,
                    url_path,
                    fs_path,
                ) {
                    PolicyResult::Granted => return PolicyResult::Granted,
                    PolicyResult::Denied => {}
                    PolicyResult::AuthRequired => auth_required = true,
                    PolicyResult::Neutral => {}
                }
            }
            if !matched {
                return if parent_and {
                    PolicyResult::Granted
                } else {
                    PolicyResult::Neutral
                };
            }
            if auth_required {
                PolicyResult::AuthRequired
            } else {
                PolicyResult::Denied
            }
        }
        AuthPolicy::And(a, b) => combine_and(
            eval_policy(
                a, req, peer, identity, env, true, docroot, url_path, fs_path,
            ),
            eval_policy(
                b, req, peer, identity, env, true, docroot, url_path, fs_path,
            ),
        ),
        AuthPolicy::Or(a, b) => combine_or(
            eval_policy(
                a, req, peer, identity, env, false, docroot, url_path, fs_path,
            ),
            eval_policy(
                b, req, peer, identity, env, false, docroot, url_path, fs_path,
            ),
        ),
    }
}

/// Evaluate legacy `Order`/`Allow`/`Deny` rules for this request method.
fn legacy_check(scope: &Scope, peer: IpAddr, method: &str) -> Access {
    let Some(legacy) = &scope.authorization.legacy else {
        return Access::Allowed;
    };
    let order = legacy.method_order(method);
    let allow = legacy
        .allow
        .iter()
        .any(|entry| entry.applies(method) && entry.value.matches(peer));
    let deny = legacy
        .deny
        .iter()
        .any(|entry| entry.applies(method) && entry.value.matches(peer));
    match order {
        // allow,deny: default deny; deny overrides allow.
        Order::AllowDeny => {
            if allow && !deny {
                Access::Allowed
            } else {
                Access::Denied
            }
        }
        // deny,allow: default allow; allow overrides deny.
        Order::DenyAllow => {
            if deny && !allow {
                Access::Denied
            } else {
                Access::Allowed
            }
        }
    }
}

fn eval_node(
    node: &RequireNode,
    req: &Request,
    peer: IpAddr,
    identity: Option<&Identity>,
    env: &[(String, Vec<u8>)],
    docroot: &Path,
    url_path: &str,
    fs_path: Option<&Path>,
) -> PolicyResult {
    // Every authorization node is an instruction in the request's compiled
    // policy program.  This also bounds wide lists of constant providers,
    // which do not otherwise perform a matcher or an expansion to debit the
    // shared request meter.
    if req.charge_policy_work(1).is_err() {
        return PolicyResult::Denied;
    }
    match node {
        RequireNode::Provider(r) => {
            eval_require(r, req, peer, identity, env, docroot, url_path, fs_path)
        }
        RequireNode::All(items) => {
            // RequireAll: all children must pass, and at least one must grant.
            let mut result = PolicyResult::Neutral;
            for item in items {
                result = combine_and(
                    result,
                    eval_node(item, req, peer, identity, env, docroot, url_path, fs_path),
                );
                if result == PolicyResult::Denied {
                    return PolicyResult::Denied;
                }
            }
            result
        }
        RequireNode::Any(items) => {
            let mut result = PolicyResult::Neutral;
            for item in items {
                result = combine_or(
                    result,
                    eval_node(item, req, peer, identity, env, docroot, url_path, fs_path),
                );
                if result == PolicyResult::Granted {
                    return PolicyResult::Granted;
                }
            }
            result
        }
        RequireNode::None(items) => {
            // Apache's <RequireNone> fails when *any* child provider is
            // satisfied.  Aggregate the children as an OR of positive hits
            // first; combining them with AND let one denied sibling erase a
            // granted child and turned the group into an allow (F46/I43).
            let results: Vec<PolicyResult> = items
                .iter()
                .map(|item| eval_node(item, req, peer, identity, env, docroot, url_path, fs_path))
                .collect();
            require_none_multi(&results)
        }
    }
}

fn eval_require(
    r: &Require,
    req: &Request,
    peer: IpAddr,
    identity: Option<&Identity>,
    env: &[(String, Vec<u8>)],
    docroot: &Path,
    url_path: &str,
    fs_path: Option<&Path>,
) -> PolicyResult {
    // Apache's negated providers can deny or stay neutral, but can never
    // independently grant access.
    fn decide(hit: bool, negate: bool) -> PolicyResult {
        if negate {
            if hit {
                PolicyResult::Denied
            } else {
                PolicyResult::Neutral
            }
        } else if hit {
            PolicyResult::Granted
        } else {
            PolicyResult::Denied
        }
    }
    fn expand_operand(
        operand: &str,
        req: &Request,
        env: &[(String, Vec<u8>)],
        peer: IpAddr,
        url_path: &str,
    ) -> Result<Vec<u8>, ()> {
        fn append(out: &mut Vec<u8>, value: &[u8], req: &Request) -> Result<(), ()> {
            if !vapache_verified::bounded_expansion_append_admit(
                out.len() as u64,
                value.len() as u64,
                crate::resource::MAX_POLICY_VALUE_BYTES,
            ) || req.charge_policy_expansion(value.len() as u64).is_err()
            {
                // Ensure an individual-value failure also poisons the shared
                // request budget when the aggregate counter still had room.
                let _ = req.charge_policy_expansion(
                    crate::resource::MAX_POLICY_VALUE_BYTES.saturating_add(1),
                );
                return Err(());
            }
            out.extend_from_slice(value);
            Ok(())
        }

        let mut out = Vec::new();
        let mut rest = operand;
        while let Some(start) = rest.find("%{") {
            append(&mut out, rest[..start].as_bytes(), req)?;
            let after = &rest[start + 2..];
            let end = after.find('}').ok_or(())?;
            let variable = &after[..end];
            let upper = variable.to_ascii_uppercase();
            let value: Vec<u8> = match upper.as_str() {
                "HTTP_HOST" => req
                    .header("host")
                    .map(vapache_verified::guard_header_bytes)
                    .unwrap_or_default(),
                "REMOTE_ADDR" => peer.to_string().into_bytes(),
                "REQUEST_URI" => url_path.as_bytes().to_vec(),
                "REQUEST_METHOD" => req.method.as_bytes().to_vec(),
                _ if upper.starts_with("HTTP:") => req
                    .header(&variable[5..].to_ascii_lowercase())
                    .map(vapache_verified::guard_header_bytes)
                    .unwrap_or_default(),
                _ if upper.starts_with("ENV:") => env
                    .iter()
                    .rev()
                    .find(|(name, _)| name.eq_ignore_ascii_case(&variable[4..]))
                    .map(|(_, value)| value.clone())
                    .unwrap_or_default(),
                _ => return Err(()),
            };
            append(&mut out, &value, req)?;
            rest = &after[end + 1..];
        }
        append(&mut out, rest.as_bytes(), req)?;
        Ok(out)
    }

    fn expanded_words(
        operands: &[String],
        req: &Request,
        env: &[(String, Vec<u8>)],
        peer: IpAddr,
        url_path: &str,
    ) -> Result<Vec<String>, ()> {
        let mut words = Vec::new();
        for operand in operands {
            // mod_authz_host/user/groupfile evaluate the string expression
            // and then consume its result with ap_getword_conf(), not a
            // whitespace-only split. Reuse the configuration-word tokenizer
            // so quoted dynamic results have the same operand boundaries.
            let expanded = String::from_utf8(expand_operand(operand, req, env, peer, url_path)?)
                .map_err(|_| ())?;
            words.extend(crate::config_frontend::tokenize(&expanded).map_err(|_| ())?);
        }
        Ok(words)
    }
    match r {
        Require::AllGranted => PolicyResult::Granted,
        Require::AllDenied => PolicyResult::Denied,
        Require::Ip { negate, nets } => {
            let hit = nets.iter().any(|(n, b)| ip_in_net(peer, *n, *b));
            decide(hit, *negate)
        }
        Require::Local { negate } => decide(canonical_ip(peer).is_loopback(), *negate),
        Require::Host { negate, names } => {
            let Ok(names) = expanded_words(names, req, env, peer, url_path) else {
                return PolicyResult::Denied;
            };
            decide(reverse_dns_matches(peer, &names), *negate)
        }
        Require::Method { negate, methods } => {
            decide(methods.iter().any(|m| same_method(m, &req.method)), *negate)
        }
        Require::ValidUser { negate } => {
            // `Require not valid-user` must carry its negation.  Like every
            // other negated provider it can deny or stay neutral, but cannot
            // independently grant access.
            let hit = identity.is_some();
            if *negate {
                decide(hit, true)
            } else if hit {
                PolicyResult::Granted
            } else {
                PolicyResult::AuthRequired
            }
        }
        Require::User { negate, names } => {
            let Some(identity) = identity else {
                return PolicyResult::AuthRequired;
            };
            let Ok(names) = expanded_words(names, req, env, peer, url_path) else {
                return PolicyResult::Denied;
            };
            decide(names.iter().any(|n| n == &identity.user), *negate)
        }
        Require::Group { negate, names } => {
            let Some(identity) = identity else {
                return PolicyResult::AuthRequired;
            };
            let Ok(names) = expanded_words(names, req, env, peer, url_path) else {
                return PolicyResult::Denied;
            };
            decide(
                identity.groups.iter().any(|g| names.iter().any(|n| n == g)),
                *negate,
            )
        }
        Require::Env { negate, names } => {
            // mod_authz_core grants the provider when any listed variable is
            // present. This remains one provider result, so negation applies
            // to the aggregate rather than only the first operand.
            let hit = names.iter().any(|name| {
                env.iter()
                    .rev()
                    .any(|(existing, _)| existing.eq_ignore_ascii_case(name))
            });
            decide(hit, *negate)
        }
        Require::Expr { negate, expr } => {
            // F63/I63: the filesystem path binds `%{REQUEST_FILENAME}`/
            // `%{SCRIPT_FILENAME}`; unbound variables fail closed in the
            // evaluator.
            let mut ctx =
                crate::expr::Context::new(req, env, peer, docroot, url_path).with_fs_path(fs_path);
            match expr.eval(&mut ctx) {
                Ok(value) => decide(value.truthy(), *negate),
                // An engine/context error is a deny, not a boolean false:
                // `Require not expr` must never grant because evaluation
                // failed (P15-C).
                Err(_) => PolicyResult::Denied,
            }
        }
        Require::Unsupported(_) => PolicyResult::Denied,
    }
}

fn same_method(configured: &str, request: &str) -> bool {
    // Apache maps HEAD onto GET's method number.
    let configured = if configured == "HEAD" {
        "GET"
    } else {
        configured
    };
    let request = if request == "HEAD" { "GET" } else { request };
    configured == request
}

/// Canonicalize an IPv4-mapped IPv6 address to IPv4 before it is used for an
/// authorization or identity decision.  A dual-stack listener reports IPv4
/// peers as `::ffff:a.b.c.d`; without this step IPv4 `Require` networks and
/// `Require local` see a different identity (F49/I46).
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match vapache_verified::ipv4_mapped_to_v4(u128::from(v6)) {
            Some(v4) => IpAddr::V4(Ipv4Addr::from(v4)),
            None => ip,
        },
        IpAddr::V4(_) => ip,
    }
}

pub fn canonical_socket_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonical_ip(addr.ip()), addr.port())
}

pub fn ip_in_net(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (canonical_ip(ip), canonical_ip(net)) {
        (IpAddr::V4(a), IpAddr::V4(n)) => ipv4_in_net(u32::from(a), u32::from(n), bits),
        (IpAddr::V6(a), IpAddr::V6(n)) => ipv6_in_net(u128::from(a), u128::from(n), bits),
        _ => false,
    }
}

fn reverse_dns_matches(ip: IpAddr, names: &[String]) -> bool {
    const MAX_DNS_REQUIRE_NAMES: usize = 256;
    const MAX_DNS_REQUIRE_BYTES: usize = 64 * 1024;

    struct DnsJob {
        ip: IpAddr,
        deadline: Instant,
        reply: mpsc::SyncSender<Option<String>>,
    }

    fn isolated_lookup(job: &DnsJob, unreaped: &mut Vec<std::process::Child>) -> Option<String> {
        unreaped.retain_mut(|child| match child.try_wait() {
            Ok(Some(_)) => false,
            Ok(None) | Err(_) => true,
        });
        if unreaped.len() >= 2 || Instant::now() >= job.deadline {
            return None;
        }
        let current = std::env::current_exe().ok()?;
        let executable = current
            .parent()
            .filter(|parent| parent.file_name().is_some_and(|name| name == "deps"))
            .and_then(Path::parent)
            .map(|parent| parent.join("vapached"))
            .filter(|candidate| candidate.is_file())
            .unwrap_or(current);
        let mut child = std::process::Command::new(executable)
            .arg("--vapache-reverse-resolver-worker")
            .arg(job.ip.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return None;
                    }
                    let output = child.wait_with_output().ok()?;
                    if output.stdout.len() > 254 {
                        return None;
                    }
                    let host = std::str::from_utf8(&output.stdout).ok()?.trim();
                    if host.is_empty()
                        || host.len() > 253
                        || host.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
                    {
                        return None;
                    }
                    return Some(host.to_string());
                }
                Ok(None) => {}
                Err(_) => return None,
            }
            if Instant::now() >= job.deadline {
                let _ = child.kill();
                if !child.try_wait().is_ok_and(|status| status.is_some()) {
                    unreaped.push(child);
                }
                return None;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn sender() -> &'static mpsc::SyncSender<DnsJob> {
        static SENDER: OnceLock<mpsc::SyncSender<DnsJob>> = OnceLock::new();
        SENDER.get_or_init(|| {
            const DNS_WORKERS: usize = 8;
            const DNS_QUEUE: usize = 64;
            let (tx, rx) = mpsc::sync_channel::<DnsJob>(DNS_QUEUE);
            let rx = Arc::new(Mutex::new(rx));
            for index in 0..DNS_WORKERS {
                let rx = Arc::clone(&rx);
                let _ = std::thread::Builder::new()
                    .name(format!("reverse-dns-{index}"))
                    .spawn(move || {
                        let mut unreaped = Vec::new();
                        loop {
                            let job = {
                                let receiver = rx.lock().unwrap_or_else(|error| error.into_inner());
                                receiver.recv()
                            };
                            let Ok(job) = job else {
                                break;
                            };
                            let result = isolated_lookup(&job, &mut unreaped);
                            let _ = job.reply.try_send(result);
                        }
                    });
            }
            tx
        })
    }

    let names_bytes = names
        .iter()
        .try_fold(0usize, |total, name| total.checked_add(name.len()));
    if names.len() > MAX_DNS_REQUIRE_NAMES
        || names_bytes.is_none_or(|bytes| bytes > MAX_DNS_REQUIRE_BYTES)
    {
        return false;
    }
    let Some(_expensive) = crate::resource::try_expensive() else {
        return false;
    };

    let (reply, result) = mpsc::sync_channel(1);
    let job = DnsJob {
        ip: canonical_ip(ip),
        deadline: Instant::now() + Duration::from_secs(2),
        reply,
    };
    if sender().try_send(job).is_err() {
        return false;
    }
    result
        .recv_timeout(Duration::from_secs(2))
        .ok()
        .flatten()
        .is_some_and(|host| names.iter().any(|domain| hostname_in_domain(domain, &host)))
}

/// Hidden disposable-process entrypoint for `Require host`. Both PTR and
/// forward confirmation occur in this process, so a wedged libc/NSS resolver
/// can be killed without consuming one of the daemon's fixed workers forever.
pub fn reverse_resolver_worker_main(ip: IpAddr) -> std::io::Result<()> {
    let ip = canonical_ip(ip);
    let host = reverse_dns(ip)?;
    if !forward_dns_confirms(&host, ip) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "reverse DNS result was not forward-confirmed",
        ));
    }
    println!("{host}");
    Ok(())
}

/// Exact port of mod_authz_host's `in_domain()`: operands are
/// case-insensitive suffixes, but a longer host must meet the suffix at a DNS
/// label boundary. A leading dot excludes the bare host and `*.` has no
/// wildcard meaning.
fn hostname_in_domain(domain: &str, host: &str) -> bool {
    let domain = domain.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if host.len() < domain.len() || !host.ends_with(&domain) {
        return false;
    }
    host.len() == domain.len()
        || domain.starts_with('.')
        || host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

fn forward_dns_confirms(host: &str, ip: IpAddr) -> bool {
    // Confirm forward resolution (FCrDNS).
    use std::net::ToSocketAddrs;
    match (host, 0).to_socket_addrs() {
        Ok(addrs) => addrs.into_iter().any(|a| a.ip() == ip),
        Err(_) => false,
    }
}

fn reverse_dns(ip: IpAddr) -> Result<String, std::io::Error> {
    let sa = std::net::SocketAddr::new(ip, 0);
    let (storage, len) = socket_addr_to_storage(&sa);
    let mut host = [0i8; libc::NI_MAXHOST as usize];
    let rc = unsafe {
        libc::getnameinfo(
            &storage as *const _ as *const libc::sockaddr,
            len,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let c = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
    Ok(c.to_string_lossy().into_owned())
}

fn socket_addr_to_storage(sa: &std::net::SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match sa {
        std::net::SocketAddr::V4(v4) => {
            let s = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &s as *const _ as *const u8,
                    &mut storage as *mut _ as *mut u8,
                    std::mem::size_of_val(&s),
                );
            }
            (storage, std::mem::size_of_val(&s) as libc::socklen_t)
        }
        std::net::SocketAddr::V6(v6) => {
            let s = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &s as *const _ as *const u8,
                    &mut storage as *mut _ as *mut u8,
                    std::mem::size_of_val(&s),
                );
            }
            (storage, std::mem::size_of_val(&s) as libc::socklen_t)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthPolicy, RequireEntry};

    fn reqs(v: Vec<Require>) -> Option<AuthPolicy> {
        Some(AuthPolicy::List(
            v.into_iter()
                .map(|r| RequireEntry {
                    node: RequireNode::Provider(r),
                    limit: None,
                })
                .collect(),
        ))
    }

    fn nodes(v: Vec<RequireNode>) -> Option<AuthPolicy> {
        Some(AuthPolicy::List(
            v.into_iter()
                .map(|node| RequireEntry { node, limit: None })
                .collect(),
        ))
    }

    fn req(method: &str) -> Request {
        Request {
            method: method.into(),
            target: b"/".to_vec(),
            raw_path: b"/".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: Default::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    #[test]
    fn cidr() {
        assert!(ip_in_net(
            "10.1.2.3".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            8
        ));
        assert!(!ip_in_net(
            "11.1.2.3".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            8
        ));
        assert!(ip_in_net(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::".parse().unwrap(),
            32
        ));
        assert!(!ip_in_net(
            "192.0.2.1".parse().unwrap(),
            "2001:db8::".parse().unwrap(),
            32
        ));
    }

    #[test]
    fn require_ip_and_negation() {
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::Ip {
            negate: false,
            nets: vec![("10.0.0.0".parse().unwrap(), 8)],
        }]);
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "10.1.2.3".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "11.1.2.3".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );

        s.authorization.requires = nodes(vec![RequireNode::All(vec![
            RequireNode::Provider(Require::AllGranted),
            RequireNode::Provider(Require::Ip {
                negate: true,
                nets: vec![("10.0.0.0".parse().unwrap(), 8)],
            }),
        ])]);
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "10.1.2.3".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "11.1.2.3".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
    }

    #[test]
    fn auth_type_without_effective_require_is_misconfigured() {
        let mut scope = Scope::default();
        assert_eq!(
            check(
                &scope,
                &req("GET"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None,
            ),
            Access::Allowed
        );

        scope.conditional_error = true;
        assert_eq!(
            check(
                &scope,
                &req("GET"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None,
            ),
            Access::Misconfigured
        );
        scope.conditional_error = false;

        scope.authorization.auth_type = Some("Basic".into());
        assert_eq!(
            check(
                &scope,
                &req("GET"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None,
            ),
            Access::Misconfigured
        );

        scope.authorization.requires = reqs(vec![Require::AllGranted]);
        assert_eq!(
            check(
                &scope,
                &req("GET"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None,
            ),
            Access::Allowed
        );
    }

    #[test]
    fn dynamic_require_operands_share_the_request_expansion_budget() {
        let mut request = req("GET");
        request.headers.insert("x-expand", vec![b'a'; 8_000]);
        let operand = "%{HTTP:X-Expand}".repeat(256);
        let mut scope = Scope::default();
        scope.authorization.requires = reqs(vec![Require::User {
            negate: false,
            names: vec![operand],
        }]);
        let identity = Identity {
            user: "alice".into(),
            groups: Vec::new(),
        };
        assert_eq!(
            check(
                &scope,
                &request,
                "127.0.0.1".parse().unwrap(),
                Some(&identity),
                "/x",
                None,
            ),
            Access::Denied
        );
        assert!(request.policy_budget_failed());
    }

    #[test]
    fn cache_keys_keep_invalid_utf8_query_bytes_distinct() {
        // `from_utf8_lossy` maps both .FF and .FE to U+FFFD, which would
        // conflate distinct requests into one cache-resource identity; the
        // key therefore keeps the raw bytes.
        let mut lossy_ff = req("GET");
        lossy_ff.query = b"\xff".to_vec();
        let mut lossy_fe = req("GET");
        lossy_fe.query = b"\xfe".to_vec();
        let mut ff_again = req("GET");
        ff_again.query = b"\xff".to_vec();
        let mut valid = req("GET");
        valid.query = b"x=1".to_vec();

        assert_ne!(
            ResourceKey::cache(None, &lossy_ff, "h.test", "/p"),
            ResourceKey::cache(None, &lossy_fe, "h.test", "/p")
        );
        assert_eq!(
            ResourceKey::cache(None, &lossy_ff, "h.test", "/p"),
            ResourceKey::cache(None, &ff_again, "h.test", "/p")
        );
        // Equal valid queries still share an identity, and a different
        // query token remains distinct.
        assert_eq!(
            ResourceKey::cache(None, &valid, "h.test", "/p"),
            ResourceKey::cache(None, &valid, "h.test", "/p")
        );
        assert_ne!(
            ResourceKey::cache(None, &valid, "h.test", "/p"),
            ResourceKey::cache(None, &lossy_ff, "h.test", "/p")
        );
    }

    #[test]
    fn grant_binding_rejects_a_different_resource() {
        let req = req("GET");
        let scope = Scope::default();
        let allowed = ResourceKey::request(None, &req, "/a", None, None);
        let other = ResourceKey::request(None, &req, "/b", None, None);
        let grant = check_grant(
            &scope,
            &req,
            "127.0.0.1".parse().unwrap(),
            None,
            "/x",
            None,
            allowed,
        )
        .expect("allowed");
        let meta = std::fs::metadata("/proc/self/exe").expect("self metadata");
        assert!(grant.bind_file(&other, &meta).is_none());
    }

    #[test]
    fn satisfy_any_host_denial_falls_back_to_authorization() {
        use crate::config::{HostSpec, LegacyAccess, MethodScoped};
        let mut s = Scope::default();
        s.authorization.legacy = Some(LegacyAccess {
            satisfy: vec![MethodScoped {
                limit: None,
                value: Satisfy::Any,
            }],
            deny: vec![MethodScoped {
                limit: None,
                value: HostSpec::All,
            }],
            ..LegacyAccess::default()
        });
        s.authorization.requires = reqs(vec![Require::AllGranted]);
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "192.0.2.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
        s.authorization.requires = reqs(vec![Require::AllDenied]);
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "192.0.2.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );
    }

    #[test]
    fn method_limited_children_are_neutral_under_or_and_empty_any_is_denied() {
        use crate::config::MethodSet;
        let r = req("GET");
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let docroot = Path::new("/");
        let post = |node| {
            AuthPolicy::List(vec![RequireEntry {
                node,
                limit: Some(MethodSet::Only(vec!["POST".into()])),
            }])
        };
        let policy = AuthPolicy::Or(
            Box::new(post(RequireNode::Provider(Require::AllDenied))),
            Box::new(post(RequireNode::Provider(Require::AllGranted))),
        );
        assert_eq!(
            eval_policy(&policy, &r, peer, None, &[], false, docroot, "/x", None),
            PolicyResult::Neutral
        );
        assert_eq!(
            eval_node(
                &RequireNode::Any(vec![
                    RequireNode::Provider(Require::AllDenied),
                    RequireNode::Provider(Require::AllDenied),
                ]),
                &r,
                peer,
                None,
                &[],
                docroot,
                "/x",
                None,
            ),
            PolicyResult::Denied
        );
    }

    #[test]
    fn legacy_check_without_rules_allows() {
        let s = Scope::default();
        assert_eq!(
            legacy_check(&s, "127.0.0.1".parse().unwrap(), "GET"),
            Access::Allowed
        );
    }

    #[test]
    fn head_configured_for_get_and_host_provider_reverse_dns() {
        assert!(same_method("HEAD", "GET"));
        assert!(same_method("GET", "HEAD"));
        assert!(!same_method("POST", "GET"));

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let host = reverse_dns(ip).expect("reverse localhost");
        assert!(reverse_dns_matches(ip, &[host.clone()]));
        assert!(!reverse_dns_matches(ip, &[format!(".{host}")]));
        assert!(!reverse_dns_matches(
            ip,
            &[format!("*.not-{host}"), "definitely.invalid".into()]
        ));
        assert!(!reverse_dns_matches(ip, &["definitely.invalid".into()]));
        assert!(!reverse_dns_matches(
            "0.0.0.0".parse::<IpAddr>().unwrap(),
            &["anything".into()]
        ));
        assert!(!reverse_dns_matches(ip, &vec!["x".into(); 257]));
        assert!(!reverse_dns_matches(ip, &["x".repeat(64 * 1024 + 1)]));
        assert!(!forward_dns_confirms("\0", ip));
        let ip6: IpAddr = "::1".parse().unwrap();
        let host6 = reverse_dns(ip6).expect("reverse ipv6 localhost");
        assert!(reverse_dns_matches(ip6, &[host6]));
        assert!(reverse_dns("0.0.0.0".parse::<IpAddr>().unwrap()).is_err());

        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::Host {
            negate: false,
            names: vec!["localhost".into()],
        }]);
        let result = check(&s, &req("GET"), ip, None, "/x", None);
        assert!(matches!(result, Access::Allowed | Access::Denied));
    }

    #[test]
    fn apache_host_domain_matching_uses_dns_label_boundaries() {
        assert!(hostname_in_domain("example.test", "example.test"));
        assert!(hostname_in_domain("example.test", "WWW.Example.Test"));
        assert!(!hostname_in_domain("example.test", "notexample.test"));
        assert!(!hostname_in_domain(".example.test", "example.test"));
        assert!(hostname_in_domain(".example.test", "www.example.test"));
        assert!(!hostname_in_domain("*.example.test", "www.example.test"));
        assert!(hostname_in_domain("*.example.test", "*.example.test"));
    }

    #[test]
    fn require_none_denies_when_any_child_matches() {
        let mut s = Scope::default();
        let inside = "127.0.0.1".parse().unwrap();
        // Two block-list providers: loopback matches one but not the other.
        s.authorization.requires = nodes(vec![RequireNode::All(vec![
            RequireNode::Provider(Require::AllGranted),
            RequireNode::None(vec![
                RequireNode::Provider(Require::Ip {
                    negate: false,
                    nets: vec![("10.0.0.0".parse().unwrap(), 8)],
                }),
                RequireNode::Provider(Require::Ip {
                    negate: false,
                    nets: vec![("127.0.0.0".parse().unwrap(), 8)],
                }),
            ]),
        ])]);
        assert_eq!(
            check(&s, &req("GET"), inside, None, "/x", None),
            Access::Denied
        );
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "10.1.2.3".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "192.0.2.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );

        // Three providers where two match must deny as well.
        s.authorization.requires = nodes(vec![RequireNode::All(vec![
            RequireNode::Provider(Require::AllGranted),
            RequireNode::None(vec![
                RequireNode::Provider(Require::Ip {
                    negate: false,
                    nets: vec![("10.0.0.0".parse().unwrap(), 8)],
                }),
                RequireNode::Provider(Require::Ip {
                    negate: false,
                    nets: vec![("127.0.0.0".parse().unwrap(), 8)],
                }),
                RequireNode::Provider(Require::Ip {
                    negate: false,
                    nets: vec![("127.0.0.1".parse().unwrap(), 32)],
                }),
            ]),
        ])]);
        assert_eq!(
            check(&s, &req("GET"), inside, None, "/x", None),
            Access::Denied
        );

        // A granted child is not neutralized by a denied sibling.
        s.authorization.requires = nodes(vec![RequireNode::None(vec![
            RequireNode::Provider(Require::AllGranted),
            RequireNode::Provider(Require::AllDenied),
        ])]);
        assert_eq!(
            check(&s, &req("GET"), inside, None, "/x", None),
            Access::Denied
        );

        // No child satisfied means the negated group cannot grant by itself.
        s.authorization.requires = nodes(vec![RequireNode::None(vec![
            RequireNode::Provider(Require::AllDenied),
            RequireNode::Provider(Require::AllDenied),
        ])]);
        assert_eq!(
            check(&s, &req("GET"), inside, None, "/x", None),
            Access::Denied
        );
    }

    #[test]
    fn ipv4_mapped_peers_are_canonicalized_for_policy() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(canonical_ip(mapped), "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(
            canonical_ip("2001:db8::1".parse::<IpAddr>().unwrap()),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
        assert!(ip_in_net(mapped, "127.0.0.0".parse().unwrap(), 8));
        assert!(!ip_in_net(
            "::ffff:192.0.2.1".parse().unwrap(),
            "127.0.0.0".parse().unwrap(),
            8
        ));

        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::Local { negate: false }]);
        assert_eq!(
            check(&s, &req("GET"), mapped, None, "/x", None),
            Access::Allowed
        );
        s.authorization.requires = nodes(vec![RequireNode::All(vec![
            RequireNode::Provider(Require::AllGranted),
            RequireNode::Provider(Require::Local { negate: true }),
        ])]);
        assert_eq!(
            check(&s, &req("GET"), mapped, None, "/x", None),
            Access::Denied
        );
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "::ffff:192.0.2.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
    }

    #[test]
    fn access_grant_is_only_created_for_allowed() {
        assert!(grant_if_allowed(
            Access::Allowed,
            ResourceKey::request(None, &req("GET"), "/", None, None)
        )
        .is_some());
        assert!(grant_if_allowed(
            Access::Denied,
            ResourceKey::request(None, &req("GET"), "/", None, None)
        )
        .is_none());
        assert!(grant_if_allowed(
            Access::AuthRequired,
            ResourceKey::request(None, &req("GET"), "/", None, None)
        )
        .is_none());
    }

    #[test]
    fn access_grants_are_bound_to_the_authorized_resource() {
        let req = req("GET");
        let peer = "127.0.0.1".parse().unwrap();
        let scope = Scope::default();
        let a = ResourceKey::request(None, &req, "/public/a", None, None);
        let b = ResourceKey::request(None, &req, "/private/b", None, None);
        let grant = check_grant(&scope, &req, peer, None, "/x", None, a.clone()).expect("allowed");
        assert!(grant.require(&a));
        assert!(!grant.require(&b));
    }

    #[test]
    fn file_binding_records_the_opened_inode() {
        let req = req("GET");
        let peer = "127.0.0.1".parse().unwrap();
        let scope = Scope::default();
        let key = ResourceKey::request(None, &req, "/file", None, None);
        let grant =
            check_grant(&scope, &req, peer, None, "/x", None, key.clone()).expect("allowed");
        let meta = std::fs::metadata("/proc/self/exe").expect("self metadata");
        let bound = grant.bind_file(&key, &meta).expect("file bound");
        assert_eq!(bound.key().file_dev, Some(meta.dev()));
        assert_eq!(bound.key().file_ino, Some(meta.ino()));
        assert!(!bound.require(&key));
    }

    #[test]
    fn transform_sink_gate_requires_each_concrete_binding() {
        let req = req("GET");
        let peer = "127.0.0.1".parse().unwrap();
        let scope = Scope::default();
        let key = ResourceKey::request(
            None,
            &req,
            "/script.php",
            Some(Path::new("/proc/self/exe")),
            Some("fcgi://backend/script.php"),
        );
        let grant = check_grant(
            &scope,
            &req,
            peer,
            None,
            "/script.php",
            Some(Path::new("/proc/self/exe")),
            key.clone(),
        )
        .expect("allowed");
        assert!(!grant.require_sink(&key, vapache_verified::TransformSink::StaticFile));
        assert!(!grant.require_sink(&key, vapache_verified::TransformSink::Proxy));

        let proxy_bound = grant
            .bind_proxy(&key, "backend.test", 8080, false, "/upstream.php")
            .expect("proxy endpoint and representation bound");
        let proxy_key = proxy_bound.key().clone();
        assert!(proxy_bound.require_proxy_sink(
            &proxy_key,
            "backend.test",
            8080,
            false,
            "/upstream.php"
        ));
        assert!(!proxy_bound.require_proxy_sink(
            &proxy_key,
            "backend.test",
            8080,
            false,
            "/different-upstream.php"
        ));
        let mut retargeted_front = proxy_key.clone();
        retargeted_front.url_path = "/different.php".into();
        assert!(
            !proxy_bound.require_sink(&retargeted_front, vapache_verified::TransformSink::Proxy)
        );
        let mut retargeted_backend = proxy_key;
        retargeted_backend.backend_target = Some("different-backend".into());
        assert!(
            !proxy_bound.require_sink(&retargeted_backend, vapache_verified::TransformSink::Proxy)
        );

        let meta = std::fs::metadata("/proc/self/exe").expect("self metadata");
        let file_bound = grant.bind_file(&key, &meta).expect("file bound");
        let file_key = file_bound.key().clone();
        assert!(file_bound.require_sink(&file_key, vapache_verified::TransformSink::LocalCgi));
        assert!(!file_bound.require_sink(&file_key, vapache_verified::TransformSink::FastCgi));

        let backend_bound = file_bound
            .bind_backend(&file_key, "fcgi-backend".into())
            .expect("backend bound");
        let backend_key = backend_bound.key().clone();
        assert!(backend_bound.require_sink(&backend_key, vapache_verified::TransformSink::FastCgi));

        let mut other = backend_key;
        other.url_path = "/different.php".into();
        assert!(!backend_bound.require_sink(&other, vapache_verified::TransformSink::FastCgi));
    }

    #[test]
    fn cache_sink_requires_a_policy_fingerprint() {
        let req = req("GET");
        let scope = Scope::default();
        let plain = ResourceKey::cache(None, &req, "example.test", "/a");
        let plain_grant = check_grant(
            &scope,
            &req,
            "127.0.0.1".parse().unwrap(),
            None,
            "/a",
            None,
            plain.clone(),
        )
        .unwrap();
        assert!(!plain_grant.require_sink(&plain, vapache_verified::TransformSink::Cache));

        let policy = ResourceKey::cache_policy(None, &req, "example.test", "/a", [7; 32]);
        let policy_grant = check_grant(
            &scope,
            &req,
            "127.0.0.1".parse().unwrap(),
            None,
            "/a",
            None,
            policy.clone(),
        )
        .unwrap();
        assert!(policy_grant.require_sink(&policy, vapache_verified::TransformSink::Cache));
    }

    #[test]
    fn negated_valid_user_carries_its_negation() {
        let r = req("GET");
        let peer = "127.0.0.1".parse().unwrap();
        let docroot = Path::new("/");
        let identity = Identity {
            user: "alice".into(),
            groups: Vec::new(),
        };
        assert_eq!(
            eval_require(
                &Require::ValidUser { negate: false },
                &r,
                peer,
                Some(&identity),
                &[],
                docroot,
                "/x",
                None,
            ),
            PolicyResult::Granted
        );
        assert_eq!(
            eval_require(
                &Require::ValidUser { negate: true },
                &r,
                peer,
                Some(&identity),
                &[],
                docroot,
                "/x",
                None,
            ),
            PolicyResult::Denied
        );
        assert_eq!(
            eval_require(
                &Require::ValidUser { negate: true },
                &r,
                peer,
                None,
                &[],
                docroot,
                "/x",
                None,
            ),
            PolicyResult::Neutral
        );
    }

    #[test]
    fn require_env_uses_apr_table_case_insensitive_names() {
        let request = req("GET");
        let peer = "127.0.0.1".parse().unwrap();
        let env = vec![("UPPER_GATE".to_string(), b"1".to_vec())];
        let provider = |negate| Require::Env {
            negate,
            names: vec!["upper_gate".into()],
        };
        assert_eq!(
            eval_require(
                &provider(false),
                &request,
                peer,
                None,
                &env,
                Path::new("/"),
                "/x",
                None,
            ),
            PolicyResult::Granted
        );
        assert_eq!(
            eval_require(
                &provider(true),
                &request,
                peer,
                None,
                &env,
                Path::new("/"),
                "/x",
                None,
            ),
            PolicyResult::Denied
        );
    }

    #[test]
    fn require_local() {
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::Local { negate: false }]);
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "10.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );
        s.authorization.requires = nodes(vec![RequireNode::All(vec![
            RequireNode::Provider(Require::AllGranted),
            RequireNode::Provider(Require::Local { negate: true }),
        ])]);
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "10.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
    }

    #[test]
    fn multiple_requires_are_an_implicit_any() {
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![
            Require::Ip {
                negate: false,
                nets: vec![("10.0.0.0".parse().unwrap(), 8)],
            },
            Require::Local { negate: false },
        ]);
        // Localhost is not in 10/8, but the second provider is enough.
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "192.0.2.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );
        // A single matching provider among deny-all siblings still wins.
        s.authorization.requires = reqs(vec![Require::AllDenied, Require::AllGranted]);
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "192.0.2.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
    }

    #[test]
    fn legacy_order_allow_deny() {
        use crate::config::{HostSpec, LegacyAccess, MethodScoped};
        let mut s = Scope::default();
        s.authorization.legacy = Some(LegacyAccess {
            order: vec![MethodScoped {
                limit: None,
                value: Order::AllowDeny,
            }],
            allow: vec![MethodScoped {
                limit: None,
                value: HostSpec::All,
            }],
            deny: vec![MethodScoped {
                limit: None,
                value: HostSpec::Net("10.0.0.0".parse().unwrap(), 8),
            }],
            ..LegacyAccess::default()
        });
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "10.1.2.3".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "192.0.2.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
    }

    #[test]
    fn legacy_order_deny_allow() {
        use crate::config::{HostSpec, LegacyAccess, MethodScoped};
        let mut s = Scope::default();
        s.authorization.legacy = Some(LegacyAccess {
            order: vec![MethodScoped {
                limit: None,
                value: Order::DenyAllow,
            }],
            allow: vec![MethodScoped {
                limit: None,
                value: HostSpec::Net("10.0.0.0".parse().unwrap(), 8),
            }],
            deny: vec![MethodScoped {
                limit: None,
                value: HostSpec::All,
            }],
            ..LegacyAccess::default()
        });
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "10.1.2.3".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "192.0.2.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );
    }

    #[test]
    fn empty_scope_allows() {
        let s = Scope::default();
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
    }

    #[test]
    fn all_granted_and_denied() {
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::AllGranted]);
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
        s.authorization.requires = reqs(vec![Require::AllDenied]);
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );
    }

    #[test]
    fn unsupported_denies() {
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::Unsupported("x".into())]);
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );
    }

    #[test]
    fn nested_require_groups() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let mut s = Scope::default();
        s.authorization.requires = nodes(vec![RequireNode::All(vec![
            RequireNode::Provider(Require::AllGranted),
            RequireNode::Provider(Require::Local { negate: false }),
        ])]);
        assert_eq!(
            check(&s, &req("GET"), peer, None, "/x", None),
            Access::Allowed
        );
        s.authorization.requires = nodes(vec![RequireNode::All(vec![
            RequireNode::Provider(Require::AllGranted),
            RequireNode::Provider(Require::AllDenied),
        ])]);
        assert_eq!(
            check(&s, &req("GET"), peer, None, "/x", None),
            Access::Denied
        );

        s.authorization.requires = nodes(vec![RequireNode::Any(vec![
            RequireNode::Provider(Require::AllDenied),
            RequireNode::Provider(Require::Local { negate: false }),
        ])]);
        assert_eq!(
            check(&s, &req("GET"), peer, None, "/x", None),
            Access::Allowed
        );

        s.authorization.requires = nodes(vec![RequireNode::None(vec![RequireNode::Provider(
            Require::AllGranted,
        )])]);
        assert_eq!(
            check(&s, &req("GET"), peer, None, "/x", None),
            Access::Denied
        );
        s.authorization.requires = nodes(vec![RequireNode::None(vec![RequireNode::Provider(
            Require::AllDenied,
        )])]);
        // A negated-only group is neutral; at the root Apache denies.
        assert_eq!(
            check(&s, &req("GET"), peer, None, "/x", None),
            Access::Denied
        );
    }

    #[test]
    fn require_method() {
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::Method {
            negate: false,
            methods: vec!["POST".into()],
        }]);
        assert_eq!(
            check(
                &s,
                &req("POST"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );
        assert_eq!(
            check(
                &s,
                &req("HEAD"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );

        s.authorization.requires = reqs(vec![Require::Method {
            negate: false,
            methods: vec!["GET".into()],
        }]);
        assert_eq!(
            check(
                &s,
                &req("HEAD"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
    }

    #[test]
    fn method_limited_requires_are_skipped_for_other_methods() {
        use crate::config::MethodSet;
        let mut s = Scope::default();
        s.authorization.requires = Some(AuthPolicy::List(vec![RequireEntry {
            node: RequireNode::Provider(Require::AllDenied),
            limit: Some(MethodSet::Only(vec!["POST".into()])),
        }]));
        // Only POST has an applicable authorization rule.
        assert_eq!(
            check(
                &s,
                &req("POST"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );
        assert_eq!(
            check(
                &s,
                &req("GET"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
        // GET and HEAD share a method number, matching Apache.
        s.authorization.requires = Some(AuthPolicy::List(vec![RequireEntry {
            node: RequireNode::Provider(Require::AllDenied),
            limit: Some(MethodSet::Only(vec!["GET".into()])),
        }]));
        assert_eq!(
            check(
                &s,
                &req("HEAD"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Denied
        );
        assert_eq!(
            check(
                &s,
                &req("POST"),
                "127.0.0.1".parse().unwrap(),
                None,
                "/x",
                None
            ),
            Access::Allowed
        );
    }

    #[test]
    fn auth_merging_and_or_combine_policies() {
        use crate::config::AuthMerging;
        let peer_inside: IpAddr = "10.1.2.3".parse().unwrap();
        let peer_outside: IpAddr = "192.0.2.1".parse().unwrap();
        let alice = Identity {
            user: "alice".into(),
            groups: Vec::new(),
        };
        let req = req("GET");

        let mut parent = Scope::default();
        parent.authorization.requires = reqs(vec![Require::Ip {
            negate: false,
            nets: vec![("10.0.0.0".parse().unwrap(), 8)],
        }]);
        let mut child = Scope::default();
        child.authorization.auth_merging = Some(AuthMerging::And);
        child.authorization.requires = reqs(vec![Require::User {
            negate: false,
            names: vec!["alice".into()],
        }]);
        let mut merged = parent.clone();
        merged.merge(&child);
        assert_eq!(
            check(&merged, &req, peer_inside, Some(&alice), "/x", None),
            Access::Allowed
        );
        assert_eq!(
            check(&merged, &req, peer_outside, Some(&alice), "/x", None),
            Access::Denied
        );
        assert_eq!(
            check(&merged, &req, peer_inside, None, "/x", None),
            Access::AuthRequired
        );

        let mut child = Scope::default();
        child.authorization.auth_merging = Some(AuthMerging::Or);
        child.authorization.requires = reqs(vec![Require::User {
            negate: false,
            names: vec!["alice".into()],
        }]);
        let mut merged = parent.clone();
        merged.merge(&child);
        assert_eq!(
            check(&merged, &req, peer_outside, Some(&alice), "/x", None),
            Access::Allowed
        );
        assert_eq!(
            check(&merged, &req, peer_inside, None, "/x", None),
            Access::Allowed
        );
        assert_eq!(
            check(&merged, &req, peer_outside, None, "/x", None),
            Access::AuthRequired
        );

        // Off (the default) keeps the child-only replacement semantics.
        let mut merged = parent.clone();
        let mut child = Scope::default();
        child.authorization.requires = reqs(vec![Require::User {
            negate: false,
            names: vec!["alice".into()],
        }]);
        merged.merge(&child);
        assert_eq!(
            check(&merged, &req, peer_inside, None, "/x", None),
            Access::AuthRequired
        );
    }

    #[test]
    fn satisfied_any_and_all_combine_host_and_auth() {
        use crate::config::{HostSpec, LegacyAccess, MethodScoped};
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        let mut s = Scope::default();
        s.authorization.requires = reqs(vec![Require::AllDenied]);
        s.authorization.legacy = Some(LegacyAccess {
            satisfy: vec![MethodScoped {
                limit: None,
                value: Satisfy::Any,
            }],
            allow: vec![MethodScoped {
                limit: None,
                value: HostSpec::All,
            }],
            ..LegacyAccess::default()
        });
        // Host access grants access, so the failing Require is bypassed.
        assert_eq!(
            check(&s, &req("GET"), peer, None, "/x", None),
            Access::Allowed
        );

        s.authorization.legacy.as_mut().unwrap().satisfy[0].value = Satisfy::All;
        s.authorization.legacy.as_mut().unwrap().allow.clear();
        // Default Order Deny,Allow allows the host; Satisfy All still needs
        // the authorization provider to pass.
        assert_eq!(
            check(&s, &req("GET"), peer, None, "/x", None),
            Access::Denied
        );

        s.authorization.requires = reqs(vec![Require::AllGranted]);
        assert_eq!(
            check(&s, &req("GET"), peer, None, "/x", None),
            Access::Allowed
        );

        // A host denial wins under Satisfy All even when Require passes.
        s.authorization
            .legacy
            .as_mut()
            .unwrap()
            .deny
            .push(MethodScoped {
                limit: None,
                value: HostSpec::All,
            });
        assert_eq!(
            check(&s, &req("GET"), peer, None, "/x", None),
            Access::Denied
        );
    }
}
