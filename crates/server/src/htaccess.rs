//! Per-directory `.htaccess` overrides.
//!
//! Only the security-sensitive and commonly used per-directory directives are
//! implemented.  Parsing is fail-closed: an unknown directive, an unsupported
//! section, an unreadable file or a file over the size limit produces a 500
//! instead of silently ignoring a possible access-control rule.

use crate::config::{
    normalize_rewrite_base, parse_filter_tokens, require_is_negated, require_node_is_negative,
    AlterEtag, AuthMerging, Capability, CompressionRule, ConditionBranch, Config, MatchKind,
    MethodSet, NonfatalMode, Order, OverrideCategories, OverrideCategory, OverrideMode,
    RequireNode, Satisfy, Scope, ScopeRule, VHost,
};
use crate::config_frontend::logical_lines;
use crate::config_payload::{PayloadArity, PayloadSchema, PayloadValueSchema, SealedPayload};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

const MAX_HTACCESS: u64 = 1024 * 1024;
const MAX_HTACCESS_LINE: usize = 8190;
const MAX_ACCESS_SECTION_DEPTH: usize = 64;
const MAX_ACCESS_INSTRUCTIONS_PER_FILE: usize = 8192;
const MAX_ACCESS_INSTRUCTIONS_PER_REQUEST: usize = 16_384;
const MAX_ACCESS_LAYERS: usize = 64;

pub fn apply(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    fs_path: &Path,
    url_path: &str,
) -> Result<(), String> {
    apply_req(
        cfg,
        vhost,
        scope,
        fs_path,
        url_path,
        None,
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
    )
}

pub fn apply_req(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    fs_path: &Path,
    url_path: &str,
    req: Option<&crate::http::Request>,
    peer: std::net::IpAddr,
) -> Result<(), String> {
    let mut config_files = Vec::new();
    let mut files = Vec::new();
    let mut deferred = Vec::new();
    let result = apply_req_deferred(
        cfg,
        vhost,
        scope,
        fs_path,
        url_path,
        req,
        peer,
        &mut files,
        &mut deferred,
        false,
        &mut config_files,
    );
    if result.is_err() {
        return result;
    }
    if let Some(req) = req {
        let fname = fs_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        let docroot = cfg.documentation_root_for(vhost);
        crate::config::apply_normal_rule_list(
            &files,
            scope,
            req,
            peer,
            &docroot,
            fs_path,
            url_path,
            &fname,
            &mut deferred,
        );
        deferred.sort_by_key(|rule| rule.order);
        let mut chain_state: HashMap<usize, bool> = HashMap::new();
        crate::config::apply_deferred_req(
            scope,
            &deferred,
            req,
            peer,
            &docroot,
            fs_path,
            url_path,
            &fname,
            &mut chain_state,
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn apply_req_deferred(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    fs_path: &Path,
    url_path: &str,
    req: Option<&crate::http::Request>,
    peer: std::net::IpAddr,
    files: &mut Vec<crate::config::ScopeRule>,
    deferred: &mut Vec<crate::config::ScopeRule>,
    apply_config_dirs: bool,
    config_files: &mut Vec<crate::config::ScopeRule>,
) -> Result<(), String> {
    apply_req_deferred_with_root(
        cfg,
        vhost,
        scope,
        fs_path,
        url_path,
        req,
        peer,
        files,
        deferred,
        apply_config_dirs,
        config_files,
        None,
    )
}

/// The access-file walk with the actual URL-mapping root supplied by
/// `map_path()`.  The root is only a URL/base label for `RewriteBase`; it is
/// never an authorization boundary.  Every ancestor directory participates
/// when its effective `AllowOverride` policy permits an access file (F50/F51).
#[allow(clippy::too_many_arguments)]
pub fn apply_req_deferred_with_root(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    fs_path: &Path,
    url_path: &str,
    req: Option<&crate::http::Request>,
    peer: std::net::IpAddr,
    files: &mut Vec<crate::config::ScopeRule>,
    deferred: &mut Vec<crate::config::ScopeRule>,
    apply_config_dirs: bool,
    config_files: &mut Vec<crate::config::ScopeRule>,
    mapping_root: Option<&Path>,
) -> Result<(), String> {
    let root = mapping_root
        .map(Path::to_path_buf)
        .unwrap_or_else(|| access_root_for(cfg, vhost, fs_path));
    let start = walk_start(fs_path);
    let dirs = ancestor_dirs(start)?;
    let mut access_layers = 0usize;
    let mut access_instructions = 0usize;
    let can_read_access = cfg.override_enabled && cfg.override_applicable(fs_path);
    let mut ignored_locations = Vec::new();
    for dir in dirs {
        // A PATH_INFO request maps to `script.cgi/info`; the immediate
        // "parent" is the script file, not a directory.  Only real
        // directories can contain access files.
        let is_dir = crate::files::is_dir_cached(&dir);
        if !is_dir {
            continue;
        }
        if apply_config_dirs {
            if let Some(req) = req {
                cfg.apply_directory_rules_for_dir(
                    vhost,
                    scope,
                    req,
                    peer,
                    &dir,
                    fs_path,
                    url_path,
                    config_files,
                    &mut ignored_locations,
                    deferred,
                );
            }
        }
        if !can_read_access {
            continue;
        }
        // Ancestors above every override-enabled directory cannot contribute
        // an access-file layer; skip their existence probes (F50 still covers
        // an enabled ancestor itself).
        if !cfg.access_file_dir_applicable(&dir) {
            continue;
        }
        let dir_scope = cfg.effective_scope_cached(vhost, &dir, url_path);
        let mode = dir_scope.override_policy.mode();
        let allow_list = dir_scope.override_policy.allow_list();
        let nonfatal = dir_scope.override_policy.nonfatal();
        if !mode.is_enabled() && allow_list.is_empty() {
            continue;
        }
        let mut selected = false;
        for name in cfg.access_file_names_for(&dir_scope) {
            let path = dir.join(&name);
            let opened = open_access_file(&path);
            let exists = !matches!(&opened, Ok(None));
            if !vapache_verified::access_file_candidate_admit(selected, exists) {
                continue;
            }
            selected = true;
            let delta = match opened {
                Ok(None) => continue, // coverage:ignore-line -- candidate_admit requires exists
                Err(e) => return Err(format!("{}: {e}", path.display())),
                Ok(Some(opened)) if !opened.meta.is_file() => {
                    return Err(format!("{}: not a regular file", path.display()))
                }
                Ok(Some(opened)) if opened.meta.len() > MAX_HTACCESS => {
                    return Err(format!("{}: access file too large", path.display()))
                }
                Ok(Some(opened)) => {
                    let identity =
                        crate::request_plan::LayerIdentity::new(&root, &dir, fs_path, url_path);
                    parse_cached(cfg, &path, mode, allow_list, nonfatal, &identity, opened)?
                }
            };
            if !vapache_verified::access_program_budget_admit(
                access_layers as u64,
                access_instructions as u64,
                delta.instruction_count as u64,
                MAX_ACCESS_LAYERS as u64,
                MAX_ACCESS_INSTRUCTIONS_PER_REQUEST as u64,
            ) {
                return Err("access-file request policy is too wide".into());
            }
            access_layers += 1;
            access_instructions += delta.instruction_count;
            scope.merge(&delta.scope);
            let fname = fs_path
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default();
            if req.is_some() {
                for rule in &delta.rules {
                    if rule.condition.is_some() || rule.branch != ConditionBranch::Normal {
                        deferred.push(rule.clone());
                    } else if matches!(
                        rule.kind,
                        MatchKind::Files(_) | MatchKind::FilesGlob(_) | MatchKind::FilesMatch(_)
                    ) {
                        files.push(rule.clone());
                    }
                }
            } else {
                crate::config::apply_rules_config(&delta.rules, scope, fs_path, url_path, &fname);
            }
        }
    }
    if apply_config_dirs {
        // F61-C: the file's own path is the final walked entry of the
        // Directory phase; apply wildcard `<Directory>` sections that match
        // it before the `<DirectoryMatch>` step.
        cfg.apply_directory_own_path_rules(
            vhost,
            scope,
            req,
            fs_path,
            url_path,
            config_files,
            &mut ignored_locations,
            deferred,
        );
        cfg.apply_directory_match_rules(
            vhost,
            scope,
            req,
            fs_path,
            url_path,
            config_files,
            &mut ignored_locations,
            deferred,
        );
    }
    Ok(())
}

fn walk_start(fs_path: &Path) -> &Path {
    if crate::files::is_dir_cached(fs_path) {
        fs_path
    } else {
        fs_path.parent().unwrap_or(fs_path)
    }
}

/// Every ancestor of `start`, from the filesystem root down to `start`.
/// Access-file authorization is directory-based, so this list is independent
/// of `DocumentRoot` and of any alias root (F50).
fn ancestor_dirs(start: &Path) -> Result<Vec<PathBuf>, String> {
    crate::util::bounded_policy_ancestor_dirs(start)
}

/// Fallback mapping root used only for URL/`RewriteBase` derivation when a
/// compatibility caller does not supply the root returned by `map_path()`.
/// For a document-root target this is `DocumentRoot`; for an
/// `Alias`/`ScriptAlias` target outside the document root it is the alias
/// target directory.  This value never bounds which ancestors contribute an
/// access file: Apache walks every ancestor whose `<Directory>` permits
/// `AllowOverride` (F50/F51).  Production authorization callers always pass
/// the URL-selected root explicitly.
fn access_root_for(cfg: &Config, vhost: Option<&VHost>, fs_path: &Path) -> PathBuf {
    let docroot = cfg.documentation_root_for(vhost);
    if fs_path == docroot || fs_path.starts_with(&docroot) {
        return docroot;
    }
    let base = vhost.map(|v| &v.scope).unwrap_or(&cfg.global);
    // Best-effort compatibility reconstruction only.  This containment-based
    // search cannot distinguish overlapping aliases; production callers use
    // the root selected by the URL mapping instead (F51/I48).
    for alias in &base.mapping_policy.aliases {
        if alias.fs_path.as_os_str().is_empty() {
            continue;
        }
        if fs_path == alias.fs_path || fs_path.starts_with(&alias.fs_path) {
            // A single-file target's access root is its parent directory.
            // Returning the file path made every `dir.starts_with(root)` test
            // fail and silently skipped the target directory's `.htaccess`
            // (F39/I36).  This applies to regex aliases too: a replacement
            // ending in `/` whose stable prefix names a file still has a file
            // base (F47/I44).
            if !alias.fs_path.is_dir() {
                return alias
                    .fs_path
                    .parent()
                    .unwrap_or(&alias.fs_path)
                    .to_path_buf();
            }
            return alias.fs_path.clone();
        }
    }
    docroot
}

/// Parse the access files that affect a request into pure layers.  Filesystem
/// I/O and parsing stay here; the merge is performed by
/// `policy_ref::effective_scope_with_layers`, so the interleaving has a single
/// implementation shared with the reference evaluator.
pub fn collect_layers(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
) -> Result<Vec<crate::policy_ref::AccessLayer>, String> {
    collect_layers_with_root(cfg, vhost, fs_path, url_path, None)
}

/// The lexical URL-mapped counterpart of a target directory when the mapping
/// root itself contains a symlink.  This is used only to inherit the
/// `AllowOverride` policy attached to the URL-mapped `<Directory>`; access
/// files are still read from the explicit target's own canonical directories
/// (F59/I60).
fn mapped_policy_dir(root: &Path, canonical_root: Option<&Path>, dir: &Path) -> Option<PathBuf> {
    if dir.starts_with(root) {
        return Some(dir.to_path_buf());
    }
    let canonical_root = canonical_root?;
    let rel = dir.strip_prefix(canonical_root).ok()?;
    Some(root.join(rel))
}

/// Collect access-file layers using the actual alias/mapping root selected by
/// `map_path()` for URL-base derivation.  The ancestor walk itself is not
/// bounded by that root (F50/F51) or by the lexical spelling of a symlinked
/// root (F59): layer files are always read from `fs_path`'s ancestors.
pub fn collect_layers_with_root(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
    mapping_root: Option<&Path>,
) -> Result<Vec<crate::policy_ref::AccessLayer>, String> {
    collect_layers_with_root_inner(cfg, vhost, fs_path, url_path, mapping_root, None)
}

pub fn collect_layers_with_root_req(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
    mapping_root: Option<&Path>,
    req: &crate::http::Request,
) -> Result<Vec<crate::policy_ref::AccessLayer>, String> {
    collect_layers_with_root_inner(cfg, vhost, fs_path, url_path, mapping_root, Some(req))
}

fn collect_layers_with_root_inner(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
    mapping_root: Option<&Path>,
    req: Option<&crate::http::Request>,
) -> Result<Vec<crate::policy_ref::AccessLayer>, String> {
    let root = match mapping_root {
        Some(root) => {
            // Callers pass the root returned by `map_path()` for the URL that
            // actually matched; they never infer it from alias containment.
            debug_assert!(crate::verified::alias_mapping_root_admit(true, false));
            root.to_path_buf()
        }
        None => access_root_for(cfg, vhost, fs_path),
    };
    let canonical_root = if fs_path.starts_with(&root) {
        None
    } else {
        fs::canonicalize(&root).ok()
    };
    let may_apply = |path: &Path| match req {
        Some(req) => cfg
            .htaccess_may_apply_req(path, req)
            .map_err(str::to_string),
        None => Ok(cfg.htaccess_may_apply(path)),
    };
    let direct_policy = may_apply(fs_path)?;
    let mapped_policy = match mapped_policy_dir(&root, canonical_root.as_deref(), fs_path) {
        Some(mapped) if mapped != fs_path => may_apply(&mapped)?,
        _ => false,
    };
    if !direct_policy && !mapped_policy {
        return Ok(Vec::new());
    }
    let start = walk_start(fs_path);
    let dirs = ancestor_dirs(start)?;
    let mut layers = Vec::new();
    let mut access_instructions = 0usize;
    for dir in dirs {
        // Ancestors above every override-enabled directory cannot contribute
        // an accessible layer (F50 still covers an enabled ancestor itself).
        let mapped_dir = mapped_policy_dir(&root, canonical_root.as_deref(), &dir);
        let dir_policy_applicable = match req {
            Some(req) => cfg
                .access_file_dir_applicable_req(&dir, req)
                .map_err(str::to_string)?,
            None => cfg.access_file_dir_applicable(&dir),
        };
        let mapped_policy_applicable = match mapped_dir.as_deref().filter(|mapped| *mapped != dir) {
            Some(mapped) => match req {
                Some(req) => cfg
                    .access_file_dir_applicable_req(mapped, req)
                    .map_err(str::to_string)?,
                None => cfg.access_file_dir_applicable(mapped),
            },
            None => false,
        };
        let policy_applicable = dir_policy_applicable || mapped_policy_applicable;
        if !policy_applicable {
            continue;
        }
        let dir_scope = match req {
            Some(req) => cfg
                .effective_scope_cached_req(vhost, &dir, url_path, req)
                .map_err(str::to_string)?,
            None => cfg.effective_scope_cached(vhost, &dir, url_path),
        };
        // A canonical target directory and its lexical URL-mapped counterpart
        // are two policy identities.  An explicit `AllowOverride None` on
        // either one denies the access file; when only one identity is
        // configured it supplies the policy; enabled category sets meet
        // (F60-D/I61).  Keeping the canonical scope merely because the lexical
        // scope was disabled was a fail-open branch.
        let mut override_policy = dir_scope.override_policy.clone();
        if let Some(mapped) = mapped_dir.as_deref().filter(|mapped| *mapped != dir) {
            let mapped_scope = match req {
                Some(req) => cfg
                    .effective_scope_cached_req(vhost, mapped, url_path, req)
                    .map_err(str::to_string)?,
                None => cfg.effective_scope_cached(vhost, mapped, url_path),
            };
            override_policy = override_policy.conjoined_with(&mapped_scope.override_policy);
        }
        let mode = override_policy.mode();
        let allow_list = override_policy.allow_list();
        let nonfatal = override_policy.nonfatal();
        if !mode.is_enabled() && allow_list.is_empty() {
            continue;
        }
        let identity = crate::request_plan::LayerIdentity::new(&root, &dir, fs_path, url_path);
        let mut layer = crate::policy_ref::AccessLayer {
            identity: identity.clone(),
            scope: Arc::new(Scope::default()),
            files: Vec::new(),
            conditionals: Vec::new(),
        };
        let mut found = false;
        for name in cfg.access_file_names_for(&dir_scope) {
            let path = dir.join(&name);
            let opened = open_access_file(&path);
            let exists = !matches!(&opened, Ok(None));
            if !vapache_verified::access_file_candidate_admit(found, exists) {
                continue;
            }
            let opened = match opened {
                Ok(None) => continue, // coverage:ignore-line -- candidate_admit requires exists
                Err(e) => return Err(format!("{}: {e}", path.display())),
                Ok(Some(opened)) if !opened.meta.is_file() => {
                    return Err(format!("{}: not a regular file", path.display()))
                }
                Ok(Some(opened)) if opened.meta.len() > MAX_HTACCESS => {
                    return Err(format!("{}: access file too large", path.display()))
                }
                Ok(Some(opened)) => opened,
            };
            // A successful `dir/access-file` open proves that every prefix,
            // including `dir`, was a directory at the kernel lookup boundary.
            // Let that same lookup establish directory existence instead of
            // preceding it with a redundant pathname `statx` on every
            // request. `ENOTDIR` is treated like an absent candidate below,
            // preserving PATH_INFO/non-directory ancestor semantics.
            debug_assert!(crate::verified::access_walk_dir_admit(true, true));
            let parsed = parse_cached(cfg, &path, mode, allow_list, nonfatal, &identity, opened)?;
            if !vapache_verified::access_program_budget_admit(
                layers.len() as u64,
                access_instructions as u64,
                parsed.instruction_count as u64,
                MAX_ACCESS_LAYERS as u64,
                MAX_ACCESS_INSTRUCTIONS_PER_REQUEST as u64,
            ) {
                return Err("access-file request policy is too wide".into());
            }
            access_instructions += parsed.instruction_count;
            // Preserve AuthMerging on the selected access file; later
            // AccessFileName candidates are not merged.
            layer.scope = Arc::clone(&parsed.scope);
            for rule in &parsed.rules {
                add_layer_rule(&mut layer, rule);
            }
            found = true;
        }
        if found {
            layers.push(layer);
        }
    }
    Ok(layers)
}

fn add_layer_rule(layer: &mut crate::policy_ref::AccessLayer, rule: &ScopeRule) {
    let slot = crate::verified::access_layer_slot(
        rule.condition.is_some(),
        rule.branch == ConditionBranch::Normal,
        matches!(
            rule.kind,
            MatchKind::Files(_) | MatchKind::FilesGlob(_) | MatchKind::FilesMatch(_)
        ),
    );
    match slot {
        crate::verified::AccessLayerSlot::Conditional => layer.conditionals.push(rule.clone()),
        crate::verified::AccessLayerSlot::Files => layer.files.push(rule.clone()),
        crate::verified::AccessLayerSlot::TopLevel => {}
    }
}

/// Diagnostic trace for `--explain`: which access files are present, which
/// override policy applies, and how many rules each parsed file contributes.
pub fn trace_access_files(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
) -> Vec<String> {
    trace_access_files_with_root(cfg, vhost, fs_path, url_path, None)
}

/// `--explain` trace using the actual mapping root for URL-base derivation.
/// Like `collect_layers_with_root`, it reports every ancestor access file that
/// can participate, not only files below `DocumentRoot`/the alias target.
pub fn trace_access_files_with_root(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
    mapping_root: Option<&Path>,
) -> Vec<String> {
    let mut out = Vec::new();
    let root = mapping_root
        .map(Path::to_path_buf)
        .unwrap_or_else(|| access_root_for(cfg, vhost, fs_path));
    let canonical_root = if fs_path.starts_with(&root) {
        None
    } else {
        fs::canonicalize(&root).ok()
    };
    if !cfg.htaccess_may_apply(fs_path)
        && !mapped_policy_dir(&root, canonical_root.as_deref(), fs_path)
            .is_some_and(|mapped| cfg.htaccess_may_apply(&mapped))
    {
        out.push("skipped (no override-enabled directory in path)".into());
        return out;
    }
    let start = walk_start(fs_path);
    let dirs = match ancestor_dirs(start) {
        Ok(dirs) => dirs,
        Err(error) => {
            out.push(format!("skipped ({error})"));
            return out;
        }
    };
    let mut found = false;
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let mapped_dir = mapped_policy_dir(&root, canonical_root.as_deref(), &dir);
        let policy_applicable = cfg.access_file_dir_applicable(&dir)
            || mapped_dir
                .as_deref()
                .is_some_and(|mapped| mapped != dir && cfg.access_file_dir_applicable(mapped));
        if !policy_applicable {
            continue;
        }
        let dir_scope = cfg.effective_scope_cached(vhost, &dir, url_path);
        let mut override_policy = dir_scope.override_policy.clone();
        if let Some(mapped) = mapped_dir.as_deref().filter(|mapped| *mapped != dir) {
            let mapped_scope = cfg.effective_scope_cached(vhost, mapped, url_path);
            override_policy = override_policy.conjoined_with(&mapped_scope.override_policy);
        }
        let mode = override_policy.mode();
        let allow_list = override_policy.allow_list();
        let nonfatal = override_policy.nonfatal();
        if !mode.is_enabled() && allow_list.is_empty() {
            continue;
        }
        let mut selected = false;
        for name in cfg.access_file_names_for(&dir_scope) {
            let path = dir.join(&name);
            let opened = open_access_file(&path);
            let exists = !matches!(&opened, Ok(None));
            if !vapache_verified::access_file_candidate_admit(selected, exists) {
                continue;
            }
            selected = true;
            let identity = crate::request_plan::LayerIdentity::new(&root, &dir, fs_path, url_path);
            let parsed = match opened {
                Ok(Some(opened)) if opened.meta.is_file() && opened.meta.len() <= MAX_HTACCESS => {
                    found = true;
                    parse_cached(cfg, &path, mode, allow_list, nonfatal, &identity, opened)
                }
                Ok(Some(_)) => continue,
                Ok(None) => continue, // coverage:ignore-line -- candidate_admit requires exists
                Err(e) => Err(format!("{}: {e}", path.display())),
            };
            match parsed {
                Ok(parsed) => out.push(format!(
                    "{} mode={:?} list={:?} nonfatal={:?} rules={}",
                    path.display(),
                    mode,
                    allow_list,
                    nonfatal,
                    parsed.rules.len()
                )),
                Err(e) => out.push(format!("{} ERROR: {e}", path.display())),
            }
        }
    }
    if !found {
        out.push("no access files present in override-enabled path".into());
    }
    out
}

#[cfg(test)]
fn rule_matches(kind: &MatchKind, fname: &str, url_path: &str) -> bool {
    match kind {
        MatchKind::Always => true,
        MatchKind::Files(re) | MatchKind::FilesMatch(re) => re.is_match(fname.as_bytes()),
        MatchKind::FilesGlob(pattern) => {
            crate::glob::fnmatch(pattern.as_bytes(), fname.as_bytes(), false)
        }
        MatchKind::Location(prefix) => {
            let base = prefix.trim_end_matches('/');
            base.is_empty()
                || url_path == base
                || (url_path.starts_with(base)
                    && url_path.as_bytes().get(base.len()) == Some(&b'/'))
        }
        MatchKind::LocationGlob(pattern) => {
            crate::glob::fnmatch(pattern.as_bytes(), url_path.as_bytes(), true)
        }
        MatchKind::LocationMatch(re) => re.is_match(url_path.as_bytes()),
        MatchKind::Directory(p) => Path::new(url_path).starts_with(p),
        MatchKind::DirectoryMatch(re) => re.is_match(url_path.as_bytes()),
    }
}

struct Parsed {
    scope: Arc<Scope>,
    rules: Vec<ScopeRule>,
    instruction_count: usize,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    config_generation: u64,
    path: PathBuf,
    server_root: PathBuf,
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    size: u64,
    mode: u32,
    allow_list: Vec<String>,
    nonfatal: u8,
    identity: crate::request_plan::LayerIdentity,
}

struct CacheProbe<'a> {
    config_generation: u64,
    path: &'a Path,
    server_root: &'a Path,
    meta: &'a fs::Metadata,
    mode: u32,
    allow_list: &'a [String],
    nonfatal: u8,
    identity: &'a crate::request_plan::LayerIdentity,
}

impl CacheProbe<'_> {
    fn matches(&self, key: &CacheKey) -> bool {
        key.config_generation == self.config_generation
            && key.path == self.path
            && key.server_root == self.server_root
            && key.dev == self.meta.dev()
            && key.ino == self.meta.ino()
            && key.mtime == self.meta.mtime()
            && key.mtime_nsec == self.meta.mtime_nsec()
            && key.ctime == self.meta.ctime()
            && key.ctime_nsec == self.meta.ctime_nsec()
            && key.size == self.meta.len()
            && key.mode == self.mode
            && key.allow_list == self.allow_list
            && key.nonfatal == self.nonfatal
            && key.identity == *self.identity
    }

    fn to_owned(&self) -> CacheKey {
        CacheKey {
            config_generation: self.config_generation,
            path: self.path.to_path_buf(),
            server_root: self.server_root.to_path_buf(),
            dev: self.meta.dev(),
            ino: self.meta.ino(),
            mtime: self.meta.mtime(),
            mtime_nsec: self.meta.mtime_nsec(),
            ctime: self.meta.ctime(),
            ctime_nsec: self.meta.ctime_nsec(),
            size: self.meta.len(),
            mode: self.mode,
            allow_list: self.allow_list.to_vec(),
            nonfatal: self.nonfatal,
            identity: self.identity.clone(),
        }
    }
}

fn mode_key(mode: OverrideMode) -> u32 {
    match mode {
        OverrideMode::None => 0,
        OverrideMode::All => 1,
        OverrideMode::Categories(c) => 2 | (c.0 << 1),
    }
}

const MAX_ACCESS_CACHE_ENTRIES: usize = 512;
const MAX_ACCESS_CACHE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Default)]
struct AccessFileCache {
    entries: HashMap<CacheKey, (Arc<Parsed>, usize)>,
    bytes: usize,
    // The common static-site case repeatedly uses one access file. Keep one
    // exact key/Arc pair so a hit can be proved from borrowed request data
    // without allocating another owned CacheKey. The Arc is the same bounded
    // entry retained by `entries`, not a duplicate parsed program.
    last: Option<(CacheKey, Arc<Parsed>)>,
}

impl AccessFileCache {
    fn weight(key: &CacheKey) -> usize {
        (key.size.min(usize::MAX as u64) as usize)
            .saturating_add(key.path.as_os_str().as_encoded_bytes().len())
            .saturating_add(key.server_root.as_os_str().as_encoded_bytes().len())
            .saturating_add(key.allow_list.iter().map(String::len).sum::<usize>())
            .saturating_add(4096)
    }

    fn get(&self, key: &CacheKey) -> Option<&Arc<Parsed>> {
        self.entries.get(key).map(|(parsed, _)| parsed)
    }

    fn insert(&mut self, key: CacheKey, parsed: Arc<Parsed>) {
        let weight = Self::weight(&key);
        if weight > MAX_ACCESS_CACHE_BYTES {
            return;
        }
        // Do not let `last` retain an entry selected for eviction below.
        self.last = None;
        if let Some((_, old_weight)) = self.entries.remove(&key) {
            self.bytes = self.bytes.saturating_sub(old_weight);
        }
        while self.entries.len() >= MAX_ACCESS_CACHE_ENTRIES
            || self.bytes.saturating_add(weight) > MAX_ACCESS_CACHE_BYTES
        {
            let Some(victim) = self.entries.keys().next().cloned() else {
                break;
            };
            if let Some((_, old_weight)) = self.entries.remove(&victim) {
                self.bytes = self.bytes.saturating_sub(old_weight);
            }
        }
        self.bytes = self.bytes.saturating_add(weight);
        self.last = Some((key.clone(), Arc::clone(&parsed)));
        self.entries.insert(key, (parsed, weight));
    }
}

fn cache() -> &'static RwLock<AccessFileCache> {
    static CACHE: OnceLock<RwLock<AccessFileCache>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(AccessFileCache::default()))
}

pub(crate) fn drop_generation_state(generation: u64) {
    let mut cache = cache().write().unwrap_or_else(|error| error.into_inner());
    cache
        .entries
        .retain(|key, _| key.config_generation != generation);
    cache.bytes = cache
        .entries
        .values()
        .fold(0usize, |total, (_, weight)| total.saturating_add(*weight));
    if cache
        .last
        .as_ref()
        .is_some_and(|(key, _)| key.config_generation == generation)
    {
        cache.last = None;
    }
}

struct OpenedAccessFile {
    file: File,
    meta: fs::Metadata,
}

/// Open an access file once and derive every subsequent fact from that
/// descriptor.  `O_NONBLOCK` prevents a raced-in FIFO from hanging the
/// request before the regular-file check.
fn open_access_file(path: &Path) -> std::io::Result<Option<OpenedAccessFile>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    let meta = file.metadata()?;
    Ok(Some(OpenedAccessFile { file, meta }))
}

fn same_access_file_version(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && before.len() == after.len()
        && before.mode() == after.mode()
}

fn stable_access_snapshot(
    path: &Path,
    mut opened: OpenedAccessFile,
) -> Result<(Vec<u8>, fs::Metadata), String> {
    let before = opened.meta;
    // The descriptor was selected by pathname before this function ran.  If
    // the name now resolves to a different inode/version, parsing the opened
    // file would silently authorize a target the caller did not select.
    let current = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !vapache_verified::descriptor_snapshot_admit(
        before.is_file() && current.is_file(),
        before.dev() == current.dev() && before.ino() == current.ino(),
        same_access_file_version(&before, &current),
        before.len() <= MAX_HTACCESS,
    ) {
        return Err(format!(
            "{}: access file changed while it was being evaluated",
            path.display()
        ));
    }
    let mut data = Vec::with_capacity((before.len().min(MAX_HTACCESS) as usize).saturating_add(1));
    opened
        .file
        .by_ref()
        .take(MAX_HTACCESS + 1)
        .read_to_end(&mut data)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let after = opened
        .file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let current_after = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !vapache_verified::descriptor_snapshot_admit(
        before.is_file() && after.is_file() && current_after.is_file(),
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.dev() == current_after.dev()
            && before.ino() == current_after.ino(),
        same_access_file_version(&before, &after)
            && same_access_file_version(&before, &current_after),
        data.len() as u64 <= MAX_HTACCESS,
    ) {
        return Err(format!(
            "{}: access file changed while it was being evaluated",
            path.display()
        ));
    }
    Ok((data, before))
}

fn parse_cached(
    cfg: &Config,
    path: &Path,
    mode: OverrideMode,
    allow_list: &[String],
    nonfatal: NonfatalMode,
    identity: &crate::request_plan::LayerIdentity,
    opened: OpenedAccessFile,
) -> Result<Arc<Parsed>, String> {
    let meta = &opened.meta;
    let nonfatal_key = match nonfatal {
        NonfatalMode::None => 0,
        NonfatalMode::Override => 1,
        NonfatalMode::Unknown => 2,
        NonfatalMode::All => 3,
    };
    let probe = CacheProbe {
        config_generation: cfg.generation,
        path,
        server_root: &cfg.server_root,
        meta,
        mode: mode_key(mode),
        allow_list,
        nonfatal: nonfatal_key,
        identity,
    };
    let validate_hit = |parsed: Arc<Parsed>| -> Result<Arc<Parsed>, String> {
        // Validate that the already-open descriptor did not change while the
        // cache lookup ran. The key and parse always describe the same
        // inode/version, never a pathname reopened later.
        let after = opened
            .file
            .metadata()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if vapache_verified::descriptor_snapshot_admit(
            meta.is_file() && after.is_file(),
            meta.dev() == after.dev() && meta.ino() == after.ino(),
            same_access_file_version(meta, &after),
            meta.len() <= MAX_HTACCESS,
        ) {
            return Ok(parsed);
        }
        Err(format!(
            "{}: access file changed while it was being evaluated",
            path.display()
        ))
    };
    {
        // Cache hits dominate static workloads. Readers may validate distinct
        // requests concurrently; reload eviction and a genuinely new access
        // file take the exclusive side only on the cold path.
        let guard = cache().read().unwrap_or_else(|e| e.into_inner());
        if let Some(parsed) = guard
            .last
            .as_ref()
            .filter(|(key, _)| probe.matches(key))
            .map(|(_, parsed)| Arc::clone(parsed))
        {
            drop(guard);
            return validate_hit(parsed);
        }
    }
    let key = probe.to_owned();
    {
        let mut guard = cache().write().unwrap_or_else(|e| e.into_inner());
        if let Some(parsed) = guard.get(&key).cloned() {
            guard.last = Some((key.clone(), Arc::clone(&parsed)));
            drop(guard);
            return validate_hit(parsed);
        }
    }
    // Parse outside the lock: a slow filesystem read must not serialize
    // unrelated requests.  Duplicate parses on a race are harmless.
    let _expensive = crate::resource::try_expensive()
        .ok_or_else(|| format!("{}: access-file parse capacity exhausted", path.display()))?;
    let (data, stable_meta) = stable_access_snapshot(path, opened)?;
    debug_assert_eq!(stable_meta.dev(), key.dev);
    debug_assert_eq!(stable_meta.ino(), key.ino);
    let parsed = Arc::new(parse_access_bytes(
        cfg, path, &data, mode, allow_list, nonfatal, identity,
    )?);
    let mut guard = cache().write().unwrap_or_else(|e| e.into_inner());
    guard.insert(key, Arc::clone(&parsed));
    Ok(parsed)
}

#[cfg(test)]
fn parse_file(
    cfg: &Config,
    path: &Path,
    mode: OverrideMode,
    base_url: &str,
) -> Result<Parsed, String> {
    let dir = path.parent().unwrap_or(path);
    let identity = crate::request_plan::LayerIdentity::with_url_mount(dir, dir, base_url);
    parse_file_with_list(cfg, path, mode, &[], NonfatalMode::None, &identity)
}

fn parse_file_with_list(
    cfg: &Config,
    path: &Path,
    mode: OverrideMode,
    allow_list: &[String],
    nonfatal: NonfatalMode,
    identity: &crate::request_plan::LayerIdentity,
) -> Result<Parsed, String> {
    let opened = open_access_file(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .ok_or_else(|| format!("{}: not found", path.display()))?;
    let (data, _) = stable_access_snapshot(path, opened)?;
    parse_access_bytes(cfg, path, &data, mode, allow_list, nonfatal, identity)
}

fn parse_access_bytes(
    cfg: &Config,
    path: &Path,
    data: &[u8],
    mode: OverrideMode,
    allow_list: &[String],
    nonfatal: NonfatalMode,
    identity: &crate::request_plan::LayerIdentity,
) -> Result<Parsed, String> {
    let text = std::str::from_utf8(data)
        .map_err(|_| format!("{}: access file is not valid UTF-8", path.display()))?;
    let lines = logical_lines(text);
    if let Some((index, _)) = lines
        .iter()
        .enumerate()
        .find(|(_, line)| line.len() > MAX_HTACCESS_LINE)
    {
        return Err(format!(
            "{}: line {} exceeds the {}-byte access-file line limit",
            path.display(),
            index + 1,
            MAX_HTACCESS_LINE
        ));
    }
    let program = AccessProgram::seal(&lines)?;
    let instruction_count = program.instructions.len();
    let mut scope = Scope::default();
    let mut rules = Vec::new();
    scope.rewrite_policy.rewrite_base = Some(identity.url_mount.clone());
    scope.rewrite_policy.rewrite_match_base = Some(identity.url_mount.clone());
    let mut i = 0;
    let mut next_chain = 0usize;
    parse_block(
        cfg,
        &program,
        &mut i,
        &mut scope,
        &mut rules,
        mode,
        allow_list,
        nonfatal,
        None,
        false,
        &mut next_chain,
        None,
    )
    .map_err(|e| format!("{}: {e}", path.display()))?;
    if !scope.header_policy.within_limits() {
        return Err(format!(
            "{}: configured response headers exceed the count/byte limit",
            path.display()
        ));
    }
    for rule in &mut scope.rewrite_policy.rewrite_rules {
        rule.subject_dir = Some(identity.dir.clone());
    }
    Ok(Parsed {
        scope: Arc::new(scope),
        rules,
        instruction_count,
    })
}

/// Closed set of access-file sections understood by the effectful parser.
/// Parsing and dispatch both consume this enum, so a new supported wrapper
/// cannot bypass the section-command override gate by being added to a second
/// string match (P18).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessSectionKind {
    Files = 0,
    FilesMatch = 1,
    If = 2,
    IfFile = 3,
    ElseIf = 4,
    Else = 5,
    IfModule = 6,
    IfDefine = 7,
    IfDirective = 8,
    IfSection = 9,
    IfVersion = 10,
    RequireAll = 11,
    RequireAny = 12,
    RequireNone = 13,
    Limit = 14,
    LimitExcept = 15,
}

impl AccessSectionKind {
    #[cfg(test)]
    const ALL: [Self; 16] = [
        Self::Files,
        Self::FilesMatch,
        Self::If,
        Self::IfFile,
        Self::ElseIf,
        Self::Else,
        Self::IfModule,
        Self::IfDefine,
        Self::IfDirective,
        Self::IfSection,
        Self::IfVersion,
        Self::RequireAll,
        Self::RequireAny,
        Self::RequireNone,
        Self::Limit,
        Self::LimitExcept,
    ];

    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "files" => Self::Files,
            "filesmatch" => Self::FilesMatch,
            "if" => Self::If,
            "iffile" => Self::IfFile,
            "elseif" => Self::ElseIf,
            "else" => Self::Else,
            "ifmodule" => Self::IfModule,
            "ifdefine" => Self::IfDefine,
            "ifdirective" => Self::IfDirective,
            "ifsection" => Self::IfSection,
            "ifversion" => Self::IfVersion,
            "requireall" => Self::RequireAll,
            "requireany" => Self::RequireAny,
            "requirenone" => Self::RequireNone,
            "limit" => Self::Limit,
            "limitexcept" => Self::LimitExcept,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Files => "files",
            Self::FilesMatch => "filesmatch",
            Self::If => "if",
            Self::IfFile => "iffile",
            Self::ElseIf => "elseif",
            Self::Else => "else",
            Self::IfModule => "ifmodule",
            Self::IfDefine => "ifdefine",
            Self::IfDirective => "ifdirective",
            Self::IfSection => "ifsection",
            Self::IfVersion => "ifversion",
            Self::RequireAll => "requireall",
            Self::RequireAny => "requireany",
            Self::RequireNone => "requirenone",
            Self::Limit => "limit",
            Self::LimitExcept => "limitexcept",
        }
    }

    fn allowed_in_limit(self) -> bool {
        matches!(
            self,
            Self::Limit
                | Self::LimitExcept
                | Self::RequireAll
                | Self::RequireAny
                | Self::RequireNone
                | Self::IfModule
                | Self::IfDefine
                | Self::IfDirective
                | Self::IfSection
                | Self::IfVersion
        )
    }
}

#[derive(Debug)]
enum AccessInstruction {
    Directive {
        name: String,
        payload: SealedPayload,
        line: usize,
        known: bool,
    },
    SectionStart {
        name: String,
        payload: AccessSectionPayload,
        line: usize,
        section: Option<AccessSectionKind>,
        end: usize,
    },
    SectionEnd {
        name: String,
        line: usize,
        start: usize,
    },
}

/// Closed semantic value for an access-file section command. Every fallible
/// parse is completed during `AccessProgram::seal`, before AllowOverride or a
/// false execute-on-read condition can skip the section.
#[derive(Debug)]
enum AccessSectionPayload {
    Unknown,
    Empty,
    Expression(crate::expr::Expr),
    IfFile { negated: bool, path: String },
    NamedCondition { negated: bool, name: String },
    StaticCondition(bool),
    Methods(MethodSet),
    Files(MatchKind),
}

fn seal_access_section(
    section: AccessSectionKind,
    args: Vec<String>,
) -> Result<AccessSectionPayload, String> {
    validate_section_arity(section, &args)?;
    Ok(match section {
        AccessSectionKind::Else
        | AccessSectionKind::RequireAll
        | AccessSectionKind::RequireAny
        | AccessSectionKind::RequireNone => AccessSectionPayload::Empty,
        AccessSectionKind::If | AccessSectionKind::ElseIf => {
            let expression = crate::expr::parse(&args.join(" "))?;
            crate::expr::validate_vars(&expression)?;
            AccessSectionPayload::Expression(expression)
        }
        AccessSectionKind::IfFile => {
            let raw = &args[0];
            let (negated, path) = raw
                .strip_prefix('!')
                .map_or((false, raw.as_str()), |path| (true, path));
            if path.is_empty() {
                return Err("<IfFile> requires a non-empty path".into());
            }
            AccessSectionPayload::IfFile {
                negated,
                path: path.to_string(),
            }
        }
        AccessSectionKind::IfModule
        | AccessSectionKind::IfDefine
        | AccessSectionKind::IfDirective
        | AccessSectionKind::IfSection => {
            let raw = &args[0];
            let (negated, name) = raw
                .strip_prefix('!')
                .map_or((false, raw.as_str()), |name| (true, name));
            if name.is_empty() {
                return Err(format!("<{}> requires a non-empty name", section.name()));
            }
            AccessSectionPayload::NamedCondition {
                negated,
                name: name.to_string(),
            }
        }
        AccessSectionKind::IfVersion => {
            AccessSectionPayload::StaticCondition(crate::config::ifversion_matches(&args)?)
        }
        AccessSectionKind::Limit | AccessSectionKind::LimitExcept => AccessSectionPayload::Methods(
            crate::config::parse_method_set_args(section.name(), &args, true)?,
        ),
        AccessSectionKind::Files => {
            AccessSectionPayload::Files(crate::config::compile_files_pattern(&args)?)
        }
        AccessSectionKind::FilesMatch => AccessSectionPayload::Files(MatchKind::FilesMatch(
            crate::config::compile_regex(&args[0])
                .map_err(|error| format!("bad FilesMatch regex: {error}"))?,
        )),
    })
}

/// Immutable access-file program. Parsing and structural validation complete
/// before any directive mutates a Scope, and every section records its exact
/// mate for fail-closed, O(1) skipping.
struct AccessProgram {
    instructions: Box<[AccessInstruction]>,
}

impl AccessProgram {
    fn seal(lines: &[String]) -> Result<Self, String> {
        if lines.len() > MAX_ACCESS_INSTRUCTIONS_PER_FILE {
            return Err(format!(
                "access program exceeds {MAX_ACCESS_INSTRUCTIONS_PER_FILE} instructions"
            ));
        }
        let mut instructions = Vec::with_capacity(lines.len());
        let mut stack: Vec<(String, usize)> = Vec::new();
        let mut depth = 0usize;
        for (index, line) in lines.iter().enumerate() {
            let line_number = index + 1;
            let line_ir = crate::config_frontend::parse_line(line)
                .map_err(|error| format!("line {line_number}: {error}"))?;
            match line_ir {
                crate::config_frontend::ConfigLine::Directive { name, args } => {
                    depth = vapache_verified::config_program_depth_step(
                        depth,
                        vapache_verified::ConfigLineKind::Directive,
                    )
                    .ok_or_else(|| format!("line {line_number}: access program depth overflow"))?;
                    let known = directive_category(&name).is_some();
                    let payload = if known {
                        SealedPayload::seal(&name, args, access_directive_schema(&name))
                            .map_err(|error| format!("line {line_number}: {error}"))?
                    } else {
                        // Unknown directives are retained so Nonfatal=Unknown
                        // can make the verified access gate skip them. They
                        // have no schema and can never reach apply_directive.
                        SealedPayload::seal(
                            &name,
                            args,
                            PayloadSchema::new(PayloadArity::ANY, false),
                        )
                        .expect("unconstrained unknown-directive payload seals")
                    };
                    instructions.push(AccessInstruction::Directive {
                        name,
                        payload,
                        line: line_number,
                        known,
                    });
                }
                crate::config_frontend::ConfigLine::SectionStart { name, args } => {
                    depth = vapache_verified::config_program_depth_step(
                        depth,
                        vapache_verified::ConfigLineKind::SectionStart,
                    )
                    .ok_or_else(|| format!("line {line_number}: access program depth overflow"))?;
                    if !vapache_verified::access_section_depth_admit(
                        depth,
                        MAX_ACCESS_SECTION_DEPTH,
                    ) {
                        return Err(format!(
                            "line {line_number}: access section nesting exceeds {MAX_ACCESS_SECTION_DEPTH}"
                        ));
                    }
                    let start = instructions.len();
                    let section = AccessSectionKind::parse(&name);
                    let payload = match section {
                        Some(section) => seal_access_section(section, args)
                            .map_err(|error| format!("line {line_number}: {error}"))?,
                        None => AccessSectionPayload::Unknown,
                    };
                    instructions.push(AccessInstruction::SectionStart {
                        name: name.clone(),
                        payload,
                        line: line_number,
                        section,
                        end: usize::MAX,
                    });
                    stack.push((name, start));
                }
                crate::config_frontend::ConfigLine::SectionEnd { name } => {
                    depth = vapache_verified::config_program_depth_step(
                        depth,
                        vapache_verified::ConfigLineKind::SectionEnd,
                    )
                    .ok_or_else(|| format!("line {line_number}: unexpected closing </{name}>"))?;
                    let Some((open, start)) = stack.pop() else {
                        return Err(format!("line {line_number}: unexpected closing </{name}>"));
                    };
                    if open != name {
                        return Err(format!(
                            "line {line_number}: closing </{name}> does not match <{open}>"
                        ));
                    }
                    let end = instructions.len();
                    let AccessInstruction::SectionStart {
                        end: matching_end, ..
                    } = &mut instructions[start]
                    else {
                        return Err("access program section index is corrupt".into());
                    };
                    *matching_end = end;
                    instructions.push(AccessInstruction::SectionEnd {
                        name,
                        line: line_number,
                        start,
                    });
                }
            }
        }
        if depth != 0 {
            let (name, _) = stack
                .last()
                .expect("non-zero verified depth has an open section");
            return Err(format!("missing closing </{name}>"));
        }
        debug_assert!(stack.is_empty());
        Ok(AccessProgram {
            instructions: instructions.into_boxed_slice(),
        })
    }
}

/// Admission for access-file section commands. Apache applies the section's
/// own override mask (or an exact `AllowOverrideList "<Section"` entry)
/// before examining the directives nested inside it.
fn section_allowed_list(
    mode: OverrideMode,
    allow_list: &[String],
    section: AccessSectionKind,
) -> bool {
    let category_allowed = vapache_verified::htaccess_section_category_admit(
        section as u8,
        mode.is_enabled(),
        mode.allows(OverrideCategory::AuthConfig),
        mode.allows(OverrideCategory::Limit),
    );
    let command_name = format!("<{}", section.name());
    let section_listed = allow_list
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&command_name));
    vapache_verified::htaccess_section_admit(category_allowed, section_listed)
}

fn parse_block(
    cfg: &Config,
    program: &AccessProgram,
    i: &mut usize,
    scope: &mut Scope,
    rules: &mut Vec<ScopeRule>,
    mode: OverrideMode,
    allow_list: &[String],
    nonfatal: NonfatalMode,
    end: Option<&str>,
    require_only: bool,
    next_chain: &mut usize,
    limit: Option<&MethodSet>,
) -> Result<(), String> {
    let mut current_chain: Option<usize> = None;
    while *i < program.instructions.len() {
        let instruction = &program.instructions[*i];
        *i += 1;
        match instruction {
            AccessInstruction::SectionEnd { name, line, .. } => {
                return match end {
                    Some(expected) if expected == name => Ok(()),
                    Some(expected) => Err(format!(
                        "line {line}: closing </{name}> does not match <{expected}>"
                    )),
                    None => Err(format!("line {line}: unexpected closing </{name}>")),
                };
            }
            AccessInstruction::SectionStart {
                name,
                payload,
                line,
                section,
                end: _,
            } => {
                let section = *section;
                // Apache gates the section command itself before it parses
                // any child directives. AllowOverrideList names are not a
                // union over arbitrary wrappers: listing `Require` does not
                // implicitly admit `<Files>`, `<If>` or `<RequireAll>` (P18).
                let policy_allowed = section
                    .map(|kind| {
                        // Apache's authz-core parser owns nested authorization
                        // containers once the outer Require section command
                        // has been admitted. Directives inside still pass the
                        // ordinary AllowOverride/List gate below.
                        (require_only
                            && matches!(
                                kind,
                                AccessSectionKind::RequireAll
                                    | AccessSectionKind::RequireAny
                                    | AccessSectionKind::RequireNone
                            ))
                            || section_allowed_list(mode, allow_list, kind)
                    })
                    // Unknown commands have no override category; pass the
                    // policy stage so the independent Unknown/Nonfatal gate
                    // decides whether to skip or reject them.
                    .unwrap_or(true);
                match vapache_verified::htaccess_gate_admit(
                    policy_allowed,
                    section.is_some(),
                    section
                        .map(|kind| {
                            vapache_verified::htaccess_section_nonfatal_override_admit(
                                kind as u8,
                                nonfatal.allows_override(),
                            )
                        })
                        .unwrap_or(nonfatal.allows_override()),
                    nonfatal.allows_unknown(),
                ) {
                    1 => {
                        skip_section(program, i, &name)?;
                        continue;
                    }
                    2 => {
                        if section.is_some() {
                            return Err(format!(
                                "line {}: <{name}> is not allowed by AllowOverride",
                                line
                            ));
                        }
                        return Err(format!(
                            "line {}: unsupported .htaccess section <{name}>",
                            line
                        ));
                    }
                    _ => {}
                }
                let section = section.expect("known section passed the admission gate");
                if limit.is_some() && !section.allowed_in_limit() {
                    return Err(format!(
                        "line {}: <{name}> is not allowed inside a method-limited section",
                        line
                    ));
                }
                match section {
                    AccessSectionKind::IfFile => {
                        if require_only {
                            return Err(format!("line {line}: <{name}> is not allowed here"));
                        }
                        let AccessSectionPayload::IfFile { negated, path } = payload else {
                            unreachable!("sealed IfFile section payload")
                        };
                        let raw_path = path.as_str();
                        let candidate = Path::new(raw_path);
                        let candidate = if candidate.is_absolute() {
                            candidate.to_path_buf()
                        } else {
                            cfg.server_root.join(candidate)
                        };
                        let exists = crate::files::metadata_cached(&candidate).is_ok();
                        let selected = exists != *negated;
                        debug_assert!(vapache_verified::iffile_exec_on_read_admit(
                            candidate.is_absolute(),
                            true,
                        ));
                        // Apache's <IfFile> is EXEC_ON_READ.  Parse children
                        // regardless (configuration errors are not hidden by
                        // a false condition), then splice the selected branch
                        // into the enclosing phase.  In particular a nested
                        // <Files> remains a Files-phase rule instead of being
                        // collapsed into the final conditional phase.
                        let mut inner = Scope::default();
                        let mut inner_rules = Vec::new();
                        parse_block(
                            cfg,
                            program,
                            i,
                            &mut inner,
                            &mut inner_rules,
                            mode,
                            allow_list,
                            nonfatal,
                            Some(&name),
                            false,
                            next_chain,
                            None,
                        )?;
                        if selected {
                            scope.merge(&inner);
                            for mut rule in inner_rules {
                                rule.order = rules.len();
                                rules.push(rule);
                            }
                        }
                        current_chain = None;
                    }
                    AccessSectionKind::If | AccessSectionKind::ElseIf | AccessSectionKind::Else => {
                        // The wrapper was admitted above; its children still
                        // pass through their own directive/section gates.
                        if require_only {
                            return Err(format!("line {line}: <{name}> is not allowed here"));
                        }
                        let (branch, chain, condition) = if section == AccessSectionKind::If {
                            let AccessSectionPayload::Expression(expression) = payload else {
                                unreachable!("sealed If expression")
                            };
                            let chain = *next_chain;
                            *next_chain += 1;
                            current_chain = Some(chain);
                            (
                                ConditionBranch::Normal,
                                Some(chain),
                                Some(expression.clone()),
                            )
                        } else {
                            let Some(chain) = current_chain else {
                                return Err(format!("line {line}: <{name}> has no preceding <If>"));
                            };
                            if section == AccessSectionKind::ElseIf {
                                let AccessSectionPayload::Expression(expression) = payload else {
                                    unreachable!("sealed ElseIf expression")
                                };
                                (
                                    ConditionBranch::ElseIf,
                                    Some(chain),
                                    Some(expression.clone()),
                                )
                            } else {
                                current_chain = None;
                                (ConditionBranch::Else, Some(chain), None)
                            }
                        };
                        let mut inner = Scope::default();
                        let mut inner_rules = Vec::new();
                        parse_block(
                            cfg,
                            program,
                            i,
                            &mut inner,
                            &mut inner_rules,
                            mode,
                            allow_list,
                            nonfatal,
                            Some(&name),
                            false,
                            next_chain,
                            None,
                        )?;
                        if inner_rules
                            .iter()
                            .any(|rule| !matches!(rule.kind, MatchKind::Always))
                        {
                            return Err(format!(
                                "line {line}: nested Files sections inside <{name}> are not supported; refusing policy nesting Apache accepts but does not execute on ordinary requests"
                            ));
                        }
                        rules.push(ScopeRule {
                            kind: MatchKind::Always,
                            delta: inner,
                            order: rules.len(),
                            condition,
                            branch,
                            chain,
                            nested: inner_rules,
                        });
                    }
                    AccessSectionKind::RequireAll
                    | AccessSectionKind::RequireAny
                    | AccessSectionKind::RequireNone => {
                        let mut inner = Scope::default();
                        let mut inner_rules = Vec::new();
                        parse_block(
                            cfg,
                            program,
                            i,
                            &mut inner,
                            &mut inner_rules,
                            mode,
                            allow_list,
                            nonfatal,
                            Some(&name),
                            true,
                            next_chain,
                            limit,
                        )?;
                        // Require sections only accept Require directives, so
                        // nested parse rules are not expected here.
                        debug_assert!(inner_rules.is_empty());
                        let mut nodes = Vec::new();
                        let inner_entries = if let Some(crate::config::AuthPolicy::List(entries)) =
                            inner.authorization.requires.take()
                        {
                            entries
                        } else {
                            Vec::new()
                        };
                        for entry in inner_entries {
                            debug_assert_eq!(entry.limit.as_ref(), limit);
                            nodes.push(entry.node);
                        }
                        if !nodes.is_empty() {
                            let invalid_negative = match section {
                                AccessSectionKind::RequireAll => {
                                    !nodes.iter().any(|node| !require_node_is_negative(node))
                                }
                                AccessSectionKind::RequireAny | AccessSectionKind::RequireNone => {
                                    nodes.iter().any(require_node_is_negative)
                                }
                                _ => unreachable!(),
                            };
                            if invalid_negative {
                                return Err(format!(
                                    "line {line}: <{name}> contains no positive authorization provider"
                                ));
                            }
                            let node = match section {
                                AccessSectionKind::RequireAll => RequireNode::All(nodes),
                                AccessSectionKind::RequireAny => RequireNode::Any(nodes),
                                AccessSectionKind::RequireNone => RequireNode::None(nodes),
                                _ => unreachable!(),
                            };
                            if !require_only && require_node_is_negative(&node) {
                                return Err(format!(
                                    "line {line}: <{name}> has no effect in <RequireAny>"
                                ));
                            }
                            scope.add_require(node, limit);
                        }
                    }
                    AccessSectionKind::Limit | AccessSectionKind::LimitExcept => {
                        if require_only {
                            return Err(format!("line {line}: <{name}> is not allowed here"));
                        }
                        let AccessSectionPayload::Methods(methods) = payload else {
                            unreachable!("sealed method section")
                        };
                        let combined = match limit {
                            Some(outer) => outer.intersect(&methods),
                            None => methods.clone(),
                        };
                        if combined.is_empty() {
                            return Err(format!(
                                "line {line}: nested <{name}> excludes every HTTP method"
                            ));
                        }
                        if matches!(limit, Some(outer) if combined == *outer) {
                            return Err(format!(
                            "line {line}: nested <{name}> does not further restrict the enclosing method set"
                        ));
                        }
                        parse_block(
                            cfg,
                            program,
                            i,
                            scope,
                            rules,
                            mode,
                            allow_list,
                            nonfatal,
                            Some(&name),
                            false,
                            next_chain,
                            Some(&combined),
                        )?;
                    }
                    AccessSectionKind::Files | AccessSectionKind::FilesMatch => {
                        if require_only {
                            return Err(format!("line {line}: <{name}> is not allowed here"));
                        }
                        let AccessSectionPayload::Files(kind) = payload else {
                            unreachable!("sealed Files section")
                        };
                        let mut inner = Scope::default();
                        let mut inner_rules = Vec::new();
                        parse_block(
                            cfg,
                            program,
                            i,
                            &mut inner,
                            &mut inner_rules,
                            mode,
                            allow_list,
                            nonfatal,
                            Some(&name),
                            false,
                            next_chain,
                            None,
                        )?;
                        rules.push(ScopeRule {
                            kind: kind.clone(),
                            delta: inner,
                            order: rules.len(),
                            condition: None,
                            branch: ConditionBranch::Normal,
                            chain: None,
                            nested: inner_rules,
                        });
                    }
                    AccessSectionKind::IfModule => {
                        let AccessSectionPayload::NamedCondition {
                            negated,
                            name: candidate,
                        } = payload
                        else {
                            unreachable!("sealed IfModule condition")
                        };
                        let active = cfg.module_loaded(candidate) != *negated;
                        if active {
                            parse_block(
                                cfg,
                                program,
                                i,
                                scope,
                                rules,
                                mode,
                                allow_list,
                                nonfatal,
                                Some(&name),
                                require_only,
                                next_chain,
                                limit,
                            )?;
                        } else {
                            skip_section(program, i, &name)?;
                        }
                    }
                    AccessSectionKind::IfDefine => {
                        let AccessSectionPayload::NamedCondition {
                            negated,
                            name: candidate,
                        } = payload
                        else {
                            unreachable!("sealed IfDefine condition")
                        };
                        let active = cfg.config_defines.contains(candidate) != *negated;
                        if active {
                            parse_block(
                                cfg,
                                program,
                                i,
                                scope,
                                rules,
                                mode,
                                allow_list,
                                nonfatal,
                                Some(&name),
                                require_only,
                                next_chain,
                                limit,
                            )?;
                        } else {
                            skip_section(program, i, &name)?;
                        }
                    }
                    AccessSectionKind::IfDirective | AccessSectionKind::IfSection => {
                        let AccessSectionPayload::NamedCondition {
                            negated,
                            name: candidate,
                        } = payload
                        else {
                            unreachable!("sealed named condition")
                        };
                        let found = if section == AccessSectionKind::IfDirective {
                            cfg.directive_exists(candidate)
                                .map_err(|e| format!("line {line}: {e}"))?
                        } else {
                            cfg.section_exists(candidate)
                        };
                        let active = found != *negated;
                        if section == AccessSectionKind::IfDirective {
                            cfg.directive_exists(candidate)
                                .map_err(|e| format!("line {line}: {e}"))?;
                        }
                        if active {
                            parse_block(
                                cfg,
                                program,
                                i,
                                scope,
                                rules,
                                mode,
                                allow_list,
                                nonfatal,
                                Some(&name),
                                require_only,
                                next_chain,
                                limit,
                            )?;
                        } else {
                            skip_section(program, i, &name)?;
                        }
                    }
                    AccessSectionKind::IfVersion => {
                        let AccessSectionPayload::StaticCondition(active) = payload else {
                            unreachable!("sealed IfVersion condition")
                        };
                        let active = *active;
                        if active {
                            parse_block(
                                cfg,
                                program,
                                i,
                                scope,
                                rules,
                                mode,
                                allow_list,
                                nonfatal,
                                Some(&name),
                                require_only,
                                next_chain,
                                limit,
                            )?;
                        } else {
                            skip_section(program, i, &name)?;
                        }
                    }
                }
            }
            AccessInstruction::Directive {
                name,
                payload,
                line,
                known,
            } => {
                let args = payload.as_slice();
                if require_only && name != "require" {
                    return Err(format!(
                        "line {line}: only Require directives are allowed in a Require section"
                    ));
                }
                if limit.is_some()
                    && !matches!(
                        name.as_str(),
                        "require" | "order" | "allow" | "deny" | "satisfy"
                    )
                {
                    return Err(format!(
                    "line {line}: directive '{name}' is not allowed inside a method-limited section"
                ));
                }
                let policy_allowed = directive_allowed_list(mode, allow_list, name, args);
                match vapache_verified::htaccess_gate_admit(
                    policy_allowed,
                    *known,
                    nonfatal.allows_override(),
                    nonfatal.allows_unknown(),
                ) {
                    1 => continue,
                    2 if !policy_allowed => {
                        return Err(format!(
                            "line {line}: directive '{name}' is not allowed by AllowOverride"
                        ));
                    }
                    2 => {
                        return Err(format!(
                            "line {line}: unsupported .htaccess directive '{name}'"
                        ));
                    }
                    _ => {}
                }
                apply_directive(cfg, scope, name, payload, limit, require_only)
                    .map_err(|e| format!("line {line}: {e}"))?;
            }
        }
    }
    if let Some(expected) = end {
        return Err(format!("missing closing </{expected}>"));
    }
    Ok(())
}

fn validate_section_arity(section: AccessSectionKind, args: &[String]) -> Result<(), String> {
    let count = args.len();
    let (min, max) = match section {
        AccessSectionKind::Else
        | AccessSectionKind::RequireAll
        | AccessSectionKind::RequireAny
        | AccessSectionKind::RequireNone => (0, Some(0)),
        AccessSectionKind::IfFile
        | AccessSectionKind::IfModule
        | AccessSectionKind::IfDefine
        | AccessSectionKind::IfDirective
        | AccessSectionKind::IfSection => (1, Some(1)),
        AccessSectionKind::IfVersion => (1, Some(2)),
        AccessSectionKind::Files => (1, Some(2)),
        AccessSectionKind::FilesMatch => (1, Some(1)),
        AccessSectionKind::If
        | AccessSectionKind::ElseIf
        | AccessSectionKind::Limit
        | AccessSectionKind::LimitExcept => (1, None),
    };
    if !vapache_verified::config_argument_arity_admit(count, min, max) {
        let requirement = match max {
            Some(max) if max == min => format!("exactly {min}"),
            Some(max) => format!("between {min} and {max}"),
            None => format!("at least {min}"),
        };
        return Err(format!(
            "<{}> requires {requirement} argument(s), got {count}",
            section.name()
        ));
    }
    if section == AccessSectionKind::Files && args.first().is_some_and(|arg| arg == "~") {
        if count < 2 {
            return Err("<files ~> requires a regular expression".into());
        }
    } else if section == AccessSectionKind::Files && count == 2 {
        return Err("<files> accepts two arguments only in the '<files ~ regex>' form".into());
    }
    Ok(())
}

fn skip_section(program: &AccessProgram, i: &mut usize, name: &str) -> Result<(), String> {
    let start = i
        .checked_sub(1)
        .ok_or_else(|| format!("cannot skip unopened <{name}>"))?;
    let Some(AccessInstruction::SectionStart {
        name: open, end, ..
    }) = program.instructions.get(start)
    else {
        return Err(format!("cannot skip unopened <{name}>"));
    };
    if open != name {
        return Err(format!("cannot skip <{name}> from <{open}>"));
    }
    let Some(AccessInstruction::SectionEnd {
        name: close,
        start: matching_start,
        ..
    }) = program.instructions.get(*end)
    else {
        return Err(format!("missing closing </{name}>"));
    };
    if close != name || *matching_start != start {
        return Err(format!("mismatched closing </{close}> for <{name}>"));
    }
    *i = *end + 1;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectiveDisposition {
    /// The directive must change the parsed scope or add a rule.
    Effectful,
    /// The directive is recognized but refused in `.htaccess`.
    Reject,
}

/// Authoritative disposition table for every directive the `.htaccess` parser
/// recognizes.  `apply_directive` refuses names absent from this table, and
/// `directive_category` derives the AllowOverride category from it.  The test
/// matrix in this module must cover every entry with an observable effect.
const DIRECTIVE_SPECS: &[(&str, OverrideCategory, DirectiveDisposition)] = &[
    (
        "addcharset",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Reject,
    ),
    (
        "adddefaultcharset",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "adddescription",
        OverrideCategory::Indexes,
        DirectiveDisposition::Reject,
    ),
    (
        "addencoding",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Reject,
    ),
    (
        "addhandler",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "addinputfilter",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "addlanguage",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Reject,
    ),
    (
        "addoutputfilter",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "addoutputfilterbytype",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "addtype",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "allow",
        OverrideCategory::Limit,
        DirectiveDisposition::Effectful,
    ),
    (
        "allowmethods",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Reject,
    ),
    (
        "authbasicprovider",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "authgroupfile",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "authmerging",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "authname",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "authtype",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "authuserfile",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "browsermatch",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "browsermatchnocase",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "brotlialteretag",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "brotlicompressionalteretag",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "brotlicompressionquality",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "cgipassauth",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "deflatealteretag",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "deflatebuffersize",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Reject,
    ),
    (
        "deflatecompressionlevel",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "deflatefilternote",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Reject,
    ),
    (
        "deflatememlevel",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Reject,
    ),
    (
        "deflatewindowssize",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Reject,
    ),
    (
        "deny",
        OverrideCategory::Limit,
        DirectiveDisposition::Effectful,
    ),
    (
        "directoryindex",
        OverrideCategory::Indexes,
        DirectiveDisposition::Effectful,
    ),
    (
        "directoryslash",
        OverrideCategory::Indexes,
        DirectiveDisposition::Effectful,
    ),
    (
        "enablesendfile",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "errordocument",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "expiresactive",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "expiresbytype",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "expiresdefault",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "fileetag",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "forcetype",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "header",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "headername",
        OverrideCategory::Indexes,
        DirectiveDisposition::Reject,
    ),
    (
        "indexignore",
        OverrideCategory::Indexes,
        DirectiveDisposition::Effectful,
    ),
    (
        "indexoptions",
        OverrideCategory::Indexes,
        DirectiveDisposition::Reject,
    ),
    (
        "options",
        OverrideCategory::Options,
        DirectiveDisposition::Effectful,
    ),
    (
        "order",
        OverrideCategory::Limit,
        DirectiveDisposition::Effectful,
    ),
    (
        "passenv",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "readmefile",
        OverrideCategory::Indexes,
        DirectiveDisposition::Reject,
    ),
    (
        "redirect",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "redirectmatch",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "redirectpermanent",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "redirecttemp",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "removecharset",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Reject,
    ),
    (
        "removeencoding",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Reject,
    ),
    (
        "removehandler",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "removetype",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "requestheader",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Reject,
    ),
    (
        "require",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "rewritebase",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "rewritecond",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "rewriteengine",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "rewriteoptions",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "rewriterule",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "satisfy",
        OverrideCategory::AuthConfig,
        DirectiveDisposition::Effectful,
    ),
    (
        "sethandler",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "setenv",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "setenvif",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "setenvifnocase",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "setinputfilter",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "setoutputfilter",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
    (
        "unsetenv",
        OverrideCategory::FileInfo,
        DirectiveDisposition::Effectful,
    ),
];

#[cfg(test)]
static TEST_REJECT_SPEC: (&str, OverrideCategory, DirectiveDisposition) = (
    "coverage-reject",
    OverrideCategory::FileInfo,
    DirectiveDisposition::Reject,
);
#[cfg(test)]
static TEST_UNHANDLED_SPEC: (&str, OverrideCategory, DirectiveDisposition) = (
    "coverage-unhandled",
    OverrideCategory::FileInfo,
    DirectiveDisposition::Effectful,
);

fn directive_spec(
    name: &str,
) -> Option<&'static (&'static str, OverrideCategory, DirectiveDisposition)> {
    #[cfg(test)]
    {
        if name == TEST_REJECT_SPEC.0 {
            return Some(&TEST_REJECT_SPEC);
        }
        if name == TEST_UNHANDLED_SPEC.0 {
            return Some(&TEST_UNHANDLED_SPEC);
        }
    }
    DIRECTIVE_SPECS.iter().find(|spec| spec.0 == name)
}

fn directive_category(name: &str) -> Option<OverrideCategory> {
    directive_spec(name).map(|spec| spec.1)
}

#[cfg(test)]
fn directive_allowed(mode: OverrideMode, name: &str, args: &[String]) -> bool {
    directive_allowed_list(mode, &[], name, args)
}

fn directive_allowed_list(
    mode: OverrideMode,
    allow_list: &[String],
    name: &str,
    args: &[String],
) -> bool {
    if allow_list
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(name))
    {
        return true;
    }
    if name == "options" {
        if mode.allows(OverrideCategory::Options) {
            return true;
        }
        if !mode.allows_any_option() {
            return false;
        }
        if args.is_empty() {
            return false;
        }
        // Apache 2.4 uses `AllowOverride Options=ExecCGI,Includes,...` for
        // per-option permissions.  Removing an option still requires
        // permission for that option; only `Options None` is always allowed
        // once any Options override is enabled.
        return args.iter().all(|arg| {
            let flag = arg.trim_start_matches(['+', '-']).to_ascii_lowercase();
            if flag == "none" {
                return true;
            }
            let bit = match flag.as_str() {
                "all" => OverrideCategories::OPTIONS,
                "execcgi" => OverrideCategories::EXEC_CGI,
                "includes" => OverrideCategories::INCLUDES,
                "includesnoexec" => OverrideCategories::INCLUDES_NOEXEC,
                "followsymlinks" => OverrideCategories::OPT_FOLLOW_SYMLINKS,
                "indexes" => OverrideCategories::OPT_INDEXES,
                "multiviews" => OverrideCategories::OPT_MULTIVIEWS,
                "symlinksifownermatch" => OverrideCategories::OPT_SYMLINKS_IF_OWNER_MATCH,
                _ => return false,
            };
            mode.allows_flag(bit)
        });
    }
    match directive_category(name) {
        Some(cat) => mode.allows(cat),
        // Unknown directives fall through to apply_directive, which rejects
        // them.  Do not let them bypass a category check.
        None => true,
    }
}

/// Schema used while sealing an access program, before section admission or
/// execute-on-read skipping. A malformed child therefore cannot hide in an
/// inactive wrapper and later acquire meaning after a configuration change.
fn access_directive_schema(name: &str) -> PayloadSchema {
    let (min, max) = match name {
        "authtype"
        | "authname"
        | "authuserfile"
        | "authgroupfile"
        | "sethandler"
        | "forcetype"
        | "adddefaultcharset"
        | "rewriteengine"
        | "rewritebase"
        | "order"
        | "satisfy"
        | "authmerging"
        | "enablesendfile"
        | "directoryslash"
        | "expiresactive"
        | "deflatecompressionlevel"
        | "brotlicompressionquality"
        | "deflatealteretag"
        | "brotlialteretag"
        | "brotlicompressionalteretag"
        | "deflatebuffersize"
        | "deflatememlevel"
        | "deflatewindowssize"
        | "headername"
        | "readmefile"
        | "cgipassauth" => (1, Some(1)),
        "errordocument" | "redirectpermanent" | "redirecttemp" => (2, Some(2)),
        "redirect" | "redirectmatch" | "rewritecond" | "rewriterule" => (2, Some(3)),
        "setenv" => (1, Some(2)),
        "addtype"
        | "addhandler"
        | "addinputfilter"
        | "addoutputfilter"
        | "addoutputfilterbytype"
        | "allow"
        | "deny"
        | "addcharset"
        | "addencoding"
        | "addlanguage"
        | "adddescription" => (2, None),
        "setenvif" | "setenvifnocase" => (3, None),
        "browsermatch" | "browsermatchnocase" => (2, None),
        "require" | "authbasicprovider" | "options" | "directoryindex" | "removetype"
        | "removehandler" | "removecharset" | "removeencoding" | "setoutputfilter"
        | "setinputfilter" | "unsetenv" | "passenv" | "indexignore" | "indexoptions"
        | "rewriteoptions" | "expiresdefault" | "fileetag" | "deflatefilternote" => (1, None),
        // Header has action-specific arity and ExpiresByType has a duration
        // expression spanning the remainder of the line.
        "header" | "expiresbytype" => (2, None),
        // Rejected directives still pass through this default; they fail
        // below rather than acquiring invented syntax here.
        _ => (0, None),
    };
    let reject_empty = matches!(
        name,
        "authtype"
            | "authuserfile"
            | "authgroupfile"
            | "authbasicprovider"
            | "sethandler"
            | "forcetype"
            | "rewriteengine"
            | "rewritebase"
            | "order"
            | "satisfy"
            | "authmerging"
    );
    let value = match name {
        "options" => PayloadValueSchema::Options,
        "require" => PayloadValueSchema::Require,
        "allow" | "deny" => PayloadValueSchema::LegacyHosts,
        "fileetag" => PayloadValueSchema::FileEtag,
        "errordocument" => PayloadValueSchema::ErrorDocument,
        "directoryindex" => PayloadValueSchema::DirectoryIndex,
        "header" => PayloadValueSchema::Header,
        "redirect" => PayloadValueSchema::Redirect {
            forced_status: None,
            regex: false,
        },
        "redirectpermanent" => PayloadValueSchema::Redirect {
            forced_status: Some(301),
            regex: false,
        },
        "redirecttemp" => PayloadValueSchema::Redirect {
            forced_status: Some(302),
            regex: false,
        },
        "redirectmatch" => PayloadValueSchema::Redirect {
            forced_status: None,
            regex: true,
        },
        "rewritecond" => PayloadValueSchema::RewriteCond,
        "rewriterule" => PayloadValueSchema::RewriteRule,
        "rewriteoptions" => PayloadValueSchema::RepeatedKeyword("Inherit"),
        "expiresdefault" => PayloadValueSchema::ExpiresDefault,
        "expiresbytype" => PayloadValueSchema::ExpiresByType,
        "setenvif" | "setenvifnocase" | "browsermatch" | "browsermatchnocase" => {
            PayloadValueSchema::EnvironmentRule
        }
        "indexignore" => PayloadValueSchema::GlobPatterns,
        "rewriteengine" | "enablesendfile" | "directoryslash" | "expiresactive" | "cgipassauth" => {
            PayloadValueSchema::OnOff
        }
        "deflatecompressionlevel" => PayloadValueSchema::Unsigned { min: 0, max: 9 },
        "brotlicompressionquality" => PayloadValueSchema::Unsigned { min: 0, max: 11 },
        "deflatealteretag" | "brotlialteretag" | "brotlicompressionalteretag" => {
            PayloadValueSchema::Keyword(&["AddSuffix", "NoChange", "Remove"])
        }
        "order" => PayloadValueSchema::Keyword(&["allow,deny", "mutual-failure", "deny,allow"]),
        "satisfy" => PayloadValueSchema::Keyword(&["all", "any"]),
        "authmerging" => PayloadValueSchema::Keyword(&["off", "and", "or"]),
        "authtype" => PayloadValueSchema::Keyword(&["basic"]),
        "authbasicprovider" => PayloadValueSchema::Keyword(&["file"]),
        _ => PayloadValueSchema::Tokens,
    };
    PayloadSchema::typed(PayloadArity { min, max }, reject_empty, value)
}

fn apply_directive(
    cfg: &Config,
    scope: &mut Scope,
    name: &str,
    payload: &SealedPayload,
    limit: Option<&MethodSet>,
    require_only: bool,
) -> Result<(), String> {
    let args = payload.as_slice();
    if !payload.refines(access_directive_schema(name).value.semantic_kind()) {
        return Err(format!(
            "internal semantic payload mismatch for .htaccess directive '{name}'"
        ));
    }
    let Some(spec) = directive_spec(name) else {
        return Err(format!("unsupported .htaccess directive '{name}'"));
    };
    if spec.2 == DirectiveDisposition::Reject {
        return Err(match name {
            "allowmethods" => {
                "AllowMethods is only allowed in directory configuration, not .htaccess".into()
            }
            "requestheader" => {
                "RequestHeader is not implemented in .htaccess; refusing to ignore a request-mutating directive"
                    .into()
            }
            _ => format!("unsupported .htaccess directive '{name}'"),
        });
    }
    let first = args.first().map(String::as_str).unwrap_or("");
    match name {
        "require" => {
            let provider = payload
                .require()
                .expect("Require is compiled while sealing")
                .clone();
            if !require_only && require_is_negated(&provider) {
                return Err("negative Require directive has no effect in <RequireAny>".into());
            }
            scope.add_require(RequireNode::Provider(provider), limit);
        }
        "authtype" => {
            debug_assert_eq!(payload.keyword(), Some(0));
            scope.authorization.auth_type = Some("basic".into());
        }
        "authname" => scope.authorization.auth_name = Some(first.to_string()),
        "authuserfile" => scope.authorization.auth_user_file = Some(server_path(cfg, first)),
        "authgroupfile" => scope.authorization.auth_group_file = Some(server_path(cfg, first)),
        "authbasicprovider" => {
            debug_assert_eq!(payload.keyword(), Some(0));
        }
        "options" => {
            let options = payload
                .options()
                .expect("Options is compiled while sealing");
            if options.requires_autoindex {
                require_capability(cfg, Capability::AutoIndex, "Options Indexes/All")?;
            }
            if options.requires_cgi {
                require_capability(cfg, Capability::Cgi, "Options ExecCGI/All")?;
            }
            scope.options.merge_child(&options.policy);
        }
        "directoryindex" => scope.content_policy.directory_index = Some(args.to_vec()),
        "errordocument" => {
            let (code, document) = payload
                .error_document()
                .expect("ErrorDocument is compiled while sealing");
            scope.error_policy.documents.push((code, document.clone()));
        }
        "addtype" => {
            scope
                .content_policy
                .add_types
                .push((args[0].clone(), args[1..].join(" ")));
        }
        "removetype" => scope
            .content_policy
            .remove_types
            .extend(args.iter().cloned()),
        "addhandler" => {
            require_handler_capability(cfg, &args[0], "AddHandler")?;
            for ext in &args[1..] {
                scope
                    .mapping_policy
                    .handlers
                    .push(crate::config::Handler::add(
                        crate::config::normalize_handler_extension(ext),
                        args[0].clone(),
                    ));
            }
        }
        "removehandler" => {
            for ext in args {
                scope
                    .mapping_policy
                    .handlers
                    .push(crate::config::Handler::remove(
                        crate::config::normalize_handler_extension(&ext),
                    ));
            }
        }
        "sethandler" => {
            require_handler_capability(cfg, first, "SetHandler")?;
            scope.mapping_policy.set_handler = Some(crate::config::SetHandler::parse(first));
        }
        "forcetype" => scope.content_policy.force_type = Some(first.to_string()),
        "adddefaultcharset" => {
            if !first.eq_ignore_ascii_case("off") {
                scope.content_policy.default_charset = Some(first.to_string());
            }
        }
        "addoutputfilterbytype" => {
            let (kinds, unsupported) = crate::config::parse_filter_names(&args[..1]);
            for kind in kinds {
                scope
                    .compression_policy
                    .compression_rules
                    .push(CompressionRule::ByType(
                        kind,
                        args[1..].iter().map(|s| s.to_ascii_lowercase()).collect(),
                    ));
            }
            for name in unsupported {
                scope.compression_policy.unsupported_filter_rules.push(
                    crate::config::UnsupportedFilterRule::ByType(
                        name,
                        args[1..].iter().map(|s| s.to_ascii_lowercase()).collect(),
                    ),
                );
            }
        }
        "addoutputfilter" => {
            let (kinds, unsupported) = crate::config::parse_filter_names(&args[..1]);
            for kind in kinds {
                scope
                    .compression_policy
                    .compression_rules
                    .push(CompressionRule::ByExt(
                        kind,
                        args[1..].iter().map(|s| s.to_ascii_lowercase()).collect(),
                    ));
            }
            for name in unsupported {
                scope.compression_policy.unsupported_filter_rules.push(
                    crate::config::UnsupportedFilterRule::ByExt(
                        name,
                        args[1..].iter().map(|s| s.to_ascii_lowercase()).collect(),
                    ),
                );
            }
        }
        "setoutputfilter" => {
            let kinds = parse_filter_tokens(scope, args);
            if !kinds.is_empty() {
                scope
                    .compression_policy
                    .compression_rules
                    .push(CompressionRule::Set(kinds));
            }
        }
        "setinputfilter" | "addinputfilter" => {
            for token in args {
                for part in token.split(';') {
                    let part = part.trim();
                    if !part.is_empty()
                        && !scope
                            .mapping_policy
                            .unsupported_filters
                            .iter()
                            .any(|f| f.eq_ignore_ascii_case(part))
                    {
                        scope
                            .mapping_policy
                            .unsupported_filters
                            .push(part.to_string());
                    }
                }
            }
        }
        "deflatecompressionlevel" => {
            scope.compression_policy.deflate_level = Some(
                payload
                    .unsigned()
                    .expect("DeflateCompressionLevel is typed while sealing")
                    as u32,
            );
        }
        "brotlicompressionquality" => {
            scope.compression_policy.brotli_quality = Some(
                payload
                    .unsigned()
                    .expect("BrotliCompressionQuality is typed while sealing")
                    as u32,
            );
        }
        "deflatealteretag" => {
            let value = match payload
                .keyword()
                .expect("DeflateAlterETag is typed while sealing")
            {
                0 => AlterEtag::AddSuffix,
                1 => AlterEtag::NoChange,
                2 => AlterEtag::Remove,
                _ => unreachable!("sealed AlterETag keyword index"),
            };
            scope.compression_policy.deflate_alter_etag = Some(value);
        }
        "brotlialteretag" | "brotlicompressionalteretag" => {
            let value = match payload
                .keyword()
                .expect("BrotliCompressionAlterETag is typed while sealing")
            {
                0 => AlterEtag::AddSuffix,
                1 => AlterEtag::NoChange,
                2 => AlterEtag::Remove,
                _ => unreachable!("sealed AlterETag keyword index"),
            };
            scope.compression_policy.brotli_alter_etag = Some(value);
        }
        "header" => {
            let previous = scope.header_policy.clone();
            payload
                .header()
                .expect("Header is compiled while sealing")
                .apply(&mut scope.header_policy);
            if !scope.header_policy.within_limits() {
                scope.header_policy = previous;
                return Err("configured response headers exceed the count/byte limit".into());
            }
        }
        "order" => {
            require_capability(cfg, Capability::LegacyAuthz, "Order")?;
            let order = match payload.keyword().expect("Order is typed while sealing") {
                0 | 1 => Order::AllowDeny,
                2 => Order::DenyAllow,
                _ => unreachable!("sealed Order keyword index"),
            };
            scope.add_order(order, limit);
        }
        "allow" | "deny" => {
            require_capability(cfg, Capability::LegacyAuthz, name)?;
            for host in payload
                .legacy_hosts()
                .expect("legacy host ACL is compiled while sealing")
                .iter()
                .cloned()
            {
                if name == "allow" {
                    scope.add_allow(host, limit);
                } else {
                    scope.add_deny(host, limit);
                }
            }
        }
        "satisfy" => {
            require_capability(cfg, Capability::LegacyAuthz, "Satisfy")?;
            let satisfy = match payload.keyword().expect("Satisfy is typed while sealing") {
                0 => Satisfy::All,
                1 => Satisfy::Any,
                _ => unreachable!("sealed Satisfy keyword index"),
            };
            scope.add_satisfy(satisfy, limit);
        }
        "authmerging" => {
            scope.authorization.auth_merging = Some(
                match payload
                    .keyword()
                    .expect("AuthMerging is typed while sealing")
                {
                    0 => AuthMerging::Off,
                    1 => AuthMerging::And,
                    2 => AuthMerging::Or,
                    _ => unreachable!("sealed AuthMerging keyword index"),
                },
            );
        }
        "rewriteengine" => {
            scope.rewrite_policy.rewrite_engine = Some(
                payload
                    .on_off()
                    .expect("RewriteEngine is typed while sealing"),
            );
        }
        "rewritebase" => scope.rewrite_policy.rewrite_base = Some(normalize_rewrite_base(first)),
        "rewritecond" => scope.rewrite_policy.pending_rewrite_conds.push(
            payload
                .rewrite_cond()
                .expect("RewriteCond is compiled while sealing")
                .clone(),
        ),
        "rewriterule" => {
            let match_base = scope
                .rewrite_policy
                .rewrite_match_base
                .as_deref()
                .unwrap_or("/");
            let subst_base = scope
                .rewrite_policy
                .rewrite_base
                .as_deref()
                .unwrap_or(match_base);
            let mut rule = payload
                .rewrite_rule()
                .expect("RewriteRule is compiled while sealing")
                .clone();
            rule.match_base = normalize_rewrite_base(match_base);
            rule.per_dir = true;
            rule.filesystem_context = true;
            if let Some(handler) = rule.flags.handler.as_deref() {
                require_handler_capability(cfg, handler, "RewriteRule")?;
            }
            rule.access_file = true;
            rule.base = normalize_rewrite_base(subst_base);
            rule.conditions = std::mem::take(&mut scope.rewrite_policy.pending_rewrite_conds);
            scope.rewrite_policy.rewrite_rules.push(rule);
        }
        "rewriteoptions" => {
            scope.rewrite_policy.rewrite_inherit = Some(true);
        }
        "redirect" | "redirectpermanent" | "redirecttemp" => {
            scope.mapping_policy.redirects.push(
                payload
                    .redirect()
                    .expect("Redirect is compiled while sealing")
                    .clone(),
            );
        }
        "redirectmatch" => scope.mapping_policy.redirects.push(
            payload
                .redirect()
                .expect("RedirectMatch is compiled while sealing")
                .clone(),
        ),
        "fileetag" => {
            scope.content_policy.file_etag = Some(
                payload
                    .file_etag()
                    .expect("FileETag is compiled while sealing"),
            );
        }
        "enablesendfile" => {
            scope.content_policy.enable_sendfile = Some(
                payload
                    .on_off()
                    .expect("EnableSendfile is typed while sealing"),
            )
        }
        "directoryslash" => {
            scope.content_policy.directory_slash = Some(
                payload
                    .on_off()
                    .expect("DirectorySlash is typed while sealing"),
            )
        }
        "expiresactive" => {
            scope.header_policy.expires_active = Some(
                payload
                    .on_off()
                    .expect("ExpiresActive is typed while sealing"),
            )
        }
        "cgipassauth" => {
            scope.environment_policy.cgi_pass_auth = Some(
                payload
                    .on_off()
                    .expect("CGIPassAuth is typed while sealing"),
            )
        }
        "expiresdefault" => {
            scope.header_policy.expires_default = Some(
                payload
                    .expires_default()
                    .expect("ExpiresDefault is compiled while sealing")
                    .to_string(),
            );
        }
        "expiresbytype" => {
            let (content_type, spec) = payload
                .expires_by_type()
                .expect("ExpiresByType is compiled while sealing");
            scope
                .header_policy
                .expires_by_type
                .push((content_type.to_string(), spec.to_string()));
        }
        "setenv" => {
            let Some(name) = args.first() else {
                return Err("SetEnv requires a variable".into());
            };
            scope
                .environment_policy
                .set_env
                .push(crate::scope_policy::Originated::access((
                    name.clone(),
                    args[1..].join(" "),
                )));
        }
        "unsetenv" => scope.environment_policy.unset_env.extend(
            args.iter()
                .cloned()
                .map(crate::scope_policy::Originated::access),
        ),
        "passenv" => scope.environment_policy.pass_env.extend(
            args.iter()
                .cloned()
                .map(crate::scope_policy::Originated::access),
        ),
        "setenvif" | "setenvifnocase" | "browsermatch" | "browsermatchnocase" => {
            scope
                .environment_policy
                .set_env_if
                .push(crate::scope_policy::Originated::access(
                    payload
                        .environment_rule()
                        .expect("environment rule is compiled while sealing")
                        .clone(),
                ));
        }
        "indexignore" => {
            scope.content_policy.index_ignore.extend(
                payload
                    .glob_patterns()
                    .expect("IndexIgnore patterns are validated while sealing")
                    .iter()
                    .cloned(),
            );
        }
        _ => return Err(format!("unsupported .htaccess directive '{name}'")),
    }
    Ok(())
}

fn require_capability(cfg: &Config, capability: Capability, feature: &str) -> Result<(), String> {
    if vapache_verified::capability_admit(cfg.capability_enabled(capability), true) {
        Ok(())
    } else {
        Err(format!(
            "{feature} requires global 'VapacheCapability {} On'",
            capability.name()
        ))
    }
}

fn require_handler_capability(cfg: &Config, handler: &str, directive: &str) -> Result<(), String> {
    if handler.eq_ignore_ascii_case("cgi-script") {
        require_capability(cfg, Capability::Cgi, &format!("{directive} cgi-script"))?;
    }
    if handler.eq_ignore_ascii_case("server-status") {
        require_capability(
            cfg,
            Capability::ServerStatus,
            &format!("{directive} server-status"),
        )?;
    }
    if handler.to_ascii_lowercase().contains("fcgi://") {
        require_capability(cfg, Capability::FastCgi, &format!("{directive} FastCGI"))?;
    }
    Ok(())
}

fn server_path(cfg: &Config, value: &str) -> PathBuf {
    let p = PathBuf::from(value);
    if p.is_absolute() {
        p
    } else {
        cfg.server_root.join(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthPolicy, Options, OverrideCategories, RequireEntry};
    use std::collections::HashMap;
    use std::fs;

    fn require_entries(policy: Option<AuthPolicy>) -> Vec<RequireEntry> {
        match policy {
            Some(AuthPolicy::List(entries)) => entries,
            other => panic!("expected a flat Require list, got {other:?}"),
        }
    }

    #[test]
    fn override_categories_gate_security_directives() {
        let req = vec!["all".into(), "denied".into()];
        let args = |s: &str| vec![s.to_string()];
        let all = OverrideMode::All;
        let auth = OverrideMode::Categories(OverrideCategories(OverrideCategories::AUTH_CONFIG));
        let file = OverrideMode::Categories(OverrideCategories(OverrideCategories::FILE_INFO));
        let limit = OverrideMode::Categories(OverrideCategories(OverrideCategories::LIMIT));
        let indexes = OverrideMode::Categories(OverrideCategories(OverrideCategories::INDEXES));
        let options = OverrideMode::Categories(OverrideCategories(OverrideCategories::OPTIONS));
        let opt_indexes =
            OverrideMode::Categories(OverrideCategories(OverrideCategories::OPT_INDEXES));

        assert!(directive_allowed(all, "require", &req));
        assert!(directive_allowed(auth, "require", &req));
        assert!(!directive_allowed(file, "require", &req));
        assert!(!directive_allowed(limit, "require", &req));
        assert!(directive_allowed(limit, "order", &args("allow,deny")));
        assert!(!directive_allowed(auth, "order", &args("allow,deny")));
        assert!(directive_allowed(file, "header", &args("set X yes")));
        assert!(!directive_allowed(auth, "header", &args("set X yes")));
        assert!(directive_allowed(
            indexes,
            "directoryindex",
            &args("index.html")
        ));
        assert!(!directive_allowed(
            file,
            "directoryindex",
            &args("index.html")
        ));
        assert!(directive_allowed(options, "options", &args("+Indexes")));
        assert!(directive_allowed(opt_indexes, "options", &args("+Indexes")));
        assert!(!directive_allowed(
            opt_indexes,
            "options",
            &args("+ExecCGI")
        ));
        assert!(directive_allowed(all, "satisfy", &args("any")));
        assert!(directive_allowed(auth, "satisfy", &args("any")));
        assert!(!directive_allowed(opt_indexes, "satisfy", &args("any")));
        assert!(!directive_allowed(OverrideMode::None, "require", &req));
    }

    fn tempdir(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("vapache-htaccess-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn config(root: &Path, text: &str) -> Config {
        let path = root.join("httpd.conf");
        fs::write(&path, format!("{}{text}", crate::config::TEST_CAPABILITIES)).unwrap();
        Config::load(&path, root, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    #[test]
    fn ancestor_walk_rejects_path_copy_amplification() {
        let mut path = PathBuf::from("/");
        for _ in 0..crate::util::MAX_POLICY_PATH_COMPONENTS {
            path.push("x");
        }
        assert!(ancestor_dirs(&path).is_err());
        assert!(ancestor_dirs(Path::new("/one/two/three")).is_ok());
    }

    #[test]
    fn enabled_override_on_a_non_directory_is_skipped() {
        let dir = tempdir("non-directory-layer");
        let blocked = dir.join("not-a-directory");
        fs::write(&blocked, "file").unwrap();
        let cfg = config(
            &dir,
            &format!(
                "Listen 127.0.0.1:0\n<Directory \"{}\">\nAllowOverride All\n</Directory>\n",
                blocked.display()
            ),
        );
        let layers = collect_layers(&cfg, None, &blocked.join("child"), "/child").unwrap();
        assert!(layers.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn parses_access_auth_and_media_directives() {
        let dir = tempdir("directives");
        let cfg = config(
            &dir,
            "Listen 127.0.0.1:0\nLoadModule authz_core_module /unused/mod_authz_core.so\n",
        );
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "# comment\n",
                "AuthType Basic\n",
                "AuthName \"Test Realm\"\n",
                "AuthUserFile users\n",
                "AuthGroupFile groups\n",
                "Require valid-user\n",
                "Options -Indexes +FollowSymLinks\n",
                "DirectoryIndex index.html index.cgi\n",
                "ErrorDocument 404 /not-found.html\n",
                "AddType text/x-test .t\n",
                "RemoveType .bad\n",
                "AddHandler cgi-script ..cgi\n",
                "ForceType text/plain\n",
                "Header set X-Test yes\n",
                "Header unset X-Old\n",
                "Header always add X-Added value with spaces\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(p.scope.authorization.auth_type.as_deref(), Some("basic"));
        assert_eq!(
            p.scope.authorization.auth_name.as_deref(),
            Some("Test Realm")
        );
        assert_eq!(
            p.scope.authorization.auth_user_file.as_deref(),
            Some(dir.join("users").as_path())
        );
        let entries = require_entries(p.scope.authorization.requires.clone());
        assert!(matches!(
            entries.as_slice(),
            [RequireEntry {
                node: RequireNode::Provider(crate::config::Require::ValidUser { negate: false }),
                limit: None,
            }]
        ));
        assert_eq!(
            p.scope.content_policy.directory_index.as_deref(),
            Some(&["index.html".to_string(), "index.cgi".to_string()][..])
        );
        assert!(p.scope.error_document(404).is_some());
        assert_eq!(
            p.scope.content_policy.force_type.as_deref(),
            Some("text/plain")
        );
        assert_eq!(p.scope.mapping_policy.handlers[0].ext, ".cgi");
        assert!(p
            .scope
            .header_policy
            .set_headers
            .iter()
            .any(|(n, v)| n == "X-Test" && v == "yes"));
        assert!(p
            .scope
            .header_policy
            .unset_headers
            .iter()
            .any(|n| n == "X-Old"));
        assert!(p
            .scope
            .header_policy
            .always_add_headers
            .iter()
            .any(|(n, v)| n == "X-Added" && v == "value with spaces"));
        let opts = p.scope.effective_options();
        assert!(!opts.contains(Options::INDEXES));
        assert!(opts.contains(Options::FOLLOW_SYMLINKS));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn setenv_directives_affect_require_and_are_not_discarded() {
        let dir = tempdir("setenv");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "SetEnv STATIC yes\n",
                "SetEnvIf X-Block yes BLOCK=1\n",
                "RewriteEngine On\n",
                "RewriteRule ^ - [E=ACCESS_REWRITE:yes]\n",
                "<Files \"secret.txt\">\n",
                "Require expr \"%{ENV:BLOCK} == ''\"\n",
                "</Files>\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(
            p.scope.environment_policy.set_env[0].value,
            ("STATIC".to_string(), "yes".to_string())
        );
        assert_eq!(
            p.scope.environment_policy.set_env[0].origin,
            vapache_verified::EnvironmentOrigin::AccessFile
        );
        assert_eq!(p.scope.environment_policy.set_env_if.len(), 1);
        assert_eq!(
            p.scope.environment_policy.set_env_if[0].origin,
            vapache_verified::EnvironmentOrigin::AccessFile
        );
        assert!(p.scope.rewrite_policy.rewrite_rules[0].access_file);
        let mut req = crate::http::Request {
            method: "GET".into(),
            target: b"/secret.txt".to_vec(),
            raw_path: b"/secret.txt".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        req.headers.push("X-Block", "yes");
        let env = p.scope.request_env(&req, "/", "127.0.0.1".parse().unwrap());
        assert!(env.iter().any(|(n, v)| n == "STATIC" && v == b"yes"));
        assert!(env.iter().any(|(n, v)| n == "BLOCK" && v == b"1"));
        let fastcgi = p.scope.fastcgi_env(&req, "/", "127.0.0.1".parse().unwrap());
        assert!(!fastcgi.iter().any(|(n, _)| n == "STATIC" || n == "BLOCK"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn indexignore_patterns_are_modeled() {
        let dir = tempdir("indexignore");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(&file, "IndexIgnore *.secret backup-?\n").unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(
            p.scope.content_policy.index_ignore,
            vec!["*.secret".to_string(), "backup-?".to_string()]
        );
        assert!(crate::config::glob_match(
            p.scope.content_policy.index_ignore[0].as_bytes(),
            b"wallet.secret"
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_require_groups_and_files_sections() {
        let dir = tempdir("sections");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "<RequireAll>\n",
                "Require all granted\n",
                "<RequireNone>\n",
                "Require ip 10.0.0.0/8\n",
                "Require ip 192.0.2.0/24\n",
                "</RequireNone>\n",
                "</RequireAll>\n",
                "<Files \"secret.txt\">\n",
                "Require all denied\n",
                "</Files>\n",
                "<FilesMatch \"\\.bak$\">\n",
                "Options -Indexes\n",
                "</FilesMatch>\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        let entries = require_entries(p.scope.authorization.requires.clone());
        assert_eq!(entries.len(), 1);
        assert_eq!(p.rules.len(), 2);
        assert!(rule_matches(&p.rules[0].kind, "secret.txt", "/secret.txt"));
        assert!(!rule_matches(&p.rules[0].kind, "other.txt", "/other.txt"));
        assert!(rule_matches(&p.rules[1].kind, "old.bak", "/old.bak"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ifmodule_skips_unknown_but_parses_supported() {
        let dir = tempdir("ifmodule");
        let cfg = config(
            &dir,
            "Listen 127.0.0.1:0\n\
             LoadModule rewrite_module /unused/mod_rewrite.so\n\
             LoadModule authz_core_module /unused/mod_authz_core.so\n",
        );
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "<IfModule mod_rewrite.c>\n",
                "RewriteEngine On\n",
                "</IfModule>\n",
                "<IfModule mod_authz_core.c>\n",
                "Require all denied\n",
                "</IfModule>\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        let entries = require_entries(p.scope.authorization.requires.clone());
        assert!(matches!(
            entries.as_slice(),
            [RequireEntry {
                node: RequireNode::Provider(crate::config::Require::AllDenied),
                limit: None,
            }]
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsupported_directives_and_sections_fail_closed() {
        let dir = tempdir("errors");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        for text in [
            "RewriteMap example txt:/tmp/map.txt\n",
            "<Limit GET>\nOptions +Indexes\n</Limit>\n",
            "<Files \"x\">\n",
            "Require all granted\n</Nope>\n",
            "<Limit BOGUS>\nRequire all granted\n</Limit>\n",
            "<Limit POST>\n<Limit POST>\nRequire all granted\n</Limit>\n</Limit>\n",
            "<Else>\nRequire all granted\n</Else>\n",
            "AllowMethods POST\n",
            "<If true>\n<Files secret.txt>\nRequire all granted\n</Files>\n</If>\n",
        ] {
            fs::write(&file, text).unwrap();
            assert!(
                parse_file(&cfg, &file, OverrideMode::All, "/").is_err(),
                "{text}"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_if_elseif_else_chains() {
        let dir = tempdir("elseif");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "<If \"%{HTTP:X-Test} == 'a'\">\n",
                "Header set X-Branch a\n",
                "</If>\n",
                "<ElseIf \"%{HTTP:X-Test} == 'b'\">\n",
                "Header set X-Branch b\n",
                "</ElseIf>\n",
                "<Else>\n",
                "Header set X-Branch c\n",
                "</Else>\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(p.rules.len(), 3);
        assert_eq!(p.rules[0].branch, ConditionBranch::Normal);
        assert_eq!(p.rules[1].branch, ConditionBranch::ElseIf);
        assert_eq!(p.rules[2].branch, ConditionBranch::Else);
        assert!(p.rules.iter().all(|rule| rule.chain == p.rules[0].chain));

        fs::write(
            &file,
            "<If \"1\">\n<If \"1\">\nHeader set X-Nested yes\n</If>\n</If>\n",
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].nested.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn iffile_is_frozen_against_server_root_and_preserves_child_phase() {
        let dir = tempdir("iffile");
        fs::create_dir_all(dir.join("sub")).unwrap();
        // A relative operand is resolved against ServerRoot, not against the
        // directory containing the access file or DocumentRoot.
        fs::write(dir.join("maintenance.flag"), "x").unwrap();
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join("sub/.htaccess");
        let parse = |text: &str| {
            fs::write(&file, text).unwrap();
            parse_file(&cfg, &file, OverrideMode::All, "/sub").unwrap()
        };
        let parsed = parse(
            "<IfFile maintenance.flag>\n<Files target.txt>\nRequire all granted\n</Files>\n</IfFile>\n",
        );
        assert_eq!(parsed.rules.len(), 1);
        assert!(matches!(parsed.rules[0].kind, MatchKind::FilesGlob(_)));
        assert!(parsed.rules[0].condition.is_none());

        fs::remove_file(dir.join("maintenance.flag")).unwrap();
        let parsed = parse("<IfFile maintenance.flag>\nHeader set X-IfFile yes\n</IfFile>\n");
        assert!(parsed.scope.header_policy.set_headers.is_empty());

        // Apache rejects extra operands instead of selecting only the first.
        fs::write(dir.join("first.flag"), "x").unwrap();
        fs::write(
            &file,
            "<IfFile first.flag ignored>\nHeader set X-IfFile yes\n</IfFile>\n",
        )
        .unwrap();
        assert!(parse_file(&cfg, &file, OverrideMode::All, "/sub").is_err());

        let parsed = parse("<IfFile !missing.flag>\nHeader set X-Negated yes\n</IfFile>\n");
        assert!(parsed
            .scope
            .header_policy
            .set_headers
            .iter()
            .any(|(name, _)| name == "X-Negated"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_authmerging() {
        let dir = tempdir("authmerging");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(&file, "AuthMerging And\nRequire all granted\n").unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(p.scope.authorization.auth_merging, Some(AuthMerging::And));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn access_files_reject_invalid_utf8() {
        let dir = tempdir("invalid-utf8");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(&file, b"Require all granted\n#\xff\n").unwrap();
        match parse_file(&cfg, &file, OverrideMode::All, "/") {
            Ok(_) => panic!("invalid UTF-8 access file was accepted"),
            Err(error) => assert!(error.contains("not valid UTF-8")),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn records_unsupported_filters() {
        let dir = tempdir("filters");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(&file, "SetOutputFilter INCLUDES\n").unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert!(p
            .scope
            .mapping_policy
            .unsupported_filters
            .iter()
            .any(|f| f.eq_ignore_ascii_case("INCLUDES")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn requestheader_is_rejected_instead_of_silently_ignored() {
        let dir = tempdir("requestheader");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        for line in [
            "RequestHeader set X-Block yes\n",
            "RequestHeader append X-Block yes\n",
            "RequestHeader unset X-Block\n",
            "RequestHeader echo X-Block\n",
        ] {
            fs::write(&file, line).unwrap();
            match parse_file(&cfg, &file, OverrideMode::All, "/") {
                Ok(_) => panic!("RequestHeader must be rejected: {line}"),
                Err(err) => assert!(err.contains("RequestHeader"), "{line}: {err}"),
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ExpectedEffect {
        Changed,
        Inert,
        Error,
    }

    struct DirectiveCase {
        name: &'static str,
        args: &'static [&'static str],
        effect: ExpectedEffect,
    }

    const DIRECTIVE_CASES: &[DirectiveCase] = &[
        DirectiveCase {
            name: "addcharset",
            args: &["utf-8", ".txt"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "adddefaultcharset",
            args: &["utf-8"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "adddescription",
            args: &["x", ".txt"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "addencoding",
            args: &["gzip", ".gz"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "addhandler",
            args: &["cgi-script", ".cgi"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "addinputfilter",
            args: &["INCLUDES", ".shtml"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "addlanguage",
            args: &["en", ".txt"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "addoutputfilter",
            args: &["DEFLATE", ".txt"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "addoutputfilterbytype",
            args: &["DEFLATE", "text/plain"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "addtype",
            args: &["text/plain", ".foo"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "allow",
            args: &["from", "all"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "allowmethods",
            args: &["POST"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "authbasicprovider",
            args: &["file"],
            effect: ExpectedEffect::Inert,
        },
        DirectiveCase {
            name: "authgroupfile",
            args: &["/tmp/htgroup"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "authmerging",
            args: &["And"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "authname",
            args: &["TestRealm"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "authtype",
            args: &["Basic"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "authuserfile",
            args: &["/tmp/htpasswd"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "browsermatch",
            args: &["yes", "FOO=bar"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "browsermatchnocase",
            args: &["yes", "FOO=bar"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "brotlialteretag",
            args: &["AddSuffix"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "brotlicompressionalteretag",
            args: &["AddSuffix"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "brotlicompressionquality",
            args: &["5"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "cgipassauth",
            args: &["On"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "deflatealteretag",
            args: &["AddSuffix"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "deflatebuffersize",
            args: &["4096"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "deflatecompressionlevel",
            args: &["6"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "deflatefilternote",
            args: &["foo"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "deflatememlevel",
            args: &["8"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "deflatewindowssize",
            args: &["15"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "deny",
            args: &["from", "all"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "directoryindex",
            args: &["index.html"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "directoryslash",
            args: &["Off"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "enablesendfile",
            args: &["On"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "errordocument",
            args: &["404", "/notfound.html"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "expiresactive",
            args: &["On"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "expiresbytype",
            args: &["text/html", "access plus 1 hour"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "expiresdefault",
            args: &["access plus 1 hour"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "fileetag",
            args: &["None"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "forcetype",
            args: &["text/plain"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "header",
            args: &["set", "X-Test", "yes"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "headername",
            args: &["HEADER"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "indexignore",
            args: &["*.secret"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "indexoptions",
            args: &["FancyIndexing"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "options",
            args: &["+Indexes"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "order",
            args: &["deny,allow"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "passenv",
            args: &["PATH"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "readmefile",
            args: &["README"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "redirect",
            args: &["/old", "/new"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "redirectmatch",
            args: &["^/old(.*)$", "/new$1"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "redirectpermanent",
            args: &["/old", "/new"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "redirecttemp",
            args: &["/old", "/new"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "removecharset",
            args: &[".txt"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "removeencoding",
            args: &[".gz"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "removehandler",
            args: &[".cgi"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "removetype",
            args: &[".foo"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "requestheader",
            args: &["set", "X-Test", "yes"],
            effect: ExpectedEffect::Error,
        },
        DirectiveCase {
            name: "require",
            args: &["all", "granted"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "rewritebase",
            args: &["/other/"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "rewritecond",
            args: &["%{REQUEST_URI}", "^/x$"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "rewriteengine",
            args: &["On"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "rewriteoptions",
            args: &["Inherit"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "rewriterule",
            args: &["^/old$", "/new", "[L]"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "satisfy",
            args: &["all"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "sethandler",
            args: &["cgi-script"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "setenv",
            args: &["FOO", "bar"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "setenvif",
            args: &["X-Test", "yes", "FOO=bar"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "setenvifnocase",
            args: &["X-Test", "yes", "FOO=bar"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "setinputfilter",
            args: &["INCLUDES"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "setoutputfilter",
            args: &["DEFLATE"],
            effect: ExpectedEffect::Changed,
        },
        DirectiveCase {
            name: "unsetenv",
            args: &["FOO"],
            effect: ExpectedEffect::Changed,
        },
    ];

    fn scope_signature(scope: &Scope) -> String {
        format!("{scope:?}")
    }

    #[test]
    fn htaccess_directive_matrix_is_exhaustive_and_matches_behavior() {
        let dir = tempdir("directive-matrix");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(&file, "").unwrap();
        let baseline = match parse_file(&cfg, &file, OverrideMode::All, "/dir/") {
            Ok(parsed) => scope_signature(&parsed.scope),
            Err(e) => panic!("empty .htaccess failed: {e}"),
        };

        let registry: std::collections::BTreeSet<&str> =
            DIRECTIVE_SPECS.iter().map(|spec| spec.0).collect();
        assert_eq!(
            registry.len(),
            DIRECTIVE_SPECS.len(),
            "duplicate directive in DIRECTIVE_SPECS"
        );
        let cases: std::collections::BTreeSet<&str> =
            DIRECTIVE_CASES.iter().map(|case| case.name).collect();
        assert_eq!(
            cases.len(),
            DIRECTIVE_CASES.len(),
            "duplicate directive in DIRECTIVE_CASES"
        );
        assert_eq!(
            cases, registry,
            "every recognized .htaccess directive needs exactly one effect case"
        );

        for case in DIRECTIVE_CASES {
            let line = if case.args.is_empty() {
                format!("{}\n", case.name)
            } else {
                format!("{} {}\n", case.name, case.args.join(" "))
            };
            fs::write(&file, &line).unwrap();
            let parsed = parse_file(&cfg, &file, OverrideMode::All, "/dir/");
            match case.effect {
                ExpectedEffect::Error => assert!(
                    parsed.is_err(),
                    "{} must fail closed, parsed successfully",
                    case.name
                ),
                ExpectedEffect::Inert => {
                    let parsed = match parsed {
                        Ok(parsed) => parsed,
                        Err(e) => panic!("{} must parse as inert: {e}", case.name),
                    };
                    assert_eq!(
                        scope_signature(&parsed.scope),
                        baseline,
                        "{} is marked inert but changed the scope",
                        case.name
                    );
                }
                ExpectedEffect::Changed => {
                    let parsed = match parsed {
                        Ok(parsed) => parsed,
                        Err(e) => panic!("{} must apply an effect: {e}", case.name),
                    };
                    assert_ne!(
                        scope_signature(&parsed.scope),
                        baseline,
                        "{} is marked effectful but did not change the scope",
                        case.name
                    );
                }
            }
            // A directive with no AllowOverride category would bypass the
            // override gate.  Every recognized directive must be denied when
            // overrides are disabled.
            assert!(
                parse_file(&cfg, &file, OverrideMode::None, "/dir/").is_err(),
                "{} is not gated by AllowOverride None",
                case.name
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn htaccess_rejects_unknown_main_config_only_directives_and_sections() {
        let dir = tempdir("rejected-surface");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        for line in [
            "DefinitelyNotADirective on\n",
            "VapacheCapability Trace On\n",
            "ProxyBlock 169.254.169.254\n",
            "AcceptPathInfo Off\n",
            "SetEnvIfExpr \"true\" X=1\n",
            "AuthzProviderAlias ldap-group foo\n",
            "<Directory /srv>\nRequire all denied\n</Directory>\n",
            "<Location />\nRequire all denied\n</Location>\n",
            "<Proxy http://example.test/>\nRequire all denied\n</Proxy>\n",
        ] {
            fs::write(&file, line).unwrap();
            match parse_file(&cfg, &file, OverrideMode::All, "/dir/") {
                Ok(_) => panic!("must fail closed: {line}"),
                Err(e) => assert!(
                    e.contains("unsupported") || e.contains("not supported"),
                    "{line}: {e}"
                ),
            }
        }
        fs::write(&file, "<IfDefine PROD>\nRequire all denied\n</IfDefine>\n").unwrap();
        let parsed = parse_file(&cfg, &file, OverrideMode::All, "/dir/").unwrap();
        assert!(parsed.scope.authorization.requires.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn htaccess_cannot_escalate_disabled_process_capabilities() {
        let dir = tempdir("capability-escalation");
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            "VapacheCapability AccessFiles On\nListen 127.0.0.1:0\n",
        )
        .unwrap();
        let cfg = Config::load(&conf, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let file = dir.join(".htaccess");
        for (line, capability) in [
            ("Options Indexes\n", "AutoIndex"),
            ("Options ExecCGI\n", "Cgi"),
            ("AddHandler cgi-script .cgi\n", "Cgi"),
            ("SetHandler server-status\n", "ServerStatus"),
            ("SetHandler proxy:fcgi://localhost\n", "FastCgi"),
            ("RewriteRule ^x$ - [H=cgi-script]\n", "Cgi"),
            ("RewriteRule ^x$ - [H=server-status]\n", "ServerStatus"),
            ("RewriteRule ^x$ - [H=proxy:fcgi://localhost]\n", "FastCgi"),
            ("Order deny,allow\n", "LegacyAuthz"),
            ("Deny from all\n", "LegacyAuthz"),
            ("Satisfy any\n", "LegacyAuthz"),
        ] {
            fs::write(&file, line).unwrap();
            let error = match parse_file(&cfg, &file, OverrideMode::All, "/dir/") {
                Ok(_) => panic!("{line:?} unexpectedly enabled a disabled capability"),
                Err(error) => error,
            };
            assert!(
                error.contains(&format!("VapacheCapability {capability} On")),
                "{line:?} did not report its disabled capability: {error}"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_method_limited_sections() {
        let dir = tempdir("limit-sections");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "<Limit POST PUT>\n",
                "Require valid-user\n",
                "Allow from 10.0.0.0/8\n",
                "Satisfy Any\n",
                "</Limit>\n",
                "<LimitExcept GET HEAD>\n",
                "Require all denied\n",
                "</LimitExcept>\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        let entries = require_entries(p.scope.authorization.requires.clone());
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].limit,
            Some(MethodSet::Only(vec!["POST".into(), "PUT".into()]))
        );
        assert_eq!(
            entries[1].limit,
            Some(MethodSet::Except(vec!["GET".into()]))
        );
        let legacy = p.scope.authorization.legacy.clone().expect("legacy rules");
        assert!(legacy.allow[0].applies("POST"));
        assert!(!legacy.allow[0].applies("GET"));
        assert!(legacy.satisfy[0].applies("PUT"));
        assert!(!legacy.satisfy[0].applies("GET"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_walks_ancestors_and_honours_allow_override() {
        let dir = tempdir("apply");
        let www = dir.join("www");
        fs::create_dir_all(www.join("sub")).unwrap();
        fs::write(www.join("sub").join("file.txt"), "body\n").unwrap();
        fs::write(www.join(".htaccess"), "Require all denied\n").unwrap();
        fs::write(
            www.join("sub").join(".htaccess"),
            "Require all granted\nHeader set X-Child yes\n",
        )
        .unwrap();
        let cfg_text = format!(
            "Listen 127.0.0.1:0\nDocumentRoot \"{}\"\n<Directory \"{}\">\nAllowOverride All\n</Directory>\n",
            www.display(),
            www.display()
        );
        let cfg = config(&dir, &cfg_text);
        let file = www.join("sub").join("file.txt");
        let mut scope = cfg.effective_scope(None, &file, "/sub/file.txt");
        apply(&cfg, None, &mut scope, &file, "/sub/file.txt").unwrap();
        let entries = require_entries(scope.authorization.requires);
        assert!(matches!(
            entries.as_slice(),
            [RequireEntry {
                node: RequireNode::Provider(crate::config::Require::AllGranted),
                limit: None,
            }]
        ));
        assert!(scope
            .header_policy
            .set_headers
            .iter()
            .any(|(n, v)| n == "X-Child" && v == "yes"));

        let no_override = config(
            &dir,
            &format!("Listen 127.0.0.1:0\nDocumentRoot \"{}\"\n", www.display()),
        );
        let mut scope = no_override.effective_scope(None, &file, "/sub/file.txt");
        apply(&no_override, None, &mut scope, &file, "/sub/file.txt").unwrap();
        assert!(scope.authorization.requires.is_none());
        assert!(scope.header_policy.set_headers.is_empty());

        // A parent directory can enable overrides while a child disables them.
        // The parent's rules still apply; the child's file must be ignored.
        let parent_only = config(
            &dir,
            &format!(
                "Listen 127.0.0.1:0\nDocumentRoot \"{}\"\n<Directory \"{}\">\nAllowOverride All\n</Directory>\n<Directory \"{}\">\nAllowOverride None\n</Directory>\n",
                www.display(),
                www.display(),
                www.join("sub").display()
            ),
        );
        let mut scope = parent_only.effective_scope(None, &file, "/sub/file.txt");
        apply(&parent_only, None, &mut scope, &file, "/sub/file.txt").unwrap();
        let entries = require_entries(scope.authorization.requires);
        assert!(matches!(
            entries.as_slice(),
            [RequireEntry {
                node: RequireNode::Provider(crate::config::Require::AllDenied),
                limit: None,
            }]
        ));
        assert!(scope.header_policy.set_headers.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn allow_override_categories_are_enforced_per_directive() {
        let dir = tempdir("categories");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        let mode = |flag| OverrideMode::Categories(crate::config::OverrideCategories(flag));

        fs::write(&file, "Require all granted\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::FILE_INFO), "/").is_err());

        fs::write(&file, "Options -Indexes\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::OPTIONS), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_err());

        fs::write(&file, "ErrorDocument 404 /missing\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::FILE_INFO), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_err());

        fs::write(&file, "Satisfy any\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::OPTIONS), "/").is_err());

        fs::write(&file, "<Limit POST>\nRequire valid-user\n</Limit>\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::LIMIT), "/").is_err());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::FILE_INFO), "/").is_err());

        fs::write(&file, "<Limit POST>\nAllow from all\n</Limit>\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::LIMIT), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_err());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::FILE_INFO), "/").is_err());

        fs::write(
            &file,
            "<Files \"secret\">\nHeader set X-Test yes\n</Files>\n",
        )
        .unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::FILE_INFO), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_err());

        fs::write(&file, "Options +ExecCGI\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::EXEC_CGI), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::OPTIONS), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::INCLUDES), "/").is_err());

        fs::write(&file, "Options +Includes\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::INCLUDES), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::EXEC_CGI), "/").is_err());

        fs::write(&file, "Options +Indexes\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::OPT_INDEXES), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::EXEC_CGI), "/").is_err());

        fs::write(&file, "Options None\n").unwrap();
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::EXEC_CGI), "/").is_ok());
        assert!(parse_file(&cfg, &file, mode(OverrideCategories::AUTH_CONFIG), "/").is_err());

        fs::write(&file, "Options +MadeUpOption\n").unwrap();
        assert!(parse_file(&cfg, &file, OverrideMode::All, "/").is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rewrite_directives_use_directory_and_rewrite_bases() {
        let dir = tempdir("rewrite-parse");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "RewriteEngine On\n",
                "RewriteCond %{QUERY_STRING} ^x=1$ [NC]\n",
                "RewriteBase /other/\n",
                "RewriteRule ^old\\.html$ new.html [L]\n",
            ),
        )
        .unwrap();
        let p = parse_file(
            &cfg,
            &file,
            OverrideMode::Categories(crate::config::OverrideCategories(
                crate::config::OverrideCategories::FILE_INFO,
            )),
            "/sub/",
        )
        .unwrap();
        assert_eq!(p.scope.rewrite_policy.rewrite_engine, Some(true));
        assert_eq!(p.scope.rewrite_policy.rewrite_rules.len(), 1);
        let rule = &p.scope.rewrite_policy.rewrite_rules[0];
        assert_eq!(rule.match_base, "/sub/");
        assert_eq!(rule.base, "/other/");
        assert!(rule.per_dir);
        assert_eq!(rule.subject_dir.as_deref(), Some(dir.as_path()));
        assert_eq!(rule.conditions[0].test, "%{QUERY_STRING}");
        assert!(rule.conditions[0].flags.nocase);

        // Unsupported flags and malformed conditions must fail closed.
        fs::write(&file, "RewriteEngine On\nRewriteRule ^x y [UNKNOWN]\n").unwrap();
        assert!(parse_file(&cfg, &file, OverrideMode::All, "/").is_err());
        fs::write(&file, "RewriteCond %{REQUEST_URI} [\nRewriteRule ^x y\n").unwrap();
        assert!(parse_file(&cfg, &file, OverrideMode::All, "/").is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_hits_and_invalidates_on_metadata_change() {
        let dir = tempdir("cache");
        let www = dir.join("www");
        fs::create_dir_all(www.join("sub")).unwrap();
        fs::write(www.join("sub").join("file.txt"), "body\n").unwrap();
        let ht = www.join(".htaccess");
        fs::write(&ht, "Require all denied\n").unwrap();
        let cfg = config(
            &dir,
            &format!(
                "Listen 127.0.0.1:0\nDocumentRoot \"{}\"\n<Directory \"{}\">\nAllowOverride All\n</Directory>\n",
                www.display(),
                www.display()
            ),
        );
        let file = www.join("sub").join("file.txt");
        for _ in 0..2 {
            let mut scope = cfg.effective_scope(None, &file, "/sub/file.txt");
            apply(&cfg, None, &mut scope, &file, "/sub/file.txt").unwrap();
            let entries = require_entries(scope.authorization.requires.clone());
            assert!(matches!(
                entries.as_slice(),
                [RequireEntry {
                    node: RequireNode::Provider(crate::config::Require::AllDenied),
                    limit: None,
                }]
            ));
        }

        // Same-size content change: the cache must notice ctime/mtime even
        // though the length has not changed.
        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&ht, "Header set X-Cache a\n").unwrap();
        let mut scope = cfg.effective_scope(None, &file, "/sub/file.txt");
        apply(&cfg, None, &mut scope, &file, "/sub/file.txt").unwrap();
        assert!(scope
            .header_policy
            .set_headers
            .iter()
            .any(|(n, v)| n == "X-Cache" && v == "a"));

        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&ht, "Header set X-Cache b\n").unwrap();
        let mut scope = cfg.effective_scope(None, &file, "/sub/file.txt");
        apply(&cfg, None, &mut scope, &file, "/sub/file.txt").unwrap();
        assert!(scope
            .header_policy
            .set_headers
            .iter()
            .any(|(n, v)| n == "X-Cache" && v == "b"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn logical_lines_join_continuations_and_skip_comments() {
        let lines = crate::config_frontend::logical_lines(
            "# hi\nRequire all \\\n denied\n\nOptions -Indexes\n",
        );
        assert_eq!(lines, vec!["Require all  denied", "Options -Indexes"]);
    }

    #[test]
    fn access_program_seals_nested_sections_before_skipping() {
        let lines = crate::config_frontend::logical_lines(
            "<Unknown>\n<Files secret>\nRequire all denied\n</Files>\n</Unknown>\nRequire all granted\n",
        );
        let program = AccessProgram::seal(&lines).unwrap();
        assert!(matches!(
            &program.instructions[0],
            AccessInstruction::SectionStart { end: 4, .. }
        ));
        assert!(matches!(
            &program.instructions[1],
            AccessInstruction::SectionStart { end: 3, .. }
        ));
        let mut cursor = 1;
        skip_section(&program, &mut cursor, "unknown").unwrap();
        assert_eq!(cursor, 5);
        assert!(matches!(
            &program.instructions[cursor],
            AccessInstruction::Directive { name, .. } if name == "require"
        ));

        let mismatched = crate::config_frontend::logical_lines("<Files x>\n</If>\n");
        assert!(AccessProgram::seal(&mismatched).is_err());

        let hidden_bad_match = crate::config_frontend::logical_lines(
            "<Unknown>\n<FilesMatch (?=unsupported-lookahead)>\n</FilesMatch>\n</Unknown>\n",
        );
        let error = match AccessProgram::seal(&hidden_bad_match) {
            Err(error) => error,
            Ok(_) => panic!("malformed nested section payload was accepted"),
        };
        assert!(error.contains("FilesMatch regex"), "{error}");

        let malformed_denied_directive =
            crate::config_frontend::logical_lines("<Files x>\nExpiresDefault nonsense\n</Files>\n");
        let error = match AccessProgram::seal(&malformed_denied_directive) {
            Err(error) => error,
            Ok(_) => panic!("malformed semantic payload was accepted"),
        };
        assert!(error.contains("invalid expiry syntax"), "{error}");
    }

    #[test]
    fn access_file_line_and_section_depth_are_bounded_before_descent() {
        let mut nested = Vec::new();
        for _ in 0..=MAX_ACCESS_SECTION_DEPTH {
            nested.push("<RequireAll>".to_string());
        }
        nested.push("Require all granted".to_string());
        for _ in 0..=MAX_ACCESS_SECTION_DEPTH {
            nested.push("</RequireAll>".to_string());
        }
        let error = match AccessProgram::seal(&nested) {
            Err(error) => error,
            Ok(_) => panic!("oversize access section nesting was accepted"),
        };
        assert!(error.contains("nesting exceeds"), "{error}");

        let wide = vec!["Require all granted".to_string(); MAX_ACCESS_INSTRUCTIONS_PER_FILE + 1];
        let error = match AccessProgram::seal(&wide) {
            Err(error) => error,
            Ok(_) => panic!("wide access program was accepted"),
        };
        assert!(error.contains("exceeds"), "{error}");

        assert!(vapache_verified::access_program_budget_admit(
            MAX_ACCESS_LAYERS as u64 - 1,
            MAX_ACCESS_INSTRUCTIONS_PER_REQUEST as u64 - 1,
            1,
            MAX_ACCESS_LAYERS as u64,
            MAX_ACCESS_INSTRUCTIONS_PER_REQUEST as u64,
        ));
        assert!(!vapache_verified::access_program_budget_admit(
            MAX_ACCESS_LAYERS as u64,
            0,
            0,
            MAX_ACCESS_LAYERS as u64,
            MAX_ACCESS_INSTRUCTIONS_PER_REQUEST as u64,
        ));

        let dir = tempdir("access-resource-bounds");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            format!("IndexIgnore {}\n", "*".repeat(MAX_HTACCESS_LINE)),
        )
        .unwrap();
        let error = match parse_file(&cfg, &file, OverrideMode::All, "/") {
            Err(error) => error,
            Ok(_) => panic!("oversize access-file line was accepted"),
        };
        assert!(error.contains("line limit"), "{error}");
        let _ = fs::remove_dir_all(dir);
    }

    fn request_with_header(name: &str, value: &str) -> crate::http::Request {
        let mut req = crate::http::Request {
            method: "GET".into(),
            target: b"/sub/secret.txt".to_vec(),
            raw_path: b"/sub/secret.txt".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        req.headers.push(name, value);
        req
    }

    #[test]
    fn access_walk_trace_collect_and_apply_request_paths() {
        let dir = tempdir("coverage-walk");
        let www = dir.join("www");
        for sub in ["sub", "empty", "bad", "oversize", "loop", "parse-error"] {
            fs::create_dir_all(www.join(sub)).unwrap();
        }
        fs::write(www.join("sub/secret.txt"), "secret\n").unwrap();
        fs::write(
            www.join(".htaccess"),
            concat!(
                "<Files \"secret.txt\">\n",
                "Header set X-FileRule yes\n",
                "</Files>\n",
                "<If \"%{HTTP:X-Branch} == 'yes'\">\n",
                "Header set X-CondRule yes\n",
                "</If>\n",
                "SetEnv ROOT yes\n",
            ),
        )
        .unwrap();
        fs::write(www.join(".htaccess2"), "SetEnv SECOND yes\n").unwrap();
        fs::write(www.join("sub/.htaccess"), "SetEnv SUB yes\n").unwrap();
        let cfg = config(
            &dir,
            &format!(
                "Listen 127.0.0.1:0\n\
                 DocumentRoot \"{}\"\n\
                 AccessFileName .htaccess .htaccess2\n\
                 <Directory \"{}\">\n\
                     AllowOverride All\n\
                 </Directory>\n",
                www.display(),
                www.display()
            ),
        );
        let file = www.join("sub/secret.txt");
        let req = request_with_header("X-Branch", "yes");
        let mut scope = Scope::default();
        apply_req(
            &cfg,
            None,
            &mut scope,
            &file,
            "/sub/secret.txt",
            Some(&req),
            "127.0.0.1".parse().unwrap(),
        )
        .unwrap();
        let env = scope.request_env(&req, "/x", "127.0.0.1".parse().unwrap());
        for expected in ["ROOT", "SUB"] {
            assert!(
                env.iter().any(|(name, _)| name == expected),
                "missing {expected}: {env:?}"
            );
        }
        assert!(!env.iter().any(|(name, _)| name == "SECOND"));
        assert!(scope
            .header_policy
            .set_headers
            .iter()
            .any(|(name, _)| name == "X-FileRule"));
        assert!(scope
            .header_policy
            .set_headers
            .iter()
            .any(|(name, _)| name == "X-CondRule"));

        let layers = collect_layers(&cfg, None, &file, "/sub/secret.txt").unwrap();
        assert_eq!(layers.len(), 2);

        let trace = trace_access_files(&cfg, None, &file, "/sub/secret.txt").join("\n");
        assert!(trace.contains(".htaccess"));
        assert!(!trace.contains(".htaccess2"));

        // The non-directory start and the outer configuration phase.
        let path_info = www.join("sub/secret.txt/more");
        let mut files = Vec::new();
        let mut deferred = Vec::new();
        let mut config_files = Vec::new();
        let mut scope = Scope::default();
        apply_req_deferred(
            &cfg,
            None,
            &mut scope,
            &www,
            "/",
            Some(&req),
            "127.0.0.1".parse().unwrap(),
            &mut files,
            &mut deferred,
            true,
            &mut config_files,
        )
        .unwrap();
        let mut files = Vec::new();
        let mut deferred = Vec::new();
        let mut config_files = Vec::new();
        let mut scope = Scope::default();
        apply_req_deferred(
            &cfg,
            None,
            &mut scope,
            &path_info,
            "/sub/secret.txt/more",
            Some(&req),
            "127.0.0.1".parse().unwrap(),
            &mut files,
            &mut deferred,
            true,
            &mut config_files,
        )
        .unwrap();

        // PATH_INFO starts at the script file; the trace must skip that
        // non-directory entry and still report the script's parent layers.
        let trace = trace_access_files(&cfg, None, &path_info, "/sub/secret.txt/more").join("\n");
        assert!(trace.contains(".htaccess"));

        // Metadata errors and parse errors are fail-closed.
        fs::create_dir_all(www.join("bad/.htaccess")).unwrap();
        assert!(collect_layers(&cfg, None, &www.join("bad/x"), "/bad/x").is_err());
        fs::write(
            www.join("oversize/.htaccess"),
            vec![b'#'; (MAX_HTACCESS + 1) as usize],
        )
        .unwrap();
        assert!(collect_layers(&cfg, None, &www.join("oversize/x"), "/oversize/x").is_err());
        std::os::unix::fs::symlink(".htaccess", www.join("loop/.htaccess")).unwrap();
        assert!(collect_layers(&cfg, None, &www.join("loop/x"), "/loop/x").is_err());
        fs::write(www.join("parse-error/.htaccess"), "Frobnicate something\n").unwrap();
        let trace =
            trace_access_files(&cfg, None, &www.join("parse-error/x"), "/parse-error/x").join("\n");
        assert!(trace.contains("ERROR"));

        // A tree with no access files at all, and a path outside every
        // override-enabled directory.
        let dir2 = tempdir("coverage-walk-empty");
        let www2 = dir2.join("www");
        fs::create_dir_all(www2.join("empty")).unwrap();
        fs::write(www2.join("empty/file.txt"), "x\n").unwrap();
        let cfg2 = config(
            &dir2,
            &format!(
                "Listen 127.0.0.1:0\nDocumentRoot \"{}\"\n<Directory \"{}\">\nAllowOverride All\n</Directory>\n",
                www2.display(),
                www2.display()
            ),
        );
        let trace =
            trace_access_files(&cfg2, None, &www2.join("empty/file.txt"), "/empty/file.txt")
                .join("\n");
        assert!(trace.contains("no access files present"));
        let trace = trace_access_files(&cfg2, None, Path::new("/outside/file"), "/file").join("\n");
        assert!(trace.contains("skipped"));
        assert!(
            collect_layers(&cfg2, None, Path::new("/outside/file"), "/file")
                .unwrap()
                .is_empty()
        );

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&dir2);
    }

    #[test]
    fn symlinked_mapping_root_trace_uses_canonical_target_layers() {
        let dir = tempdir("coverage-walk-symlink");
        let real = dir.join("real/public");
        let admin = real.join("admin");
        fs::create_dir_all(&admin).unwrap();
        fs::create_dir_all(dir.join("www")).unwrap();
        let root = dir.join("www/html");
        std::os::unix::fs::symlink(&real, &root).unwrap();
        fs::write(admin.join(".htaccess"), "Options -ExecCGI\n").unwrap();
        fs::write(admin.join("run.cgi"), "#!/bin/sh\n").unwrap();
        let cfg = config(
            &dir,
            &format!(
                "Listen 127.0.0.1:0\nDocumentRoot \"{}\"\n<Directory \"{}\">\nAllowOverride All\n</Directory>\n",
                root.display(),
                root.display()
            ),
        );
        let canonical = dir.join("real/public/admin/run.cgi");
        let trace =
            trace_access_files_with_root(&cfg, None, &canonical, "/admin/run.cgi", Some(&root))
                .join("\n");
        assert!(trace.contains(&admin.join(".htaccess").display().to_string()));
        let layers =
            collect_layers_with_root(&cfg, None, &canonical, "/admin/run.cgi", Some(&root))
                .unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].identity.dir, admin);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lexical_allow_override_none_vetoes_canonical_all() {
        let dir = tempdir("coverage-walk-override-deny");
        let real = dir.join("real/public");
        let admin = real.join("admin");
        fs::create_dir_all(&admin).unwrap();
        fs::create_dir_all(dir.join("www")).unwrap();
        let root = dir.join("www/html");
        std::os::unix::fs::symlink(&real, &root).unwrap();
        fs::write(
            admin.join(".htaccess"),
            "Options +ExecCGI\nAddHandler cgi-script .cgi\n",
        )
        .unwrap();
        let cfg = config(
            &dir,
            &format!(
                "Listen 127.0.0.1:0\nDocumentRoot \"{}\"\n\
                 <Directory \"{}\">\nAllowOverride None\n</Directory>\n\
                 <Directory \"{}\">\nAllowOverride All\n</Directory>\n",
                root.display(),
                root.display(),
                real.display()
            ),
        );
        let canonical = admin.join("run.cgi");
        let layers =
            collect_layers_with_root(&cfg, None, &canonical, "/admin/run.cgi", Some(&root))
                .unwrap();
        assert!(
            layers.is_empty(),
            "a lexical AllowOverride None must suppress the canonical access file"
        );
        let trace =
            trace_access_files_with_root(&cfg, None, &canonical, "/admin/run.cgi", Some(&root))
                .join("\n");
        assert!(!trace.contains(&admin.join(".htaccess").display().to_string()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn access_roots_rule_matching_and_path_helpers() {
        let dir = tempdir("coverage-root");
        let www = dir.join("www");
        let alias = dir.join("alias");
        fs::create_dir_all(&www).unwrap();
        fs::create_dir_all(&alias).unwrap();
        let target = alias.join("wallet.dat");
        fs::write(&target, "wallet\n").unwrap();
        let file_dir = dir.join("files");
        fs::create_dir_all(&file_dir).unwrap();
        let target = file_dir.join("wallet.dat");
        fs::write(&target, "wallet\n").unwrap();
        let regex_dir = dir.join("regex-files");
        fs::create_dir_all(&regex_dir).unwrap();
        let regex_target = regex_dir.join("wallet.dat");
        fs::write(&regex_target, "wallet\n").unwrap();
        let cfg = config(
            &dir,
            &format!(
                "ServerRoot \"{}\"\n\
                 Listen 127.0.0.1:0\n\
                 DocumentRoot \"{}\"\n\
                 Alias /dir \"{}/\"\n\
                 Alias /file \"{}\"\n\
                 AliasMatch \"^/regex-wallet$\" \"{}/\"\n\
                 AliasMatch \"^/cap(.*)$\" \"$1\"\n",
                dir.display(),
                www.display(),
                alias.display(),
                target.display(),
                regex_target.display()
            ),
        );
        assert_eq!(access_root_for(&cfg, None, &alias.join("x")), alias);
        assert_eq!(access_root_for(&cfg, None, &target), file_dir);
        assert_eq!(
            access_root_for(&cfg, None, &regex_target),
            regex_dir,
            "regex file target with trailing slash must use its parent"
        );
        assert_eq!(access_root_for(&cfg, None, &dir.join("other")), www);

        let re = |p: &str| regex::bytes::Regex::new(p).unwrap();
        assert!(rule_matches(&MatchKind::Always, "x", "/x"));
        assert!(rule_matches(&MatchKind::Files(re("x")), "x", "/x"));
        assert!(rule_matches(&MatchKind::FilesMatch(re("x")), "x", "/x"));
        assert!(rule_matches(
            &MatchKind::Location(String::new()),
            "x",
            "/any"
        ));
        assert!(rule_matches(&MatchKind::Location("/a/".into()), "x", "/a"));
        assert!(rule_matches(&MatchKind::Location("/a".into()), "x", "/a/b"));
        assert!(!rule_matches(&MatchKind::Location("/a".into()), "x", "/ab"));
        assert!(rule_matches(
            &MatchKind::LocationGlob("/a/*".into()),
            "x",
            "/a/b"
        ));
        assert!(rule_matches(
            &MatchKind::LocationMatch(re("^/a")),
            "x",
            "/a/b"
        ));
        assert!(rule_matches(
            &MatchKind::Directory(PathBuf::from("/a")),
            "x",
            "/a/b"
        ));
        assert!(rule_matches(
            &MatchKind::DirectoryMatch(re("^/a")),
            "x",
            "/a/b"
        ));

        assert_eq!(mode_key(OverrideMode::None), 0);
        assert_eq!(
            crate::request_plan::layer_url_mount(&www, &www, &www.join("x"), "/x"),
            "/"
        );
        assert_eq!(
            crate::request_plan::layer_url_mount(
                &www,
                &alias,
                &alias.join("deep/file"),
                "/alias/deep/file"
            ),
            "/alias/"
        );
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv/www"),
                Path::new("/srv/www/a/b"),
                Path::new("/srv/www/a/b/f"),
                "/a/b/f"
            ),
            "/a/b/"
        );
        // F53: an alias target at the mapping root still has the URL mount,
        // not `/`, as its per-directory base.
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/srv/site"),
                Path::new("/srv/site/private/wallet.dat"),
                "/site/private/wallet.dat"
            ),
            "/site/"
        );
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/srv/site/private"),
                Path::new("/srv/site/private/wallet.dat"),
                "/site/private/wallet.dat"
            ),
            "/site/private/"
        );
        // A target deeper than the URL (fixed AliasMatch suffix) cannot be
        // described by URL depth; the layer uses Apache's filesystem
        // directory form.  Rewrite subject matching itself is carried by
        // `subject_dir`, not this substitution base (F58).
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/srv/site"),
                Path::new("/srv/site/sub1/sub2/private/wallet.dat"),
                "/m/private/wallet.dat"
            ),
            "/srv/site/"
        );
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/srv/site"),
                Path::new("/other/wallet.dat"),
                "/other/wallet.dat"
            ),
            "/srv/site/"
        );
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/other"),
                Path::new("/srv/site/wallet.dat"),
                "/other/deep/wallet.dat"
            ),
            "/other/"
        );
        assert_eq!(
            crate::request_plan::layer_url_mount(
                Path::new("/srv"),
                Path::new("/srv/site"),
                Path::new("/other/wallet.dat"),
                "/other/wallet.dat"
            ),
            "/srv/site/"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parser_section_and_directive_error_branches() {
        let dir = tempdir("coverage-parse-errors");
        let cfg = config(
            &dir,
            "Listen 127.0.0.1:0\nLoadModule authz_core_module /unused/mod_authz_core.so\n",
        );
        let file = dir.join(".htaccess");
        let parse = |text: &str, mode: OverrideMode, nonfatal: NonfatalMode, allow: &[String]| {
            fs::write(&file, text).unwrap();
            let identity = crate::request_plan::LayerIdentity::with_url_mount(&dir, &dir, "/");
            parse_file_with_list(&cfg, &file, mode, allow, nonfatal, &identity)
        };

        let all = OverrideMode::All;
        let cases: &[(&str, bool)] = &[
            ("Header \"unterminated\n", false),
            ("<Files \"x\">\n</If>\n", false),
            ("<Limit GET>\n<Files \"x\">\n</Files>\n</Limit>\n", false),
            (
                "<RequireAll>\n<If \"true\">\nRequire all granted\n</If>\n</RequireAll>\n",
                false,
            ),
            (
                "<IfFile ignored path>\nHeader set X-IfFile yes\n</IfFile>\n",
                false,
            ),
            ("<If \"true\">\n</If>\n<Else extra more>\n</Else>\n", false),
            (
                "<If \"true\">\n<FilesMatch \"[\">\n</FilesMatch>\n</If>\n",
                false,
            ),
            (
                "<IfModule mod_authz_core.c>\n<FilesMatch \"[\">\n</FilesMatch>\n</IfModule>\n",
                false,
            ),
            ("<RequireAll>\n</RequireAll>\n", true),
            (
                "<RequireAll>\n<Limit GET>\nRequire all granted\n</Limit>\n</RequireAll>\n",
                false,
            ),
            (
                "<Limit GET>\n<Limit POST>\nRequire all granted\n</Limit>\n</Limit>\n",
                false,
            ),
            (
                "<RequireAll>\n<Files \"x\">\nRequire all granted\n</Files>\n</RequireAll>\n",
                false,
            ),
            (
                "<FilesMatch \"[\">\nRequire all granted\n</FilesMatch>\n",
                false,
            ),
            (
                "<IfModule !mod_rewrite.c>\nRequire all denied\n</IfModule>\n",
                true,
            ),
            ("<IfModule>\nRequire all denied\n</IfModule>\n", false),
            (
                "<IfModule !mod_not_builtin.c>\nRequire all denied\n</IfModule>\n",
                true,
            ),
            ("<RequireAll>\nHeader set X y\n</RequireAll>\n", false),
            ("SetEnv\n", false),
            ("Options\n", false),
            ("Options All\n", true),
            ("Options Indexes\n", true),
            (
                "Options Indexes FollowSymLinks SymLinksIfOwnerMatch ExecCGI Includes IncludesNoExec MultiViews\n",
                true,
            ),
            ("Header always\n", false),
            ("Header always set\n", false),
            ("Header always set X yes\n", true),
            ("Header add X yes\n", true),
            ("Header bogus X y\n", false),
            ("Redirect\n", false),
            ("Redirect 301 /old /new\n", true),
            ("RedirectMatch 301 ^/old /new\n", true),
            ("FileETag Inode MTime Size All\n", true),
            ("AuthBasicProvider ldap\n", false),
            ("ErrorDocument x /x\n", false),
            ("ErrorDocument 404 http://example.test/x\n", true),
            ("ErrorDocument 404 plain text\n", false),
            ("DirectoryIndex index.html\n", true),
            ("DirectoryIndex index%2ehtml\n", false),
            ("DirectoryIndex index.html?variant=1\n", false),
            ("DirectoryIndex nested/index.html\n", false),
            ("Order bogus\n", false),
            ("Allow all\n", false),
            ("Allow from bogus\n", false),
            ("Satisfy bogus\n", false),
            ("AuthMerging bogus\n", false),
            ("RewriteEngine bogus\n", false),
            ("ReadmeFile README\n", false),
        ];
        for (text, ok) in cases {
            let result = parse(text, all, NonfatalMode::None, &[]);
            assert_eq!(result.is_ok(), *ok, "{text:?}");
        }

        // Nonfatal=Override/Unknown skip restricted material instead of
        // failing the whole request.
        for text in [
            "<RequireAll>\nRequire all denied\n</RequireAll>\n",
            "<Limit GET>\nRequire all denied\n</Limit>\n",
            "Options +Indexes\n",
        ] {
            assert!(parse(text, OverrideMode::None, NonfatalMode::Override, &[]).is_ok());
        }
        let unknown = parse(
            "<Unknown>\n\nplain text\n</Unknown>\n",
            OverrideMode::None,
            NonfatalMode::Unknown,
            &[],
        );
        assert!(unknown.is_ok(), "{:?}", unknown.err());
        let skipped = AccessProgram::seal(&crate::config_frontend::logical_lines(
            "<Unknown>\n<Nested>\n</Nested>\n</Unknown>\n",
        ))
        .unwrap();
        let mut at = 1usize;
        assert!(skip_section(&skipped, &mut at, "unknown").is_ok());
        assert_eq!(at, skipped.instructions.len());
        assert!(AccessProgram::seal(&["<Unknown>".to_string()]).is_err());
        assert!(parse(
            "Frobnicate x\n",
            OverrideMode::None,
            NonfatalMode::Unknown,
            &[],
        )
        .is_ok());
        assert!(parse(
            "<Unknown>\nRequire all granted\n",
            OverrideMode::None,
            NonfatalMode::Unknown,
            &[],
        )
        .is_err());
        // Nonfatal controls policy disposition, not lexical validity: the
        // complete access program must seal before any wrapper can be skipped.
        assert!(parse(
            "<RequireAll>\n\"unterminated\n</RequireAll>\n",
            OverrideMode::None,
            NonfatalMode::Override,
            &[],
        )
        .is_err());
        assert!(parse(
            "<RequireAll>\nRequire all denied\n</RequireAll>\n",
            OverrideMode::None,
            NonfatalMode::None,
            &[],
        )
        .is_err());
        assert!(parse(
            "Require all granted\n",
            OverrideMode::None,
            NonfatalMode::None,
            &["require".to_string()],
        )
        .is_ok());

        // P18: an inner directive in AllowOverrideList never admits its
        // section wrapper. This covers all supported section-mask families,
        // not only the reported <Files>/<FilesMatch> spelling.
        let require_only_list = &["require".to_string()];
        for text in [
            "<Files \"x\">\nRequire all granted\n</Files>\n",
            "<FilesMatch \"^x$\">\nRequire all granted\n</FilesMatch>\n",
            "<If \"true\">\nRequire all granted\n</If>\n",
            "<IfFile /tmp>\nRequire all granted\n</IfFile>\n",
            "<IfModule core_module>\nRequire all granted\n</IfModule>\n",
            "<RequireAll>\nRequire all granted\n</RequireAll>\n",
            "<Limit GET>\nRequire all granted\n</Limit>\n",
        ] {
            assert!(
                parse(
                    text,
                    OverrideMode::None,
                    NonfatalMode::None,
                    require_only_list,
                )
                .is_err(),
                "section wrapper escaped AllowOverrideList: {text:?}"
            );
        }
        assert!(parse(
            "<Files \"x\">\nRequire all granted\n</Files>\n",
            OverrideMode::None,
            NonfatalMode::Override,
            require_only_list,
        )
        .is_ok());
        for text in [
            "<IfFile missing>\nRequire all granted\n</IfFile>\n",
            "<IfModule core_module>\nRequire all granted\n</IfModule>\n",
            "<IfDefine MISSING>\nRequire all granted\n</IfDefine>\n",
            "<IfDirective Require>\nRequire all granted\n</IfDirective>\n",
            "<IfSection Files>\nRequire all granted\n</IfSection>\n",
            "<IfVersion >= 2.4>\nRequire all granted\n</IfVersion>\n",
        ] {
            assert!(
                parse(
                    text,
                    OverrideMode::None,
                    NonfatalMode::Override,
                    require_only_list,
                )
                .is_err(),
                "execute-on-read wrapper was incorrectly skipped: {text:?}"
            );
        }
        assert!(parse(
            "<RequireAll>\nRequire all granted\n<RequireNone>\nRequire ip 192.0.2.1\n</RequireNone>\n</RequireAll>\n",
            OverrideMode::None,
            NonfatalMode::None,
            &["<requireall".to_string(), "require".to_string()],
        )
        .is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn directive_permission_edges_options_and_cached_metadata() {
        let args = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(directive_allowed_list(
            OverrideMode::None,
            &["require".to_string()],
            "require",
            &args(&["all", "granted"])
        ));
        for section in AccessSectionKind::ALL {
            assert_eq!(AccessSectionKind::parse(section.name()), Some(section));
            assert!(
                !section_allowed_list(OverrideMode::None, &["require".to_string()], section),
                "{}",
                section.name()
            );
        }
        assert!(section_allowed_list(
            OverrideMode::None,
            &["<files".to_string()],
            AccessSectionKind::Files,
        ));
        assert!(!section_allowed_list(
            OverrideMode::None,
            &["files".to_string()],
            AccessSectionKind::Files,
        ));
        assert!(section_allowed_list(
            OverrideMode::Categories(OverrideCategories(OverrideCategories::AUTH_CONFIG,)),
            &[],
            AccessSectionKind::Files,
        ));
        assert!(!directive_allowed_list(
            OverrideMode::Categories(OverrideCategories(OverrideCategories::OPT_INDEXES)),
            &[],
            "options",
            &[]
        ));
        let per_option =
            OverrideMode::Categories(OverrideCategories(OverrideCategories::OPT_INDEXES));
        for flag in [
            "+All",
            "+Includes",
            "+IncludesNoExec",
            "+FollowSymLinks",
            "+Indexes",
            "+MultiViews",
            "+SymLinksIfOwnerMatch",
            "+MadeUp",
        ] {
            let _ = directive_allowed_list(per_option, &[], "options", &args(&[flag]));
        }

        let dir = tempdir("coverage-cache");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(&file, "Require all granted\n").unwrap();
        let mut parsed = None;
        for nonfatal in [
            NonfatalMode::None,
            NonfatalMode::Override,
            NonfatalMode::Unknown,
            NonfatalMode::All,
        ] {
            parsed = Some(
                parse_cached(
                    &cfg,
                    &file,
                    OverrideMode::All,
                    &[],
                    nonfatal,
                    &crate::request_plan::LayerIdentity::with_url_mount(&dir, &dir, "/"),
                    open_access_file(&file).unwrap().unwrap(),
                )
                .unwrap(),
            );
        }
        let parsed = parsed.unwrap();
        {
            let mut guard = cache().write().unwrap_or_else(|e| e.into_inner());
            for n in 0..512 {
                guard.insert(
                    CacheKey {
                        config_generation: cfg.generation,
                        path: dir.join(format!("dummy-{n}")),
                        server_root: cfg.server_root.clone(),
                        dev: 0,
                        ino: n,
                        mtime: 0,
                        mtime_nsec: 0,
                        ctime: 0,
                        ctime_nsec: 0,
                        size: 0,
                        mode: 0,
                        allow_list: Vec::new(),
                        nonfatal: 0,
                        identity: crate::request_plan::LayerIdentity::with_url_mount(
                            &dir, &dir, "/",
                        ),
                    },
                    Arc::clone(&parsed),
                );
            }
        }
        assert!(parse_cached(
            &cfg,
            &file,
            OverrideMode::All,
            &[],
            NonfatalMode::None,
            &crate::request_plan::LayerIdentity::with_url_mount(&dir, &dir, "/"),
            open_access_file(&file).unwrap().unwrap()
        )
        .is_ok());

        let big = dir.join("big.htaccess");
        fs::write(&big, vec![b'#'; (MAX_HTACCESS + 1) as usize]).unwrap();
        assert!(parse_file(&cfg, &big, OverrideMode::All, "/").is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn access_file_cache_is_partitioned_by_configuration_generation() {
        let dir = tempdir("generation-cache");
        let file = dir.join(".htaccess");
        fs::write(&file, "<IfDefine PROD>\nRequire all granted\n</IfDefine>\n").unwrap();
        let with_define = config(&dir, "Listen 127.0.0.1:0\nDefine PROD\n");
        let without_define = config(&dir, "Listen 127.0.0.1:0\n");
        let identity = crate::request_plan::LayerIdentity::with_url_mount(&dir, &dir, "/");

        let first = parse_cached(
            &with_define,
            &file,
            OverrideMode::All,
            &[],
            NonfatalMode::None,
            &identity,
            open_access_file(&file).unwrap().unwrap(),
        )
        .unwrap();
        assert!(first.scope.authorization.requires.is_some());

        let second = parse_cached(
            &without_define,
            &file,
            OverrideMode::All,
            &[],
            NonfatalMode::None,
            &identity,
            open_access_file(&file).unwrap().unwrap(),
        )
        .unwrap();
        assert!(second.scope.authorization.requires.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn files_tilde_regex_arity_matches_main_config() {
        let args = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(
            validate_section_arity(AccessSectionKind::Files, &args(&["~", "^secret\\.txt$"]))
                .is_ok()
        );
        assert!(validate_section_arity(AccessSectionKind::Files, &args(&["~"])).is_err());
        assert!(validate_section_arity(AccessSectionKind::Files, &args(&["x", "y"])).is_err());
        assert!(validate_section_arity(AccessSectionKind::FilesMatch, &args(&["x", "y"])).is_err());
    }

    #[test]
    fn access_file_parse_is_bound_to_the_opened_inode() {
        let dir = tempdir("descriptor-snapshot");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let path = dir.join(".htaccess");
        let displaced = dir.join("opened.htaccess");
        fs::write(&path, "SetEnv SNAPSHOT opened\n").unwrap();
        let opened = open_access_file(&path).unwrap().unwrap();

        // Swap the directory entry after selection.  Parsing must consume the
        // already-open descriptor, not reopen `path` and silently authorize
        // the replacement file.
        fs::rename(&path, &displaced).unwrap();
        fs::write(&path, "SetEnv SNAPSHOT replacement\n").unwrap();
        let error = parse_cached(
            &cfg,
            &path,
            OverrideMode::All,
            &[],
            NonfatalMode::None,
            &crate::request_plan::LayerIdentity::with_url_mount(&dir, &dir, "/"),
            opened,
        )
        .err()
        .expect("a pathname swap must fail closed");
        assert!(error.contains("changed while it was being evaluated"));

        // A cache hit is usable only while the descriptor still describes
        // exactly the version captured in its cache key.
        let cached = dir.join("cached.htaccess");
        fs::write(&cached, "SetEnv SNAPSHOT cached\n").unwrap();
        let identity = crate::request_plan::LayerIdentity::with_url_mount(&dir, &dir, "/");
        parse_cached(
            &cfg,
            &cached,
            OverrideMode::All,
            &[],
            NonfatalMode::None,
            &identity,
            open_access_file(&cached).unwrap().unwrap(),
        )
        .unwrap();
        let stale = open_access_file(&cached).unwrap().unwrap();
        fs::write(&cached, "SetEnv SNAPSHOT changed-and-longer\n").unwrap();
        let error = parse_cached(
            &cfg,
            &cached,
            OverrideMode::All,
            &[],
            NonfatalMode::None,
            &identity,
            stale,
        )
        .err()
        .expect("a changed cached descriptor must fail closed");
        assert!(error.contains("changed while it was being evaluated"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn access_file_snapshot_survives_concurrent_atomic_path_swaps() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let dir = tempdir("descriptor-race");
        let path = dir.join(".htaccess");
        let other = dir.join("other.htaccess");
        let first = b"SetEnv SNAPSHOT first\n";
        let second = b"SetEnv SNAPSHOT second\n";
        fs::write(&path, first).unwrap();
        fs::write(&other, second).unwrap();
        let first_meta = fs::metadata(&path).unwrap();
        let second_meta = fs::metadata(&other).unwrap();
        let admitted_inodes = [
            (first_meta.dev(), first_meta.ino()),
            (second_meta.dev(), second_meta.ino()),
        ];
        let path_c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let other_c = std::ffi::CString::new(other.as_os_str().as_encoded_bytes()).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let attacker_stop = Arc::clone(&stop);
        let attacker = std::thread::spawn(move || {
            while !attacker_stop.load(Ordering::Relaxed) {
                let rc = unsafe {
                    libc::syscall(
                        libc::SYS_renameat2,
                        libc::AT_FDCWD,
                        path_c.as_ptr(),
                        libc::AT_FDCWD,
                        other_c.as_ptr(),
                        libc::RENAME_EXCHANGE,
                    )
                };
                assert_eq!(rc, 0);
                std::thread::yield_now();
            }
        });

        for _ in 0..2_000 {
            let Some(opened) = open_access_file(&path).unwrap() else {
                panic!("atomic exchange must keep both names present");
            };
            if let Ok((data, meta)) = stable_access_snapshot(&path, opened) {
                assert!(data == first || data == second);
                assert!(admitted_inodes.contains(&(meta.dev(), meta.ino())));
            }
        }
        stop.store(true, Ordering::Relaxed);
        attacker.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remaining_walk_trace_and_unreachable_defensive_branches() {
        let dir = tempdir("coverage-remaining");
        let www = dir.join("www");
        fs::create_dir_all(www.join("sub")).unwrap();
        fs::create_dir_all(www.join("none")).unwrap();
        fs::create_dir_all(www.join("nonfile")).unwrap();
        fs::create_dir_all(www.join("bad2")).unwrap();
        fs::write(www.join("sub/file.txt"), "x\n").unwrap();
        fs::write(www.join("none/.htaccess"), "Require all granted\n").unwrap();
        fs::write(www.join(".htaccess"), "Require all granted\n").unwrap();
        fs::create_dir_all(www.join("nonfile/.htaccess")).unwrap();
        fs::create_dir_all(www.join("bad2/.htaccess")).unwrap();
        fs::write(www.join("bad2/.htaccess2"), "Require all granted\n").unwrap();
        let mut cfg = config(
            &dir,
            &format!(
                "Listen 127.0.0.1:0\n\
                 DocumentRoot \"{}\"\n\
                 AccessFileName .htaccess .htaccess2\n\
                 <Directory \"{}\">\n\
                     AllowOverride All\n\
                 </Directory>\n\
                 <Directory \"{}/none\">\n\
                     AllowOverride None\n\
                 </Directory>\n",
                www.display(),
                www.display(),
                www.display()
            ),
        );
        cfg.access_file_names = vec![".htaccess".into(), ".htaccess2".into()];

        // trace_access_files with a directory start and a non-file access name.
        let trace = trace_access_files(&cfg, None, &www, "/").join("\n");
        assert!(trace.contains(".htaccess"));
        let trace = trace_access_files(&cfg, None, &www.join("nonfile/x"), "/nonfile/x").join("\n");
        assert!(!trace.contains("nonfile/.htaccess"));
        let layers = collect_layers(&cfg, None, &www.join("none/x"), "/none/x").unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].identity.dir, www);
        let trace = trace_access_files(&cfg, None, &www.join("none/x"), "/none/x").join("\n");
        assert!(!trace.contains("none/.htaccess"));

        // apply_req_deferred error branches: ELOOP, non-regular, oversized.
        let mut scope = Scope::default();
        let mut files = Vec::new();
        let mut deferred = Vec::new();
        let mut config_files = Vec::new();
        assert!(apply_req_deferred(
            &cfg,
            None,
            &mut scope,
            &www.join("bad2/x"),
            "/bad2/x",
            None,
            "127.0.0.1".parse().unwrap(),
            &mut files,
            &mut deferred,
            false,
            &mut config_files,
        )
        .is_err());
        let req = request_with_header("X-Branch", "yes");
        assert!(apply_req(
            &cfg,
            None,
            &mut Scope::default(),
            &www.join("bad2/x"),
            "/bad2/x",
            Some(&req),
            "127.0.0.1".parse().unwrap(),
        )
        .is_err());
        std::os::unix::fs::symlink(".htaccess", www.join("sub/.htaccess")).unwrap();
        fs::write(www.join("sub/.htaccess2"), "Require all granted\n").unwrap();
        let trace =
            trace_access_files(&cfg, None, &www.join("sub/file.txt"), "/sub/file.txt").join("\n");
        assert!(trace.contains("ERROR"));
        let mut scope = Scope::default();
        let mut files = Vec::new();
        let mut deferred = Vec::new();
        let mut config_files = Vec::new();
        assert!(apply_req_deferred(
            &cfg,
            None,
            &mut scope,
            &www.join("sub/file.txt"),
            "/sub/file.txt",
            None,
            "127.0.0.1".parse().unwrap(),
            &mut files,
            &mut deferred,
            false,
            &mut config_files,
        )
        .is_err());
        fs::remove_file(www.join("sub/.htaccess")).unwrap();
        fs::write(
            www.join("sub/.htaccess"),
            vec![b'#'; (MAX_HTACCESS + 1) as usize],
        )
        .unwrap();
        let mut scope = Scope::default();
        let mut files = Vec::new();
        let mut deferred = Vec::new();
        let mut config_files = Vec::new();
        assert!(apply_req_deferred(
            &cfg,
            None,
            &mut scope,
            &www.join("sub/file.txt"),
            "/sub/file.txt",
            None,
            "127.0.0.1".parse().unwrap(),
            &mut files,
            &mut deferred,
            false,
            &mut config_files,
        )
        .is_err());

        // A normal non-Files/non-conditional rule lands in the TopLevel slot.
        let mut layer = crate::policy_ref::AccessLayer {
            identity: crate::request_plan::LayerIdentity::new(&www, &www, &www.join("x"), "/x"),
            scope: Arc::new(Scope::default()),
            files: Vec::new(),
            conditionals: Vec::new(),
        };
        let top = ScopeRule {
            kind: MatchKind::Always,
            delta: Scope::default(),
            order: 0,
            condition: None,
            branch: ConditionBranch::Normal,
            chain: None,
            nested: Vec::new(),
        };
        add_layer_rule(&mut layer, &top);
        assert!(layer.files.is_empty() && layer.conditionals.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn direct_directive_errors_and_unknown_specs() {
        let dir = tempdir("coverage-directive-errors");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let unknown = SealedPayload::seal(
            "definitely-unknown",
            Vec::new(),
            PayloadSchema::new(PayloadArity::ANY, false),
        )
        .unwrap();
        assert!(apply_directive(
            &cfg,
            &mut Scope::default(),
            "definitely-unknown",
            &unknown,
            None,
            false,
        )
        .is_err());
        let file = dir.join(".htaccess");
        let parse = |text: &str| {
            fs::write(&file, text).unwrap();
            parse_file(&cfg, &file, OverrideMode::All, "/")
        };
        for (text, ok) in [
            ("Require ip not-an-ip\n", false),
            ("Require dbm ignored\n", true),
            ("RedirectMatch\n", false),
            ("RedirectMatch 301\n", false),
            ("FileETag made-up\n", false),
            ("AddHandler cgi-script .cgi\n", true),
            ("AddHandler cgi-script\n", false),
            ("ErrorDocument 404\n", false),
            ("AddOutputFilterByType DEFLATE text/plain\n", true),
            ("AddOutputFilterByType DEFLATE\n", false),
            ("AddOutputFilter DEFLATE .html\n", true),
            ("AddOutputFilter DEFLATE\n", false),
            ("coverage-reject anything\n", false),
            ("coverage-unhandled anything\n", false),
        ] {
            let result = parse(text);
            assert_eq!(result.is_ok(), ok, "{text}: {:?}", result.err());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn effectful_access_directives_share_main_semantic_domains() {
        for (name, _, disposition) in DIRECTIVE_SPECS {
            if *disposition != DirectiveDisposition::Effectful {
                continue;
            }
            let access = access_directive_schema(name);
            let main = crate::config::directive_payload_schema(name);
            assert_eq!(
                access.value.semantic_kind(),
                main.value.semantic_kind(),
                "main and .htaccess semantic schemas drifted for {name}"
            );
        }
    }
}

#[cfg(test)]
mod compression_tests {
    use super::*;
    use crate::config::OverrideCategories;
    use std::collections::HashMap;

    fn tempdir(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("vapache-htaccess-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn config(root: &Path, text: &str) -> Config {
        let path = root.join("httpd.conf");
        fs::write(&path, format!("{}{text}", crate::config::TEST_CAPABILITIES)).unwrap();
        Config::load(&path, root, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    #[test]
    fn parses_compression_filter_directives() {
        let dir = tempdir("compression");
        let cfg = config(&dir, "Listen 127.0.0.1:0\n");
        let file = dir.join(".htaccess");
        fs::write(
            &file,
            concat!(
                "AddOutputFilterByType DEFLATE text/plain text/css\n",
                "AddOutputFilter BROTLI_COMPRESS .html\n",
                "SetOutputFilter DEFLATE\n",
                "DeflateCompressionLevel 9\n",
                "BrotliCompressionQuality 11\n",
                "DeflateAlterETag Remove\n",
                "BrotliAlterETag NoChange\n",
            ),
        )
        .unwrap();
        let p = parse_file(&cfg, &file, OverrideMode::All, "/").unwrap();
        assert_eq!(p.scope.compression_policy.compression_rules.len(), 3);
        assert_eq!(p.scope.compression_policy.deflate_level, Some(9));
        assert_eq!(p.scope.compression_policy.brotli_quality, Some(11));
        assert_eq!(
            p.scope.compression_policy.deflate_alter_etag,
            Some(crate::config::AlterEtag::Remove)
        );
        assert_eq!(
            p.scope.compression_policy.brotli_alter_etag,
            Some(crate::config::AlterEtag::NoChange)
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
