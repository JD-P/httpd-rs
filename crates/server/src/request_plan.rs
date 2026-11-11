//! One immutable request identity shared by dispatch, cache, access control,
//! rewrite evaluation and `--explain`.
//!
//! The recurring F50–F58 failures came from recomputing the same identities
//! in different places: the raw request target vs. the canonical URL path, and
//! an access-file layer's URL mount vs. its filesystem-relative rewrite
//! subject.  `RequestPlan` is built once per request/rewrite round and carries
//! those values, so policy consumers cannot silently disagree.

use crate::config::{Config, Scope, ScopeRule, VHost};
use crate::http::Request;
use crate::policy_ref::AccessLayer;
use crate::verified::{normalize_uri_path, percent_decode_path};
use std::fmt;
use std::fs::{File, Metadata};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A request-target path exactly as it appeared on the wire.
///
/// This type is deliberately distinct from [`DecodedUrlPath`].  A wire path
/// may contain percent escapes and must pass through `CanonicalTarget` before
/// any policy or resource-key API can consume it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireUrlPath<'a>(&'a [u8]);

impl<'a> WireUrlPath<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

/// A decoded, normalized, query-free URL path suitable for policy decisions.
///
/// The inner string is private so wire serialization cannot be passed to an
/// authorization boundary accidentally.  Instances are minted only by the
/// canonical request/rewrite pipeline or by descriptor-selected child
/// construction below.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DecodedUrlPath(String);

impl DecodedUrlPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// Validate an internal path before it crosses into policy/resource
    /// identity. Callers must make this conversion explicitly; wire paths use
    /// `WireUrlPath` and descriptor children use `FilesystemName` instead.
    pub(crate) fn from_canonical(path: &str) -> Option<Self> {
        let target = CanonicalTarget::from_url_path(path)?;
        (target.url_path.as_str() == path).then_some(target.url_path)
    }
}

impl Deref for DecodedUrlPath {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for DecodedUrlPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for DecodedUrlPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl PartialEq<str> for DecodedUrlPath {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for DecodedUrlPath {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for DecodedUrlPath {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<DecodedUrlPath> for String {
    fn eq(&self, other: &DecodedUrlPath) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<DecodedUrlPath> for str {
    fn eq(&self, other: &DecodedUrlPath) -> bool {
        self == other.as_str()
    }
}

/// One descriptor-enumerated filesystem child name.
///
/// It is neither a URL path nor a wire target.  Converting it to a policy
/// identity requires UTF-8 validation and decoded-path construction in
/// `CanonicalTarget::from_selected_child`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilesystemName<'a>(&'a [u8]);

impl<'a> FilesystemName<'a> {
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        (!bytes.is_empty() && bytes != b"." && bytes != b".." && !bytes.contains(&b'/'))
            .then_some(Self(bytes))
    }

    pub fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalError {
    /// The request path could not be percent-decoded.
    Decode,
    /// The decoded path was relative, malformed, or could not be normalized.
    Normalize,
    /// Mapping and policy operate on one textual URL identity; invalid UTF-8
    /// is rejected rather than conflated through U+FFFD.
    Utf8,
}

impl CanonicalError {
    pub fn status(self) -> u16 {
        match self {
            CanonicalError::Decode => 404,
            CanonicalError::Normalize | CanonicalError::Utf8 => 400,
        }
    }
}

/// The dispatcher-selected URL identity.  `url_path` is decoded, normalized
/// and query-free; `norm` is the mapping form used by `map_path()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTarget {
    pub url_path: DecodedUrlPath,
    pub norm: Vec<u8>,
}

impl CanonicalTarget {
    pub fn from_request(req: &Request, allow_encoded: bool) -> Result<Self, CanonicalError> {
        let raw_path: &[u8] = if req.raw_path == b"*" {
            b"/"
        } else {
            &req.raw_path
        };
        Self::from_raw_path(WireUrlPath::new(raw_path), allow_encoded)
    }

    pub fn from_raw_path(
        raw_path: WireUrlPath<'_>,
        allow_encoded: bool,
    ) -> Result<Self, CanonicalError> {
        let decoded = percent_decode_path(raw_path.as_bytes(), allow_encoded)
            .ok_or(CanonicalError::Decode)?;
        let trailing_slash = decoded.len() > 1 && decoded.ends_with(b"/");
        let norm = normalize_uri_path(&decoded).ok_or(CanonicalError::Normalize)?;
        let canonical = crate::util::is_canonical_path(&norm);
        if !canonical {
            // normalize_uri_path() proves this property; keep the guard as
            // defense in depth for non-verified callers.
            return Err(CanonicalError::Normalize); // coverage:ignore-line
        }
        if !vapache_verified::canonical_path_text_admit(
            canonical,
            std::str::from_utf8(&norm).is_ok(),
        ) {
            return Err(CanonicalError::Utf8);
        }
        let mut url_path = String::from_utf8(norm.clone()).map_err(|_| CanonicalError::Utf8)?;
        if trailing_slash && url_path != "/" {
            url_path.push('/');
        }
        Ok(Self {
            url_path: DecodedUrlPath(url_path),
            norm,
        })
    }

    /// Build a target from an internal rewrite result.  `norm` is retained as
    /// the mapping form because rewrite canonicalization already ran.
    pub fn from_normalized(norm: Vec<u8>, url_path: String) -> Option<Self> {
        let trailing_slash = url_path.len() > 1 && url_path.ends_with('/');
        let checked = normalize_uri_path(url_path.as_bytes())?;
        if checked != norm {
            return None;
        }
        let mut canonical = String::from_utf8(checked).ok()?;
        if trailing_slash && canonical != "/" {
            canonical.push('/');
        }
        (canonical == url_path).then_some(Self {
            url_path: DecodedUrlPath(url_path),
            norm,
        })
    }

    pub fn from_url_path(path: &str) -> Option<Self> {
        let trailing_slash = path.len() > 1 && path.ends_with('/');
        let norm = normalize_uri_path(path.as_bytes())?;
        let mut url_path = String::from_utf8(norm.clone()).ok()?;
        if trailing_slash && url_path != "/" {
            url_path.push('/');
        }
        Some(Self {
            url_path: DecodedUrlPath(url_path),
            norm,
        })
    }

    /// Build the decoded URL identity for a filesystem child selected by an
    /// internal transform. Policy always consumes decoded canonical paths;
    /// percent encoding belongs only at later wire-serialization boundaries.
    pub fn from_selected_child(
        parent_url: &DecodedUrlPath,
        name: FilesystemName<'_>,
        directory: bool,
    ) -> Option<Self> {
        let name = std::str::from_utf8(name.as_bytes()).ok()?;
        let mut candidate = parent_url.trim_end_matches('/').to_string();
        candidate.push('/');
        candidate.push_str(name);
        if directory {
            candidate.push('/');
        }
        let target = Self::from_url_path(&candidate)?;
        (target.url_path == candidate).then_some(target)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// `map_path()` rejected the URL (for example a regex alias expanded
    /// outside its configured base).
    Unmapped,
    /// An access file exists but could not be read or parsed.
    AccessFiles(String),
    /// The mapped filesystem path would make request-time policy evaluation
    /// exceed its fixed component or ancestor-copy budget.
    PolicyLimit(String),
}

/// Identity of one access-file layer.
///
/// `dir` is the layer directory whose filesystem-relative path is Apache's
/// per-directory rewrite subject.  `mapping_root` is the URL-selected root
/// returned by `map_path()`.  `url_mount` is the URL prefix used only for
/// relative rewrite substitutions, never for subject matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LayerIdentity {
    pub dir: PathBuf,
    pub mapping_root: PathBuf,
    pub url_mount: String,
}

impl LayerIdentity {
    pub fn new(mapping_root: &Path, dir: &Path, fs_path: &Path, url_path: &str) -> Self {
        Self {
            dir: dir.to_path_buf(),
            mapping_root: mapping_root.to_path_buf(),
            url_mount: layer_url_mount(mapping_root, dir, fs_path, url_path),
        }
    }

    pub fn with_url_mount(mapping_root: &Path, dir: &Path, url_mount: &str) -> Self {
        Self {
            dir: dir.to_path_buf(),
            mapping_root: mapping_root.to_path_buf(),
            url_mount: crate::config::normalize_rewrite_base(url_mount),
        }
    }

    /// Apache's per-directory RewriteRule subject: the selected filesystem
    /// target relative to the layer directory.  Directory requests keep their
    /// trailing slash even though `map_path()` normalizes it from `fs_path`.
    pub fn subject(&self, fs_path: &Path, url_path: &str) -> Option<String> {
        layer_subject(&self.dir, fs_path, url_path)
    }
}

/// The single implementation of a per-directory rewrite subject.
pub fn layer_subject(dir: &Path, fs_path: &Path, url_path: &str) -> Option<String> {
    let rel = fs_path.strip_prefix(dir).ok()?;
    let mut subject = rel
        .to_str()?
        .replace('\\', "/")
        .trim_matches('/')
        .to_string();
    if !subject.is_empty() && url_path.ends_with('/') {
        subject.push('/');
    }
    Some(subject)
}

/// The single implementation of a layer's relative-substitution base.
///
/// Layers at/below the URL mapping root use the URL mount.  A strict ancestor
/// of the mapping root has no URL-mount representation; Apache uses the
/// filesystem directory itself.  A fixed alias target deeper than the URL has
/// the same shape.  None of these branches is used for subject matching.
pub fn layer_url_mount(mapping_root: &Path, dir: &Path, fs_path: &Path, url_path: &str) -> String {
    let Some(rel) = fs_path.strip_prefix(dir).ok() else {
        return crate::config::normalize_rewrite_base(&dir.to_string_lossy());
    };
    if dir != mapping_root && mapping_root.starts_with(dir) {
        return crate::config::normalize_rewrite_base(&dir.to_string_lossy());
    }
    let depth = rel.components().count();
    let trimmed = url_path.trim_end_matches('/');
    let mut end = trimmed.len();
    let mut remaining = depth;
    let mut url_depth_sufficient = true;
    while remaining > 0 {
        let Some(slash) = trimmed[..end].rfind('/') else {
            url_depth_sufficient = false;
            break;
        };
        end = slash;
        remaining -= 1;
    }
    if !vapache_verified::htaccess_layer_url_base_admit(true, url_depth_sufficient) {
        return crate::config::normalize_rewrite_base(&dir.to_string_lossy());
    }
    crate::config::normalize_rewrite_base(&trimmed[..end])
}

/// Immutable mapping + access-layer identity for one request or rewrite round.
#[derive(Debug, Clone)]
pub struct RequestPlan {
    target: CanonicalTarget,
    root: PathBuf,
    rel: PathBuf,
    fs_path: PathBuf,
    script_alias: bool,
    layers: Vec<AccessLayer>,
    access_may_apply: bool,
    preopened_target: Option<PreopenedTarget>,
    precomputed_scope: Option<EvaluatedScope>,
    skip_url_translation: bool,
}

#[derive(Debug, Clone)]
struct PreopenedTarget {
    file: Arc<File>,
    meta: Metadata,
    follow_symlinks: bool,
    owner_match_only: bool,
}

impl RequestPlan {
    /// Canonicalize the client request and resolve it through the normal URL
    /// mapping.  This is the only place dispatch/cache/explain should build
    /// their initial plan.
    pub fn from_request(
        cfg: &Config,
        vhost: Option<&VHost>,
        req: &Request,
        allow_encoded: bool,
    ) -> Result<Self, CanonicalErrorOrPlan> {
        let target = CanonicalTarget::from_request(req, allow_encoded)
            .map_err(CanonicalErrorOrPlan::Canonical)?;
        Self::resolve_for_request(cfg, vhost, target, req).map_err(CanonicalErrorOrPlan::Plan)
    }

    pub fn resolve(
        cfg: &Config,
        vhost: Option<&VHost>,
        target: CanonicalTarget,
    ) -> Result<Self, PlanError> {
        let (root, rel, script_alias) =
            crate::server::map_path(cfg, vhost, &target.norm).ok_or(PlanError::Unmapped)?;
        Self::build(cfg, vhost, target, root, rel, script_alias, None)
    }

    pub fn resolve_for_request(
        cfg: &Config,
        vhost: Option<&VHost>,
        target: CanonicalTarget,
        req: &Request,
    ) -> Result<Self, PlanError> {
        let (root, rel, script_alias) =
            crate::server::map_path(cfg, vhost, &target.norm).ok_or(PlanError::Unmapped)?;
        Self::build(cfg, vhost, target, root, rel, script_alias, Some(req))
    }

    /// Build a plan for an explicit filesystem target that may differ from
    /// the URL mapping (a symlink target or rewrite filesystem override).
    pub fn from_fs_target(
        cfg: &Config,
        vhost: Option<&VHost>,
        target: CanonicalTarget,
        root: PathBuf,
        fs_path: PathBuf,
        script_alias: bool,
    ) -> Result<Self, PlanError> {
        Self::from_fs_target_inner(cfg, vhost, target, root, fs_path, script_alias, None)
    }

    pub fn from_fs_target_for_request(
        cfg: &Config,
        vhost: Option<&VHost>,
        target: CanonicalTarget,
        root: PathBuf,
        fs_path: PathBuf,
        script_alias: bool,
        req: &Request,
    ) -> Result<Self, PlanError> {
        Self::from_fs_target_inner(cfg, vhost, target, root, fs_path, script_alias, Some(req))
    }

    #[allow(clippy::too_many_arguments)]
    fn from_fs_target_inner(
        cfg: &Config,
        vhost: Option<&VHost>,
        target: CanonicalTarget,
        root: PathBuf,
        fs_path: PathBuf,
        script_alias: bool,
        req: Option<&Request>,
    ) -> Result<Self, PlanError> {
        let rel = fs_path
            .strip_prefix(&root)
            .map(Path::to_path_buf)
            .ok()
            .or_else(|| {
                // A symlinked mapping root has a lexical spelling that does
                // not prefix the canonical target.  Recover the URL-relative
                // identity from the root's canonical form.
                let canonical_root = std::fs::canonicalize(&root).ok()?;
                fs_path
                    .strip_prefix(canonical_root)
                    .ok()
                    .map(Path::to_path_buf)
            })
            .unwrap_or_else(|| {
                PathBuf::from(
                    fs_path
                        .file_name()
                        .map(|name| name.to_os_string())
                        .unwrap_or_default(),
                )
            });
        Self::build_with_fs_path(cfg, vhost, target, root, rel, fs_path, script_alias, req)
    }

    fn build(
        cfg: &Config,
        vhost: Option<&VHost>,
        target: CanonicalTarget,
        root: PathBuf,
        rel: PathBuf,
        script_alias: bool,
        req: Option<&Request>,
    ) -> Result<Self, PlanError> {
        let fs_path = root.join(&rel);
        Self::build_with_fs_path(cfg, vhost, target, root, rel, fs_path, script_alias, req)
    }

    /// Build a plan around one explicit filesystem target.  The target path,
    /// the access-file walk and every layer identity must come from this same
    /// path: the mapping root is only the URL/`RewriteBase` label and may be a
    /// symlink whose canonical target is outside the lexical root (F59/I60).
    fn build_with_fs_path(
        cfg: &Config,
        vhost: Option<&VHost>,
        target: CanonicalTarget,
        root: PathBuf,
        rel: PathBuf,
        fs_path: PathBuf,
        script_alias: bool,
        req: Option<&Request>,
    ) -> Result<Self, PlanError> {
        // Enforce this before checking whether `.htaccess` happens to apply.
        // Main-config Directory/Files evaluation walks the same ancestors and
        // rewrites may expand a short client target into a much deeper path.
        let policy_walk_start = if crate::files::is_dir_cached(&fs_path) {
            fs_path.as_path()
        } else {
            fs_path.parent().unwrap_or(fs_path.as_path())
        };
        crate::util::validate_policy_path(policy_walk_start).map_err(PlanError::PolicyLimit)?;
        // Paths participate in routing, access-file selection, rewrite
        // subjects and CGI identity.  Reject a filesystem identity that
        // cannot be represented exactly instead of projecting it through
        // U+FFFD at any of those policy boundaries.
        let textual_identity =
            root.to_str().is_some() && rel.to_str().is_some() && fs_path.to_str().is_some();
        if !vapache_verified::text_identity_admit(textual_identity) {
            return Err(PlanError::AccessFiles(format!(
                "{}: non-UTF-8 filesystem policy identity",
                fs_path.display()
            )));
        }
        let layers = match req {
            Some(req) => crate::htaccess::collect_layers_with_root_req(
                cfg,
                vhost,
                &fs_path,
                &target.url_path,
                Some(&root),
                req,
            ),
            None => crate::htaccess::collect_layers_with_root(
                cfg,
                vhost,
                &fs_path,
                &target.url_path,
                Some(&root),
            ),
        }
        .map_err(PlanError::AccessFiles)?;
        let access_may_apply = match req {
            Some(req) => cfg
                .htaccess_may_apply_req(&fs_path, req)
                .map_err(|error| PlanError::AccessFiles(error.to_string()))?,
            None => cfg.htaccess_may_apply(&fs_path),
        };
        let layers_match_target = layers
            .iter()
            .all(|layer| fs_path.starts_with(&layer.identity.dir));
        if !vapache_verified::explicit_target_layer_admit(true, true, layers_match_target) {
            // coverage:ignore-start
            return Err(PlanError::AccessFiles(format!(
                "{}: access layers do not belong to the explicit target",
                fs_path.display()
            )));
            // coverage:ignore-stop
        }
        Ok(Self {
            target,
            root,
            rel,
            fs_path,
            script_alias,
            layers,
            access_may_apply,
            preopened_target: None,
            precomputed_scope: None,
            skip_url_translation: false,
        })
    }

    pub fn target(&self) -> &CanonicalTarget {
        &self.target
    }

    pub fn url_path(&self) -> &DecodedUrlPath {
        &self.target.url_path
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn rel(&self) -> &Path {
        &self.rel
    }

    pub fn fs_path(&self) -> &Path {
        &self.fs_path
    }

    pub fn script_alias(&self) -> bool {
        self.script_alias
    }

    pub fn layers(&self) -> &[AccessLayer] {
        &self.layers
    }

    /// Retarget a directory plan to the `DirectoryIndex` selected in that
    /// exact directory without reopening and reparsing the same access files.
    ///
    /// `AllowOverride` is valid only in `<Directory>` context, and both the
    /// directory URL and its index file start their access-file walk at the
    /// same directory.  The layer identity equality below additionally proves
    /// that every rewrite subject base is unchanged.  If either invariant is
    /// not true, the caller falls back to constructing a fresh plan.
    pub fn retarget_directory_index(
        &self,
        cfg: &Config,
        vhost: Option<&VHost>,
        target: CanonicalTarget,
        preopened_target: Option<(File, Metadata, bool, bool)>,
        reusable_scope: Option<Scope>,
    ) -> Option<Self> {
        let parent_url = self.target.url_path.trim_end_matches('/');
        let child_url = target.url_path.as_str();
        let child_name = child_url.strip_prefix(parent_url)?.strip_prefix('/')?;
        if child_name.is_empty() || child_name.contains('/') {
            return None;
        }
        let mut rel = self.rel.clone();
        rel.push(child_name);
        let fs_path = self.root.join(&rel);
        if fs_path.parent() != Some(self.fs_path.as_path()) {
            return None;
        }
        // A child URL may cross an Alias/ScriptAlias boundary even though it
        // is lexically below the directory URL. Reuse is valid only when the
        // normal URL mapper selects the exact same root, relative target and
        // execution class as the descriptor selected by mod_dir semantics.
        let (mapped_root, mapped_rel, mapped_script_alias) =
            crate::server::map_path(cfg, vhost, &target.norm)?;
        if mapped_root != self.root || mapped_rel != rel || mapped_script_alias != self.script_alias
        {
            return None;
        }
        let identities_match = self.layers.iter().all(|layer| {
            LayerIdentity::new(&self.root, &layer.identity.dir, &fs_path, child_url)
                == layer.identity
        });
        if !identities_match {
            return None;
        }
        let precomputed_scope = reusable_scope
            .filter(|_| self.directory_index_scope_reusable(cfg, vhost, &fs_path))
            .map(|scope| EvaluatedScope {
                scope,
                config_conditionals: Arc::new(Vec::new()),
                access_conditionals: Arc::new(Vec::new()),
            });
        let skip_url_translation =
            precomputed_scope.is_some() && !cfg.url_translation_may_terminate(vhost, child_url);
        Some(Self {
            target,
            root: self.root.clone(),
            rel,
            fs_path,
            script_alias: self.script_alias,
            // One request must observe one access-file snapshot. Reusing the
            // already descriptor-bound parsed layers is both cheaper and more
            // internally consistent than reopening a mutable pathname during
            // the synchronous index transition.
            layers: self.layers.clone(),
            access_may_apply: self.access_may_apply,
            preopened_target: preopened_target.map(
                |(file, meta, follow_symlinks, owner_match_only)| PreopenedTarget {
                    file: Arc::new(file),
                    meta,
                    follow_symlinks,
                    owner_match_only,
                },
            ),
            precomputed_scope,
            skip_url_translation,
        })
    }

    /// Retarget an internal rewrite within the same mapped directory while
    /// retaining the request's descriptor-validated access-file snapshot.
    /// Apache carries its per-directory configuration through this transition;
    /// reopening the same `.htaccess` pathname made one logical request see
    /// two policy versions and repeated the complete access-file walk.
    ///
    /// Reuse is deliberately narrow: URL mapping, execution class, policy
    /// walk directory, and every layer identity must remain identical. Any
    /// alias boundary or deeper/shallower target falls back to a fresh plan.
    pub fn retarget_same_directory_rewrite(
        &self,
        cfg: &Config,
        vhost: Option<&VHost>,
        target: CanonicalTarget,
    ) -> Option<Self> {
        let (root, rel, script_alias) = crate::server::map_path(cfg, vhost, &target.norm)?;
        if root != self.root || script_alias != self.script_alias {
            return None;
        }
        let fs_path = root.join(&rel);
        let source_walk_dir = if crate::files::is_dir_cached(&self.fs_path) {
            self.fs_path.as_path()
        } else {
            self.fs_path.parent()?
        };
        let target_walk_dir = if crate::files::is_dir_cached(&fs_path) {
            fs_path.as_path()
        } else {
            fs_path.parent()?
        };
        if source_walk_dir != target_walk_dir {
            return None;
        }
        let identities_match = self.layers.iter().all(|layer| {
            LayerIdentity::new(&root, &layer.identity.dir, &fs_path, &target.url_path)
                == layer.identity
        });
        if !identities_match {
            return None;
        }
        Some(Self {
            target,
            root,
            rel,
            fs_path,
            script_alias,
            layers: self.layers.clone(),
            access_may_apply: self.access_may_apply,
            preopened_target: None,
            precomputed_scope: None,
            skip_url_translation: false,
        })
    }

    /// A typed DirectoryIndex transition can reuse its already mapped target
    /// only when the configuration compiler proved that URL translation has
    /// no matching terminal rule for the child URL.
    pub(crate) fn skips_url_translation(&self) -> bool {
        self.skip_url_translation
    }

    /// Whether the directory and its direct index child are guaranteed to
    /// receive the same merged policy. This deliberately recognizes only the
    /// simple, common shape: literal ancestor `<Directory>` sections plus
    /// access-file directives that do not contain a leaf-sensitive section.
    /// Any rule whose result could depend on the child basename, URL or full
    /// filesystem path falls back to a complete evaluation.
    fn directory_index_scope_reusable(
        &self,
        cfg: &Config,
        vhost: Option<&VHost>,
        child_fs_path: &Path,
    ) -> bool {
        if self
            .layers
            .iter()
            .any(|layer| !layer.files.is_empty() || !layer.conditionals.is_empty())
        {
            return false;
        }
        let rules = vhost
            .map(|vhost| vhost.rules.as_slice())
            .unwrap_or(cfg.global_rules.as_slice());
        rules.iter().all(|rule| {
            if rule.condition.is_some()
                || rule.branch != crate::config::ConditionBranch::Normal
                || !rule.nested.is_empty()
            {
                return false;
            }
            let crate::config::MatchKind::Directory(pattern) = &rule.kind else {
                return false;
            };
            let pattern_bytes = pattern.as_os_str().as_encoded_bytes();
            !pattern_bytes
                .iter()
                .any(|byte| matches!(byte, b'*' | b'?' | b'['))
                && pattern != child_fs_path
        })
    }

    /// Clone the already selected index descriptor only when the index's
    /// effective symlink policy is identical to the directory policy that
    /// selected it. A `<Files>` rule that changes `Options` therefore forces a
    /// fresh descriptor-relative resolution.
    pub(crate) fn take_preopened_target(
        &mut self,
        follow_symlinks: bool,
        owner_match_only: bool,
    ) -> Option<(File, Metadata)> {
        let opened = self.preopened_target.take()?;
        if opened.follow_symlinks != follow_symlinks || opened.owner_match_only != owner_match_only
        {
            return None;
        }
        // The ordinary DirectoryIndex path moves its typed plan directly into
        // the child dispatch, so the selected descriptor has one owner and
        // can be moved without an fcntl/dup round trip. A cloned diagnostic
        // plan remains correct and merely pays the old fallback cost.
        let file = std::sync::Arc::try_unwrap(opened.file)
            .or_else(|file| file.try_clone().map_err(|_| file))
            .ok()?;
        Some((file, opened.meta))
    }

    /// Evaluate the complete configuration/access-file scope for this plan.
    /// The returned conditionals are not yet applied so dispatch can insert
    /// rewrite `[E=...]` effects first.
    pub fn evaluate_scope(
        &self,
        cfg: &Config,
        vhost: Option<&VHost>,
        req: &Request,
        peer: std::net::IpAddr,
    ) -> EvaluatedScope {
        // A nonempty layer set already proves that access files apply.  Never
        // fall back to the configuration-only path merely because the target
        // path is outside the lexical `AllowOverride` prefix (F59/I60).
        let use_layers = vapache_verified::target_layer_consume_admit(
            self.access_may_apply,
            !self.layers.is_empty(),
        );
        if use_layers {
            let (scope, config_conditionals, access_conditionals) = cfg
                .effective_scope_with_layers_cached(
                    vhost,
                    &self.fs_path,
                    &self.target.url_path,
                    req,
                    peer,
                    &self.layers,
                );
            EvaluatedScope {
                scope,
                config_conditionals,
                access_conditionals,
            }
        } else {
            let (scope, conditionals) = cfg.effective_scope_req_cached(
                vhost,
                &self.fs_path,
                &self.target.url_path,
                req,
                peer,
            );
            EvaluatedScope {
                scope,
                config_conditionals: conditionals,
                access_conditionals: Arc::new(Vec::new()),
            }
        }
    }

    /// Dispatch owns its plan, so a request-local precomputed scope can be
    /// moved into the child request instead of deep-cloning every policy
    /// vector. Ordinary plans continue through the shared evaluator.
    pub(crate) fn take_evaluate_scope(
        &mut self,
        cfg: &Config,
        vhost: Option<&VHost>,
        req: &Request,
        peer: std::net::IpAddr,
    ) -> EvaluatedScope {
        self.precomputed_scope
            .take()
            .unwrap_or_else(|| self.evaluate_scope(cfg, vhost, req, peer))
    }

    /// Re-evaluate the same canonical directory and access-file layers while
    /// matching Files sections against a lexical basename.  Only handler
    /// fields from this scope may be consumed; its authorization fields are
    /// intentionally not a substitute for the canonical evaluation.
    pub fn evaluate_scope_with_file_name(
        &self,
        cfg: &Config,
        vhost: Option<&VHost>,
        req: &Request,
        peer: std::net::IpAddr,
        file_name: &str,
    ) -> EvaluatedScope {
        let (scope, config_conditionals, access_conditionals) =
            crate::policy_ref::effective_scope_with_layers_and_file_name(
                cfg,
                vhost,
                &self.fs_path,
                &self.target.url_path,
                req,
                peer,
                &self.layers,
                file_name,
            );
        EvaluatedScope {
            scope,
            config_conditionals: Arc::new(config_conditionals),
            access_conditionals: Arc::new(access_conditionals),
        }
    }

    /// Evaluate and apply every conditional phase.  Cache policy needs the
    /// final scope, while dispatch needs `evaluate_scope()` so it can insert
    /// rewrite effects before this call.
    pub fn effective_scope(
        &self,
        cfg: &Config,
        vhost: Option<&VHost>,
        req: &Request,
        peer: std::net::IpAddr,
    ) -> Scope {
        let mut evaluated = self.evaluate_scope(cfg, vhost, req, peer);
        evaluated.apply_conditionals(cfg, vhost, &self.fs_path, &self.target.url_path, req, peer);
        evaluated.scope
    }
}

#[derive(Debug, Clone)]
pub struct EvaluatedScope {
    pub scope: Scope,
    pub config_conditionals: Arc<Vec<ScopeRule>>,
    pub access_conditionals: Arc<Vec<ScopeRule>>,
}

impl EvaluatedScope {
    pub fn apply_conditionals(
        &mut self,
        cfg: &Config,
        vhost: Option<&VHost>,
        fs_path: &Path,
        url_path: &str,
        req: &Request,
        peer: std::net::IpAddr,
    ) {
        apply_conditionals(
            cfg,
            vhost,
            &mut self.scope,
            &self.config_conditionals,
            &self.access_conditionals,
            fs_path,
            url_path,
            req,
            peer,
        );
    }
}

/// Apply configuration and access-file conditional rules in one place.
#[allow(clippy::too_many_arguments)]
pub fn apply_conditionals(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    config_conditionals: &[ScopeRule],
    access_conditionals: &[ScopeRule],
    fs_path: &Path,
    url_path: &str,
    req: &Request,
    peer: std::net::IpAddr,
) {
    let fname = fs_path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    apply_conditionals_with_file_name(
        cfg,
        vhost,
        scope,
        config_conditionals,
        access_conditionals,
        fs_path,
        url_path,
        req,
        peer,
        &fname,
    );
}

/// Apply deferred rules with a caller-supplied Files basename while keeping
/// filesystem expressions bound to the canonical target path.
#[allow(clippy::too_many_arguments)]
pub fn apply_conditionals_with_file_name(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    config_conditionals: &[ScopeRule],
    access_conditionals: &[ScopeRule],
    fs_path: &Path,
    url_path: &str,
    req: &Request,
    peer: std::net::IpAddr,
    fname: &str,
) {
    let docroot = cfg.documentation_root_for(vhost);
    for source in crate::verified::condition_source_plan_exec() {
        let conditionals = match source {
            crate::verified::ConditionSource::Config => config_conditionals,
            crate::verified::ConditionSource::Access => access_conditionals,
        };
        // Apache's <If>/<ElseIf>/<Else> chain state is local to its source
        // stream; an access-file chain cannot continue a main-config chain.
        let mut state = std::collections::HashMap::new();
        crate::config::apply_deferred_req(
            scope,
            conditionals,
            req,
            peer,
            &docroot,
            fs_path,
            url_path,
            fname,
            &mut state,
        );
    }
}

/// Error union used by the initial dispatch/cache plan construction.
#[derive(Debug)]
pub enum CanonicalErrorOrPlan {
    Canonical(CanonicalError),
    Plan(PlanError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_children_keep_decoded_policy_identity() {
        let docs = CanonicalTarget::from_url_path("/docs/").unwrap().url_path;
        for (name, expected) in [
            (
                b"name with space.txt".as_slice(),
                "/docs/name with space.txt",
            ),
            ("café.txt".as_bytes(), "/docs/café.txt"),
            (b"pct%20literal.txt".as_slice(), "/docs/pct%20literal.txt"),
        ] {
            let target = CanonicalTarget::from_selected_child(
                &docs,
                FilesystemName::new(name).unwrap(),
                false,
            )
            .unwrap();
            assert_eq!(target.url_path, expected);
        }
        let docs = CanonicalTarget::from_url_path("/docs").unwrap().url_path;
        assert_eq!(
            CanonicalTarget::from_selected_child(
                &docs,
                FilesystemName::new(b"child").unwrap(),
                true,
            )
            .unwrap()
            .url_path,
            "/docs/child/"
        );
        assert!(FilesystemName::new(b"bad/name").is_none());
        assert!(FilesystemName::new(b"..").is_none());
        assert!(CanonicalTarget::from_selected_child(
            &docs,
            FilesystemName::new(b"bad\xff").unwrap(),
            false,
        )
        .is_none());
        let borrowed: &str = docs.as_ref();
        assert_eq!(borrowed, "/docs");
        assert!(DecodedUrlPath::from_canonical("/docs//").is_none());
    }

    #[test]
    fn canonical_target_is_query_free_decoded_and_normalized() {
        let target = CanonicalTarget::from_raw_path(WireUrlPath::new(b"/%2eenv"), false).unwrap();
        assert_eq!(target.url_path, "/.env");

        let target =
            CanonicalTarget::from_raw_path(WireUrlPath::new(b"/api/%2e%2e/secret"), false).unwrap();
        assert_eq!(target.url_path, "/secret");
        assert_eq!(target.norm, b"/secret");

        let target = CanonicalTarget::from_raw_path(WireUrlPath::new(b"/dir/"), false).unwrap();
        assert_eq!(target.url_path, "/dir/");
        assert_eq!(target.norm, b"/dir");

        let target =
            CanonicalTarget::from_raw_path(WireUrlPath::new("/café".as_bytes()), false).unwrap();
        assert_eq!(target.url_path, "/café");
        let target =
            CanonicalTarget::from_raw_path(WireUrlPath::new(b"/caf%c3%a9"), false).unwrap();
        assert_eq!(target.url_path, "/café");
    }

    #[test]
    fn canonical_errors_are_fail_closed() {
        assert_eq!(CanonicalError::Decode.status(), 404);
        assert_eq!(CanonicalError::Normalize.status(), 400);
        assert_eq!(CanonicalError::Utf8.status(), 400);
        assert!(CanonicalTarget::from_raw_path(WireUrlPath::new(b"relative"), false).is_err());
        assert!(CanonicalTarget::from_raw_path(WireUrlPath::new(b"/%zz"), false).is_err());
        assert_eq!(
            CanonicalTarget::from_raw_path(WireUrlPath::new(b"/\xff"), false),
            Err(CanonicalError::Utf8)
        );
        assert_eq!(
            CanonicalTarget::from_raw_path(WireUrlPath::new(b"/%ff"), false),
            Err(CanonicalError::Utf8)
        );
        assert!(CanonicalTarget::from_normalized(b"/other".to_vec(), "/expected".into()).is_none());
        assert!(CanonicalTarget::from_url_path("relative").is_none());
        let identity =
            LayerIdentity::with_url_mount(Path::new("/srv/www"), Path::new("/srv/www"), "sub");
        assert_eq!(identity.url_mount, "/sub/");
        assert_eq!(identity.mapping_root, Path::new("/srv/www"));
        assert_eq!(
            identity.subject(Path::new("/srv/www/dir/file"), "/dir/file"),
            Some("dir/file".into())
        );
    }

    #[test]
    fn directory_index_retargets_same_directory_access_snapshot() {
        let root = PathBuf::from("/srv/www");
        let layer = AccessLayer {
            identity: LayerIdentity::new(&root, &root, &root, "/"),
            scope: Arc::new(Scope::default()),
            files: Vec::new(),
            conditionals: Vec::new(),
        };
        let plan = RequestPlan {
            target: CanonicalTarget::from_url_path("/").unwrap(),
            root: root.clone(),
            rel: PathBuf::new(),
            fs_path: root.clone(),
            script_alias: false,
            layers: vec![layer],
            access_may_apply: true,
            preopened_target: None,
            precomputed_scope: None,
            skip_url_translation: false,
        };
        let cfg = load_config("Listen 127.0.0.1:0\nDocumentRoot /srv/www\n");
        let reusable = Scope::default();
        let index = plan
            .retarget_directory_index(
                &cfg,
                None,
                CanonicalTarget::from_url_path("/index.html").unwrap(),
                None,
                Some(reusable),
            )
            .unwrap();
        assert_eq!(index.rel(), Path::new("index.html"));
        assert_eq!(index.fs_path(), Path::new("/srv/www/index.html"));
        assert_eq!(index.url_path(), "/index.html");
        assert!(Arc::ptr_eq(&plan.layers[0].scope, &index.layers[0].scope));
        assert!(index.precomputed_scope.is_some());
        assert!(index.skips_url_translation());

        assert!(plan
            .retarget_directory_index(
                &cfg,
                None,
                CanonicalTarget::from_url_path("/nested/index.html").unwrap(),
                None,
                None,
            )
            .is_none());

        let mut inconsistent_path = plan.clone();
        inconsistent_path.fs_path = PathBuf::from("/srv/other");
        assert!(inconsistent_path
            .retarget_directory_index(
                &cfg,
                None,
                CanonicalTarget::from_url_path("/index.html").unwrap(),
                None,
                None,
            )
            .is_none());

        let mut inconsistent_layer = plan.clone();
        inconsistent_layer.layers[0].identity =
            LayerIdentity::with_url_mount(&root, &root, "/different/");
        assert!(inconsistent_layer
            .retarget_directory_index(
                &cfg,
                None,
                CanonicalTarget::from_url_path("/index.html").unwrap(),
                None,
                None,
            )
            .is_none());

        let alias_cfg = load_config(
            "Listen 127.0.0.1:0\nDocumentRoot /srv/www\nAlias /index.html /srv/other.html\n",
        );
        assert!(plan
            .retarget_directory_index(
                &alias_cfg,
                None,
                CanonicalTarget::from_url_path("/index.html").unwrap(),
                None,
                None,
            )
            .is_none());
    }

    #[test]
    fn rewrite_retargets_same_directory_access_snapshot() {
        let root = PathBuf::from("/srv/www");
        let source_path = root.join("dir/old.html");
        let layer = AccessLayer {
            identity: LayerIdentity::new(&root, &root.join("dir"), &source_path, "/dir/old.html"),
            scope: Arc::new(Scope::default()),
            files: Vec::new(),
            conditionals: Vec::new(),
        };
        let plan = RequestPlan {
            target: CanonicalTarget::from_url_path("/dir/old.html").unwrap(),
            root: root.clone(),
            rel: PathBuf::from("dir/old.html"),
            fs_path: source_path,
            script_alias: false,
            layers: vec![layer],
            access_may_apply: true,
            preopened_target: None,
            precomputed_scope: None,
            skip_url_translation: false,
        };
        let cfg = load_config("Listen 127.0.0.1:0\nDocumentRoot /srv/www\n");
        let target = plan
            .retarget_same_directory_rewrite(
                &cfg,
                None,
                CanonicalTarget::from_url_path("/dir/new.html").unwrap(),
            )
            .unwrap();
        assert_eq!(target.fs_path(), Path::new("/srv/www/dir/new.html"));
        assert!(Arc::ptr_eq(&plan.layers[0].scope, &target.layers[0].scope));
        assert!(plan
            .retarget_same_directory_rewrite(
                &cfg,
                None,
                CanonicalTarget::from_url_path("/other/new.html").unwrap(),
            )
            .is_none());
    }

    #[test]
    fn directory_index_scope_reuse_rejects_context_sensitive_policy() {
        let root = PathBuf::from("/srv/www");
        let base_plan = || RequestPlan {
            target: CanonicalTarget::from_url_path("/").unwrap(),
            root: root.clone(),
            rel: PathBuf::new(),
            fs_path: root.clone(),
            script_alias: false,
            layers: vec![AccessLayer {
                identity: LayerIdentity::new(&root, &root, &root, "/"),
                scope: Arc::new(Scope::default()),
                files: Vec::new(),
                conditionals: Vec::new(),
            }],
            access_may_apply: true,
            preopened_target: None,
            precomputed_scope: None,
            skip_url_translation: false,
        };
        let reusable = Scope::default();
        for policy in [
            "<Files \"index.html\">\nRequire all denied\n</Files>\n",
            "<Location \"/index.html\">\nRequire all denied\n</Location>\n",
            "<DirectoryMatch \"index[.]html$\">\nRequire all denied\n</DirectoryMatch>\n",
            "<Directory \"/srv/www/*\">\nRequire all denied\n</Directory>\n",
            "<Directory \"/srv/www/index.html\">\nRequire all denied\n</Directory>\n",
            "<Directory \"/srv/www\">\n<If \"true\">\nRequire all denied\n</If>\n</Directory>\n",
        ] {
            let cfg = load_config(&format!(
                "Listen 127.0.0.1:0\nDocumentRoot /srv/www\n{policy}"
            ));
            let child = base_plan()
                .retarget_directory_index(
                    &cfg,
                    None,
                    CanonicalTarget::from_url_path("/index.html").unwrap(),
                    None,
                    Some(reusable.clone()),
                )
                .unwrap();
            assert!(
                child.precomputed_scope.is_none(),
                "context-sensitive policy reused the directory scope: {policy}"
            );
        }

        let files_cfg = load_config(
            "Listen 127.0.0.1:0\n<Files \"index.html\">\nRequire all denied\n</Files>\n",
        );
        let mut access_sensitive = base_plan();
        access_sensitive.layers[0].files = files_cfg.global_rules.clone();
        let child = access_sensitive
            .retarget_directory_index(
                &load_config("Listen 127.0.0.1:0\nDocumentRoot /srv/www\n"),
                None,
                CanonicalTarget::from_url_path("/index.html").unwrap(),
                None,
                Some(reusable),
            )
            .unwrap();
        assert!(child.precomputed_scope.is_none());

        let redirect_cfg =
            load_config("Listen 127.0.0.1:0\nDocumentRoot /srv/www\nRedirect /index.html /next\n");
        let child = base_plan()
            .retarget_directory_index(
                &redirect_cfg,
                None,
                CanonicalTarget::from_url_path("/index.html").unwrap(),
                None,
                Some(Scope::default()),
            )
            .unwrap();
        assert!(child.precomputed_scope.is_some());
        assert!(!child.skips_url_translation());
    }

    #[test]
    fn directory_index_preopened_target_requires_identical_symlink_policy() {
        let root = PathBuf::from("/srv/www");
        let plan = RequestPlan {
            target: CanonicalTarget::from_url_path("/").unwrap(),
            root: root.clone(),
            rel: PathBuf::new(),
            fs_path: root,
            script_alias: false,
            layers: Vec::new(),
            access_may_apply: false,
            preopened_target: None,
            precomputed_scope: None,
            skip_url_translation: false,
        };
        let fixture =
            std::env::temp_dir().join(format!("vapache-plan-index-fd-{}", std::process::id()));
        std::fs::write(&fixture, b"index").unwrap();
        let file = File::open(&fixture).unwrap();
        let meta = file.metadata().unwrap();
        let child = plan
            .retarget_directory_index(
                &load_config("Listen 127.0.0.1:0\nDocumentRoot /srv/www\n"),
                None,
                CanonicalTarget::from_url_path("/index.html").unwrap(),
                Some((file, meta, true, false)),
                None,
            )
            .unwrap();
        let mut child = child;
        assert!(child.take_preopened_target(false, true).is_none());

        let file = File::open(&fixture).unwrap();
        let meta = file.metadata().unwrap();
        let mut matching = plan
            .retarget_directory_index(
                &load_config("Listen 127.0.0.1:0\nDocumentRoot /srv/www\n"),
                None,
                CanonicalTarget::from_url_path("/index.html").unwrap(),
                Some((file, meta, true, false)),
                None,
            )
            .unwrap();
        assert!(matching.take_preopened_target(true, false).is_some());
        let _ = std::fs::remove_file(fixture);
    }

    #[test]
    fn filesystem_policy_identities_reject_invalid_utf8() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let cfg = load_config("Listen 127.0.0.1:0\n");
        let root = PathBuf::from(OsString::from_vec(b"/tmp/vapache-root-\xff".to_vec()));
        let error = RequestPlan::build_with_fs_path(
            &cfg,
            None,
            CanonicalTarget::from_url_path("/file.txt").unwrap(),
            root.clone(),
            PathBuf::from("file.txt"),
            root.join("file.txt"),
            false,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, PlanError::AccessFiles(message) if message.contains("non-UTF-8")));
    }

    #[test]
    fn filesystem_policy_paths_have_a_universal_component_bound() {
        let cfg = load_config("Listen 127.0.0.1:0\n");
        let root = PathBuf::from("/srv/www");
        let mut rel = PathBuf::new();
        for _ in 0..crate::util::MAX_POLICY_PATH_COMPONENTS {
            rel.push("x");
        }
        let error = RequestPlan::build_with_fs_path(
            &cfg,
            None,
            CanonicalTarget::from_url_path("/file.txt").unwrap(),
            root.clone(),
            rel.clone(),
            root.join(rel),
            false,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, PlanError::PolicyLimit(message) if message.contains("too many")));
    }

    #[test]
    fn layer_subject_is_filesystem_relative_for_all_mapping_shapes() {
        assert_eq!(
            layer_subject(
                Path::new("/srv/www"),
                Path::new("/srv/www/wallet/public/.env"),
                "/wallet/.env"
            )
            .as_deref(),
            Some("wallet/public/.env")
        );
        assert_eq!(
            layer_subject(
                Path::new("/srv/www"),
                Path::new("/srv/www/wallet/public/private"),
                "/wallet/private/"
            )
            .as_deref(),
            Some("wallet/public/private/")
        );
        assert_eq!(
            layer_subject(
                Path::new("/srv/storage"),
                Path::new("/srv/storage/current/public/private/wallet.dat"),
                "/wallet/private/wallet.dat"
            )
            .as_deref(),
            Some("current/public/private/wallet.dat")
        );
        assert!(
            layer_subject(Path::new("/srv/www"), Path::new("/other/wallet"), "/wallet").is_none()
        );
    }

    fn load_config(text: &str) -> Config {
        static NEXT_FIXTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let fixture = NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("vapache-plan-{}-{fixture}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("httpd.conf");
        std::fs::write(&path, format!("{}{text}", crate::config::TEST_CAPABILITIES)).unwrap();
        Config::load(
            &path,
            &dir,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            false,
        )
        .unwrap_or_else(|errors| panic!("{errors:?}"))
    }

    #[test]
    fn fs_target_outside_mapping_root_reads_explicit_target_layers() {
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!("vapache-plan-f59-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let real = base.join("real").join("public");
        let admin = real.join("admin");
        std::fs::create_dir_all(&admin).unwrap();
        std::fs::create_dir_all(base.join("www")).unwrap();
        let root = base.join("www").join("html");
        symlink(&real, &root).unwrap();
        std::fs::write(admin.join(".htaccess"), "Options -ExecCGI\n").unwrap();
        std::fs::write(admin.join("sh.cgi"), "#!/bin/sh\n").unwrap();
        let cfg = load_config(&format!(
            "Listen 127.0.0.1:0\n\
             Options +ExecCGI\n\
             <Directory \"{}\">\n\
                 AllowOverride All\n\
                 Require all granted\n\
             </Directory>\n",
            root.display()
        ));
        let fs_path = std::fs::canonicalize(admin.join("sh.cgi")).unwrap();
        let target = CanonicalTarget::from_url_path("/admin/sh.cgi").unwrap();
        let plan =
            RequestPlan::from_fs_target(&cfg, None, target, root.clone(), fs_path.clone(), false)
                .unwrap();
        assert_eq!(plan.fs_path(), fs_path);
        assert_eq!(plan.rel(), Path::new("admin/sh.cgi"));
        assert_eq!(
            plan.layers()
                .iter()
                .map(|layer| layer.identity.dir.clone())
                .collect::<Vec<_>>(),
            vec![admin.clone()]
        );
        // The canonical target is outside the lexical <Directory> prefix, so
        // the old fast path would have discarded the layer entirely.
        assert!(!cfg.htaccess_may_apply(plan.fs_path()));
        let req = crate::http::Request {
            method: "GET".into(),
            target: b"/admin/sh.cgi".to_vec(),
            raw_path: b"/admin/sh.cgi".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        let scope = plan.effective_scope(
            &cfg,
            None,
            &req,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        );
        assert!(!scope
            .effective_options()
            .contains(crate::config::Options::EXEC_CGI));

        // A target outside both the lexical and canonical root keeps the
        // basename fallback instead of fabricating a relative path.
        let basename_plan = RequestPlan::from_fs_target(
            &cfg,
            None,
            CanonicalTarget::from_url_path("/admin/sh.cgi").unwrap(),
            base.join("absent-root"),
            fs_path.clone(),
            false,
        )
        .unwrap();
        assert_eq!(basename_plan.rel(), Path::new("sh.cgi"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn layer_url_mount_handles_alias_root_ancestor_and_depth_fallback() {
        assert_eq!(
            layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/srv/site"),
                Path::new("/srv/site/private/wallet.dat"),
                "/site/private/wallet.dat"
            ),
            "/site/"
        );
        assert_eq!(
            layer_url_mount(
                Path::new("/srv/site/private"),
                Path::new("/srv/site/private"),
                Path::new("/srv/site/private/wallet.dat"),
                "/site/private/wallet.dat"
            ),
            "/site/private/"
        );
        assert_eq!(
            layer_url_mount(
                Path::new("/srv/www/wallet/public"),
                Path::new("/srv/www"),
                Path::new("/srv/www/wallet/public/.env"),
                "/wallet/.env"
            ),
            "/srv/www/"
        );
        assert_eq!(
            layer_url_mount(
                Path::new("/srv/site"),
                Path::new("/srv/site"),
                Path::new("/srv/site/sub1/sub2/file"),
                "/m/file"
            ),
            "/srv/site/"
        );
    }
}
