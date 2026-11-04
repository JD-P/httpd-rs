//! Apache HTTPD configuration parser and compiler.
//!
//! The parser accepts the real httpd 2.4 configuration grammar: quoted
//! arguments, line continuations, `${VAR}` interpolation, `Include`/
//! `IncludeOptional` globs, `Define`, `<IfDefine>`, `<IfModule>`, nested
//! containers, virtual hosts, and per-directory scopes.
//!
//! Directives are compiled into an immutable typed configuration. Unknown,
//! malformed and recognized-but-unimplemented directives are configuration
//! errors in every mode; no policy-bearing syntax is accepted as an inert
//! compatibility placeholder.

use crate::config_payload::{
    PayloadArity, PayloadSchema, PayloadValidation, PayloadValueSchema, SealedPayload,
};
use crate::scope_policy::{
    AuthorizationPolicy, CompressionPolicy, ContentPolicy, EnvironmentPolicy, ErrorDocumentPolicy,
    HeaderPolicy, MappingPolicy, OptionsPolicy, Originated, OverridePolicy, ProxyPolicy,
    RewriteCachePolicy,
};
// Apache's directive regexes operate on request bytes and use ASCII character
// classes unless UTF mode was explicitly requested.  Keeping one byte-regex
// type for every directive surface prevents Unicode `\w`/`\b` semantics and
// lossy UTF-8 conversion from silently changing an ACL decision.
use regex::bytes::Regex;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Vapache has one process-wide HTTP/1 worker pool rather than Apache's
/// multi-process MPM topology.  Keep configuration compatibility within the
/// largest pool this implementation can safely provide; accepting a larger
/// Apache `ServerLimit` would otherwise turn a configuration value into an
/// effectively unbounded thread/HTTP2-connection ceiling.
pub const MAX_IMPLEMENTED_REQUEST_WORKERS: usize = 512;

const MAX_CONFIG_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CONFIG_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TYPES_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CONFIG_SECTION_DEPTH: usize = 64;

#[derive(Debug, Clone)]
pub struct ConfigError {
    pub file: String,
    pub line: usize,
    pub msg: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.file.is_empty() {
            write!(f, "{}", self.msg)
        } else {
            write!(f, "{} line {}: {}", self.file, self.line, self.msg)
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerTokens {
    Full,
    Os,
    Minimal,
    Minor,
    Major,
    Prod,
}

fn version_prefix(components: usize) -> String {
    crate::VERSION
        .split('.')
        .take(components)
        .collect::<Vec<_>>()
        .join(".")
}

fn server_software_for_tokens(tokens: ServerTokens) -> String {
    match tokens {
        ServerTokens::Full | ServerTokens::Os => {
            format!("{} (Linux)", crate::SERVER_SOFTWARE)
        }
        ServerTokens::Minimal => crate::SERVER_SOFTWARE.into(),
        ServerTokens::Minor => format!("vapache/{}", version_prefix(2)),
        ServerTokens::Major => format!("vapache/{}", version_prefix(1)),
        ServerTokens::Prod => "vapache".into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerSignature {
    Off,
    On,
    Email,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodedSlashes {
    Off,
    On,
    NoDecode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverrideCategories(pub u32);

impl OverrideCategories {
    pub const AUTH_CONFIG: u32 = 1 << 0;
    pub const FILE_INFO: u32 = 1 << 1;
    pub const INDEXES: u32 = 1 << 2;
    pub const LIMIT: u32 = 1 << 3;
    /// The `Options` directive is allowed with any option token.
    pub const OPTIONS: u32 = 1 << 4;
    pub const EXEC_CGI: u32 = 1 << 5;
    pub const INCLUDES: u32 = 1 << 6;
    pub const INCLUDES_NOEXEC: u32 = 1 << 7;
    pub const LANGUAGE_PRIORITY: u32 = 1 << 8;
    /// Individual `Options=...` permissions accepted by Apache 2.4.
    pub const OPT_FOLLOW_SYMLINKS: u32 = 1 << 9;
    pub const OPT_INDEXES: u32 = 1 << 10;
    pub const OPT_MULTIVIEWS: u32 = 1 << 11;
    pub const OPT_SYMLINKS_IF_OWNER_MATCH: u32 = 1 << 12;
    pub const OPT_NONE: u32 = 1 << 13;
    pub const OPTION_MASK: u32 = Self::OPTIONS
        | Self::EXEC_CGI
        | Self::INCLUDES
        | Self::INCLUDES_NOEXEC
        | Self::OPT_FOLLOW_SYMLINKS
        | Self::OPT_INDEXES
        | Self::OPT_MULTIVIEWS
        | Self::OPT_SYMLINKS_IF_OWNER_MATCH
        | Self::OPT_NONE;

    pub fn empty() -> Self {
        OverrideCategories(0)
    }
    pub fn all() -> Self {
        OverrideCategories(
            Self::AUTH_CONFIG
                | Self::FILE_INFO
                | Self::INDEXES
                | Self::LIMIT
                | Self::OPTIONS
                | Self::EXEC_CGI
                | Self::INCLUDES
                | Self::INCLUDES_NOEXEC
                | Self::LANGUAGE_PRIORITY
                | Self::OPT_FOLLOW_SYMLINKS
                | Self::OPT_INDEXES
                | Self::OPT_MULTIVIEWS
                | Self::OPT_SYMLINKS_IF_OWNER_MATCH
                | Self::OPT_NONE,
        )
    }
    pub fn contains(self, flag: u32) -> bool {
        self.0 & flag != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideMode {
    None,
    All,
    Categories(OverrideCategories),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NonfatalMode {
    #[default]
    None,
    Override,
    Unknown,
    All,
}

impl NonfatalMode {
    pub(crate) fn allows_override(self) -> bool {
        matches!(self, Self::Override | Self::All)
    }
    pub(crate) fn allows_unknown(self) -> bool {
        matches!(self, Self::Unknown | Self::All)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideCategory {
    AuthConfig,
    FileInfo,
    Indexes,
    Limit,
    Options,
    ExecCgi,
    Includes,
    IncludesNoExec,
    LanguagePriority,
}

impl OverrideCategory {
    fn flag(self) -> u32 {
        match self {
            Self::AuthConfig => OverrideCategories::AUTH_CONFIG,
            Self::FileInfo => OverrideCategories::FILE_INFO,
            Self::Indexes => OverrideCategories::INDEXES,
            Self::Limit => OverrideCategories::LIMIT,
            Self::Options => OverrideCategories::OPTIONS,
            Self::ExecCgi => OverrideCategories::EXEC_CGI,
            Self::Includes => OverrideCategories::INCLUDES,
            Self::IncludesNoExec => OverrideCategories::INCLUDES_NOEXEC,
            Self::LanguagePriority => OverrideCategories::LANGUAGE_PRIORITY,
        }
    }
}

impl OverrideMode {
    fn proof_parts(self) -> (u8, u32) {
        match self {
            Self::None => (0, 0),
            Self::All => (1, OverrideCategories::all().0),
            Self::Categories(c) => (2, c.0),
        }
    }

    pub fn is_enabled(self) -> bool {
        match self {
            Self::None => false,
            Self::All => true,
            Self::Categories(c) => c.0 != 0,
        }
    }

    pub fn allows(self, category: OverrideCategory) -> bool {
        let (mode, categories) = self.proof_parts();
        vapache_verified::override_mode_allows(mode, categories, category.flag())
    }

    pub fn allows_flag(self, flag: u32) -> bool {
        let (mode, categories) = self.proof_parts();
        vapache_verified::override_mode_allows(mode, categories, flag)
    }

    pub fn allows_any_option(self) -> bool {
        match self {
            Self::None => false,
            Self::All => true,
            Self::Categories(c) => c.0 & OverrideCategories::OPTION_MASK != 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options(pub u32);

impl Options {
    pub const NONE: u32 = 0;
    pub const INDEXES: u32 = 1 << 0;
    pub const FOLLOW_SYMLINKS: u32 = 1 << 1;
    pub const SYMLINKS_IF_OWNER_MATCH: u32 = 1 << 2;
    pub const EXEC_CGI: u32 = 1 << 3;
    pub const INCLUDES: u32 = 1 << 4;
    pub const INCLUDES_NOEXEC: u32 = 1 << 5;
    pub const MULTIVIEWS: u32 = 1 << 6;

    pub fn empty() -> Self {
        Options(0)
    }
    pub fn all() -> Self {
        Options(
            Self::INDEXES
                | Self::FOLLOW_SYMLINKS
                | Self::SYMLINKS_IF_OWNER_MATCH
                | Self::EXEC_CGI
                | Self::INCLUDES
                | Self::INCLUDES_NOEXEC
                | Self::MULTIVIEWS,
        )
    }
    pub fn contains(self, flag: u32) -> bool {
        self.0 & flag != 0
    }
    pub fn set(mut self, flag: u32, on: bool) -> Self {
        if on {
            self.0 |= flag;
        } else {
            self.0 &= !flag;
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    AllowDeny,
    DenyAllow,
}

#[derive(Debug, Clone)]
pub enum Require {
    AllGranted,
    AllDenied,
    Ip {
        negate: bool,
        nets: Vec<(IpAddr, u8)>,
    },
    Local {
        negate: bool,
    },
    Host {
        negate: bool,
        names: Vec<String>,
    },
    Method {
        negate: bool,
        methods: Vec<String>,
    },
    ValidUser {
        negate: bool,
    },
    Env {
        negate: bool,
        names: Vec<String>,
    },
    Expr {
        negate: bool,
        expr: crate::expr::Expr,
    },
    User {
        negate: bool,
        names: Vec<String>,
    },
    Group {
        negate: bool,
        names: Vec<String>,
    },
    /// Anything we cannot evaluate safely denies.
    Unsupported(String),
}

/// Nested authorization expression. Multiple top-level nodes are an implicit
/// RequireAny, matching Apache.
#[derive(Debug, Clone)]
pub enum RequireNode {
    Provider(Require),
    All(Vec<RequireNode>),
    Any(Vec<RequireNode>),
    None(Vec<RequireNode>),
}

pub(crate) fn require_is_negated(require: &Require) -> bool {
    match require {
        Require::Ip { negate, .. }
        | Require::Local { negate }
        | Require::Host { negate, .. }
        | Require::Method { negate, .. }
        | Require::ValidUser { negate }
        | Require::Env { negate, .. }
        | Require::Expr { negate, .. }
        | Require::User { negate, .. }
        | Require::Group { negate, .. } => *negate,
        Require::AllGranted | Require::AllDenied | Require::Unsupported(_) => false,
    }
}

pub(crate) fn require_node_is_negative(node: &RequireNode) -> bool {
    match node {
        RequireNode::Provider(require) => require_is_negated(require),
        RequireNode::None(_) => true,
        RequireNode::All(_) | RequireNode::Any(_) => false,
    }
}

/// A set of HTTP methods used by `<Limit>` / `<LimitExcept>`.
///
/// `Only` applies to exactly the listed methods, `Except` applies to every
/// method not listed (including methods unknown to the server).  Apache maps
/// `HEAD` onto the `GET` method number, so limiting GET also limits HEAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodSet {
    Only(Vec<String>),
    Except(Vec<String>),
}

impl MethodSet {
    pub fn all() -> Self {
        MethodSet::Except(Vec::new())
    }

    fn listed(list: &[String], method: &str) -> bool {
        // Apache treats HEAD as the same method number as GET for the purpose
        // of <Limit>.  Other method names are case-sensitive.
        let method = if method == "HEAD" { "GET" } else { method };
        list.iter().any(|m| m == method)
    }

    pub fn matches(&self, method: &str) -> bool {
        match self {
            MethodSet::Only(list) => Self::listed(list, method),
            MethodSet::Except(list) => !Self::listed(list, method),
        }
    }

    /// Intersection used by nested `<Limit>` sections.  Every nested section
    /// must further restrict the enclosing one.
    pub fn intersect(&self, other: &Self) -> Self {
        let dedup = |v: Vec<String>| {
            let mut out: Vec<String> = Vec::new();
            for m in v {
                if !out.contains(&m) {
                    out.push(m);
                }
            }
            out
        };
        match (self, other) {
            (MethodSet::Only(a), MethodSet::Only(b)) => {
                MethodSet::Only(dedup(a.iter().filter(|m| b.contains(m)).cloned().collect()))
            }
            (MethodSet::Only(a), MethodSet::Except(b)) => MethodSet::Only(dedup(
                a.iter().filter(|m| !b.contains(m)).cloned().collect(),
            )),
            (MethodSet::Except(a), MethodSet::Only(b)) => MethodSet::Only(dedup(
                b.iter().filter(|m| !a.contains(m)).cloned().collect(),
            )),
            (MethodSet::Except(a), MethodSet::Except(b)) => {
                MethodSet::Except(dedup(a.iter().chain(b.iter()).cloned().collect()))
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, MethodSet::Only(list) if list.is_empty())
    }
}

/// One `Require` provider plus the methods it applies to.  A `None` limit
/// applies to every method.
#[derive(Debug, Clone)]
pub struct RequireEntry {
    pub node: RequireNode,
    pub limit: Option<MethodSet>,
}

impl RequireEntry {
    pub fn applies(&self, method: &str) -> bool {
        self.limit
            .as_ref()
            .map(|limit| limit.matches(method))
            .unwrap_or(true)
    }
}

/// Authorization configuration for a scope.  `List` is the implicit
/// `RequireAny` formed by ordinary `Require` directives.  `And`/`Or` nodes are
/// created when a child section uses `AuthMerging And|Or` to combine its
/// authorization logic with the preceding section's logic.
#[derive(Debug, Clone)]
pub enum AuthPolicy {
    List(Vec<RequireEntry>),
    And(Box<AuthPolicy>, Box<AuthPolicy>),
    Or(Box<AuthPolicy>, Box<AuthPolicy>),
}

impl AuthPolicy {
    pub fn is_list(&self) -> bool {
        matches!(self, AuthPolicy::List(_))
    }
}

/// Value of the `AuthMerging` directive.  It is local to the configuration
/// section in which it appears and controls how that section's authorization
/// is combined with its predecessor during merging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMerging {
    Off,
    And,
    Or,
}

/// Parsed value of the `AllowMethods` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowMethods {
    /// `AllowMethods reset`: remove any inherited restriction.
    Reset,
    Only(Vec<String>),
}

impl AllowMethods {
    pub fn allows(&self, method: &str) -> bool {
        match self {
            AllowMethods::Reset => true,
            AllowMethods::Only(methods) => {
                let method = if method == "HEAD" { "GET" } else { method };
                methods.iter().any(|m| {
                    let m = if m == "HEAD" { "GET" } else { m.as_str() };
                    m == method
                })
            }
        }
    }

    pub fn header(&self) -> String {
        match self {
            AllowMethods::Reset => String::new(),
            AllowMethods::Only(methods) => {
                let mut out: Vec<String> = Vec::new();
                for method in methods {
                    if !out.iter().any(|m| m == method) {
                        out.push(method.clone());
                    }
                    // Apache treats GET and HEAD as equivalent; advertise
                    // both so the Allow header is accurate.
                    let counterpart = match method.as_str() {
                        "GET" => Some("HEAD"),
                        "HEAD" => Some("GET"),
                        _ => None,
                    };
                    if let Some(counterpart) = counterpart {
                        if !methods.iter().any(|m| m == counterpart)
                            && !out.iter().any(|m| m == counterpart)
                        {
                            out.push(counterpart.to_string());
                        }
                    }
                }
                out.join(", ")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Satisfy {
    All,
    Any,
}

#[derive(Debug, Clone)]
pub enum HostSpec {
    All,
    Net(IpAddr, u8),
}

impl HostSpec {
    pub fn matches(&self, peer: IpAddr) -> bool {
        match self {
            HostSpec::All => true,
            HostSpec::Net(net, bits) => crate::access::ip_in_net(peer, *net, *bits),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MethodScoped<T> {
    pub limit: Option<MethodSet>,
    pub value: T,
}

impl<T> MethodScoped<T> {
    pub fn applies(&self, method: &str) -> bool {
        self.limit
            .as_ref()
            .map(|limit| limit.matches(method))
            .unwrap_or(true)
    }
}

/// Legacy `mod_access_compat` configuration (`Order`/`Allow`/`Deny`) and the
/// matching `Satisfy` policy.  As in Apache, a configuration section that
/// contains any of these directives replaces, rather than inherits, the
/// legacy policy from its parent.
#[derive(Debug, Clone, Default)]
pub struct LegacyAccess {
    pub order: Vec<MethodScoped<Order>>,
    pub satisfy: Vec<MethodScoped<Satisfy>>,
    pub allow: Vec<MethodScoped<HostSpec>>,
    pub deny: Vec<MethodScoped<HostSpec>>,
}

impl LegacyAccess {
    pub fn method_order(&self, method: &str) -> Order {
        self.order
            .iter()
            .rev()
            .find(|entry| entry.applies(method))
            .map(|entry| entry.value)
            // Apache's compiled-in default is `Order Deny,Allow`.
            .unwrap_or(Order::DenyAllow)
    }

    pub fn method_satisfy(&self, method: &str) -> Satisfy {
        self.satisfy
            .iter()
            .rev()
            .find(|entry| entry.applies(method))
            .map(|entry| entry.value)
            .unwrap_or(Satisfy::All)
    }
}

#[derive(Debug, Clone)]
pub enum ErrorDoc {
    Text(String),
    Local(String),
    External(String),
}

#[derive(Debug, Clone)]
pub struct Alias {
    pub virtual_path: String,
    pub fs_path: PathBuf,
    pub script: bool,
    /// `AliasMatch`/`ScriptAliasMatch`: match the URL with this regex and
    /// build the target from `target_template` instead of `fs_path`.
    pub regex: Option<Arc<Regex>>,
    pub target_template: Option<String>,
}

impl Alias {
    pub fn prefix(virtual_path: String, fs_path: PathBuf, script: bool) -> Self {
        Self {
            virtual_path,
            fs_path,
            script,
            regex: None,
            target_template: None,
        }
    }

    pub fn regex(
        regex: Arc<Regex>,
        target_template: String,
        script: bool,
        server_root: &Path,
    ) -> Self {
        // Keep the stable directory prefix of the replacement so the target
        // mapping and the `.htaccess` walk share the same alias root.  A
        // template such as `/srv/private/$1` has root `/srv/private`; a fixed
        // target such as `/srv/index.html` uses its parent directory.
        // Relative replacements are resolved exactly like `map_path()` does,
        // against ServerRoot.  Representing them as an empty root made the
        // access-file walk fall back to DocumentRoot and skip the target tree.
        let cut = target_template.find('$').unwrap_or(target_template.len());
        let prefix = &target_template[..cut];
        // A capture-only or leading-capture replacement has no configured
        // directory base.  Substituting ServerRoot turned `$1` into an
        // arbitrary read of the configuration tree (F42).  Keep the base
        // empty; `map_path()` rejects every empty-base mapping.
        if prefix.is_empty() {
            return Self {
                virtual_path: String::new(),
                fs_path: PathBuf::new(),
                script,
                regex: Some(regex),
                target_template: Some(target_template),
            };
        }
        let mut root = PathBuf::from(prefix);
        if !prefix.ends_with('/') {
            root = root.parent().map(Path::to_path_buf).unwrap_or(root);
        }
        let root = if root.is_absolute() {
            root
        } else {
            server_root.join(root)
        };
        Self {
            virtual_path: String::new(),
            fs_path: clean_path(&root),
            script,
            regex: Some(regex),
            target_template: Some(target_template),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Redirect {
    pub from: String,
    pub to: String,
    pub status: u16,
    /// `RedirectMatch`: match the full URL path with this regex and expand
    /// `$1`..`$9` captures in `to`.
    pub regex: Option<Arc<Regex>>,
}

#[derive(Debug, Clone, Default)]
pub struct RewriteFlags {
    pub last: bool,
    pub end: bool,
    pub redirect: Option<u16>,
    pub forbidden: bool,
    pub gone: bool,
    pub qsa: bool,
    pub nocase: bool,
    pub noescape: bool,
    pub passthrough: bool,
    pub proxy: bool,
    pub chain: bool,
    pub skip: Option<usize>,
    pub next: bool,
    pub qsd: bool,
    pub qslast: bool,
    pub unsafe_allow_3f: bool,
    pub env: Vec<(String, Option<String>)>,
    pub cookies: Vec<String>,
    pub handler: Option<String>,
    pub content_type: Option<String>,
    pub escape_backrefs: bool,
    pub escape_chars: String,
    pub escape_controls: bool,
    pub noescape_backrefs: bool,
    pub noescape_chars: String,
    pub backref_no_plus: bool,
    pub unsafe_prefix_stat: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RewriteCondFlags {
    pub nocase: bool,
    /// This condition is ORed with the next condition instead of ANDed.
    pub or: bool,
}

#[derive(Debug, Clone)]
pub struct RewriteCond {
    pub test: String,
    pub pattern: String,
    pub flags: RewriteCondFlags,
    /// Precompiled regex for ordinary condition patterns.  File tests and
    /// string comparisons leave this as `None`.
    pub regex: Option<Arc<Regex>>,
    pub expr: Option<crate::expr::Expr>,
}

#[derive(Debug, Clone)]
pub struct RewriteRule {
    pub pattern: Arc<Regex>,
    pub negated: bool,
    pub substitution: String,
    pub flags: RewriteFlags,
    pub conditions: Vec<RewriteCond>,
    /// URL prefix used to resolve relative substitutions in per-directory
    /// context (possibly changed by `RewriteBase`).
    pub base: String,
    /// URL prefix that per-directory patterns are matched against.  This is
    /// the containing directory and is not changed by `RewriteBase`.
    pub match_base: String,
    /// Access-file directory for a per-directory rule.  The rewrite subject is
    /// the requested target relative to this directory (Apache's
    /// `r->filename`-relative subject), which remains defined for layers above
    /// the URL-mapping root and targets deeper than the URL mount (F58/I58).
    pub subject_dir: Option<PathBuf>,
    pub per_dir: bool,
    /// True only for rules parsed from an access file.  Directory-context
    /// rules in the trusted main configuration are also `per_dir`, so phase
    /// alone is not a sufficient provenance boundary for FastCGI.
    pub access_file: bool,
}

#[derive(Debug, Clone)]
pub struct Handler {
    pub ext: String,
    pub handler: String,
    /// `RemoveHandler`: the matching extension no longer has a handler.
    pub remove: bool,
}

/// A `SetHandler` directive.  Unlike `AddHandler`/`RemoveHandler` (entries in
/// the ordered extension table) a `SetHandler` assignment has precedence: the
/// most specific scope that configured one decides the handler, and while a
/// name is forced the extension table can neither add nor remove execution
/// (F64/I62).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetHandler {
    Name(String),
    /// `SetHandler None`: no forced handler; the extension table applies.
    None_,
}

impl SetHandler {
    pub fn name(&self) -> Option<&str> {
        match self {
            SetHandler::Name(name) => Some(name.as_str()),
            SetHandler::None_ => None,
        }
    }

    /// Parse the `SetHandler` value argument.  `None` (case-insensitive)
    /// clears any inherited force.
    pub fn parse(value: &str) -> Self {
        if value.eq_ignore_ascii_case("none") {
            SetHandler::None_
        } else {
            SetHandler::Name(value.to_string())
        }
    }
}

impl Handler {
    pub fn add(ext: String, handler: String) -> Self {
        Self {
            ext,
            handler,
            remove: false,
        }
    }

    pub fn remove(ext: String) -> Self {
        Self {
            ext,
            handler: String::new(),
            remove: true,
        }
    }
}

pub(crate) fn normalize_handler_extension(raw: &str) -> String {
    raw.strip_prefix('.').unwrap_or(raw).to_ascii_lowercase()
}

/// Return Apache-style extension tokens for a basename.  Leading dots belong
/// to the hidden-file stem, not to an extension; at least one non-dot stem
/// byte and a subsequent separator are required.  Every non-empty token is
/// retained because mod_mime applies metadata across multi-extension names.
pub(crate) fn filename_extension_tokens(name: &[u8]) -> Vec<&[u8]> {
    let base = name.rsplit(|b| *b == b'/').next().unwrap_or(name);
    let Some(first_stem) = base.iter().position(|b| *b != b'.') else {
        return Vec::new();
    };
    let visible = &base[first_stem..];
    let separator = visible.iter().position(|b| *b == b'.');
    if !vapache_verified::extension_table_admit(
        separator.is_some_and(|index| index > 0),
        separator.is_some(),
    ) {
        return Vec::new();
    }
    visible[separator.unwrap_or(visible.len()) + 1..]
        .split(|b| *b == b'.')
        .filter(|part| !part.is_empty())
        .collect()
}

/// Resolve the effective handler for one literal extension token.
/// `RemoveHandler` is a deny entry and wins over matching additions in the
/// effective scope regardless of directive order.
pub(crate) fn effective_handler_for_ext<'a>(scope: &'a Scope, ext: &str) -> Option<&'a str> {
    let removed = scope
        .mapping_policy
        .handlers
        .iter()
        .any(|handler| handler.remove && handler.ext.eq_ignore_ascii_case(ext));
    let added = scope
        .mapping_policy
        .handlers
        .iter()
        .rev()
        .find(|handler| !handler.remove && handler.ext.eq_ignore_ascii_case(ext));
    if !vapache_verified::handler_extension_admit(removed, added.is_some()) {
        return None;
    }
    added.map(|handler| handler.handler.as_str())
}

/// Resolve the effective handler for a filename.  `SetHandler` has
/// precedence over the extension table (F64/I62): the most specific scope
/// that configured one decides the handler no matter how the `AddHandler`
/// and `SetHandler` directives are ordered across parse order and
/// inheritance.  `SetHandler None` unforces, so the extension table applies.
pub(crate) fn effective_handler<'a>(scope: &'a Scope, name: &[u8]) -> Option<&'a str> {
    match &scope.mapping_policy.set_handler {
        Some(SetHandler::Name(forced)) => return Some(forced.as_str()),
        Some(SetHandler::None_) | None => {}
    }
    let mut selected = None;
    for token in filename_extension_tokens(name) {
        let Some(ext) = std::str::from_utf8(token).ok() else {
            continue;
        };
        if let Some(handler) = effective_handler_for_ext(scope, ext) {
            selected = Some(handler);
        }
    }
    selected
}

/// Meet two handler maps.  For every extension either side mentions, the
/// result grants a handler only when both scopes resolve to the same handler;
/// everything else is an explicit removal.  Unknown extensions follow the
/// same rule through the wildcard entry.  This is what prevents a canonical
/// target `AddHandler` from undoing a lexical `RemoveHandler` (F60/I61).
fn conjoined_handlers(base: &[Handler], target: &[Handler]) -> Vec<Handler> {
    fn lookup<'a>(handlers: &'a [Handler], ext: &str) -> Option<&'a str> {
        let removed = handlers
            .iter()
            .any(|handler| handler.remove && handler.ext.eq_ignore_ascii_case(ext));
        let added = handlers
            .iter()
            .rev()
            .find(|handler| !handler.remove && handler.ext.eq_ignore_ascii_case(ext));
        if vapache_verified::handler_extension_admit(removed, added.is_some()) {
            if let Some(handler) = added {
                return Some(handler.handler.as_str());
            }
        }
        None
    }

    fn same(a: Option<&str>, b: Option<&str>) -> bool {
        match (a, b) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            (None, None) => true,
            _ => false,
        }
    }

    let mut out = Vec::new();
    let mut extensions: Vec<String> = Vec::new();
    for handler in base.iter().chain(target.iter()) {
        let ext = handler.ext.to_ascii_lowercase();
        if !extensions.contains(&ext) {
            extensions.push(ext);
        }
    }
    for ext in extensions {
        let base_handler = lookup(base, &ext);
        let target_handler = lookup(target, &ext);
        if vapache_verified::handler_conjoin_admit(
            base_handler.is_some(),
            target_handler.is_some(),
            same(base_handler, target_handler),
        ) {
            out.push(Handler::add(
                ext,
                base_handler.unwrap_or_default().to_string(),
            ));
        } else {
            out.push(Handler::remove(ext));
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionKind {
    Gzip,
    Brotli,
}

impl CompressionKind {
    pub fn encoding(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Brotli => "br",
        }
    }

    pub fn parse_filter(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("DEFLATE") || name.eq_ignore_ascii_case("GZIP") {
            Some(Self::Gzip)
        } else if name.eq_ignore_ascii_case("BROTLI_COMPRESS")
            || name.eq_ignore_ascii_case("BROTLI")
        {
            Some(Self::Brotli)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionRule {
    /// `SetOutputFilter DEFLATE BROTLI_COMPRESS`
    Set(Vec<CompressionKind>),
    /// `AddOutputFilterByType DEFLATE text/html ...`
    ByType(CompressionKind, Vec<String>),
    /// `AddOutputFilter DEFLATE .html .css`
    ByExt(CompressionKind, Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedFilterRule {
    ByType(String, Vec<String>),
    ByExt(String, Vec<String>),
}

pub(crate) fn parse_filter_names(tokens: &[String]) -> (Vec<CompressionKind>, Vec<String>) {
    let mut kinds = Vec::new();
    let mut unsupported = Vec::new();
    for token in tokens {
        for part in token.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            match CompressionKind::parse_filter(part) {
                Some(kind) if !kinds.contains(&kind) => kinds.push(kind),
                Some(_) => {}
                None if !unsupported
                    .iter()
                    .any(|name: &String| name.eq_ignore_ascii_case(part)) =>
                {
                    unsupported.push(part.to_string());
                }
                None => {}
            }
        }
    }
    (kinds, unsupported)
}

/// Parse filter names, recording any unimplemented filter so requests fail
/// closed instead of serving unfiltered source.
pub(crate) fn parse_filter_tokens(scope: &mut Scope, tokens: &[String]) -> Vec<CompressionKind> {
    let (kinds, unsupported) = parse_filter_names(tokens);
    for name in unsupported {
        if !scope
            .mapping_policy
            .unsupported_filters
            .iter()
            .any(|filter| filter.eq_ignore_ascii_case(&name))
        {
            scope.mapping_policy.unsupported_filters.push(name);
        }
    }
    kinds
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlterEtag {
    AddSuffix,
    NoChange,
    Remove,
}

impl AlterEtag {
    pub fn parse(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("AddSuffix") {
            Some(Self::AddSuffix)
        } else if s.eq_ignore_ascii_case("NoChange") {
            Some(Self::NoChange)
        } else if s.eq_ignore_ascii_case("Remove") {
            Some(Self::Remove)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct HealthTemplate {
    pub method: Option<String>,
    pub uri: Option<String>,
    pub interval: Option<Duration>,
    pub passes: Option<u32>,
    pub fails: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct BalancerMember {
    pub url: String,
    pub hcmethod: Option<String>,
    pub hcuri: Option<String>,
    pub hcinterval: Option<Duration>,
    pub hcpasses: Option<u32>,
    pub hcfails: Option<u32>,
    pub template: Option<String>,
    pub route: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Balancer {
    pub name: String,
    pub members: Vec<BalancerMember>,
    pub health: HealthTemplate,
    pub sticky_cookie: Option<String>,
    pub sticky_sep: Option<String>,
    pub fail_on_status: Vec<u16>,
}

impl Balancer {
    pub fn health_enabled(&self) -> bool {
        self.health.uri.is_some()
            || self.health.method.is_some()
            || self
                .members
                .iter()
                .any(|m| m.hcuri.is_some() || m.hcmethod.is_some() || m.template.is_some())
    }
}

#[derive(Debug, Clone)]
pub struct ProxyRule {
    pub pattern: Arc<Regex>,
    pub backend: String,
    /// Position in the merged `ProxyPass`/`ProxyPassMatch` route table.
    pub route_order: usize,
}

#[derive(Debug, Clone)]
pub struct ProxyPassRule {
    pub prefix: String,
    pub backend: String,
    pub sticky_cookie: Option<String>,
    pub fail_on_status: Vec<u16>,
    /// Position in the merged `ProxyPass`/`ProxyPassMatch` route table.
    pub route_order: usize,
}

#[derive(Debug, Clone)]
pub struct ProxyReverseRule {
    pub front: String,
    pub backend: String,
}

#[derive(Debug, Clone)]
pub struct RewriteProgram {
    pub(crate) path: PathBuf,
    /// Canonical root-controlled source whose parents belong in the
    /// privileged administrative-input manifest. The configured spelling is
    /// retained separately for the runtime binding check.
    pub(crate) admin_trust_path: Option<PathBuf>,
    pub(crate) args: Vec<String>,
    pub(crate) file: Arc<File>,
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    size: u64,
    mode: u32,
}

impl RewriteProgram {
    pub(crate) fn bind(path: PathBuf, args: Vec<String>) -> std::io::Result<Self> {
        Self::bind_with_trust(path, args, crate::files::AdminFileTrust::ProcessOwned)
    }

    pub(crate) fn bind_with_trust(
        path: PathBuf,
        args: Vec<String>,
        trust: crate::files::AdminFileTrust,
    ) -> std::io::Result<Self> {
        let (mut source, admin_trust_path) = if trust == crate::files::AdminFileTrust::RootOwned {
            // Root-controlled symlink spellings such as /bin -> /usr/bin are
            // compatible, but the resolved executable itself must be a
            // root-owned non-writable regular file opened without symlinks.
            let canonical = std::fs::canonicalize(&path)?;
            (
                crate::files::validate_root_owned_admin_file(&canonical)?,
                Some(canonical),
            )
        } else {
            (
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_CLOEXEC)
                    .open(&path)?,
                None,
            )
        };
        let meta = source.metadata()?;
        if !meta.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "is not a regular file",
            ));
        }
        if meta.mode() & 0o111 == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "is not executable",
            ));
        }
        if meta.len() > MAX_REWRITEMAP_PROGRAM {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("exceeds the {MAX_REWRITEMAP_PROGRAM} byte executable limit"),
            ));
        }

        // Copy the validated version into a sealed anonymous executable. The
        // later pathname check detects operator changes, while execution from
        // this immutable snapshot also closes same-inode write races between
        // the check and execve.
        let name = CString::new("vapache-rewritemap-prg").expect("static memfd name");
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            // coverage:ignore-start -- kernel/platform lacks required memfd support
            return Err(std::io::Error::last_os_error());
            // coverage:ignore-stop
        }
        let mut file = unsafe { File::from_raw_fd(fd as i32) };
        let copied = std::io::copy(
            &mut source
                .by_ref()
                .take(MAX_REWRITEMAP_PROGRAM.saturating_add(1)),
            &mut file,
        )?; // coverage:ignore-line -- regular-file/memfd I/O failure
        let after = source.metadata()?;
        if copied != meta.len()
            || !vapache_verified::descriptor_snapshot_admit(
                meta.is_file() && after.is_file(),
                meta.dev() == after.dev() && meta.ino() == after.ino(),
                meta.mtime() == after.mtime()
                    && meta.mtime_nsec() == after.mtime_nsec()
                    && meta.ctime() == after.ctime()
                    && meta.ctime_nsec() == after.ctime_nsec()
                    && meta.len() == after.len()
                    && meta.mode() == after.mode(),
                copied <= MAX_REWRITEMAP_PROGRAM,
            )
        {
            // coverage:ignore-start -- concurrent source mutation during startup snapshot
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "changed while its executable snapshot was created",
            ));
            // coverage:ignore-stop
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o500) } != 0 {
            // coverage:ignore-start -- kernel rejects mode change on a new memfd
            return Err(std::io::Error::last_os_error());
            // coverage:ignore-stop
        }
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            // coverage:ignore-start -- kernel rejects sealing despite MFD_ALLOW_SEALING
            return Err(std::io::Error::last_os_error());
            // coverage:ignore-stop
        }
        Ok(Self {
            path,
            admin_trust_path,
            args,
            file: Arc::new(file),
            dev: meta.dev(),
            ino: meta.ino(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            size: meta.len(),
            mode: meta.mode(),
        })
    }

    fn metadata_matches(&self, meta: &std::fs::Metadata) -> bool {
        meta.dev() == self.dev
            && meta.ino() == self.ino
            && meta.mtime() == self.mtime
            && meta.mtime_nsec() == self.mtime_nsec
            && meta.ctime() == self.ctime
            && meta.ctime_nsec() == self.ctime_nsec
            && meta.len() == self.size
            && meta.mode() == self.mode
    }

    /// The configured pathname must still name the exact executable version
    /// retained at load time. Execution uses the retained descriptor, so a
    /// rename after this check cannot redirect the child to a replacement.
    pub(crate) fn binding_intact(&self) -> bool {
        let retained = match self.file.metadata() {
            Ok(meta) => meta,
            Err(_) => return false, // coverage:ignore-line -- live owned memfd fstat failure
        };
        let current = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(&self.path)
            .and_then(|file| file.metadata())
        {
            Ok(meta) => meta,
            Err(_) => return false,
        };
        vapache_verified::descriptor_snapshot_admit(
            retained.is_file() && current.is_file(),
            current.dev() == self.dev && current.ino() == self.ino,
            self.metadata_matches(&current),
            current.len() <= MAX_REWRITEMAP_PROGRAM,
        ) && retained.mode() & 0o111 != 0
            && current.mode() & 0o111 != 0
    }

    pub(crate) fn cache_material(&self) -> String {
        format!(
            "{}|{:?}|{}:{}:{}:{}:{}:{}:{}:{}",
            self.path.display(),
            self.args,
            self.dev,
            self.ino,
            self.mtime,
            self.mtime_nsec,
            self.ctime,
            self.ctime_nsec,
            self.size,
            self.mode
        )
    }
}

#[derive(Debug, Clone)]
pub enum RewriteMap {
    Txt(HashMap<String, String>),
    /// key -> one of several pipe-separated random choices
    Rnd(HashMap<String, Vec<String>>),
    Prg(RewriteProgram),
    Int(String),
}

#[derive(Debug, Clone)]
pub struct EnvRule {
    pub attribute: String,
    pub pattern: Arc<Regex>,
    pub negate: bool,
    pub nocase: bool,
    /// `(name, Some(value))` sets the variable; `(name, None)` unsets it.
    pub actions: Vec<(String, Option<String>)>,
}

/// Byte-exact request environment used by authorization, rewrite evaluation,
/// CGI and FastCGI. Text conversion is deferred until a consumer explicitly
/// requires UTF-8, so chained captures cannot collapse attacker-controlled
/// bytes through the replacement character.
pub type RequestEnvironment = Vec<(String, Vec<u8>)>;

/// Parse `SetEnvIf`, `SetEnvIfNoCase`, `BrowserMatch` and
/// `BrowserMatchNoCase` uniformly.  `.htaccess` and the main configuration
/// must share this parser: silently dropping or mis-indexing an environment
/// action changes the result of `Require env`/`Require expr`.
pub(crate) fn parse_env_rule(name: &str, args: &[String]) -> Result<EnvRule, String> {
    let nocase = name.ends_with("nocase");
    let (attribute, pattern_idx, actions_idx) = if name.starts_with("browsermatch") {
        ("User-Agent".to_string(), 0, 1)
    } else {
        (args.first().cloned().unwrap_or_default(), 1, 2)
    };
    let Some(pattern) = args.get(pattern_idx) else {
        return Err(format!("{name} requires an attribute, pattern and action"));
    };
    let attr_l = attribute.to_ascii_lowercase();
    if matches!(attr_l.as_str(), "remote_host" | "server_addr") {
        return Err(format!(
            "{name} attribute '{attribute}' is not supported safely"
        ));
    }
    if !matches!(
        attr_l.as_str(),
        "remote_addr" | "request_uri" | "request_method" | "request_protocol"
    ) && !attribute
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        // Apache treats a non-simple attribute as a regex over header names.
        // Refuse that mode until it is represented explicitly; treating the
        // regex text as an absent header can turn `^$` into an ACL grant.
        return Err(format!(
            "{name} regex header attributes are not supported safely"
        ));
    }
    let pattern = if nocase {
        format!("(?i:{pattern})")
    } else {
        pattern.clone()
    };
    let pattern = compile_regex(&pattern).map_err(|e| format!("bad SetEnvIf regex: {e}"))?;
    let mut actions = Vec::new();
    for action in &args[actions_idx..] {
        if let Some(name) = action.strip_prefix('!') {
            actions.push((name.to_string(), None));
        } else if let Some((k, v)) = action.split_once('=') {
            actions.push((k.to_string(), Some(v.to_string())));
        } else {
            // mod_setenvif assigns "1" to a bare environment action.
            actions.push((action.to_string(), Some("1".into())));
        }
    }
    if actions.is_empty() {
        return Err(format!("{name} requires an environment action"));
    }
    Ok(EnvRule {
        attribute,
        pattern: Arc::new(pattern),
        negate: false,
        nocase,
        actions,
    })
}

#[derive(Debug, Clone)]
pub struct Scope {
    /// Set when a request-time conditional cannot be evaluated. Every
    /// authorization path treats this as a configuration failure, so an
    /// engine error can never erase a deny/handler restriction (P15-C).
    pub conditional_error: bool,
    pub options: OptionsPolicy,
    pub override_policy: OverridePolicy,
    pub authorization: AuthorizationPolicy,
    pub header_policy: HeaderPolicy,
    pub content_policy: ContentPolicy,
    pub mapping_policy: MappingPolicy,
    pub error_policy: ErrorDocumentPolicy,
    pub environment_policy: EnvironmentPolicy,
    pub rewrite_policy: RewriteCachePolicy,
    pub compression_policy: CompressionPolicy,
    pub proxy_policy: ProxyPolicy,
}

impl Default for Scope {
    fn default() -> Self {
        Scope {
            conditional_error: false,
            options: OptionsPolicy::default(),
            override_policy: OverridePolicy::default(),
            authorization: AuthorizationPolicy::default(),
            header_policy: HeaderPolicy::default(),
            content_policy: ContentPolicy::default(),
            mapping_policy: MappingPolicy::default(),
            rewrite_policy: RewriteCachePolicy::default(),
            compression_policy: CompressionPolicy::default(),
            proxy_policy: ProxyPolicy::default(),
            error_policy: ErrorDocumentPolicy::default(),
            environment_policy: EnvironmentPolicy::default(),
        }
    }
}

pub const ETAG_INODE: u32 = 1;
pub const ETAG_MTIME: u32 = 2;
pub const ETAG_SIZE: u32 = 4;
pub const ETAG_ALL: u32 = 7;

/// Upper bound on any RewriteMap file loaded at startup (txt/rnd), mirroring
/// the `.htaccess` size cap: parsing an unbounded file into memory is
/// unbounded work a configuration error can avert.
const MAX_REWRITEMAP: u64 = 1024 * 1024;
const MAX_REWRITEMAP_PROGRAM: u64 = 64 * 1024 * 1024;

#[cfg(debug_assertions)]
#[derive(Debug, PartialEq, Eq)]
struct ContainerSnapshot {
    error_documents: Vec<(u16, u64)>,
    aliases: Vec<u64>,
    redirects: Vec<u64>,
    handlers: Vec<u64>,
    unsupported_filters: Vec<u64>,
    add_types: Vec<u64>,
    remove_types: Vec<u64>,
    add_headers: Vec<u64>,
    set_headers: Vec<(String, u64)>,
    unset_headers: Vec<u64>,
    always_add_headers: Vec<u64>,
    always_set_headers: Vec<(String, u64)>,
    always_unset_headers: Vec<u64>,
    expires_by_type: Vec<u64>,
    rewrite_env: Vec<u64>,
    rewrite_unset_env: Vec<u64>,
    rewrite_late_env: Vec<u64>,
    rewrite_late_unset_env: Vec<u64>,
    set_env: Vec<u64>,
    unset_env: Vec<u64>,
    pass_env: Vec<u64>,
    set_env_if: Vec<u64>,
    cookies: Vec<u64>,
    vary: Vec<u64>,
    rewrite_maps: Vec<(String, u64)>,
    cache_enable: Vec<u64>,
    cache_disable: Vec<u64>,
    rewrite_rules: Vec<u64>,
    compression_rules: Vec<u64>,
    unsupported_filter_rules: Vec<u64>,
    proxy_rules: Vec<u64>,
    proxy_passes: Vec<u64>,
    proxy_reverses: Vec<u64>,
}

#[cfg(debug_assertions)]
fn hash_item<T: std::fmt::Debug>(value: &T) -> u64 {
    let mut h = DefaultHasher::new();
    format!("{value:?}").hash(&mut h);
    h.finish()
}

#[cfg(debug_assertions)]
fn hash_vec<T: std::fmt::Debug>(values: &[T]) -> Vec<u64> {
    values.iter().map(hash_item).collect()
}

#[cfg(debug_assertions)]
impl Scope {
    fn container_snapshot(&self) -> ContainerSnapshot {
        ContainerSnapshot {
            error_documents: self
                .error_policy
                .documents
                .iter()
                .map(|(k, v)| (*k, hash_item(v)))
                .collect(),
            aliases: hash_vec(&self.mapping_policy.aliases),
            redirects: hash_vec(&self.mapping_policy.redirects),
            handlers: hash_vec(&self.mapping_policy.handlers),
            unsupported_filters: hash_vec(&self.mapping_policy.unsupported_filters),
            add_types: hash_vec(&self.content_policy.add_types),
            remove_types: hash_vec(&self.content_policy.remove_types),
            add_headers: hash_vec(&self.header_policy.add_headers),
            set_headers: self
                .header_policy
                .set_headers
                .iter()
                .map(|(k, v)| (k.clone(), hash_item(v)))
                .collect(),
            unset_headers: hash_vec(&self.header_policy.unset_headers),
            always_add_headers: hash_vec(&self.header_policy.always_add_headers),
            always_set_headers: self
                .header_policy
                .always_set_headers
                .iter()
                .map(|(k, v)| (k.clone(), hash_item(v)))
                .collect(),
            always_unset_headers: hash_vec(&self.header_policy.always_unset_headers),
            expires_by_type: hash_vec(&self.header_policy.expires_by_type),
            rewrite_env: hash_vec(&self.environment_policy.rewrite_env),
            rewrite_unset_env: hash_vec(&self.environment_policy.rewrite_unset_env),
            rewrite_late_env: hash_vec(&self.environment_policy.rewrite_late_env),
            rewrite_late_unset_env: hash_vec(&self.environment_policy.rewrite_late_unset_env),
            set_env: hash_vec(&self.environment_policy.set_env),
            unset_env: hash_vec(&self.environment_policy.unset_env),
            pass_env: hash_vec(&self.environment_policy.pass_env),
            set_env_if: hash_vec(&self.environment_policy.set_env_if),
            cookies: hash_vec(&self.header_policy.cookies),
            vary: hash_vec(&self.header_policy.vary),
            rewrite_maps: self
                .rewrite_policy
                .rewrite_maps
                .iter()
                .map(|(k, v)| (k.clone(), hash_item(v)))
                .collect(),
            cache_enable: hash_vec(&self.rewrite_policy.cache_enable),
            cache_disable: hash_vec(&self.rewrite_policy.cache_disable),
            rewrite_rules: hash_vec(&self.rewrite_policy.rewrite_rules),
            compression_rules: hash_vec(&self.compression_policy.compression_rules),
            unsupported_filter_rules: hash_vec(&self.compression_policy.unsupported_filter_rules),
            proxy_rules: hash_vec(&self.proxy_policy.proxy_rules),
            proxy_passes: hash_vec(&self.proxy_policy.proxy_passes),
            proxy_reverses: hash_vec(&self.proxy_policy.proxy_reverses),
        }
    }

    fn container_snapshot_with_rewrite(
        &self,
        rewrite_rules: Option<&[RewriteRule]>,
    ) -> ContainerSnapshot {
        let mut snapshot = self.container_snapshot();
        if let Some(rules) = rewrite_rules {
            snapshot.rewrite_rules = hash_vec(rules);
        }
        snapshot
    }

    #[allow(dead_code)]
    fn merge_container_snapshots(
        parent: &ContainerSnapshot,
        child: &ContainerSnapshot,
    ) -> ContainerSnapshot {
        let mut error_documents = parent.error_documents.clone();
        error_documents.extend(child.error_documents.iter().copied());
        let mut rewrite_maps = parent.rewrite_maps.clone();
        rewrite_maps.extend(child.rewrite_maps.iter().cloned());
        let append = |a: &Vec<u64>, b: &Vec<u64>| {
            let mut out = a.clone();
            out.extend(b.iter().copied());
            out
        };
        let merge_set = |a: &Vec<(String, u64)>, b: &Vec<(String, u64)>| {
            let mut out = a.clone();
            for (name, value) in b {
                out.retain(|(existing, _)| existing != name);
                out.push((name.clone(), *value));
            }
            out
        };
        ContainerSnapshot {
            error_documents,
            aliases: append(&parent.aliases, &child.aliases),
            redirects: append(&parent.redirects, &child.redirects),
            handlers: append(&parent.handlers, &child.handlers),
            unsupported_filters: append(&parent.unsupported_filters, &child.unsupported_filters),
            add_types: append(&parent.add_types, &child.add_types),
            remove_types: append(&parent.remove_types, &child.remove_types),
            add_headers: append(&parent.add_headers, &child.add_headers),
            set_headers: merge_set(&parent.set_headers, &child.set_headers),
            unset_headers: append(&parent.unset_headers, &child.unset_headers),
            always_add_headers: append(&parent.always_add_headers, &child.always_add_headers),
            always_set_headers: merge_set(&parent.always_set_headers, &child.always_set_headers),
            always_unset_headers: append(&parent.always_unset_headers, &child.always_unset_headers),
            expires_by_type: append(&parent.expires_by_type, &child.expires_by_type),
            rewrite_env: append(&parent.rewrite_env, &child.rewrite_env),
            rewrite_unset_env: append(&parent.rewrite_unset_env, &child.rewrite_unset_env),
            rewrite_late_env: append(&parent.rewrite_late_env, &child.rewrite_late_env),
            rewrite_late_unset_env: append(
                &parent.rewrite_late_unset_env,
                &child.rewrite_late_unset_env,
            ),
            set_env: append(&parent.set_env, &child.set_env),
            unset_env: append(&parent.unset_env, &child.unset_env),
            pass_env: append(&parent.pass_env, &child.pass_env),
            set_env_if: append(&parent.set_env_if, &child.set_env_if),
            cookies: append(&parent.cookies, &child.cookies),
            vary: append(&parent.vary, &child.vary),
            rewrite_maps,
            cache_enable: append(&parent.cache_enable, &child.cache_enable),
            cache_disable: append(&parent.cache_disable, &child.cache_disable),
            rewrite_rules: append(&parent.rewrite_rules, &child.rewrite_rules),
            compression_rules: append(&parent.compression_rules, &child.compression_rules),
            unsupported_filter_rules: append(
                &parent.unsupported_filter_rules,
                &child.unsupported_filter_rules,
            ),
            proxy_rules: append(&parent.proxy_rules, &child.proxy_rules),
            proxy_passes: append(&parent.proxy_passes, &child.proxy_passes),
            proxy_reverses: append(&parent.proxy_reverses, &child.proxy_reverses),
        }
    }
}

impl Scope {
    /// Child scopes are appended after their parent; reverse lookup therefore
    /// gives the child value for a duplicate status code.
    pub fn error_document(&self, status: u16) -> Option<&ErrorDoc> {
        self.error_policy.get(status)
    }

    /// Environment visible before authentication/authorization. Apache runs
    /// SetEnvIf during request/header parsing and server-scope rewrite `[E]`
    /// before authz. Per-directory rewrite `[E]` and mod_env's
    /// SetEnv/PassEnv/UnsetEnv hook run later in fixups.
    fn apply_set_env_if_rules(
        rules: &[Originated<EnvRule>],
        req: &crate::http::Request,
        url_path: &str,
        peer: IpAddr,
        fastcgi: bool,
        env: &mut RequestEnvironment,
    ) {
        for entry in rules {
            if fastcgi && !vapache_verified::fastcgi_environment_origin_admit(entry.origin) {
                continue;
            }
            let rule = &entry.value;
            let attr = rule.attribute.to_ascii_lowercase();
            let subject: Vec<u8> = match attr.as_str() {
                "request_method" | "request-method" => req.method.as_bytes().to_vec(),
                "request_uri" | "request-uri" => url_path.as_bytes().to_vec(),
                "remote_addr" | "remote-addr" => peer.to_string().into_bytes(),
                "request_protocol" | "request-protocol" => match req.version {
                    crate::http::Version::Http10 => b"HTTP/1.0".to_vec(),
                    crate::http::Version::Http11 => b"HTTP/1.1".to_vec(),
                    crate::http::Version::Http2 => b"HTTP/2.0".to_vec(),
                },
                "host" => req
                    .header("host")
                    .map(vapache_verified::guard_header_bytes)
                    .unwrap_or_default(),
                "user-agent" | "user_agent" => req
                    .header("user-agent")
                    .map(vapache_verified::guard_header_bytes)
                    .unwrap_or_default(),
                "referer" => req
                    .header("referer")
                    .map(vapache_verified::guard_header_bytes)
                    .unwrap_or_default(),
                "content-type" | "content_type" => req
                    .header("content-type")
                    .map(vapache_verified::guard_header_bytes)
                    .unwrap_or_default(),
                other => req
                    .header(other)
                    .map(vapache_verified::guard_header_bytes)
                    .or_else(|| {
                        env.iter()
                            .rev()
                            .find(|(name, _)| name.eq_ignore_ascii_case(other))
                            .map(|(_, value)| value.clone())
                    })
                    .unwrap_or_default(),
            };
            let work = rule
                .pattern
                .as_str()
                .len()
                .checked_add(subject.len())
                .and_then(|n| n.checked_add(1))
                .and_then(|n| u64::try_from(n).ok());
            let Some(work) = work else {
                let _ = req.charge_policy_work(u64::MAX);
                return;
            };
            if req.charge_policy_work(work).is_err() {
                return;
            }
            let captures = rule.pattern.captures(&subject);
            if captures.is_some() == rule.negate {
                continue;
            }
            for (name, value) in &rule.actions {
                match value {
                    Some(v) => {
                        // `regex::Captures::expand` writes directly to a Vec.
                        // Admit a conservative upper bound before calling it:
                        // every '$' can contribute at most the complete
                        // matched subject, while every literal byte contributes
                        // at most itself.  This prevents the CVE-2011-4415
                        // `$1$1...` allocation shape before memory is reserved.
                        let expansion_bound = if captures.is_some() {
                            v.len().checked_add(
                                v.as_bytes()
                                    .iter()
                                    .filter(|byte| **byte == b'$')
                                    .count()
                                    .checked_mul(subject.len())
                                    .unwrap_or(usize::MAX),
                            )
                        } else {
                            Some(v.len())
                        };
                        let Some(expansion_bound) =
                            expansion_bound.and_then(|bytes| u64::try_from(bytes).ok())
                        else {
                            let _ = req.charge_policy_expansion(u64::MAX);
                            return;
                        };
                        if req.charge_policy_expansion(expansion_bound).is_err() {
                            return;
                        }
                        let mut expanded = Vec::new();
                        if let Some(captures) = &captures {
                            captures.expand(v.as_bytes(), &mut expanded);
                        } else {
                            expanded.extend_from_slice(v.as_bytes());
                        }
                        debug_assert!(expanded.len() as u64 <= expansion_bound);
                        env.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
                        env.push((name.clone(), expanded));
                    }
                    None => env.retain(|(n, _)| !n.eq_ignore_ascii_case(name)),
                }
            }
        }
    }

    fn authorization_environment(
        &self,
        req: &crate::http::Request,
        url_path: &str,
        peer: IpAddr,
        fastcgi: bool,
    ) -> RequestEnvironment {
        let mut env = RequestEnvironment::new();
        Self::apply_set_env_if_rules(
            &self.environment_policy.set_env_if,
            req,
            url_path,
            peer,
            fastcgi,
            &mut env,
        );
        for entry in &self.environment_policy.rewrite_env {
            if fastcgi && !vapache_verified::fastcgi_environment_origin_admit(entry.origin) {
                continue;
            }
            let (name, value) = &entry.value;
            env.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
            env.push((name.clone(), value.clone()));
        }
        for entry in &self.environment_policy.rewrite_unset_env {
            if fastcgi && !vapache_verified::fastcgi_environment_origin_admit(entry.origin) {
                continue;
            }
            let name = &entry.value;
            env.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        }
        env
    }

    pub fn authorization_env(
        &self,
        req: &crate::http::Request,
        url_path: &str,
        peer: IpAddr,
    ) -> RequestEnvironment {
        self.authorization_environment(req, url_path, peer, false)
    }

    fn complete_environment(
        &self,
        req: &crate::http::Request,
        url_path: &str,
        peer: IpAddr,
        fastcgi: bool,
    ) -> RequestEnvironment {
        let mut env = self.authorization_environment(req, url_path, peer, fastcgi);
        for entry in &self.environment_policy.rewrite_late_env {
            if fastcgi && !vapache_verified::fastcgi_environment_origin_admit(entry.origin) {
                continue;
            }
            let (name, value) = &entry.value;
            env.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
            env.push((name.clone(), value.clone()));
        }
        for entry in &self.environment_policy.rewrite_late_unset_env {
            if fastcgi && !vapache_verified::fastcgi_environment_origin_admit(entry.origin) {
                continue;
            }
            let name = &entry.value;
            env.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        }
        for entry in &self.environment_policy.set_env {
            if fastcgi && !vapache_verified::fastcgi_environment_origin_admit(entry.origin) {
                continue;
            }
            let (name, value) = &entry.value;
            env.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
            env.push((name.clone(), value.as_bytes().to_vec()));
        }
        for entry in &self.environment_policy.pass_env {
            if fastcgi && !vapache_verified::fastcgi_environment_origin_admit(entry.origin) {
                continue;
            }
            let name = &entry.value;
            let Some(value) = std::env::var_os(name) else {
                continue;
            };
            env.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
            env.push((name.clone(), value.as_os_str().as_bytes().to_vec()));
        }
        for entry in &self.environment_policy.unset_env {
            if fastcgi && !vapache_verified::fastcgi_environment_origin_admit(entry.origin) {
                continue;
            }
            let name = &entry.value;
            env.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        }
        env
    }

    /// Complete fixups environment for a local CGI process. Access-file
    /// environment mutations are intentionally supported here, matching
    /// Apache's local CGI behavior.
    pub fn request_env(
        &self,
        req: &crate::http::Request,
        url_path: &str,
        peer: IpAddr,
    ) -> RequestEnvironment {
        self.complete_environment(req, url_path, peer, false)
    }

    /// Environment forwarded as FastCGI parameters. Apache does not promote
    /// `.htaccess` environment mutations into proxy/FastCGI parameters; keep
    /// that trust boundary by provenance, independently of variable names.
    pub fn fastcgi_env(
        &self,
        req: &crate::http::Request,
        url_path: &str,
        peer: IpAddr,
    ) -> RequestEnvironment {
        self.complete_environment(req, url_path, peer, true)
    }

    pub fn add_require(&mut self, node: RequireNode, limit: Option<&MethodSet>) {
        self.authorization.add_require(node, limit);
    }

    /// The `AllowMethods` restriction for this scope, if any.
    pub fn method_allowed(&self, method: &str) -> bool {
        self.authorization.method_allowed(method)
    }

    pub fn allow_methods_header(&self) -> Option<String> {
        self.authorization.allow_methods_header()
    }

    pub fn add_order(&mut self, order: Order, limit: Option<&MethodSet>) {
        self.authorization.legacy_mut().order.push(MethodScoped {
            limit: limit.cloned(),
            value: order,
        });
    }

    pub fn add_satisfy(&mut self, satisfy: Satisfy, limit: Option<&MethodSet>) {
        self.authorization.legacy_mut().satisfy.push(MethodScoped {
            limit: limit.cloned(),
            value: satisfy,
        });
    }

    pub fn add_allow(&mut self, host: HostSpec, limit: Option<&MethodSet>) {
        self.authorization.legacy_mut().allow.push(MethodScoped {
            limit: limit.cloned(),
            value: host,
        });
    }

    pub fn add_deny(&mut self, host: HostSpec, limit: Option<&MethodSet>) {
        self.authorization.legacy_mut().deny.push(MethodScoped {
            limit: limit.cloned(),
            value: host,
        });
    }

    /// Apply a (possibly partial) child scope over this one.
    pub fn merge(&mut self, child: &Scope) {
        self.merge_inner(child, None);
    }

    /// Merge a rule delta while substituting a pre-transformed rewrite-rule
    /// list.  Used for per-directory rewrite rules so the hot path does not
    /// clone the whole `Scope`.
    pub fn merge_with_rewrite_rules(&mut self, child: &Scope, rules: &[RewriteRule]) {
        self.merge_inner(child, Some(rules));
    }

    fn merge_inner(&mut self, child: &Scope, rewrite_rules: Option<&[RewriteRule]>) {
        #[cfg(debug_assertions)]
        let audit_parent = self.container_snapshot();
        #[cfg(debug_assertions)]
        let audit_child = child.container_snapshot_with_rewrite(rewrite_rules);
        self.conditional_error |= child.conditional_error;
        self.content_policy.merge_child(&child.content_policy);
        self.options.merge_child(&child.options);
        self.override_policy.merge_child(&child.override_policy);
        self.authorization.merge_child(&child.authorization);
        self.mapping_policy.merge_child(&child.mapping_policy);
        self.error_policy.merge_child(&child.error_policy);
        if !self.header_policy.merge_child(&child.header_policy) {
            self.conditional_error = true;
        }
        self.environment_policy
            .merge_child(&child.environment_policy);
        self.rewrite_policy
            .merge_child_with_rules(&child.rewrite_policy, rewrite_rules);
        self.compression_policy
            .merge_child(&child.compression_policy);
        self.proxy_policy.merge_child(&child.proxy_policy);
        // Pending conditions are parser-local and must never leak from one
        // scope into the next.
        #[cfg(debug_assertions)]
        debug_assert_eq!(
            self.container_snapshot(),
            Scope::merge_container_snapshots(&audit_parent, &audit_child),
            "Scope::merge container-field audit failed"
        );
    }

    /// Restrict `self` (a canonical-target or rewritten-target scope) with the
    /// policy of the URL identity the client actually requested.  This is a
    /// meet, never a replacement: a resolved target may add restrictions but
    /// may not grant an `Options` bit, handler or `AllowOverride` category the
    /// URL scope denies.  Authorization is checked separately before and after
    /// resolution, so both grants remain required (F60/I61).
    pub fn restrict_with(&mut self, base: &Scope) {
        self.restrict_policy_with(base);
        self.mapping_policy.handlers =
            conjoined_handlers(&base.mapping_policy.handlers, &self.mapping_policy.handlers);
        // F64/I62: `SetHandler` forces conjoin like the extension table.  A
        // name forced by both identities must agree; a disagreement degrades
        // to "no forced handler" (fail closed: the conjoined extension table
        // below still limits what can execute).  A force from one identity
        // alone, or agreement on the same name, is kept.
        //
        // F60/I61: an explicit `SetHandler none` on the URL identity is a
        // handler denial.  The resolved target must not re-arm an extension
        // handler the lexical identity unforced, so the denial survives the
        // conjoin as a `none` force (the request serves static content).
        let (url_denied, url_forced, url_name) = match &base.mapping_policy.set_handler {
            Some(SetHandler::Name(name)) => (false, true, name.clone()),
            Some(SetHandler::None_) => (true, false, String::new()),
            None => (false, false, String::new()),
        };
        let (target_forced, target_name) = match &self.mapping_policy.set_handler {
            Some(SetHandler::Name(name)) => (true, name.clone()),
            Some(SetHandler::None_) | None => (false, String::new()),
        };
        let same_name = url_name.eq_ignore_ascii_case(&target_name);
        self.mapping_policy.set_handler = match vapache_verified::set_handler_conjoin_admit(
            url_denied,
            url_forced,
            target_forced,
            same_name,
        ) {
            1 => {
                // A surviving force keeps whichever side actually forced; an
                // explicit URL-side `SetHandler none` is materialized as a
                // `none` force.
                if url_denied {
                    Some(SetHandler::Name("none".into()))
                } else if url_forced {
                    Some(SetHandler::Name(url_name))
                } else if target_forced {
                    Some(SetHandler::Name(target_name))
                } else {
                    // Verified result 1 implies at least one of the three
                    // preceding predicates; this arm is defensive only.
                    Some(SetHandler::None_) // coverage:ignore-line
                }
            }
            // Conflict: no forced handler; the conjoined extension table
            // still governs `AddHandler`-style execution.
            _ => Some(SetHandler::None_),
        };
    }

    /// Conjoin execution/list/override/header policy without touching the
    /// handler map.  Used when a rewrite legitimately changes the filename
    /// extension, so the original URL's handler map is not the handler map of
    /// the selected target.
    pub fn restrict_policy_with(&mut self, base: &Scope) {
        self.conditional_error |= base.conditional_error;
        let url_options = base.options.effective_bits(Options::FOLLOW_SYMLINKS);
        let target_options = self.options.effective_bits(Options::FOLLOW_SYMLINKS);
        let conjoined = vapache_verified::options_conjoin(url_options, target_options);
        self.options = crate::scope_policy::OptionsPolicy::default();
        self.options.push_set(conjoined);

        self.override_policy = self.override_policy.conjoined_with(&base.override_policy);

        // The selected target and the client-visible URL are both policy
        // identities.  Keep target content/environment effects, then apply
        // the URL identity last just as a lexical child scope would apply:
        // scalar content decisions and duplicate environment values cannot
        // silently discard the policy attached to the requested URL, while
        // RemoveType/UnsetEnv from either side remain effective.
        self.content_policy.merge_child(&base.content_policy);
        self.environment_policy
            .merge_child(&base.environment_policy);

        // Preserve lexical response-header policy while still allowing the
        // target to add its own restrictions.  Unsets from either identity are
        // retained; target sets override lexical values only when the lexical
        // scope did not explicitly unset the header.
        let mut headers = base.header_policy.clone();
        if !headers.merge_child(&self.header_policy) {
            self.conditional_error = true;
        }
        self.header_policy = headers;

        for filter in &base.mapping_policy.unsupported_filters {
            if !self
                .mapping_policy
                .unsupported_filters
                .iter()
                .any(|f| f.eq_ignore_ascii_case(filter))
            {
                self.mapping_policy.unsupported_filters.push(filter.clone());
            }
        }
        for rule in &base.compression_policy.unsupported_filter_rules {
            if !self
                .compression_policy
                .unsupported_filter_rules
                .contains(rule)
            {
                self.compression_policy
                    .unsupported_filter_rules
                    .push(rule.clone());
            }
        }
    }

    pub fn effective_options(&self) -> Options {
        // Apache's compiled-in default for a directory with no Options
        // directive is FollowSymLinks.
        Options(self.options.effective_bits(Options::FOLLOW_SYMLINKS))
    }
}

#[derive(Debug, Clone)]
pub enum MatchKind {
    Always,
    Directory(PathBuf),
    DirectoryMatch(Regex),
    Files(Regex),
    /// `<Files shell-pattern>`: full-match the basename with the verified
    /// fnmatch kernel (F61/F62 — classes honor both `!` and `^` negation).
    FilesGlob(String),
    FilesMatch(Regex),
    /// `<Location literal-url>`: Apache's literal prefix semantics with the
    /// trailing `/` boundary.
    Location(String),
    /// `<Location shell-pattern>` containing a wildcard: compiled to the
    /// stack-safe fnmatch evaluator in path mode at parse time (F61-A/A2/B).
    LocationGlob(String),
    LocationMatch(Regex),
}

/// Canonical merge phase for a compiled rule.  This is the ordering the
/// dispatcher and `.htaccess` walker implement; it is also the ordering a
/// formal model should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RulePhase {
    Directory,
    Files,
    Location,
    Condition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionBranch {
    /// `<If>` / `<IfFile>`, or an ordinary directive rule.
    Normal,
    /// `<ElseIf>`: applies when this expression matches and the preceding
    /// branch of the chain did not.
    ElseIf,
    /// `<Else>`: applies when no preceding branch of the chain matched.
    Else,
}

#[derive(Debug, Clone)]
pub struct ScopeRule {
    pub kind: MatchKind,
    pub delta: Scope,
    pub order: usize,
    pub condition: Option<crate::expr::Expr>,
    pub branch: ConditionBranch,
    /// Identifies the `<If>/<ElseIf>/<Else>` chain this rule belongs to.
    pub chain: Option<usize>,
    /// Rules nested inside the enclosing container (`<If>`, `<Directory>`,
    /// `<Files>`, ...).  They only apply when the parent rule matches.
    pub nested: Vec<ScopeRule>,
}

impl ScopeRule {
    pub fn phase(&self) -> RulePhase {
        match vapache_verified::config_rule_phase(
            verified_config_rule_kind(&self.kind),
            rule_is_conditional(self),
        ) {
            vapache_verified::ConfigRulePhase::Directory => RulePhase::Directory,
            vapache_verified::ConfigRulePhase::Files => RulePhase::Files,
            vapache_verified::ConfigRulePhase::Location => RulePhase::Location,
            vapache_verified::ConfigRulePhase::Condition => RulePhase::Condition,
        }
    }
}

fn verified_config_rule_kind(kind: &MatchKind) -> vapache_verified::ConfigRuleKind {
    match kind {
        MatchKind::Always => vapache_verified::ConfigRuleKind::Always,
        MatchKind::Directory(_) => vapache_verified::ConfigRuleKind::Directory,
        MatchKind::DirectoryMatch(_) => vapache_verified::ConfigRuleKind::DirectoryMatch,
        MatchKind::Files(_) | MatchKind::FilesGlob(_) | MatchKind::FilesMatch(_) => {
            vapache_verified::ConfigRuleKind::Files
        }
        MatchKind::Location(_) | MatchKind::LocationGlob(_) => {
            vapache_verified::ConfigRuleKind::Location
        }
        MatchKind::LocationMatch(_) => vapache_verified::ConfigRuleKind::LocationMatch,
    }
}

fn rule_is_conditional(rule: &ScopeRule) -> bool {
    rule.condition.is_some() || rule.branch != ConditionBranch::Normal
}

fn defer_rule_by_verified_phase(
    rule: &ScopeRule,
    files: &mut Vec<ScopeRule>,
    locations: &mut Vec<ScopeRule>,
    conditionals: &mut Vec<ScopeRule>,
) {
    match vapache_verified::config_deferred_slot(
        verified_config_rule_kind(&rule.kind),
        rule_is_conditional(rule),
    ) {
        vapache_verified::ConfigDeferredSlot::Files => files.push(rule.clone()),
        vapache_verified::ConfigDeferredSlot::Location => locations.push(rule.clone()),
        vapache_verified::ConfigDeferredSlot::Condition => conditionals.push(rule.clone()),
        vapache_verified::ConfigDeferredSlot::Ignore => {}
    }
}

#[derive(Debug, Clone)]
pub enum ProxyMatchKind {
    /// `<Proxy wildcard-url>`: prefix match unless wildcard characters are
    /// present, in which case shell-style glob matching is used.
    Wildcard(String),
    /// `<ProxyMatch regex>`
    Regex(Regex),
}

#[derive(Debug, Clone)]
pub struct ProxyContainer {
    pub kind: ProxyMatchKind,
    pub delta: Scope,
    /// Conditional rules nested inside the container (currently `<If>`).
    pub rules: Vec<ScopeRule>,
    pub order: usize,
}

#[derive(Debug, Clone)]
pub struct CustomLog {
    pub path: String,
    pub format: String,
    pub condition: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VHost {
    pub addrs: Vec<String>,
    pub ports: Vec<u16>,
    pub server_name: Option<String>,
    pub aliases: Vec<String>,
    pub scope: Scope,
    pub delta: Scope,
    pub rules: Vec<ScopeRule>,
    pub directory_index: DirectoryRuleIndex,
    pub proxy_containers: Vec<ProxyContainer>,
    pub custom_logs: Vec<CustomLog>,
    pub error_log: Option<String>,
    pub server_admin: Option<String>,
    pub protocols: Vec<HttpProtocol>,
    pub ssl: SslConfig,
}

impl VHost {
    pub fn matches_name(&self, host: &str) -> bool {
        fn without_port(name: &str) -> &str {
            name.split(':').next().unwrap_or(name)
        }

        let host = host.trim_end_matches('.');
        if self
            .server_name
            .as_ref()
            .is_some_and(|name| host.eq_ignore_ascii_case(without_port(name).trim_end_matches('.')))
        {
            return true;
        }
        self.aliases.iter().any(|alias| {
            crate::verified::host_pattern_matches(
                host.as_bytes(),
                without_port(alias).trim_end_matches('.').as_bytes(),
            )
        })
    }

    pub fn has_wildcard_default(&self) -> bool {
        self.addrs
            .iter()
            .any(|a| a.starts_with("_default_") || a.starts_with('*') || a.is_empty())
    }
}

const MAX_VHOST_WILDCARD_PATTERNS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum VHostAddressKey {
    NoAddress,
    Wildcard,
    Exact(IpAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct VHostBucketKey {
    address: VHostAddressKey,
    port: u16,
}

#[derive(Debug, Clone, Default)]
struct VHostBucket {
    candidates: Vec<usize>,
    exact_names: HashMap<String, usize>,
    wildcard_names: Vec<(usize, String)>,
}

impl VHostBucket {
    fn build(vhosts: &[VHost], candidates: Vec<usize>) -> Self {
        let mut exact_names = HashMap::new();
        let mut wildcard_names = Vec::new();
        for index in &candidates {
            let vhost = &vhosts[*index];
            if let Some(name) = &vhost.server_name {
                exact_names.entry(vhost_name_key(name)).or_insert(*index);
            }
            for alias in &vhost.aliases {
                if alias.bytes().any(|byte| matches!(byte, b'*' | b'?')) {
                    wildcard_names.push((*index, vhost_name_key(alias)));
                } else {
                    exact_names.entry(vhost_name_key(alias)).or_insert(*index);
                }
            }
        }
        Self {
            candidates,
            exact_names,
            wildcard_names,
        }
    }

    fn select(&self, vhosts: &[VHost], host: Option<&str>) -> Option<usize> {
        let default = *self.candidates.first()?;
        let Some(host) = host else {
            return Some(default);
        };
        let bare = authority_host(host).trim_end_matches('.');
        let key = bare.to_ascii_lowercase();
        let mut selected = self.exact_names.get(&key).copied();
        for (index, pattern) in &self.wildcard_names {
            if !vapache_verified::vhost_name_candidate_precedes(selected, *index) {
                continue;
            }
            if crate::verified::host_pattern_matches(bare.as_bytes(), pattern.as_bytes()) {
                selected = Some(*index);
            }
        }
        selected
            .or(Some(default))
            .filter(|index| *index < vhosts.len())
    }
}

fn vhost_name_key(name: &str) -> String {
    name.split(':')
        .next()
        .unwrap_or(name)
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

#[derive(Debug, Clone, Default)]
struct VHostIndex {
    buckets: HashMap<VHostBucketKey, VHostBucket>,
}

impl VHostIndex {
    fn build(vhosts: &[VHost], listeners: &[ListenSpec]) -> Self {
        let mut ports = HashSet::new();
        let mut exact_addresses = HashSet::new();
        for listener in listeners {
            ports.insert(listener.port);
            if let Ok(ip) = listener.addr.parse::<IpAddr>() {
                let ip = crate::access::canonical_ip(ip);
                if !ip.is_unspecified() {
                    exact_addresses.insert(ip);
                }
            }
        }
        for vhost in vhosts {
            for port in &vhost.ports {
                if *port != 0 {
                    ports.insert(*port);
                }
            }
            for address in &vhost.addrs {
                if !Config::vhost_address_is_wildcard(address) {
                    if let Ok(ip) = Config::vhost_address_text(address).parse::<IpAddr>() {
                        exact_addresses.insert(crate::access::canonical_ip(ip));
                    }
                }
            }
        }
        let mut buckets = HashMap::new();
        for port in ports {
            let no_address: Vec<_> = vhosts
                .iter()
                .enumerate()
                .filter(|(_, vhost)| {
                    vhost.addrs.is_empty() || Config::vhost_port_matches(vhost, port)
                })
                .map(|(index, _)| index)
                .collect();
            if !no_address.is_empty() {
                buckets.insert(
                    VHostBucketKey {
                        address: VHostAddressKey::NoAddress,
                        port,
                    },
                    VHostBucket::build(vhosts, no_address),
                );
            }
            let wildcard: Vec<_> = vhosts
                .iter()
                .enumerate()
                .filter(|(_, vhost)| {
                    vhost.addrs.is_empty()
                        || vhost.addrs.iter().any(|address| {
                            (vhost_port(address) == 0 || vhost_port(address) == port)
                                && Config::vhost_address_is_wildcard(address)
                        })
                })
                .map(|(index, _)| index)
                .collect();
            if !wildcard.is_empty() {
                buckets.insert(
                    VHostBucketKey {
                        address: VHostAddressKey::Wildcard,
                        port,
                    },
                    VHostBucket::build(vhosts, wildcard),
                );
            }
            for address in &exact_addresses {
                let exact: Vec<_> = vhosts
                    .iter()
                    .enumerate()
                    .filter(|(_, vhost)| Config::vhost_address_is_specific(vhost, *address, port))
                    .map(|(index, _)| index)
                    .collect();
                if !exact.is_empty() {
                    buckets.insert(
                        VHostBucketKey {
                            address: VHostAddressKey::Exact(*address),
                            port,
                        },
                        VHostBucket::build(vhosts, exact),
                    );
                }
            }
        }
        Self { buckets }
    }
}

#[derive(Debug, Clone)]
pub struct MimeMap {
    pub types: HashMap<String, String>,
    pub encodings: HashMap<String, String>,
}

impl MimeMap {
    pub fn new() -> Self {
        MimeMap {
            types: HashMap::new(),
            encodings: HashMap::new(),
        }
    }

    pub fn load_types_file(&mut self, path: &Path) -> Result<(), String> {
        self.load_types_file_with_trust(path, crate::files::AdminFileTrust::for_current_process())
    }

    fn load_types_file_with_trust(
        &mut self,
        path: &Path,
        trust: crate::files::AdminFileTrust,
    ) -> Result<(), String> {
        if !vapache_verified::text_identity_admit(path.to_str().is_some()) {
            return Err("TypesConfig path is not valid UTF-8".into());
        }
        let data = crate::files::read_admin_file_with_trust(path, MAX_TYPES_CONFIG_BYTES, trust)
            .map_err(|e| format!("cannot read TypesConfig {}: {e}", path.display()))?;
        let text = std::str::from_utf8(&data)
            .map_err(|_| format!("TypesConfig {} is not valid UTF-8", path.display()))?;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let fields: Vec<&str> = line.split_ascii_whitespace().collect();
            if fields.len() < 2 {
                continue;
            }
            let ty = fields[0].to_string();
            for ext in &fields[1..] {
                let e = ext.trim_start_matches('.').to_ascii_lowercase();
                if !e.is_empty() {
                    self.types.insert(e, ty.clone());
                }
            }
        }
        Ok(())
    }

    pub fn add_type(&mut self, ty: &str, exts: &[String]) {
        for e in exts {
            let e = e.trim_start_matches('.').to_ascii_lowercase();
            if !e.is_empty() {
                self.types.insert(e, ty.to_string());
            }
        }
    }

    pub fn remove_type(&mut self, exts: &[String]) {
        for e in exts {
            self.types
                .remove(&e.trim_start_matches('.').to_ascii_lowercase());
        }
    }

    /// Look up one dot-separated extension without allocating for the common
    /// short-ASCII case.  `mod_mime` keys are ASCII and lowercase.
    fn lookup_type(&self, ext: &[u8]) -> Option<&str> {
        if ext.len() <= 64 {
            let mut buf = [0u8; 64];
            for (i, b) in ext.iter().enumerate() {
                buf[i] = b.to_ascii_lowercase();
            }
            let key = std::str::from_utf8(&buf[..ext.len()]).ok()?;
            self.types.get(key).map(|t| t.as_str())
        } else {
            let key = std::str::from_utf8(ext).ok()?.to_ascii_lowercase();
            self.types.get(&key).map(|t| t.as_str())
        }
    }

    pub fn content_type(&self, name: &[u8]) -> Option<String> {
        let base = name.rsplit(|b| *b == b'/').next().unwrap_or(name);
        let mut best: Option<(usize, &str)> = None;
        // Longest matching extension wins, as in mod_mime.  Walk the
        // dot-separated suffixes without collecting them into a Vec.
        let mut parts = base.split(|b| *b == b'.');
        parts.next();
        for part in parts {
            if part.is_empty() {
                continue;
            }
            if let Some(t) = self.lookup_type(part) {
                if best.map(|(l, _)| part.len() > l).unwrap_or(true) {
                    best = Some((part.len(), t));
                }
            }
        }
        // Apache does not invent a media type for unknown extensions or for
        // extensionless files; the response simply has no Content-Type.
        best.map(|(_, t)| t.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ListenSpec {
    pub raw: String,
    pub addr: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientVerify {
    None,
    Optional,
    Require,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRevocationCheck {
    None,
    Leaf,
    Chain,
}

/// Application protocols offered by a TLS listener through ALPN. Keep this
/// separate from `SslConfig::protocols`, which models `SSLProtocol` and thus
/// selects TLS versions rather than HTTP versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpProtocol {
    Http2,
    Http11,
}

impl HttpProtocol {
    pub(crate) fn alpn(self) -> &'static [u8] {
        match self {
            Self::Http2 => b"h2",
            Self::Http11 => b"http/1.1",
        }
    }
}

pub(crate) fn parse_http_protocols(args: &[String]) -> Result<Vec<HttpProtocol>, String> {
    if args.is_empty() {
        return Err("Protocols requires at least one protocol".into());
    }
    let mut protocols = Vec::with_capacity(args.len());
    for raw in args {
        let protocol = if raw.eq_ignore_ascii_case("h2") {
            HttpProtocol::Http2
        } else if raw.eq_ignore_ascii_case("http/1.1") {
            HttpProtocol::Http11
        } else if raw.eq_ignore_ascii_case("h2c") {
            return Err("Protocols h2c is unsupported; cleartext HTTP/2 is not implemented".into());
        } else {
            return Err(format!("unsupported Protocols token '{raw}'"));
        };
        if !protocols.contains(&protocol) {
            protocols.push(protocol);
        }
    }
    Ok(protocols)
}

/// Modern Linux distributions keep `/var/run` as a compatibility symlink to
/// `/run`. Privileged output creation intentionally refuses parent symlinks,
/// so normalize Apache's conventional PID location before it reaches that
/// boundary instead of weakening the boundary itself.
fn normalize_pid_path(path: PathBuf) -> PathBuf {
    if let Ok(relative) = path.strip_prefix("/var/run") {
        Path::new("/run").join(relative)
    } else {
        path
    }
}

#[derive(Debug, Clone, Default)]
pub struct SslConfig {
    pub engine: bool,
    // Distinguishes the default (inherit from the enclosing scope) from an
    // explicit `SSLEngine off` in a virtual host.
    pub engine_set: bool,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub chain_file: Option<PathBuf>,
    pub protocols: Option<String>,
    pub cipher_suite: Option<String>,
    pub honor_cipher_order: Option<bool>,
    pub session_cache: Option<bool>,
    pub session_cache_timeout: Option<Duration>,
    pub session_tickets: Option<bool>,
    pub verify_client: Option<ClientVerify>,
    pub ca_file: Option<PathBuf>,
    pub ca_revocation_file: Option<PathBuf>,
    pub ca_revocation_check: Option<ClientRevocationCheck>,
    pub stapling: bool,
    pub stapling_set: bool,
    pub stapling_force_url: Option<String>,
    pub stapling_responder_timeout: Duration,
    pub stapling_standard_cache_timeout: Duration,
    pub stapling_return_responder_errors: bool,
}

impl SslConfig {
    fn inherit(&mut self, parent: &SslConfig) {
        if !self.engine_set {
            self.engine = parent.engine;
            self.engine_set = parent.engine_set;
        }
        if self.cert_file.is_none() {
            self.cert_file = parent.cert_file.clone();
        }
        if self.key_file.is_none() {
            self.key_file = parent.key_file.clone();
        }
        if self.chain_file.is_none() {
            self.chain_file = parent.chain_file.clone();
        }
        if self.protocols.is_none() {
            self.protocols = parent.protocols.clone();
        }
        if self.cipher_suite.is_none() {
            self.cipher_suite = parent.cipher_suite.clone();
        }
        if self.honor_cipher_order.is_none() {
            self.honor_cipher_order = parent.honor_cipher_order;
        }
        if self.session_cache.is_none() {
            self.session_cache = parent.session_cache;
        }
        if self.session_cache_timeout.is_none() {
            self.session_cache_timeout = parent.session_cache_timeout;
        }
        if self.session_tickets.is_none() {
            self.session_tickets = parent.session_tickets;
        }
        if self.verify_client.is_none() {
            self.verify_client = parent.verify_client;
        }
        if self.ca_file.is_none() {
            self.ca_file = parent.ca_file.clone();
        }
        if self.ca_revocation_file.is_none() {
            self.ca_revocation_file = parent.ca_revocation_file.clone();
        }
        if self.ca_revocation_check.is_none() {
            self.ca_revocation_check = parent.ca_revocation_check;
        }
        if !self.stapling_set {
            self.stapling = parent.stapling;
            self.stapling_set = parent.stapling_set;
        }
        if self.stapling_force_url.is_none() {
            self.stapling_force_url = parent.stapling_force_url.clone();
        }
        if self.stapling_responder_timeout == Duration::default() {
            self.stapling_responder_timeout = parent.stapling_responder_timeout;
        }
        if self.stapling_standard_cache_timeout == Duration::default() {
            self.stapling_standard_cache_timeout = parent.stapling_standard_cache_timeout;
        }
        self.stapling_return_responder_errors |= parent.stapling_return_responder_errors;
    }
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub root: Option<PathBuf>,
    pub default_expire: u64,
    pub max_expire: u64,
    pub min_expire: u64,
    pub max_file_size: u64,
    pub min_file_size: u64,
    /// Total bytes persisted under `CacheRoot`.  The on-disk cache is
    /// independently bounded from the in-memory entry map so unique query
    /// strings cannot fill the filesystem (F44).
    pub max_disk_size: u64,
    /// Total estimated resident bytes retained by the process-wide cache.
    /// Zero disables the memory tier while leaving the bounded disk cache on.
    pub max_memory_size: u64,
    pub ignore_no_last_mod: bool,
    pub ignore_cache_control: bool,
    pub store_no_store: bool,
    pub store_private: bool,
    pub ignore_query_string: bool,
    pub header: bool,
    pub detail_header: bool,
    pub last_modified_factor: f64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            root: None,
            default_expire: 3600,
            max_expire: 86_400,
            min_expire: 0,
            max_file_size: 1024 * 1024,
            min_file_size: 0,
            max_disk_size: 64 * 1024 * 1024,
            max_memory_size: 64 * 1024 * 1024,
            ignore_no_last_mod: false,
            ignore_cache_control: false,
            store_no_store: false,
            store_private: false,
            ignore_query_string: false,
            header: false,
            detail_header: false,
            last_modified_factor: 0.1,
        }
    }
}

#[derive(Debug, Clone)]
struct CachedPolicy {
    scope: Scope,
    conditionals: Arc<Vec<ScopeRule>>,
}

type PolicyCacheKey = (usize, PathBuf, String);
const POLICY_CACHE_MAX_ENTRIES: usize = 256;
const POLICY_CACHE_MAX_BYTES: usize = 32 * 1024 * 1024;
const POLICY_CACHE_VALUE_CHARGE: usize = 128 * 1024;

#[derive(Debug)]
struct BoundedPolicyCache<V> {
    entries: HashMap<PolicyCacheKey, (Arc<V>, usize)>,
    bytes: usize,
}

impl<V> Default for BoundedPolicyCache<V> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            bytes: 0,
        }
    }
}

impl<V> BoundedPolicyCache<V> {
    fn weight(key: &PolicyCacheKey) -> usize {
        key.1
            .as_os_str()
            .as_bytes()
            .len()
            .saturating_add(key.2.len())
            // Scope merges own several policy vectors. Their exact allocator
            // footprint is not observable here, so reserve a deliberately
            // conservative charge and independently cap the entry count.
            .saturating_add(POLICY_CACHE_VALUE_CHARGE)
    }

    fn get(&self, key: &PolicyCacheKey) -> Option<Arc<V>> {
        self.entries.get(key).map(|(value, _)| Arc::clone(value))
    }

    fn insert(&mut self, key: PolicyCacheKey, value: Arc<V>) {
        let weight = Self::weight(&key);
        if weight > POLICY_CACHE_MAX_BYTES {
            return;
        }
        if let Some((_, old_weight)) = self.entries.remove(&key) {
            self.bytes = self.bytes.saturating_sub(old_weight);
        }
        while self.entries.len() >= POLICY_CACHE_MAX_ENTRIES
            || self.bytes.saturating_add(weight) > POLICY_CACHE_MAX_BYTES
        {
            let Some(victim) = self.entries.keys().next().cloned() else {
                break;
            };
            if let Some((_, old_weight)) = self.entries.remove(&victim) {
                self.bytes = self.bytes.saturating_sub(old_weight);
            }
        }
        self.bytes = self.bytes.saturating_add(weight);
        self.entries.insert(key, (value, weight));
    }
}

/// One `mod_remoteip` trust entry. Apache gives internal proxies permission
/// to present private addresses; an external trusted proxy may only present a
/// public address. Keeping the class on each entry is security-significant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteIpProxy {
    pub network: IpAddr,
    pub bits: u8,
    pub internal: bool,
}

/// Exact transport identity covered by a FastCGI stability policy.  A policy
/// cannot silently migrate from one PHP-FPM pool to another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastCgiEndpoint {
    Unix(PathBuf),
    Tcp { host: String, port: u16 },
}

/// Local filesystem stability contract for one exact FastCGI backend.
/// `backend_uid` is the worker identity that must be unable to mutate the
/// script path. `endpoint_owner_uid` independently authenticates a Unix socket
/// pathname. Strict policies reject TCP because it cannot authenticate the
/// backend process; the TCP enum variant remains the routing endpoint identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastCgiStablePathPolicy {
    pub endpoint: FastCgiEndpoint,
    pub backend_uid: u32,
    pub endpoint_owner_uid: Option<u32>,
    pub trusted_owner_uids: Vec<u32>,
}

/// Individually reviewable gates for compatibility features that materially
/// expand the request parser, filesystem walk, generated-content, or code
/// execution surface. Every capability is off unless the global server
/// configuration explicitly enables it with `VapacheCapability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    AbsoluteRequestTarget,
    AccessFiles,
    AutoIndex,
    Cgi,
    FastCgi,
    LegacyAuthz,
    MutableAuthFiles,
    RequestTrailers,
    RewriteProgram,
    ServerStatus,
    Trace,
    UnstableFastCgiPaths,
}

impl Capability {
    pub const ALL: [Self; 12] = [
        Self::AbsoluteRequestTarget,
        Self::AccessFiles,
        Self::AutoIndex,
        Self::Cgi,
        Self::FastCgi,
        Self::LegacyAuthz,
        Self::MutableAuthFiles,
        Self::RequestTrailers,
        Self::RewriteProgram,
        Self::ServerStatus,
        Self::Trace,
        Self::UnstableFastCgiPaths,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::AbsoluteRequestTarget => "AbsoluteRequestTarget",
            Self::AccessFiles => "AccessFiles",
            Self::AutoIndex => "AutoIndex",
            Self::Cgi => "Cgi",
            Self::FastCgi => "FastCgi",
            Self::LegacyAuthz => "LegacyAuthz",
            Self::MutableAuthFiles => "MutableAuthFiles",
            Self::RequestTrailers => "RequestTrailers",
            Self::RewriteProgram => "RewriteProgram",
            Self::ServerStatus => "ServerStatus",
            Self::Trace => "Trace",
            Self::UnstableFastCgiPaths => "UnstableFastCgiPaths",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|capability| capability.name().eq_ignore_ascii_case(value))
    }

    const fn bit(self) -> u64 {
        1u64 << self as u8
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities(u64);

#[cfg(test)]
pub(crate) const TEST_CAPABILITIES: &str = "\
VapacheCapability AbsoluteRequestTarget On\n\
VapacheCapability AccessFiles On\n\
VapacheCapability AutoIndex On\n\
VapacheCapability Cgi On\n\
VapacheCapability FastCgi On\n\
VapacheCapability LegacyAuthz On\n\
VapacheCapability MutableAuthFiles On\n\
VapacheCapability RequestTrailers On\n\
VapacheCapability RewriteProgram On\n\
VapacheCapability ServerStatus On\n\
VapacheCapability Trace On\n\
VapacheCapability UnstableFastCgiPaths On\n";

impl Capabilities {
    pub fn contains(self, capability: Capability) -> bool {
        self.0 & capability.bit() != 0
    }

    pub(crate) fn set(&mut self, capability: Capability, enabled: bool) {
        if enabled {
            self.0 |= capability.bit();
        } else {
            self.0 &= !capability.bit();
        }
    }

    pub fn enabled_names(self) -> Vec<&'static str> {
        Capability::ALL
            .into_iter()
            .filter(|capability| self.contains(*capability))
            .map(Capability::name)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub server_root: PathBuf,
    pub server_name: Option<String>,
    pub server_admin: String,
    pub listeners: Vec<ListenSpec>,
    pub user: String,
    pub group: String,
    pub pid_file: PathBuf,
    pub error_log: String,
    pub log_level: String,
    pub keep_alive: bool,
    pub keep_alive_timeout: Duration,
    pub timeout: Duration,
    pub max_keep_alive_requests: usize,
    pub server_tokens: ServerTokens,
    pub server_signature: ServerSignature,
    pub protocols: Vec<HttpProtocol>,
    pub trace_enable: bool,
    pub capabilities: Capabilities,
    /// Capabilities required by effectful directives in the loaded main
    /// configuration. Used by the migration audit; access-file contents are
    /// deliberately not inferred or auto-enabled.
    pub required_capabilities: Vec<Capability>,
    /// Audit-mode configurations are report artifacts, not runnable server
    /// configurations. This prevents deliberately suppressed capability
    /// errors from becoming an execution path through the public loader.
    pub(crate) capability_audit_only: bool,
    pub limit_request_line: usize,
    pub limit_request_fields: usize,
    pub limit_request_field_size: usize,
    pub limit_request_body: u64,
    pub max_request_workers: usize,
    pub listen_backlog: i32,
    pub graceful_shutdown_timeout: Duration,
    pub request_header_timeout: Duration,
    pub request_body_timeout: Duration,
    pub request_header_min_rate: u64,
    pub request_body_min_rate: u64,
    pub encoded_slashes: EncodedSlashes,
    pub vhosts: Vec<VHost>,
    vhost_index: Arc<VHostIndex>,
    pub global: Scope,
    pub global_rules: Vec<ScopeRule>,
    pub global_directory_index: DirectoryRuleIndex,
    pub proxy_containers: Vec<ProxyContainer>,
    pub mime: MimeMap,
    pub log_formats: HashMap<String, String>,
    pub custom_logs: Vec<CustomLog>,
    pub modules: Vec<String>,
    /// Final global `Define` set, used by execute-on-read sections in
    /// request-parsed access files.
    pub config_defines: HashSet<String>,
    pub warnings: Vec<String>,
    pub balancers: Vec<Balancer>,
    pub health_templates: HashMap<String, HealthTemplate>,
    pub remoteip_header: Option<String>,
    pub remoteip_proxies: Vec<RemoteIpProxy>,
    /// `None` is explicitly off. `Some` is strict: every FastCGI target must
    /// match exactly one registered endpoint policy.
    pub fastcgi_stable_paths: Option<Vec<FastCgiStablePathPolicy>>,
    pub max_spool_bytes: u64,
    pub max_spool_files: u64,
    pub max_dynamic_requests: u64,
    pub max_fastcgi_output: u64,
    pub resource_budget: Arc<crate::resource::ResourceBudget>,
    pub access_file_names: Vec<String>,
    pub directory_index: Vec<String>,
    /// True when any compiled scope enables `AllowOverride All`.  This lets
    /// the request path skip all `.htaccess` filesystem work in the common
    /// case where overrides are disabled.
    pub override_enabled: bool,
    /// Directory prefixes whose effective `AllowOverride` is enabled.  Used to
    /// avoid even the existence check for `.htaccess` when a request cannot be
    /// inside an override-enabled directory.
    pub override_prefixes: Vec<PathBuf>,
    /// Set when an override-enabled section cannot be represented as a simple
    /// path prefix (for example `<DirectoryMatch>` or a global/vhost scope).
    pub override_anywhere: bool,
    /// Conservative startup-compiled proof bit used before body ingestion.
    /// False means no configured route can consume request body bytes.
    pub(crate) body_handlers_possible: bool,
    /// Conservative startup-compiled bit for CGI/PATH_INFO dispatch.  False
    /// means a missing static path must not trigger any script-prefix probes.
    pub(crate) cgi_path_info_possible: bool,
    pub document_root: PathBuf,
    pub default_charset: Option<String>,
    pub use_canonical_name: bool,
    pub hostname_lookups: bool,
    pub server_software: String,
    pub ssl: SslConfig,
    pub cache: CacheConfig,
    /// Trust captured before privilege drop and retained by every reload.
    admin_file_trust: crate::files::AdminFileTrust,
    /// File-shaped targets whose parent chain must remain outside the service
    /// account's control. Include globs and directories are represented by a
    /// synthetic child so an empty directory is still checked.
    admin_input_targets: Vec<PathBuf>,
    /// Main-configuration password/group databases validated before serving.
    /// Access-file declarations are checked on every runtime read instead.
    auth_file_targets: Vec<PathBuf>,
    policy_cache: Arc<RwLock<BoundedPolicyCache<CachedPolicy>>>,
    dir_scope_cache: Arc<RwLock<BoundedPolicyCache<Scope>>>,
}

impl Config {
    pub(crate) fn body_handlers_possible(&self) -> bool {
        self.body_handlers_possible
    }

    fn compute_body_handlers_possible(&self) -> bool {
        fn scope_may_consume(scope: &Scope) -> bool {
            scope
                .mapping_policy
                .aliases
                .iter()
                .any(|alias| alias.script)
                || scope
                    .mapping_policy
                    .handlers
                    .iter()
                    .any(|handler| !handler.remove)
                || scope
                    .mapping_policy
                    .set_handler
                    .as_ref()
                    .and_then(SetHandler::name)
                    .is_some()
                || !scope.proxy_policy.proxy_passes.is_empty()
                || !scope.proxy_policy.proxy_rules.is_empty()
                || scope
                    .rewrite_policy
                    .rewrite_rules
                    .iter()
                    .any(|rule| rule.flags.proxy || rule.flags.handler.is_some())
        }
        fn rules_may_consume(rules: &[ScopeRule]) -> bool {
            let mut pending: Vec<&ScopeRule> = rules.iter().rev().collect();
            while let Some(rule) = pending.pop() {
                if scope_may_consume(&rule.delta) {
                    return true;
                }
                pending.extend(rule.nested.iter().rev());
            }
            false
        }
        self.override_enabled
            || scope_may_consume(&self.global)
            || rules_may_consume(&self.global_rules)
            || self.vhosts.iter().any(|vhost| {
                scope_may_consume(&vhost.scope)
                    || scope_may_consume(&vhost.delta)
                    || rules_may_consume(&vhost.rules)
            })
    }

    fn compute_cgi_path_info_possible(&self) -> bool {
        if !self.capability_enabled(Capability::Cgi) {
            return false;
        }
        fn scope_may_dispatch_cgi(scope: &Scope) -> bool {
            scope
                .mapping_policy
                .aliases
                .iter()
                .any(|alias| alias.script)
                || scope.effective_options().contains(Options::EXEC_CGI)
                || scope.mapping_policy.handlers.iter().any(|handler| {
                    !handler.remove && handler.handler.eq_ignore_ascii_case("cgi-script")
                })
                || scope
                    .mapping_policy
                    .set_handler
                    .as_ref()
                    .and_then(SetHandler::name)
                    .is_some_and(|handler| handler.eq_ignore_ascii_case("cgi-script"))
                || scope.rewrite_policy.rewrite_rules.iter().any(|rule| {
                    rule.flags
                        .handler
                        .as_deref()
                        .is_some_and(|handler| handler.eq_ignore_ascii_case("cgi-script"))
                })
        }
        fn rules_may_dispatch_cgi(rules: &[ScopeRule]) -> bool {
            let mut pending: Vec<&ScopeRule> = rules.iter().rev().collect();
            while let Some(rule) = pending.pop() {
                if scope_may_dispatch_cgi(&rule.delta) {
                    return true;
                }
                pending.extend(rule.nested.iter().rev());
            }
            false
        }
        // An access file can introduce Options/AddHandler/SetHandler at
        // request time, so any enabled override remains conservatively true.
        self.override_enabled
            || scope_may_dispatch_cgi(&self.global)
            || rules_may_dispatch_cgi(&self.global_rules)
            || self.vhosts.iter().any(|vhost| {
                scope_may_dispatch_cgi(&vhost.scope)
                    || scope_may_dispatch_cgi(&vhost.delta)
                    || rules_may_dispatch_cgi(&vhost.rules)
            })
    }

    pub(crate) fn cgi_path_info_possible(&self) -> bool {
        self.cgi_path_info_possible
    }

    /// Reject directives whose startup effects cannot be changed by swapping
    /// an in-memory configuration generation. Accepting them would make the
    /// reported configuration disagree with the process identity, pid guard,
    /// path base, or kernel listener state.
    pub fn validate_reload_from(&self, previous: &Config) -> Result<(), String> {
        let mut changed = Vec::new();
        if self.user != previous.user {
            changed.push("User");
        }
        if self.group != previous.group {
            changed.push("Group");
        }
        if self.pid_file != previous.pid_file {
            changed.push("PidFile");
        }
        if self.server_root != previous.server_root {
            changed.push("ServerRoot");
        }
        if self.listen_backlog != previous.listen_backlog {
            changed.push("ListenBacklog");
        }
        let listeners_changed = self.listeners.len() != previous.listeners.len()
            || self
                .listeners
                .iter()
                .zip(&previous.listeners)
                .any(|(a, b)| a.addr != b.addr || a.port != b.port || a.raw != b.raw);
        if listeners_changed {
            changed.push("Listen");
        }
        if changed.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "changing {} requires a full restart",
                changed.join(", ")
            ))
        }
    }

    pub fn capability_enabled(&self, capability: Capability) -> bool {
        self.capabilities.contains(capability)
    }

    pub(crate) fn module_loaded(&self, name: &str) -> bool {
        let wanted = norm_module(name);
        prelinked_module_names().contains(&wanted)
            || self
                .modules
                .iter()
                .any(|module| norm_module(module) == wanted)
    }

    pub(crate) fn directive_exists(&self, name: &str) -> Result<bool, String> {
        let name = name.to_ascii_lowercase();
        if core_directive_exists(&name) {
            return Ok(true);
        }
        if let Some(owner) = directive_owner(&name) {
            return Ok(self.module_loaded(owner));
        }
        if !known_directives().contains(name.as_str()) {
            return Ok(false);
        }
        Err(format!(
            "cannot safely determine module ownership for <IfDirective {name}>"
        ))
    }

    pub(crate) fn section_exists(&self, name: &str) -> bool {
        match config_section_owner(&name.to_ascii_lowercase()) {
            Some(None) => true,
            Some(Some(owner)) => self.module_loaded(owner),
            None => false,
        }
    }

    pub fn load(
        path: &Path,
        server_root: &Path,
        env: &HashMap<String, String>,
        defines: &HashMap<String, String>,
        strict: bool,
    ) -> Result<Config, Vec<ConfigError>> {
        Self::load_mode(
            path,
            server_root,
            env,
            defines,
            strict,
            false,
            crate::files::AdminFileTrust::for_current_process(),
            None,
        )
    }

    /// Reload while retaining the trust boundary captured by the original
    /// configuration generation. `service_uid` is the identity of the
    /// request process, not the euid performing this parse.
    pub fn load_for_reload(
        path: &Path,
        server_root: &Path,
        env: &HashMap<String, String>,
        defines: &HashMap<String, String>,
        strict: bool,
        previous: &Config,
        service_uid: u32,
    ) -> Result<Config, Vec<ConfigError>> {
        Self::load_mode(
            path,
            server_root,
            env,
            defines,
            strict,
            false,
            previous.admin_file_trust,
            Some(service_uid),
        )
    }

    /// Validate paths discovered before the configured service identity was
    /// resolved. This closes the empty-IncludeOptional case at initial start.
    pub fn validate_admin_input_parents(&self, service_uid: u32) -> Result<(), String> {
        if self.admin_file_trust != crate::files::AdminFileTrust::RootOwned {
            return Ok(());
        }
        for target in &self.admin_input_targets {
            crate::files::validate_admin_parents(target, service_uid).map_err(|error| {
                format!(
                    "administrative input parent for {} is unsafe: {error}",
                    target.display()
                )
            })?;
        }
        Ok(())
    }

    /// Authentication databases are operator-controlled by default. The
    /// explicit compatibility capability permits deployments whose service
    /// account intentionally maintains htpasswd/group files.
    pub fn validate_auth_files(&self, service_uid: u32) -> Result<(), String> {
        let mutable = self.capability_enabled(Capability::MutableAuthFiles);
        for path in &self.auth_file_targets {
            crate::auth::validate_auth_file(path, mutable, service_uid)?;
        }
        Ok(())
    }

    /// Parse a configuration for capability migration reporting. Missing
    /// capability declarations are collected instead of making the audit
    /// itself fail; every other configuration error remains fatal.
    pub fn load_capability_audit(
        path: &Path,
        server_root: &Path,
        env: &HashMap<String, String>,
        defines: &HashMap<String, String>,
        strict: bool,
    ) -> Result<Config, Vec<ConfigError>> {
        Self::load_mode(
            path,
            server_root,
            env,
            defines,
            strict,
            true,
            crate::files::AdminFileTrust::for_current_process(),
            None,
        )
    }

    fn load_mode(
        path: &Path,
        server_root: &Path,
        env: &HashMap<String, String>,
        defines: &HashMap<String, String>,
        strict: bool,
        capability_audit: bool,
        admin_file_trust: crate::files::AdminFileTrust,
        admin_service_uid: Option<u32>,
    ) -> Result<Config, Vec<ConfigError>> {
        let mut p = ParserState {
            events: Vec::new(),
            section_stack: Vec::new(),
            modules: HashSet::new(),
            module_names: prelinked_module_names(),
            defines: defines.clone(),
            env: env.clone(),
            depth: 0,
            warnings: Vec::new(),
            errors: Vec::new(),
            initial_server_root: server_root.to_path_buf(),
            server_root: server_root.to_path_buf(),
            include_count: 0,
            config_bytes: 0,
            admin_file_trust,
            admin_service_uid,
            admin_input_targets: Vec::new(),
        };
        p.parse_file(path, true);
        if let Some((open, _, _)) = p.section_stack.last() {
            p.error(
                &SourceLoc {
                    file: path.display().to_string(),
                    line: 0,
                },
                format!("<{open}> was not closed"),
            );
        }
        if !p.errors.is_empty() {
            return Err(p.errors);
        }
        let program = match ConfigProgram::seal(std::mem::take(&mut p.events)) {
            Ok(program) => program,
            Err(msg) => {
                return Err(vec![ConfigError {
                    file: path.display().to_string(),
                    line: 0,
                    msg,
                }]);
            }
        };
        match Compile::new(p, program, strict, capability_audit).compile() {
            Ok(mut c) => {
                c.override_enabled = c.override_scan();
                let (prefixes, anywhere) = c.override_paths();
                c.override_prefixes = prefixes;
                c.override_anywhere = anywhere;
                c.body_handlers_possible = c.compute_body_handlers_possible();
                c.cgi_path_info_possible = c.compute_cgi_path_info_possible();
                Ok(c)
            }
            Err(e) => Err(vec![e]),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceLoc {
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub enum Event {
    Directive {
        name: String,
        args: Vec<String>,
        loc: SourceLoc,
    },
    SectionStart {
        name: String,
        args: Vec<String>,
        loc: SourceLoc,
        active: bool,
        transparent: bool,
    },
    SectionEnd {
        loc: SourceLoc,
    },
}

/// Canonical directive identity established once when the expanded
/// configuration stream is sealed.  The compiler consumes these facts rather
/// than reclassifying an unhandled string at every policy mutation site.
#[derive(Debug, Clone)]
struct DirectiveIdentity {
    canonical: String,
    security_sensitive: bool,
    apache_known: bool,
    schema: PayloadSchema,
}

/// Minimum structural payload schema. Complex values (regular expressions,
/// routes, Require providers, TLS policy) are parsed by their dedicated typed
/// parsers later in compilation; this table prevents a missing token from
/// being normalized into an empty path, user, handler, or security policy.
fn directive_arity(name: &str) -> PayloadArity {
    match name {
        "vapachecapability" => PayloadArity {
            min: 2,
            max: Some(2),
        },
        "require"
        | "allowoverride"
        | "allowoverridelist"
        | "protocols"
        | "serveralias"
        | "directoryindex"
        | "indexignore"
        | "fileetag"
        | "accessfilename"
        | "options"
        | "expiresdefault"
        | "deflatefilternote"
        | "requestreadtimeout"
        | "rewriteoptions"
        | "sslprotocol"
        | "ssloptions"
        | "allowmethods"
        | "unsetenv"
        | "passenv"
        | "sslciphersuite"
        | "sslciphersuitetls13"
        | "removetype"
        | "removehandler"
        | "cachedisable"
        | "setoutputfilter"
        | "setinputfilter" => PayloadArity::at_least(1),
        "order"
        | "rewriteengine"
        | "rewritebase"
        | "sethandler"
        | "forcetype"
        | "adddefaultcharset"
        | "enablesendfile"
        | "directoryslash"
        | "typesconfig"
        | "cacheroot"
        | "cachedefaultexpire"
        | "cachemaxexpire"
        | "cacheminexpire"
        | "cachemaxfilesize"
        | "cachemaxdisksize"
        | "cachemaxmemorysize"
        | "cacheminsize"
        | "cacheignorenolastmod"
        | "cacheignorecachecontrol"
        | "cachestorenostore"
        | "cachestoreprivate"
        | "cacheignorequerystring"
        | "cacheheader"
        | "cachedetailheader"
        | "cachelastmodifiedfactor"
        | "deflatecompressionlevel"
        | "brotlicompressionquality"
        | "deflatealteretag"
        | "brotlialteretag"
        | "brotlicompressionalteretag"
        | "expiresactive"
        | "deflatebuffersize"
        | "deflatememlevel"
        | "deflatewindowssize"
        | "user"
        | "group"
        | "pidfile"
        | "errorlog"
        | "remoteipheader"
        | "timeout"
        | "keepalive"
        | "keepalivetimeout"
        | "maxkeepaliverequests"
        | "hostnamelookups"
        | "usecanonicalname"
        | "servertokens"
        | "serversignature"
        | "traceenable"
        | "limitrequestline"
        | "limitrequestfields"
        | "limitrequestfieldsize"
        | "maxrequestworkers"
        | "serverlimit"
        | "listenbacklog"
        | "gracefulshutdowntimeout"
        | "limitrequestbody"
        | "allowencodedslashes"
        | "satisfy"
        | "authmerging"
        | "secruleengine"
        | "sslsessioncachetimeout"
        | "sslsessiontickets"
        | "sslhonorcipherorder"
        | "sslengine"
        | "sslcertificatefile"
        | "sslcertificatekeyfile"
        | "sslcertificatechainfile"
        | "sslusestapling"
        | "sslstaplingforceurl"
        | "sslstaplingrespondertimeout"
        | "sslstaplingstandardcachetimeout"
        | "sslstaplingreturnrespondererrors"
        | "sslstaplingcache"
        | "sslproxycacertificatefile"
        | "sslverifyclient"
        | "sslcacertificatefile"
        | "sslcarevocationfile"
        | "sslcarevocationcheck"
        | "authtype"
        | "authname"
        | "authuserfile"
        | "authgroupfile"
        | "authbasicprovider"
        | "serverroot"
        | "servername"
        | "serveradmin"
        | "documentroot"
        | "defaultruntime"
        | "defaultruntimedir"
        | "defaulttype"
        | "include"
        | "includeoptional"
        | "undefine"
        | "vapachemaxspoolbytes"
        | "vapachemaxspoolfiles"
        | "vapachemaxdynamicrequests"
        | "vapachemaxfastcgioutput"
        | "loglevel" => PayloadArity::ONE,
        "loadmodule" => PayloadArity::TWO,
        "define" => PayloadArity::between(1, 2),
        "setenv" => PayloadArity::between(1, 2),
        "listen" => PayloadArity::between(1, 2),
        "allow" | "deny" | "rewritecond" | "rewriterule" | "addtype" | "addhandler"
        | "addinputfilter" | "header" | "expiresbytype" | "browsermatch" | "browsermatchnocase" => {
            PayloadArity::at_least(2)
        }
        "setenvif" | "setenvifnocase" => PayloadArity::at_least(3),
        "addcharset"
        | "addencoding"
        | "addlanguage"
        | "remoteipinternalproxy"
        | "remoteiptrustedproxy"
        | "balancermember"
        | "proxyset"
        | "proxyhctemplate"
        | "vapachefastcgistablepath"
        | "sslrandomseed"
        | "sslpassphrasedialog"
        | "sslsessioncache" => PayloadArity::at_least(1),
        "alias" | "scriptalias" | "aliasmatch" | "scriptaliasmatch" | "rewritemap"
        | "errordocument" => PayloadArity::TWO,
        "redirect" | "redirectmatch" => PayloadArity::between(2, 3),
        "redirectpermanent" | "redirecttemp" => PayloadArity::TWO,
        "proxypass" | "addoutputfilter" | "addoutputfilterbytype" => PayloadArity::at_least(2),
        "proxypassreverse" | "proxypassmatch" => PayloadArity::TWO,
        "cacheenable" => PayloadArity::between(1, 2),
        // Vapache currently supports named LogFormat definitions and
        // unconditional CustomLog sinks. Refuse the otherwise-valid Apache
        // variants until their effects are implemented; accepting them as
        // no-ops or unconditional logs changes the audit policy.
        "logformat" | "customlog" => PayloadArity::TWO,
        // SSLRequireSSL is intentionally a zero-argument directive. Unknown
        // and compatibility-only directives retain their existing parser or
        // disposition behavior.
        _ => PayloadArity::ANY,
    }
}

fn directive_rejects_empty(name: &str) -> bool {
    matches!(
        name,
        "serverroot"
            | "servername"
            | "documentroot"
            | "user"
            | "group"
            | "pidfile"
            | "errorlog"
            | "sethandler"
            | "forcetype"
            | "typesconfig"
            | "cacheroot"
            | "remoteipheader"
            | "sslcertificatefile"
            | "sslcertificatekeyfile"
            | "sslcertificatechainfile"
            | "sslproxycacertificatefile"
            | "sslcacertificatefile"
            | "sslcarevocationfile"
            | "sslprotocol"
            | "sslciphersuite"
            | "sslciphersuitetls13"
            | "authtype"
            | "authuserfile"
            | "authgroupfile"
            | "authbasicprovider"
            | "vapachecapability"
            | "vapachefastcgistablepath"
            | "serveralias"
            | "allowoverride"
            | "allowoverridelist"
            | "rewritemap"
            | "loglevel"
            | "sslrandomseed"
            | "sslpassphrasedialog"
            | "sslsessioncache"
            | "sslstaplingcache"
            | "ssloptions"
            | "balancermember"
            | "proxyset"
            | "proxyhctemplate"
    )
}

const ALTER_ETAG_KEYWORDS: &[&str] = &["AddSuffix", "NoChange", "Remove"];
const HOSTNAME_LOOKUPS_KEYWORDS: &[&str] = &["On", "Off", "Double"];
const CANONICAL_NAME_KEYWORDS: &[&str] = &["On", "Off", "DNS"];
const SERVER_TOKENS_KEYWORDS: &[&str] = &["Full", "OS", "Minimal", "Minor", "Major", "Prod"];
const SERVER_SIGNATURE_KEYWORDS: &[&str] = &["On", "Off", "Email"];
const TRACE_ENABLE_KEYWORDS: &[&str] = &["Off", "On", "Extended"];
const ENCODED_SLASH_KEYWORDS: &[&str] = &["On", "Off", "NoDecode"];
const ORDER_KEYWORDS: &[&str] = &["allow,deny", "mutual-failure", "deny,allow"];
const SATISFY_KEYWORDS: &[&str] = &["all", "any"];
const AUTH_MERGING_KEYWORDS: &[&str] = &["off", "and", "or"];
const BASIC_AUTH_KEYWORDS: &[&str] = &["basic"];
const FILE_PROVIDER_KEYWORDS: &[&str] = &["file"];
const SSL_CA_REVOCATION_CHECK_KEYWORDS: &[&str] = &["none", "leaf", "chain"];

/// Directive payloads are compiled while the immutable program is sealed.
/// Remaining token payloads are exact strings or lists whose application is
/// infallible; fallible semantic parsers have a closed value variant.
fn directive_payload_schema(name: &str) -> PayloadSchema {
    let arity = directive_arity(name);
    let reject_empty = directive_rejects_empty(name);
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
        "protocols" => PayloadValueSchema::HttpProtocols,
        "expiresdefault" => PayloadValueSchema::ExpiresDefault,
        "expiresbytype" => PayloadValueSchema::ExpiresByType,
        "setenvif" | "setenvifnocase" | "browsermatch" | "browsermatchnocase" => {
            PayloadValueSchema::EnvironmentRule
        }
        "indexignore" => PayloadValueSchema::GlobPatterns,
        "allowmethods" => PayloadValueSchema::AllowMethods,
        "requestreadtimeout" => PayloadValueSchema::RequestReadTimeout,
        "listen" => PayloadValueSchema::Listen,
        "remoteipinternalproxy" | "remoteiptrustedproxy" => PayloadValueSchema::RemoteIpNetworks,
        "sslprotocol" => PayloadValueSchema::SslProtocol,
        "rewriteengine"
        | "enablesendfile"
        | "directoryslash"
        | "expiresactive"
        | "cacheignorenolastmod"
        | "cacheignorecachecontrol"
        | "cachestorenostore"
        | "cachestoreprivate"
        | "cacheignorequerystring"
        | "cacheheader"
        | "cachedetailheader"
        | "keepalive"
        | "sslengine"
        | "sslusestapling"
        | "sslstaplingreturnrespondererrors"
        | "sslsessiontickets"
        | "sslhonorcipherorder" => PayloadValueSchema::OnOff,
        "vapachemaxspoolbytes"
        | "vapachemaxspoolfiles"
        | "vapachemaxdynamicrequests"
        | "vapachemaxfastcgioutput" => PayloadValueSchema::Unsigned {
            min: 1,
            max: u64::MAX,
        },
        "cachedefaultexpire" | "cachemaxexpire" | "cacheminexpire" | "cachemaxfilesize"
        | "cachemaxdisksize" | "cachemaxmemorysize" | "cacheminsize" | "limitrequestbody" => {
            PayloadValueSchema::Unsigned {
                min: 0,
                max: u64::MAX,
            }
        }
        "deflatecompressionlevel" => PayloadValueSchema::Unsigned { min: 0, max: 9 },
        "brotlicompressionquality" => PayloadValueSchema::Unsigned { min: 0, max: 11 },
        "timeout"
        | "keepalivetimeout"
        | "maxkeepaliverequests"
        | "limitrequestline"
        | "limitrequestfields"
        | "limitrequestfieldsize"
        | "gracefulshutdowntimeout" => PayloadValueSchema::Unsigned {
            min: 0,
            max: u32::MAX as u64,
        },
        "maxrequestworkers" | "serverlimit" => PayloadValueSchema::Unsigned {
            min: 1,
            max: MAX_IMPLEMENTED_REQUEST_WORKERS as u64,
        },
        "listenbacklog" => PayloadValueSchema::Unsigned {
            min: 1,
            max: i32::MAX as u64,
        },
        "sslstaplingrespondertimeout"
        | "sslstaplingstandardcachetimeout"
        | "sslsessioncachetimeout" => PayloadValueSchema::Unsigned {
            min: 0,
            max: u64::MAX,
        },
        "deflatealteretag" | "brotlialteretag" | "brotlicompressionalteretag" => {
            PayloadValueSchema::Keyword(ALTER_ETAG_KEYWORDS)
        }
        "hostnamelookups" => PayloadValueSchema::Keyword(HOSTNAME_LOOKUPS_KEYWORDS),
        "usecanonicalname" => PayloadValueSchema::Keyword(CANONICAL_NAME_KEYWORDS),
        "servertokens" => PayloadValueSchema::Keyword(SERVER_TOKENS_KEYWORDS),
        "serversignature" => PayloadValueSchema::Keyword(SERVER_SIGNATURE_KEYWORDS),
        "traceenable" => PayloadValueSchema::Keyword(TRACE_ENABLE_KEYWORDS),
        "allowencodedslashes" => PayloadValueSchema::Keyword(ENCODED_SLASH_KEYWORDS),
        "order" => PayloadValueSchema::Keyword(ORDER_KEYWORDS),
        "satisfy" => PayloadValueSchema::Keyword(SATISFY_KEYWORDS),
        "authmerging" => PayloadValueSchema::Keyword(AUTH_MERGING_KEYWORDS),
        "authtype" => PayloadValueSchema::Keyword(BASIC_AUTH_KEYWORDS),
        "authbasicprovider" => PayloadValueSchema::Keyword(FILE_PROVIDER_KEYWORDS),
        "sslverifyclient" => {
            PayloadValueSchema::Keyword(&["none", "optional", "require", "optional_no_ca"])
        }
        "sslcarevocationcheck" => PayloadValueSchema::Keyword(SSL_CA_REVOCATION_CHECK_KEYWORDS),
        "cachelastmodifiedfactor" => PayloadValueSchema::UnitFloat,
        "sslstaplingforceurl" => PayloadValueSchema::OcspResponderUrl,
        "aliasmatch" | "scriptaliasmatch" => PayloadValueSchema::AliasRegex,
        "proxypass" => PayloadValueSchema::ProxyPass,
        "proxypassreverse" => PayloadValueSchema::ProxyPassReverse,
        "proxypassmatch" => PayloadValueSchema::ProxyPassMatch,
        "vapachecapability" => PayloadValueSchema::Validated(PayloadValidation::Capability),
        "vapachefastcgistablepath" => {
            PayloadValueSchema::Validated(PayloadValidation::FastCgiStablePath)
        }
        "serveralias" => PayloadValueSchema::Validated(PayloadValidation::ServerAliases),
        "allowoverride" => PayloadValueSchema::Validated(PayloadValidation::AllowOverride),
        "allowoverridelist" => PayloadValueSchema::Validated(PayloadValidation::AllowOverrideList),
        "rewritemap" => PayloadValueSchema::Validated(PayloadValidation::RewriteMap),
        "loglevel" => PayloadValueSchema::Validated(PayloadValidation::LogLevel),
        "sslrandomseed" => PayloadValueSchema::Validated(PayloadValidation::SslRandomSeed),
        "sslpassphrasedialog" => {
            PayloadValueSchema::Validated(PayloadValidation::SslPassphraseDialog)
        }
        "sslsessioncache" => PayloadValueSchema::Validated(PayloadValidation::SslSessionCache),
        "sslstaplingcache" => PayloadValueSchema::Validated(PayloadValidation::SslStaplingCache),
        "ssloptions" => PayloadValueSchema::Validated(PayloadValidation::SslOptions),
        "balancermember" => PayloadValueSchema::Validated(PayloadValidation::BalancerMember),
        "proxyset" => PayloadValueSchema::Validated(PayloadValidation::ProxySet),
        "proxyhctemplate" => PayloadValueSchema::Validated(PayloadValidation::ProxyHealthTemplate),
        _ => PayloadValueSchema::Tokens,
    };
    PayloadSchema::typed(arity, reject_empty, value)
}

impl DirectiveIdentity {
    fn new(
        canonical: String,
        known: &HashSet<&'static str>,
        fail_closed: &HashSet<&'static str>,
    ) -> Self {
        let security_sensitive = is_security_directive_with(&canonical, fail_closed);
        DirectiveIdentity {
            security_sensitive,
            apache_known: known.contains(canonical.as_str()),
            schema: directive_payload_schema(&canonical),
            canonical,
        }
    }

    fn as_str(&self) -> &str {
        &self.canonical
    }
}

/// Closed section vocabulary. Unknown names remain explicit data so the
/// compiler can reject them; they can never acquire transparent semantics by
/// falling through a string comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProgramSectionClass {
    VirtualHost,
    Directory,
    DirectoryMatch,
    Location,
    LocationMatch,
    Files,
    FilesMatch,
    Proxy,
    ProxyMatch,
    Limit,
    LimitExcept,
    If,
    IfFile,
    ElseIf,
    Else,
    RequireAll,
    RequireAny,
    RequireNone,
    AuthzProviderAlias,
    ExecuteOnRead,
    Unknown,
}

impl ProgramSectionClass {
    fn from_name(name: &str) -> Self {
        match name {
            "virtualhost" => Self::VirtualHost,
            "directory" => Self::Directory,
            "directorymatch" => Self::DirectoryMatch,
            "location" => Self::Location,
            "locationmatch" => Self::LocationMatch,
            "files" => Self::Files,
            "filesmatch" => Self::FilesMatch,
            "proxy" => Self::Proxy,
            "proxymatch" => Self::ProxyMatch,
            "limit" => Self::Limit,
            "limitexcept" => Self::LimitExcept,
            "if" => Self::If,
            "iffile" => Self::IfFile,
            "elseif" => Self::ElseIf,
            "else" => Self::Else,
            "requireall" => Self::RequireAll,
            "requireany" => Self::RequireAny,
            "requirenone" => Self::RequireNone,
            "authzprovideralias" => Self::AuthzProviderAlias,
            "ifmodule" | "ifdefine" | "ifdirective" | "ifsection" | "ifversion" => {
                Self::ExecuteOnRead
            }
            _ => Self::Unknown,
        }
    }
}

fn validate_config_section_arity(name: &str, args: &[String]) -> Result<(), String> {
    let (min, max) = match name {
        "else" | "requireall" | "requireany" | "requirenone" => (0, Some(0)),
        "ifmodule" | "ifdefine" | "iffile" | "ifdirective" | "ifsection" => (1, Some(1)),
        "ifversion" => (1, Some(2)),
        "authzprovideralias" => (2, Some(2)),
        "directory" | "location" | "files" => (1, Some(2)),
        "directorymatch" | "locationmatch" | "filesmatch" | "proxy" | "proxymatch" => (1, Some(1)),
        "virtualhost" | "limit" | "limitexcept" | "if" | "elseif" => (1, None),
        _ => return Ok(()),
    };
    if !vapache_verified::config_argument_arity_admit(args.len(), min, max) {
        let requirement = match max {
            Some(max) if max == min => format!("exactly {min}"),
            Some(max) => format!("between {min} and {max}"),
            None => format!("at least {min}"),
        };
        return Err(format!(
            "<{name}> requires {requirement} argument(s), got {}",
            args.len()
        ));
    }
    if matches!(name, "directory" | "location" | "files")
        && args.first().is_some_and(|arg| arg == "~")
        && args.len() < 2
    {
        return Err(format!("<{name} ~> requires a regular expression"));
    }
    if matches!(name, "directory" | "location" | "files") && args.len() == 2 && args[0] != "~" {
        return Err(format!(
            "<{name}> accepts two arguments only in the '<{name} ~ regex>' form"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum ProgramEvent {
    Directive {
        identity: DirectiveIdentity,
        payload: SealedPayload,
        loc: SourceLoc,
    },
    SectionStart {
        name: String,
        class: ProgramSectionClass,
        payload: ProgramSectionPayload,
        loc: SourceLoc,
        active: bool,
        transparent: bool,
        /// Exact matching `SectionEnd` instruction, established while sealing.
        end: usize,
    },
    SectionEnd {
        /// Exact matching `SectionStart` instruction.
        start: usize,
    },
}

/// Closed semantic value for a main-configuration section command. The only
/// path still resolved during the mutation walk is a relative literal
/// `<Directory>` path because `ServerRoot` is order-sensitive; its glob syntax
/// is nevertheless validated here.
#[derive(Debug, Clone)]
enum ProgramSectionPayload {
    Unknown,
    Empty,
    Arguments(Box<[String]>),
    Expression(crate::expr::Expr),
    Methods(MethodSet),
    Match(MatchKind),
    DirectoryLiteral(String),
    ProxyWildcard(String),
    ProxyRegex(Regex),
}

fn seal_program_section(
    name: &str,
    class: ProgramSectionClass,
    args: Vec<String>,
) -> Result<ProgramSectionPayload, String> {
    validate_config_section_arity(name, &args)?;
    Ok(match class {
        ProgramSectionClass::If | ProgramSectionClass::ElseIf => {
            let expression = crate::expr::parse(&args.join(" "))
                .map_err(|error| format!("bad <{name}> expression: {error}"))?;
            crate::expr::validate_vars(&expression)
                .map_err(|error| format!("bad <{name}> expression: {error}"))?;
            ProgramSectionPayload::Expression(expression)
        }
        ProgramSectionClass::IfFile => {
            let expression = crate::expr::Expr::IfFile(args[0].clone());
            crate::expr::validate_vars(&expression)
                .map_err(|error| format!("bad <IfFile> expression: {error}"))?;
            ProgramSectionPayload::Expression(expression)
        }
        ProgramSectionClass::Else
        | ProgramSectionClass::RequireAll
        | ProgramSectionClass::RequireAny
        | ProgramSectionClass::RequireNone => ProgramSectionPayload::Empty,
        ProgramSectionClass::Limit | ProgramSectionClass::LimitExcept => {
            ProgramSectionPayload::Methods(parse_method_set_args(name, &args, false)?)
        }
        ProgramSectionClass::Directory => {
            if args[0] == "~" {
                ProgramSectionPayload::Match(MatchKind::DirectoryMatch(
                    compile_regex(&args[1..].join(" "))
                        .map_err(|error| format!("bad Directory regex: {error}"))?,
                ))
            } else {
                validate_glob_pattern(&args[0])
                    .map_err(|error| format!("bad Directory pattern: {error}"))?;
                ProgramSectionPayload::DirectoryLiteral(args[0].clone())
            }
        }
        ProgramSectionClass::DirectoryMatch => {
            ProgramSectionPayload::Match(MatchKind::DirectoryMatch(
                compile_regex(&args[0]).map_err(|error| format!("bad Directory regex: {error}"))?,
            ))
        }
        ProgramSectionClass::Files => ProgramSectionPayload::Match(compile_files_pattern(&args)?),
        ProgramSectionClass::FilesMatch => ProgramSectionPayload::Match(MatchKind::FilesMatch(
            compile_regex(&args[0]).map_err(|error| format!("bad FilesMatch regex: {error}"))?,
        )),
        ProgramSectionClass::Location => {
            ProgramSectionPayload::Match(compile_location_pattern(&args)?)
        }
        ProgramSectionClass::LocationMatch => {
            ProgramSectionPayload::Match(MatchKind::LocationMatch(
                compile_regex(&args[0])
                    .map_err(|error| format!("bad LocationMatch regex: {error}"))?,
            ))
        }
        ProgramSectionClass::Proxy => {
            validate_glob_pattern(&args[0])
                .map_err(|error| format!("bad <Proxy> pattern: {error}"))?;
            ProgramSectionPayload::ProxyWildcard(args[0].clone())
        }
        ProgramSectionClass::ProxyMatch => ProgramSectionPayload::ProxyRegex(
            compile_regex(&args[0]).map_err(|error| format!("bad <ProxyMatch> regex: {error}"))?,
        ),
        ProgramSectionClass::VirtualHost
        | ProgramSectionClass::AuthzProviderAlias
        | ProgramSectionClass::ExecuteOnRead => {
            ProgramSectionPayload::Arguments(args.into_boxed_slice())
        }
        ProgramSectionClass::Unknown => ProgramSectionPayload::Unknown,
    })
}

/// Immutable, include-expanded configuration program.  It is constructed
/// only after syntax/conditional processing succeeds. Every section has an
/// exact mate and the verified depth transition proves that sealing cannot
/// accept stack underflow or arithmetic wrap.
#[derive(Debug)]
struct ConfigProgram {
    instructions: Box<[ProgramEvent]>,
}

impl ConfigProgram {
    fn seal(events: Vec<Event>) -> Result<Self, String> {
        let mut instructions = Vec::with_capacity(events.len());
        let mut stack: Vec<usize> = Vec::new();
        let mut depth = 0usize;
        // These registries are immutable for one compilation. Constructing
        // them once keeps sealing linear in the number of input events.
        let known = known_directives();
        let fail_closed = fail_closed_directives();
        for event in events {
            match event {
                Event::Directive { name, args, loc } => {
                    depth = vapache_verified::config_program_depth_step(
                        depth,
                        vapache_verified::ConfigLineKind::Directive,
                    )
                    .ok_or("configuration program depth overflow")?;
                    let identity = DirectiveIdentity::new(name, &known, &fail_closed);
                    let payload = SealedPayload::seal(identity.as_str(), args, identity.schema)
                        .map_err(|message| format!("{}:{}: {message}", loc.file, loc.line))?;
                    instructions.push(ProgramEvent::Directive {
                        identity,
                        payload,
                        loc,
                    });
                }
                Event::SectionStart {
                    name,
                    args,
                    loc,
                    active,
                    transparent,
                } => {
                    depth = vapache_verified::config_program_depth_step(
                        depth,
                        vapache_verified::ConfigLineKind::SectionStart,
                    )
                    .ok_or("configuration program depth overflow")?;
                    if !vapache_verified::config_section_depth_admit(
                        depth,
                        MAX_CONFIG_SECTION_DEPTH,
                    ) {
                        return Err(format!(
                            "configuration section nesting exceeds {MAX_CONFIG_SECTION_DEPTH}"
                        ));
                    }
                    let start = instructions.len();
                    let class = ProgramSectionClass::from_name(&name);
                    let payload = seal_program_section(&name, class, args)
                        .map_err(|message| format!("{}:{}: {message}", loc.file, loc.line))?;
                    instructions.push(ProgramEvent::SectionStart {
                        name,
                        class,
                        payload,
                        loc,
                        active,
                        transparent,
                        end: usize::MAX,
                    });
                    stack.push(start);
                }
                Event::SectionEnd { loc: _ } => {
                    depth = vapache_verified::config_program_depth_step(
                        depth,
                        vapache_verified::ConfigLineKind::SectionEnd,
                    )
                    .ok_or("configuration program contains an unmatched closing section")?;
                    let start = stack
                        .pop()
                        .ok_or("configuration program contains an unmatched closing section")?;
                    let end = instructions.len();
                    let ProgramEvent::SectionStart {
                        end: matching_end, ..
                    } = &mut instructions[start]
                    else {
                        return Err("configuration program section index is corrupt".into());
                    };
                    *matching_end = end;
                    instructions.push(ProgramEvent::SectionEnd { start });
                }
            }
        }
        if depth != 0 || !stack.is_empty() {
            return Err("configuration program contains an unclosed section".into());
        }
        Ok(ConfigProgram {
            instructions: instructions.into_boxed_slice(),
        })
    }
}

struct ParserState {
    events: Vec<Event>,
    section_stack: Vec<(String, bool, bool)>,
    modules: HashSet<String>,
    module_names: HashSet<String>,
    defines: HashMap<String, String>,
    env: HashMap<String, String>,
    depth: usize,
    warnings: Vec<String>,
    errors: Vec<ConfigError>,
    /// CLI/default root at the start of the configuration stream. Compilation
    /// replays ServerRoot events from this value; `server_root` below tracks
    /// the execute-on-read value used while expanding includes.
    initial_server_root: PathBuf,
    server_root: PathBuf,
    include_count: usize,
    config_bytes: u64,
    admin_file_trust: crate::files::AdminFileTrust,
    admin_service_uid: Option<u32>,
    admin_input_targets: Vec<PathBuf>,
}

fn norm_module(name: &str) -> String {
    let n = name.trim();
    let n = n.strip_prefix('!').unwrap_or(n);
    let n = n.trim_end_matches(".so");
    let n = n.trim_end_matches(".c");
    let n = n.strip_prefix("mod_").unwrap_or(n);
    let n = n.strip_suffix("_module").unwrap_or(n);
    n.to_ascii_lowercase()
}

fn prelinked_module_names() -> HashSet<String> {
    // Apache 2.4.69's linked-in modules (`apache2 -l`). `http_core.c`
    // declares `http_module`, so retain both accepted spellings.
    [
        "core",
        "so",
        "watchdog",
        "http",
        "http_core",
        "log_config",
        "logio",
        "version",
        "unixd",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn module_name_is_loaded(names: &HashSet<String>, name: &str) -> bool {
    names.contains(&norm_module(name))
}

fn core_directive_exists(name: &str) -> bool {
    matches!(
        name,
        "acceptpathinfo"
            | "accessfilename"
            | "adddefaultcharset"
            | "allowencodedslashes"
            | "allowoverride"
            | "allowoverridelist"
            | "define"
            | "documentroot"
            | "enablemmap"
            | "enablesendfile"
            | "errordocument"
            | "errorlog"
            | "errorlogformat"
            | "fileetag"
            | "forcetype"
            | "hostnamelookups"
            | "include"
            | "includeoptional"
            | "limitinternalrecursion"
            | "limitrequestbody"
            | "limitrequestfields"
            | "limitrequestfieldsize"
            | "limitrequestline"
            | "limitxmlrequestbody"
            | "loglevel"
            | "maxrangeoverlaps"
            | "maxranges"
            | "options"
            | "protocol"
            | "protocols"
            | "protocolshonororder"
            | "rlimitcpu"
            | "rlimitmem"
            | "rlimitnproc"
            | "serveradmin"
            | "serveralias"
            | "servername"
            | "serverpath"
            | "serverroot"
            | "serversignature"
            | "servertokens"
            | "sethandler"
            | "timeout"
            | "traceenable"
            | "undefine"
            | "usecanonicalname"
            | "usecanonicalphysicalport"
            | "vapachefastcgistablepath"
            | "vapachecapability"
            | "vapachemaxdynamicrequests"
            | "vapachemaxfastcgioutput"
            | "vapachemaxspoolbytes"
            | "vapachemaxspoolfiles"
    )
}

fn directive_owner(name: &str) -> Option<&'static str> {
    Some(match name {
        "loadfile" | "loadmodule" => "so",
        "require" | "authmerging" | "authzsendforbiddenonfailure" => "authz_core",
        "allow" | "deny" | "order" | "satisfy" => "access_compat",
        "allowmethods" => "allowmethods",
        "authname"
        | "authtype"
        | "authbasicprovider"
        | "authbasicauthoritative"
        | "authbasicfake" => "auth_basic",
        "authuserfile" => "authn_file",
        "authgroupfile" => "authz_groupfile",
        "alias" | "aliasmatch" | "redirect" | "redirectmatch" | "redirectpermanent"
        | "redirecttemp" | "scriptalias" | "scriptaliasmatch" => "alias",
        "directoryindex" | "directoryslash" | "fallbackresource" => "dir",
        "addhandler" | "addtype" | "removetype" | "removehandler" | "typesconfig"
        | "multiviewsmatch" => "mime",
        "header" | "requestheader" => "headers",
        "setenvif" | "setenvifnocase" | "setenvifexpr" | "browsermatch" | "browsermatchnocase" => {
            "setenvif"
        }
        "setenv" | "unsetenv" | "passenv" => "env",
        "rewritebase" | "rewritecond" | "rewriteengine" | "rewritemap" | "rewriteoptions"
        | "rewriterule" => "rewrite",
        "remoteipheader" | "remoteipinternalproxy" | "remoteiptrustedproxy" => "remoteip",
        "proxybadheader" | "proxyblock" | "proxyerroroverride" | "proxypass" | "proxypassmatch"
        | "proxypassreverse" | "proxypreservehost" | "proxyrequests" | "proxyset"
        | "proxytimeout" => "proxy",
        "cachedefaultexpire" | "cachedisable" | "cacheenable" | "cacheignoreheaders"
        | "cachelock" | "cachemaxexpire" | "cachemaxfilesize" | "cachequickhandler"
        | "cachestorenostore" | "cachestoreprivate" => "cache",
        "cacheroot" | "cachedirlevels" | "cachedirlength" => "cache_disk",
        "expiresactive" | "expiresbytype" | "expiresdefault" => "expires",
        "addoutputfilterbytype" | "filterchain" | "filterdeclare" | "filterprovider" => "filter",
        "deflatecompressionlevel" | "deflatefilternote" => "deflate",
        "brotlicompressionquality" => "brotli",
        "indexignore" | "indexoptions" | "readmename" | "headername" => "autoindex",
        "sslengine"
        | "sslprotocol"
        | "sslciphersuite"
        | "sslverifyclient"
        | "sslverifydepth"
        | "sslcertificatefile"
        | "sslcertificatekeyfile"
        | "sslcacertificatefile"
        | "sslcarevocationfile"
        | "sslcarevocationcheck"
        | "ssloptions"
        | "sslrequiressl" => "ssl",
        "listen" => "mpm_event",
        "customlog" | "logformat" | "transferlog" => "log_config",
        "user" | "group" => "unixd",
        _ => return None,
    })
}

fn config_section_owner(name: &str) -> Option<Option<&'static str>> {
    Some(match name {
        "directory" | "directorymatch" | "location" | "locationmatch" | "files" | "filesmatch"
        | "virtualhost" | "limit" | "limitexcept" | "if" | "elseif" | "else" | "ifmodule"
        | "ifdefine" | "iffile" | "ifdirective" | "ifsection" => None,
        "ifversion" => Some("version"),
        "requireall" | "requireany" | "requirenone" | "authzprovideralias" => Some("authz_core"),
        "proxy" | "proxymatch" => Some("proxy"),
        _ => return None,
    })
}

fn parse_compat_version(value: &str) -> Result<(u32, u32, u32), String> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.is_empty() || parts.len() > 3 || parts.iter().any(|part| part.is_empty()) {
        return Err("IfVersion requires major[.minor[.patch]]".into());
    }
    let mut out = [0u32; 3];
    for (idx, part) in parts.iter().enumerate() {
        out[idx] = part
            .parse()
            .map_err(|_| "IfVersion requires major[.minor[.patch]]".to_string())?;
    }
    Ok((out[0], out[1], out[2]))
}

pub(crate) fn ifversion_matches(args: &[String]) -> Result<bool, String> {
    let (operator, version) = match args {
        [version] => ("=", version.as_str()),
        [operator, version] => (operator.as_str(), version.as_str()),
        _ => return Err("<IfVersion> requires a version and optional operator".into()),
    };
    let (negated, operator) = match operator.strip_prefix('!') {
        Some(operator) if !operator.is_empty() => (true, operator),
        _ => (false, operator),
    };
    if operator == "~" || version.starts_with('/') {
        return Err("<IfVersion> regex comparisons are not supported safely".into());
    }
    let configured = parse_compat_version(version)?;
    let current = (2u32, 4u32, 69u32);
    let matched = match operator {
        "=" | "==" => current == configured,
        ">" => current > configured,
        ">=" => current >= configured,
        "<" => current < configured,
        "<=" => current <= configured,
        _ => return Err(format!("unrecognized <IfVersion> operator '{operator}'")),
    };
    Ok(if negated { !matched } else { matched })
}

impl ParserState {
    fn error(&mut self, loc: &SourceLoc, msg: impl Into<String>) {
        self.errors.push(ConfigError {
            file: loc.file.clone(),
            line: loc.line,
            msg: msg.into(),
        });
    }

    fn warn(&mut self, msg: impl Into<String>) {
        let m = msg.into();
        if self.warnings.len() < 500 {
            self.warnings.push(m);
        }
    }

    fn register_admin_input(&mut self, target: &Path, loc: &SourceLoc) -> bool {
        if !self.admin_input_targets.iter().any(|known| known == target) {
            self.admin_input_targets.push(target.to_path_buf());
        }
        if self.admin_file_trust == crate::files::AdminFileTrust::RootOwned {
            if let Some(service_uid) = self.admin_service_uid {
                if let Err(error) = crate::files::validate_admin_parents(target, service_uid) {
                    self.error(
                        loc,
                        format!(
                            "administrative input parent for {} is unsafe: {error}",
                            target.display()
                        ),
                    );
                    return false;
                }
            }
        }
        true
    }

    fn expand_vars(&mut self, args: &[String], loc: &SourceLoc) -> Option<Vec<String>> {
        let mut out = Vec::with_capacity(args.len());
        for a in args {
            let mut s = String::with_capacity(a.len());
            let bytes = a.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                    let end = match a[i + 2..].find('}') {
                        Some(e) => i + 2 + e,
                        None => {
                            self.error(loc, "unterminated ${...} variable reference");
                            return None;
                        }
                    };
                    let name = &a[i + 2..end];
                    if let Some(v) = self.defines.get(name) {
                        s.push_str(v);
                    } else if let Some(v) = self.env.get(name) {
                        s.push_str(v);
                    } else if name.contains(':') {
                        // mod_rewrite map syntax (${map:key}) is expanded by
                        // the rewrite engine, not by core config parsing.
                        s.push_str("${");
                        s.push_str(name);
                        s.push('}');
                    } else {
                        self.error(
                            loc,
                            format!("AH00111: config variable ${{{name}}} is not defined"),
                        );
                        return None;
                    }
                    i = end + 1;
                } else {
                    s.push(bytes[i] as char);
                    i += 1;
                }
            }
            out.push(s);
        }
        Some(out)
    }

    fn active(&self) -> bool {
        self.section_stack.iter().all(|(_, active, _)| *active)
    }

    fn parse_file(&mut self, path: &Path, required: bool) {
        let path_loc = SourceLoc {
            file: path.display().to_string(),
            line: 0,
        };
        if !self.register_admin_input(path, &path_loc) {
            return;
        }
        if !vapache_verified::text_identity_admit(path.to_str().is_some()) {
            let loc = SourceLoc {
                file: path.display().to_string(),
                line: 0,
            };
            self.error(&loc, "config path is not valid UTF-8");
            return;
        }
        if self.depth > 32 {
            let loc = SourceLoc {
                file: path.display().to_string(),
                line: 0,
            };
            self.error(&loc, "Include nesting too deep");
            return;
        }
        let data = match crate::files::read_admin_file_with_trust(
            path,
            MAX_CONFIG_FILE_BYTES,
            self.admin_file_trust,
        ) {
            Ok(d) => d,
            Err(e) => {
                if required {
                    let loc = SourceLoc {
                        file: path.display().to_string(),
                        line: 0,
                    };
                    self.error(&loc, format!("could not open config file: {e}"));
                }
                return;
            }
        };
        let Some(total) = self.config_bytes.checked_add(data.len() as u64) else {
            let loc = SourceLoc {
                file: path.display().to_string(),
                line: 0,
            };
            self.error(&loc, "aggregate configuration size overflow");
            return;
        };
        if total > MAX_CONFIG_TOTAL_BYTES {
            let loc = SourceLoc {
                file: path.display().to_string(),
                line: 0,
            };
            self.error(
                &loc,
                format!("aggregate configuration exceeds the {MAX_CONFIG_TOTAL_BYTES} byte limit"),
            );
            return;
        }
        self.config_bytes = total;
        let text = match std::str::from_utf8(&data) {
            Ok(text) => text,
            Err(_) => {
                let loc = SourceLoc {
                    file: path.display().to_string(),
                    line: 0,
                };
                self.error(&loc, "config file is not valid UTF-8");
                return;
            }
        };
        self.depth += 1;
        let logical = crate::config_frontend::logical_lines_with_numbers(text);

        for (lineno, line) in logical {
            let loc = SourceLoc {
                file: path.display().to_string(),
                line: lineno,
            };
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let line_ir = match crate::config_frontend::parse_line(trimmed) {
                Ok(line) => line,
                Err(e) => {
                    self.error(&loc, format!("syntax error: {e}"));
                    continue;
                }
            };
            match line_ir {
                crate::config_frontend::ConfigLine::SectionEnd { name } => {
                    match self.section_stack.pop() {
                        Some((open, _, _)) if open == name => {
                            self.events.push(Event::SectionEnd { loc });
                        }
                        Some((open, _, _)) => {
                            self.error(&loc, format!("closing </{name}> does not match <{open}>"));
                            self.section_stack.push((open, true, false));
                        }
                        None => self.error(&loc, format!("unexpected </{name}>")),
                    }
                    continue;
                }
                crate::config_frontend::ConfigLine::SectionStart { name, args } => {
                    if name == "ifmodule" {
                        for a in &args {
                            if a.contains('>') {
                                self.error(&loc, "malformed <IfModule>");
                            }
                        }
                    }
                    let parent_active = self.active();
                    if parent_active {
                        if let Err(error) = validate_config_section_arity(&name, &args) {
                            self.error(&loc, error);
                        }
                    }
                    let active = if parent_active {
                        self.eval_condition(&name, &args, &loc)
                    } else {
                        false
                    };
                    let transparent = matches!(
                        name.as_str(),
                        "ifmodule"
                            | "ifdefine"
                            | "iffile"
                            | "ifdirective"
                            | "ifsection"
                            | "ifversion"
                    );
                    self.events.push(Event::SectionStart {
                        name: name.clone(),
                        args: args.clone(),
                        loc: loc.clone(),
                        active,
                        transparent,
                    });
                    self.section_stack.push((name, active, transparent));
                    continue;
                }
                crate::config_frontend::ConfigLine::Directive {
                    name: cmd,
                    args: raw_args,
                } => {
                    let args = match self.expand_vars(&raw_args, &loc) {
                        Some(a) => a,
                        None => continue,
                    };
                    if !self.active() {
                        continue;
                    }
                    match cmd.as_str() {
                        "serverroot" => match args.as_slice() {
                            [root] if !root.is_empty() => {
                                let root = PathBuf::from(root);
                                if root.is_absolute() {
                                    // Apache's ServerRoot is EXEC_ON_READ: it
                                    // changes resolution of subsequent Include
                                    // directives even when written inside a
                                    // syntactic section.
                                    self.server_root = root;
                                } else {
                                    self.error(&loc, "ServerRoot must be an absolute path");
                                }
                            }
                            _ => self.error(&loc, "ServerRoot requires exactly one path"),
                        },
                        "define" => {
                            let name = args.first().cloned().unwrap_or_default();
                            if name.is_empty() {
                                self.error(&loc, "Define requires a name");
                            } else {
                                let value = args.get(1).cloned().unwrap_or_default();
                                self.defines.insert(name, value);
                            }
                        }
                        "undefine" => {
                            if let Some(n) = args.first() {
                                self.defines.remove(n);
                            }
                        }
                        "loadmodule" => {
                            let name = args.first().cloned().unwrap_or_default();
                            if name.is_empty() {
                                self.error(&loc, "LoadModule requires a module name");
                            } else {
                                self.modules.insert(name.clone());
                                self.module_names.insert(norm_module(&name));
                                if self.module_names.len() > 4096 {
                                    self.error(&loc, "too many modules");
                                }
                            }
                        }
                        "include" | "includeoptional" => {
                            let optional = cmd == "includeoptional";
                            let pattern = match args.first() {
                                Some(p) => p.clone(),
                                None => {
                                    self.error(&loc, "Include requires a path");
                                    continue;
                                }
                            };
                            self.include_pattern(&pattern, optional, &loc);
                            self.events.push(Event::Directive {
                                name: cmd,
                                args,
                                loc,
                            });
                            continue;
                        }
                        _ => {}
                    }
                    self.events.push(Event::Directive {
                        name: cmd,
                        args,
                        loc,
                    });
                }
            }
        }
        self.depth -= 1;
    }

    fn include_pattern(&mut self, pattern: &str, optional: bool, loc: &SourceLoc) {
        if self.include_count > 10_000 {
            self.error(loc, "too many included files");
            return;
        }
        let p = Path::new(pattern);
        let full = if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.server_root.join(p)
        };
        let Some(s) = full.to_str().map(str::to_owned) else {
            self.error(loc, "Include path is not valid UTF-8");
            return;
        };
        let has_glob = s.contains('*') || s.contains('?') || s.contains('[');
        let trust_target = if !has_glob && full.is_dir() {
            full.join(".vapache-include-entry")
        } else {
            full.clone()
        };
        if !self.register_admin_input(&trust_target, loc) {
            return;
        }
        if has_glob {
            let (dir, pat) = match s.rfind('/') {
                Some(i) => (&s[..i], &s[i + 1..]),
                None => (".", s.as_str()),
            };
            let mut names: Vec<String> = Vec::new();
            for ent in std::fs::read_dir(if dir.is_empty() { "/" } else { dir })
                .into_iter()
                .flatten()
                .flatten()
            {
                let Some(n) = ent.file_name().to_str().map(str::to_owned) else {
                    self.error(loc, "Include directory contains a non-UTF-8 path");
                    return;
                };
                if glob_match(pat.as_bytes(), n.as_bytes()) {
                    names.push(format!("{dir}/{n}"));
                }
            }
            names.sort();
            if names.is_empty() && !optional {
                self.error(loc, format!("Include file not found: {pattern}"));
                return;
            }
            for n in names {
                self.include_count += 1;
                self.parse_file(Path::new(&n), !optional);
            }
        } else if full.is_dir() {
            let mut names: Vec<PathBuf> = std::fs::read_dir(&full)
                .into_iter()
                .flatten()
                .flatten()
                .map(|ent| ent.path())
                .filter(|path| path.is_file())
                .collect();
            names.sort();
            for n in names {
                self.include_count += 1;
                self.parse_file(&n, !optional);
            }
        } else {
            self.include_count += 1;
            self.parse_file(&full, !optional);
        }
    }

    fn eval_condition(&mut self, name: &str, args: &[String], loc: &SourceLoc) -> bool {
        let argument = |this: &mut Self| {
            let Some(raw) = args.first() else {
                this.error(loc, format!("<{name}> requires an argument"));
                return None;
            };
            if raw.is_empty() {
                this.error(loc, format!("<{name}> requires an argument"));
                return None;
            }
            Some(match raw.strip_prefix('!') {
                Some(value) => (true, value),
                None => (false, raw.as_str()),
            })
        };
        match name {
            "ifmodule" => {
                let Some((neg, m)) = argument(self) else {
                    return false;
                };
                let want = norm_module(m);
                let found = self.module_names.contains(&want)
                    || self.modules.iter().any(|x| norm_module(x) == want);
                if neg {
                    !found
                } else {
                    found
                }
            }
            "ifdefine" => {
                let Some((neg, d)) = argument(self) else {
                    return false;
                };
                let found = self.defines.contains_key(d);
                if neg {
                    !found
                } else {
                    found
                }
            }
            "iffile" => {
                let Some((neg, file)) = argument(self) else {
                    return false;
                };
                let path = Path::new(file);
                let path = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    self.server_root.join(path)
                };
                let found = std::fs::metadata(path).is_ok();
                if neg {
                    !found
                } else {
                    found
                }
            }
            "ifdirective" => {
                let Some((neg, directive)) = argument(self) else {
                    return false;
                };
                let directive = directive.to_ascii_lowercase();
                let found = if core_directive_exists(&directive) {
                    true
                } else if let Some(owner) = directive_owner(&directive) {
                    module_name_is_loaded(&self.module_names, owner)
                } else if !known_directives().contains(directive.as_str()) {
                    false
                } else {
                    self.error(
                        loc,
                        format!(
                            "cannot safely determine module ownership for <IfDirective {directive}>"
                        ),
                    );
                    return false;
                };
                if neg {
                    !found
                } else {
                    found
                }
            }
            "ifsection" => {
                let Some((neg, section)) = argument(self) else {
                    return false;
                };
                let section = section.to_ascii_lowercase();
                let found = match config_section_owner(&section) {
                    Some(None) => true,
                    Some(Some(owner)) => module_name_is_loaded(&self.module_names, owner),
                    None => false,
                };
                if neg {
                    !found
                } else {
                    found
                }
            }
            "ifversion" => match ifversion_matches(args) {
                Ok(matched) => matched,
                Err(msg) => {
                    self.error(loc, msg);
                    false
                }
            },
            "if" => true,
            _ => true,
        }
    }
}

pub(crate) fn glob_match(pat: &[u8], name: &[u8]) -> bool {
    crate::glob::fnmatch(pat, name, false)
}

// ---------------------------------------------------------------------------
// Compiler
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum SectionKind {
    Server,
    VirtualHost,
    Directory,
    DirectoryMatch,
    Location,
    Files,
    Proxy,
    Require,
    Conditional,
}

fn section_kind(class: ProgramSectionClass) -> Option<SectionKind> {
    Some(match class {
        ProgramSectionClass::VirtualHost => SectionKind::VirtualHost,
        ProgramSectionClass::Directory => SectionKind::Directory,
        ProgramSectionClass::DirectoryMatch => SectionKind::DirectoryMatch,
        ProgramSectionClass::Location | ProgramSectionClass::LocationMatch => SectionKind::Location,
        ProgramSectionClass::Files | ProgramSectionClass::FilesMatch => SectionKind::Files,
        ProgramSectionClass::Proxy | ProgramSectionClass::ProxyMatch => SectionKind::Proxy,
        _ => return None,
    })
}

/// Apache rejects most cross-section nesting outright.  Keeping these checks
/// in the compiler means a configuration that Apache refuses cannot silently
/// acquire a different meaning here.
fn section_kind_model(kind: SectionKind) -> vapache_verified::ConfigSectionKind {
    use SectionKind::*;
    match kind {
        Server => vapache_verified::ConfigSectionKind::Server,
        VirtualHost => vapache_verified::ConfigSectionKind::VirtualHost,
        Directory => vapache_verified::ConfigSectionKind::Directory,
        DirectoryMatch => vapache_verified::ConfigSectionKind::DirectoryMatch,
        Location => vapache_verified::ConfigSectionKind::Location,
        Files => vapache_verified::ConfigSectionKind::Files,
        Proxy => vapache_verified::ConfigSectionKind::Proxy,
        Require => vapache_verified::ConfigSectionKind::Require,
        Conditional => vapache_verified::ConfigSectionKind::Conditional,
    }
}

fn structural_section_allowed(parent: SectionKind, child: SectionKind) -> bool {
    vapache_verified::config_section_nesting_allowed(
        section_kind_model(parent),
        section_kind_model(child),
    )
}

fn authz_section_allowed(section: SectionKind) -> bool {
    matches!(
        section,
        SectionKind::Directory
            | SectionKind::DirectoryMatch
            | SectionKind::Location
            | SectionKind::Files
            | SectionKind::Proxy
            | SectionKind::Conditional
            | SectionKind::Require
    )
}

pub(crate) fn parse_fastcgi_policy_endpoint(raw: &str) -> Result<FastCgiEndpoint, String> {
    if let Some(path) = raw.strip_prefix("unix:") {
        let path = PathBuf::from(path);
        if path.as_os_str().is_empty() || !path.is_absolute() || raw.contains('|') {
            return Err("Unix FastCGI policy endpoints must be absolute socket paths".into());
        }
        if path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        }) {
            return Err("Unix FastCGI policy endpoints must use normal path components".into());
        }
        return Ok(FastCgiEndpoint::Unix(path));
    }

    let authority = raw
        .strip_prefix("fcgi://")
        .ok_or_else(|| "FastCGI policy endpoint must start with unix: or fcgi://".to_string())?;
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('@')
        || authority.contains('?')
        || authority.contains('#')
    {
        return Err("TCP FastCGI policy endpoint must contain only host[:port]".into());
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| "unterminated IPv6 FastCGI policy endpoint".to_string())?;
        let host = &rest[..close];
        let suffix = &rest[close + 1..];
        let port = if suffix.is_empty() {
            9000
        } else {
            suffix
                .strip_prefix(':')
                .ok_or_else(|| "invalid IPv6 FastCGI policy endpoint".to_string())?
                .parse::<u16>()
                .map_err(|_| "invalid FastCGI policy port".to_string())?
        };
        (host.to_ascii_lowercase(), port)
    } else {
        if authority.matches(':').count() > 1 {
            return Err("IPv6 FastCGI policy endpoints must use brackets".into());
        }
        match authority.rsplit_once(':') {
            Some((host, port)) => (
                host.to_ascii_lowercase(),
                port.parse::<u16>()
                    .map_err(|_| "invalid FastCGI policy port".to_string())?,
            ),
            None => (authority.to_ascii_lowercase(), 9000),
        }
    };
    if host.is_empty() || port == 0 {
        return Err("invalid TCP FastCGI policy endpoint".into());
    }
    Ok(FastCgiEndpoint::Tcp { host, port })
}

struct Compile {
    program: ConfigProgram,
    pos: usize,
    cfg: Config,
    warnings: Vec<String>,
    errors: Vec<ConfigError>,
    strict: bool,
    vhosts_raw: Vec<VHost>,
    current_vhost: Option<usize>,
    order: usize,
    current_balancer: Option<usize>,
    next_condition_chain: usize,
    next_route: usize,
    required_capabilities: Vec<(Capability, SourceLoc, String)>,
    capability_audit: bool,
    server_limit: Option<usize>,
    max_request_workers_set: bool,
}

impl Compile {
    fn new(p: ParserState, program: ConfigProgram, strict: bool, capability_audit: bool) -> Self {
        let server_root = p.initial_server_root.clone();
        let admin_file_trust = p.admin_file_trust;
        let admin_input_targets = p.admin_input_targets.clone();
        let config_defines: HashSet<String> = p.defines.keys().cloned().collect();
        let modules: Vec<String> = {
            let mut v: Vec<String> = p.modules.into_iter().collect();
            v.sort();
            v
        };
        let cfg = Config {
            server_root: server_root.clone(),
            server_name: None,
            server_admin: "you@example.com".into(),
            listeners: Vec::new(),
            user: "www-data".into(),
            group: "www-data".into(),
            pid_file: PathBuf::from("/run/apache2/apache2.pid"),
            error_log: "logs/error.log".into(),
            log_level: "warn".into(),
            keep_alive: true,
            keep_alive_timeout: Duration::from_secs(5),
            timeout: Duration::from_secs(60),
            max_keep_alive_requests: 100,
            server_tokens: ServerTokens::Full,
            server_signature: ServerSignature::On,
            protocols: vec![HttpProtocol::Http2, HttpProtocol::Http11],
            trace_enable: false,
            capabilities: Capabilities::default(),
            required_capabilities: Vec::new(),
            capability_audit_only: capability_audit,
            limit_request_line: 8190,
            limit_request_fields: 100,
            limit_request_field_size: 8190,
            limit_request_body: 1_073_741_824,
            max_request_workers: 512,
            listen_backlog: 511,
            graceful_shutdown_timeout: Duration::from_secs(30),
            request_header_timeout: Duration::from_secs(20),
            request_body_timeout: Duration::from_secs(30),
            request_header_min_rate: 0,
            request_body_min_rate: 0,
            encoded_slashes: EncodedSlashes::Off,
            vhosts: Vec::new(),
            vhost_index: Arc::new(VHostIndex::default()),
            global: Scope::default(),
            global_rules: Vec::new(),
            global_directory_index: DirectoryRuleIndex::default(),
            proxy_containers: Vec::new(),
            mime: MimeMap::new(),
            log_formats: HashMap::new(),
            custom_logs: Vec::new(),
            modules,
            config_defines,
            warnings: Vec::new(),
            balancers: Vec::new(),
            health_templates: HashMap::new(),
            remoteip_header: None,
            remoteip_proxies: Vec::new(),
            fastcgi_stable_paths: None,
            max_spool_bytes: 1024 * 1024 * 1024,
            max_spool_files: 128,
            max_dynamic_requests: 64,
            max_fastcgi_output: 64 * 1024 * 1024,
            resource_budget: Arc::new(crate::resource::ResourceBudget::default()),
            access_file_names: vec![".htaccess".into()],
            directory_index: vec!["index.html".into()],
            override_enabled: false,
            override_prefixes: Vec::new(),
            override_anywhere: false,
            body_handlers_possible: false,
            cgi_path_info_possible: false,
            document_root: server_root.join("htdocs"),
            default_charset: None,
            use_canonical_name: false,
            hostname_lookups: false,
            server_software: server_software_for_tokens(ServerTokens::Full),
            ssl: SslConfig::default(),
            cache: CacheConfig::default(),
            admin_file_trust,
            admin_input_targets,
            auth_file_targets: Vec::new(),
            policy_cache: Arc::new(RwLock::new(BoundedPolicyCache::default())),
            dir_scope_cache: Arc::new(RwLock::new(BoundedPolicyCache::default())),
        };
        Compile {
            program,
            pos: 0,
            cfg,
            warnings: p.warnings,
            errors: p.errors,
            strict,
            vhosts_raw: Vec::new(),
            current_vhost: None,
            order: 0,
            current_balancer: None,
            next_condition_chain: 0,
            next_route: 0,
            required_capabilities: Vec::new(),
            capability_audit,
            server_limit: None,
            max_request_workers_set: false,
        }
    }

    fn require_capability(
        &mut self,
        capability: Capability,
        loc: &SourceLoc,
        feature: impl Into<String>,
    ) {
        self.required_capabilities
            .push((capability, loc.clone(), feature.into()));
    }

    fn validate_capabilities(&mut self) {
        // FastCGI normally requires a strict endpoint/path policy.  Retaining
        // the historical pathname-only handoff is a separate, explicit
        // process-wide capability because the external backend reopens
        // SCRIPT_FILENAME after vapache's final inode check.
        if self.cfg.fastcgi_stable_paths.is_none() {
            let unstable: Vec<_> = self
                .required_capabilities
                .iter()
                .filter(|(capability, _, _)| *capability == Capability::FastCgi)
                .map(|(_, loc, feature)| {
                    (
                        Capability::UnstableFastCgiPaths,
                        loc.clone(),
                        format!("{feature} without VapacheFastCGIStablePath"),
                    )
                })
                .collect();
            self.required_capabilities.extend(unstable);
        }
        for (capability, loc, feature) in &self.required_capabilities {
            if !self.cfg.required_capabilities.contains(capability) {
                self.cfg.required_capabilities.push(*capability);
            }
            if !self.capability_audit && !self.cfg.capabilities.contains(*capability) {
                self.errors.push(ConfigError {
                    file: loc.file.clone(),
                    line: loc.line,
                    msg: format!(
                        "{feature} requires 'VapacheCapability {} On' in global server context",
                        capability.name()
                    ),
                });
            }
        }
    }

    fn warn(&mut self, msg: impl Into<String>) {
        let m = msg.into();
        if self.warnings.len() < 500 {
            self.warnings.push(m);
        }
    }

    /// Load one on-disk RewriteMap source (txt/rnd) fail-closed: a missing,
    /// unreadable or oversized map file is a configuration error instead of
    /// silently becoming an empty map (which would disable every rule gated
    /// on `${map:...}` lookups).
    fn load_rewritemap_file(
        &mut self,
        loc: &SourceLoc,
        name: &str,
        kind: &str,
        path: &Path,
    ) -> Option<String> {
        if !self
            .cfg
            .admin_input_targets
            .iter()
            .any(|known| known == path)
        {
            self.cfg.admin_input_targets.push(path.to_path_buf());
        }
        match crate::files::read_admin_file_with_trust(
            path,
            MAX_REWRITEMAP,
            self.cfg.admin_file_trust,
        ) {
            Ok(data) => match String::from_utf8(data) {
                Ok(data) => Some(data),
                Err(_) => {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: format!(
                            "RewriteMap '{name}': {kind} map file {} is not valid UTF-8",
                            path.display()
                        ),
                    });
                    None
                }
            },
            Err(e) => {
                self.errors.push(ConfigError {
                    file: loc.file.clone(),
                    line: loc.line,
                    msg: format!(
                        "RewriteMap '{name}': cannot read {kind} map file {}: {e}",
                        path.display()
                    ),
                });
                None
            }
        }
    }

    /// A recognized directive with malformed or unsupported effectful
    /// payload is always a configuration error. Apache rejects these during
    /// `-t`; accepting and dropping them can remove an intended route, ACL,
    /// handler, header, filter or audit control.
    fn directive_error(&mut self, loc: &SourceLoc, msg: impl Into<String>) {
        self.errors.push(ConfigError {
            file: loc.file.clone(),
            line: loc.line,
            msg: msg.into(),
        });
    }

    fn compile(mut self) -> Result<Config, ConfigError> {
        let mut scope = self.cfg.global.clone();
        let mut rules: Vec<ScopeRule> = Vec::new();
        self.walk(
            &mut scope,
            &mut rules,
            false,
            false,
            None,
            SectionKind::Server,
        );
        self.validate_capabilities();
        if let Some(e) = self.errors.into_iter().next() {
            return Err(e);
        }
        self.cfg.global = scope;
        sort_rules(&mut rules);
        self.cfg.global_directory_index = DirectoryRuleIndex::build(&rules);
        self.cfg.global_rules = rules;

        if self.cfg.listeners.is_empty() {
            self.cfg.listeners.push(ListenSpec {
                raw: "80".into(),
                addr: "0.0.0.0".into(),
                port: 80,
            });
        }
        // Normalize default document root.
        if let Some(dr) = &self.cfg.global.content_policy.document_root {
            self.cfg.document_root = dr.clone();
        }
        // P14-C: make the compiled-in ServerRoot/htdocs default an explicit
        // scope invariant too. Require-expr file predicates consume Scope,
        // so leaving this absent previously turned their confinement root
        // into the filesystem root.
        self.cfg.global.content_policy.document_root = Some(self.cfg.document_root.clone());

        let global_scope = self.cfg.global.clone();
        let global_rules = self.cfg.global_rules.clone();
        let global_ssl = self.cfg.ssl.clone();
        for v in &mut self.vhosts_raw {
            v.ports = v.addrs.iter().map(|a| vhost_port(a)).collect();
            v.scope = global_scope.clone();
            // Apache does not inherit server-level RewriteRules into a
            // virtual host (RewriteOptions Inherit is not implemented here).
            // Keep `<Directory>` rewrite rules in `v.rules`, but do not let a
            // server-level URL rule silently rewrite virtual-host traffic.
            if v.scope.rewrite_policy.rewrite_inherit != Some(true) {
                v.scope.rewrite_policy.rewrite_rules.clear();
                v.scope.rewrite_policy.rewrite_base = None;
                v.scope.rewrite_policy.rewrite_match_base = None;
            }
            v.scope.merge(&v.delta);
            let mut rules = global_rules.clone();
            rules.extend(v.rules.clone());
            sort_rules(&mut rules);
            v.directory_index = DirectoryRuleIndex::build(&rules);
            v.rules = rules;
            let mut proxy_containers = self.cfg.proxy_containers.clone();
            proxy_containers.extend(v.proxy_containers.clone());
            v.proxy_containers = proxy_containers;
            v.ssl.inherit(&global_ssl);
            if v.protocols.is_empty() {
                v.protocols = self.cfg.protocols.clone();
            }
            if v.error_log.is_none() {
                v.error_log = Some(self.cfg.error_log.clone());
            }
        }
        self.cfg.vhosts = self.vhosts_raw;
        let wildcard_patterns = self
            .cfg
            .vhosts
            .iter()
            .flat_map(|vhost| &vhost.aliases)
            .filter(|alias| alias.bytes().any(|byte| matches!(byte, b'*' | b'?')))
            .count();
        if wildcard_patterns > MAX_VHOST_WILDCARD_PATTERNS {
            return Err(ConfigError {
                file: String::new(),
                line: 0,
                msg: format!(
                    "virtual-host wildcard alias count {wildcard_patterns} exceeds the request-time bound of {MAX_VHOST_WILDCARD_PATTERNS}"
                ),
            });
        }
        self.cfg.vhost_index = Arc::new(VHostIndex::build(&self.cfg.vhosts, &self.cfg.listeners));
        let mut tls_inputs = Vec::new();
        let mut collect_tls = |ssl: &SslConfig| {
            tls_inputs.extend(
                [
                    ssl.cert_file.as_ref(),
                    ssl.key_file.as_ref(),
                    ssl.chain_file.as_ref(),
                    ssl.ca_file.as_ref(),
                    ssl.ca_revocation_file.as_ref(),
                ]
                .into_iter()
                .flatten()
                .cloned(),
            );
        };
        collect_tls(&self.cfg.ssl);
        for vhost in &self.cfg.vhosts {
            collect_tls(&vhost.ssl);
        }
        for path in tls_inputs {
            if !self
                .cfg
                .admin_input_targets
                .iter()
                .any(|known| known == &path)
            {
                self.cfg.admin_input_targets.push(path);
            }
        }
        self.cfg.warnings = std::mem::take(&mut self.warnings);
        Ok(self.cfg)
    }

    fn walk(
        &mut self,
        scope: &mut Scope,
        rules: &mut Vec<ScopeRule>,
        inside_vhost: bool,
        in_directory: bool,
        limit: Option<&MethodSet>,
        section: SectionKind,
    ) {
        // Tracks the most recent <If>/<IfFile> chain in this configuration
        // scope so a following <ElseIf>/<Else> can attach to it.
        let mut current_chain: Option<usize> = None;
        while self.pos < self.program.instructions.len() {
            let ev = self.program.instructions[self.pos].clone();
            self.pos += 1;
            match ev {
                ProgramEvent::SectionEnd { .. } => return,
                ProgramEvent::Directive {
                    identity,
                    payload,
                    loc,
                } => {
                    let name = identity.as_str();
                    if matches!(
                        name,
                        "include" | "includeoptional" | "loadmodule" | "define" | "undefine"
                    ) {
                        continue;
                    }
                    if section == SectionKind::Require && name != "require" {
                        self.errors.push(ConfigError {
                            file: loc.file.clone(),
                            line: loc.line,
                            msg: format!(
                                "only Require directives are allowed in a Require section"
                            ),
                        });
                        continue;
                    }
                    self.apply_directive(
                        &identity,
                        &payload,
                        &loc,
                        scope,
                        inside_vhost,
                        in_directory,
                        limit,
                        section,
                    );
                }
                ProgramEvent::SectionStart {
                    name,
                    class,
                    payload,
                    loc,
                    active,
                    transparent,
                    end: _,
                } => {
                    if !active {
                        self.skip_section();
                        continue;
                    }
                    if transparent {
                        // Conditional blocks are transparent: their directives
                        // have exactly the same scope as the surrounding text.
                        self.walk(scope, rules, inside_vhost, in_directory, limit, section);
                        continue;
                    }
                    if let Some(child) = section_kind(class) {
                        if !structural_section_allowed(section, child) {
                            self.errors.push(ConfigError {
                                file: loc.file.clone(),
                                line: loc.line,
                                msg: format!(
                                    "<{name}> is not allowed in this configuration context"
                                ),
                            });
                            self.skip_section();
                            continue;
                        }
                    }
                    match name.as_str() {
                        "if" | "iffile" | "elseif" | "else" => {
                            if limit.is_some() {
                                self.errors.push(ConfigError {
                                    file: loc.file.clone(),
                                    line: loc.line,
                                    msg: format!(
                                        "<{name}> is not allowed inside a method-limited section"
                                    ),
                                });
                                self.skip_section();
                                continue;
                            }
                            let (branch, chain, condition) = if name == "if" || name == "iffile" {
                                let ProgramSectionPayload::Expression(condition) = &payload else {
                                    unreachable!("sealed conditional section")
                                };
                                let chain = self.next_condition_chain;
                                self.next_condition_chain += 1;
                                current_chain = Some(chain);
                                (
                                    ConditionBranch::Normal,
                                    Some(chain),
                                    Some(condition.clone()),
                                )
                            } else {
                                let Some(chain) = current_chain else {
                                    self.errors.push(ConfigError {
                                        file: loc.file.clone(),
                                        line: loc.line,
                                        msg: format!(
                                            "<{name}> has no preceding <If> in this scope"
                                        ),
                                    });
                                    self.skip_section();
                                    continue;
                                };
                                if name == "elseif" {
                                    let ProgramSectionPayload::Expression(condition) = &payload
                                    else {
                                        unreachable!("sealed ElseIf expression")
                                    };
                                    (
                                        ConditionBranch::ElseIf,
                                        Some(chain),
                                        Some(condition.clone()),
                                    )
                                } else {
                                    current_chain = None;
                                    (ConditionBranch::Else, Some(chain), None)
                                }
                            };
                            let mut inner = Scope::default();
                            let mut inner_rules = Vec::new();
                            self.walk(
                                &mut inner,
                                &mut inner_rules,
                                inside_vhost,
                                true,
                                None,
                                SectionKind::Conditional,
                            );
                            if inner_rules
                                .iter()
                                .any(|rule| !matches!(rule.kind, MatchKind::Always))
                            {
                                self.directive_error(
                                    &loc,
                                    format!(
                                        "nested Directory/Files/Location sections inside <{name}> are not supported; refusing policy nesting Apache accepts but does not execute on ordinary requests"
                                    ),
                                );
                            }
                            self.order += 1;
                            rules.push(ScopeRule {
                                kind: MatchKind::Always,
                                delta: inner,
                                order: self.order,
                                condition,
                                branch,
                                chain,
                                nested: inner_rules,
                            });
                        }
                        "virtualhost" => {
                            let ProgramSectionPayload::Arguments(args) = payload else {
                                unreachable!("sealed VirtualHost arguments")
                            };
                            let vh = VHost {
                                addrs: args.into_vec(),
                                ports: Vec::new(),
                                server_name: None,
                                aliases: Vec::new(),
                                scope: Scope::default(),
                                delta: Scope::default(),
                                rules: Vec::new(),
                                directory_index: DirectoryRuleIndex::default(),
                                proxy_containers: Vec::new(),
                                custom_logs: Vec::new(),
                                error_log: None,
                                server_admin: None,
                                protocols: Vec::new(),
                                ssl: SslConfig::default(),
                            };
                            self.vhosts_raw.push(vh);
                            let idx = self.vhosts_raw.len() - 1;
                            let mut vdelta = Scope::default();
                            let mut vrules = Vec::new();
                            let prev = self.current_vhost.replace(idx);
                            self.walk(
                                &mut vdelta,
                                &mut vrules,
                                true,
                                false,
                                None,
                                SectionKind::VirtualHost,
                            );
                            self.current_vhost = prev;
                            self.vhosts_raw[idx].delta = vdelta;
                            self.vhosts_raw[idx].rules = vrules;
                        }
                        "directory" | "files" | "filesmatch" | "location" | "locationmatch"
                        | "directorymatch" => {
                            let kind = match &payload {
                                ProgramSectionPayload::Match(kind) => kind.clone(),
                                ProgramSectionPayload::DirectoryLiteral(path) => {
                                    let path = Path::new(path);
                                    let resolved = if path.is_absolute() {
                                        path.to_path_buf()
                                    } else {
                                        self.cfg.server_root.join(path)
                                    };
                                    MatchKind::Directory(clean_path(&resolved))
                                }
                                _ => unreachable!("sealed match section"),
                            };
                            let mut delta = Scope::default();
                            let mut nested = Vec::new();
                            let child_section = match name.as_str() {
                                "directorymatch" => SectionKind::DirectoryMatch,
                                "files" | "filesmatch" => SectionKind::Files,
                                "location" | "locationmatch" => SectionKind::Location,
                                _ => SectionKind::Directory,
                            };
                            self.walk(
                                &mut delta,
                                &mut nested,
                                inside_vhost,
                                true,
                                None,
                                child_section,
                            );
                            self.order += 1;
                            let order = self.order;
                            rules.push(ScopeRule {
                                kind,
                                delta,
                                order,
                                condition: None,
                                branch: ConditionBranch::Normal,
                                chain: None,
                                nested,
                            });
                        }
                        "requireall" | "requireany" | "requirenone" => {
                            if !authz_section_allowed(section) {
                                self.errors.push(ConfigError {
                                    file: loc.file.clone(),
                                    line: loc.line,
                                    msg: format!(
                                        "<{name}> requires a directory, location, files, or proxy context"
                                    ),
                                });
                                self.skip_section();
                                continue;
                            }
                            let mut inner = Scope::default();
                            let mut inner_rules = Vec::new();
                            self.walk(
                                &mut inner,
                                &mut inner_rules,
                                inside_vhost,
                                in_directory,
                                limit,
                                SectionKind::Require,
                            );
                            if !inner_rules.is_empty() {
                                self.directive_error(
                                    &loc,
                                    format!(
                                        "nested sections inside <{name}> are not supported; refusing to ignore their authorization policy"
                                    ),
                                );
                            }
                            let mut items = Vec::new();
                            let inner_entries = match inner.authorization.requires.take() {
                                Some(AuthPolicy::List(entries)) => entries,
                                _ => Vec::new(),
                            };
                            for entry in inner_entries {
                                if entry.limit.as_ref() != limit {
                                    self.errors.push(ConfigError {
                                        file: loc.file.clone(),
                                        line: loc.line,
                                        msg: format!(
                                            "nested method-limited sections are not allowed inside <{name}>"
                                        ),
                                    });
                                    continue;
                                }
                                items.push(entry.node);
                            }
                            let invalid_negative = match name.as_str() {
                                "requireall" => {
                                    !items.iter().any(|item| !require_node_is_negative(item))
                                }
                                "requireany" | "requirenone" => {
                                    items.iter().any(require_node_is_negative)
                                }
                                _ => false,
                            };
                            if invalid_negative {
                                self.errors.push(ConfigError {
                                    file: loc.file.clone(),
                                    line: loc.line,
                                    msg: format!(
                                        "<{name}> contains an authorization section with no positive provider"
                                    ),
                                });
                                continue;
                            }
                            let has_items = !items.is_empty();
                            let node = match name.as_str() {
                                "requireall" => RequireNode::All(items),
                                "requireany" => RequireNode::Any(items),
                                _ => RequireNode::None(items),
                            };
                            if has_items
                                && section != SectionKind::Require
                                && require_node_is_negative(&node)
                            {
                                self.errors.push(ConfigError {
                                    file: loc.file.clone(),
                                    line: loc.line,
                                    msg: format!("<{name}> has no effect in <RequireAny>"),
                                });
                            } else if has_items {
                                scope.add_require(node, limit);
                            } else {
                                self.errors.push(ConfigError {
                                    file: loc.file.clone(),
                                    line: loc.line,
                                    msg: format!(
                                        "<{name}> directive contains no authorization directives"
                                    ),
                                });
                            }
                        }
                        "limit" | "limitexcept" => {
                            if !in_directory && limit.is_none() {
                                self.errors.push(ConfigError {
                                    file: loc.file.clone(),
                                    line: loc.line,
                                    msg: format!("<{name}> is only allowed in directory context"),
                                });
                                self.skip_section();
                                continue;
                            }
                            let ProgramSectionPayload::Methods(methods) = &payload else {
                                unreachable!("sealed method section")
                            };
                            let combined = match limit {
                                Some(outer) => outer.intersect(&methods),
                                None => methods.clone(),
                            };
                            if combined.is_empty() {
                                self.errors.push(ConfigError {
                                    file: loc.file.clone(),
                                    line: loc.line,
                                    msg: format!("nested <{name}> excludes every HTTP method"),
                                });
                                self.skip_section();
                                continue;
                            }
                            if matches!(limit, Some(outer) if combined == *outer) {
                                self.errors.push(ConfigError {
                                    file: loc.file.clone(),
                                    line: loc.line,
                                    msg: format!(
                                        "nested <{name}> does not further restrict the enclosing method set"
                                    ),
                                });
                                self.skip_section();
                                continue;
                            }
                            self.walk(
                                scope,
                                rules,
                                inside_vhost,
                                in_directory,
                                Some(&combined),
                                section,
                            );
                        }
                        "proxy" | "proxymatch" => {
                            let (pattern, kind) = match &payload {
                                ProgramSectionPayload::ProxyWildcard(pattern) => {
                                    (pattern.clone(), ProxyMatchKind::Wildcard(pattern.clone()))
                                }
                                ProgramSectionPayload::ProxyRegex(regex) => {
                                    (String::new(), ProxyMatchKind::Regex(regex.clone()))
                                }
                                _ => unreachable!("sealed Proxy section"),
                            };
                            if inside_vhost && name == "proxy" && pattern.starts_with("balancer://")
                            {
                                self.errors.push(ConfigError {
                                    file: loc.file.clone(),
                                    line: loc.line,
                                    msg: "virtual-host balancer definitions are not implemented; refusing to expose a vhost-local balancer globally".into(),
                                });
                                self.skip_section();
                                continue;
                            }
                            let mut balancer_prev = None;
                            let mut balancer_created = false;
                            if name == "proxy" {
                                if let Some(balancer) = pattern.strip_prefix("balancer://") {
                                    balancer_created = true;
                                    let balancer = balancer.trim_end_matches('/').to_string();
                                    self.cfg.balancers.push(Balancer {
                                        name: balancer,
                                        members: Vec::new(),
                                        health: HealthTemplate::default(),
                                        sticky_cookie: None,
                                        sticky_sep: None,
                                        fail_on_status: Vec::new(),
                                    });
                                    let idx = self.cfg.balancers.len() - 1;
                                    balancer_prev = self.current_balancer.replace(idx);
                                }
                            }
                            let mut delta = Scope::default();
                            let mut inner_rules = Vec::new();
                            self.walk(
                                &mut delta,
                                &mut inner_rules,
                                inside_vhost,
                                true,
                                None,
                                SectionKind::Proxy,
                            );
                            if balancer_created {
                                self.current_balancer = balancer_prev;
                            }
                            self.order += 1;
                            let container = ProxyContainer {
                                kind,
                                delta,
                                rules: inner_rules,
                                order: self.order,
                            };
                            if let Some(idx) = self.current_vhost {
                                self.vhosts_raw[idx].proxy_containers.push(container);
                            } else {
                                self.cfg.proxy_containers.push(container);
                            }
                        }
                        _ => {
                            if limit.is_some() {
                                self.errors.push(ConfigError {
                                    file: loc.file.clone(),
                                    line: loc.line,
                                    msg: format!(
                                        "<{name}> is not allowed inside a method-limited section"
                                    ),
                                });
                                self.skip_section();
                                continue;
                            }
                            // Inventing transparent semantics for an unknown
                            // container can turn its conditional grant into an
                            // unconditional one. Apache refuses unknown
                            // sections, so fail the configuration too.
                            self.errors.push(ConfigError {
                                file: loc.file.clone(),
                                line: loc.line,
                                msg: format!("unsupported section <{name}>"),
                            });
                            self.skip_section();
                        }
                    }
                }
            }
        }
    }

    fn skip_section(&mut self) {
        let Some(ProgramEvent::SectionStart { end, .. }) = self
            .pos
            .checked_sub(1)
            .and_then(|start| self.program.instructions.get(start))
        else {
            debug_assert!(
                false,
                "skip_section must immediately follow a section start"
            );
            return;
        };
        let Some(ProgramEvent::SectionEnd { start, .. }) = self.program.instructions.get(*end)
        else {
            debug_assert!(false, "sealed section end must exist");
            return;
        };
        debug_assert_eq!(*start, self.pos - 1);
        self.pos = *end + 1;
    }

    fn directive_disposition(
        &self,
        identity: &DirectiveIdentity,
    ) -> vapache_verified::DirectiveDisposition {
        vapache_verified::directive_disposition(
            identity.security_sensitive,
            identity.apache_known,
            self.strict,
        )
    }

    fn apply_directive(
        &mut self,
        identity: &DirectiveIdentity,
        payload: &SealedPayload,
        loc: &SourceLoc,
        scope: &mut Scope,
        inside_vhost: bool,
        in_directory: bool,
        limit: Option<&MethodSet>,
        section: SectionKind,
    ) {
        let args = payload.as_slice();
        let name = identity.as_str();
        // Some Apache directives are scoped per-vhost or per-directory, but
        // Vapache currently stores their value in the process-wide Config.
        // Accepting those forms would let the last unrelated scope overwrite
        // every other scope. Until the storage is scoped, admit only the
        // global form rather than silently broadening its effect.
        if matches!(
            name,
            "listen"
                | "user"
                | "group"
                | "pidfile"
                | "loglevel"
                | "logformat"
                | "remoteipheader"
                | "remoteipinternalproxy"
                | "remoteiptrustedproxy"
                | "timeout"
                | "keepalive"
                | "keepalivetimeout"
                | "maxkeepaliverequests"
                | "hostnamelookups"
                | "usecanonicalname"
                | "servertokens"
                | "serversignature"
                | "traceenable"
                | "limitrequestline"
                | "limitrequestfields"
                | "limitrequestfieldsize"
                | "maxrequestworkers"
                | "serverlimit"
                | "listenbacklog"
                | "gracefulshutdowntimeout"
                | "requestreadtimeout"
                | "limitrequestbody"
                | "allowencodedslashes"
                | "typesconfig"
                | "addencoding"
                | "cacheroot"
                | "cachedefaultexpire"
                | "cachemaxexpire"
                | "cacheminexpire"
                | "cachemaxfilesize"
                | "cachemaxdisksize"
                | "cachemaxmemorysize"
                | "cacheminsize"
                | "cacheignorenolastmod"
                | "cacheignorecachecontrol"
                | "cachestorenostore"
                | "cachestoreprivate"
                | "cacheignorequerystring"
                | "cacheheader"
                | "cachedetailheader"
                | "cachelastmodifiedfactor"
                | "proxyhctemplate"
        ) && (section != SectionKind::Server || inside_vhost)
        {
            self.directive_error(
                loc,
                format!(
                    "directive '{name}' is not supported outside global server context; refusing to globalize a scoped Apache value"
                ),
            );
            return;
        }
        if matches!(name, "cacheenable" | "cachedisable")
            && !vapache_verified::cache_base_scope_admit(matches!(
                section,
                SectionKind::Server | SectionKind::VirtualHost
            ))
        {
            self.directive_error(
                loc,
                format!("directive '{name}' is only supported in server or virtual-host context"),
            );
            return;
        }
        if matches!(
            name,
            "servername"
                | "serveradmin"
                | "documentroot"
                | "errorlog"
                | "accessfilename"
                | "alias"
                | "scriptalias"
                | "aliasmatch"
                | "scriptaliasmatch"
                | "rewritemap"
                | "proxypass"
                | "proxypassreverse"
                | "proxypassmatch"
                | "customlog"
                | "sslengine"
                | "sslcertificatefile"
                | "sslcertificatekeyfile"
                | "sslcertificatechainfile"
                | "sslusestapling"
                | "sslstaplingforceurl"
                | "sslstaplingrespondertimeout"
                | "sslstaplingstandardcachetimeout"
                | "sslstaplingreturnrespondererrors"
                | "sslstaplingcache"
                | "sslrandomseed"
                | "sslpassphrasedialog"
                | "sslsessioncache"
                | "sslsessioncachetimeout"
                | "sslsessiontickets"
                | "sslhonorcipherorder"
                | "sslverifyclient"
                | "sslcacertificatefile"
                | "sslcarevocationfile"
                | "sslcarevocationcheck"
                | "sslprotocol"
                | "sslciphersuite"
                | "sslciphersuitetls13"
        ) && !matches!(section, SectionKind::Server | SectionKind::VirtualHost)
        {
            self.directive_error(
                loc,
                format!("directive '{name}' is only supported in server or virtual-host context"),
            );
            return;
        }
        // Directives accepted inside <Limit> must not be warned-and-ignored:
        // Apache applies Options/Header/AddHandler/SetHandler there, and a
        // discarded `Options -ExecCGI` is a remote-execution bypass (F40).
        // Auth-only directives below consume `limit`; every other directive is
        // applied to the enclosing scope exactly as Apache applies it.
        if matches!(name, "sslverifyclient" | "sslcacertificatefile")
            && !matches!(section, SectionKind::Server | SectionKind::VirtualHost)
        {
            self.errors.push(ConfigError {
                file: loc.file.clone(),
                line: loc.line,
                msg: format!(
                    "'{name}' is not supported in a per-location context; Rustls applies client                      authentication to the whole TLS connection"
                ),
            });
            return;
        }
        if matches!(section, SectionKind::Server | SectionKind::VirtualHost)
            && matches!(
                name,
                "require"
                    | "order"
                    | "allow"
                    | "deny"
                    | "satisfy"
                    | "authtype"
                    | "authname"
                    | "authuserfile"
                    | "authgroupfile"
                    | "authbasicprovider"
                    | "authmerging"
            )
        {
            self.errors.push(ConfigError {
                file: loc.file.clone(),
                line: loc.line,
                msg: format!("directive '{name}' is not allowed in this configuration context"),
            });
            return;
        }
        let first = || args.first().cloned().unwrap_or_default();
        let joined = || args.join(" ");
        match name {
            "vapachecapability" => {
                if section != SectionKind::Server || inside_vhost {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "VapacheCapability is only allowed in global server context".into(),
                    });
                    return;
                }
                if args.len() != 2 {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "VapacheCapability requires '<name> On|Off'".into(),
                    });
                    return;
                }
                let Some(capability) = Capability::parse(&args[0]) else {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: format!("unknown vapache capability '{}'", args[0]),
                    });
                    return;
                };
                let enabled = if args[1].eq_ignore_ascii_case("on") {
                    true
                } else if args[1].eq_ignore_ascii_case("off") {
                    false
                } else {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "VapacheCapability requires On or Off".into(),
                    });
                    return;
                };
                self.cfg.capabilities.set(capability, enabled);
            }
            "serverroot" => {
                if let Some(a) = args.first() {
                    self.cfg.server_root = PathBuf::from(a);
                }
            }
            "vapachefastcgistablepath" => {
                if section != SectionKind::Server || inside_vhost {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "VapacheFastCGIStablePath is only allowed in global server context"
                            .into(),
                    });
                    return;
                }
                if args.len() == 1 && args[0].eq_ignore_ascii_case("off") {
                    self.cfg.fastcgi_stable_paths = None;
                    return;
                }
                if args.len() < 5 || !args[0].eq_ignore_ascii_case("on") {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "VapacheFastCGIStablePath requires 'Off' or 'On <unix-endpoint> <backend-uid> <endpoint-owner-uid> <trusted-owner-uid>...'".into(),
                    });
                    return;
                }
                let endpoint = match parse_fastcgi_policy_endpoint(&args[1]) {
                    Ok(endpoint) => endpoint,
                    Err(msg) => {
                        self.errors.push(ConfigError {
                            file: loc.file.clone(),
                            line: loc.line,
                            msg,
                        });
                        return;
                    }
                };
                if matches!(endpoint, FastCgiEndpoint::Tcp { .. }) {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "VapacheFastCGIStablePath requires a Unix socket; TCP cannot authenticate the backend process".into(),
                    });
                    return;
                }
                let Ok(backend_uid) = args[2].parse::<u32>() else {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: format!("invalid FastCGI backend uid '{}'", args[2]),
                    });
                    return;
                };
                if backend_uid == 0 {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "VapacheFastCGIStablePath rejects uid 0 backends".into(),
                    });
                    return;
                }
                let endpoint_owner_uid = match args[3].parse::<u32>() {
                    Ok(uid) => Some(uid),
                    Err(_) => {
                        self.errors.push(ConfigError {
                            file: loc.file.clone(),
                            line: loc.line,
                            msg: format!("invalid Unix FastCGI endpoint-owner uid '{}'", args[3]),
                        });
                        return;
                    }
                };
                let mut trusted_owner_uids = Vec::new();
                for raw in &args[4..] {
                    let Ok(uid) = raw.parse::<u32>() else {
                        self.errors.push(ConfigError {
                            file: loc.file.clone(),
                            line: loc.line,
                            msg: format!("invalid trusted path-owner uid '{raw}'"),
                        });
                        return;
                    };
                    if !trusted_owner_uids.contains(&uid) {
                        trusted_owner_uids.push(uid);
                    }
                }
                let policies = self.cfg.fastcgi_stable_paths.get_or_insert_with(Vec::new);
                if policies.iter().any(|policy| policy.endpoint == endpoint) {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: format!("duplicate FastCGI stable-path endpoint '{}'", args[1]),
                    });
                    return;
                }
                policies.push(FastCgiStablePathPolicy {
                    endpoint,
                    backend_uid,
                    endpoint_owner_uid,
                    trusted_owner_uids,
                });
            }
            "vapachemaxspoolbytes"
            | "vapachemaxspoolfiles"
            | "vapachemaxdynamicrequests"
            | "vapachemaxfastcgioutput" => {
                if section != SectionKind::Server || inside_vhost {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: format!("{name} is only allowed in global server context"),
                    });
                    return;
                }
                let value = payload
                    .unsigned()
                    .expect("resource limits are typed while sealing");
                match name {
                    "vapachemaxspoolbytes" => self.cfg.max_spool_bytes = value,
                    "vapachemaxspoolfiles" => self.cfg.max_spool_files = value,
                    "vapachemaxdynamicrequests" => self.cfg.max_dynamic_requests = value,
                    "vapachemaxfastcgioutput" => self.cfg.max_fastcgi_output = value,
                    _ => unreachable!(),
                }
            }
            "protocols" => {
                if !matches!(section, SectionKind::Server | SectionKind::VirtualHost) {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "Protocols is only allowed in server or virtual-host context".into(),
                    });
                    return;
                }
                let protocols = payload
                    .http_protocols()
                    .expect("Protocols is compiled while sealing")
                    .to_vec();
                if let Some(i) = self.current_vhost {
                    self.vhosts_raw[i].protocols = protocols;
                } else {
                    self.cfg.protocols = protocols;
                }
            }
            "servername" => {
                let v = first();
                if inside_vhost {
                    if let Some(i) = self.current_vhost {
                        self.vhosts_raw[i].server_name = Some(v);
                    }
                } else {
                    self.cfg.server_name = Some(v);
                }
            }
            "serveralias" => {
                let Some(i) = self.current_vhost else {
                    self.directive_error(
                        loc,
                        "ServerAlias is only valid inside <VirtualHost>",
                    );
                    return;
                };
                for alias in args {
                    let wildcard = alias.contains('*') || alias.contains('?');
                    let supported_wildcard = alias == "*"
                        || alias.strip_prefix("*.").is_some_and(|suffix| {
                            !suffix.is_empty() && !suffix.contains('*') && !suffix.contains('?')
                        });
                    if wildcard && !supported_wildcard {
                        self.directive_error(
                            loc,
                            format!(
                                "ServerAlias wildcard '{alias}' is not implemented; only '*' or a leading '*.suffix' wildcard is supported"
                            ),
                        );
                    } else {
                        self.vhosts_raw[i].aliases.push(alias.clone());
                    }
                }
            }
            "serveradmin" => {
                let v = first();
                if let Some(i) = self.current_vhost {
                    self.vhosts_raw[i].server_admin = Some(v);
                } else {
                    self.cfg.server_admin = v;
                }
            }
            "documentroot" => {
                let p = PathBuf::from(first());
                scope.content_policy.document_root = Some(if p.is_absolute() {
                    clean_path(&p)
                } else {
                    clean_path(&self.cfg.server_root.join(p))
                });
            }
            "directoryindex" => {
                scope.content_policy.directory_index = Some(args.to_vec());
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
            "options" => {
                let options = payload
                    .options()
                    .expect("Options is compiled while sealing");
                if options.requires_autoindex {
                    self.require_capability(Capability::AutoIndex, loc, "Options Indexes/All");
                }
                if options.requires_cgi {
                    self.require_capability(Capability::Cgi, loc, "Options ExecCGI/All");
                }
                scope.options.merge_child(&options.policy);
            }
            "allowoverride" => {
                if section != SectionKind::Directory {
                    if matches!(section, SectionKind::Server | SectionKind::VirtualHost) {
                        self.errors.push(ConfigError {
                            file: loc.file.clone(),
                            line: loc.line,
                            msg: "AllowOverride is only allowed in <Directory>".into(),
                        });
                    } else {
                        self.warn(format!(
                            "{}:{}: useless use of AllowOverride outside <Directory> (ignored)",
                            loc.file, loc.line
                        ));
                    }
                    return;
                }
                let mut all = false;
                let mut none = false;
                let mut nonfatal = NonfatalMode::None;
                let mut flags = OverrideCategories::empty();
                let mut unknown = Vec::new();
                let mut invalid_options = Vec::new();
                for a in args {
                    let lower = a.to_ascii_lowercase();
                    if let Some(mode) = lower.strip_prefix("nonfatal=") {
                        nonfatal = match mode {
                            "override" => NonfatalMode::Override,
                            "unknown" => NonfatalMode::Unknown,
                            "all" => NonfatalMode::All,
                            _ => {
                                self.errors.push(ConfigError {
                                    file: loc.file.clone(),
                                    line: loc.line,
                                    msg: format!("invalid Nonfatal mode '{mode}'"),
                                });
                                NonfatalMode::None
                            }
                        };
                        continue;
                    }
                    if let Some(list) = lower.strip_prefix("options=") {
                        if list.is_empty() {
                            invalid_options.push(a.clone());
                            continue;
                        }
                        for option in list.split(',') {
                            match option {
                                "all" => flags.0 |= OverrideCategories::OPTIONS,
                                "none" => flags.0 |= OverrideCategories::OPT_NONE,
                                "execcgi" => flags.0 |= OverrideCategories::EXEC_CGI,
                                "includes" => flags.0 |= OverrideCategories::INCLUDES,
                                "includesnoexec" => flags.0 |= OverrideCategories::INCLUDES_NOEXEC,
                                "followsymlinks" => {
                                    flags.0 |= OverrideCategories::OPT_FOLLOW_SYMLINKS
                                }
                                "indexes" => flags.0 |= OverrideCategories::OPT_INDEXES,
                                "multiviews" => flags.0 |= OverrideCategories::OPT_MULTIVIEWS,
                                "symlinksifownermatch" => {
                                    flags.0 |= OverrideCategories::OPT_SYMLINKS_IF_OWNER_MATCH
                                }
                                _ => invalid_options.push(a.clone()),
                            }
                        }
                        continue;
                    }
                    match lower.as_str() {
                        "all" => all = true,
                        "none" => none = true,
                        "authconfig" => flags.0 |= OverrideCategories::AUTH_CONFIG,
                        "fileinfo" => flags.0 |= OverrideCategories::FILE_INFO,
                        "indexes" => flags.0 |= OverrideCategories::INDEXES,
                        "limit" => flags.0 |= OverrideCategories::LIMIT,
                        "options" => flags.0 |= OverrideCategories::OPTIONS,
                        // Older Apache documentation/versions used these as
                        // standalone categories.  Keep them as aliases for
                        // the equivalent modern Options=... form.
                        "execcgi" => flags.0 |= OverrideCategories::EXEC_CGI,
                        "includes" => flags.0 |= OverrideCategories::INCLUDES,
                        "includesnoexec" => flags.0 |= OverrideCategories::INCLUDES_NOEXEC,
                        "languagepriority" => flags.0 |= OverrideCategories::LANGUAGE_PRIORITY,
                        other => unknown.push(other.to_string()),
                    }
                }
                for option in invalid_options {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: format!("invalid AllowOverride option '{option}'"),
                    });
                }
                scope.override_policy.set_mode(if all {
                    OverrideMode::All
                } else if none || flags.0 == 0 {
                    OverrideMode::None
                } else {
                    OverrideMode::Categories(flags)
                });
                if all || (!none && flags.0 != 0) {
                    self.require_capability(Capability::AccessFiles, loc, "enabled AllowOverride");
                }
                scope.override_policy.set_nonfatal(nonfatal);
                if !all && !none && flags.0 == 0 {
                    // Silently turning all overrides off here would make a
                    // misspelled category bypass Require directives in a
                    // .htaccess file.  Fail closed instead, matching Apache.
                    let msg = if args.is_empty() {
                        "AllowOverride requires at least one category".to_string()
                    } else {
                        "AllowOverride has no supported categories".to_string()
                    };
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg,
                    });
                } else {
                    for u in unknown {
                        self.directive_error(
                            loc,
                            format!("unsupported AllowOverride category '{u}'"),
                        );
                    }
                }
            }
            "allowoverridelist" => {
                if section != SectionKind::Directory {
                    if matches!(section, SectionKind::Server | SectionKind::VirtualHost) {
                        self.errors.push(ConfigError {
                            file: loc.file.clone(),
                            line: loc.line,
                            msg: "AllowOverrideList is only allowed in <Directory>".into(),
                        });
                    } else {
                        self.warn(format!(
                            "{}:{}: useless use of AllowOverrideList outside <Directory> (ignored)",
                            loc.file, loc.line
                        ));
                    }
                    return;
                }
                if args.is_empty() {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "AllowOverrideList requires None or directive names".into(),
                    });
                    return;
                }
                let mut none = false;
                let mut list = Vec::new();
                for arg in args {
                    if arg.eq_ignore_ascii_case("none") {
                        none = true;
                    } else {
                        list.push(arg.clone());
                    }
                }
                if none && !list.is_empty() {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "AllowOverrideList None cannot be combined with directive names"
                            .into(),
                    });
                    return;
                }
                scope
                    .override_policy
                    .set_allow_list(if none { Vec::new() } else { list });
                if !none {
                    self.require_capability(
                        Capability::AccessFiles,
                        loc,
                        "enabled AllowOverrideList",
                    );
                }
            }
            "require" => {
                let provider = payload
                    .require()
                    .expect("Require is compiled while sealing")
                    .clone();
                if section != SectionKind::Require && require_is_negated(&provider) {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "negative Require directive has no effect in <RequireAny>".into(),
                    });
                    return;
                }
                scope.add_require(RequireNode::Provider(provider), limit);
            }
            "order" => {
                self.require_capability(Capability::LegacyAuthz, loc, "Order");
                let order = match payload.keyword().expect("Order is typed while sealing") {
                    0 | 1 => Order::AllowDeny,
                    2 => Order::DenyAllow,
                    _ => unreachable!("sealed Order keyword index"),
                };
                scope.add_order(order, limit);
            }
            "allow" | "deny" => {
                self.require_capability(Capability::LegacyAuthz, loc, name);
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
            "errordocument" => {
                let (code, document) = payload
                    .error_document()
                    .expect("ErrorDocument is compiled while sealing");
                scope.error_policy.documents.push((code, document.clone()));
            }
            "alias" | "scriptalias" => {
                if args.len() < 2 {
                    return;
                }
                let vpath = args[0].clone();
                if name == "scriptalias" {
                    self.require_capability(Capability::Cgi, loc, "ScriptAlias");
                }
                let mut fpath = PathBuf::from(&args[1]);
                if !fpath.is_absolute() {
                    fpath = self.cfg.server_root.join(fpath);
                }
                scope.mapping_policy.aliases.push(Alias::prefix(
                    vpath,
                    clean_path(&fpath),
                    name == "scriptalias",
                ));
            }
            "aliasmatch" | "scriptaliasmatch" => {
                if name == "scriptaliasmatch" {
                    self.require_capability(Capability::Cgi, loc, "ScriptAliasMatch");
                }
                let alias = payload
                    .alias_regex()
                    .expect("regex alias is compiled while sealing");
                scope.mapping_policy.aliases.push(Alias::regex(
                    alias.pattern.clone(),
                    alias.target.clone(),
                    name == "scriptaliasmatch",
                    &self.cfg.server_root,
                ));
            }
            "redirectmatch" => {
                scope.mapping_policy.redirects.push(
                    payload
                        .redirect()
                        .expect("RedirectMatch is compiled while sealing")
                        .clone(),
                );
            }
            "redirect" | "redirectpermanent" | "redirecttemp" => {
                scope.mapping_policy.redirects.push(
                    payload
                        .redirect()
                        .expect("Redirect is compiled while sealing")
                        .clone(),
                );
            }
            "rewritemap" => {
                if args.len() < 2 {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "RewriteMap requires a name and a map source".into(),
                    });
                    return;
                }
                let name = args[0].clone();
                let (kind, source) = args[1].split_once(':').unwrap_or(("txt", &args[1]));
                match kind.to_ascii_lowercase().as_str() {
                    "txt" => {
                        let path = if source.starts_with('/') {
                            PathBuf::from(source)
                        } else {
                            self.cfg.server_root.join(source)
                        };
                        let Some(data) = self.load_rewritemap_file(loc, &name, "txt", &path) else {
                            return;
                        };
                        let mut map = HashMap::new();
                        for line in data.lines() {
                            let line = line.trim();
                            if line.is_empty() || line.starts_with('#') {
                                continue;
                            }
                            let Some((k, v)) = line.split_once(char::is_whitespace) else {
                                continue;
                            };
                            map.insert(k.to_string(), v.trim().to_string());
                        }
                        scope
                            .rewrite_policy
                            .rewrite_maps
                            .push((name, RewriteMap::Txt(map)));
                    }
                    "rnd" => {
                        let path = if source.starts_with('/') {
                            PathBuf::from(source)
                        } else {
                            self.cfg.server_root.join(source)
                        };
                        let Some(data) = self.load_rewritemap_file(loc, &name, "rnd", &path) else {
                            return;
                        };
                        let mut map = HashMap::new();
                        for line in data.lines() {
                            let line = line.trim();
                            if line.is_empty() || line.starts_with('#') {
                                continue;
                            }
                            let Some((k, v)) = line.split_once(char::is_whitespace) else {
                                continue;
                            };
                            let choices = v
                                .trim()
                                .split('|')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect::<Vec<_>>();
                            map.insert(k.to_string(), choices);
                        }
                        scope
                            .rewrite_policy
                            .rewrite_maps
                            .push((name, RewriteMap::Rnd(map)));
                    }
                    "prg" => {
                        self.require_capability(Capability::RewriteProgram, loc, "RewriteMap prg");
                        // Resolve and retain the executable descriptor at load
                        // time. Runtime execution uses that descriptor and
                        // refuses a pathname/version mismatch, so replacing a
                        // validated helper cannot redirect a later request to
                        // attacker code.
                        let (program, args_rest) = match source.split_once(char::is_whitespace) {
                            Some((p, r)) => (p, r.split_whitespace().map(str::to_string).collect()),
                            None => (source, Vec::new()),
                        };
                        let prog_path = if program.starts_with('/') {
                            PathBuf::from(program)
                        } else {
                            self.cfg.server_root.join(program)
                        };
                        let program = match RewriteProgram::bind_with_trust(
                            prog_path.clone(),
                            args_rest,
                            self.cfg.admin_file_trust,
                        ) {
                            Ok(program) => program,
                            Err(error) => {
                                self.errors.push(ConfigError {
                                    file: loc.file.clone(),
                                    line: loc.line,
                                    msg: format!(
                                        "RewriteMap '{name}': prg program {} {error}",
                                        prog_path.display()
                                    ),
                                });
                                return;
                            }
                        };
                        if let Some(trusted) = &program.admin_trust_path {
                            if !self
                                .cfg
                                .admin_input_targets
                                .iter()
                                .any(|known| known == trusted)
                            {
                                self.cfg.admin_input_targets.push(trusted.clone());
                            }
                        }
                        scope
                            .rewrite_policy
                            .rewrite_maps
                            .push((name, RewriteMap::Prg(program)));
                    }
                    "int" => {
                        let function = source.to_ascii_lowercase();
                        if !matches!(
                            function.as_str(),
                            "tolower" | "toupper" | "escape" | "unescape"
                        ) {
                            self.errors.push(ConfigError {
                                file: loc.file.clone(),
                                line: loc.line,
                                msg: format!(
                                    "unsupported RewriteMap int function '{source}' (expected tolower, toupper, escape or unescape)"
                                ),
                            });
                            return;
                        }
                        scope
                            .rewrite_policy
                            .rewrite_maps
                            .push((name, RewriteMap::Int(function)));
                    }
                    _ => self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: format!("unsupported RewriteMap type '{kind}'"),
                    }),
                }
            }
            "rewriteengine" => {
                scope.rewrite_policy.rewrite_engine = Some(
                    payload
                        .on_off()
                        .expect("RewriteEngine is typed while sealing"),
                );
            }
            "rewritebase" => {
                scope.rewrite_policy.rewrite_base = Some(normalize_rewrite_base(&first()));
            }
            "rewritecond" => scope
                .rewrite_policy
                .pending_rewrite_conds
                .push(
                    payload
                        .rewrite_cond()
                        .expect("RewriteCond is compiled while sealing")
                        .clone(),
                ),
            "rewriterule" => {
                let base = scope.rewrite_policy.rewrite_base.as_deref().unwrap_or("/");
                let mut rule = payload
                    .rewrite_rule()
                    .expect("RewriteRule is compiled while sealing")
                    .clone();
                rule.base = normalize_rewrite_base(base);
                rule.match_base = rule.base.clone();
                // Certbot's Apache HTTP-01 performer writes this exact trusted
                // server-context rule. Add an equivalent regex Alias without
                // relaxing arbitrary absolute rewrite targets (CVE-2024-38475).
                let certbot_http01_alias = args.len() == 3
                    && args[0] == r"^/\.well-known/acme-challenge/([A-Za-z0-9-_=]+)$"
                    && args[2].eq_ignore_ascii_case("[END]")
                    && rule.substitution == "/var/lib/letsencrypt/http_challenges/$1"
                    && scope.rewrite_policy.pending_rewrite_conds.is_empty();
                if let Some(handler) = rule.flags.handler.as_deref() {
                    if handler.eq_ignore_ascii_case("cgi-script") {
                        self.require_capability(
                            Capability::Cgi,
                            loc,
                            "RewriteRule cgi-script handler",
                        );
                    }
                    if handler.eq_ignore_ascii_case("server-status") {
                        self.require_capability(
                            Capability::ServerStatus,
                            loc,
                            "RewriteRule server-status handler",
                        );
                    }
                    if handler.to_ascii_lowercase().contains("fcgi://") {
                        self.require_capability(
                            Capability::FastCgi,
                            loc,
                            "RewriteRule FastCGI handler",
                        );
                    }
                }
                if rule.flags.unsafe_prefix_stat {
                    self.warn(format!(
                        "{}:{}: [UnsafePrefixStat] is accepted for compatibility and has no effect",
                        loc.file, loc.line
                    ));
                }
                rule.conditions = std::mem::take(&mut scope.rewrite_policy.pending_rewrite_conds);
                if certbot_http01_alias {
                    scope.mapping_policy.aliases.push(Alias::regex(
                        rule.pattern.clone(),
                        rule.substitution.clone(),
                        false,
                        &self.cfg.server_root,
                    ));
                }
                scope.rewrite_policy.rewrite_rules.push(rule);
            }
            "rewriteoptions" => {
                scope.rewrite_policy.rewrite_inherit = Some(true);
            }
            "addtype" => {
                if args.len() < 2 {
                    self.directive_error(
                        loc,
                        "AddType requires a MIME-type and one or more extensions",
                    );
                    return;
                }
                scope
                    .content_policy
                    .add_types
                    .push((args[0].clone(), args[1..].join(" ")));
            }
            "removetype" => {
                scope
                    .content_policy
                    .remove_types
                    .extend(args.iter().cloned());
            }
            "addhandler" => {
                if args.len() < 2 {
                    self.directive_error(
                        loc,
                        "AddHandler requires a handler-name and one or more extensions",
                    );
                    return;
                }
                if args[0].eq_ignore_ascii_case("cgi-script") {
                    self.require_capability(Capability::Cgi, loc, "AddHandler cgi-script");
                }
                if args[0].eq_ignore_ascii_case("server-status") {
                    self.require_capability(
                        Capability::ServerStatus,
                        loc,
                        "AddHandler server-status",
                    );
                }
                if args[0].to_ascii_lowercase().contains("fcgi://") {
                    self.require_capability(Capability::FastCgi, loc, "AddHandler FastCGI");
                }
                for ext in &args[1..] {
                    scope.mapping_policy.handlers.push(Handler::add(
                        normalize_handler_extension(ext),
                        args[0].clone(),
                    ));
                }
            }
            "removehandler" => {
                for ext in args {
                    scope
                        .mapping_policy
                        .handlers
                        .push(Handler::remove(normalize_handler_extension(&ext)));
                }
            }
            "sethandler" => {
                // F64/I62: `SetHandler` carries precedence; it is stored as a
                // separate assignment, not as an extension-table entry, so a
                // later or inherited `AddHandler` can never replace it.
                let handler = first();
                if handler.eq_ignore_ascii_case("cgi-script") {
                    self.require_capability(Capability::Cgi, loc, "SetHandler cgi-script");
                }
                if handler.eq_ignore_ascii_case("server-status") {
                    self.require_capability(
                        Capability::ServerStatus,
                        loc,
                        "SetHandler server-status",
                    );
                }
                if handler.to_ascii_lowercase().contains("fcgi://") {
                    self.require_capability(Capability::FastCgi, loc, "SetHandler FastCGI");
                }
                scope.mapping_policy.set_handler = Some(SetHandler::parse(&handler));
            }
            "forcetype" => scope.content_policy.force_type = Some(first()),
            "adddefaultcharset" => {
                let a = first();
                if !a.eq_ignore_ascii_case("off") {
                    scope.content_policy.default_charset = Some(a);
                }
            }
            "defaultruntime" => self.warn(format!(
                "{}:{}: DefaultRuntime is accepted for compatibility and has no Vapache effect",
                loc.file, loc.line
            )),
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
                );
            }
            "directoryslash" => {
                scope.content_policy.directory_slash = Some(
                    payload
                        .on_off()
                        .expect("DirectorySlash is typed while sealing"),
                );
            }
            "accessfilename" => {
                scope.content_policy.access_file_names = Some(args.to_vec());
            }
            "header" => {
                let previous = scope.header_policy.clone();
                payload
                    .header()
                    .expect("Header is compiled while sealing")
                    .apply(&mut scope.header_policy);
                if !scope.header_policy.within_limits() {
                    scope.header_policy = previous;
                    self.directive_error(
                        loc,
                        "configured response headers exceed the count/byte limit",
                    );
                }
            }
            "expiresactive" => {
                scope.header_policy.expires_active = Some(
                    payload
                        .on_off()
                        .expect("ExpiresActive is typed while sealing"),
                );
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
            "typesconfig" => {
                let p = PathBuf::from(first());
                let full = if p.is_absolute() {
                    p
                } else {
                    self.cfg.server_root.join(p)
                };
                if !self
                    .cfg
                    .admin_input_targets
                    .iter()
                    .any(|known| known == &full)
                {
                    self.cfg.admin_input_targets.push(full.clone());
                }
                if let Err(e) = self
                    .cfg
                    .mime
                    .load_types_file_with_trust(&full, self.cfg.admin_file_trust)
                {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: e,
                    });
                }
            }
            "cacheenable" => {
                scope.rewrite_policy.cache_enable.push((
                    args[0].to_ascii_lowercase(),
                    args.get(1).cloned().unwrap_or_else(|| "/".into()),
                ));
            }
            "cachedisable" => {
                if let Some(prefix) = args.first() {
                    scope.rewrite_policy.cache_disable.push(prefix.clone());
                }
            }
            "cacheroot" => {
                let p = PathBuf::from(first());
                self.cfg.cache.root = Some(if p.is_absolute() {
                    p
                } else {
                    self.cfg.server_root.join(p)
                });
            }
            "cachedefaultexpire" => {
                self.cfg.cache.default_expire = payload
                    .unsigned()
                    .expect("CacheDefaultExpire is typed while sealing");
            }
            "cachemaxexpire" => {
                self.cfg.cache.max_expire = payload
                    .unsigned()
                    .expect("CacheMaxExpire is typed while sealing");
            }
            "cacheminexpire" => {
                self.cfg.cache.min_expire = payload
                    .unsigned()
                    .expect("CacheMinExpire is typed while sealing");
            }
            "cachemaxfilesize" => {
                self.cfg.cache.max_file_size = payload
                    .unsigned()
                    .expect("CacheMaxFileSize is typed while sealing");
            }
            "cachemaxdisksize" => {
                self.cfg.cache.max_disk_size = payload
                    .unsigned()
                    .expect("CacheMaxDiskSize is typed while sealing");
            }
            "cachemaxmemorysize" => {
                self.cfg.cache.max_memory_size = payload
                    .unsigned()
                    .expect("CacheMaxMemorySize is typed while sealing");
            }
            "cacheminsize" => {
                self.cfg.cache.min_file_size = payload
                    .unsigned()
                    .expect("CacheMinSize is typed while sealing");
            }
            "cacheignorenolastmod" => {
                self.cfg.cache.ignore_no_last_mod = payload
                    .on_off()
                    .expect("CacheIgnoreNoLastMod is typed while sealing");
            }
            "cacheignorecachecontrol" => {
                self.cfg.cache.ignore_cache_control = payload
                    .on_off()
                    .expect("CacheIgnoreCacheControl is typed while sealing");
            }
            "cachestorenostore" => {
                self.cfg.cache.store_no_store = payload
                    .on_off()
                    .expect("CacheStoreNoStore is typed while sealing");
            }
            "cachestoreprivate" => {
                self.cfg.cache.store_private = payload
                    .on_off()
                    .expect("CacheStorePrivate is typed while sealing");
            }
            "cacheignorequerystring" => {
                self.cfg.cache.ignore_query_string = payload
                    .on_off()
                    .expect("CacheIgnoreQueryString is typed while sealing");
            }
            "cacheheader" => {
                self.cfg.cache.header = payload
                    .on_off()
                    .expect("CacheHeader is typed while sealing");
            }
            "cachedetailheader" => {
                self.cfg.cache.detail_header = payload
                    .on_off()
                    .expect("CacheDetailHeader is typed while sealing");
            }
            "cachelastmodifiedfactor" => {
                self.cfg.cache.last_modified_factor = payload
                    .unit_float()
                    .expect("CacheLastModifiedFactor is compiled while sealing");
            }
            "proxypass" => {
                let sealed = payload
                    .proxy_pass()
                    .expect("ProxyPass is compiled while sealing");
                if sealed.fastcgi {
                    self.require_capability(Capability::FastCgi, loc, "ProxyPass FastCGI");
                }
                let rule = ProxyPassRule {
                    prefix: sealed.prefix.clone(),
                    backend: sealed.backend.clone(),
                    sticky_cookie: sealed.sticky_cookie.clone(),
                    fail_on_status: sealed.fail_on_status.clone(),
                    route_order: self.next_route,
                };
                self.next_route += 1;
                scope.proxy_policy.proxy_passes.push(rule);
            }
            "proxypassreverse" => {
                let sealed = payload
                    .proxy_pass_reverse()
                    .expect("ProxyPassReverse is compiled while sealing");
                scope.proxy_policy.proxy_reverses.push(ProxyReverseRule {
                    front: sealed.front.clone(),
                    backend: sealed.backend.clone(),
                });
            }
            "proxypassmatch" => {
                let sealed = payload
                    .proxy_pass_match()
                    .expect("ProxyPassMatch is compiled while sealing");
                if sealed.fastcgi {
                    self.require_capability(Capability::FastCgi, loc, "ProxyPassMatch FastCGI");
                }
                scope.proxy_policy.proxy_rules.push(ProxyRule {
                    pattern: sealed.pattern.clone(),
                    backend: sealed.backend.clone(),
                    route_order: self.next_route,
                });
                self.next_route += 1;
            }
            "addoutputfilterbytype" => {
                if args.len() < 2 {
                    return;
                }
                let (kinds, unsupported) = parse_filter_names(&args[..1]);
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
                        UnsupportedFilterRule::ByType(
                            name,
                            args[1..].iter().map(|s| s.to_ascii_lowercase()).collect(),
                        ),
                    );
                }
            }
            "addoutputfilter" => {
                if args.len() < 2 {
                    return;
                }
                let (kinds, unsupported) = parse_filter_names(&args[..1]);
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
                        UnsupportedFilterRule::ByExt(
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
            "deflatefilternote" | "deflatebuffersize" | "deflatememlevel"
            | "deflatewindowssize" => self.directive_error(
                loc,
                format!(
                    "directive '{name}' is not implemented by the Rust compression backend; refusing to ignore its resource policy"
                ),
            ),
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
                scope.compression_policy.deflate_alter_etag = Some(match payload
                    .keyword()
                    .expect("DeflateAlterETag is typed while sealing")
                {
                    0 => AlterEtag::AddSuffix,
                    1 => AlterEtag::NoChange,
                    2 => AlterEtag::Remove,
                    _ => unreachable!("sealed AlterETag keyword index"),
                });
            }
            "brotlialteretag" | "brotlicompressionalteretag" => {
                scope.compression_policy.brotli_alter_etag = Some(match payload
                    .keyword()
                    .expect("BrotliAlterETag is typed while sealing")
                {
                    0 => AlterEtag::AddSuffix,
                    1 => AlterEtag::NoChange,
                    2 => AlterEtag::Remove,
                    _ => unreachable!("sealed AlterETag keyword index"),
                });
            }
            "addencoding" => {
                for e in &args[1..] {
                    self.cfg.mime.encodings.insert(
                        e.trim_start_matches('.').to_ascii_lowercase(),
                        args[0].clone(),
                    );
                }
            }
            "addcharset" | "addlanguage" => self.directive_error(
                loc,
                format!(
                    "{name} is not implemented; refusing to ignore a content metadata directive"
                ),
            ),
            "listen" => {
                self.cfg.listeners.push(
                    payload
                        .listen()
                        .expect("Listen is compiled while sealing")
                        .clone(),
                );
            }
            "user" => self.cfg.user = first(),
            "group" => self.cfg.group = first(),
            "pidfile" => {
                let path = PathBuf::from(first());
                self.cfg.pid_file = normalize_pid_path(if path.is_absolute() {
                    path
                } else {
                    self.cfg.server_root.join(path)
                });
            }
            "errorlog" => {
                let p = first();
                if let Some(i) = self.current_vhost {
                    self.vhosts_raw[i].error_log = Some(p);
                } else {
                    self.cfg.error_log = p;
                }
            }
            "loglevel" => {
                let valid_level = |value: &str| {
                    let level = value.rsplit_once(':').map_or(value, |(_, level)| level);
                    matches!(
                        level.to_ascii_lowercase().as_str(),
                        "emerg"
                            | "alert"
                            | "crit"
                            | "error"
                            | "warn"
                            | "notice"
                            | "info"
                            | "debug"
                            | "trace1"
                            | "trace2"
                            | "trace3"
                            | "trace4"
                            | "trace5"
                            | "trace6"
                            | "trace7"
                            | "trace8"
                    )
                };
                if args.len() > 1 || first().contains(':') {
                    self.directive_error(
                        loc,
                        "module-specific LogLevel is not implemented; refusing to replace the configured audit policy with a global level",
                    );
                } else if args.iter().all(|value| valid_level(value)) {
                    self.cfg.log_level = first();
                } else {
                    self.directive_error(loc, "LogLevel contains an invalid level");
                }
            }
            "logformat" => {
                if args.len() >= 2 {
                    let fmt = args[0].clone();
                    let nick = args[1].clone();
                    self.cfg.log_formats.insert(nick, fmt);
                }
            }
            "customlog" => {
                let cl = CustomLog {
                    path: args[0].clone(),
                    format: args[1].clone(),
                    condition: None,
                };
                if let Some(i) = self.current_vhost {
                    self.vhosts_raw[i].custom_logs.push(cl);
                } else {
                    self.cfg.custom_logs.push(cl);
                }
            }
            "setenv" => {
                if let Some(name) = args.first() {
                    scope
                        .environment_policy
                        .set_env
                        .push(Originated::main((name.clone(), args[1..].join(" "))));
                }
            }
            "unsetenv" => scope
                .environment_policy
                .unset_env
                .extend(args.iter().cloned().map(Originated::main)),
            "passenv" => scope
                .environment_policy
                .pass_env
                .extend(args.iter().cloned().map(Originated::main)),
            "setenvif" | "setenvifnocase" | "browsermatch" | "browsermatchnocase" => {
                scope.environment_policy.set_env_if.push(Originated::main(
                    payload
                        .environment_rule()
                        .expect("environment rule is compiled while sealing")
                        .clone(),
                ));
            }
            "remoteipheader" => {
                self.cfg.remoteip_header = Some(first());
            }
            "remoteipinternalproxy" | "remoteiptrustedproxy" => {
                let internal = name == "remoteipinternalproxy";
                for (network, bits) in payload
                    .remote_ip_networks()
                    .expect("RemoteIP networks are compiled while sealing")
                {
                    self.cfg.remoteip_proxies.push(RemoteIpProxy {
                        network: *network,
                        bits: *bits,
                        internal,
                    });
                }
            }
            "timeout" => {
                let d = Duration::from_secs(
                    payload
                        .unsigned()
                        .expect("Timeout is typed while sealing"),
                );
                self.cfg.timeout = d;
                self.cfg.request_header_timeout = d;
                self.cfg.request_body_timeout = d;
            }
            "keepalive" => {
                self.cfg.keep_alive = payload
                    .on_off()
                    .expect("KeepAlive is typed while sealing");
            }
            "keepalivetimeout" => {
                self.cfg.keep_alive_timeout = Duration::from_secs(
                    payload
                        .unsigned()
                        .expect("KeepAliveTimeout is typed while sealing"),
                );
            }
            "maxkeepaliverequests" => {
                self.cfg.max_keep_alive_requests = payload
                    .unsigned()
                    .expect("MaxKeepAliveRequests is typed while sealing")
                    as usize;
            }
            "hostnamelookups" => match payload
                .keyword()
                .expect("HostnameLookups is typed while sealing")
            {
                0 => self.cfg.hostname_lookups = true,
                1 => self.cfg.hostname_lookups = false,
                2 => self.directive_error(
                    loc,
                    "HostnameLookups Double is not implemented; refusing to omit forward-confirmation",
                ),
                _ => unreachable!("sealed HostnameLookups keyword index"),
            },
            "usecanonicalname" => match payload
                .keyword()
                .expect("UseCanonicalName is typed while sealing")
            {
                0 => self.cfg.use_canonical_name = true,
                1 => self.cfg.use_canonical_name = false,
                // Apache resolves the local address for `DNS`.  Until that
                // reverse-DNS path is modeled, use ServerName, which is the
                // conservative choice for redirects and expression variables:
                // the client Host header never becomes the canonical name.
                2 => self.cfg.use_canonical_name = true,
                _ => unreachable!("sealed UseCanonicalName keyword index"),
            },
            "servertokens" => {
                let tokens = match payload
                    .keyword()
                    .expect("ServerTokens is typed while sealing")
                {
                    0 => ServerTokens::Full,
                    1 => ServerTokens::Os,
                    2 => ServerTokens::Minimal,
                    3 => ServerTokens::Minor,
                    4 => ServerTokens::Major,
                    5 => ServerTokens::Prod,
                    _ => unreachable!("sealed ServerTokens keyword index"),
                };
                self.cfg.server_tokens = tokens;
                self.cfg.server_software = server_software_for_tokens(tokens);
            }
            "serversignature" => match payload
                .keyword()
                .expect("ServerSignature is typed while sealing")
            {
                0 => self.cfg.server_signature = ServerSignature::On,
                1 => self.cfg.server_signature = ServerSignature::Off,
                2 => self.cfg.server_signature = ServerSignature::Email,
                _ => unreachable!("sealed ServerSignature keyword index"),
            },
            "traceenable" => {
                self.cfg.trace_enable = payload
                    .keyword()
                    .map(|value| value != 0)
                    .expect("TraceEnable is typed while sealing");
                if self.cfg.trace_enable {
                    self.require_capability(Capability::Trace, loc, "enabled TraceEnable");
                }
            }
            "limitrequestline" => {
                self.cfg.limit_request_line = payload
                    .unsigned()
                    .expect("LimitRequestLine is typed while sealing")
                    as usize;
            }
            "limitrequestfields" => {
                self.cfg.limit_request_fields = payload
                    .unsigned()
                    .expect("LimitRequestFields is typed while sealing")
                    as usize;
            }
            "limitrequestfieldsize" => {
                self.cfg.limit_request_field_size = payload
                    .unsigned()
                    .expect("LimitRequestFieldSize is typed while sealing")
                    as usize;
            }
            "maxrequestworkers" => {
                let n = payload
                    .unsigned()
                    .expect("MaxRequestWorkers is typed while sealing")
                    as usize;
                if self.server_limit.is_some_and(|limit| n > limit) {
                    self.directive_error(loc, "MaxRequestWorkers exceeds ServerLimit");
                } else {
                    self.cfg.max_request_workers = n;
                    self.max_request_workers_set = true;
                }
            }
            "serverlimit" => {
                let limit = payload
                    .unsigned()
                    .expect("ServerLimit is typed while sealing")
                    as usize;
                if self.max_request_workers_set && self.cfg.max_request_workers > limit {
                    self.directive_error(loc, "MaxRequestWorkers exceeds ServerLimit");
                } else {
                    self.server_limit = Some(limit);
                    self.cfg.max_request_workers = self.cfg.max_request_workers.min(limit);
                }
            }
            "listenbacklog" => {
                self.cfg.listen_backlog = payload
                    .unsigned()
                    .expect("ListenBacklog is typed while sealing")
                    as i32;
            }
            "gracefulshutdowntimeout" => {
                self.cfg.graceful_shutdown_timeout = Duration::from_secs(
                    payload
                        .unsigned()
                        .expect("GracefulShutdownTimeout is typed while sealing"),
                );
            }
            "requestreadtimeout" => {
                let (header, body, header_rate, body_rate) = payload
                    .request_read_timeout()
                    .expect("RequestReadTimeout is compiled while sealing");
                if let Some(header) = header {
                    self.cfg.request_header_timeout = header;
                }
                if let Some(body) = body {
                    self.cfg.request_body_timeout = body;
                }
                if let Some(rate) = header_rate {
                    self.cfg.request_header_min_rate = rate;
                }
                if let Some(rate) = body_rate {
                    self.cfg.request_body_min_rate = rate;
                }
            }
            "limitrequestbody" => {
                self.cfg.limit_request_body = payload
                    .unsigned()
                    .expect("LimitRequestBody is typed while sealing");
            }
            "allowencodedslashes" => {
                self.cfg.encoded_slashes = match payload
                    .keyword()
                    .expect("AllowEncodedSlashes is typed while sealing")
                {
                    0 => EncodedSlashes::On,
                    1 => EncodedSlashes::Off,
                    2 => EncodedSlashes::NoDecode,
                    _ => unreachable!("sealed AllowEncodedSlashes keyword index"),
                }
            }
            "satisfy" => {
                self.require_capability(Capability::LegacyAuthz, loc, "Satisfy");
                let satisfy = match payload
                    .keyword()
                    .expect("Satisfy is typed while sealing")
                {
                    0 => Satisfy::All,
                    1 => Satisfy::Any,
                    _ => unreachable!("sealed Satisfy keyword index"),
                };
                scope.add_satisfy(satisfy, limit);
            }
            "allowmethods" => {
                if !in_directory {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "AllowMethods is only allowed in directory context".into(),
                    });
                    return;
                }
                scope.authorization.allow_methods = Some(
                    payload
                        .allow_methods()
                        .expect("AllowMethods is compiled while sealing")
                        .clone(),
                );
            }
            "authmerging" => {
                let merging = match payload
                    .keyword()
                    .expect("AuthMerging is typed while sealing")
                {
                    0 => AuthMerging::Off,
                    1 => AuthMerging::And,
                    2 => AuthMerging::Or,
                    _ => unreachable!("sealed AuthMerging keyword index"),
                };
                scope.authorization.auth_merging = Some(merging);
            }
            "sslrequiressl" => {
                self.errors.push(ConfigError {
                    file: loc.file.clone(),
                    line: loc.line,
                    msg: "SSLRequireSSL is not implemented; refusing to weaken TLS policy".into(),
                });
            }
            "sslrequire" => {
                self.errors.push(ConfigError {
                    file: loc.file.clone(),
                    line: loc.line,
                    msg: "SSLRequire is not implemented; refusing to weaken TLS policy".into(),
                });
            }
            "secruleengine" => {
                if !first().eq_ignore_ascii_case("off") {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg:
                            "SecRuleEngine is not implemented; refusing to silently disable the WAF"
                                .into(),
                    });
                }
            }
            "defaultruntimedir" => self.warn(format!(
                "{}:{}: DefaultRuntimeDir is accepted for Apache layout compatibility; Vapache runtime paths are compiled separately",
                loc.file, loc.line
            )),
            "sslrandomseed" => {
                let valid_context = args.first().is_some_and(|value| {
                    matches!(value.to_ascii_lowercase().as_str(), "startup" | "connect")
                });
                let valid_source = args.get(1).is_some_and(|value| {
                    let normalized = value.to_ascii_lowercase();
                    normalized == "builtin"
                        || ["file:", "exec:", "egd:"].iter().any(|prefix| {
                            normalized.starts_with(prefix) && normalized.len() > prefix.len()
                        })
                });
                let valid_bytes = args
                    .get(2)
                    .is_none_or(|value| crate::util::parse_u64(value.as_bytes()).is_some());
                if !(2..=3).contains(&args.len()) || !valid_context || !valid_source || !valid_bytes
                {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "SSLRandomSeed requires startup|connect, a builtin/file:/exec:/egd: source, and optional byte count".into(),
                    });
                }
                // Rustls obtains cryptographic randomness directly from the
                // OS. Apache's OpenSSL PRNG seed sources must never be opened
                // or executed by this process.
            }
            "sslpassphrasedialog" => {
                let value = first();
                let supported = value.eq_ignore_ascii_case("builtin")
                    || value
                        .strip_prefix("exec:")
                        .is_some_and(|program| Path::new(program).is_absolute());
                if args.len() != 1 || !supported {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "SSLPassPhraseDialog requires builtin or exec:/absolute/program"
                            .into(),
                    });
                } else {
                    self.warn(format!(
                        "{}:{}: SSLPassPhraseDialog is unnecessary with Rustls; encrypted private keys remain unsupported",
                        loc.file, loc.line
                    ));
                }
            }
            "sslsessioncache" => {
                let value = first();
                let enabled = if value.eq_ignore_ascii_case("none")
                    || value.eq_ignore_ascii_case("nonenotnull")
                {
                    Some(false)
                } else if value
                    .split_once(':')
                    .is_some_and(|(provider, target)| !provider.is_empty() && !target.is_empty())
                {
                    Some(true)
                } else {
                    None
                };
                if args.len() != 1 || enabled.is_none() {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "SSLSessionCache requires none or a provider:target value".into(),
                    });
                } else {
                    let target = if let Some(i) = self.current_vhost {
                        &mut self.vhosts_raw[i].ssl
                    } else {
                        &mut self.cfg.ssl
                    };
                    target.session_cache = enabled;
                    if enabled == Some(true) {
                        self.warn(format!(
                            "{}:{}: SSLSessionCache uses Rustls' bounded in-process cache; the Apache provider path is ignored",
                            loc.file, loc.line
                        ));
                    }
                }
            }
            "sslsessioncachetimeout" => {
                let seconds = payload
                    .unsigned()
                    .expect("SSLSessionCacheTimeout is compiled while sealing");
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                target.session_cache_timeout = Some(Duration::from_secs(seconds));
            }
            "sslsessiontickets" => {
                let enabled = payload
                    .on_off()
                    .expect("SSLSessionTickets is compiled while sealing");
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                target.session_tickets = Some(enabled);
            }
            "sslhonorcipherorder" => {
                let enabled = payload
                    .on_off()
                    .expect("SSLHonorCipherOrder is compiled while sealing");
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                target.honor_cipher_order = Some(enabled);
            }
            "ssloptions" => {
                if args.is_empty()
                    || args
                        .iter()
                        .any(|value| !value.eq_ignore_ascii_case("+StrictRequire"))
                {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "only SSLOptions +StrictRequire is supported".into(),
                    });
                }
                // StrictRequire changes how mod_ssl's legacy SSLRequire
                // access check interacts with Satisfy. Vapache rejects both
                // directives instead of approximating them, so accepting the
                // strengthening flag itself cannot weaken request policy.
            }
            "sslengine" => {
                let on = payload
                    .on_off()
                    .expect("SSLEngine is compiled while sealing");
                if let Some(i) = self.current_vhost {
                    self.vhosts_raw[i].ssl.engine = on;
                    self.vhosts_raw[i].ssl.engine_set = true;
                } else {
                    self.cfg.ssl.engine = on;
                    self.cfg.ssl.engine_set = true;
                }
            }
            "sslcertificatefile" | "sslcertificatekeyfile" | "sslcertificatechainfile" => {
                if args.len() != 1 || first().is_empty() {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: format!("{name} requires exactly one non-empty path"),
                    });
                    return;
                }
                let p = PathBuf::from(first());
                let full = if p.is_absolute() {
                    p
                } else {
                    self.cfg.server_root.join(p)
                };
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                match name {
                    "sslcertificatefile" => target.cert_file = Some(full),
                    "sslcertificatekeyfile" => target.key_file = Some(full),
                    _ => target.chain_file = Some(full),
                }
            }
            "sslusestapling" => {
                let on = payload
                    .on_off()
                    .expect("SSLUseStapling is compiled while sealing");
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                target.stapling = on;
                target.stapling_set = true;
            }
            "sslstaplingforceurl" => {
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                target.stapling_force_url = Some(
                    payload
                        .ocsp_responder_url()
                        .expect("SSLStaplingForceURL is compiled while sealing")
                        .to_string(),
                );
            }
            "sslstaplingrespondertimeout" => {
                let n = payload
                    .unsigned()
                    .expect("SSLStaplingResponderTimeout is compiled while sealing");
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                target.stapling_responder_timeout = Duration::from_secs(n.max(1));
            }
            "sslstaplingstandardcachetimeout" => {
                let n = payload
                    .unsigned()
                    .expect("SSLStaplingStandardCacheTimeout is compiled while sealing");
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                target.stapling_standard_cache_timeout = Duration::from_secs(n.max(1));
            }
            "sslstaplingreturnrespondererrors" => {
                let enabled = payload
                    .on_off()
                    .expect("SSLStaplingReturnResponderErrors is compiled while sealing");
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                target.stapling_return_responder_errors = enabled;
                if enabled {
                    self.warn(format!(
                        "{}:{}: Vapache staples only successful, signed OCSP responses even when SSLStaplingReturnResponderErrors is On",
                        loc.file, loc.line
                    ));
                }
            }
            "sslstaplingcache" => {
                let value = first();
                let valid = value
                    .split_once(':')
                    .is_some_and(|(provider, target)| !provider.is_empty() && !target.is_empty());
                if !valid {
                    self.directive_error(
                        loc,
                        "SSLStaplingCache requires a provider:target value",
                    );
                } else {
                    self.warn(format!(
                        "{}:{}: SSLStaplingCache uses Vapache's bounded in-process OCSP cache; the Apache provider path is ignored",
                        loc.file, loc.line
                    ));
                }
            }
            "sslproxycacertificatefile" => {
                let p = PathBuf::from(first());
                let full = if p.is_absolute() {
                    p
                } else {
                    self.cfg.server_root.join(p)
                };
                if !self
                    .cfg
                    .admin_input_targets
                    .iter()
                    .any(|known| known == &full)
                {
                    self.cfg.admin_input_targets.push(full.clone());
                }
                scope.proxy_policy.proxy_ca_file = Some(full);
                scope.proxy_policy.proxy_ca_trust = self.cfg.admin_file_trust;
                scope.proxy_policy.tls_config_cache =
                    std::sync::Arc::new(crate::scope_policy::ProxyTlsConfigCache::default());
            }
            "balancermember" => {
                let Some(i) = self.current_balancer else {
                    self.directive_error(
                        loc,
                        "BalancerMember outside <Proxy balancer://...> is not implemented",
                    );
                    return;
                };
                let Some(url) = args.first() else {
                    return;
                };
                let mut member = BalancerMember {
                    url: url.clone(),
                    ..BalancerMember::default()
                };
                for item in &args[1..] {
                    let Some((key, value)) = item.split_once('=') else {
                        self.directive_error(
                            loc,
                            format!("BalancerMember parameter '{item}' must use name=value syntax"),
                        );
                        continue;
                    };
                    match key.to_ascii_lowercase().as_str() {
                        "hcmethod" => member.hcmethod = Some(value.to_string()),
                        "hcuri" => member.hcuri = Some(value.to_string()),
                        "hcinterval" => match parse_duration(value) {
                            Some(duration) => member.hcinterval = Some(duration),
                            None => self.directive_error(
                                loc,
                                format!("invalid BalancerMember hcinterval '{value}'"),
                            ),
                        },
                        "hcpasses" => match value.parse() {
                            Ok(passes) => member.hcpasses = Some(passes),
                            Err(_) => self.directive_error(
                                loc,
                                format!("invalid BalancerMember hcpasses '{value}'"),
                            ),
                        },
                        "hcfails" => match value.parse() {
                            Ok(fails) => member.hcfails = Some(fails),
                            Err(_) => self.directive_error(
                                loc,
                                format!("invalid BalancerMember hcfails '{value}'"),
                            ),
                        },
                        "template" => member.template = Some(value.to_string()),
                        "route" => member.route = Some(value.to_string()),
                        _ => self.directive_error(
                            loc,
                            format!("unsupported BalancerMember parameter '{key}'"),
                        ),
                    }
                }
                self.cfg.balancers[i].members.push(member);
            }
            "proxyset" => {
                let Some(i) = self.current_balancer else {
                    self.directive_error(
                        loc,
                        "ProxySet outside <Proxy balancer://...> is not implemented",
                    );
                    return;
                };
                for item in args {
                    let Some((key, value)) = item.split_once('=') else {
                        self.directive_error(
                            loc,
                            format!("ProxySet parameter '{item}' must use name=value syntax"),
                        );
                        continue;
                    };
                    match key.to_ascii_lowercase().as_str() {
                        "hcmethod" => self.cfg.balancers[i].health.method = Some(value.to_string()),
                        "hcuri" => self.cfg.balancers[i].health.uri = Some(value.to_string()),
                        "hcinterval" => match parse_duration(value) {
                            Some(duration) => self.cfg.balancers[i].health.interval = Some(duration),
                            None => self.directive_error(
                                loc,
                                format!("invalid ProxySet hcinterval '{value}'"),
                            ),
                        },
                        "hcpasses" => match value.parse() {
                            Ok(passes) => self.cfg.balancers[i].health.passes = Some(passes),
                            Err(_) => self.directive_error(
                                loc,
                                format!("invalid ProxySet hcpasses '{value}'"),
                            ),
                        },
                        "hcfails" => match value.parse() {
                            Ok(fails) => self.cfg.balancers[i].health.fails = Some(fails),
                            Err(_) => self.directive_error(
                                loc,
                                format!("invalid ProxySet hcfails '{value}'"),
                            ),
                        },
                        "stickysession" => {
                            self.cfg.balancers[i].sticky_cookie = Some(value.to_string())
                        }
                        "stickysessionsep" => {
                            self.cfg.balancers[i].sticky_sep = Some(value.to_string())
                        }
                        "failonstatus" => {
                            let (statuses, unparsable) = parse_status_list(value);
                            if !unparsable.is_empty() {
                                self.directive_error(
                                    loc,
                                    format!(
                                        "ProxySet failonstatus contains non-numeric entries {unparsable:?}"
                                    ),
                                );
                            }
                            self.cfg.balancers[i].fail_on_status = statuses;
                        }
                        _ => self.directive_error(
                            loc,
                            format!("unsupported ProxySet parameter '{key}'"),
                        ),
                    }
                }
            }
            "proxyhctemplate" => {
                let Some(name) = args.first() else {
                    return;
                };
                let mut template = HealthTemplate::default();
                for item in &args[1..] {
                    let Some((key, value)) = item.split_once('=') else {
                        self.directive_error(
                            loc,
                            format!("ProxyHCTemplate parameter '{item}' must use name=value syntax"),
                        );
                        continue;
                    };
                    match key.to_ascii_lowercase().as_str() {
                        "hcmethod" => template.method = Some(value.to_string()),
                        "hcuri" => template.uri = Some(value.to_string()),
                        "hcinterval" => match parse_duration(value) {
                            Some(duration) => template.interval = Some(duration),
                            None => self.directive_error(
                                loc,
                                format!("invalid ProxyHCTemplate hcinterval '{value}'"),
                            ),
                        },
                        "hcpasses" => match value.parse() {
                            Ok(passes) => template.passes = Some(passes),
                            Err(_) => self.directive_error(
                                loc,
                                format!("invalid ProxyHCTemplate hcpasses '{value}'"),
                            ),
                        },
                        "hcfails" => match value.parse() {
                            Ok(fails) => template.fails = Some(fails),
                            Err(_) => self.directive_error(
                                loc,
                                format!("invalid ProxyHCTemplate hcfails '{value}'"),
                            ),
                        },
                        _ => self.directive_error(
                            loc,
                            format!("unsupported ProxyHCTemplate parameter '{key}'"),
                        ),
                    }
                }
                self.cfg.health_templates.insert(name.clone(), template);
            }
            "sslverifyclient" => {
                let verify_index = payload
                    .keyword()
                    .expect("SSLVerifyClient is compiled while sealing");
                if verify_index == 3 {
                    self.directive_error(
                        loc,
                        "SSLVerifyClient optional_no_ca is not implemented by Rustls; refusing to replace unverified client-certificate semantics with verified optional authentication",
                    );
                    return;
                }
                let verify = match verify_index {
                    0 => ClientVerify::None,
                    1 => ClientVerify::Optional,
                    2 => ClientVerify::Require,
                    _ => unreachable!("sealed SSLVerifyClient keyword index"),
                };
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                target.verify_client = Some(verify);
            }
            "sslcacertificatefile" => {
                if args.len() != 1 || first().is_empty() {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: "SSLCACertificateFile requires exactly one non-empty path".into(),
                    });
                    return;
                }
                let p = PathBuf::from(first());
                let full = if p.is_absolute() {
                    p
                } else {
                    self.cfg.server_root.join(p)
                };
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                target.ca_file = Some(full);
            }
            "sslcarevocationfile" => {
                let p = PathBuf::from(first());
                let full = if p.is_absolute() {
                    p
                } else {
                    self.cfg.server_root.join(p)
                };
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                target.ca_revocation_file = Some(full);
            }
            "sslcarevocationcheck" => {
                let check = match payload
                    .keyword()
                    .expect("SSLCARevocationCheck is compiled while sealing")
                {
                    0 => ClientRevocationCheck::None,
                    1 => ClientRevocationCheck::Leaf,
                    2 => ClientRevocationCheck::Chain,
                    _ => unreachable!("sealed SSLCARevocationCheck keyword index"),
                };
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                target.ca_revocation_check = Some(check);
            }
            "sslprotocol" => {
                let target = if let Some(i) = self.current_vhost {
                    &mut self.vhosts_raw[i].ssl
                } else {
                    &mut self.cfg.ssl
                };
                target.protocols = Some(
                    payload
                        .ssl_protocol()
                        .expect("SSLProtocol is compiled while sealing")
                        .to_string(),
                );
            }
            "sslciphersuite" | "sslciphersuitetls13" => {
                self.directive_error(
                    loc,
                    format!(
                        "{name} is not implemented by the Rustls backend; refusing to replace an explicit cipher policy with defaults"
                    ),
                );
            }
            "authtype" => {
                debug_assert_eq!(payload.keyword(), Some(0));
                scope.authorization.auth_type = Some("basic".into());
            }
            "authname" => scope.authorization.auth_name = Some(first()),
            "authuserfile" => {
                let p = PathBuf::from(first());
                let full = if p.is_absolute() {
                    p
                } else {
                    self.cfg.server_root.join(p)
                };
                if !self.cfg.auth_file_targets.contains(&full) {
                    self.cfg.auth_file_targets.push(full.clone());
                }
                scope.authorization.auth_user_file = Some(full);
            }
            "authgroupfile" => {
                let p = PathBuf::from(first());
                let full = if p.is_absolute() {
                    p
                } else {
                    self.cfg.server_root.join(p)
                };
                if !self.cfg.auth_file_targets.contains(&full) {
                    self.cfg.auth_file_targets.push(full.clone());
                }
                scope.authorization.auth_group_file = Some(full);
            }
            "authbasicprovider" => {
                debug_assert_eq!(payload.keyword(), Some(0));
            }
            "defaulttype" => { /* removed in 2.4; accepted for compat */ }
            _ => match self.directive_disposition(identity) {
                vapache_verified::DirectiveDisposition::FailClosedSecurity => {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: format!(
                            "security-sensitive directive '{name}' is not implemented; refusing to start"
                        ),
                    });
                }
                vapache_verified::DirectiveDisposition::FailClosedKnown => {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: format!(
                            "directive '{name}' is recognised but not implemented; refusing to ignore its effect"
                        ),
                    });
                }
                vapache_verified::DirectiveDisposition::FailClosedUnknown => {
                    self.errors.push(ConfigError {
                        file: loc.file.clone(),
                        line: loc.line,
                        msg: format!("Invalid command '{name}', perhaps misspelled or defined by a module not included in the server configuration"),
                    });
                }
            },
        }
        let _ = joined;
    }
}

/// Parse mod_alias redirect operands without treating an unknown status word
/// as a URL path. Redirect statuses require a target; terminal error statuses
/// (notably `gone`/410 and numeric 4xx/5xx) deliberately do not.
pub(crate) fn parse_redirect_arguments(
    args: &[String],
    forced_status: Option<u16>,
) -> Result<(u16, String, String), String> {
    if let Some(status) = forced_status {
        return match args {
            [from, to] => Ok((status, from.clone(), to.clone())),
            _ => Err("Redirect requires a source and target".into()),
        };
    }
    let Some(first) = args.first() else {
        return Err("Redirect requires a source path".into());
    };
    let keyword = first.to_ascii_lowercase();
    let explicit = match keyword.as_str() {
        "permanent" => Some(301),
        "temp" => Some(302),
        "seeother" => Some(303),
        "gone" => Some(410),
        _ => first.parse::<u16>().ok(),
    };
    match explicit {
        Some(status) if !(300..=599).contains(&status) => {
            Err(format!("unsupported Redirect status '{status}'"))
        }
        Some(status @ 300..=399) => match args {
            [_, from, to] => Ok((status, from.clone(), to.clone())),
            _ => Err(format!(
                "Redirect status {status} requires a source and target"
            )),
        },
        Some(status) => match args {
            [_, from] => Ok((status, from.clone(), String::new())),
            _ => Err(format!(
                "Redirect status {status} requires a source and no target"
            )),
        },
        None => match args {
            [from, to] => Ok((302, from.clone(), to.clone())),
            _ => Err("Redirect requires a source and target".into()),
        },
    }
}

/// Parse a comma-separated status list (ProxyPass/BalancerMember
/// `failonstatus`).  Unparsable tokens are returned alongside the codes so
/// callers can refuse them under strict mode instead of silently loading a
/// shorter list (an entry like `failonstatus=500,lop` used to load as
/// `[500]`).
pub(crate) fn parse_status_list(value: &str) -> (Vec<u16>, Vec<String>) {
    let mut statuses = Vec::new();
    let mut unparsable = Vec::new();
    for v in value.split(',') {
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        match v.parse::<u16>() {
            Ok(code) => statuses.push(code),
            Err(_) => unparsable.push(v.to_string()),
        }
    }
    (statuses, unparsable)
}

pub(crate) fn parse_request_read_timeout(
    raw: &str,
) -> Option<(Option<Duration>, Option<Duration>, Option<u64>, Option<u64>)> {
    let part = |prefix: &str| -> Option<(Duration, Option<u64>)> {
        let start = raw.find(prefix)? + prefix.len();
        let mut values = raw[start..]
            .split(|c: char| c == ',' || c == ' ' || c == '\t')
            .filter(|v| !v.is_empty());
        let time = values
            .next()?
            .split('-')
            // Preserve Apache's range maximum as the hard lifetime ceiling.
            // Using only the initial value and then extending it from an
            // attacker-controlled count made the timeout effectively
            // unbounded.
            .next_back()?
            .parse::<u64>()
            .ok()
            .map(Duration::from_secs)?;
        let mut rate = None;
        for value in values {
            if let Some(v) = value.strip_prefix("MinRate=") {
                rate = v.parse::<u64>().ok();
                break;
            }
        }
        Some((time, rate))
    };
    let header = part("header=");
    let body = part("body=");
    if header.is_none() && body.is_none() {
        None
    } else {
        Some((
            header.as_ref().map(|v| v.0),
            body.as_ref().map(|v| v.0),
            header.and_then(|v| v.1),
            body.and_then(|v| v.1),
        ))
    }
}

fn parse_duration(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Some(ms) = value.strip_suffix("ms") {
        return ms.parse::<u64>().ok().map(Duration::from_millis);
    }
    if let Some(s) = value.strip_suffix('s') {
        return s.parse::<u64>().ok().map(Duration::from_secs);
    }
    if let Some(m) = value.strip_suffix('m') {
        return m.parse::<u64>().ok().map(|v| Duration::from_secs(v * 60));
    }
    value.parse::<u64>().ok().map(Duration::from_secs)
}

fn parse_u32_arg(args: &[String]) -> Option<u32> {
    args.first().and_then(|s| s.parse().ok())
}

fn clean_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        use std::path::Component::*;
        match c {
            Prefix(_) | RootDir => out.push(c.as_os_str()),
            CurDir => {}
            ParentDir => {
                out.pop();
            }
            Normal(x) => out.push(x),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

/// Evaluate a configuration rule's `<If>`/`<ElseIf>`/`<Else>` condition.
/// `chain_state` records whether an earlier branch of each chain matched.
/// `fs_path` is the filesystem path mapped for the request when one exists;
/// it binds `%{REQUEST_FILENAME}`/`%{SCRIPT_FILENAME}` (F63/I63).
#[allow(clippy::too_many_arguments)]
pub(crate) fn rule_condition_result(
    rule: &ScopeRule,
    req: &crate::http::Request,
    env: &[(String, Vec<u8>)],
    peer: IpAddr,
    docroot: &Path,
    url_path: &str,
    fs_path: Option<&Path>,
    chain_state: &mut HashMap<usize, bool>,
) -> Result<bool, String> {
    let eval = |expr: &crate::expr::Expr| {
        let mut ctx =
            crate::expr::Context::new(req, env, peer, docroot, url_path).with_fs_path(fs_path);
        expr.eval(&mut ctx).map(|v| v.truthy())
    };
    match rule.branch {
        ConditionBranch::Normal => match &rule.condition {
            None => Ok(true),
            Some(expr) => {
                let matched = eval(expr)?;
                if let Some(chain) = rule.chain {
                    chain_state.insert(chain, matched);
                }
                Ok(matched)
            }
        },
        ConditionBranch::ElseIf => {
            let (Some(chain), Some(expr)) = (rule.chain, rule.condition.as_ref()) else {
                return Ok(false);
            };
            let prior = chain_state.get(&chain).copied().unwrap_or(false);
            let matched = !prior && eval(expr)?;
            chain_state.insert(chain, prior || matched);
            Ok(matched)
        }
        ConditionBranch::Else => {
            let Some(chain) = rule.chain else {
                return Ok(false);
            };
            let prior = chain_state.get(&chain).copied().unwrap_or(false);
            chain_state.insert(chain, true);
            Ok(!prior)
        }
    }
}

#[cfg(test)]
fn rule_condition_matches(
    rule: &ScopeRule,
    req: &crate::http::Request,
    env: &[(String, Vec<u8>)],
    peer: IpAddr,
    docroot: &Path,
    url_path: &str,
    fs_path: Option<&Path>,
    chain_state: &mut HashMap<usize, bool>,
) -> bool {
    rule_condition_result(
        rule,
        req,
        env,
        peer,
        docroot,
        url_path,
        fs_path,
        chain_state,
    )
    .unwrap_or(false)
}

fn path_has_prefix(path: &Path, prefix: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let path = path.as_os_str().as_bytes();
    let prefix = prefix.as_os_str().as_bytes();
    if prefix.is_empty() {
        return true;
    }
    if !path.starts_with(prefix) {
        return false;
    }
    path.len() == prefix.len() || prefix.ends_with(b"/") || path.get(prefix.len()) == Some(&b'/')
}

fn wildcard_path_matches(pattern: &Path, path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let p = pattern.as_os_str().as_bytes();
    let n = path.as_os_str().as_bytes();
    if !p.iter().any(|b| matches!(b, b'*' | b'?' | b'[')) {
        return path_has_prefix(path, pattern);
    }
    let pc: Vec<&[u8]> = p.split(|b| *b == b'/').filter(|c| !c.is_empty()).collect();
    let nc: Vec<&[u8]> = n.split(|b| *b == b'/').filter(|c| !c.is_empty()).collect();
    if pc.len() != nc.len() {
        return false;
    }
    pc.iter()
        .zip(nc.iter())
        .all(|(pat, name)| glob_match(pat, name))
}

fn wildcard_path_matches_req(
    pattern: &Path,
    path: &Path,
    req: &crate::http::Request,
) -> Result<bool, &'static str> {
    use std::os::unix::ffi::OsStrExt;
    let p = pattern.as_os_str().as_bytes();
    let n = path.as_os_str().as_bytes();
    if !p.iter().any(|b| matches!(b, b'*' | b'?' | b'[')) {
        req.charge_policy_work(1)?;
        return Ok(path_has_prefix(path, pattern));
    }
    let pc: Vec<&[u8]> = p.split(|b| *b == b'/').filter(|c| !c.is_empty()).collect();
    let nc: Vec<&[u8]> = n.split(|b| *b == b'/').filter(|c| !c.is_empty()).collect();
    if pc.len() != nc.len() {
        req.charge_policy_work(pc.len().min(nc.len()) as u64 + 1)?;
        return Ok(false);
    }
    for (pat, name) in pc.iter().zip(nc.iter()) {
        if !crate::glob::fnmatch_budgeted(pat, name, false, req.policy_budget())? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn directory_wildcard_matches(pattern: &Path, fs_path: &Path) -> bool {
    // A <Directory> pattern walks the filesystem ancestors of the mapped
    // path.  Apache includes the mapped path itself, even when it names a
    // regular file: a request for `/www/zdir/run.cgi` (mapped to
    // `/www/zdir/run.cgi`) is governed by `<Directory ".../zdir">` and by a
    // wildcard pattern that matches the file's own path (F61-C).  Skipping
    // the file's own path made such a section inert for files.
    for ancestor in fs_path.ancestors() {
        if wildcard_path_matches(pattern, ancestor) {
            return true;
        }
    }
    false
}

fn directory_wildcard_matches_req(
    pattern: &Path,
    fs_path: &Path,
    req: &crate::http::Request,
) -> Result<bool, &'static str> {
    for ancestor in fs_path.ancestors() {
        req.charge_policy_work(1)?;
        if wildcard_path_matches_req(pattern, ancestor, req)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn directory_pattern_matches_exact(pattern: &Path, dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let pattern_bytes = pattern.as_os_str().as_bytes();
    if pattern_bytes
        .iter()
        .any(|b| matches!(b, b'*' | b'?' | b'['))
    {
        wildcard_path_matches(pattern, dir)
    } else {
        // Configuration directory patterns are canonicalized; compare bytes
        // with trailing-slash normalization so non-matching rules do not pay
        // for repeated `Path::components` parsing on every request.
        let d = dir.as_os_str().as_bytes();
        let d = d.strip_suffix(b"/").unwrap_or(d);
        let p = pattern_bytes.strip_suffix(b"/").unwrap_or(pattern_bytes);
        d == p
    }
}

fn directory_pattern_matches_exact_req(
    pattern: &Path,
    dir: &Path,
    req: &crate::http::Request,
) -> Result<bool, &'static str> {
    use std::os::unix::ffi::OsStrExt;
    let pattern_bytes = pattern.as_os_str().as_bytes();
    if pattern_bytes
        .iter()
        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
    {
        wildcard_path_matches_req(pattern, dir, req)
    } else {
        req.charge_policy_work(
            (pattern_bytes.len() as u64)
                .saturating_add(dir.as_os_str().as_bytes().len() as u64)
                .saturating_add(1),
        )?;
        let dir_bytes = dir.as_os_str().as_bytes();
        Ok(dir_bytes.strip_suffix(b"/").unwrap_or(dir_bytes)
            == pattern_bytes.strip_suffix(b"/").unwrap_or(pattern_bytes))
    }
}

fn rule_kind_matches(kind: &MatchKind, fs_path: &Path, url_path: &str, fname: &str) -> bool {
    match kind {
        MatchKind::Always => true,
        MatchKind::Directory(p) => {
            use std::os::unix::ffi::OsStrExt;
            if p.as_os_str()
                .as_bytes()
                .iter()
                .any(|b| matches!(b, b'*' | b'?' | b'['))
            {
                directory_wildcard_matches(p, fs_path)
            } else {
                path_has_prefix(fs_path, p)
            }
        }
        MatchKind::DirectoryMatch(re) => re.is_match(fs_path.as_os_str().as_encoded_bytes()),
        MatchKind::Files(re) | MatchKind::FilesMatch(re) => re.is_match(fname.as_bytes()),
        MatchKind::FilesGlob(pattern) => {
            crate::glob::fnmatch(pattern.as_bytes(), fname.as_bytes(), false)
        }
        MatchKind::Location(prefix) => {
            if prefix.is_empty() || prefix == "/" {
                return true;
            }
            if prefix.ends_with('/') {
                // A Location ending in "/" is a distinct prefix from the same
                // path without the slash.  Apache does not let
                // <Location "/admin/"> match the file "/admin".
                url_path.starts_with(prefix)
            } else {
                url_path == prefix
                    || (url_path.starts_with(prefix)
                        && url_path.as_bytes().get(prefix.len()) == Some(&b'/'))
            }
        }
        MatchKind::LocationGlob(pattern) => {
            crate::glob::fnmatch(pattern.as_bytes(), url_path.as_bytes(), true)
        }
        MatchKind::LocationMatch(re) => re.is_match(url_path.as_bytes()),
    }
}

fn rule_kind_matches_req(
    kind: &MatchKind,
    fs_path: &Path,
    url_path: &str,
    fname: &str,
    req: &crate::http::Request,
) -> Result<bool, &'static str> {
    req.charge_policy_work(1)?;
    match kind {
        MatchKind::Always => Ok(true),
        MatchKind::Directory(pattern) => {
            use std::os::unix::ffi::OsStrExt;
            if pattern
                .as_os_str()
                .as_bytes()
                .iter()
                .any(|byte| matches!(byte, b'*' | b'?' | b'['))
            {
                directory_wildcard_matches_req(pattern, fs_path, req)
            } else {
                req.charge_policy_work(fs_path.as_os_str().as_encoded_bytes().len() as u64)?;
                Ok(path_has_prefix(fs_path, pattern))
            }
        }
        MatchKind::DirectoryMatch(regex) => {
            let subject = fs_path.as_os_str().as_encoded_bytes();
            req.charge_policy_work(
                (regex.as_str().len() as u64)
                    .saturating_add(subject.len() as u64)
                    .saturating_add(1),
            )?;
            Ok(regex.is_match(subject))
        }
        MatchKind::Files(regex) | MatchKind::FilesMatch(regex) => {
            req.charge_policy_work(
                (regex.as_str().len() as u64)
                    .saturating_add(fname.len() as u64)
                    .saturating_add(1),
            )?;
            Ok(regex.is_match(fname.as_bytes()))
        }
        MatchKind::FilesGlob(pattern) => crate::glob::fnmatch_budgeted(
            pattern.as_bytes(),
            fname.as_bytes(),
            false,
            req.policy_budget(),
        ),
        MatchKind::Location(prefix) => {
            req.charge_policy_work(
                (prefix.len() as u64)
                    .saturating_add(url_path.len() as u64)
                    .saturating_add(1),
            )?;
            if prefix.is_empty() || prefix == "/" {
                Ok(true)
            } else if prefix.ends_with('/') {
                Ok(url_path.starts_with(prefix))
            } else {
                Ok(url_path == prefix
                    || (url_path.starts_with(prefix)
                        && url_path.as_bytes().get(prefix.len()) == Some(&b'/')))
            }
        }
        MatchKind::LocationGlob(pattern) => crate::glob::fnmatch_budgeted(
            pattern.as_bytes(),
            url_path.as_bytes(),
            true,
            req.policy_budget(),
        ),
        MatchKind::LocationMatch(regex) => {
            req.charge_policy_work(
                (regex.as_str().len() as u64)
                    .saturating_add(url_path.len() as u64)
                    .saturating_add(1),
            )?;
            Ok(regex.is_match(url_path.as_bytes()))
        }
    }
}

fn transformed_rewrite_rules(
    rule: &ScopeRule,
    fs_path: &Path,
    url_path: &str,
) -> Option<Vec<RewriteRule>> {
    if rule.delta.rewrite_policy.rewrite_rules.is_empty() {
        return None;
    }
    let MatchKind::Directory(dir) = &rule.kind else {
        return None;
    };
    // Wildcard/pattern <Directory> blocks keep the legacy non-per-directory
    // rewrite treatment; a wildcard pattern is not itself a filesystem layer
    // from which Apache can derive a per-directory prefix.
    if dir
        .as_os_str()
        .as_encoded_bytes()
        .iter()
        .any(|b| matches!(b, b'*' | b'?' | b'['))
    {
        return None;
    }
    // Main-configuration <Directory> rewrites use the same layer identity as
    // access files: the URL mount is the substitution base, while the match
    // subject is always the selected target relative to the directory.
    let base = crate::request_plan::layer_url_mount(dir, dir, fs_path, url_path);
    let mut rules = rule.delta.rewrite_policy.rewrite_rules.clone();
    for rr in &mut rules {
        rr.per_dir = true;
        rr.match_base = base.clone();
        rr.subject_dir = Some(dir.clone());
        if rr.base == "/" {
            rr.base = base.clone();
        }
    }
    Some(rules)
}

fn merge_rule_delta(s: &mut Scope, rule: &ScopeRule, fs_path: &Path, url_path: &str) {
    match transformed_rewrite_rules(rule, fs_path, url_path) {
        Some(rules) => s.merge_with_rewrite_rules(&rule.delta, &rules),
        None => s.merge(&rule.delta),
    }
}

pub(crate) fn apply_rules_config(
    rules: &[ScopeRule],
    s: &mut Scope,
    fs_path: &Path,
    url_path: &str,
    fname: &str,
) {
    let mut pending: Vec<&ScopeRule> = rules.iter().rev().collect();
    while let Some(rule) = pending.pop() {
        if rule.phase() == RulePhase::Condition {
            continue;
        }
        if !rule_kind_matches(&rule.kind, fs_path, url_path, fname) {
            continue;
        }
        merge_rule_delta(s, rule, fs_path, url_path);
        pending.extend(rule.nested.iter().rev());
    }
}

fn apply_rules_config_budgeted(
    rules: &[ScopeRule],
    s: &mut Scope,
    fs_path: &Path,
    url_path: &str,
    fname: &str,
    req: &crate::http::Request,
) -> Result<(), &'static str> {
    let mut pending: Vec<&ScopeRule> = rules.iter().rev().collect();
    while let Some(rule) = pending.pop() {
        if rule.phase() == RulePhase::Condition {
            continue;
        }
        if !rule_kind_matches_req(&rule.kind, fs_path, url_path, fname, req)? {
            continue;
        }
        merge_rule_delta(s, rule, fs_path, url_path);
        pending.extend(rule.nested.iter().rev());
    }
    Ok(())
}

/// Apply normal directory/file/location rules first, then all `<If>`-style
/// conditionals.  Apache documents that `<If>`, `<ElseIf>` and `<Else>` are
/// applied last; applying them in section order can let a later
/// `<Directory>` or `<Location>` grant override a conditional denial.
pub(crate) fn apply_rules_req(
    rules: &[ScopeRule],
    s: &mut Scope,
    req: &crate::http::Request,
    peer: IpAddr,
    docroot: &Path,
    fs_path: &Path,
    url_path: &str,
    fname: &str,
    chain_state: &mut HashMap<usize, bool>,
) {
    let mut deferred: Vec<ScopeRule> = Vec::new();
    collect_rules_req(
        rules,
        s,
        req,
        peer,
        docroot,
        fs_path,
        url_path,
        fname,
        &mut deferred,
    );
    deferred.sort_by_key(|rule| rule.order);
    apply_deferred_req(
        s,
        &deferred,
        req,
        peer,
        docroot,
        fs_path,
        url_path,
        fname,
        chain_state,
    );
}

/// Apply every normal rule immediately and collect conditional rules for a
/// later pass.  Apache applies `<If>`-style sections after Directory, Files
/// and Location merges; this lets a caller merge `.htaccess` normal rules
/// before evaluating conditionals from the configuration and from parent
/// access files.
#[allow(clippy::too_many_arguments)]
pub(crate) fn collect_rules_req(
    rules: &[ScopeRule],
    s: &mut Scope,
    req: &crate::http::Request,
    _peer: IpAddr,
    _docroot: &Path,
    fs_path: &Path,
    url_path: &str,
    fname: &str,
    deferred: &mut Vec<ScopeRule>,
) {
    // Preserve the recursive walk's preorder while keeping request stack use
    // independent of configuration nesting.
    let mut pending: Vec<&ScopeRule> = rules.iter().rev().collect();
    while let Some(rule) = pending.pop() {
        let matched = match rule_kind_matches_req(&rule.kind, fs_path, url_path, fname, req) {
            Ok(matched) => matched,
            Err(_) => {
                s.conditional_error = true;
                return;
            }
        };
        if !matched {
            continue;
        }
        if rule.phase() == RulePhase::Condition {
            deferred.push(rule.clone());
            continue;
        }
        merge_rule_delta(s, rule, fs_path, url_path);
        pending.extend(rule.nested.iter().rev());
    }
}

/// Apply literal Directory/DirectoryMatch rules and defer Files, Location and
/// conditional rules.  Apache processes Files after Directory/.htaccess and
/// Location after Files, so callers must not merge those sections early.
#[allow(clippy::too_many_arguments)]
pub(crate) fn collect_directory_phase(
    rules: &[ScopeRule],
    s: &mut Scope,
    req: &crate::http::Request,
    peer: IpAddr,
    docroot: &Path,
    fs_path: &Path,
    url_path: &str,
    fname: &str,
    files: &mut Vec<ScopeRule>,
    locations: &mut Vec<ScopeRule>,
    conditionals: &mut Vec<ScopeRule>,
) {
    for rule in rules {
        let matched = match rule_kind_matches_req(&rule.kind, fs_path, url_path, fname, req) {
            Ok(matched) => matched,
            Err(_) => {
                s.conditional_error = true;
                return;
            }
        };
        if !matched {
            continue;
        }
        match rule.phase() {
            RulePhase::Condition => conditionals.push(rule.clone()),
            RulePhase::Directory => {
                merge_rule_delta(s, rule, fs_path, url_path);
                for nested in &rule.nested {
                    defer_rule_by_verified_phase(nested, files, locations, conditionals);
                }
            }
            RulePhase::Files => files.push(rule.clone()),
            RulePhase::Location => locations.push(rule.clone()),
        }
    }
}

/// Apply a pre-collected Files or Location rule list in order, collecting any
/// nested conditional sections for the final pass.
#[allow(clippy::too_many_arguments)]
pub fn apply_normal_rule_list(
    rules: &[ScopeRule],
    s: &mut Scope,
    req: &crate::http::Request,
    peer: IpAddr,
    docroot: &Path,
    fs_path: &Path,
    url_path: &str,
    fname: &str,
    conditionals: &mut Vec<ScopeRule>,
) {
    for rule in rules {
        let matched = match rule_kind_matches_req(&rule.kind, fs_path, url_path, fname, req) {
            Ok(matched) => matched,
            Err(_) => {
                s.conditional_error = true;
                return;
            }
        };
        if !matched {
            continue;
        }
        if rule.phase() == RulePhase::Condition {
            conditionals.push(rule.clone());
            continue;
        }
        merge_rule_delta(s, rule, fs_path, url_path);
        for nested in &rule.nested {
            if nested.phase() == RulePhase::Condition {
                conditionals.push(nested.clone());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn apply_deferred_req(
    s: &mut Scope,
    rules: &[ScopeRule],
    req: &crate::http::Request,
    peer: IpAddr,
    docroot: &Path,
    fs_path: &Path,
    url_path: &str,
    fname: &str,
    chain_state: &mut HashMap<usize, bool>,
) {
    // A matched conditional applies all of its normal nested rules and then
    // its nested conditionals before the next sibling. Use an explicit LIFO
    // worklist to preserve that recursive ordering without consuming one
    // request-stack frame per section.
    let mut pending: Vec<&ScopeRule> = rules.iter().rev().collect();
    while let Some(rule) = pending.pop() {
        let env = s.authorization_env(req, url_path, peer);
        let matched = match rule_condition_result(
            rule,
            req,
            &env,
            peer,
            docroot,
            url_path,
            Some(fs_path),
            chain_state,
        ) {
            Ok(matched) => matched,
            Err(error) => {
                eprintln!("vapached: conditional expression failed closed: {error}");
                s.conditional_error = true;
                continue;
            }
        };
        if !matched {
            continue;
        }
        merge_rule_delta(s, rule, fs_path, url_path);
        let mut nested = Vec::new();
        collect_rule_refs_req(
            &rule.nested,
            s,
            req,
            peer,
            docroot,
            fs_path,
            url_path,
            fname,
            &mut nested,
        );
        nested.sort_by_key(|nested_rule| nested_rule.order);
        pending.extend(nested.into_iter().rev());
    }
}

/// Borrowing form used while applying an already-owned deferred tree.  The
/// public collector must clone conditionals because callers combine rules
/// from multiple configuration/access-file owners; once that owned list is
/// being evaluated, cloning every remaining subtree at each nesting level is
/// unnecessary and can turn a deep tree into quadratic request work.
#[allow(clippy::too_many_arguments)]
fn collect_rule_refs_req<'a>(
    rules: &'a [ScopeRule],
    s: &mut Scope,
    req: &crate::http::Request,
    _peer: IpAddr,
    _docroot: &Path,
    fs_path: &Path,
    url_path: &str,
    fname: &str,
    deferred: &mut Vec<&'a ScopeRule>,
) {
    let mut pending: Vec<&ScopeRule> = rules.iter().rev().collect();
    while let Some(rule) = pending.pop() {
        let matched = match rule_kind_matches_req(&rule.kind, fs_path, url_path, fname, req) {
            Ok(matched) => matched,
            Err(_) => {
                s.conditional_error = true;
                return;
            }
        };
        if !matched {
            continue;
        }
        if rule.phase() == RulePhase::Condition {
            deferred.push(rule);
            continue;
        }
        merge_rule_delta(s, rule, fs_path, url_path);
        pending.extend(rule.nested.iter().rev());
    }
}

fn sort_rules(rules: &mut [ScopeRule]) {
    // Compile every nesting level, not only the top-level vector. Conditional
    // sections may themselves contain Directory/Files/Location sections, and
    // leaving those in source order bypassed the canonical phase compiler.
    for rule in rules.iter_mut() {
        sort_rules(&mut rule.nested);
    }
    rules.sort_by(|a, b| {
        let specificity = |rule: &ScopeRule| {
            if rule_is_conditional(rule) {
                return 0;
            }
            match &rule.kind {
                MatchKind::Directory(p) => p.as_os_str().len(),
                MatchKind::Location(p) | MatchKind::LocationGlob(p) => p.len(),
                _ => 0,
            }
        };
        let ab = vapache_verified::config_rule_precedes(
            verified_config_rule_kind(&a.kind),
            rule_is_conditional(a),
            specificity(a),
            a.order,
            verified_config_rule_kind(&b.kind),
            rule_is_conditional(b),
            specificity(b),
            b.order,
        );
        let ba = vapache_verified::config_rule_precedes(
            verified_config_rule_kind(&b.kind),
            rule_is_conditional(b),
            specificity(b),
            b.order,
            verified_config_rule_kind(&a.kind),
            rule_is_conditional(a),
            specificity(a),
            a.order,
        );
        match (ab, ba) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => std::cmp::Ordering::Equal,
        }
    });
}

pub(crate) fn parse_allow_methods(args: &[String]) -> Result<AllowMethods, String> {
    if args.is_empty() {
        return Err("AllowMethods requires a method or 'reset'".into());
    }
    if args.len() == 1 && args[0].eq_ignore_ascii_case("reset") {
        return Ok(AllowMethods::Reset);
    }
    let mut methods: Vec<String> = Vec::new();
    for arg in args {
        if arg.eq_ignore_ascii_case("reset") {
            return Err("AllowMethods: 'reset' cannot be combined with methods".into());
        }
        if !valid_method_token(arg) || !known_http_method(arg) {
            return Err(format!("AllowMethods: invalid method '{arg}'"));
        }
        if !methods.iter().any(|m| m == arg) {
            methods.push(arg.clone());
        }
    }
    Ok(AllowMethods::Only(methods))
}

/// Compile a configuration-supplied regex only after the verified dialect
/// admission check.  The external engine is assumed to implement the accepted
/// regular subset; PCRE-only constructs are rejected at load time rather than
/// silently changing meaning.
pub(crate) fn guard_regex(pattern: &str) -> Result<(), String> {
    let inline_unicode_classes = directive_regex_enables_unicode(pattern);
    if !vapache_verified::directive_regex_pattern_admit(true, false, inline_unicode_classes) {
        return Err(
            "unsupported regex mode: inline Unicode classes are not Apache-compatible".into(),
        );
    }
    if vapache_verified::regex_dialect_admit(pattern.as_bytes()) {
        Ok(())
    } else {
        Err("unsupported regex dialect: backreferences/look-around/control bytes".into())
    }
}

/// `RegexBuilder::unicode(false)` sets only the default: Rust's regex syntax
/// can turn Unicode classes back on with `(?u)`, `(?iu:...)` or `(?i-u:...)`.
/// PCRE does not use that option spelling, so accepting it both violates the
/// Apache dialect and reopens P16-B. Ignore escaped text and character classes
/// while examining inline option groups.
fn directive_regex_enables_unicode(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    let mut in_class = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i = (i + 2).min(bytes.len()),
            b'[' if !in_class => {
                in_class = true;
                i += 1;
            }
            b']' if in_class => {
                in_class = false;
                i += 1;
            }
            b'(' if !in_class && bytes.get(i + 1) == Some(&b'?') => {
                let mut j = i + 2;
                let mut option_group = false;
                while let Some(&flag) = bytes.get(j) {
                    if matches!(flag, b':' | b')') {
                        break;
                    }
                    if !matches!(flag, b'i' | b'm' | b's' | b'R' | b'U' | b'u' | b'x' | b'-') {
                        break;
                    }
                    option_group = true;
                    if flag == b'u' {
                        return true;
                    }
                    j += 1;
                }
                i += if option_group { 2 } else { 1 };
            }
            _ => i += 1,
        }
    }
    false
}

pub(crate) fn compile_regex(pattern: &str) -> Result<Regex, String> {
    compile_regex_flags(pattern, false)
}

pub(crate) fn compile_regex_flags(pattern: &str, nocase: bool) -> Result<Regex, String> {
    guard_regex(pattern)?;
    let unicode_classes = false;
    if !vapache_verified::directive_regex_mode_admit(true, unicode_classes) {
        return Err("directive regex mode is not Apache-compatible".into());
    }
    regex::bytes::RegexBuilder::new(pattern)
        .unicode(unicode_classes)
        .case_insensitive(nocase)
        .build()
        .map_err(|e| e.to_string())
}

/// True when the string contains one of the shell wildcard characters that
/// Apache's `<Location>`/`<Files>` pattern matching treats specially.
pub(crate) fn has_glob_wildcard(pattern: &str) -> bool {
    pattern.bytes().any(|b| matches!(b, b'*' | b'?' | b'['))
}

pub(crate) fn validate_glob_pattern(pattern: &str) -> Result<(), String> {
    if pattern.len() > crate::glob::MAX_PATTERN_BYTES {
        return Err(format!(
            "shell pattern exceeds {} bytes",
            crate::glob::MAX_PATTERN_BYTES
        ));
    }
    Ok(())
}

/// Compile a `<Location>` argument (F61-A/A2/B).
///
/// Apache distinguishes two forms: with `~` as the first argument the rest is
/// a regular expression (and `<Location ~>` with no expression is a
/// configuration error); otherwise the argument is a URL-path pattern in
/// which the shell wildcards `*`, `?` and `[…]` are honored.  A wildcard
/// form must be compiled to the stack-safe fnmatch evaluator at parse time —
/// leaving it a literal string silently disables every guard inside the
/// section.  In path mode the kernel keeps `*` and `?` inside their URL
/// component and anchors the match over the whole path.
pub(crate) fn compile_location_pattern(args: &[String]) -> Result<MatchKind, String> {
    if args.is_empty() {
        return Err("<Location> requires a URL path pattern".into());
    }
    if args[0] == "~" {
        if args.len() < 2 {
            return Err("<Location ~> requires a regular expression".into());
        }
        let pattern = args[1..].join(" ");
        return compile_regex(&pattern)
            .map(MatchKind::LocationMatch)
            .map_err(|e| format!("bad Location regex: {e}"));
    }
    let pattern = args.join(" ");
    validate_glob_pattern(&pattern)?;
    if has_glob_wildcard(&pattern) {
        // F61: the wildcard form is compiled to the iterative matcher
        // (`LocationGlob`).  Falling back to a literal `MatchKind::Location`
        // would silently disable every guard inside the section; the kernel
        // records the admission invariant.
        debug_assert!(vapache_verified::location_wildcard_compiled_admit(
            true, true
        ));
        return Ok(MatchKind::LocationGlob(pattern));
    }
    Ok(MatchKind::Location(pattern))
}

pub(crate) fn compile_files_pattern(args: &[String]) -> Result<MatchKind, String> {
    if args.is_empty() {
        return Err("<Files> requires a filename pattern".into());
    }
    if args[0] == "~" {
        if args.len() < 2 {
            return Err("<Files ~> requires a regular expression".into());
        }
        let pattern = args[1..].join(" ");
        return compile_regex(&pattern)
            .map(MatchKind::FilesMatch)
            .map_err(|e| format!("bad Files regex: {e}"));
    }
    let pattern = args.join(" ");
    validate_glob_pattern(&pattern)?;
    // Shell-style <Files> patterns are matched against the basename with the
    // stack-safe fnmatch implementation (F62/F62b: both `!` and `^` negate
    // a class; the old hand-rolled regex translation escaped `^` as a literal
    // and only recognized `!`).
    Ok(MatchKind::FilesGlob(pattern))
}

pub(crate) fn parse_method_set_args(
    section: &str,
    args: &[String],
    htaccess: bool,
) -> Result<MethodSet, String> {
    if args.is_empty() {
        return Err(format!("<{section}> requires at least one HTTP method"));
    }
    let mut methods: Vec<String> = Vec::new();
    for arg in args {
        if !valid_method_token(arg) {
            return Err(format!("invalid HTTP method '{arg}' in <{section}>"));
        }
        // Apache maps HEAD onto the GET method number.
        let method = if arg == "HEAD" { "GET" } else { arg.as_str() };
        if section == "limit" && method == "TRACE" {
            return Err("TRACE cannot be controlled by <Limit>, see TraceEnable".into());
        }
        // Unknown methods are only registrable from the main configuration;
        // in .htaccess Apache rejects them.  Rejecting a typo is safer than
        // silently creating a restriction that never matches.
        if htaccess && !known_http_method(method) {
            return Err(format!(
                "could not register method '{arg}' for <{section}> from .htaccess"
            ));
        }
        if !methods.iter().any(|m| m == method) {
            methods.push(method.to_string());
        }
    }
    Ok(if section == "limit" {
        MethodSet::Only(methods)
    } else {
        MethodSet::Except(methods)
    })
}

fn valid_method_token(method: &str) -> bool {
    !method.is_empty()
        && method.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn known_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET"
            | "HEAD"
            | "POST"
            | "PUT"
            | "DELETE"
            | "CONNECT"
            | "OPTIONS"
            | "TRACE"
            | "PATCH"
            | "PROPFIND"
            | "PROPPATCH"
            | "MKCOL"
            | "COPY"
            | "MOVE"
            | "LOCK"
            | "UNLOCK"
    )
}

pub(crate) fn require_syntax_error(msg: &str) -> bool {
    msg.starts_with("bad Require ip")
        || msg.starts_with("Require ip needs")
        || msg.starts_with("bad Require method")
        || msg.starts_with("Require all needs")
        || msg.starts_with("empty Require")
        || msg.starts_with("incomplete Require")
        || msg.starts_with("Require env requires")
        || msg.starts_with("empty Require env variable")
        || msg.starts_with("Require env does not support")
        || msg.starts_with("Require host dynamic")
        || msg.starts_with("Require user dynamic")
        || msg.starts_with("Require group dynamic")
        || msg.starts_with("bad Require expr")
        || msg.starts_with("unknown Require provider")
}

fn authz_string_operands_supported(operands: &[String]) -> bool {
    operands.iter().all(|operand| {
        let mut rest = operand.as_str();
        while let Some(start) = rest.find("%{") {
            let after = &rest[start + 2..];
            let Some(end) = after.find('}') else {
                return false;
            };
            let variable = &after[..end];
            let known = matches!(
                variable.to_ascii_uppercase().as_str(),
                "HTTP_HOST" | "REMOTE_ADDR" | "REQUEST_URI" | "REQUEST_METHOD"
            ) || variable
                .get(..5)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("HTTP:"))
                || variable
                    .get(..4)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("ENV:"));
            if !known {
                return false;
            }
            rest = &after[end + 1..];
        }
        true
    })
}

pub(crate) fn parse_require(args: &[String]) -> Require {
    if args.is_empty() {
        return Require::Unsupported("empty Require".into());
    }
    let mut idx = 0;
    let mut negate = false;
    if args[0].eq_ignore_ascii_case("not") {
        negate = true;
        idx = 1;
    }
    if idx >= args.len() {
        return Require::Unsupported("incomplete Require".into());
    }
    let kind = args[idx].to_ascii_lowercase();
    let rest = &args[idx + 1..];
    match kind.as_str() {
        "all" if !negate => {
            if rest.len() == 1 && rest[0].eq_ignore_ascii_case("granted") {
                Require::AllGranted
            } else if rest.len() == 1 && rest[0].eq_ignore_ascii_case("denied") {
                Require::AllDenied
            } else {
                Require::Unsupported("Require all needs granted/denied".into())
            }
        }
        "ip" => {
            if rest.is_empty() {
                return Require::Unsupported("Require ip needs an address".into());
            }
            let mut nets = Vec::new();
            for a in rest {
                match parse_ip_net(a) {
                    Some(n) => nets.push(n),
                    None => return Require::Unsupported(format!("bad Require ip '{a}'")),
                }
            }
            Require::Ip { negate, nets }
        }
        "local" => Require::Local { negate },
        "host" => {
            if !authz_string_operands_supported(rest) {
                return Require::Unsupported(
                    "Require host dynamic expressions are not supported safely".into(),
                );
            }
            Require::Host {
                negate,
                names: rest.to_vec(),
            }
        }
        "method" => {
            let methods: Vec<String> = rest.to_vec();
            if !vapache_verified::require_method_operand_admit(
                !methods.is_empty(),
                methods.iter().all(|method| known_http_method(method)),
            ) {
                return Require::Unsupported("bad Require method".into());
            }
            Require::Method { negate, methods }
        }
        "env" => {
            if rest.is_empty() {
                return Require::Unsupported("Require env requires a variable".into());
            }
            let mut names = Vec::with_capacity(rest.len());
            for item in rest {
                let has_equals = item.contains('=');
                let name = item.split_once('=').map(|(name, _)| name).unwrap_or(item);
                if !vapache_verified::require_env_operand_admit(!name.is_empty(), has_equals) {
                    if has_equals {
                        return Require::Unsupported(
                            "Require env does not support NAME=VALUE comparisons".into(),
                        );
                    }
                    return Require::Unsupported("empty Require env variable".into());
                }
                names.push(name.to_string());
            }
            Require::Env { negate, names }
        }
        "expr" => {
            let text = rest.join(" ");
            match crate::expr::parse(&text) {
                Ok(expr) => {
                    // F63/I63: unknown variables fail closed as an
                    // unsupported provider (denied), not as an empty string.
                    match crate::expr::validate_vars(&expr) {
                        Ok(()) => Require::Expr { negate, expr },
                        Err(e) => Require::Unsupported(format!("bad Require expr: {e}")),
                    }
                }
                Err(e) => Require::Unsupported(format!("bad Require expr: {e}")),
            }
        }
        "valid-user" => Require::ValidUser { negate },
        "user" => {
            if !authz_string_operands_supported(rest) {
                return Require::Unsupported(
                    "Require user dynamic expressions are not supported safely".into(),
                );
            }
            Require::User {
                negate,
                names: rest.to_vec(),
            }
        }
        "group" => {
            if !authz_string_operands_supported(rest) {
                return Require::Unsupported(
                    "Require group dynamic expressions are not supported safely".into(),
                );
            }
            Require::Group {
                negate,
                names: rest.to_vec(),
            }
        }
        "dbm" | "dbd" | "ldap" | "file" => {
            Require::Unsupported("this authentication provider is not implemented".into())
        }
        other => Require::Unsupported(format!("unknown Require provider '{other}'")),
    }
}

pub(crate) fn parse_rewrite_flags(args: &[String]) -> Result<RewriteFlags, String> {
    let raw = args.join(",");
    let raw = raw.trim().replace('[', "").replace(']', "");
    let mut out = RewriteFlags::default();
    if raw.is_empty() {
        return Ok(out);
    }
    for flag in raw.split(',') {
        let flag = flag.trim();
        if flag.is_empty() {
            continue;
        }
        let upper = flag.to_ascii_uppercase();
        match upper.as_str() {
            "L" => out.last = true,
            "END" => {
                out.last = true;
                out.end = true;
            }
            "QSA" => out.qsa = true,
            "NC" => out.nocase = true,
            "NE" => out.noescape = true,
            "PT" => out.passthrough = true,
            "P" => out.proxy = true,
            "C" => out.chain = true,
            "N" => out.next = true,
            "QSD" => out.qsd = true,
            "QSL" => out.qslast = true,
            "UNSAFEALLOW3F" => out.unsafe_allow_3f = true,
            "B" => out.escape_backrefs = true,
            "BNE" => {
                out.escape_backrefs = true;
                out.noescape_backrefs = true;
            }
            "BNP" => out.backref_no_plus = true,
            "BCTLS" => {
                out.escape_backrefs = true;
                out.escape_controls = true;
            }
            "UNSAFEPREFIXSTAT" => out.unsafe_prefix_stat = true,
            "DPI" => {
                return Err(
                    "RewriteRule flag '[DPI]' is not implemented; refusing to ignore path-info discarding"
                        .into(),
                )
            }
            "F" => out.forbidden = true,
            "G" => out.gone = true,
            "R" => out.redirect = Some(302),
            _ if upper.starts_with("R=") => {
                let value = &upper[2..];
                let code = match value {
                    "PERMANENT" => 301,
                    "TEMP" => 302,
                    "SEEOTHER" => 303,
                    _ => value
                        .parse::<u16>()
                        .map_err(|_| format!("invalid RewriteRule redirect status '{value}'"))?,
                };
                if !(300..=599).contains(&code) {
                    return Err(format!("invalid RewriteRule redirect status '{value}'"));
                }
                out.redirect = Some(code);
            }
            _ if upper.starts_with("B=") => {
                out.escape_backrefs = true;
                out.escape_chars = flag[2..].to_string();
            }
            _ if upper.starts_with("BNE=") => {
                out.escape_backrefs = true;
                out.noescape_backrefs = true;
                out.noescape_chars = flag[4..].to_string();
            }
            _ if upper.starts_with("E=") => {
                let raw = &flag[2..];
                if let Some(name) = raw.strip_prefix('!') {
                    out.env.push((name.to_string(), None));
                } else if let Some((k, v)) = raw.split_once(':') {
                    out.env.push((k.to_string(), Some(v.to_string())));
                } else {
                    out.env.push((raw.to_string(), Some(String::new())));
                }
            }
            _ if upper.starts_with("CO=") => {
                out.cookies.push(flag[3..].to_string());
            }
            _ if upper.starts_with("H=") => {
                out.handler = Some(flag[2..].to_string());
            }
            _ if upper.starts_with("T=") => {
                out.content_type = Some(flag[2..].to_string());
            }
            _ if upper.starts_with("S=") => {
                out.skip = Some(
                    upper[2..]
                        .parse::<usize>()
                        .map_err(|_| format!("invalid RewriteRule skip value '{flag}'"))?,
                );
            }
            "NS" => {
                return Err(
                    "RewriteRule flag '[NS]' is not implemented; refusing to apply the rule to internal subrequests"
                        .into(),
                )
            }
            _ => return Err(format!("unsupported RewriteRule flag '[{flag}]'")),
        }
    }
    out.escape_backrefs =
        vapache_verified::rewrite_backref_escape_admit(out.escape_backrefs, out.noescape_backrefs);
    Ok(out)
}

fn reject_rewrite_lookahead(value: &str) -> Result<(), String> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("%{la-") || lower.contains("${la-") {
        return Err("mod_rewrite lookahead (%{LA-...}) is unsupported and fails closed".into());
    }
    Ok(())
}

pub(crate) fn parse_rewrite_cond(args: &[String]) -> Result<RewriteCond, String> {
    for arg in args {
        reject_rewrite_lookahead(arg)?;
    }
    if args.first().map(|a| a.eq_ignore_ascii_case("expr")) == Some(true) {
        let mut flags = RewriteCondFlags::default();
        let mut end = args.len();
        let last = args.last().expect("expr condition has an expression");
        if last.trim_start().starts_with('[') {
            let raw = last.trim().replace(['[', ']'], "");
            for flag in raw.split(',') {
                match flag.trim().to_ascii_uppercase().as_str() {
                    "NC" => flags.nocase = true,
                    "OR" => flags.or = true,
                    other => return Err(format!("unsupported RewriteCond flag '[{other}]'")),
                }
            }
            end -= 1;
        }
        let expr = crate::expr::parse(&args[1..end].join(" "))
            .map_err(|e| format!("bad RewriteCond expr: {e}"))?;
        // F63/I63: unknown variables are a configuration error, never an
        // empty-string substitution.
        crate::expr::validate_vars(&expr).map_err(|e| format!("bad RewriteCond expr: {e}"))?;
        return Ok(RewriteCond {
            test: String::new(),
            pattern: String::new(),
            flags,
            regex: None,
            expr: Some(expr),
        });
    }
    if args.len() < 2 {
        return Err("RewriteCond requires a test string and a pattern".into());
    }
    let mut flags = RewriteCondFlags::default();
    let raw = args[2..].join(",");
    let raw = raw.trim().replace('[', "").replace(']', "");
    if !raw.is_empty() {
        for flag in raw.split(',') {
            match flag.trim().to_ascii_uppercase().as_str() {
                "NC" => flags.nocase = true,
                "OR" => flags.or = true,
                "AND" => {}
                "" => {}
                other => return Err(format!("unsupported RewriteCond flag '[{other}]'")),
            }
        }
    }
    let raw_pattern = args[1].as_str();
    if raw_pattern.contains("%{") || raw_pattern.contains("${") {
        return Err("variables are not supported in RewriteCond patterns".into());
    }
    let stripped = raw_pattern.strip_prefix('!').unwrap_or(raw_pattern);
    let regex = if stripped.starts_with("-f")
        || stripped.starts_with("-d")
        || stripped.starts_with("-s")
        || stripped.starts_with("-l")
        || stripped.starts_with('=')
    {
        None
    } else {
        {
            Some(Arc::new(
                compile_regex_flags(stripped, flags.nocase)
                    .map_err(|e| format!("invalid RewriteCond pattern: {e}"))?,
            ))
        }
    };
    Ok(RewriteCond {
        test: args[0].clone(),
        pattern: args[1].clone(),
        flags,
        regex,
        expr: None,
    })
}

pub(crate) fn parse_rewrite_rule(
    args: &[String],
    base: &str,
    per_dir: bool,
) -> Result<RewriteRule, String> {
    if args.len() < 2 {
        return Err("RewriteRule requires a pattern and substitution".into());
    }
    for arg in args.iter().take(2) {
        reject_rewrite_lookahead(arg)?;
    }
    let flags = parse_rewrite_flags(&args[2..])?;
    if flags.proxy && !proxy_template_authority_safe(&args[1]) {
        return Err(
            "RewriteRule [P] authority may not be derived from a request capture or variable"
                .into(),
        );
    }
    let raw_pattern = &args[0];
    if raw_pattern.contains("%{") || raw_pattern.contains("${") {
        return Err("variables are not supported in RewriteRule patterns".into());
    }
    let (negated, pattern) = match raw_pattern.strip_prefix('!') {
        Some(p) => (true, p),
        None => (false, raw_pattern.as_str()),
    };
    let pattern = compile_regex_flags(pattern, flags.nocase)
        .map_err(|e| format!("invalid RewriteRule pattern: {e}"))?;
    Ok(RewriteRule {
        pattern: Arc::new(pattern),
        negated,
        substitution: args[1].clone(),
        flags,
        conditions: Vec::new(),
        base: normalize_rewrite_base(base),
        match_base: normalize_rewrite_base(base),
        subject_dir: None,
        per_dir,
        access_file: false,
    })
}

pub(crate) fn normalize_rewrite_base(base: &str) -> String {
    if base.is_empty() {
        return "/".into();
    }
    let mut out = String::with_capacity(base.len() + 2);
    if !base.starts_with('/') {
        out.push('/');
    }
    out.push_str(base);
    if !out.ends_with('/') {
        out.push('/');
    }
    out
}

pub(crate) fn parse_ip_net(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, bits) = match s.split_once('/') {
        Some((ip, b)) => (ip, Some(b)),
        None => (s, None),
    };
    let addr: IpAddr = ip.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let bits = match bits {
        Some(b) => b.parse::<u8>().ok()?,
        None => max,
    };
    if bits > max {
        return None;
    }
    Some((addr, bits))
}

pub(crate) fn parse_listen(s: &str) -> Result<ListenSpec, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty Listen".into());
    }
    let (addr, port) = if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']').ok_or("bad IPv6 Listen address")?;
        let a = &rest[..end];
        let after = &rest[end + 1..];
        let p = after.strip_prefix(':').unwrap_or("80");
        (a.to_string(), p.to_string())
    } else if let Some((a, p)) = s.rsplit_once(':') {
        if a.contains(':') {
            // IPv6 without brackets.
            (s.to_string(), "80".to_string())
        } else {
            (a.to_string(), p.to_string())
        }
    } else {
        ("0.0.0.0".to_string(), s.to_string())
    };
    let port: u16 = port
        .parse()
        .map_err(|_| format!("invalid Listen port in '{s}'"))?;
    let addr = if addr.is_empty() || addr == "*" {
        "0.0.0.0".to_string()
    } else {
        addr
    };
    Ok(ListenSpec {
        raw: s.to_string(),
        addr,
        port,
    })
}

/// Directives whose absence would silently weaken an access, authorization,
/// proxy, filter or path policy.  These must fail closed even in compatibility
/// mode; a harmless module directive may be ignored, but a security control
/// may not.
/// Security-relevant directives whose absence would silently weaken a
/// policy.  Handled directives never reach the fallback; this classifier is
/// deliberately broader than the explicit list so an unknown member of an
/// auth/TLS/proxy/filter/DAV/LDAP/cache family fails closed too.
#[cfg(test)]
fn is_security_directive(name: &str) -> bool {
    is_security_directive_with(name, &fail_closed_directives())
}

fn is_security_directive_with(name: &str, fail_closed: &HashSet<&'static str>) -> bool {
    if fail_closed.contains(name) {
        return true;
    }
    [
        "acceptpathinfo",
        "allowconnect",
        "auth",
        "cache",
        "dav",
        "extfilter",
        "filter",
        "ldap",
        "proxy",
        "requestheader",
        "sec",
        "setenvifexpr",
        "ssl",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn fail_closed_directives() -> HashSet<&'static str> {
    [
        "acceptpathinfo",
        "action",
        "authnprovideralias",
        "authzprovideralias",
        "browseripmatch",
        "cgidscripttimeout",
        "extfilterdefine",
        "extfilteroptions",
        "filterchain",
        "filterdeclare",
        "filterprovider",
        "forceauthoritative",
        "inputfilter",
        "limitinternalrecursion",
        "limitxmlrequestbody",
        "outputfilterbytype",
        "protocolshonororder",
        "proxyblock",
        "removeinputfilter",
        "removeoutputfilter",
        "requestheader",
        "rlimitcpu",
        "rlimitmem",
        "rlimitnofile",
        "rlimitnproc",
        "scriptlog",
        "scriptlogbuffer",
        "scriptloglength",
        "setenvifexpr",
        "transferlog",
    ]
    .into_iter()
    .collect()
}

pub(crate) fn proxy_template_authority_safe(value: &str) -> bool {
    let value = value.trim();
    let Some((_, rest)) = value.split_once("://") else {
        // Non-URL backends (notably Unix FastCGI sockets) must not be
        // derivable from a rewrite capture either.
        return vapache_verified::rewrite_template_static(value.as_bytes());
    };
    let end = rest
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    !authority.is_empty()
        && vapache_verified::rewrite_template_static(authority.as_bytes())
        && !authority.contains('@')
}

pub(crate) fn supported_proxy_backend(value: &str, allow_fastcgi: bool) -> bool {
    let value = value.trim();
    value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("ws://")
        || value.starts_with("wss://")
        || value.starts_with("balancer://")
        || (allow_fastcgi && value.starts_with("unix:"))
}

fn known_directives() -> HashSet<&'static str> {
    // Directives from modules not yet implemented.  Keeping an explicit list
    // (rather than accepting every unknown token) means a typo in a security
    // directive is still a startup error under --strict-config.
    [
        "acceptfilter",
        "acceptpathinfo",
        "accessfilename",
        "action",
        "addalt",
        "addaltbyencoding",
        "addaltbytype",
        "addcharset",
        "adddefaultcharset",
        "adddescription",
        "addencoding",
        "addhandler",
        "addicon",
        "addiconbyencoding",
        "addiconbytype",
        "addlanguage",
        "addmoduleinfo",
        "addoutputfilter",
        "addoutputfilterbytype",
        "addtype",
        "alias",
        "aliasmatch",
        "allow",
        "allowconnect",
        "allowencodedslashes",
        "allowmethods",
        "allowoverride",
        "allowoverridelist",
        "authbasicauthoritative",
        "authbasicfake",
        "authbasicprovider",
        "authbasicusedigestalgorithm",
        "authcache",
        "authdbmtype",
        "authdbmuserfile",
        "authdigestalgorithm",
        "authdigestdomain",
        "authdigestnccheck",
        "authdigestnonceformat",
        "authdigestnoncelifetime",
        "authdigestprovider",
        "authdigestqop",
        "authdigestshmemsize",
        "authformauthoritative",
        "authformbody",
        "authformfakebasicauth",
        "authformlocation",
        "authformlogintimeout",
        "authformmethod",
        "authformmimetype",
        "authformpassword",
        "authformprovider",
        "authformsitepassphrase",
        "authformsize",
        "authformusername",
        "authgroupfile",
        "authldapbindauthoritative",
        "authldapbinddn",
        "authldapbindpassword",
        "authldapcharsetconfig",
        "authldapcompareasuser",
        "authldapcomparednonserver",
        "authldapderefaliases",
        "authldapgroupattribute",
        "authldapgroupattributeisdn",
        "authldapinitialbindasuser",
        "authldapinitialbindpattern",
        "authldapmaxsubgroupdepth",
        "authldapreferrals",
        "authldapremoteuserattribute",
        "authldapremoteuserisdn",
        "authldapurl",
        "authmerging",
        "authname",
        "authnprovideralias",
        "authntrace",
        "authtype",
        "authuserfile",
        "authzprovideralias",
        "browsermatch",
        "browseripmatch",
        "buffersize",
        "cachedefaultexpire",
        "cachedetailheader",
        "cachedirlength",
        "cachedirlevels",
        "cachedisable",
        "cacheenable",
        "cachefile",
        "cacheheader",
        "cacheignorecachecontrol",
        "cacheignoreheaders",
        "cacheignorenolastmod",
        "cacheignorequerystring",
        "cachelastmodifiedfactor",
        "cachelock",
        "cachemaxexpire",
        "cachemaxfilesize",
        "cacheminsize",
        "cacheminexpire",
        "cachenegotiateddocs",
        "cachequickhandler",
        "cachereadsize",
        "cachereadsize",
        "cacheremote",
        "cacheroot",
        "cachesocache",
        "cachesocachemaxobjectsize",
        "cachesocachemaxstreamingbuffersize",
        "cachesocacheminobjectsize",
        "cachesochereadsize",
        "cachestorenostore",
        "cachestoreprivate",
        "cachestoresession",
        "cachettl",
        "cgidscripttimeout",
        "charsetdefault",
        "charsetoptions",
        "charsetsourceenc",
        "checkcaseonly",
        "checkspelling",
        "contentdigest",
        "cookiedomain",
        "cookieexpires",
        "cookiename",
        "cookiestyle",
        "cookietracking",
        "coredumpdirectory",
        "customlog",
        "dav",
        "davdepthinfinity",
        "davgenericlockdb",
        "davlockdb",
        "davmintimeout",
        "dbdexptime",
        "dbdkeep",
        "dbdmax",
        "dbdmin",
        "dbdparams",
        "dbdpersist",
        "dbdpreparesql",
        "dbdriver",
        "defaulticon",
        "defaultlanguage",
        "defaultruntimedir",
        "defaulttype",
        "deflatebuffersize",
        "deflatecompressionlevel",
        "deflatefilternote",
        "deflatememlevel",
        "deflatewindowssize",
        "definemodule",
        "definemodulesql",
        "deny",
        "directory",
        "directoryindex",
        "directorymatch",
        "directoryslash",
        "disableimagemaps",
        "documentroot",
        "dumpioinput",
        "dumpiooutput",
        "enablemmap",
        "enablesendfile",
        "enableexceptionhook",
        "errordocument",
        "errorlog",
        "errorlogformat",
        "expiresactive",
        "expiresbytype",
        "expiresdefault",
        "extendedstatus",
        "extfilterdefine",
        "extfilteroptions",
        "fallbackresource",
        "fileetag",
        "files",
        "filesmatch",
        "filterchain",
        "filterdeclare",
        "filterprotocol",
        "filterprovider",
        "filtertrace",
        "forceauthoritative",
        "forcelanguagepriority",
        "forcetype",
        "forensiclog",
        "globalmutex",
        "group",
        "header",
        "headerif",
        "headername",
        "heartbeataddress",
        "heartbeatlisten",
        "heartbeatserver",
        "heartbeatstorage",
        "hostnamelookups",
        "identitycheck",
        "identitychecktimeout",
        "imapbase",
        "imapdefault",
        "imapmenu",
        "include",
        "includeoptional",
        "indexignore",
        "indexlegend",
        "indexoptions",
        "indexorderdefault",
        "indexstylesheet",
        "inputfilter",
        "isapiimplements",
        "isapilognotsupported",
        "isapireadaheadbuffer",
        "keepalive",
        "keepalivetimeout",
        "keptbodysize",
        "languagepriority",
        "ldapcacheentries",
        "ldapcachettl",
        "ldapconnectiontimeout",
        "ldapopcacheentries",
        "ldapopcachettl",
        "ldapreferralhoplimit",
        "ldapreferrals",
        "ldapretries",
        "ldapretrydelay",
        "ldapsharedcachefile",
        "ldapsharedcachesize",
        "ldaptrustedca",
        "ldaptrustedcatype",
        "ldaptrustedclientcert",
        "ldaptrustedglobalcert",
        "ldaptrustedmode",
        "ldapverifyservercert",
        "limit",
        "limitexcept",
        "limitinternalrecursion",
        "limitrequestbody",
        "limitrequestfields",
        "limitrequestfieldsize",
        "limitrequestline",
        "limitxmlrequestbody",
        "listen",
        "gracefulshutdowntimeout",
        "gracefulshutdowntimeout",
        "maxconnectionsperchild",
        "listenbacklog",
        "loadfile",
        "loadmodule",
        "logformat",
        "loglevel",
        "logmessage",
        "maxclients",
        "maxkeepaliverequests",
        "maxmemfree",
        "maxrangeoverlaps",
        "maxranges",
        "maxrequestworkers",
        "maxspareservers",
        "maxsparethreads",
        "maxthreads",
        "maxthreadsperchild",
        "mcachemaxobjectcount",
        "mcachemaxobjectsize",
        "mcachemaxstreamingbuffersize",
        "mcacheminobjectsize",
        "mcacheremovalalgorithm",
        "mcachesize",
        "metadir",
        "metafiles",
        "metasuffix",
        "mimemagicfile",
        "minspareservers",
        "minsparethreads",
        "modmimeuseapachemagic",
        "multiviewsmatch",
        "mutex",
        "namevirtualhost",
        "negotiationengine",
        "nwssltrustedcerts",
        "nwsslupgradeable",
        "options",
        "order",
        "outputfilterbytype",
        "passenv",
        "pidfile",
        "privilegesmode",
        "protocol",
        "protocols",
        "protocolshonororder",
        "proxy",
        "proxybadheader",
        "proxyblock",
        "proxydomain",
        "proxyerroroverride",
        "proxyfcgibackendtype",
        "proxyfcgisendenv",
        "proxyftpallowmdtm",
        "proxyiobuffersize",
        "proxymatch",
        "proxymaxforwards",
        "proxyhccheck",
        "proxyhctemplate",
        "proxypass",
        "proxypassinherit",
        "proxypassinterpolateenv",
        "proxypassmatch",
        "proxypassnobuffer",
        "proxypassreverse",
        "proxypassreversecookiepath",
        "proxypassreversecookiedomain",
        "proxypreservehost",
        "proxyreceivebuffersize",
        "proxyremote",
        "proxyremotematch",
        "proxyrequests",
        "proxyset",
        "proxysource",
        "proxystatus",
        "proxytimeout",
        "proxyvia",
        "readmename",
        "redirect",
        "redirectmatch",
        "redirectpermanent",
        "redirecttemp",
        "reflectorheader",
        "refurl",
        "removetype",
        "removecharset",
        "removeencoding",
        "removehandler",
        "removeinputfilter",
        "removeoutputfilter",
        "requestheader",
        "requestreadtimeout",
        "require",
        "rewritebase",
        "rewritecond",
        "rewriteengine",
        "rewriteinherit",
        "rewritelock",
        "rewriteloglevel",
        "rewritemap",
        "rewriteoptions",
        "rewriterule",
        "rlimitcpu",
        "rlimitmem",
        "rlimitnofile",
        "rlimitnproc",
        "satisfy",
        "scoreboardfile",
        "script",
        "scriptalias",
        "scriptaliasmatch",
        "scriptinterpretersource",
        "scriptlog",
        "scriptlogbuffer",
        "scriptloglength",
        "seccacherequestheader",
        "seccacherequestheader",
        "seccacherequestheaders",
        "seccacherequesttime",
        "seccachesocache",
        "seccachesocacheexpiry",
        "seccheckerreq",
        "seccheckerreq",
        "secdebuglog",
        "secdebugloglevel",
        "secdefaultaction",
        "secrule",
        "secruleengine",
        "secruleinheritance",
        "secruleremovebyid",
        "secruleremovetargetbyid",
        "secrulevariables",
        "secserverlocale",
        "secuploaddir",
        "secuploadfilelimit",
        "secdownloaddir",
        "secauditengine",
        "secauditlog",
        "secauditlogparts",
        "secauditlogtype",
        "secbodyinspectionlimit",
        "seccollectiontimeout",
        "seccookieformat",
        "seccontentinjection",
        "secdatadirstorage",
        "secstatusengine",
        "serveradmin",
        "serverlimit",
        "serveralias",
        "servername",
        "serverpath",
        "serverroot",
        "serversignature",
        "servertokens",
        "session",
        "sessioncookiename",
        "sessioncookiessecure",
        "sessioncookiepath",
        "sessionmaxage",
        "setenv",
        "setenvif",
        "setenvifexpr",
        "setenvifnocase",
        "sethandler",
        "singlelisten",
        "sslcacertificatefile",
        "sslcacertificatepath",
        "sslcarevocationcheck",
        "sslcarevocationfile",
        "sslcarevocationpath",
        "sslciphersuite",
        "sslcompression",
        "sslcryptodevice",
        "sslengine",
        "sslfips",
        "sslhonorcipherorder",
        "sslinsecurerenegotiation",
        "sslocspdefaultresponder",
        "sslocspenable",
        "sslocspnoverify",
        "sslocspoverrideresponder",
        "sslocsprespondertimeout",
        "sslocspuserequestnonce",
        "sslopensslconfcmd",
        "ssloptions",
        "sslpassphrasedialog",
        "sslprotocol",
        "sslrequire",
        "sslproxycacertificatefile",
        "sslproxycacertificatepath",
        "sslproxycarevocationfile",
        "sslproxycarevocationpath",
        "sslproxycheckpeercn",
        "sslproxycheckpeerexpire",
        "sslproxyciphersuite",
        "sslproxyengine",
        "sslproxymachinecertificatechainfile",
        "sslproxymachinecertificatefile",
        "sslproxymachinecertificatepath",
        "sslproxyprotocol",
        "sslproxyverify",
        "sslproxyverifydepth",
        "sslrandomseed",
        "sslrenegbuffersize",
        "sslrequiressl",
        "sslsessioncache",
        "sslsessioncachetimeout",
        "sslsessionticketkeyfile",
        "sslsessionticketkeys",
        "sslsessiontickets",
        "sslstaplingcache",
        "sslstaplingforceurl",
        "sslstaplingrespondertimeout",
        "sslstaplingreturnrespondererrors",
        "sslstaplingstandardcachetimeout",
        "sslstaplingstaplingnoverify",
        "sslstrictpeernamecheck",
        "sslstrictpeernamecheck",
        "sslusername",
        "sslusestapling",
        "sslverifyclient",
        "sslverifydepth",
        "sslcertificatechainfile",
        "sslcertificatefile",
        "sslcertificatekeyfile",
        "sslcrlfile",
        "sslproxycrlfile",
        "sslcertificatefile",
        "startservers",
        "status",
        "substitute",
        "substituteinheritance",
        "suexec",
        "suexecusergroup",
        "threadlimit",
        "threadsperchild",
        "threadstacksize",
        "timeout",
        "traceenable",
        "transferlog",
        "typesconfig",
        "undefine",
        "unsetenv",
        "usecanonicalname",
        "usecanonicalphysicalport",
        "user",
        "userdir",
        "userdirnegotiation",
        "vapachefastcgistablepath",
        "vapachemaxdynamicrequests",
        "vapachemaxfastcgioutput",
        "vapachemaxspoolbytes",
        "vapachemaxspoolfiles",
        "vapachecapability",
        "variantname",
        "virtualhost",
        "xml2encalias",
        "xml2encdefault",
        "xml2encrequires",
        "xsltengine",
        "xsltlocale",
        "xsltprocenv",
        "sslstaplingcache",
        "sslcertificatefile",
        "protocols",
        "protocoldirective",
    ]
    .into_iter()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_dialect_guard_rejects_unsupported_constructs() {
        assert!(compile_regex("^/index\\.html$").is_ok());
        assert!(compile_regex("(?i:index)").is_ok());
        assert!(compile_regex("(?=index)").is_err());
        assert!(compile_regex("(index)\\1").is_err());
        assert!(compile_regex("(?<!x)y").is_err());
    }

    fn require_entries(policy: Option<AuthPolicy>) -> Vec<RequireEntry> {
        match policy {
            Some(AuthPolicy::List(entries)) => entries,
            other => panic!("expected a flat Require list, got {other:?}"),
        }
    }

    fn test_request(method: &str) -> crate::http::Request {
        crate::http::Request {
            method: method.into(),
            target: b"/x".to_vec(),
            raw_path: b"/x".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    #[test]
    fn globs() {
        assert!(glob_match(b"*.conf", b"site.conf"));
        assert!(!glob_match(b"*.conf", b"site.txt"));
        assert!(glob_match(b"a?c", b"abc"));
        assert!(glob_match(b"[abc]x", b"bx"));
        assert!(glob_match(b"[!abc]x", b"dx"));
    }

    #[test]
    fn require_parse() {
        let r = parse_require(&["all".into(), "granted".into()]);
        assert!(matches!(r, Require::AllGranted));
        let r = parse_require(&["ip".into(), "10.0.0.0/8".into()]);
        match r {
            Require::Ip { nets, .. } => assert_eq!(nets.len(), 1),
            _ => panic!(),
        }
        let r = parse_require(&["expr".into(), "true".into()]);
        assert!(matches!(r, Require::Expr { .. }));
        let r = parse_require(&["env".into(), "ALLOW_ME".into()]);
        assert!(matches!(r, Require::Env { .. }));
        // Negation must shift with the provider operand, not read `args[1]`
        // (which is the literal word `env`).
        let r = parse_require(&["not".into(), "env".into(), "BLOCK".into()]);
        match r {
            Require::Env { negate, names } => {
                assert!(negate);
                assert_eq!(names, vec!["BLOCK"]);
            }
            _ => panic!(),
        }
        match parse_require(&["env".into(), "FIRST".into(), "SECOND".into()]) {
            Require::Env { names, .. } => assert_eq!(names, vec!["FIRST", "SECOND"]),
            _ => panic!(),
        }
        assert!(matches!(
            parse_require(&["all".into(), "granted".into(), "denied".into()]),
            Require::Unsupported(_)
        ));
        assert!(matches!(
            parse_require(&["not".into(), "env".into(), "BLOCK=1".into()]),
            Require::Unsupported(_)
        ));
        assert!(matches!(
            parse_require(&["method".into(), "get".into()]),
            Require::Unsupported(_)
        ));
        let r = parse_require(&[
            "not".into(),
            "expr".into(),
            "%{ENV:BLOCK}".into(),
            "==".into(),
            "''".into(),
        ]);
        assert!(matches!(r, Require::Expr { .. }));
    }

    #[test]
    fn listen_parse() {
        assert_eq!(parse_listen("8080").unwrap().port, 8080);
        assert_eq!(parse_listen("127.0.0.1:8081").unwrap().addr, "127.0.0.1");
        assert_eq!(parse_listen("[::1]:8082").unwrap().addr, "::1");
    }

    #[test]
    fn vhost_selection_respects_destination_address() {
        let cfg = load_text(
            "Listen 0.0.0.0:19213\n\
             ServerName public.local\n\
             DocumentRoot /srv/public\n\
             <VirtualHost 127.0.0.1:19213>\n\
                 ServerName admin.local\n\
                 DocumentRoot /srv/private\n\
             </VirtualHost>\n\
             <VirtualHost *:19213>\n\
                 ServerName public.local\n\
                 DocumentRoot /srv/public\n\
             </VirtualHost>\n",
            false,
        )
        .unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let other: IpAddr = "127.0.0.2".parse().unwrap();
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let admin =
            |v: Option<&VHost>| v.and_then(|v| v.server_name.as_deref()) == Some("admin.local");

        assert!(admin(cfg.select_vhost(
            Some(loopback),
            19213,
            Some("admin.local")
        )));
        assert!(admin(cfg.select_vhost(
            Some(mapped),
            19213,
            Some("admin.local")
        )));
        // The loopback-bound vhost is not eligible on another address even
        // when the attacker controls Host (F48).
        assert!(!admin(cfg.select_vhost(
            Some(other),
            19213,
            Some("admin.local")
        )));
        // An exact-address vhost wins over a wildcard vhost on its address,
        // matching Apache's address/port bucket precedence.
        assert!(admin(cfg.select_vhost(
            Some(loopback),
            19213,
            Some("public.local")
        )));
        assert!(!admin(cfg.select_vhost(
            Some(other),
            19213,
            Some("public.local")
        )));
        // Without a destination address the historical Host-first behavior
        // remains available for --explain.
        assert!(admin(cfg.select_vhost(None, 19213, Some("admin.local"))));
        assert!(cfg.select_vhost(Some(loopback), 19214, None).is_none());
    }

    fn load_text_with_prelude(
        prelude: &str,
        text: &str,
        strict: bool,
        capability_audit: bool,
    ) -> Result<Config, Vec<ConfigError>> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vapache-config-test-{}-{}.conf",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, format!("{prelude}{text}")).unwrap();
        let result = if capability_audit {
            Config::load_capability_audit(
                &path,
                std::env::temp_dir().as_path(),
                &HashMap::new(),
                &HashMap::new(),
                strict,
            )
        } else {
            Config::load(
                &path,
                std::env::temp_dir().as_path(),
                &HashMap::new(),
                &HashMap::new(),
                strict,
            )
        };
        let _ = std::fs::remove_file(path);
        result
    }

    fn load_text(text: &str, strict: bool) -> Result<Config, Vec<ConfigError>> {
        load_text_with_prelude(TEST_CAPABILITIES, text, strict, false)
    }

    fn load_text_default(text: &str) -> Result<Config, Vec<ConfigError>> {
        load_text_with_prelude("", text, false, false)
    }

    #[test]
    fn compiled_vhost_index_preserves_first_match_and_bounds_wildcards() {
        let cfg = load_text(
            "Listen 127.0.0.1:19215\n\
             <VirtualHost *:19215>\nServerName first.test\nServerAlias *.example.test\n</VirtualHost>\n\
             <VirtualHost *:19215>\nServerName exact.example.test\n</VirtualHost>\n",
            false,
        )
        .unwrap();
        let selected = cfg
            .select_vhost(
                Some("127.0.0.1".parse().unwrap()),
                19215,
                Some("exact.example.test"),
            )
            .unwrap();
        assert_eq!(selected.server_name.as_deref(), Some("first.test"));

        let aliases = (0..=MAX_VHOST_WILDCARD_PATTERNS)
            .map(|index| format!("ServerAlias *.wildcard-{index}.test\n"))
            .collect::<String>();
        let error = load_text(
            &format!("Listen 127.0.0.1:19216\n<VirtualHost *:19216>\n{aliases}</VirtualHost>\n"),
            false,
        )
        .unwrap_err();
        assert!(
            error[0].msg.contains("wildcard alias count"),
            "unexpected error: {:?}",
            error
        );
    }

    #[test]
    fn serverroot_is_execute_on_read_for_relative_includes() {
        let dir = std::env::temp_dir().join(format!(
            "vapache-serverroot-exec-on-read-{}",
            std::process::id()
        ));
        let root = dir.join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("included.conf"), "ServerName included.test\n").unwrap();
        let main = dir.join("main.conf");
        std::fs::write(
            &main,
            format!(
                "ServerRoot \"{}\"\nInclude included.conf\nListen 127.0.0.1:0\n",
                root.display()
            ),
        )
        .unwrap();
        let cfg = Config::load(&main, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        assert_eq!(cfg.server_root, root);
        assert_eq!(cfg.server_name.as_deref(), Some("included.test"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn typed_config_program_seals_sections_and_payload_schema() {
        let loc = SourceLoc {
            file: "test.conf".into(),
            line: 1,
        };
        let program = ConfigProgram::seal(vec![
            Event::SectionStart {
                name: "directory".into(),
                args: vec!["/srv".into()],
                loc: loc.clone(),
                active: true,
                transparent: false,
            },
            Event::Directive {
                name: "require".into(),
                args: vec!["all".into(), "granted".into()],
                loc: loc.clone(),
            },
            Event::SectionEnd { loc },
        ])
        .unwrap();
        assert_eq!(program.instructions.len(), 3);
        assert!(matches!(
            &program.instructions[0],
            ProgramEvent::SectionStart {
                class: ProgramSectionClass::Directory,
                end: 2,
                ..
            }
        ));
        assert!(matches!(
            &program.instructions[2],
            ProgramEvent::SectionEnd { start: 0, .. }
        ));

        let errors = load_text("Alias /missing-target\n", false).unwrap_err();
        assert!(
            errors.iter().any(|error| error.msg.contains("exactly 2")),
            "{errors:?}"
        );

        let errors =
            load_text("<Directory /srv>\nAuthUserFile \"\"\n</Directory>\n", false).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.msg.contains("does not permit an empty argument")));

        let invalid_inactive_match = ConfigProgram::seal(vec![
            Event::SectionStart {
                name: "filesmatch".into(),
                args: vec!["(?=unsupported-lookahead)".into()],
                loc: SourceLoc {
                    file: "inactive.conf".into(),
                    line: 7,
                },
                active: false,
                transparent: false,
            },
            Event::SectionEnd {
                loc: SourceLoc {
                    file: "inactive.conf".into(),
                    line: 8,
                },
            },
        ])
        .unwrap_err();
        assert!(invalid_inactive_match.contains("FilesMatch regex"));

        let invalid_condition = load_text(
            "<If \"%{NOSUCHVAR} == 'x'\">\nRequire all granted\n</If>\n",
            false,
        )
        .unwrap_err();
        assert!(
            invalid_condition
                .iter()
                .any(|error| error.msg.contains("bad <if> expression")),
            "{invalid_condition:?}"
        );

        for (name, args) in [
            ("protocols", vec!["h2c"]),
            ("expiresdefault", vec!["nonsense"]),
            ("setenvif", vec!["Remote_Addr", "(?=lookahead)", "X=1"]),
            ("listen", vec!["not-a-port"]),
            ("remoteiptrustedproxy", vec!["not-an-address"]),
            ("sslprotocol", vec!["TLSv9"]),
            ("sslverifyclient", vec!["sometimes"]),
            ("sslcarevocationcheck", vec!["sometimes"]),
            ("aliasmatch", vec!["(?=lookahead)", "/srv"]),
            ("proxypass", vec!["/", "gopher://backend"]),
            ("proxyset", vec!["unknown=value"]),
        ] {
            let result = ConfigProgram::seal(vec![Event::Directive {
                name: name.into(),
                args: args.into_iter().map(str::to_string).collect(),
                loc: SourceLoc {
                    file: "semantic.conf".into(),
                    line: 1,
                },
            }]);
            assert!(result.is_err(), "{name} reached the mutation walk unsealed");
        }

        let nested_program = |depth: usize| {
            let loc = SourceLoc {
                file: "nested.conf".into(),
                line: 1,
            };
            let mut events = Vec::new();
            for _ in 0..depth {
                events.push(Event::SectionStart {
                    name: "ifmodule".into(),
                    args: vec!["core_module".into()],
                    loc: loc.clone(),
                    active: true,
                    transparent: true,
                });
            }
            for _ in 0..depth {
                events.push(Event::SectionEnd { loc: loc.clone() });
            }
            events
        };
        assert!(ConfigProgram::seal(nested_program(MAX_CONFIG_SECTION_DEPTH)).is_ok());
        let error = ConfigProgram::seal(nested_program(MAX_CONFIG_SECTION_DEPTH + 1)).unwrap_err();
        assert!(error.contains("section nesting exceeds"), "{error}");
        assert!(vapache_verified::config_section_depth_admit(
            MAX_CONFIG_SECTION_DEPTH,
            MAX_CONFIG_SECTION_DEPTH,
        ));
        assert!(!vapache_verified::config_section_depth_admit(
            MAX_CONFIG_SECTION_DEPTH + 1,
            MAX_CONFIG_SECTION_DEPTH,
        ));
    }

    #[test]
    fn cache_enable_is_rejected_in_rule_producing_sections() {
        let errors = load_text(
            "CacheRoot /tmp/vapache-cache-prefilter\n\
             <Directory /tmp>\n\
             <If \"true\">\n\
             CacheEnable disk /nested\n\
             </If>\n\
             </Directory>\n",
            false,
        )
        .unwrap_err();
        assert!(errors.iter().any(|error| {
            error
                .msg
                .contains("only supported in server or virtual-host context")
        }));

        let cfg = load_text(
            "CacheRoot /tmp/vapache-cache-prefilter\nCacheEnable disk /cache\n",
            false,
        )
        .unwrap();
        assert_eq!(
            cfg.global.rewrite_policy.cache_enable,
            vec![("disk".into(), "/cache".into())]
        );
    }

    #[test]
    fn relative_pid_file_is_resolved_below_server_root() {
        let config = load_text("Listen 127.0.0.1:0\nPidFile run/vapached.pid\n", false).unwrap();
        assert_eq!(
            config.pid_file,
            std::env::temp_dir().join("run/vapached.pid")
        );

        let config = load_text(
            "Listen 127.0.0.1:0\nPidFile /var/run/apache2/apache2.pid\n",
            false,
        )
        .unwrap();
        assert_eq!(config.pid_file, Path::new("/run/apache2/apache2.pid"));
    }

    #[test]
    fn compatibility_capabilities_are_individual_global_and_default_off() {
        let defaults = load_text_default("Listen 127.0.0.1:0\n").unwrap();
        for capability in Capability::ALL {
            assert!(!defaults.capability_enabled(capability));
            let cfg = load_text_default(&format!(
                "VapacheCapability {} On\nListen 127.0.0.1:0\n",
                capability.name()
            ))
            .unwrap();
            assert!(cfg.capability_enabled(capability));
            assert_eq!(cfg.capabilities.enabled_names(), vec![capability.name()]);
        }

        let cases = [
            (
                "Trace",
                "Listen 127.0.0.1:0\nTraceEnable On\n",
            ),
            (
                "AccessFiles",
                "Listen 127.0.0.1:0\n<Directory /srv>\nAllowOverride All\n</Directory>\n",
            ),
            (
                "AutoIndex",
                "Listen 127.0.0.1:0\n<Directory /srv>\nOptions Indexes\n</Directory>\n",
            ),
            (
                "Cgi",
                "Listen 127.0.0.1:0\nScriptAlias /cgi/ /srv/cgi/\n",
            ),
            (
                "FastCgi",
                "Listen 127.0.0.1:0\nProxyPassMatch ^/(.*\\.php)$ unix:/run/php.sock|fcgi://localhost/srv/\n",
            ),
            (
                "LegacyAuthz",
                "Listen 127.0.0.1:0\n<Directory /srv>\nOrder deny,allow\nDeny from all\n</Directory>\n",
            ),
            (
                "RewriteProgram",
                "Listen 127.0.0.1:0\nRewriteMap helper prg:/bin/cat\n",
            ),
            (
                "ServerStatus",
                "Listen 127.0.0.1:0\n<Location /status>\nSetHandler server-status\n</Location>\n",
            ),
            (
                "Cgi",
                "Listen 127.0.0.1:0\nRewriteRule ^x$ - [H=cgi-script]\n",
            ),
            (
                "FastCgi",
                "Listen 127.0.0.1:0\nRewriteRule ^x$ - [H=proxy:fcgi://localhost]\n",
            ),
            (
                "ServerStatus",
                "Listen 127.0.0.1:0\nRewriteRule ^x$ - [H=server-status]\n",
            ),
        ];
        for (name, text) in cases {
            let errors = load_text_default(text).unwrap_err();
            assert!(
                errors
                    .iter()
                    .any(|error| error.msg.contains(&format!("VapacheCapability {name} On"))),
                "missing {name} rejection: {errors:?}"
            );
            let prelude = if name == "FastCgi" {
                "VapacheCapability FastCgi On\nVapacheCapability UnstableFastCgiPaths On\n"
                    .to_string()
            } else {
                format!("VapacheCapability {name} On\n")
            };
            assert!(
                load_text_with_prelude(&prelude, text, false, false).is_ok(),
                "explicit {name} opt-in was rejected"
            );
        }

        // Declarations are process-global, order independent, and final: a
        // later Off cannot leave an earlier feature enabled by accident.
        assert!(load_text_default(
            "Listen 127.0.0.1:0\nTraceEnable On\nVapacheCapability Trace On\n"
        )
        .is_ok());
        assert!(load_text_default(
            "Listen 127.0.0.1:0\nVapacheCapability Trace On\nTraceEnable On\nVapacheCapability Trace Off\n"
        )
        .is_err());

        for text in [
            "Listen 127.0.0.1:0\nVapacheCapability Unknown On\n",
            "Listen 127.0.0.1:0\nVapacheCapability Trace Maybe\n",
            "Listen 127.0.0.1:0\n<Directory /srv>\nVapacheCapability Trace On\n</Directory>\n",
            "Listen 127.0.0.1:0\n<VirtualHost *:80>\nVapacheCapability Trace On\n</VirtualHost>\n",
            "Listen 127.0.0.1:0\n<If true>\nVapacheCapability Trace On\n</If>\n",
            "Listen 127.0.0.1:0\nTraceEnable Maybe\n",
            "Listen 127.0.0.1:0\nTraceEnable\n",
            "Listen 127.0.0.1:0\nTraceEnable On Off\n",
        ] {
            assert!(load_text_default(text).is_err(), "accepted: {text}");
        }
        assert!(load_text_default(
            "VapacheCapability Trace On\nListen 127.0.0.1:0\nTraceEnable Extended\n"
        )
        .is_ok());
    }

    #[test]
    fn capability_audit_reports_but_does_not_auto_enable_missing_gates() {
        let cfg = load_text_with_prelude(
            "",
            "Listen 127.0.0.1:0\nTraceEnable On\n<Directory /srv>\nOptions Indexes\n</Directory>\n",
            false,
            true,
        )
        .unwrap();
        assert!(!cfg.capability_enabled(Capability::Trace));
        assert!(!cfg.capability_enabled(Capability::AutoIndex));
        assert!(cfg.required_capabilities.contains(&Capability::Trace));
        assert!(cfg.required_capabilities.contains(&Capability::AutoIndex));
    }

    #[test]
    fn mutable_authentication_databases_require_the_global_capability() {
        let auth_file =
            std::env::temp_dir().join(format!("vapache-mutable-auth-{}", std::process::id()));
        std::fs::write(&auth_file, "alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n").unwrap();
        let body = format!(
            "Listen 127.0.0.1:0\n<Directory /srv>\nAuthType Basic\nAuthUserFile {}\nRequire valid-user\n</Directory>\n",
            auth_file.display()
        );
        let service_uid = std::fs::metadata(&auth_file).unwrap().uid();
        let strict = load_text_default(&body).unwrap();
        assert!(strict.validate_auth_files(service_uid).is_err());
        let mutable = load_text_with_prelude(
            "VapacheCapability MutableAuthFiles On\n",
            &body,
            false,
            false,
        )
        .unwrap();
        assert!(mutable.validate_auth_files(service_uid).is_ok());

        std::fs::write(&auth_file, b"alice:\xff\n").unwrap();
        assert!(mutable.validate_auth_files(service_uid).is_err());
        let _ = std::fs::remove_file(auth_file);
    }

    #[test]
    fn fastcgi_requires_stable_paths_or_an_explicit_unsafe_capability() {
        let route =
            "Listen 127.0.0.1:0\nProxyPassMatch ^/(.*\\.php)$ unix:/run/php.sock|fcgi://localhost/srv/\n";
        let errors = load_text_with_prelude("VapacheCapability FastCgi On\n", route, false, false)
            .unwrap_err();
        assert!(errors.iter().any(|error| error
            .msg
            .contains("VapacheCapability UnstableFastCgiPaths On")));

        assert!(load_text_with_prelude(
            "VapacheCapability FastCgi On\nVapacheCapability UnstableFastCgiPaths On\n",
            route,
            false,
            false,
        )
        .is_ok());
        assert!(load_text_with_prelude(
            "VapacheCapability FastCgi On\nVapacheFastCGIStablePath On unix:/run/php.sock 33 0 0\n",
            route,
            false,
            false,
        )
        .is_ok());

        let audited = load_text_with_prelude("", route, false, true).unwrap();
        assert!(!audited.capability_enabled(Capability::FastCgi));
        assert!(!audited.capability_enabled(Capability::UnstableFastCgiPaths));
        assert!(audited.required_capabilities.contains(&Capability::FastCgi));
        assert!(audited
            .required_capabilities
            .contains(&Capability::UnstableFastCgiPaths));
    }

    #[test]
    fn configuration_and_types_files_reject_invalid_utf8() {
        let dir = std::env::temp_dir().join(format!(
            "vapache-invalid-config-utf8-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("httpd.conf");
        std::fs::write(&config, b"Listen 127.0.0.1:0\nServerName bad\xffname\n").unwrap();
        let errors =
            Config::load(&config, &dir, &HashMap::new(), &HashMap::new(), false).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.msg.contains("not valid UTF-8")));

        let types = dir.join("mime.types");
        std::fs::write(&types, b"text/plain txt\xff\n").unwrap();
        assert!(MimeMap::new()
            .load_types_file(&types)
            .unwrap_err()
            .contains("not valid UTF-8"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn implicit_document_root_is_bound_into_the_global_scope() {
        let cfg = load_text("Listen 127.0.0.1:0\n", true).unwrap();
        assert_eq!(
            cfg.global.content_policy.document_root.as_deref(),
            Some(cfg.document_root.as_path())
        );
        assert_ne!(cfg.document_root, Path::new("/"));
    }

    #[test]
    fn malformed_directives_fail_in_every_mode() {
        let promoted = [
            "RewriteOptions bogus",
            "Options +NoSuchOption",
            "AddType text/plain",
            "AddHandler handler",
            "Header set",
            "Header always",
            "ExpiresByType image/png",
            "ProxyPass /p",
        ];
        for text in &promoted {
            assert!(
                load_text(&format!("Listen 127.0.0.1:0\n{text}\n"), false).is_err(),
                "{text} must be refused in normal mode"
            );
            assert!(
                load_text(&format!("Listen 127.0.0.1:0\n{text}\n"), true).is_err(),
                "{text} must be refused in strict mode"
            );
        }
        // A partially valid list must not be shortened into a different
        // retry policy.
        let config = |entries: &str| {
            format!("Listen 127.0.0.1:0\nProxyPass /p http://127.0.0.1:9000 {entries}\n")
        };
        assert!(load_text(&config("failonstatus=500,lop"), false).is_err());
        assert!(load_text(&config("failonstatus=500,502"), true).is_ok());
        assert!(load_text(&config("failonstatus=500,lop"), true).is_err());
        assert!(load_text(&config("failonstatus=200,no"), false).is_err());
        let balancer = |entries: &str| {
            format!("Listen 127.0.0.1:0\n<Proxy balancer://pool>\nProxySet {entries}\n</Proxy>\n")
        };
        assert!(load_text(&balancer("failonstatus=500,lop"), false).is_err());
        assert!(load_text(&balancer("failonstatus=500,lop"), true).is_err());
    }

    #[test]
    fn coverable_parser_rejection_edges_are_explicit() {
        let strings = |values: &[&str]| {
            values
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>()
        };

        assert!(parse_http_protocols(&[]).is_err());
        assert!(parse_http_protocols(&strings(&["h2c"])).is_err());
        assert!(parse_http_protocols(&strings(&["spdy/3"])).is_err());

        assert!(ifversion_matches(&strings(&[])).is_err());
        assert!(ifversion_matches(&strings(&["2..4"])).is_err());
        assert!(ifversion_matches(&strings(&["~", "2.4"])).is_err());
        assert!(ifversion_matches(&strings(&["=", "/2\\.4/"])).is_err());
        assert!(!ifversion_matches(&strings(&["!<", "2.5"])).unwrap());
        assert!(ifversion_matches(&strings(&["<", "3"])).unwrap());
        assert!(ifversion_matches(&strings(&["<>", "2.4"])).is_err());

        for invalid in [
            "unix:relative.sock",
            "unix:/run/../tmp/fcgi.sock",
            "http://host:9000",
            "fcgi://",
            "fcgi://host/path",
            "fcgi://[::1",
            "fcgi://[::1]suffix",
            "fcgi://[::1]:nope",
            "fcgi://::1",
            "fcgi://host:nope",
            "fcgi://:9000",
            "fcgi://host:0",
        ] {
            assert!(
                parse_fastcgi_policy_endpoint(invalid).is_err(),
                "{invalid} must fail"
            );
        }
        assert!(matches!(
            parse_fastcgi_policy_endpoint("fcgi://EXAMPLE.test").unwrap(),
            FastCgiEndpoint::Tcp { ref host, port } if host == "example.test" && port == 9000
        ));
        assert!(matches!(
            parse_fastcgi_policy_endpoint("fcgi://[::1]:9001").unwrap(),
            FastCgiEndpoint::Tcp { ref host, port } if host == "::1" && port == 9001
        ));

        assert!(parse_redirect_arguments(&strings(&["/from"]), Some(301)).is_err());
        assert!(parse_redirect_arguments(&[], None).is_err());
        assert!(parse_redirect_arguments(&strings(&["299", "/from", "/to"]), None).is_err());
        assert!(parse_redirect_arguments(&strings(&["301", "/from"]), None).is_err());
        assert!(parse_redirect_arguments(&strings(&["410", "/from", "/to"]), None).is_err());
        assert!(parse_redirect_arguments(&strings(&["mystery"]), None).is_err());

        assert!(validate_glob_pattern(&"x".repeat(crate::glob::MAX_PATTERN_BYTES + 1)).is_err());
        for (provider, operand) in [
            ("host", "%{UNKNOWN}"),
            ("host", "%{HTTP_HOST"),
            ("user", "%{UNKNOWN}"),
            ("group", "%{UNKNOWN}"),
        ] {
            assert!(matches!(
                parse_require(&strings(&[provider, operand])),
                Require::Unsupported(_)
            ));
        }
        assert!(matches!(
            parse_require(&strings(&["host", "%{HTTP:X-Test}", "%{ENV:ZONE}"])),
            Require::Host { .. }
        ));

        assert!(parse_env_rule("setenvif", &strings(&["remote_host", "x", "MATCH"])).is_err());
        assert!(parse_env_rule("setenvif", &strings(&["X-(.*)", "x", "MATCH"])).is_err());
    }

    #[test]
    fn coverable_environment_protocol_and_fastcgi_origin_edges_are_explicit() {
        let mut scope = Scope::default();
        for (attribute, pattern, action) in [
            ("Request_Protocol", "^HTTP/1\\.0$", "HTTP10=1"),
            ("Request_Protocol", "^HTTP/2\\.0$", "HTTP2=1"),
            ("Host", "^$", "NO_HOST=1"),
            ("Referer", "^$", "NO_REFERER=1"),
        ] {
            scope.environment_policy.set_env_if.push(Originated::main(
                parse_env_rule(
                    "setenvif",
                    &[attribute.into(), pattern.into(), action.into()],
                )
                .unwrap(),
            ));
        }
        let peer = "127.0.0.1".parse().unwrap();
        let mut http10 = test_request("GET");
        http10.version = crate::http::Version::Http10;
        let env10 = scope.authorization_env(&http10, "/", peer);
        assert!(env10.contains(&("HTTP10".into(), b"1".to_vec())));
        assert!(env10.contains(&("NO_HOST".into(), b"1".to_vec())));
        assert!(env10.contains(&("NO_REFERER".into(), b"1".to_vec())));

        let mut http2 = test_request("GET");
        http2.version = crate::http::Version::Http2;
        assert!(scope
            .authorization_env(&http2, "/", peer)
            .contains(&("HTTP2".into(), b"1".to_vec())));

        scope
            .environment_policy
            .rewrite_env
            .push(Originated::access(("ACCESS_EARLY".into(), b"1".to_vec())));
        scope
            .environment_policy
            .rewrite_unset_env
            .push(Originated::access("ACCESS_EARLY".into()));
        scope
            .environment_policy
            .rewrite_late_unset_env
            .push(Originated::access("ACCESS_LATE".into()));
        scope
            .environment_policy
            .pass_env
            .push(Originated::access("PATH".into()));
        scope
            .environment_policy
            .pass_env
            .push(Originated::main("VAPACHE_TEST_MISSING_ENV".into()));
        scope
            .environment_policy
            .unset_env
            .push(Originated::access("ACCESS_UNSET".into()));
        let fastcgi = scope.fastcgi_env(&http2, "/", peer);
        for forbidden in ["ACCESS_EARLY", "ACCESS_LATE", "ACCESS_UNSET"] {
            assert!(!fastcgi.iter().any(|(name, _)| name == forbidden));
        }
    }

    #[test]
    fn coverable_directive_rejection_matrix_is_executed() {
        let oversized_glob = "x".repeat(crate::glob::MAX_PATTERN_BYTES + 1);
        let cases = [
            ("VapacheCapability Cgi\n".to_string(), "capability arity"),
            (
                "VapacheMaxSpoolBytes 1 2\n".to_string(),
                "resource-limit arity",
            ),
            (
                "VapacheFastCGIStablePath On unix:/run/php/test.sock 33 0 nope\n".to_string(),
                "trusted FastCGI owner uid",
            ),
            (
                "<VirtualHost *:80>\nServerAlias foo*bar.example\n</VirtualHost>\n".to_string(),
                "server-alias wildcard",
            ),
            (format!("IndexIgnore {oversized_glob}\n"), "oversized IndexIgnore"),
            (
                "<Directory /tmp>\nAllowOverride\n</Directory>\n".to_string(),
                "empty AllowOverride",
            ),
            (
                "<Directory /tmp>\nAllowOverrideList\n</Directory>\n".to_string(),
                "empty AllowOverrideList",
            ),
            (
                "<Directory /tmp>\nAllow 127.0.0.1\n</Directory>\n".to_string(),
                "Allow without from",
            ),
            (
                "RedirectMatch 302 [ /target\n".to_string(),
                "invalid RedirectMatch regex",
            ),
            (
                "RedirectMatch 302 ^/from$\n".to_string(),
                "RedirectMatch missing target",
            ),
            ("RewriteMap\n".to_string(), "RewriteMap arity"),
            (
                "RewriteMap map dbm:/tmp/map\n".to_string(),
                "unsupported RewriteMap type",
            ),
            ("Header\n".to_string(), "Header arity"),
            (
                "ExpiresByType text/plain nonsense\n".to_string(),
                "invalid expiry syntax",
            ),
            (
                "CacheLastModifiedFactor NaN\n".to_string(),
                "invalid cache factor",
            ),
            (
                "ProxyPass /app http://127.0.0.1:9000/ broken\n".to_string(),
                "ProxyPass parameter shape",
            ),
            (
                "AddOutputFilterByType DEFLATE\n".to_string(),
                "output-filter arity",
            ),
            (
                "BrotliAlterETag Invalid\n".to_string(),
                "Brotli ETag mode",
            ),
            (
                "Listen 127.0.0.1:0 spdy\n".to_string(),
                "Listen protocol hint",
            ),
            ("LogLevel impossible\n".to_string(), "invalid LogLevel"),
            ("TraceEnable impossible\n".to_string(), "invalid TraceEnable"),
            (
                "MaxRequestWorkers 0\n".to_string(),
                "zero MaxRequestWorkers",
            ),
            (
                "ServerLimit 1\nMaxRequestWorkers 2\n".to_string(),
                "workers above prior limit",
            ),
            (
                "MaxRequestWorkers 2\nServerLimit 1\n".to_string(),
                "workers above later limit",
            ),
            ("ListenBacklog 0\n".to_string(), "invalid listen backlog"),
            (
                "SSLCertificateFile\n".to_string(),
                "certificate path arity",
            ),
            (
                "SSLStaplingStandardCacheTimeout nope\n".to_string(),
                "stapling cache timeout",
            ),
            (
                "<Proxy balancer://pool>\nBalancerMember http://127.0.0.1:9000 broken hcinterval=nope hcpasses=nope hcfails=nope unknown=x\nProxySet broken hcinterval=nope hcpasses=nope hcfails=nope unknown=x\n</Proxy>\n".to_string(),
                "balancer parameter matrix",
            ),
            (
                "ProxyHCTemplate t broken hcinterval=nope hcpasses=nope hcfails=nope unknown=x\n"
                    .to_string(),
                "health-template parameter matrix",
            ),
            ("SSLVerifyClient\n".to_string(), "client verify arity"),
            (
                "SSLCACertificateFile one two\n".to_string(),
                "client CA path arity",
            ),
            (
                "SSLCARevocationFile one two\n".to_string(),
                "client CRL path arity",
            ),
            (
                "SSLCARevocationCheck sometimes\n".to_string(),
                "client revocation mode",
            ),
            ("SSLProtocol\n".to_string(), "empty TLS protocol policy"),
            (
                "<Directory /tmp>\nAuthType Digest\n</Directory>\n".to_string(),
                "unsupported authentication type",
            ),
        ];
        for (snippet, label) in cases {
            assert!(
                load_text(&format!("Listen 127.0.0.1:0\n{snippet}"), false).is_err(),
                "{label} was unexpectedly accepted: {snippet}"
            );
        }
    }

    #[test]
    fn rewritemap_loading_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vapache-rewritemap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(dir.join("good.txt"), "alpha one\n# comment\n\nbeta two\n").unwrap();
        std::fs::write(
            dir.join("big.txt"),
            vec![b'#'; (MAX_REWRITEMAP + 1) as usize],
        )
        .unwrap();
        std::fs::write(dir.join("bin/worker"), "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(
            dir.join("bin/worker"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let oversized_program = dir.join("bin/oversized-worker");
        let oversized = std::fs::File::create(&oversized_program).unwrap();
        oversized.set_len(MAX_REWRITEMAP_PROGRAM + 1).unwrap();
        std::fs::set_permissions(&oversized_program, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        std::fs::write(dir.join("plain.txt"), "x y\n").unwrap();
        std::fs::write(dir.join("invalid-utf8.map"), [0xff, 0xfe]).unwrap();
        std::fs::set_permissions(
            dir.join("plain.txt"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let load_with_root = |config: &str| {
            let path = dir.join("rmap-test.conf");
            std::fs::write(&path, format!("{}{config}", TEST_CAPABILITIES)).unwrap();
            let r = Config::load(
                &path,
                dir.as_path(),
                &HashMap::new(),
                &HashMap::new(),
                false,
            );
            let _ = std::fs::remove_file(&path);
            r
        };
        let maps = |config: &str| {
            let c = load_with_root(config).unwrap();
            c.global.rewrite_policy.rewrite_maps
        };

        // Malformed directive: error in every mode, never a silent skip.
        for strict in [false, true] {
            assert!(
                load_text("Listen 127.0.0.1:0\nRewriteMap onlyone\n", strict).is_err(),
                "short RewriteMap must be an error (strict={strict})"
            );
        }
        // txt: missing file, unreadable file and oversized file all error.
        assert!(load_with_root("Listen 127.0.0.1:0\nRewriteMap m txt:missing.txt\n").is_err());
        assert!(load_with_root(&format!(
            "Listen 127.0.0.1:0\nRewriteMap big txt:{}\n",
            dir.join("big.txt").display()
        ))
        .is_err());
        assert!(
            load_with_root("Listen 127.0.0.1:0\nRewriteMap bad txt:invalid-utf8.map\n").is_err()
        );
        assert!(
            load_with_root("Listen 127.0.0.1:0\nRewriteMap bad rnd:invalid-utf8.map\n").is_err()
        );
        let good = maps("Listen 127.0.0.1:0\nRewriteMap t txt:good.txt\n");
        assert!(matches!(
            good.as_slice(),
            [(_, RewriteMap::Txt(m))] if m.get("alpha").map(String::as_str) == Some("one")
        ));
        // int: unknown functions are rejected at load; known ones register.
        assert!(load_with_root("Listen 127.0.0.1:0\nRewriteMap ix int:nosuch\n").is_err());
        let int_map = maps("Listen 127.0.0.1:0\nRewriteMap up int:toupper\n");
        assert!(matches!(
            int_map.as_slice(),
            [(_, RewriteMap::Int(f))] if f == "toupper"
        ));
        // prg: a relative program is resolved against ServerRoot and must be
        // an existing executable regular file.
        let prg = maps("Listen 127.0.0.1:0\nRewriteMap w prg:bin/worker\n");
        assert!(
            matches!(
                prg.as_slice(),
                [(_, RewriteMap::Prg(p))] if p.path.ends_with("bin/worker") && p.args.is_empty()
            ),
            "{prg:?}"
        );
        let prg_args = maps("Listen 127.0.0.1:0\nRewriteMap w \"prg:bin/worker --mode test\"\n");
        assert!(matches!(
            prg_args.as_slice(),
            [(_, RewriteMap::Prg(p))]
                if p.path.ends_with("bin/worker") && p.args == ["--mode", "test"]
        ));
        let unsafe_prefix = load_with_root(
            "Listen 127.0.0.1:0\nRewriteEngine On\nRewriteRule ^/x$ /y [UnsafePrefixStat]\n",
        )
        .unwrap();
        assert!(unsafe_prefix
            .warnings
            .iter()
            .any(|warning| warning.contains("UnsafePrefixStat")));
        assert!(load_with_root("Listen 127.0.0.1:0\nRewriteMap n prg:plain.txt\n").is_err());
        assert!(load_with_root("Listen 127.0.0.1:0\nRewriteMap n prg:bin\n").is_err());
        assert!(
            load_with_root("Listen 127.0.0.1:0\nRewriteMap n prg:bin/oversized-worker\n").is_err()
        );
        assert!(load_with_root("Listen 127.0.0.1:0\nRewriteMap n prg:no-such-worker\n").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ssl_directives_and_listen_protocol() {
        let cfg = "Listen 127.0.0.1:443 https\n\
<VirtualHost *:443>\n\
SSLEngine on\n\
SSLCertificateFile /etc/ssl/cert.pem\n\
SSLCertificateKeyFile /etc/ssl/key.pem\n\
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n\
</VirtualHost>\n";
        let c = load_text(cfg, false).unwrap();
        assert_eq!(c.listeners.len(), 1);
        assert_eq!(c.listeners[0].port, 443);
        let v = &c.vhosts[0];
        assert!(v.ssl.engine);
        assert_eq!(
            v.ssl.cert_file.as_deref(),
            Some(std::path::Path::new("/etc/ssl/cert.pem"))
        );
        assert_eq!(
            v.ssl.key_file.as_deref(),
            Some(std::path::Path::new("/etc/ssl/key.pem"))
        );
        assert!(v.ssl.protocols.as_deref().unwrap().contains("TLSv1.1"));
    }

    #[test]
    fn stock_debian_ssl_module_configuration_is_supported() {
        let cfg = "Listen 127.0.0.1:443 https\n\
SSLRandomSeed startup builtin\n\
SSLRandomSeed startup file:/dev/urandom 512\n\
SSLRandomSeed connect builtin\n\
SSLRandomSeed connect file:/dev/urandom 512\n\
SSLPassPhraseDialog exec:/usr/share/apache2/ask-for-passphrase\n\
SSLSessionCache shmcb:/run/apache2/ssl_scache(512000)\n\
SSLStaplingCache shmcb:/run/apache2/ssl_stapling(32768)\n\
SSLSessionCacheTimeout 300\n\
SSLSessionTickets Off\n\
SSLHonorCipherOrder Off\n\
SSLOptions +StrictRequire\n";

        for strict in [false, true] {
            let parsed = load_text(cfg, strict).unwrap();
            assert_eq!(parsed.ssl.session_cache, Some(true));
            assert_eq!(
                parsed.ssl.session_cache_timeout,
                Some(Duration::from_secs(300))
            );
            assert_eq!(parsed.ssl.session_tickets, Some(false));
            assert_eq!(parsed.ssl.honor_cipher_order, Some(false));
            assert!(parsed
                .warnings
                .iter()
                .any(|warning| warning.contains("SSLPassPhraseDialog")));
            assert!(parsed
                .warnings
                .iter()
                .any(|warning| warning.contains("bounded in-process cache")));
            assert!(parsed
                .warnings
                .iter()
                .any(|warning| warning.contains("bounded in-process OCSP cache")));
        }
    }

    #[test]
    fn malformed_ssl_session_and_seed_directives_fail_closed() {
        let invalid = [
            "SSLRandomSeed later builtin",
            "SSLRandomSeed startup relative-file",
            "SSLRandomSeed startup file:",
            "SSLRandomSeed startup file:/dev/urandom many",
            "SSLPassPhraseDialog builtin extra",
            "SSLPassPhraseDialog nonsense",
            "SSLSessionCache shmcb:",
            "SSLStaplingCache nonsense",
            "SSLSessionCacheTimeout forever",
            "SSLSessionTickets Maybe",
            "SSLHonorCipherOrder Prefer",
            "SSLOptions -StrictRequire",
            "SSLOptions +StrictRequire +StdEnvVars",
            "SSLProtocol nonsense",
            "SSLProtocol TLSv1",
        ];
        for directive in invalid {
            for strict in [false, true] {
                assert!(
                    load_text(&format!("Listen 127.0.0.1:443\n{directive}\n"), strict).is_err(),
                    "{directive} must fail (strict={strict})"
                );
            }
        }
    }

    #[test]
    fn ssl_engine_off_is_not_overridden_by_global_on() {
        let cfg = "SSLEngine on\nListen 127.0.0.1:443\n\
<VirtualHost *:443>\nSSLEngine off\n</VirtualHost>\n";
        let c = load_text(cfg, false).unwrap();
        assert!(!c.vhosts[0].ssl.engine);
    }

    #[test]
    fn protocols_is_effectful_ordered_and_fail_closed() {
        let c = load_text("Listen 127.0.0.1:443\nProtocols http/1.1\n", true).unwrap();
        assert_eq!(c.protocols, vec![HttpProtocol::Http11]);
        assert!(c
            .warnings
            .iter()
            .all(|warning| !warning.contains("Protocols")));

        let c = load_text(
            "Listen 127.0.0.1:443\nProtocols http/1.1 h2 http/1.1\n\
             <VirtualHost *:443>\nProtocols h2 http/1.1\n</VirtualHost>\n",
            true,
        )
        .unwrap();
        assert_eq!(c.protocols, vec![HttpProtocol::Http11, HttpProtocol::Http2]);
        assert_eq!(
            c.vhosts[0].protocols,
            vec![HttpProtocol::Http2, HttpProtocol::Http11]
        );

        assert!(load_text("Listen 127.0.0.1:443\nProtocols\n", false).is_err());
        assert!(load_text("Listen 127.0.0.1:443\nProtocols h2c\n", false).is_err());
        assert!(load_text("Listen 127.0.0.1:443\nProtocols quic\n", false).is_err());
        assert!(load_text(
            "Listen 127.0.0.1:443\n<Directory /srv>\nProtocols http/1.1\n</Directory>\n",
            false,
        )
        .is_err());
    }

    #[test]
    fn allow_override_all_is_supported() {
        let cfg = "Listen 127.0.0.1:0\n<Directory /srv>\nAllowOverride All\n</Directory>\n";
        let c = load_text(cfg, false).unwrap();
        assert!(!c.warnings.iter().any(|w| w.contains("AllowOverride")));
        assert!(load_text(cfg, true).is_ok());

        let cfg = "Listen 127.0.0.1:0\n<Directory /srv>\nAllowOverride None\n</Directory>\n";
        let c = load_text(cfg, false).unwrap();
        assert!(!c.warnings.iter().any(|w| w.contains("AllowOverride")));
        assert!(load_text(cfg, true).is_ok());

        let cfg = "Listen 127.0.0.1:0\n<Directory /srv>\nAllowOverride AuthConfig FileInfo Options\n</Directory>\n";
        let c = load_text(cfg, false).unwrap();
        assert!(!c.warnings.iter().any(|w| w.contains("AllowOverride")));
        let s = c.effective_scope(None, Path::new("/srv/file"), "/file");
        assert_eq!(
            s.override_policy.raw_mode(),
            Some(OverrideMode::Categories(OverrideCategories(
                OverrideCategories::AUTH_CONFIG
                    | OverrideCategories::FILE_INFO
                    | OverrideCategories::OPTIONS
            )))
        );
        assert!(load_text(cfg, true).is_ok());

        let cfg =
            "Listen 127.0.0.1:0\n<Directory /srv>\nAllowOverride NotACategory\n</Directory>\n";
        assert!(load_text(cfg, false).is_err());
        assert!(load_text(cfg, true).is_err());

        let cfg = "Listen 127.0.0.1:0\n<Directory /srv>\nAllowOverride AuthConfig NotACategory\n</Directory>\n";
        assert!(load_text(cfg, false).is_err());
        assert!(load_text(cfg, true).is_err());
    }

    #[test]
    fn per_location_client_authentication_is_rejected() {
        let cfg = concat!(
            "Listen 127.0.0.1:443 https\n",
            "<VirtualHost *:443>\n",
            "SSLEngine on\n",
            "SSLCertificateFile /etc/ssl/cert.pem\n",
            "SSLCertificateKeyFile /etc/ssl/key.pem\n",
            "<Location />\n",
            "SSLVerifyClient require\n",
            "</Location>\n",
            "</VirtualHost>\n",
        );
        assert!(load_text(cfg, false).is_err());
    }

    #[test]
    fn rewrite_directives_compile_and_validate() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "RewriteEngine On\n",
            "RewriteCond %{QUERY_STRING} ^x=1$ [NC]\n",
            "RewriteRule ^/old$ /new [L,QSA]\n",
        );
        let c = load_text(cfg, false).unwrap();
        let s = c.effective_scope(None, Path::new("/srv/file"), "/old");
        assert_eq!(s.rewrite_policy.rewrite_engine, Some(true));
        assert_eq!(s.rewrite_policy.rewrite_rules.len(), 1);
        assert_eq!(s.rewrite_policy.rewrite_rules[0].match_base, "/");
        assert!(!s.rewrite_policy.rewrite_rules[0].per_dir);
        assert_eq!(s.rewrite_policy.rewrite_rules[0].conditions.len(), 1);
        assert!(s.rewrite_policy.rewrite_rules[0].conditions[0].flags.nocase);

        for bad in [
            "Listen 127.0.0.1:0\nRewriteEngine Maybe\n",
            "Listen 127.0.0.1:0\nRewriteRule ^x y [UNKNOWN]\n",
            "Listen 127.0.0.1:0\nRewriteCond %{REQUEST_URI} [\nRewriteRule ^x y\n",
        ] {
            assert!(load_text(bad, false).is_err(), "{bad}");
        }
    }

    #[test]
    fn allow_override_option_sets_compile() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<Directory /srv>\n",
            "AllowOverride Options=ExecCGI,Includes Options=Indexes\n",
            "</Directory>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let mode = c
            .effective_scope(None, Path::new("/srv/file"), "/file")
            .override_policy
            .raw_mode()
            .expect("override mode");
        assert!(mode.allows_flag(OverrideCategories::EXEC_CGI));
        assert!(mode.allows_flag(OverrideCategories::INCLUDES));
        assert!(mode.allows_flag(OverrideCategories::OPT_INDEXES));
        assert!(!mode.allows_flag(OverrideCategories::OPT_FOLLOW_SYMLINKS));

        let bad = concat!(
            "Listen 127.0.0.1:0\n",
            "<Directory /srv>\nAllowOverride Options=NotAnOption\n</Directory>\n",
        );
        assert!(load_text(bad, false).is_err());
    }

    #[test]
    fn override_prefilter_covers_every_enabled_directory() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<Directory /srv>\n",
            "AllowOverride All\n",
            "</Directory>\n",
            "<Directory /srv/sub>\n",
            "AllowOverride AuthConfig\n",
            "</Directory>\n",
            "<Directory /opt/*/public>\n",
            "AllowOverride All\n",
            "</Directory>\n",
            "<VirtualHost *:80>\n",
            "ServerName vhost.test\n",
            "DocumentRoot /srv/vhost\n",
            "<Directory /srv/vhost/private>\n",
            "AllowOverride Options\n",
            "</Directory>\n",
            "</VirtualHost>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let vhost = c
            .vhosts
            .iter()
            .find(|v| v.server_name.as_deref() == Some("vhost.test"));
        for (vhost, path, url) in [
            (None, "/srv/file", "/file"),
            (None, "/srv/sub/file", "/sub/file"),
            (None, "/opt/a/public/file", "/file"),
            (None, "/opt/a/private/file", "/file"),
            (vhost, "/srv/vhost/private/file", "/private/file"),
            (vhost, "/srv/vhost/elsewhere/file", "/elsewhere/file"),
        ] {
            let scope = c.effective_scope(vhost, Path::new(path), url);
            if scope
                .override_policy
                .raw_mode()
                .map(OverrideMode::is_enabled)
                .unwrap_or(false)
            {
                let covered = c.override_applicable(Path::new(path));
                assert!(
                    covered,
                    "override prefilter would skip {path} despite enabled AllowOverride"
                );
            }
        }
    }

    #[test]
    fn directory_wildcards_match_whole_components() {
        assert!(directory_wildcard_matches(
            Path::new("/srv/*/public"),
            Path::new("/srv/alice/public/file")
        ));
        assert!(!directory_wildcard_matches(
            Path::new("/srv/*/public"),
            Path::new("/srv/alice/private/file")
        ));
        assert!(directory_wildcard_matches(
            Path::new("/srv/wild?/public"),
            Path::new("/srv/wild1/public/file")
        ));
        assert!(!directory_wildcard_matches(
            Path::new("/srv/wild?/public"),
            Path::new("/srv/wild12/public/file")
        ));
    }

    #[test]
    fn files_patterns_support_apache_globs_and_regex() {
        let kind = compile_files_pattern(&["secret*".into()]).unwrap();
        assert!(rule_kind_matches(
            &kind,
            Path::new("/srv/secret.txt"),
            "/secret.txt",
            "secret.txt"
        ));
        assert!(!rule_kind_matches(
            &kind,
            Path::new("/srv/public.txt"),
            "/public.txt",
            "public.txt"
        ));
        let kind = compile_files_pattern(&["secret?.txt".into()]).unwrap();
        assert!(rule_kind_matches(
            &kind,
            Path::new("/srv/secret1.txt"),
            "/secret1.txt",
            "secret1.txt"
        ));
        let kind = compile_files_pattern(&["~".into(), "^secret\\..*$".into()]).unwrap();
        assert!(rule_kind_matches(
            &kind,
            Path::new("/srv/secret.txt"),
            "/secret.txt",
            "secret.txt"
        ));
    }

    #[test]
    fn location_trailing_slash_is_a_distinct_prefix() {
        let slash = MatchKind::Location("/admin/".into());
        assert!(rule_kind_matches(
            &slash,
            Path::new("/srv/admin/file"),
            "/admin/file",
            "file"
        ));
        assert!(!rule_kind_matches(
            &slash,
            Path::new("/srv/admin"),
            "/admin",
            "admin"
        ));
        let no_slash = MatchKind::Location("/admin".into());
        assert!(rule_kind_matches(
            &no_slash,
            Path::new("/srv/admin"),
            "/admin",
            "admin"
        ));
        assert!(!rule_kind_matches(
            &no_slash,
            Path::new("/srv/administrator"),
            "/administrator",
            "administrator"
        ));
    }

    #[test]
    fn method_set_intersection_is_exact() {
        let sets = [
            MethodSet::all(),
            MethodSet::Only(vec![]),
            MethodSet::Only(vec!["GET".into()]),
            MethodSet::Only(vec!["GET".into(), "POST".into()]),
            MethodSet::Except(vec!["GET".into()]),
            MethodSet::Except(vec!["POST".into(), "PUT".into()]),
        ];
        for a in &sets {
            for b in &sets {
                let i = a.intersect(b);
                for m in ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"] {
                    assert_eq!(
                        i.matches(m),
                        a.matches(m) && b.matches(m),
                        "intersection mismatch for {m}: {a:?} ∩ {b:?} = {i:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn rule_phases_match_documented_merge_order() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<Directory /srv>\n",
            "Require all granted\n",
            "</Directory>\n",
            "<Files \"secret.txt\">\n",
            "Require all denied\n",
            "</Files>\n",
            "<Location \"/x\">\n",
            "Require local\n",
            "</Location>\n",
            "<If \"true\">\n",
            "Require all denied\n",
            "</If>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let mut phases: Vec<RulePhase> = c.global_rules.iter().map(|r| r.phase()).collect();
        assert_eq!(
            phases,
            vec![
                RulePhase::Directory,
                RulePhase::Files,
                RulePhase::Location,
                RulePhase::Condition
            ]
        );
        phases.sort();
        assert_eq!(
            phases,
            vec![
                RulePhase::Directory,
                RulePhase::Files,
                RulePhase::Location,
                RulePhase::Condition
            ]
        );
    }

    #[test]
    fn conditionals_are_applied_after_directory_grants() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<If \"%{REQUEST_METHOD} == 'GET'\">\n",
            "Require all denied\n",
            "</If>\n",
            "<Directory /srv>\n",
            "Require all granted\n",
            "</Directory>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let req = test_request("GET");
        let s = c.effective_scope_req(
            None,
            Path::new("/srv/file"),
            "/file",
            &req,
            "127.0.0.1".parse().unwrap(),
        );
        assert!(matches!(
            s.authorization.requires,
            Some(AuthPolicy::List(ref entries))
                if entries.iter().any(|e| matches!(e.node, RequireNode::Provider(Require::AllDenied)))
        ));

        let failed = load_text(
            "DocumentRoot /srv\n<If \"file('../escape') == 'x'\">\nRequire all granted\n</If>\n",
            false,
        )
        .unwrap();
        let failed_scope = failed.effective_scope_req(
            None,
            Path::new("/srv/file"),
            "/file",
            &req,
            "127.0.0.1".parse().unwrap(),
        );
        assert!(failed_scope.conditional_error);
    }

    #[test]
    fn global_rewrite_rules_do_not_leak_into_vhosts() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "RewriteEngine On\n",
            "RewriteRule ^/global$ /hello.txt [L]\n",
            "<VirtualHost *:80>\n",
            "ServerName vhost.test\n",
            "DocumentRoot /srv/vhost\n",
            "RewriteEngine On\n",
            "RewriteRule ^/vhost$ /vhost.txt [L]\n",
            "</VirtualHost>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let v = c
            .vhosts
            .iter()
            .find(|v| v.server_name.as_deref() == Some("vhost.test"))
            .unwrap();
        let s = c.effective_scope(Some(v), Path::new("/srv/vhost/file"), "/vhost");
        assert_eq!(s.rewrite_policy.rewrite_rules.len(), 1);
        assert_eq!(s.rewrite_policy.rewrite_rules[0].substitution, "/vhost.txt");
        let s = c.effective_scope(Some(v), Path::new("/srv/vhost/file"), "/global");
        assert_eq!(s.rewrite_policy.rewrite_rules.len(), 1);
        assert_eq!(s.rewrite_policy.rewrite_rules[0].substitution, "/vhost.txt");
    }

    #[test]
    fn certbot_http01_rewrite_gets_a_confined_regex_mapping_root() {
        let c = load_text(
            "Listen 127.0.0.1:80\n\
             RewriteEngine On\n\
             RewriteRule ^/\\.well-known/acme-challenge/([A-Za-z0-9-_=]+)$ /var/lib/letsencrypt/http_challenges/$1 [END]\n",
            false,
        )
        .unwrap();
        assert_eq!(c.global.rewrite_policy.rewrite_rules.len(), 1);
        assert_eq!(c.global.mapping_policy.aliases.len(), 1);
        let alias = &c.global.mapping_policy.aliases[0];
        assert!(alias.regex.is_some());
        assert_eq!(
            alias.fs_path,
            Path::new("/var/lib/letsencrypt/http_challenges")
        );
        assert_eq!(
            alias.target_template.as_deref(),
            Some("/var/lib/letsencrypt/http_challenges/$1")
        );

        let unrelated = load_text(
            "Listen 127.0.0.1:80\n\
             RewriteEngine On\n\
             RewriteRule ^/download/(.+)$ /srv/files/$1 [END]\n\
             RewriteRule ^/\\.well-known/acme-challenge/([A-Za-z0-9-_=]+)$ /srv/files/$1 [END]\n",
            false,
        )
        .unwrap();
        assert!(unrelated.global.mapping_policy.aliases.is_empty());
    }

    #[test]
    fn directory_rewrite_rules_use_a_per_directory_base() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "RewriteEngine On\n",
            "<Directory /srv/www/sub>\n",
            "RewriteRule ^old$ new [L]\n",
            "</Directory>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let s = c.effective_scope(None, Path::new("/srv/www/sub/old"), "/sub/old");
        assert_eq!(s.rewrite_policy.rewrite_rules.len(), 1);
        assert!(s.rewrite_policy.rewrite_rules[0].per_dir);
        assert_eq!(s.rewrite_policy.rewrite_rules[0].match_base, "/sub/");
        assert_eq!(s.rewrite_policy.rewrite_rules[0].base, "/sub/");
        assert_eq!(
            s.rewrite_policy.rewrite_rules[0].subject_dir.as_deref(),
            Some(Path::new("/srv/www/sub"))
        );

        let s = c.effective_scope(None, Path::new("/srv/www/sub"), "/sub");
        assert_eq!(s.rewrite_policy.rewrite_rules[0].match_base, "/sub/");

        // Wildcard <Directory> patterns are not filesystem layer identities;
        // keep the legacy non-per-directory rewrite treatment.
        let wildcard = load_text(
            concat!(
                "Listen 127.0.0.1:0\n",
                "RewriteEngine On\n",
                "<Directory /srv/www/*>\n",
                "RewriteRule ^old$ new [L]\n",
                "</Directory>\n",
            ),
            false,
        )
        .unwrap();
        let s = wildcard.effective_scope(None, Path::new("/srv/www/sub/old"), "/sub/old");
        assert!(!s.rewrite_policy.rewrite_rules[0].per_dir);
        assert!(s.rewrite_policy.rewrite_rules[0].subject_dir.is_none());
    }

    #[test]
    fn limit_sections_compile_method_scoped_rules() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<Directory /srv>\n",
            "<Limit POST PUT>\n",
            "Require valid-user\n",
            "Order allow,deny\n",
            "Allow from 10.0.0.0/8\n",
            "Satisfy any\n",
            "</Limit>\n",
            "</Directory>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let s = c.effective_scope(None, Path::new("/srv/file"), "/file");
        let entries = require_entries(s.authorization.requires);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].limit,
            Some(MethodSet::Only(vec!["POST".into(), "PUT".into()]))
        );
        assert!(entries[0].applies("POST"));
        assert!(entries[0].applies("PUT"));
        assert!(!entries[0].applies("GET"));
        let legacy = s.authorization.legacy.expect("limited legacy rules");
        assert_eq!(legacy.order.len(), 1);
        assert_eq!(legacy.allow.len(), 1);
        assert_eq!(legacy.satisfy.len(), 1);
        assert!(!legacy.order[0].applies("GET"));

        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<Directory /srv>\n",
            "<LimitExcept GET HEAD>\n",
            "Require all denied\n",
            "</LimitExcept>\n",
            "</Directory>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let s = c.effective_scope(None, Path::new("/srv/file"), "/file");
        let entries = require_entries(s.authorization.requires);
        assert!(entries[0].applies("POST"));
        assert!(!entries[0].applies("GET"));
        assert!(!entries[0].applies("HEAD"));

        // Nested limits intersect, and restricting names must not appear in
        // server/vhost scope.
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<Directory /srv>\n",
            "<Limit POST PUT>\n",
            "<Limit POST>\n",
            "Require all denied\n",
            "</Limit>\n",
            "</Limit>\n",
            "</Directory>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let s = c.effective_scope(None, Path::new("/srv/file"), "/file");
        let entries = require_entries(s.authorization.requires);
        assert_eq!(entries[0].limit, Some(MethodSet::Only(vec!["POST".into()])));
        assert!(load_text(
            "Listen 127.0.0.1:0\n<Limit GET>\nRequire all denied\n</Limit>\n",
            false
        )
        .is_err());
        let c = load_text(
            "Listen 127.0.0.1:0\n<Directory /srv>\n<Limit GET>\nOptions Indexes\n</Limit>\n</Directory>\n",
            false,
        )
        .unwrap();
        let s = c.effective_scope(None, Path::new("/srv/file"), "/file");
        assert!(s.effective_options().contains(Options::INDEXES));
        let c = load_text(
            "Listen 127.0.0.1:0\n<Directory /srv>\nOptions ExecCGI\n<Limit GET>\nOptions -ExecCGI\n</Limit>\n</Directory>\n",
            false,
        )
        .unwrap();
        let s = c.effective_scope(None, Path::new("/srv/file"), "/file");
        assert!(!s.effective_options().contains(Options::EXEC_CGI));
        assert!(load_text(
            "Listen 127.0.0.1:0\n<Directory /srv>\n<Limit TRACE>\nRequire all denied\n</Limit>\n</Directory>\n",
            false
        )
        .is_err());
        assert!(load_text(
            "Listen 127.0.0.1:0\n<Directory /srv>\n<Limit POST PUT>\n<Limit POST PUT>\nRequire all denied\n</Limit>\n</Limit>\n</Directory>\n",
            false
        )
        .is_err());
    }

    #[test]
    fn disk_cache_limits_are_parsed() {
        let c = load_text(
            "Listen 127.0.0.1:0\n\
             CacheMaxFileSize 1234\n\
             CacheMaxDiskSize 5678\n\
             CacheMaxMemorySize 3456\n\
             CacheDefaultExpire 9\n",
            false,
        )
        .unwrap();
        assert_eq!(c.cache.max_file_size, 1234);
        assert_eq!(c.cache.max_disk_size, 5678);
        assert_eq!(c.cache.max_memory_size, 3456);
        assert_eq!(c.cache.default_expire, 9);
    }

    #[test]
    fn default_runtime_dir_is_strict_compatible() {
        assert!(load_text("Listen 127.0.0.1:0\nDefaultRuntimeDir /tmp\n", true).is_ok());
    }

    #[test]
    fn proxy_target_authority_cannot_come_from_request_capture() {
        assert!(load_text(
            "Listen 127.0.0.1:0\nProxyPassMatch ^/(.*)$ http://$1/\n",
            false
        )
        .is_err());
        assert!(load_text(
            "Listen 127.0.0.1:0\nProxyPassMatch ^/(.*)$ http://127.0.0.1:9000/$1\n",
            false
        )
        .is_ok());
        assert!(load_text(
            "Listen 127.0.0.1:0\nRewriteRule ^/(.*)$ http://$1/ [P]\n",
            false
        )
        .is_err());
        for target in [r"http://\1/", "http://%1/"] {
            assert!(
                load_text(
                    &format!("Listen 127.0.0.1:0\nRewriteRule ^/(.*)$ {target} [P]\n"),
                    false,
                )
                .is_err(),
                "dynamic proxy authority was accepted: {target}"
            );
        }
        assert!(load_text(
            "Listen 127.0.0.1:0\nRewriteRule ^/(.*)$ http://127.0.0.1:9000/$1 [P]\n",
            false
        )
        .is_ok());
    }

    #[test]
    fn unsupported_proxy_transports_fail_closed() {
        for directive in [
            "ProxyPass /x ftp://127.0.0.1/pub/",
            "ProxyPassReverse /x ftp://127.0.0.1/pub/",
            "ProxyPassMatch ^/x$ udp://127.0.0.1:9000/",
        ] {
            let text = format!("Listen 127.0.0.1:0\n{directive}\n");
            assert!(
                load_text(&text, false).is_err(),
                "unsupported proxy transport must fail: {directive}"
            );
        }
        assert!(load_text(
            "Listen 127.0.0.1:0\nProxyPass /x http://127.0.0.1:9000/\n",
            false
        )
        .is_ok());
    }

    #[test]
    fn vhost_name_patterns_use_verified_boundary_matching() {
        assert!(crate::verified::host_pattern_matches(
            b"anything.test",
            b"*"
        ));
        assert!(crate::verified::host_pattern_matches(
            b"a.example.com",
            b"*.example.com"
        ));
        assert!(!crate::verified::host_pattern_matches(
            b"example.com",
            b"*.example.com"
        ));
        assert!(!crate::verified::host_pattern_matches(
            b"badexample.com",
            b"*.example.com"
        ));
        assert!(crate::verified::host_pattern_matches(
            b"EXAMPLE.COM",
            b"example.com"
        ));
        assert!(!crate::verified::host_pattern_matches(
            b"a.example.com",
            b".example.com"
        ));
        assert!(load_text(
            "Listen 127.0.0.1:0\n<VirtualHost *:0>\nServerAlias ~[bad\n</VirtualHost>\n",
            false
        )
        .is_ok());
    }

    #[test]
    fn security_sensitive_directives_fail_closed() {
        for cfg in [
            "Listen 127.0.0.1:0\nAllowMethods GET\n",
            "Listen 127.0.0.1:0\nSSLRequireSSL\n",
            "Listen 127.0.0.1:0\nSSLRequire %{SSL_PROTOCOL} eq 'TLSv1.2'\n",
            "Listen 127.0.0.1:0\nSecRuleEngine On\n",
        ] {
            assert!(load_text(cfg, false).is_err(), "{cfg}");
        }
        assert!(load_text("Listen 127.0.0.1:0\nSecRuleEngine Off\n", false).is_ok());
        // Satisfy is supported only in a directory context, with a valid argument.
        assert!(load_text(
            "Listen 127.0.0.1:0\n<Directory /srv>\nSatisfy any\n</Directory>\n",
            false
        )
        .is_ok());
        assert!(load_text(
            "Listen 127.0.0.1:0\n<Directory /srv>\nSatisfy sometimes\n</Directory>\n",
            false
        )
        .is_err());
        assert!(load_text("Listen 127.0.0.1:0\nSatisfy any\n", false).is_err());
    }

    #[test]
    fn connection_wide_tls_directives_cannot_be_globalized_from_a_location() {
        for directive in [
            "SSLSessionCache none",
            "SSLSessionCacheTimeout 999999",
            "SSLRandomSeed startup builtin",
            "SSLPassPhraseDialog builtin",
            "SSLStaplingCache shmcb:/run/apache2/stapling(32768)",
            "SSLCARevocationFile /etc/apache2/client.crl",
            "SSLCARevocationCheck leaf",
        ] {
            let config = format!(
                "Listen 127.0.0.1:443\n<Directory /srv/private>\n{directive}\n</Directory>\n"
            );
            let errors = load_text(&config, false).unwrap_err();
            assert!(
                errors.iter().any(|error| error
                    .msg
                    .contains("only supported in server or virtual-host context")),
                "scoped TLS directive was globalized: {directive}: {errors:?}"
            );
        }
    }

    #[test]
    fn security_sensitive_unimplemented_directives_fail_closed() {
        for directive in [
            "ProxyBlock 169.254.169.254",
            "RequestHeader unset Authorization",
            "SetEnvIfExpr \"true\" X=1",
            "AcceptPathInfo Off",
            "AuthzProviderAlias ldap-group foo",
            "FilterProvider foo bar",
        ] {
            let text = format!("Listen 127.0.0.1:0\n{directive}\n");
            assert!(
                load_text(&text, false).is_err(),
                "compat mode must reject security directive: {directive}"
            );
        }
        for directive in [
            "ProxyRequests On",
            "SSLOptions +StdEnvVars",
            "LDAPTrustedCA /etc/ssl/ca.pem",
            "DAVDepthInfinity On",
            "CacheSocache shmcb",
            "AllowConnect 443",
        ] {
            let text = format!("Listen 127.0.0.1:0\n{directive}\n");
            assert!(
                load_text(&text, false).is_err(),
                "security family must fail closed: {directive}"
            );
        }
        assert!(load_text("Listen 127.0.0.1:0\nAddDescription \"x\" .txt\n", false).is_err());
    }

    #[test]
    fn non_file_auth_provider_fails_closed() {
        let err = load_text("Listen 127.0.0.1:0\nAuthBasicProvider ldap\n", false);
        assert!(err.is_err());
    }

    #[test]
    fn unknown_and_unimplemented_directives() {
        let unknown = "Listen 127.0.0.1:0\nDefinitelyNotADirective on\n";
        assert!(load_text(unknown, false).is_err());
        assert!(load_text(unknown, true).is_err());

        let known = "Listen 127.0.0.1:0\nAddDescription \"x\" .txt\n";
        assert!(load_text(known, false).is_err());
        assert!(load_text(known, true).is_err());
    }

    #[test]
    fn security_and_resource_directive_disposition_matrix() {
        // Every security-, filter-, audit- or resource-relevant directive in
        // the compatibility warning set must fail closed instead of being
        // silently ignored.
        for name in fail_closed_directives() {
            let text = format!("Listen 127.0.0.1:0\n{name} on\n");
            assert!(
                load_text(&text, false).is_err(),
                "security/resource directive '{name}' must fail closed in compat mode"
            );
            assert!(
                load_text(&text, true).is_err(),
                "security/resource directive '{name}' must fail closed in strict mode"
            );
        }

        // Presentation and module directives are effectful too. Refuse to
        // claim they were applied when Vapache has no implementation.
        for directive in [
            "AddDescription \"x\" .txt",
            "UserDir public_html",
            "SessionCookieName session path=/",
            "Substitute \"s/a/b/\"",
            "CharsetDefault utf-8",
        ] {
            let text = format!("Listen 127.0.0.1:0\n{directive}\n");
            assert!(
                load_text(&text, false).is_err(),
                "normal mode must reject '{directive}'"
            );
            assert!(
                load_text(&text, true).is_err(),
                "strict mode must reject '{directive}'"
            );
        }
    }

    #[test]
    fn effectful_unimplemented_mapping_and_header_forms_fail_closed() {
        assert!(load_text("Listen 127.0.0.1:0\nProxyPass /app !\n", false).is_err());
        assert!(load_text("Listen 127.0.0.1:0\nHeader edit X-Test a b\n", false).is_err());
    }

    #[test]
    fn regex_alias_redirect_and_remove_handler_are_handled() {
        let cfg = load_text(
            concat!(
                "Listen 127.0.0.1:0\n",
                "RedirectMatch 404 /\\.env$\n",
                "AliasMatch \"^/pub/(.*)$\" \"/srv/private/$1\"\n",
                "ScriptAliasMatch \"^/cgi/(.*)$\" \"/srv/cgi/$1\"\n",
                "AddHandler cgi-script .cgi\n",
                "RemoveHandler .cgi\n",
            ),
            false,
        )
        .unwrap();
        let redirect = cfg.global.mapping_policy.redirects.first().unwrap();
        assert_eq!(redirect.status, 404);
        assert!(redirect.regex.as_ref().unwrap().is_match(b"/.env"));
        assert!(cfg
            .global
            .mapping_policy
            .aliases
            .iter()
            .any(|a| a.regex.is_some() && !a.script));
        assert!(cfg
            .global
            .mapping_policy
            .aliases
            .iter()
            .any(|a| a.regex.is_some() && a.script));
        assert!(effective_handler(&cfg.global, b"evil.cgi").is_none());
    }

    #[test]
    fn relative_regex_alias_root_is_resolved_against_server_root() {
        let cfg = load_text(
            concat!(
                "Listen 127.0.0.1:0\n",
                "AliasMatch \"^/x/(.*)$\" \"private/$1\"\n",
                "ScriptAliasMatch \"^/cgi/(.*)$\" \"cgi-bin/$1\"\n",
            ),
            false,
        )
        .unwrap();
        let server_root = std::env::temp_dir();
        for alias in &cfg.global.mapping_policy.aliases {
            assert!(
                alias.fs_path.starts_with(&server_root),
                "relative alias root must be anchored at ServerRoot: {:?}",
                alias.fs_path
            );
            assert!(!alias.fs_path.as_os_str().is_empty());
        }
        let alias = &cfg.global.mapping_policy.aliases[0];
        assert_eq!(alias.fs_path, server_root.join("private"));
    }

    #[test]
    fn auth_location_scope_is_applied() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<Location \"/auth/\">\n",
            "AuthType Basic\n",
            "AuthName \"Realm\"\n",
            "AuthUserFile /tmp/users\n",
            "Require valid-user\n",
            "</Location>\n",
            "<VirtualHost *:0>\n",
            "ServerName localhost\n",
            "</VirtualHost>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let vh = c.vhosts.first();
        let s = c.effective_scope(
            vh,
            Path::new("/srv/www/auth/protected.txt"),
            "/auth/protected.txt",
        );
        let entries = require_entries(s.authorization.requires);
        assert!(matches!(
            entries.as_slice(),
            [RequireEntry {
                node: RequireNode::Provider(Require::ValidUser { negate: false }),
                limit: None,
            }]
        ));
        assert_eq!(s.authorization.auth_type.as_deref(), Some("basic"));
    }

    #[test]
    fn scope_merge_applies_each_policy_once() {
        let mut parent = Scope::default();
        parent
            .content_policy
            .add_types
            .push(("parent".into(), "ptype".into()));
        parent
            .header_policy
            .set_headers
            .push(("X-Parent".into(), "1".into()));
        parent
            .environment_policy
            .set_env
            .push(Originated::main(("PARENT".into(), "1".into())));

        let mut child = Scope::default();
        child
            .content_policy
            .add_types
            .push(("child".into(), "ctype".into()));
        child
            .header_policy
            .set_headers
            .push(("X-Child".into(), "2".into()));
        child
            .environment_policy
            .set_env
            .push(Originated::main(("CHILD".into(), "2".into())));
        child.content_policy.document_root = Some("/child".into());

        parent.merge(&child);
        assert_eq!(
            parent.content_policy.add_types,
            vec![
                ("parent".into(), "ptype".into()),
                ("child".into(), "ctype".into())
            ]
        );
        assert_eq!(
            parent.content_policy.document_root.as_deref(),
            Some(Path::new("/child"))
        );
        assert_eq!(parent.header_policy.set_headers.len(), 2);
        assert_eq!(parent.environment_policy.set_env.len(), 2);
    }

    #[test]
    fn scope_merge_replaces_child_set_headers_and_audits_always_lists() {
        let mut parent = Scope::default();
        parent
            .header_policy
            .set_headers
            .push(("X-Set".into(), "one".into()));
        parent
            .header_policy
            .always_set_headers
            .push(("X-Always".into(), "one".into()));
        let mut child = Scope::default();
        child
            .header_policy
            .set_headers
            .push(("X-Set".into(), "two".into()));
        child
            .header_policy
            .always_set_headers
            .push(("X-Always".into(), "two".into()));
        child
            .header_policy
            .always_unset_headers
            .push("X-Old".into());
        parent.merge(&child);
        assert_eq!(
            parent.header_policy.set_headers,
            vec![("X-Set".into(), "two".into())]
        );
        assert_eq!(
            parent.header_policy.always_set_headers,
            vec![("X-Always".into(), "two".into())]
        );
        assert_eq!(
            parent.header_policy.always_unset_headers,
            vec!["X-Old".to_string()]
        );
    }

    #[test]
    fn tokenizer() {
        assert_eq!(
            crate::config_frontend::tokenize("a \"b c\" d").unwrap(),
            vec!["a", "b c", "d"]
        );
        assert_eq!(
            crate::config_frontend::tokenize("a\\ b").unwrap(),
            vec!["a b"]
        );
        assert_eq!(
            crate::config_frontend::tokenize("\"^\\.ht\"").unwrap(),
            vec!["^\\.ht"]
        );
        assert_eq!(
            crate::config_frontend::tokenize("\"a \\\"b\\\"\"").unwrap(),
            vec!["a \"b\""]
        );
        assert!(crate::config_frontend::tokenize("\"unterminated").is_err());
    }

    #[test]
    fn proxy_directives_are_compiled_into_scopes() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "ProxyPass /app http://127.0.0.1:9000/\n",
            "ProxyPassReverse /app http://127.0.0.1:9000/\n",
            "ProxyPassMatch ^/(.*\\.php)$ unix:/run/php.sock|fcgi://localhost/var/www/\n",
            "<VirtualHost *:8080>\n",
            "ServerName localhost\n",
            "</VirtualHost>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let s = c.effective_scope(c.vhosts.first(), Path::new("/srv/app/x"), "/app/x");
        assert_eq!(s.proxy_policy.proxy_passes.len(), 1);
        assert_eq!(s.proxy_policy.proxy_reverses.len(), 1);
        assert_eq!(s.proxy_policy.proxy_rules.len(), 1);
    }

    #[test]
    fn iffile_section_is_frozen_when_configuration_is_read() {
        let file = std::env::temp_dir().join(format!("vapache-iffile-{}", std::process::id()));
        std::fs::write(&file, "x").unwrap();
        let cfg = format!(
            "Listen 127.0.0.1:0\n<IfFile \"{}\" >\nHeader set X-IfFile yes\n</IfFile>\n",
            file.display()
        );
        let c = load_text(&cfg, false).unwrap();
        let req = crate::http::Request {
            method: "GET".into(),
            target: b"/x".to_vec(),
            raw_path: b"/x".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        let s = c.effective_scope_req(
            None,
            Path::new("/srv/x"),
            "/x",
            &req,
            "127.0.0.1".parse().unwrap(),
        );
        assert!(s
            .header_policy
            .set_headers
            .iter()
            .any(|(n, _)| n == "X-IfFile"));
        std::fs::remove_file(file).unwrap();
        let still_selected = c.effective_scope_req(
            None,
            Path::new("/srv/y"),
            "/y",
            &req,
            "127.0.0.1".parse().unwrap(),
        );
        assert!(still_selected
            .header_policy
            .set_headers
            .iter()
            .any(|(n, _)| n == "X-IfFile"));
    }

    #[test]
    fn if_section_expression_is_applied_per_request() {
        let cfg = "Listen 127.0.0.1:0\n\
<If \"%{HTTP:X-Test} == 'yes'\">\n\
Header set X-If yes\n\
</If>\n\
<VirtualHost *:8080>\nServerName localhost\n</VirtualHost>\n";
        let c = load_text(cfg, false).unwrap();
        let mut req = crate::http::Request {
            method: "GET".into(),
            target: b"/x".to_vec(),
            raw_path: b"/x".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        let plain = c.effective_scope_req(
            c.vhosts.first(),
            Path::new("/srv/x"),
            "/x",
            &req,
            "127.0.0.1".parse().unwrap(),
        );
        assert!(plain.header_policy.set_headers.is_empty());
        req.headers.insert("x-test", b"yes".to_vec());
        let matched = c.effective_scope_req(
            c.vhosts.first(),
            Path::new("/srv/x"),
            "/x",
            &req,
            "127.0.0.1".parse().unwrap(),
        );
        assert!(matched
            .header_policy
            .set_headers
            .iter()
            .any(|(n, _)| n == "X-If"));
    }

    #[test]
    fn compression_directives_survive_ifmodule_and_vhost_merge() {
        let cfg = "LoadModule deflate_module /usr/lib/apache2/modules/mod_deflate.so\n\
Listen 127.0.0.1:0\n\
<IfModule mod_deflate.c>\n\
AddOutputFilterByType DEFLATE text/plain\n\
DeflateCompressionLevel 7\n\
</IfModule>\n\
<VirtualHost *:8080>\n\
ServerName localhost\n\
</VirtualHost>\n";
        let c = load_text(cfg, false).unwrap();
        let vh = c.vhosts.first();
        let s = c.effective_scope(vh, Path::new("/srv/a.txt"), "/a.txt");
        assert!(!s.compression_policy.compression_rules.is_empty());
        assert_eq!(s.compression_policy.deflate_level, Some(7));
    }

    #[test]
    fn has_cgi_detects_dispatch_paths() {
        assert!(!load_text("Listen 127.0.0.1:0\n", false).unwrap().has_cgi());

        let c = load_text(
            "Listen 127.0.0.1:0\nScriptAlias /cgi-bin/ /srv/cgi-bin/\n",
            false,
        )
        .unwrap();
        assert!(c.has_cgi());

        let c = load_text(
            "Listen 127.0.0.1:0\n<Directory /srv>\nOptions +ExecCGI\n</Directory>\n",
            false,
        )
        .unwrap();
        assert!(c.has_cgi());

        let c = load_text(
            "Listen 127.0.0.1:0\nAddHandler cgi-script .cgi .sh\n",
            false,
        )
        .unwrap();
        assert!(c.has_cgi());

        let c = load_text(
            "Listen 127.0.0.1:0\n<VirtualHost *:8080>\nScriptAlias /cgi/ /srv/cgi/\n</VirtualHost>\n",
            false,
        )
        .unwrap();
        assert!(c.has_cgi());

        let c = load_text(
            "Listen 127.0.0.1:0\n<Directory /srv>\n<Files *.run>\nSetHandler cgi-script\n</Files>\n</Directory>\n",
            false,
        )
        .unwrap();
        assert!(c.has_cgi());

        // Access files are request-time configuration and can introduce CGI
        // handlers, so the startup gate must stay conservatively enabled.
        let c = load_text(
            "Listen 127.0.0.1:0\n<Directory /srv>\nAllowOverride FileInfo\n</Directory>\n",
            false,
        )
        .unwrap();
        assert!(c.has_cgi());
    }

    #[test]
    fn auth_merging_and_allowmethods_are_compiled() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<Directory /srv>\n",
            "Require ip 10.0.0.0/8\n",
            "</Directory>\n",
            "<Directory /srv/sub>\n",
            "AuthMerging And\n",
            "Require user alice\n",
            "AllowMethods GET HEAD OPTIONS\n",
            "</Directory>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let s = c.effective_scope(None, Path::new("/srv/sub/file"), "/sub/file");
        assert!(matches!(
            s.authorization.requires,
            Some(AuthPolicy::And(_, _))
        ));
        assert_eq!(
            s.authorization.allow_methods,
            Some(AllowMethods::Only(vec![
                "GET".into(),
                "HEAD".into(),
                "OPTIONS".into()
            ]))
        );
        assert!(s.method_allowed("GET"));
        assert!(s.method_allowed("HEAD"));
        assert!(!s.method_allowed("POST"));
        assert_eq!(
            s.authorization.allow_methods_header().as_deref(),
            Some("GET, HEAD, OPTIONS")
        );

        let s = c.effective_scope(None, Path::new("/srv/plain"), "/plain");
        assert_eq!(s.authorization.allow_methods, None);
        assert!(s.method_allowed("POST"));

        assert!(load_text("Listen 127.0.0.1:0\nAuthMerging And\n", false).is_err());
        assert!(load_text("Listen 127.0.0.1:0\nAllowMethods GET\n", false).is_err());
        assert!(load_text("Listen 127.0.0.1:0\nAllowMethods BOGUS\n", false).is_err());
    }

    #[test]
    fn unsupported_filters_and_handlers_are_recorded() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<Directory /srv>\n",
            "SetOutputFilter INCLUDES\n",
            "AddHandler application/x-httpd-php .php\n",
            "</Directory>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let s = c.effective_scope(None, Path::new("/srv/x.php"), "/x.php");
        assert!(s
            .mapping_policy
            .unsupported_filters
            .iter()
            .any(|f| f.eq_ignore_ascii_case("INCLUDES")));
        assert_eq!(
            crate::config::effective_handler(&s, b"x.php"),
            Some("application/x-httpd-php")
        );

        let c = load_text(
            "Listen 127.0.0.1:0\nAddOutputFilter INCLUDES .shtml\n",
            false,
        )
        .unwrap();
        let s = c.effective_scope(None, Path::new("/srv/x.html"), "/x.html");
        assert!(s.mapping_policy.unsupported_filters.is_empty());
        assert_eq!(s.compression_policy.unsupported_filter_rules.len(), 1);

        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<Directory /srv>\n",
            "AddOutputFilterByType DEFLATE text/plain\n",
            "AddHandler cgi-script .cgi\n",
            "</Directory>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let s = c.effective_scope(None, Path::new("/srv/x.cgi"), "/x.cgi");
        assert!(s.mapping_policy.unsupported_filters.is_empty());
        assert_eq!(
            crate::config::effective_handler(&s, b"x.cgi"),
            Some("cgi-script")
        );
    }

    #[test]
    fn elseif_and_else_follow_the_if_chain() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<Directory /srv>\n",
            "<If \"%{HTTP:X-Test} == 'a'\">\n",
            "Header set X-Branch a\n",
            "</If>\n",
            "<ElseIf \"%{HTTP:X-Test} == 'b'\">\n",
            "Header set X-Branch b\n",
            "</ElseIf>\n",
            "<Else>\n",
            "Header set X-Branch c\n",
            "</Else>\n",
            "</Directory>\n",
        );
        let c = load_text(cfg, false).unwrap();
        for (header, expected) in [(Some("a"), "a"), (Some("b"), "b"), (None, "c")] {
            let mut req = test_request("GET");
            if let Some(value) = header {
                req.headers.insert("x-test", value.as_bytes().to_vec());
            }
            let s = c.effective_scope_req(
                None,
                Path::new("/srv/file"),
                "/file",
                &req,
                "127.0.0.1".parse().unwrap(),
            );
            let value = s
                .header_policy
                .set_headers
                .iter()
                .find(|(name, _)| name == "X-Branch")
                .map(|(_, value)| value.as_str());
            assert_eq!(value, Some(expected), "header {header:?}");
        }

        assert!(load_text(
            "Listen 127.0.0.1:0\n<Directory /srv>\n<Else>\nHeader set X-Test no\n</Else>\n</Directory>\n",
            false
        )
        .is_err());
        let c = load_text(
            "Listen 127.0.0.1:0\n<Directory /srv>\n<If \"1\">\n<If \"1\">\nHeader set X-Nested yes\n</If>\n</If>\n</Directory>\n",
            false,
        )
        .unwrap();
        let req = test_request("GET");
        let s = c.effective_scope_req(
            None,
            Path::new("/srv/file"),
            "/file",
            &req,
            "127.0.0.1".parse().unwrap(),
        );
        assert!(s
            .header_policy
            .set_headers
            .iter()
            .any(|(n, _)| n == "X-Nested"));
    }

    #[test]
    fn proxy_containers_apply_access_rules() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<Proxy \"http://backend/app/*\">\n",
            "Require ip 10.0.0.0/8\n",
            "</Proxy>\n",
            "<ProxyMatch \"^http://other/[0-9]+/\">\n",
            "<If \"%{HTTP:X-Allow} == 'yes'\">\n",
            "Require all granted\n",
            "</If>\n",
            "</ProxyMatch>\n",
        );
        let c = load_text(cfg, false).unwrap();
        assert_eq!(c.proxy_containers.len(), 2);
        let req = test_request("GET");
        let mut scope = Scope::default();
        c.apply_proxy_access(
            None,
            &mut scope,
            "http://backend/app/file",
            &req,
            "127.0.0.1".parse().unwrap(),
            "/app/file",
        );
        assert_eq!(
            crate::access::check(
                &scope,
                &req,
                "127.0.0.1".parse().unwrap(),
                None,
                "/app/file",
                None
            ),
            crate::access::Access::Denied
        );
        assert!(
            crate::access::check(
                &scope,
                &req,
                "10.1.2.3".parse().unwrap(),
                None,
                "/app/file",
                None
            ) == crate::access::Access::Allowed
        );

        let mut scope = Scope::default();
        c.apply_proxy_access(
            None,
            &mut scope,
            "http://other/42/x",
            &req,
            "127.0.0.1".parse().unwrap(),
            "/other/42/x",
        );
        // The <If> did not match; no authorization rule was added.
        assert!(scope.authorization.requires.is_none());
        let mut req_allowed = test_request("GET");
        req_allowed.headers.insert("x-allow", b"yes".to_vec());
        let mut scope = Scope::default();
        c.apply_proxy_access(
            None,
            &mut scope,
            "http://other/42/x",
            &req_allowed,
            "127.0.0.1".parse().unwrap(),
            "/other/42/x",
        );
        assert_eq!(
            crate::access::check(
                &scope,
                &req_allowed,
                "127.0.0.1".parse().unwrap(),
                None,
                "/other/42/x",
                None
            ),
            crate::access::Access::Allowed
        );
    }

    #[test]
    fn coverage_simple_types_and_helpers() {
        let e = ConfigError {
            file: String::new(),
            line: 7,
            msg: "bare".into(),
        };
        assert_eq!(e.to_string(), "bare");
        let e = ConfigError {
            file: "x.conf".into(),
            line: 7,
            msg: "failed".into(),
        };
        assert_eq!(e.to_string(), "x.conf line 7: failed");
        let _: &dyn std::error::Error = &e;

        let all = OverrideCategories::all();
        assert!(all.contains(OverrideCategories::AUTH_CONFIG));
        assert!(all.contains(OverrideCategories::OPT_NONE));
        assert!(!OverrideCategories::empty().contains(OverrideCategories::AUTH_CONFIG));

        let categories = OverrideMode::Categories(OverrideCategories(
            OverrideCategories::AUTH_CONFIG | OverrideCategories::OPT_INDEXES,
        ));
        assert!(categories.is_enabled());
        assert!(categories.allows(OverrideCategory::AuthConfig));
        assert!(!categories.allows(OverrideCategory::FileInfo));
        assert!(categories.allows_flag(OverrideCategories::OPT_INDEXES));
        assert!(categories.allows_any_option());
        assert!(!OverrideMode::None.is_enabled());
        assert!(!OverrideMode::None.allows(OverrideCategory::Options));
        assert!(!OverrideMode::None.allows_flag(1));
        assert!(!OverrideMode::None.allows_any_option());
        assert!(OverrideMode::All.is_enabled());
        assert!(OverrideMode::All.allows(OverrideCategory::LanguagePriority));
        assert!(OverrideMode::All.allows_any_option());

        let options = Options::empty()
            .set(Options::INDEXES, true)
            .set(Options::EXEC_CGI, true)
            .set(Options::INDEXES, false);
        assert!(options.contains(Options::EXEC_CGI));
        assert!(!options.contains(Options::INDEXES));
        assert!(Options::all().contains(Options::MULTIVIEWS));

        assert!(AuthPolicy::List(Vec::new()).is_list());
        assert!(!AuthPolicy::And(
            Box::new(AuthPolicy::List(Vec::new())),
            Box::new(AuthPolicy::List(Vec::new()))
        )
        .is_list());

        assert!(AllowMethods::Reset.allows("PATCH"));
        assert!(AllowMethods::Reset.header().is_empty());
        let get = AllowMethods::Only(vec!["GET".into()]);
        assert!(get.allows("HEAD"));
        assert_eq!(get.header(), "GET, HEAD");
        let head = AllowMethods::Only(vec!["HEAD".into()]);
        assert!(head.allows("GET"));
        assert_eq!(head.header(), "HEAD, GET");
        assert_eq!(AllowMethods::Only(vec!["POST".into()]).header(), "POST");
        assert_eq!(
            AllowMethods::Only(vec!["GET".into(), "HEAD".into()]).header(),
            "GET, HEAD"
        );

        assert!(HostSpec::All.matches("127.0.0.1".parse().unwrap()));
        assert!(HostSpec::Net("10.0.0.0".parse().unwrap(), 8).matches("10.1.2.3".parse().unwrap()));
        assert!(
            !HostSpec::Net("10.0.0.0".parse().unwrap(), 8).matches("127.0.0.1".parse().unwrap())
        );
        let scoped = MethodScoped {
            limit: Some(MethodSet::Only(vec!["GET".into()])),
            value: 1,
        };
        assert!(scoped.applies("HEAD"));
        assert!(!scoped.applies("POST"));
        let unscoped = MethodScoped {
            limit: None,
            value: 2,
        };
        assert!(unscoped.applies("POST"));

        assert!(MethodSet::all().matches("PATCH"));
        assert!(MethodSet::Only(vec!["GET".into()]).matches("HEAD"));
        assert!(!MethodSet::Except(vec!["GET".into()]).matches("HEAD"));
        assert_eq!(
            MethodSet::Only(vec!["GET".into(), "POST".into()])
                .intersect(&MethodSet::Only(vec!["GET".into()])),
            MethodSet::Only(vec!["GET".into()])
        );
        assert_eq!(
            MethodSet::Only(vec!["GET".into()]).intersect(&MethodSet::Except(vec!["POST".into()])),
            MethodSet::Only(vec!["GET".into()])
        );
        assert_eq!(
            MethodSet::Except(vec!["GET".into()])
                .intersect(&MethodSet::Only(vec!["GET".into(), "POST".into()])),
            MethodSet::Only(vec!["POST".into()])
        );
        assert_eq!(
            MethodSet::Except(vec!["GET".into()])
                .intersect(&MethodSet::Except(vec!["GET".into(), "POST".into()])),
            MethodSet::Except(vec!["GET".into(), "POST".into()])
        );
        assert!(MethodSet::Only(Vec::new()).is_empty());

        assert_eq!(CompressionKind::Gzip.encoding(), "gzip");
        assert_eq!(CompressionKind::Brotli.encoding(), "br");
        for (name, expected) in [
            ("DEFLATE", Some(CompressionKind::Gzip)),
            ("gzip", Some(CompressionKind::Gzip)),
            ("BROTLI_COMPRESS", Some(CompressionKind::Brotli)),
            ("brotli", Some(CompressionKind::Brotli)),
            ("nope", None),
        ] {
            assert_eq!(CompressionKind::parse_filter(name), expected);
        }
        assert_eq!(AlterEtag::parse("addsuffix"), Some(AlterEtag::AddSuffix));
        assert_eq!(AlterEtag::parse("NoChange"), Some(AlterEtag::NoChange));
        assert_eq!(AlterEtag::parse("REMOVE"), Some(AlterEtag::Remove));
        assert_eq!(AlterEtag::parse("bad"), None);

        let mut scope = Scope::default();
        let kinds = parse_filter_tokens(
            &mut scope,
            &["gzip;brotli;unknown;;".into(), "UNKNOWN".into()],
        );
        assert_eq!(kinds, vec![CompressionKind::Gzip, CompressionKind::Brotli]);
        assert_eq!(scope.mapping_policy.unsupported_filters, vec!["unknown"]);

        let mut scope = Scope::default();
        scope.add_order(Order::AllowDeny, None);
        scope.add_satisfy(Satisfy::Any, None);
        scope.add_allow(HostSpec::All, None);
        scope.add_deny(
            HostSpec::Net("10.0.0.0".parse().unwrap(), 8),
            Some(&MethodSet::Only(vec!["GET".into()])),
        );
        let legacy = scope.authorization.legacy.as_ref().unwrap();
        assert_eq!(legacy.method_order("POST"), Order::AllowDeny);
        assert_eq!(legacy.method_satisfy("GET"), Satisfy::Any);
        assert_eq!(legacy.allow.len(), 1);
        assert_eq!(legacy.deny.len(), 1);

        let mut mime = MimeMap::new();
        mime.add_type("text/plain", &["txt".into(), ".TXT".into(), String::new()]);
        mime.add_type("application/gzip", &["gz".into()]);
        mime.add_type("application/octet-stream", &["inner".into()]);
        assert_eq!(
            mime.content_type(b"dir/name.TXT").as_deref(),
            Some("text/plain")
        );
        assert_eq!(
            mime.content_type(b"archive.tar.gz").as_deref(),
            Some("application/gzip")
        );
        assert_eq!(mime.content_type(b"name."), None);
        assert_eq!(mime.content_type(b"name"), None);
        assert_eq!(mime.content_type(b"name.unknown"), None);
        let long = "a".repeat(65);
        mime.add_type("text/long", &[long.clone()]);
        assert_eq!(
            mime.content_type(format!("file.{long}").as_bytes())
                .as_deref(),
            Some("text/long")
        );
        mime.remove_type(&[".TXT".into(), "gz".into()]);
        assert_eq!(mime.content_type(b"name.txt"), None);
        assert_eq!(mime.content_type(b"name.gz"), None);

        let dir = std::env::temp_dir().join(format!("vapache-types-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let types = dir.join("mime.types");
        std::fs::write(&types, "# comment\ntext/html html htm\n\nbroken\n").unwrap();
        assert!(mime.load_types_file(&types).is_ok());
        assert_eq!(mime.content_type(b"x.html").as_deref(), Some("text/html"));
        assert!(mime.load_types_file(&dir.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&dir);

        let root = Path::new("/tmp/root");
        let regex = Arc::new(compile_regex("^/x$").unwrap());
        let fixed = Alias::regex(regex.clone(), "/srv/index.html".into(), false, root);
        assert_eq!(fixed.fs_path, PathBuf::from("/srv"));
        let relative = Alias::regex(regex.clone(), "rel/index.php".into(), true, root);
        assert_eq!(relative.fs_path, PathBuf::from("/tmp/root/rel"));
        let relative_dir = Alias::regex(regex.clone(), "rel/$1".into(), false, root);
        assert_eq!(relative_dir.fs_path, PathBuf::from("/tmp/root/rel"));
        let capture = Alias::regex(regex, "$1".into(), false, root);
        assert!(capture.fs_path.as_os_str().is_empty());
        assert!(capture.target_template.is_some());

        let env_rule = parse_env_rule(
            "browsermatch",
            &[
                "^agent".into(),
                "A=1".into(),
                "!REMOVE".into(),
                "PLAIN".into(),
            ],
        )
        .unwrap();
        assert_eq!(env_rule.attribute, "User-Agent");
        assert_eq!(env_rule.actions.len(), 3);
        assert_eq!(env_rule.actions[0], ("A".into(), Some("1".into())));
        assert_eq!(env_rule.actions[1], ("REMOVE".into(), None));
        assert_eq!(env_rule.actions[2], ("PLAIN".into(), Some("1".into())));
        let nocase = parse_env_rule(
            "setenvifnocase",
            &["Host".into(), "EXAMPLE".into(), "X=1".into()],
        )
        .unwrap();
        assert!(nocase.nocase);
        assert!(parse_env_rule("setenvif", &[]).is_err());
        assert!(parse_env_rule("setenvif", &["Host".into(), "x".into()]).is_err());

        let mut scope = Scope::default();
        scope
            .environment_policy
            .set_env
            .push(Originated::main(("BASE".into(), "1".into())));
        scope.environment_policy.rewrite_env.push(Originated::main((
            "SERVER_REWRITE".into(),
            b"early".to_vec(),
        )));
        scope
            .environment_policy
            .rewrite_late_env
            .push(Originated::main((
                "DIRECTORY_REWRITE".into(),
                b"late".to_vec(),
            )));
        let mut rule = parse_env_rule(
            "setenvif",
            &[
                "Request_URI".into(),
                "^/x".into(),
                "HIT=yes".into(),
                "!BASE".into(),
            ],
        )
        .unwrap();
        scope
            .environment_policy
            .set_env_if
            .push(Originated::main(rule.clone()));
        rule.attribute = "Content-Type".into();
        rule.negate = true;
        scope
            .environment_policy
            .set_env_if
            .push(Originated::main(rule));
        scope
            .environment_policy
            .pass_env
            .push(Originated::main("VAPACHE_TEST_ENV".into()));
        scope
            .environment_policy
            .unset_env
            .push(Originated::main("DROP".into()));
        scope
            .environment_policy
            .set_env
            .push(Originated::main(("DROP".into(), "x".into())));
        std::env::set_var("VAPACHE_TEST_ENV", "passed");
        let mut req = test_request("GET");
        req.target = b"/x?q=1".to_vec();
        req.headers.insert("content-type", b"text/plain".to_vec());
        let peer = "127.0.0.1".parse().unwrap();
        let auth_env = scope.authorization_env(&req, "/x", peer);
        assert!(auth_env.contains(&("HIT".into(), b"yes".to_vec())));
        assert!(auth_env.contains(&("SERVER_REWRITE".into(), b"early".to_vec())));
        assert!(!auth_env.iter().any(|(k, _)| k == "DIRECTORY_REWRITE"));
        assert!(!auth_env.iter().any(|(k, _)| k == "BASE"));
        assert!(!auth_env.iter().any(|(k, _)| k == "VAPACHE_TEST_ENV"));
        let env = scope.request_env(&req, "/x", peer);
        assert!(env.contains(&("HIT".into(), b"yes".to_vec())));
        assert!(env.contains(&("SERVER_REWRITE".into(), b"early".to_vec())));
        assert!(env.contains(&("DIRECTORY_REWRITE".into(), b"late".to_vec())));
        assert!(env.contains(&("BASE".into(), b"1".to_vec())));
        assert!(env.contains(&("VAPACHE_TEST_ENV".into(), b"passed".to_vec())));
        assert!(!env.iter().any(|(k, _)| k == "DROP"));
        std::env::remove_var("VAPACHE_TEST_ENV");
    }

    #[test]
    fn set_env_if_capture_amplification_is_rejected_before_expansion() {
        let mut scope = Scope::default();
        let replacement = "$1".repeat(256);
        scope.environment_policy.set_env_if.push(Originated::main(
            parse_env_rule(
                "setenvif",
                &[
                    "X-Capture".into(),
                    "^(.*)$".into(),
                    format!("EXPANDED={replacement}"),
                ],
            )
            .unwrap(),
        ));
        let mut req = test_request("GET");
        req.headers.insert("x-capture", vec![b'a'; 8_000]);
        let env = scope.authorization_env(&req, "/", "127.0.0.1".parse().unwrap());
        assert!(!env.iter().any(|(name, _)| name == "EXPANDED"));
        assert!(req.policy_budget_failed());

        let mut safe = Scope::default();
        safe.environment_policy.set_env_if.push(Originated::main(
            parse_env_rule(
                "setenvif",
                &[
                    "X-Capture".into(),
                    "^([a-z]+)$".into(),
                    "EXPANDED=$1-$1".into(),
                ],
            )
            .unwrap(),
        ));
        let mut req = test_request("GET");
        req.headers.insert("x-capture", b"safe".to_vec());
        let env = safe.authorization_env(&req, "/", "127.0.0.1".parse().unwrap());
        assert!(env.contains(&("EXPANDED".into(), b"safe-safe".to_vec())));
        assert!(!req.policy_budget_failed());
    }

    #[test]
    fn access_file_prefilter_consumes_the_request_policy_budget() {
        let mut cfg = load_text("Listen 127.0.0.1:0\n", false).unwrap();
        cfg.override_enabled = true;
        cfg.override_anywhere = false;
        cfg.override_prefixes = vec![PathBuf::from(format!("/{}", "*".repeat(8_188)))];
        let path = PathBuf::from(format!("/{}", "a".repeat(3_000)));
        let req = test_request("GET");
        assert!(cfg.override_applicable_req(&path, &req).is_err());
        assert!(req.policy_budget_failed());
    }

    #[test]
    fn p16_regex_header_bytes_and_fastcgi_environment_provenance() {
        // Apache's directive PCRE mode is byte-oriented and ASCII by default.
        // Pin both the deny-guard and positive-gate directions at the shared
        // compiler used by SetEnvIf, rewrite and match containers.
        assert!(!compile_regex(r"^\w+$").unwrap().is_match("é".as_bytes()));
        assert!(!compile_regex(r"^\d+$").unwrap().is_match("١٢٣".as_bytes()));
        assert!(!compile_regex(r"^\s+$")
            .unwrap()
            .is_match("\u{a0}".as_bytes()));
        assert!(compile_regex(r"\badmin\b")
            .unwrap()
            .is_match("éadmin".as_bytes()));
        assert!(compile_regex(r"^\W+$").unwrap().is_match("é".as_bytes()));
        assert!(compile_regex(r"^\D+$").unwrap().is_match("١٢٣".as_bytes()));
        assert!(compile_regex(r"^\S+$")
            .unwrap()
            .is_match("\u{a0}".as_bytes()));
        assert!(compile_regex(r"^\w+$").unwrap().is_match(b"admin_1"));
        assert!(compile_regex(r"^\d+$").unwrap().is_match(b"123"));
        assert!(compile_regex(r"^\s+$").unwrap().is_match(b" \t"));
        assert!(!compile_regex(r"\badmin\b").unwrap().is_match(b"xadminx"));
        assert!(compile_regex(r"(?u)^\w+$").is_err());
        assert!(compile_regex(r"(?iu:^\w+$)").is_err());

        let mut scope = Scope::default();
        scope.environment_policy.set_env.push(Originated::main((
            "PHP_VALUE".into(),
            "main=allowed".into(),
        )));
        scope.environment_policy.set_env.push(Originated::access((
            "PHP_VALUE".into(),
            "auto_prepend_file=/tmp/pwn".into(),
        )));
        scope.environment_policy.set_env.push(Originated::access((
            "PHP_ADMIN_VALUE".into(),
            "auto_prepend_file=/tmp/pwn".into(),
        )));
        scope
            .environment_policy
            .rewrite_late_env
            .push(Originated::main(("MAIN_REWRITE".into(), b"yes".to_vec())));
        scope
            .environment_policy
            .rewrite_late_env
            .push(Originated::access((
                "ACCESS_REWRITE".into(),
                b"yes".to_vec(),
            )));

        // Raw obs-text must stay visible to SetEnvIf matching. The action is
        // access-file-originated so it participates in ACLs/local CGI but is
        // never promoted into FastCGI parameters.
        scope.environment_policy.set_env_if.push(Originated::access(
            parse_env_rule(
                "setenvif",
                &["X-Scan".into(), "sqlmap".into(), "ACCESS_BLOCK=1".into()],
            )
            .unwrap(),
        ));
        scope.environment_policy.set_env_if.push(Originated::access(
            parse_env_rule(
                "setenvif",
                &[
                    "X-Capture".into(),
                    "^(.)sqlmap$".into(),
                    "RAW_BYTE=$1".into(),
                ],
            )
            .unwrap(),
        ));
        scope.environment_policy.set_env_if.push(Originated::access(
            parse_env_rule(
                "setenvif",
                &["RAW_BYTE".into(), "^.$".into(), "RAW_BLOCK=1".into()],
            )
            .unwrap(),
        ));

        // Pin the P16-D semantics at the same time: bare action => 1, prior
        // environment chaining, and capture expansion.
        scope.environment_policy.set_env_if.push(Originated::main(
            parse_env_rule(
                "setenvif",
                &[
                    "User-Agent".into(),
                    "^([a-z]+)$".into(),
                    "BAD".into(),
                    "ID=$1".into(),
                ],
            )
            .unwrap(),
        ));
        scope.environment_policy.set_env_if.push(Originated::main(
            parse_env_rule("setenvif", &["BAD".into(), "^1$".into(), "DENY".into()]).unwrap(),
        ));

        let mut req = test_request("GET");
        req.headers
            .insert("x-scan", [vec![0xff], b"sqlmap".to_vec()].concat());
        req.headers
            .insert("x-capture", [vec![0xff], b"sqlmap".to_vec()].concat());
        req.headers.insert("user-agent", b"scanner".to_vec());
        let peer = "127.0.0.1".parse().unwrap();

        let auth = scope.authorization_env(&req, "/index.php", peer);
        assert!(auth.contains(&("ACCESS_BLOCK".into(), b"1".to_vec())));
        assert!(auth.contains(&("RAW_BYTE".into(), vec![0xff])));
        assert!(auth.contains(&("RAW_BLOCK".into(), b"1".to_vec())));
        assert!(auth.contains(&("BAD".into(), b"1".to_vec())));
        assert!(auth.contains(&("DENY".into(), b"1".to_vec())));
        assert!(auth.contains(&("ID".into(), b"scanner".to_vec())));

        let local = scope.request_env(&req, "/index.php", peer);
        assert!(local.contains(&("PHP_VALUE".into(), b"auto_prepend_file=/tmp/pwn".to_vec())));
        assert!(local.contains(&(
            "PHP_ADMIN_VALUE".into(),
            b"auto_prepend_file=/tmp/pwn".to_vec()
        )));
        assert!(local.contains(&("ACCESS_REWRITE".into(), b"yes".to_vec())));

        let fastcgi = scope.fastcgi_env(&req, "/index.php", peer);
        assert!(fastcgi.contains(&("PHP_VALUE".into(), b"main=allowed".to_vec())));
        assert!(fastcgi.contains(&("MAIN_REWRITE".into(), b"yes".to_vec())));
        for forbidden in ["PHP_ADMIN_VALUE", "ACCESS_REWRITE", "ACCESS_BLOCK"] {
            assert!(!fastcgi.iter().any(|(name, _)| name == forbidden));
        }
    }

    #[test]
    fn coverage_rule_helpers_and_vhost_names() {
        let cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<VirtualHost *:80>\n",
            "ServerName Example.Test:80\n",
            "ServerAlias ~^rx[0-9]+\\.test$ *.foo.test bar.test\n",
            "ServerAdmin admin@example.test\n",
            "</VirtualHost>\n",
        );
        let c = load_text(cfg, false).unwrap();
        let vh = &c.vhosts[0];
        assert!(vh.matches_name("example.test."));
        assert!(vh.matches_name("one.foo.test"));
        assert!(!vh.matches_name("foo.test"));
        assert!(!vh.matches_name("rx12.test"));
        assert!(vh.matches_name("BAR.TEST"));
        assert!(!vh.matches_name("other.test"));
        assert!(vh.has_wildcard_default());
        assert_eq!(vh.server_admin.as_deref(), Some("admin@example.test"));

        let req = test_request("GET");
        let base = ScopeRule {
            kind: MatchKind::Always,
            delta: Scope::default(),
            order: 1,
            condition: None,
            branch: ConditionBranch::Normal,
            chain: None,
            nested: Vec::new(),
        };
        let mut chain = HashMap::new();
        assert!(rule_condition_matches(
            &base,
            &req,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
            None,
            &mut chain
        ));

        let mut matched = base.clone();
        matched.condition = Some(crate::expr::parse("true").unwrap());
        matched.chain = Some(1);
        assert!(rule_condition_matches(
            &matched,
            &req,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
            None,
            &mut chain
        ));
        assert_eq!(chain.get(&1), Some(&true));

        let mut elseif = base.clone();
        elseif.branch = ConditionBranch::ElseIf;
        elseif.chain = Some(2);
        elseif.condition = Some(crate::expr::parse("true").unwrap());
        assert!(rule_condition_matches(
            &elseif,
            &req,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
            None,
            &mut chain
        ));
        chain.insert(2, true);
        let mut later = elseif.clone();
        later.chain = Some(2);
        assert!(!rule_condition_matches(
            &later,
            &req,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
            None,
            &mut chain
        ));
        let missing = base.clone();
        let mut no_chain = missing.clone();
        no_chain.branch = ConditionBranch::ElseIf;
        no_chain.chain = None;
        assert!(!rule_condition_matches(
            &no_chain,
            &req,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
            None,
            &mut chain
        ));
        let no_chain_condition = {
            let mut r = base.clone();
            r.branch = ConditionBranch::ElseIf;
            r.chain = Some(9);
            r.condition = None;
            r
        };
        assert!(!rule_condition_matches(
            &no_chain_condition,
            &req,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
            None,
            &mut chain
        ));
        let mut else_rule = base.clone();
        else_rule.branch = ConditionBranch::Else;
        else_rule.chain = Some(2);
        assert!(!rule_condition_matches(
            &else_rule,
            &req,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
            None,
            &mut chain
        ));
        let mut else_rule = base.clone();
        else_rule.branch = ConditionBranch::Else;
        else_rule.chain = Some(3);
        assert!(rule_condition_matches(
            &else_rule,
            &req,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
            None,
            &mut chain
        ));
        let mut else_missing = base.clone();
        else_missing.branch = ConditionBranch::Else;
        else_missing.chain = None;
        assert!(!rule_condition_matches(
            &else_missing,
            &req,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
            None,
            &mut chain
        ));

        assert!(path_has_prefix(
            Path::new("/srv/www/x"),
            Path::new("/srv/www")
        ));
        assert!(path_has_prefix(
            Path::new("/srv/www/x"),
            Path::new("/srv/www/")
        ));
        assert!(path_has_prefix(
            Path::new("/srv/www"),
            Path::new("/srv/www")
        ));
        assert!(!path_has_prefix(
            Path::new("/srv/wwwx"),
            Path::new("/srv/www")
        ));
        assert!(path_has_prefix(Path::new("/anything"), Path::new("")));
        assert!(wildcard_path_matches(
            Path::new("/srv/*/www"),
            Path::new("/srv/site/www")
        ));
        assert!(!wildcard_path_matches(
            Path::new("/srv/*/www"),
            Path::new("/srv/site/other")
        ));
        assert!(!wildcard_path_matches(
            Path::new("/srv/*"),
            Path::new("/srv/a/b")
        ));
        assert!(wildcard_path_matches(
            Path::new("/srv/site"),
            Path::new("/srv/site/child")
        ));

        let dir = std::env::temp_dir().join(format!("vapache-rule-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("file"), "x").unwrap();
        let wildcard = dir.parent().unwrap().join("*");
        assert!(directory_wildcard_matches(&wildcard, &dir.join("sub/file")));
        assert!(directory_pattern_matches_exact(
            Path::new(&format!("{}/sub/", dir.display())),
            &dir.join("sub")
        ));
        assert!(!directory_pattern_matches_exact(
            Path::new("/other"),
            &dir.join("sub")
        ));

        assert!(rule_kind_matches(
            &MatchKind::Always,
            &dir.join("file"),
            "/file",
            "file"
        ));
        assert!(rule_kind_matches(
            &MatchKind::Directory(dir.clone()),
            &dir.join("file"),
            "/file",
            "file"
        ));
        assert!(rule_kind_matches(
            &MatchKind::Directory(dir.parent().unwrap().join("*")),
            &dir.join("file"),
            "/file",
            "file"
        ));
        assert!(rule_kind_matches(
            &MatchKind::DirectoryMatch(compile_regex("vapache-rule-path").unwrap()),
            &dir.join("file"),
            "/file",
            "file"
        ));
        assert!(rule_kind_matches(
            &MatchKind::Files(compile_regex("^file$").unwrap()),
            &dir.join("file"),
            "/file",
            "file"
        ));
        assert!(rule_kind_matches(
            &MatchKind::FilesMatch(compile_regex("file").unwrap()),
            &dir.join("file"),
            "/file",
            "file"
        ));
        assert!(rule_kind_matches(
            &MatchKind::Location(String::new()),
            &dir.join("file"),
            "/file",
            "file"
        ));
        assert!(rule_kind_matches(
            &MatchKind::Location("/".into()),
            &dir.join("file"),
            "/file",
            "file"
        ));
        assert!(rule_kind_matches(
            &MatchKind::Location("/file/".into()),
            &dir.join("file"),
            "/file/child",
            "file"
        ));
        assert!(rule_kind_matches(
            &MatchKind::Location("/file".into()),
            &dir.join("file"),
            "/file",
            "file"
        ));
        assert!(rule_kind_matches(
            &MatchKind::Location("/file".into()),
            &dir.join("file"),
            "/file/child",
            "file"
        ));
        assert!(!rule_kind_matches(
            &MatchKind::Location("/file".into()),
            &dir.join("file"),
            "/filex",
            "file"
        ));
        assert!(rule_kind_matches(
            &MatchKind::LocationMatch(compile_regex("^/file").unwrap()),
            &dir.join("file"),
            "/file",
            "file"
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remoteip_trusted_and_internal_classes_match_apache_chain_rules() {
        let trusted = load_text(
            "RemoteIPHeader X-Forwarded-For\nRemoteIPTrustedProxy 127.0.0.1\n",
            false,
        )
        .unwrap();
        assert_eq!(trusted.remoteip_proxies.len(), 1);
        assert!(!trusted.remoteip_proxies[0].internal);
        let peer: std::net::SocketAddr = "127.0.0.1:1234".parse().unwrap();
        assert!(trusted.transport_peer_is_trusted_proxy(peer.ip()));
        assert!(!trusted.transport_peer_is_trusted_proxy("127.0.0.2".parse().unwrap()));
        for spoof in [
            "10.1.2.3",
            "8.8.8.8, 10.1.2.3",
            "::ffff:10.1.2.3",
            "10.1.2.3,",
            "8.8.8.8, not-an-ip",
        ] {
            let mut request = test_request("GET");
            request
                .headers
                .insert("x-forwarded-for", spoof.as_bytes().to_vec());
            assert_eq!(trusted.client_addr(peer, &request), peer, "{spoof}");
        }

        let mut public = test_request("GET");
        public
            .headers
            .insert("x-forwarded-for", b"8.8.8.8".to_vec());
        assert_eq!(
            trusted.client_addr(peer, &public),
            "8.8.8.8:1234".parse().unwrap()
        );
        assert_eq!(
            trusted.client_addr_from_headers(peer, &public.headers),
            "8.8.8.8:1234".parse().unwrap()
        );

        let internal = load_text(
            "RemoteIPHeader X-Forwarded-For\nRemoteIPInternalProxy 127.0.0.1\n",
            false,
        )
        .unwrap();
        assert!(internal.remoteip_proxies[0].internal);
        let mut private = test_request("GET");
        private
            .headers
            .insert("x-forwarded-for", b"10.1.2.3".to_vec());
        assert_eq!(
            internal.client_addr(peer, &private),
            "10.1.2.3:1234".parse().unwrap()
        );

        let errors = load_text("RemoteIPTrustedProxy not-an-address\n", false).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.msg.contains("bad RemoteIPTrustedProxy address")));
    }

    #[test]
    fn remoteip_private_classifier_pins_apache_2469_ranges() {
        for private in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "::1",
            "fc00::1",
        ] {
            assert!(!Config::remoteip_candidate_is_public(
                private.parse().unwrap()
            ));
        }
        for public in ["8.8.8.8", "172.32.0.1", "100.64.0.1", "2001:db8::1"] {
            assert!(Config::remoteip_candidate_is_public(
                public.parse().unwrap()
            ));
        }
    }

    fn parser_state(root: &Path) -> ParserState {
        ParserState {
            events: Vec::new(),
            section_stack: Vec::new(),
            modules: HashSet::new(),
            module_names: HashSet::new(),
            defines: HashMap::new(),
            env: HashMap::new(),
            depth: 0,
            warnings: Vec::new(),
            errors: Vec::new(),
            initial_server_root: root.to_path_buf(),
            server_root: root.to_path_buf(),
            include_count: 0,
            config_bytes: 0,
            admin_file_trust: crate::files::AdminFileTrust::for_current_process(),
            admin_service_uid: None,
            admin_input_targets: Vec::new(),
        }
    }

    #[test]
    fn configuration_inputs_enforce_per_file_and_aggregate_limits() {
        let root =
            std::env::temp_dir().join(format!("vapache-config-limits-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let oversized = root.join("oversized.conf");
        std::fs::write(&oversized, vec![b'#'; MAX_CONFIG_FILE_BYTES as usize + 1]).unwrap();
        let mut parser = parser_state(&root);
        parser.parse_file(&oversized, true);
        assert!(parser
            .errors
            .iter()
            .any(|error| error.msg.contains("could not open config file")));

        let small = root.join("small.conf");
        std::fs::write(&small, b"Listen 127.0.0.1:8080\n").unwrap();
        let mut parser = parser_state(&root);
        parser.config_bytes = MAX_CONFIG_TOTAL_BYTES;
        parser.parse_file(&small, true);
        assert!(parser
            .errors
            .iter()
            .any(|error| error.msg.contains("aggregate configuration exceeds")));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn coverage_parser_state_and_sections() {
        let root =
            std::env::temp_dir().join(format!("vapache-parser-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let loc = SourceLoc {
            file: "test.conf".into(),
            line: 1,
        };
        let mut p = parser_state(&root);
        p.defines.insert("A".into(), "one".into());
        p.env.insert("E".into(), "two".into());
        p.warn("first");
        assert_eq!(p.warnings, vec!["first"]);
        assert_eq!(
            p.expand_vars(&["${A}-${E}-${map:key}".into()], &loc),
            Some(vec!["one-two-${map:key}".into()])
        );
        assert_eq!(
            p.expand_vars(&["$plain".into()], &loc),
            Some(vec!["$plain".into()])
        );
        assert!(p.expand_vars(&["${MISSING}".into()], &loc).is_none());
        p.warnings.clear();
        assert_eq!(p.errors.len(), 1);
        assert!(p.errors[0].msg.contains("not defined"));
        p.errors.clear();
        assert!(p.expand_vars(&["${unterminated".into()], &loc).is_none());
        assert!(p.errors[0].msg.contains("unterminated"));
        p.errors.clear();

        p.defines.insert("D".into(), String::new());
        p.modules.insert("mod_test.c".into());
        p.module_names.insert(norm_module("mod_test.c"));
        assert!(p.eval_condition("ifdefine", &["D".into()], &loc));
        assert!(!p.eval_condition("ifdefine", &["!D".into()], &loc));
        assert!(p.eval_condition("ifdefine", &["!NOPE".into()], &loc));
        assert!(p.eval_condition("ifmodule", &["test_module".into()], &loc));
        assert!(!p.eval_condition("ifmodule", &["!test_module".into()], &loc));
        assert!(p.eval_condition("ifmodule", &["!other".into()], &loc));
        assert!(p.eval_condition("if", &[], &loc));
        assert!(!p.eval_condition("iffile", &[], &loc));
        assert!(p
            .errors
            .iter()
            .any(|error| error.msg.contains("<iffile> requires an argument")));
        p.errors.clear();
        assert!(p.eval_condition("unknown", &[], &loc));

        assert!(p.active());
        p.section_stack.push(("ifmodule".into(), false, true));
        assert!(!p.active());
        p.section_stack.clear();

        p.include_count = 10_001;
        p.include_pattern("none", false, &loc);
        assert!(p.errors.iter().any(|e| e.msg.contains("too many included")));
        p.include_count = 0;
        p.errors.clear();

        std::fs::write(root.join("one.conf"), "ServerName one\n").unwrap();
        std::fs::write(root.join("two.conf"), "ServerName two\n").unwrap();
        std::fs::create_dir_all(root.join("incdir")).unwrap();
        std::fs::write(root.join("incdir/a.conf"), "ServerName a\n").unwrap();
        std::fs::write(root.join("incdir/b.conf"), "ServerName b\n").unwrap();
        p.include_pattern("one.conf", false, &loc);
        assert_eq!(p.include_count, 1);
        p.include_pattern("missing*.conf", true, &loc);
        assert_eq!(p.include_count, 1);
        p.include_pattern("missing*.conf", false, &loc);
        assert!(p
            .errors
            .iter()
            .any(|e| e.msg.contains("Include file not found")));
        p.errors.clear();
        p.include_pattern(&root.join("*.conf").to_string_lossy(), false, &loc);
        assert_eq!(p.include_count, 3);
        p.include_pattern(&root.join("incdir").to_string_lossy(), false, &loc);
        assert_eq!(p.include_count, 5);
        let saved_root = p.server_root.clone();
        p.server_root = PathBuf::new();
        p.include_pattern("*.vapache-none", true, &loc);
        p.include_pattern(&root.join("incdir").to_string_lossy(), true, &loc);
        p.server_root = saved_root;
        p.depth = 33;
        p.parse_file(&root.join("one.conf"), true);
        assert!(p.errors.iter().any(|e| e.msg.contains("nesting too deep")));
        p.depth = 0;
        p.errors.clear();
        p.parse_file(&root.join("missing.conf"), true);
        assert!(p.errors.iter().any(|e| e.msg.contains("could not open")));
        p.errors.clear();
        p.parse_file(&root.join("missing.conf"), false);
        assert!(p.errors.is_empty());
        std::fs::write(
            root.join("broken.conf"),
            "Options \"unterminated\n<Directory /x>\n</Files>\n</Nope>\n",
        )
        .unwrap();
        p.parse_file(&root.join("broken.conf"), true);
        assert!(!p.errors.is_empty());
        let _ = std::fs::remove_dir_all(&root);

        let cfg = "ServerName default.test\n";
        let c = load_text(cfg, false).unwrap();
        assert_eq!(c.listeners[0].port, 80);
        assert!(load_text("<Directory /x>\nOptions Indexes\n", false).is_err());
        assert!(load_text("</Directory>\n", false).is_err());
        assert!(load_text("<Directory /x>\n</Files>\n", false).is_err());
        assert!(load_text("<VirtualHost>\n</VirtualHost>\n", false).is_err());
        assert!(load_text("Define\n", false).is_err());
        assert!(load_text("LoadModule\n", false).is_err());
        assert!(load_text("Include\n", false).is_err());
        assert!(load_text("IncludeOptional\n", false).is_err());
        assert!(load_text("<IfModule foo>>\n</IfModule>\n", false).is_err());
        assert!(load_text(
            "<IfDefine NOPE>\n<Directory /x>\nServerName hidden\n</Directory>\n</IfDefine>\n",
            false
        )
        .is_ok());
        assert!(load_text(
            "<Location>\n<Directory /nested>\nRequire all granted\n</Directory>\n</Location>\n",
            false
        )
        .is_err());
        assert!(load_text(
            "<If \"%{NOSUCHVAR} == 'x'\">\nRequire all granted\n</If>\n",
            false
        )
        .is_err());
        let unsupported_expr = load_text(
            "<Directory /srv>\nRequire expr \"%{NOSUCHVAR} == 'x'\"\n</Directory>\n",
            false,
        )
        .unwrap_err();
        assert!(format!("{:?}", unsupported_expr).contains("bad Require expr"));
        assert!(load_text("Include /definitely/missing.conf\n", false).is_err());
        assert!(load_text("IncludeOptional /definitely/missing.conf\n", false).is_ok());
        assert!(load_text("<IfDefine !NOPE>\nServerName x\n</IfDefine>\n", false).is_ok());
        assert!(load_text(
            "LoadModule test_module /x.so\n<IfModule test_module>\nServerName x\n</IfModule>\n",
            false
        )
        .is_ok());
        assert!(load_text(
            "Define X\n<IfDefine !X>\nServerName x\n</IfDefine>\n",
            false
        )
        .is_ok());
    }

    #[test]
    fn empty_optional_include_parent_is_part_of_the_trust_manifest() {
        let root = std::env::temp_dir().join(format!(
            "vapache-config-empty-include-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("includes")).unwrap();
        let conf = root.join("httpd.conf");
        std::fs::write(
            &conf,
            format!(
                "Listen 127.0.0.1:0\nIncludeOptional {}/*.conf\n",
                root.join("includes").display()
            ),
        )
        .unwrap();
        let cfg = Config::load(&conf, &root, &HashMap::new(), &HashMap::new(), false).unwrap();
        assert!(cfg
            .admin_input_targets
            .contains(&root.join("includes/*.conf")));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reload_rejects_startup_only_directive_changes() {
        let cfg = load_text(
            "Listen 127.0.0.1:8080\nUser nobody\nGroup nogroup\nPidFile /tmp/old.pid\n",
            false,
        )
        .unwrap();
        let mut changed = cfg.clone();
        changed.user = "other".into();
        changed.group = "other".into();
        changed.pid_file = "/tmp/new.pid".into();
        changed.server_root = "/different".into();
        changed.listen_backlog += 1;
        changed.listeners[0].port = 8081;
        let error = changed.validate_reload_from(&cfg).unwrap_err();
        for directive in [
            "User",
            "Group",
            "PidFile",
            "ServerRoot",
            "ListenBacklog",
            "Listen",
        ] {
            assert!(error.contains(directive), "{error}");
        }
        assert!(cfg.validate_reload_from(&cfg).is_ok());
    }

    #[test]
    fn coverage_glob_and_section_helpers() {
        assert!(glob_match(b"[a-z]x", b"bx"));
        assert!(!glob_match(b"[abc]x", b"dx"));
        assert!(!glob_match(b"[abc]", b""));
        assert!(glob_match(b"[abc", b"[abc"));
        assert!(!glob_match(b"*x", b"abc"));
        assert!(glob_match(b"*", b""));
        assert_eq!(
            section_kind_model(SectionKind::Require),
            vapache_verified::ConfigSectionKind::Require
        );
        assert_eq!(
            section_kind_model(SectionKind::Conditional),
            vapache_verified::ConfigSectionKind::Conditional
        );
        for section in [
            SectionKind::Server,
            SectionKind::VirtualHost,
            SectionKind::Directory,
            SectionKind::DirectoryMatch,
            SectionKind::Location,
            SectionKind::Files,
            SectionKind::Proxy,
            SectionKind::Require,
            SectionKind::Conditional,
        ] {
            let expected = matches!(
                section,
                SectionKind::Directory
                    | SectionKind::DirectoryMatch
                    | SectionKind::Location
                    | SectionKind::Files
                    | SectionKind::Proxy
                    | SectionKind::Conditional
                    | SectionKind::Require
            );
            assert_eq!(authz_section_allowed(section), expected);
        }
        for category in [
            OverrideCategory::AuthConfig,
            OverrideCategory::FileInfo,
            OverrideCategory::Indexes,
            OverrideCategory::Limit,
            OverrideCategory::Options,
            OverrideCategory::ExecCgi,
            OverrideCategory::Includes,
            OverrideCategory::IncludesNoExec,
            OverrideCategory::LanguagePriority,
        ] {
            let _ = category.flag();
            assert!(OverrideMode::All.allows(category));
        }
        assert!(OverrideMode::All.allows_flag(OverrideCategories::AUTH_CONFIG));
    }

    #[test]
    fn coverage_parse_helper_edges() {
        // Unparsable entries are reported instead of silently dropped; the
        // codes still parse through.
        assert_eq!(
            parse_status_list("200, 404,no, 503"),
            (vec![200, 404, 503], vec!["no".to_string()])
        );
        assert_eq!(parse_status_list("500,,404"), (vec![500, 404], Vec::new()));
        assert_eq!(
            parse_request_read_timeout("header=10-20, body=30-40 MinRate=99"),
            Some((
                Some(Duration::from_secs(20)),
                Some(Duration::from_secs(40)),
                Some(99),
                Some(99)
            ))
        );
        assert_eq!(
            parse_request_read_timeout("header=5 MinRate=7 body=6 MinRate=8"),
            Some((
                Some(Duration::from_secs(5)),
                Some(Duration::from_secs(6)),
                Some(7),
                Some(8)
            ))
        );
        assert_eq!(
            parse_request_read_timeout("header=5 body=6"),
            Some((
                Some(Duration::from_secs(5)),
                Some(Duration::from_secs(6)),
                None,
                None
            ))
        );
        assert_eq!(parse_request_read_timeout("header=x body=y"), None);
        assert_eq!(parse_request_read_timeout("none"), None);
        assert_eq!(parse_duration("5ms"), Some(Duration::from_millis(5)));
        assert_eq!(parse_duration("5s"), Some(Duration::from_secs(5)));
        assert_eq!(parse_duration("2m"), Some(Duration::from_secs(120)));
        assert_eq!(parse_duration("7"), Some(Duration::from_secs(7)));
        assert_eq!(parse_duration("bad"), None);
        assert_eq!(parse_u32_arg(&["12".into()]), Some(12));
        assert_eq!(parse_u32_arg(&["bad".into()]), None);
        assert_eq!(parse_u32_arg(&[]), None);

        assert_eq!(clean_path(Path::new("/a/./b/../c")), PathBuf::from("/a/c"));
        assert_eq!(clean_path(Path::new("")), PathBuf::from("."));
        assert_eq!(clean_path(Path::new("./")), PathBuf::from("."));

        assert!(parse_allow_methods(&[]).is_err());
        assert_eq!(
            parse_allow_methods(&["reset".into()]).unwrap(),
            AllowMethods::Reset
        );
        assert!(parse_allow_methods(&["reset".into(), "GET".into()]).is_err());
        assert!(parse_allow_methods(&["BAD METHOD".into()]).is_err());
        assert!(parse_allow_methods(&["UNKNOWN".into()]).is_err());
        assert_eq!(
            parse_allow_methods(&["GET".into(), "GET".into(), "POST".into()]).unwrap(),
            AllowMethods::Only(vec!["GET".into(), "POST".into()])
        );

        assert!(compile_files_pattern(&[]).is_err());
        assert!(matches!(
            compile_files_pattern(&["~".into(), "^index".into()]).unwrap(),
            MatchKind::FilesMatch(_)
        ));
        assert!(compile_files_pattern(&["*.php".into()]).is_ok());
        assert!(compile_files_pattern(&["[!a]?.txt".into()]).is_ok());
        assert!(compile_files_pattern(&["[abc".into()]).is_ok());
        assert!(compile_files_pattern(&["trailing\\".into()]).is_ok());
        assert!(compile_files_pattern(&["^abc".into()]).is_ok());
        assert!(compile_files_pattern(&["[^abc].txt".into()]).is_ok());
        assert!(compile_files_pattern(&["a\\\\*b".into()]).is_ok());

        assert!(parse_method_set_args("limit", &[], false).is_err());
        assert!(parse_method_set_args("limit", &["BAD METHOD".into()], false).is_err());
        assert!(parse_method_set_args("limit", &["TRACE".into()], false).is_err());
        assert!(parse_method_set_args("limitexcept", &["UNKNOWN".into()], true).is_err());
        assert_eq!(
            parse_method_set_args("limit", &["GET".into(), "HEAD".into(), "GET".into()], false)
                .unwrap(),
            MethodSet::Only(vec!["GET".into()])
        );
        assert_eq!(
            parse_method_set_args("limitexcept", &["GET".into()], false).unwrap(),
            MethodSet::Except(vec!["GET".into()])
        );

        assert!(matches!(parse_require(&[]), Require::Unsupported(_)));
        assert!(matches!(
            parse_require(&["not".into()]),
            Require::Unsupported(_)
        ));
        assert!(matches!(
            parse_require(&["all".into(), "maybe".into()]),
            Require::Unsupported(_)
        ));
        assert!(matches!(
            parse_require(&["ip".into()]),
            Require::Unsupported(_)
        ));
        assert!(matches!(
            parse_require(&["ip".into(), "bad".into()]),
            Require::Unsupported(_)
        ));
        assert!(matches!(
            parse_require(&["method".into()]),
            Require::Unsupported(_)
        ));
        assert!(matches!(
            parse_require(&["method".into(), "NOPE".into()]),
            Require::Unsupported(_)
        ));
        assert!(matches!(
            parse_require(&["env".into()]),
            Require::Unsupported(_)
        ));
        assert!(matches!(
            parse_require(&["env".into(), "=x".into()]),
            Require::Unsupported(_)
        ));
        assert!(matches!(
            parse_require(&["env".into(), "".into()]),
            Require::Unsupported(_)
        ));
        assert!(matches!(
            parse_require(&["expr".into(), "(".into()]),
            Require::Unsupported(_)
        ));
        for provider in ["dbm", "dbd", "ldap", "file"] {
            assert!(matches!(
                parse_require(&[provider.into()]),
                Require::Unsupported(_)
            ));
        }
        assert!(matches!(
            parse_require(&["unknown".into()]),
            Require::Unsupported(_)
        ));
        assert!(matches!(
            parse_require(&["all".into(), "denied".into()]),
            Require::AllDenied
        ));
        assert!(matches!(
            parse_require(&["host".into(), "example.test".into()]),
            Require::Host { names, .. } if names == vec!["example.test".to_string()]
        ));
        assert!(matches!(
            parse_require(&["valid-user".into()]),
            Require::ValidUser { negate: false }
        ));
        assert!(matches!(
            parse_require(&["user".into(), "a".into()]),
            Require::User { names, .. } if names == vec!["a".to_string()]
        ));
        assert!(matches!(
            parse_require(&["group".into(), "g".into()]),
            Require::Group { names, .. } if names == vec!["g".to_string()]
        ));

        assert!(
            parse_rewrite_flags(&[
                "L".into(),
                "END".into(),
                "QSA,NC".into(),
                "NE".into(),
                "PT".into(),
                "P".into(),
                "C".into(),
                "N".into()
            ])
            .unwrap()
            .last
        );
        assert!(parse_rewrite_flags(&[
            "QSD".into(),
            "QSL".into(),
            "UNSAFEALLOW3F".into(),
            "B".into(),
            "BNE".into(),
            "BNP".into(),
            "BCTLS".into(),
            "UNSAFEPREFIXSTAT".into(),
            "F".into(),
            "G".into()
        ])
        .is_ok());
        assert!(parse_rewrite_flags(&["DPI".into()]).is_err());
        assert!(parse_rewrite_flags(&["NS".into()]).is_err());
        assert_eq!(
            parse_rewrite_flags(&["R".into()]).unwrap().redirect,
            Some(302)
        );
        for code in ["R=301", "R=PERMANENT", "R=TEMP", "R=SEEOTHER", "R=399"] {
            assert!(parse_rewrite_flags(&[code.into()]).is_ok(), "{code}");
        }
        assert!(parse_rewrite_flags(&["R=bad".into()]).is_err());
        assert!(parse_rewrite_flags(&["R=200".into()]).is_err());
        let custom = parse_rewrite_flags(&["B= !".into(), "BNE=&".into()]).unwrap();
        assert!(custom.escape_backrefs);
        assert_eq!(custom.escape_chars, " !");
        assert_eq!(custom.noescape_chars, "&");
        let env = parse_rewrite_flags(&[
            "E=SET:value".into(),
            "E=EMPTY".into(),
            "E=!DROP".into(),
            "CO=name:value".into(),
            "H=handler".into(),
            "T=text/plain".into(),
            "S=2".into(),
        ])
        .unwrap();
        assert_eq!(env.env.len(), 3);
        assert_eq!(env.env[0], ("SET".into(), Some("value".into())));
        assert_eq!(env.env[1], ("EMPTY".into(), Some(String::new())));
        assert_eq!(env.env[2], ("DROP".into(), None));
        assert_eq!(env.cookies, vec!["name:value"]);
        assert_eq!(env.handler.as_deref(), Some("handler"));
        assert_eq!(env.content_type.as_deref(), Some("text/plain"));
        assert_eq!(env.skip, Some(2));
        assert!(parse_rewrite_flags(&["S=bad".into()]).is_err());
        assert!(parse_rewrite_flags(&["NOPE".into()]).is_err());
        assert!(parse_rewrite_flags(&["".into(), ",".into()]).is_ok());

        assert!(parse_rewrite_cond(&["%{LA-REQUEST}".into()]).is_err());
        assert!(parse_rewrite_cond(&["expr".into(), "true".into(), "[NC,OR]".into()]).is_ok());
        assert!(parse_rewrite_cond(&["expr".into(), "true".into(), "[BAD]".into()]).is_err());
        assert!(parse_rewrite_cond(&["expr".into()]).is_err());
        assert!(parse_rewrite_cond(&["only".into()]).is_err());
        assert!(parse_rewrite_cond(&["x".into(), "^a$".into(), "[NC,AND,,]".into()]).is_ok());
        assert!(parse_rewrite_cond(&["x".into(), "^a$".into(), "[BAD]".into()]).is_err());
        assert!(parse_rewrite_cond(&["x".into(), "%{HTTP_HOST}".into()]).is_err());
        assert!(parse_rewrite_cond(&["x".into(), "(".into()]).is_err());
        assert!(parse_rewrite_cond(&["x".into(), "-f".into()])
            .unwrap()
            .regex
            .is_none());
        assert!(parse_rewrite_cond(&["x".into(), "!-d".into()])
            .unwrap()
            .regex
            .is_none());
        assert!(parse_rewrite_cond(&["x".into(), "=abc".into()])
            .unwrap()
            .regex
            .is_none());

        assert!(parse_rewrite_rule(&["only".into()], "/", false).is_err());
        assert!(parse_rewrite_rule(&["%{LA-REQUEST}".into(), "/x".into()], "/", false).is_err());
        assert!(
            parse_rewrite_rule(&["^/x$".into(), "$1".into(), "[P]".into()], "/", false).is_err()
        );
        assert!(parse_rewrite_rule(&["%{HTTP_HOST}".into(), "/x".into()], "/", false).is_err());
        let negated =
            parse_rewrite_rule(&["!^/x$".into(), "/y".into(), "[NC]".into()], "base", true)
                .unwrap();
        assert!(negated.negated);
        assert_eq!(negated.base, "/base/");
        assert_eq!(negated.match_base, "/base/");

        assert_eq!(normalize_rewrite_base(""), "/");
        assert_eq!(normalize_rewrite_base("x"), "/x/");
        assert_eq!(normalize_rewrite_base("/x"), "/x/");

        assert_eq!(
            parse_ip_net("10.0.0.1"),
            Some(("10.0.0.1".parse().unwrap(), 32))
        );
        assert_eq!(
            parse_ip_net("2001:db8::1"),
            Some(("2001:db8::1".parse().unwrap(), 128))
        );
        assert_eq!(parse_ip_net("10.0.0.0/33"), None);
        assert_eq!(parse_ip_net("bad"), None);
        assert_eq!(parse_ip_net("10.0.0.0/bad"), None);

        assert!(parse_listen("").is_err());
        assert_eq!(parse_listen("[::1]").unwrap().port, 80);
        assert_eq!(parse_listen("::1").unwrap().addr, "::1");
        assert_eq!(parse_listen("::1").unwrap().port, 80);
        assert_eq!(parse_listen("*:8080").unwrap().addr, "0.0.0.0");
        assert_eq!(parse_listen(":8080").unwrap().addr, "0.0.0.0");
        assert!(parse_listen("127.0.0.1:bad").is_err());
        assert!(parse_listen("[::1").is_err());

        assert!(proxy_template_authority_safe("http://backend"));
        assert!(!proxy_template_authority_safe("http://$1/"));
        assert!(!proxy_template_authority_safe("http://\\1/"));
        assert!(!proxy_template_authority_safe("http://%1/"));
        assert!(!proxy_template_authority_safe("http://backend@host/"));
        assert!(!proxy_template_authority_safe("http:///path"));
        assert!(!proxy_template_authority_safe("$1"));
        assert!(!proxy_template_authority_safe("\\1"));
        assert!(!proxy_template_authority_safe("%1"));
        assert!(!proxy_template_authority_safe("%{HTTP_HOST}"));
        assert!(proxy_template_authority_safe("http://backend/$1"));
        assert!(proxy_template_authority_safe("/unix/socket"));
        assert!(supported_proxy_backend("https://x", false));
        assert!(supported_proxy_backend("ws://x", false));
        assert!(supported_proxy_backend("wss://x", false));
        assert!(supported_proxy_backend("balancer://x", false));
        assert!(supported_proxy_backend("unix:/x", true));
        assert!(!supported_proxy_backend("unix:/x", false));
        assert!(!supported_proxy_backend("ftp://x", false));
        assert!(is_security_directive("sslverifyclient"));
        assert!(is_security_directive("proxypass"));
        assert!(is_security_directive("requestheader"));
        assert!(!is_security_directive("servername"));
    }

    #[test]
    fn coverage_directive_matrix() {
        let dir = std::env::temp_dir().join(format!("vapache-directives-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("mime.types"),
            "text/html html htm\ntext/plain txt\n",
        )
        .unwrap();
        std::fs::write(dir.join("types.txt"), "one value\n# skip\nbadline\n").unwrap();
        std::fs::write(dir.join("rnd.txt"), "key one|two\nempty |\n").unwrap();
        let mime = dir.join("mime.types").to_string_lossy().to_string();
        let types = dir.join("types.txt").to_string_lossy().to_string();
        let rnd = dir.join("rnd.txt").to_string_lossy().to_string();
        let cache = dir.join("cache");
        let cache = cache.to_string_lossy().to_string();
        let cert = dir.join("cert.pem").to_string_lossy().to_string();
        let key = dir.join("key.pem").to_string_lossy().to_string();
        let chain = dir.join("chain.pem").to_string_lossy().to_string();

        let cfg = format!(
            "Listen 127.0.0.1:0\n\
ServerName www.example.test\n\
ServerAdmin admin@example.test\n\
DocumentRoot /srv/www\n\
DirectoryIndex index.php index.html\n\
IndexIgnore .git .svn\n\
Options Indexes FollowSymLinks SymLinksIfOwnerMatch Includes IncludesNoExec MultiViews +ExecCGI -Indexes +All -All None\n\
Timeout 30\n\
KeepAlive On\n\
KeepAliveTimeout 5\n\
MaxKeepAliveRequests 10\n\
HostnameLookups On\n\
UseCanonicalName DNS\n\
ServerTokens Prod\n\
ServerSignature Email\n\
TraceEnable Off\n\
LimitRequestLine 1000\n\
LimitRequestFields 20\n\
LimitRequestFieldSize 500\n\
MaxRequestWorkers 8\n\
ServerLimit 9\n\
ListenBacklog 5\n\
GracefulShutdownTimeout 2\n\
RequestReadTimeout header=10-20,MinRate=5 body=20-30,MinRate=6\n\
LimitRequestBody 1234\n\
AllowEncodedSlashes NoDecode\n\
LogLevel debug\n\
LogFormat \"%h\" combined\n\
CustomLog logs/access.log combined\n\
SetEnv FOO \"bar baz\"\n\
UnsetEnv OLD\n\
PassEnv PATH\n\
RemoteIPHeader X-Forwarded-For\n\
RemoteIPInternalProxy all 10.0.0.0/8 192.0.2.1 2001:db8::1\n\
TypesConfig {mime}\n\
AddType text/x-test .tst\n\
RemoveType .tst\n\
AddEncoding gzip .gz\n\
FileETag MTime Size\n\
EnableSendfile Off\n\
DirectorySlash Off\n\
AccessFileName .htaccess .acl\n\
AddDefaultCharset UTF-8\n\
ForceType text/plain\n\
CacheRoot {cache}\n\
CacheDefaultExpire 10\n\
CacheMaxExpire 20\n\
CacheMinExpire 1\n\
CacheMaxFileSize 100\n\
CacheMinSize 2\n\
CacheMaxDiskSize 1024\n\
CacheMaxMemorySize 512\n\
CacheIgnoreNoLastMod On\n\
CacheIgnoreCacheControl On\n\
CacheStoreNoStore On\n\
CacheStorePrivate On\n\
CacheIgnoreQueryString On\n\
CacheHeader On\n\
CacheDetailHeader On\n\
CacheLastModifiedFactor 0.5\n\
CacheEnable disk /\n\
CacheDisable /admin\n\
SetOutputFilter DEFLATE BROTLI_COMPRESS\n\
AddOutputFilter DEFLATE .html .css\n\
AddOutputFilterByType DEFLATE text/html\n\
SetInputFilter INCLUDES\n\
AddInputFilter INCLUDES .shtml\n\
DeflateCompressionLevel 9\n\
BrotliCompressionQuality 11\n\
DeflateAlterETag AddSuffix\n\
BrotliAlterETag Remove\n\
BrotliCompressionAlterETag NoChange\n\
ProxyHCTemplate health hcmethod=GET hcuri=/health hcinterval=5s hcpasses=2 hcfails=3\n\
ProxyPass /p http://127.0.0.1:9000 stickysession=JSESSIONID failonstatus=500,502\n\
ProxyPassReverse /p http://127.0.0.1:9000\n\
ProxyPassMatch ^/m/(.*)$ http://127.0.0.1:9000/$1\n\
SSLEngine On\n\
SSLCertificateFile {cert}\n\
SSLCertificateKeyFile {key}\n\
SSLCertificateChainFile {chain}\n\
SSLProtocol all -SSLv3\n\
SSLUseStapling On\n\
SSLStaplingForceURL http://example.test/ocsp\n\
SSLStaplingResponderTimeout 5\n\
SSLStaplingStandardCacheTimeout 10\n\
SSLStaplingReturnResponderErrors On\n\
SSLVerifyClient optional\n\
SSLCACertificateFile {cert}\n\
SSLCARevocationFile {chain}\n\
SSLCARevocationCheck leaf\n\
SSLProxyCACertificateFile {cert}\n\
RewriteEngine On\n\
RewriteBase /base\n\
RewriteMap txtmap txt:{types}\n\
RewriteMap rndmap rnd:{rnd}\n\
RewriteMap prgmap prg:/bin/cat\n\
RewriteMap intmap int:toupper\n\
RewriteCond %{{REQUEST_URI}} ^/old [NC]\n\
RewriteRule ^/old$ /new [L,QSA]\n\
RewriteOptions Inherit\n"
        );
        let c = load_text(&cfg, false).unwrap();
        assert_eq!(c.server_name.as_deref(), Some("www.example.test"));
        assert_eq!(c.server_admin, "admin@example.test");
        assert_eq!(c.server_tokens, ServerTokens::Prod);
        assert_eq!(c.server_software, "vapache");
        assert_eq!(c.server_signature, ServerSignature::Email);
        assert!(!c.trace_enable);
        assert_eq!(c.limit_request_line, 1000);
        assert_eq!(c.limit_request_fields, 20);
        assert_eq!(c.limit_request_field_size, 500);
        assert_eq!(c.limit_request_body, 1234);
        assert_eq!(c.max_request_workers, 8);
        assert_eq!(c.listen_backlog, 5);
        assert_eq!(c.graceful_shutdown_timeout, Duration::from_secs(2));
        assert_eq!(c.request_header_min_rate, 5);
        assert_eq!(c.request_body_min_rate, 6);
        assert_eq!(c.encoded_slashes, EncodedSlashes::NoDecode);
        assert_eq!(c.cache.max_expire, 20);
        assert_eq!(c.cache.min_expire, 1);
        assert_eq!(c.cache.max_file_size, 100);
        assert_eq!(c.cache.min_file_size, 2);
        assert_eq!(c.cache.max_disk_size, 1024);
        assert_eq!(c.cache.max_memory_size, 512);
        assert!(c.cache.ignore_no_last_mod);
        assert!(c.cache.ignore_cache_control);
        assert!(c.cache.store_no_store);
        assert!(c.cache.store_private);
        assert!(c.cache.ignore_query_string);
        assert!(c.cache.header);
        assert!(c.cache.detail_header);
        assert_eq!(c.cache.last_modified_factor, 0.5);
        assert_eq!(c.remoteip_proxies.len(), 4);
        assert!(c.remoteip_proxies.iter().all(|proxy| proxy.internal));
        assert_eq!(c.remoteip_header.as_deref(), Some("X-Forwarded-For"));
        assert_eq!(c.mime.content_type(b"x.html").as_deref(), Some("text/html"));
        assert_eq!(c.mime.encodings.get("gz").map(String::as_str), Some("gzip"));
        assert_eq!(c.health_templates["health"].method.as_deref(), Some("GET"));
        let s = c.effective_scope(None, Path::new("/srv/www/file"), "/file");
        assert_eq!(s.rewrite_policy.rewrite_rules.len(), 1);
        assert_eq!(s.rewrite_policy.rewrite_maps.len(), 4);
        assert_eq!(s.proxy_policy.proxy_passes.len(), 1);
        assert_eq!(s.proxy_policy.proxy_rules.len(), 1);
        assert_eq!(s.proxy_policy.proxy_reverses.len(), 1);
        assert_eq!(s.compression_policy.compression_rules.len(), 3);
        assert_eq!(s.compression_policy.deflate_level, Some(9));
        assert_eq!(s.compression_policy.brotli_quality, Some(11));
        assert_eq!(
            s.compression_policy.deflate_alter_etag,
            Some(AlterEtag::AddSuffix)
        );
        assert_eq!(
            s.compression_policy.brotli_alter_etag,
            Some(AlterEtag::NoChange)
        );
        assert!(s
            .mapping_policy
            .unsupported_filters
            .iter()
            .any(|f| f == "INCLUDES"));
        assert_eq!(s.content_policy.force_type.as_deref(), Some("text/plain"));
        assert_eq!(s.content_policy.default_charset.as_deref(), Some("UTF-8"));
        assert_eq!(s.content_policy.file_etag, Some(ETAG_MTIME | ETAG_SIZE));
        assert_eq!(s.content_policy.enable_sendfile, Some(false));
        assert_eq!(s.content_policy.directory_slash, Some(false));
        assert_eq!(
            s.content_policy.access_file_names.as_ref().unwrap().len(),
            2
        );
        assert_eq!(c.ssl.verify_client, Some(ClientVerify::Optional));
        assert_eq!(c.ssl.ca_revocation_file.as_deref(), Some(Path::new(&chain)));
        assert_eq!(c.ssl.ca_revocation_check, Some(ClientRevocationCheck::Leaf));
        assert!(c.ssl.engine);
        assert!(c.ssl.stapling);
        assert_eq!(c.ssl.stapling_responder_timeout, Duration::from_secs(5));
        assert_eq!(
            c.ssl.stapling_standard_cache_timeout,
            Duration::from_secs(10)
        );
        assert!(c.ssl.stapling_return_responder_errors);

        let directory = format!(
            "<Directory /srv/www>\n\
Options None\n\
AllowOverride All\n\
AllowOverrideList None\n\
DirectoryIndex index.php\n\
Require all granted\n\
Order deny,allow\n\
Allow from all 10.0.0.0/8\n\
Deny from 10.1.0.0/16\n\
Satisfy any\n\
AllowMethods GET HEAD POST\n\
AuthMerging And\n\
AuthType Basic\n\
AuthName \"realm\"\n\
AuthUserFile /tmp/passwd\n\
AuthGroupFile /tmp/group\n\
AuthBasicProvider file\n\
AddHandler cgi-script .cgi\n\
RemoveHandler .php\n\
SetHandler handler\n\
AddType text/plain .txt\n\
RemoveType .html\n\
Redirect 301 /old /new\n\
RedirectPermanent /old2 /new2\n\
RedirectTemp /old3 /new3\n\
RedirectMatch 302 ^/rm/(.*)$ /new/$1\n\
ErrorDocument 404 /404.html\n\
ErrorDocument 500 \"text\"\n\
ErrorDocument 502 http://example.test/error\n\
Header always set X-Test v\n\
Header add X-Add v\n\
Header unset X-Remove\n\
Header always unset X-Remove2\n\
ExpiresActive On\n\
ExpiresDefault \"access plus 1 day\"\n\
ExpiresByType text/html \"access plus 1 hour\"\n\
SetEnv DIR yes\n\
</Directory>\n"
        );
        let cfg = format!(
            "Listen 127.0.0.1:0\n\
Alias /alias /srv/alias\n\
ScriptAlias /cgi /srv/cgi\n\
AliasMatch ^/am/(.*)$ /srv/$1\n\
ScriptAliasMatch ^/sam/(.*)$ /srv/cgi/$1\n\
{directory}"
        );
        let c = load_text(&cfg, false).unwrap();
        let s = c.effective_scope(None, Path::new("/srv/www/file"), "/file");
        assert_eq!(s.options.effective_bits(0), 0);
        assert_eq!(s.override_policy.raw_mode(), Some(OverrideMode::All));
        assert!(
            s.authorization.auth_merging.is_none()
                || s.authorization.auth_merging == Some(AuthMerging::And)
        );
        assert_eq!(
            s.authorization.allow_methods,
            Some(AllowMethods::Only(vec![
                "GET".into(),
                "HEAD".into(),
                "POST".into()
            ]))
        );
        assert_eq!(s.authorization.auth_type.as_deref(), Some("basic"));
        assert_eq!(s.authorization.auth_name.as_deref(), Some("realm"));
        assert_eq!(
            s.authorization.auth_user_file.as_deref(),
            Some(Path::new("/tmp/passwd"))
        );
        assert_eq!(
            s.authorization.auth_group_file.as_deref(),
            Some(Path::new("/tmp/group"))
        );
        assert_eq!(s.mapping_policy.handlers.len(), 2);
        // F64/I62: `SetHandler` is a precedence field, not an extension-table
        // entry.
        assert_eq!(
            s.mapping_policy.set_handler,
            Some(SetHandler::Name("handler".into()))
        );
        assert_eq!(s.mapping_policy.aliases.len(), 4);
        assert_eq!(s.mapping_policy.redirects.len(), 4);
        assert_eq!(s.error_policy.documents.len(), 3);
        assert_eq!(s.header_policy.always_set_headers.len(), 1);
        assert_eq!(s.header_policy.add_headers.len(), 1);
        assert_eq!(s.header_policy.unset_headers.len(), 1);
        assert_eq!(s.header_policy.always_unset_headers.len(), 1);
        assert_eq!(s.header_policy.expires_by_type.len(), 1);
        assert_eq!(
            s.header_policy.expires_default.as_deref(),
            Some("access plus 1 day")
        );
        assert!(s.header_policy.expires_active.unwrap());
        assert!(s
            .environment_policy
            .set_env
            .iter()
            .any(|entry| entry.value.0 == "DIR"));

        let vhost = format!(
            "<VirtualHost *:443>\n\
ServerName vhost.test\n\
ServerAdmin vhost@example.test\n\
DocumentRoot /srv/vh\n\
ErrorLog logs/vh-error.log\n\
CustomLog logs/vh-access.log combined\n\
SSLEngine On\n\
SSLCertificateFile {cert}\n\
SSLCertificateKeyFile {key}\n\
SSLCertificateChainFile {chain}\n\
SSLUseStapling On\n\
SSLStaplingForceURL http://example.test/ocsp\n\
SSLStaplingResponderTimeout 4\n\
SSLStaplingStandardCacheTimeout 8\n\
SSLStaplingReturnResponderErrors On\n\
SSLVerifyClient require\n\
SSLCACertificateFile {cert}\n\
SSLCARevocationFile {chain}\n\
SSLCARevocationCheck chain\n\
SSLProtocol all\n\
</VirtualHost>\n\
<VirtualHost *:80>\n\
ServerName plain.test\n\
</VirtualHost>\n"
        );
        let cfg = format!("Listen 127.0.0.1:443 https\n{vhost}");
        let c = load_text(&cfg, false).unwrap();
        let v = c
            .vhosts
            .iter()
            .find(|v| v.server_name.as_deref() == Some("vhost.test"))
            .unwrap();
        assert_eq!(v.server_admin.as_deref(), Some("vhost@example.test"));
        assert!(v.ssl.engine);
        assert_eq!(v.ssl.verify_client, Some(ClientVerify::Require));
        assert_eq!(
            v.ssl.ca_revocation_check,
            Some(ClientRevocationCheck::Chain)
        );
        assert_eq!(v.ssl.stapling_responder_timeout, Duration::from_secs(4));
        assert_eq!(
            v.ssl.stapling_standard_cache_timeout,
            Duration::from_secs(8)
        );
        assert!(v.ssl.stapling_return_responder_errors);
        assert_eq!(v.custom_logs.len(), 1);
        assert_eq!(v.error_log.as_deref(), Some("logs/vh-error.log"));
        let plain = c
            .vhosts
            .iter()
            .find(|v| v.server_name.as_deref() == Some("plain.test"))
            .unwrap();
        assert_eq!(plain.error_log.as_deref(), Some(c.error_log.as_str()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_directive_edge_paths() {
        let dir =
            std::env::temp_dir().join(format!("vapache-directive-edges-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(dir.join("rel")).unwrap();
        std::fs::write(dir.join("mime.types"), "text/html html\n").unwrap();
        std::fs::write(dir.join("types.txt"), "one value\n# skip\nbadline\n").unwrap();
        std::fs::write(
            dir.join("rnd.txt"),
            "key one|two\nempty |\n# skip\nbadline\n",
        )
        .unwrap();
        let relative = dir
            .strip_prefix(std::env::temp_dir())
            .unwrap()
            .to_string_lossy()
            .to_string();

        let cfg = format!(
            "Listen 127.0.0.1:0\n\
Define TEMP 1\n\
Undefine TEMP\n\
DocumentRoot rel/www\n\
Options All\n\
FileETag MTime\n\
TypesConfig {relative}/mime.types\n\
CacheRoot rel/cache\n\
SSLProxyCACertificateFile rel/ca.pem\n\
Alias /rel rel/alias\n\
Redirect /old /new\n\
RedirectMatch ^/rm/(.*)$ /new/$1\n\
RewriteMap reltxt txt:{relative}/types.txt\n\
RewriteMap relrnd rnd:{relative}/rnd.txt\n\
<Directory /srv/edge>\n\
Options All\n\
AllowOverride All Nonfatal=Override\n\
AllowOverride AuthConfig Nonfatal=Unknown\n\
AllowOverride FileInfo Nonfatal=All\n\
AllowOverride Options=FollowSymLinks,Indexes,SymLinksIfOwnerMatch,All,None,ExecCGI,Includes,IncludesNoExec\n\
AllowOverrideList Directive1 Directive2\n\
AuthUserFile rel/passwd\n\
AuthGroupFile rel/group\n\
</Directory>\n\
<Directory rel>\n\
Options None\n\
</Directory>\n\
<Directory /dbm>\n\
Require dbm\n\
</Directory>\n\
<LocationMatch ^/x>\n\
Options None\n\
</LocationMatch>\n\
<Proxy balancer://pool>\n\
BalancerMember http://127.0.0.1:9000 hcmethod=GET hcuri=/health hcinterval=1s hcpasses=1 hcfails=2 template=health route=r1\n\
ProxySet hcmethod=POST hcuri=/health hcinterval=2s hcpasses=2 hcfails=3 stickysession=S stickysessionsep=. failonstatus=500,502\n\
</Proxy>\n\
ProxyPass /extra http://127.0.0.1:9000 stickysession=S\n\
ProxyHCTemplate edge hcmethod=GET hcuri=/health hcinterval=3s hcpasses=4 hcfails=5\n\
DefaultType text/plain\n\
DefaultRuntimeDir /tmp\n\
AllowEncodedSlashes On\n\
AllowEncodedSlashes Off\n\
RemoteIPInternalProxy 192.0.2.5\n\
<Proxy balancer://empty>\n\
</Proxy>\n\
<VirtualHost *:443>\n\
SSLEngine On\n\
SSLCertificateFile rel/cert.pem\n\
SSLCertificateKeyFile rel/key.pem\n\
SSLCACertificateFile rel/ca.pem\n\
SSLCARevocationFile rel/client.crl\n\
SSLCARevocationCheck leaf\n\
<Proxy *>\n\
Require all granted\n\
</Proxy>\n\
</VirtualHost>\n"
        );
        let c = load_text(&cfg, false).unwrap();
        assert_eq!(c.document_root, PathBuf::from("/tmp/rel/www"));
        assert_eq!(c.cache.root.as_deref(), Some(Path::new("/tmp/rel/cache")));
        assert_eq!(c.remoteip_proxies.len(), 1);
        assert_eq!(c.balancers.len(), 2);
        let b = &c.balancers[0];
        assert_eq!(b.members.len(), 1);
        assert_eq!(b.members[0].template.as_deref(), Some("health"));
        assert_eq!(b.members[0].route.as_deref(), Some("r1"));
        assert_eq!(b.health.uri.as_deref(), Some("/health"));
        assert_eq!(b.health.passes, Some(2));
        assert_eq!(b.health.fails, Some(3));
        assert_eq!(b.sticky_cookie.as_deref(), Some("S"));
        assert_eq!(b.sticky_sep.as_deref(), Some("."));
        assert_eq!(b.fail_on_status, vec![500, 502]);
        assert!(c.health_templates.contains_key("edge"));
        let s = c.effective_scope(None, Path::new("/srv/edge/file"), "/file");
        assert_eq!(s.options.effective_bits(0), Options::all().0);
        assert!(s.override_policy.raw_mode().is_some());
        assert_eq!(
            s.authorization.auth_user_file.as_deref(),
            Some(Path::new("/tmp/rel/passwd"))
        );
        assert_eq!(
            s.authorization.auth_group_file.as_deref(),
            Some(Path::new("/tmp/rel/group"))
        );
        assert_eq!(s.rewrite_policy.rewrite_maps.len(), 2);
        assert_eq!(
            s.proxy_policy.proxy_ca_file.as_deref(),
            Some(Path::new("/tmp/rel/ca.pem"))
        );
        assert!(c
            .admin_input_targets
            .contains(&PathBuf::from("/tmp/rel/ca.pem")));
        assert_eq!(
            c.vhosts[0].ssl.cert_file.as_deref(),
            Some(Path::new("/tmp/rel/cert.pem"))
        );
        assert_eq!(
            c.vhosts[0].ssl.ca_revocation_file.as_deref(),
            Some(Path::new("/tmp/rel/client.crl"))
        );
        assert_eq!(
            c.vhosts[0].ssl.ca_revocation_check,
            Some(ClientRevocationCheck::Leaf)
        );

        let full = format!("vapache/{} (Linux)", crate::VERSION);
        let minimal = format!("vapache/{}", crate::VERSION);
        let minor = format!("vapache/{}", version_prefix(2));
        let major = format!("vapache/{}", version_prefix(1));
        let defaults = load_text("Listen 127.0.0.1:0\n", false).unwrap();
        assert_eq!(defaults.server_tokens, ServerTokens::Full);
        assert_eq!(defaults.server_software, full);
        for (value, expected) in [
            ("Full", full.as_str()),
            ("OS", full.as_str()),
            ("Minimal", minimal.as_str()),
            ("Minor", minor.as_str()),
            ("Major", major.as_str()),
            ("Prod", "vapache"),
        ] {
            let cfg = format!("Listen 127.0.0.1:0\nServerTokens {value}\n");
            let c = load_text(&cfg, false).unwrap();
            assert_eq!(c.server_software, expected);
        }
        for value in ["Unknown"] {
            let cfg = format!("Listen 127.0.0.1:0\nServerTokens {value}\n");
            assert!(load_text(&cfg, false).is_err());
        }
        let c = load_text(
            "Listen 127.0.0.1:0\nUseCanonicalName On\nServerSignature Off\n",
            false,
        )
        .unwrap();
        assert!(c.use_canonical_name);
        assert_eq!(c.server_signature, ServerSignature::Off);
        let c = load_text(
            "Listen 127.0.0.1:0\nUseCanonicalName Off\nServerSignature Email\n",
            false,
        )
        .unwrap();
        assert!(!c.use_canonical_name);
        assert_eq!(c.server_signature, ServerSignature::Email);
        let c = load_text("Listen 127.0.0.1:0\nServerSignature On\n", false).unwrap();
        assert_eq!(c.server_signature, ServerSignature::On);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_section_and_directive_errors() {
        let err = |cfg: &str| {
            assert!(load_text(cfg, false).is_err(), "{cfg}");
        };
        err("<RequireAll>\n</RequireAll>\n");
        err("<RequireAll>\nOptions Indexes\n</RequireAll>\n");
        err("<Directory /x>\n<RequireAll>\nOptions Indexes\n</RequireAll>\n</Directory>\n");
        err("<Directory /x>\n<Directory /y>\n</Directory>\n</Directory>\n");
        err("<Directory /x>\n<Limit GET>\n<If true>\n</If>\n</Limit>\n</Directory>\n");
        err("<If (>\n</If>\n");
        err("<If true>\n</If>\n<ElseIf (>\n</ElseIf>\n");
        err("<If true>\n</If>\n<Else foo>\n</Else>\n");
        err("<DirectoryMatch (>\n</DirectoryMatch>\n");
        err("<Files>\n</Files>\n");
        err("<FilesMatch (>\n</FilesMatch>\n");
        err("<LocationMatch (>\n</LocationMatch>\n");
        err("<Directory /x>\n<RequireAll>\n</RequireAll>\n</Directory>\n");
        err("<Directory /x>\n<Limit GET>\n<Limit POST>\n</Limit>\n</Limit>\n</Directory>\n");
        err("<Directory /x>\n<RequireAll>\n<Limit GET>\nRequire all granted\n</Limit>\n</RequireAll>\n</Directory>\n");
        err("<Directory /x>\nDocumentRoot /tmp\n</Directory>\n");
        err("<Directory /x>\nAlias /a /tmp\n</Directory>\n");
        err("<Directory /x>\nProxyPass /p http://127.0.0.1:1/\n</Directory>\n");
        err("<Directory /x>\nCacheEnable disk /\n</Directory>\n");
        err("<Directory /x>\nLimitRequestBody 1\n</Directory>\n");
        err("<VirtualHost *:80>\nLogLevel debug\n</VirtualHost>\n");
        err("<VirtualHost *:80>\nRemoteIPHeader X-Real-IP\n</VirtualHost>\n");
        err("<Proxy>\n</Proxy>\n");
        err("<ProxyMatch (>\n</ProxyMatch>\n");
        err("<Directory /x>\n<Limit GET>\n<Unknown>\n</Unknown>\n</Limit>\n</Directory>\n");
        err("<Directory /x>\n<Limit GET>\n<If true>\n</If>\n</Limit>\n</Directory>\n");
        err("AllowOverride All\n");
        err("<Directory /x>\nAllowOverride\n</Directory>\n");
        err("<Directory /x>\nAllowOverride Nonfatal=bad\n</Directory>\n");
        err("<Directory /x>\nAllowOverride Options=\n</Directory>\n");
        err("<Directory /x>\nAllowOverride Options=Bad\n</Directory>\n");
        err("AllowOverrideList None\n");
        err("<Directory /x>\nAllowOverrideList\n</Directory>\n");
        err("<Directory /x>\nAllowOverrideList None Foo\n</Directory>\n");
        err("<Directory /x>\nRequire all maybe\n</Directory>\n");
        err("<Directory /x>\nRequire nonsense\n</Directory>\n");
        err("<Directory /x>\nOrder sideways\n</Directory>\n");
        err("<Directory /x>\nAllow all\n</Directory>\n");
        err("<Directory /x>\nDeny from host.example\n</Directory>\n");
        err("ErrorDocument nope /x\n");
        err("ErrorDocument 404 /error#fragment\n");
        err("ErrorDocument 404 /bad\\\\path\n");
        err("ErrorDocument 404 \"/error page\"\n");
        err("ErrorDocument 404 /bad%zz\n");
        err("ErrorDocument 404 /bad%0dpath\n");
        err("ErrorDocument 404 /bad%ffpath\n");
        err("DirectoryIndex index%2ehtml\n");
        err("DirectoryIndex index.html?variant=1\n");
        err("DirectoryIndex nested/index.html\n");
        err("<Directory /x>\nAliasMatch ( /x\n</Directory>\n");
        err("<Directory /x>\nAliasMatch onlyone\n</Directory>\n");
        err("<Directory /x>\nRedirectMatch ( /x\n</Directory>\n");
        err("<Directory /x>\nRedirectMatch\n</Directory>\n");
        err("<Directory /x>\nRedirect\n</Directory>\n");
        err("<Directory /x>\nRedirectTemp\n</Directory>\n");
        err("<Directory /x>\nRedirectPermanent\n</Directory>\n");
        err("<Directory /x>\nRewriteMap bad urldb:/tmp/x\n</Directory>\n");
        err("<Directory /x>\nHeader bad X y\n</Directory>\n");
        err("TypesConfig /definitely/missing.types\n");
        err("ProxyPass /x ftp://backend\n");
        err("ProxyPass /x !\n");
        err("ProxyPassReverse /x ftp://backend\n");
        err("ProxyPassMatch ^/x$ !\n");
        err("ProxyPassMatch ^/x$ ftp://backend\n");
        err("ProxyPassMatch ^/x$ http://$1/\n");
        err("ProxyPassMatch ( http://backend/\n");
        err("Listen 127.0.0.1:bad\n");
        err("SetEnvIf Host\n");
        err("SetEnvIf Host ( X=1\n");
        err("RemoteIPInternalProxy bad-address\n");
        err("UseCanonicalName sometimes\n");
        err("<Directory /x>\nSatisfy maybe\n</Directory>\n");
        err("<Directory /x>\nAllowMethods\n</Directory>\n");
        err("AllowMethods GET\n");
        err("<Directory /x>\nAllowMethods BAD\n</Directory>\n");
        err("AuthMerging And\n");
        err("<Directory /x>\nAuthMerging Maybe\n</Directory>\n");
        err("<IfModule \"a>b\">\n</IfModule>\n");
        err("SSLRequireSSL\n");
        err("SSLRequire true\n");
        err("SecRuleEngine On\n");
        err("SSLEngine optional\n");
        err("SSLEngine On extra\n");
        err("SSLCertificateFile\n");
        err("SSLCertificateKeyFile one two\n");
        err("SSLUseStapling maybe\n");
        err("SSLHonorCipherOrder maybe\n");
        err("SSLOptions +StdEnvVars\n");
        err("SSLStaplingForceURL https://example.test/ocsp\n");
        err("SSLStaplingResponderTimeout later\n");
        err("SSLStaplingStandardCacheTimeout 1 2\n");
        err("SSLStaplingReturnResponderErrors maybe\n");
        err("SSLVerifyClient maybe\n");
        err("SSLVerifyClient optional_no_ca\n");
        err("SSLVerifyClient none extra\n");
        err("SSLCACertificateFile\n");
        err("SSLCARevocationFile\n");
        err("SSLCARevocationCheck maybe\n");
        err("SSLProtocol\n");
        err("SSLCipherSuite HIGH\n");
        err("LogLevel ssl:info\n");
        err("DeflateBufferSize 4096\n");
        err("AuthBasicProvider ldap\n");
        err("<Directory /x>\nAuthBasicProvider ldap\n</Directory>\n");
        err("Options\n");
        err("Options +NoSuchOption\n");
        err("FileETag Unknown\n");
        err("ServerAlias at.example\n");
        err("ErrorDocument 404\n");
        err("AddType text/plain\n");
        err("AddHandler handler\n");
        err("Header set X\n");
        err("Header set\n");
        err("Header set X value env=FLAG\n");
        err("ProxyPass /shortun\n");
        err("ProxyPassReverse /shortun\n");
        err("ProxyPassMatch ^/short$\n");
        err("AddOutputFilterByType DEFLATE\n");
        err("AddOutputFilter DEFLATE\n");
        err("CustomLog logs/short.log\n");
        err("CustomLog logs/access.log combined env=FLAG\n");
        err("RequestReadTimeout nonsense\n");
        err("BalancerMember\n");
        err("ProxySet foo=bar\n");
        err("ProxyHCTemplate\n");

        err("<Directory /x>\n<RequireAny>\nRequire all granted\n<If true>\nOptions Indexes\n</If>\n</RequireAny>\n</Directory>\n");
        let invalid = "<UnknownSection>\nServerName unknown.test\n</UnknownSection>\n";
        assert!(load_text(invalid, false).is_err());
        let invalid = concat!(
            "Listen 127.0.0.1:0\n",
            "<If true>\n",
            "<Files x>\n",
            "Options Indexes\n",
            "</Files>\n",
            "</If>\n",
        );
        assert!(load_text(invalid, false).is_err());
        let warning_cfg = concat!(
            "Listen 127.0.0.1:0\n",
            "<Location />\nAllowOverride All\n</Location>\n",
            "<Location /list>\nAllowOverrideList None\n</Location>\n",
            "SecRuleEngine Off\n",
        );
        let c = load_text(warning_cfg, false).unwrap();
        assert!(c
            .warnings
            .iter()
            .any(|w| w.contains("useless use of AllowOverride")));
        assert!(c
            .warnings
            .iter()
            .any(|w| w.contains("useless use of AllowOverrideList")));
        err("AllowEncodedSlashes maybe\n");
        err("DeflateCompressionLevel 10\n");
        err("BrotliCompressionQuality 12\n");
    }

    #[test]
    fn coverage_too_many_modules() {
        let mut cfg = String::from("Listen 127.0.0.1:0\n");
        for i in 0..4097 {
            cfg.push_str(&format!("LoadModule m{i} /tmp/m{i}.so\n"));
        }
        assert!(load_text(&cfg, false).is_err());
    }

    #[test]
    fn coverage_rule_application_phases() {
        let req = test_request("GET");
        let peer = "127.0.0.1".parse().unwrap();
        let root = Path::new("/tmp");
        let fs_path = Path::new("/srv/www/file.php");
        let fname = "file.php";
        let url_path = "/file.php";

        let mut dir_rule = ScopeRule {
            kind: MatchKind::Directory(PathBuf::from("/srv/www")),
            delta: Scope::default(),
            order: 1,
            condition: None,
            branch: ConditionBranch::Normal,
            chain: None,
            nested: Vec::new(),
        };
        dir_rule
            .delta
            .header_policy
            .add_headers
            .push(("X-Dir".into(), "1".into()));
        let mut files_rule = ScopeRule {
            kind: MatchKind::Files(compile_regex("^file").unwrap()),
            delta: Scope::default(),
            order: 2,
            condition: None,
            branch: ConditionBranch::Normal,
            chain: None,
            nested: Vec::new(),
        };
        files_rule
            .delta
            .header_policy
            .add_headers
            .push(("X-Files".into(), "1".into()));
        let mut loc_rule = ScopeRule {
            kind: MatchKind::Location("/file.php".into()),
            delta: Scope::default(),
            order: 3,
            condition: None,
            branch: ConditionBranch::Normal,
            chain: None,
            nested: Vec::new(),
        };
        loc_rule
            .delta
            .header_policy
            .add_headers
            .push(("X-Loc".into(), "1".into()));
        let mut conditional = ScopeRule {
            kind: MatchKind::Always,
            delta: Scope::default(),
            order: 4,
            condition: Some(crate::expr::parse("true").unwrap()),
            branch: ConditionBranch::Normal,
            chain: Some(1),
            nested: Vec::new(),
        };
        conditional
            .delta
            .header_policy
            .add_headers
            .push(("X-If".into(), "1".into()));
        let nested_conditional = ScopeRule {
            kind: MatchKind::Always,
            delta: Scope::default(),
            order: 5,
            condition: Some(crate::expr::parse("true").unwrap()),
            branch: ConditionBranch::Normal,
            chain: Some(2),
            nested: Vec::new(),
        };
        let plain_always = ScopeRule {
            kind: MatchKind::Always,
            delta: Scope::default(),
            order: 6,
            condition: None,
            branch: ConditionBranch::Normal,
            chain: None,
            nested: Vec::new(),
        };
        let mut plain_always_nested = plain_always.clone();
        plain_always_nested.order = 7;
        let nonmatching = ScopeRule {
            kind: MatchKind::Files(compile_regex("^nomatch$").unwrap()),
            delta: Scope::default(),
            order: 8,
            condition: None,
            branch: ConditionBranch::Normal,
            chain: None,
            nested: Vec::new(),
        };
        let mut files_nested = files_rule.clone();
        files_nested.nested.push(conditional.clone());
        dir_rule.nested.push(files_rule.clone());
        dir_rule.nested.push(loc_rule.clone());
        dir_rule.nested.push(nested_conditional.clone());
        dir_rule.nested.push(conditional.clone());
        dir_rule.nested.push(plain_always_nested);

        let mut scope = Scope::default();
        let mut files = Vec::new();
        let mut locations = Vec::new();
        let mut conditionals = Vec::new();
        collect_directory_phase(
            &[
                dir_rule.clone(),
                files_rule.clone(),
                loc_rule.clone(),
                conditional.clone(),
                plain_always.clone(),
                nonmatching.clone(),
            ],
            &mut scope,
            &req,
            peer,
            root,
            fs_path,
            url_path,
            fname,
            &mut files,
            &mut locations,
            &mut conditionals,
        );
        assert_eq!(files.len(), 2);
        assert_eq!(locations.len(), 2);
        assert_eq!(conditionals.len(), 5);
        assert!(scope
            .header_policy
            .add_headers
            .iter()
            .any(|(n, _)| n == "X-Dir"));

        let mut scope = Scope::default();
        let mut conditionals = Vec::new();
        apply_normal_rule_list(
            &[
                files_rule.clone(),
                files_nested,
                loc_rule.clone(),
                conditional.clone(),
                nonmatching.clone(),
            ],
            &mut scope,
            &req,
            peer,
            root,
            fs_path,
            url_path,
            fname,
            &mut conditionals,
        );
        assert!(scope
            .header_policy
            .add_headers
            .iter()
            .any(|(n, _)| n == "X-Files"));
        assert!(scope
            .header_policy
            .add_headers
            .iter()
            .any(|(n, _)| n == "X-Loc"));
        assert_eq!(conditionals.len(), 2);

        let mut scope = Scope::default();
        let mut deferred = Vec::new();
        collect_rules_req(
            &[
                dir_rule.clone(),
                files_rule.clone(),
                loc_rule.clone(),
                conditional.clone(),
                plain_always.clone(),
                nonmatching.clone(),
            ],
            &mut scope,
            &req,
            peer,
            root,
            fs_path,
            url_path,
            fname,
            &mut deferred,
        );
        assert_eq!(deferred.len(), 5);
        let mut chain = HashMap::new();
        apply_deferred_req(
            &mut scope, &deferred, &req, peer, root, fs_path, url_path, fname, &mut chain,
        );
        assert!(scope
            .header_policy
            .add_headers
            .iter()
            .any(|(n, _)| n == "X-If"));

        let mut non_dir_rewrite = files_rule.clone();
        non_dir_rewrite
            .delta
            .rewrite_policy
            .rewrite_rules
            .push(parse_rewrite_rule(&["^x$".into(), "/y".into()], "/", false).unwrap());
        let mut non_dir_scope = Scope::default();
        merge_rule_delta(&mut non_dir_scope, &non_dir_rewrite, fs_path, url_path);

        let mut scope = Scope::default();
        apply_rules_config(&[dir_rule.clone()], &mut scope, fs_path, url_path, fname);
        assert!(scope
            .header_policy
            .add_headers
            .iter()
            .any(|(n, _)| n == "X-Dir"));
        let mut scope = Scope::default();
        apply_rules_req(
            &[dir_rule, files_rule, loc_rule, conditional],
            &mut scope,
            &req,
            peer,
            root,
            fs_path,
            url_path,
            fname,
            &mut chain,
        );
        assert!(scope
            .header_policy
            .add_headers
            .iter()
            .any(|(n, _)| n == "X-If"));

        let mut rules = vec![
            ScopeRule {
                kind: MatchKind::LocationMatch(compile_regex("x").unwrap()),
                ..nested_conditional.clone()
            },
            ScopeRule {
                kind: MatchKind::LocationMatch(compile_regex("y").unwrap()),
                ..nested_conditional.clone()
            },
            ScopeRule {
                kind: MatchKind::Location("/a".into()),
                ..nested_conditional.clone()
            },
            ScopeRule {
                kind: MatchKind::Location("/abcdef".into()),
                ..nested_conditional.clone()
            },
            ScopeRule {
                kind: MatchKind::LocationGlob("/a*".into()),
                ..nested_conditional.clone()
            },
            ScopeRule {
                kind: MatchKind::LocationGlob("/abcdef*".into()),
                ..nested_conditional.clone()
            },
            ScopeRule {
                kind: MatchKind::DirectoryMatch(compile_regex("x").unwrap()),
                ..nested_conditional.clone()
            },
            ScopeRule {
                kind: MatchKind::Directory(PathBuf::from("/a")),
                ..nested_conditional.clone()
            },
            ScopeRule {
                kind: MatchKind::Files(compile_regex("x").unwrap()),
                ..nested_conditional.clone()
            },
        ];
        sort_rules(&mut rules);
        assert_eq!(rules.len(), 9);
    }

    #[test]
    fn verified_phase_classification_and_recursive_sort_agree() {
        let make_rule = |kind: MatchKind, order: usize| ScopeRule {
            kind,
            delta: Scope::default(),
            order,
            condition: None,
            branch: ConditionBranch::Normal,
            chain: None,
            nested: Vec::new(),
        };

        let classified = [
            (
                make_rule(MatchKind::Directory(PathBuf::from("/a")), 1),
                RulePhase::Directory,
            ),
            (
                make_rule(MatchKind::DirectoryMatch(compile_regex("a").unwrap()), 2),
                RulePhase::Directory,
            ),
            (
                make_rule(MatchKind::FilesGlob("*.php".into()), 3),
                RulePhase::Files,
            ),
            (
                make_rule(MatchKind::FilesMatch(compile_regex("php").unwrap()), 4),
                RulePhase::Files,
            ),
            (
                make_rule(MatchKind::LocationGlob("/a*".into()), 5),
                RulePhase::Location,
            ),
            (
                make_rule(MatchKind::LocationMatch(compile_regex("a").unwrap()), 6),
                RulePhase::Location,
            ),
            // `Always` is the parser's synthetic <If>/<Else> carrier.  The
            // verified classifier keeps it in the final condition phase even
            // if a hand-built rule omits its expression and branch marker.
            (make_rule(MatchKind::Always, 7), RulePhase::Condition),
        ];
        for (rule, expected) in classified {
            assert_eq!(rule.phase(), expected);
        }

        let mut conditional_files = make_rule(MatchKind::FilesGlob("*.deny".into()), 9);
        conditional_files.condition = Some(crate::expr::parse("true").unwrap());
        let mut parent = make_rule(MatchKind::Directory(PathBuf::from("/outer")), 20);
        parent.nested = vec![
            make_rule(MatchKind::Always, 4),
            make_rule(MatchKind::Location("/nested/deep".into()), 3),
            make_rule(MatchKind::FilesGlob("*.php".into()), 2),
            make_rule(MatchKind::Directory(PathBuf::from("/nested/deep")), 6),
            make_rule(MatchKind::Directory(PathBuf::from("/n")), 1),
            make_rule(
                MatchKind::DirectoryMatch(compile_regex("nested").unwrap()),
                7,
            ),
            make_rule(MatchKind::Location("/n".into()), 5),
            make_rule(
                MatchKind::LocationMatch(compile_regex("nested").unwrap()),
                8,
            ),
            conditional_files,
        ];
        let mut rules = vec![
            make_rule(MatchKind::Always, 40),
            make_rule(MatchKind::FilesGlob("*.html".into()), 30),
            parent,
        ];
        sort_rules(&mut rules);
        assert_eq!(
            rules.iter().map(ScopeRule::phase).collect::<Vec<_>>(),
            vec![RulePhase::Directory, RulePhase::Files, RulePhase::Condition]
        );
        assert_eq!(
            rules[0]
                .nested
                .iter()
                .map(ScopeRule::phase)
                .collect::<Vec<_>>(),
            vec![
                RulePhase::Directory,
                RulePhase::Directory,
                RulePhase::Directory,
                RulePhase::Files,
                RulePhase::Location,
                RulePhase::Location,
                RulePhase::Location,
                RulePhase::Condition,
                RulePhase::Condition,
            ]
        );
        assert_eq!(
            rules[0]
                .nested
                .iter()
                .map(|rule| rule.order)
                .collect::<Vec<_>>(),
            vec![1, 6, 7, 2, 5, 3, 8, 4, 9]
        );
    }

    #[test]
    fn resolved_target_scope_is_a_meet_not_a_replacement() {
        let mut url = Scope::default();
        url.options.push_add(Options::EXEC_CGI | Options::INDEXES);
        url.content_policy.force_type = Some("text/plain".into());
        url.content_policy.remove_types.push("secret".into());
        url.environment_policy.set_env_if.push(Originated::main(
            parse_env_rule(
                "setenvif",
                &["X-Gate".into(), "^yes$".into(), "SHARED=url".into()],
            )
            .unwrap(),
        ));
        url.environment_policy
            .unset_env
            .push(Originated::main("TARGET_ONLY".into()));
        url.mapping_policy
            .handlers
            .push(Handler::remove("cgi".into()));

        let mut target = Scope::default();
        target
            .options
            .push_add(Options::EXEC_CGI | Options::INDEXES);
        target.options.push_remove(Options::INDEXES);
        target.content_policy.force_type = Some("application/octet-stream".into());
        target
            .content_policy
            .add_types
            .push(("application/x-secret".into(), "secret".into()));
        target.environment_policy.set_env_if.push(Originated::main(
            parse_env_rule(
                "setenvif",
                &["X-Gate".into(), "^yes$".into(), "SHARED=target".into()],
            )
            .unwrap(),
        ));
        target
            .environment_policy
            .set_env
            .push(Originated::main(("TARGET_ONLY".into(), "visible".into())));
        target
            .mapping_policy
            .handlers
            .push(Handler::add("cgi".into(), "cgi-script".into()));

        target.restrict_with(&url);
        let options = target.effective_options();
        assert!(options.contains(Options::EXEC_CGI));
        assert!(!options.contains(Options::INDEXES));
        assert_eq!(
            target.content_policy.force_type.as_deref(),
            Some("text/plain")
        );
        assert!(target
            .content_policy
            .remove_types
            .iter()
            .any(|ext| ext == "secret"));
        assert!(target
            .content_policy
            .add_types
            .iter()
            .any(|(ty, ext)| ty == "application/x-secret" && ext == "secret"));

        let mut req = test_request("GET");
        req.headers.insert("x-gate", b"yes".to_vec());
        let peer = "127.0.0.1".parse().unwrap();
        let auth_env = target.authorization_env(&req, "/x", peer);
        assert_eq!(
            auth_env
                .iter()
                .find(|(name, _)| name == "SHARED")
                .map(|(_, value)| value.as_slice()),
            Some(b"url".as_slice())
        );
        assert!(!target
            .request_env(&req, "/x", peer)
            .iter()
            .any(|(name, _)| name == "TARGET_ONLY"));
        // The lexical RemoveHandler survives a canonical AddHandler.
        assert_eq!(effective_handler(&target, b"upload.cgi"), None);

        // A target-only AddHandler cannot grant execution either.
        let mut url = Scope::default();
        let mut target = Scope::default();
        target
            .mapping_policy
            .handlers
            .push(Handler::add("cgi".into(), "cgi-script".into()));
        target.restrict_with(&url);
        assert_eq!(effective_handler(&target, b"upload.cgi"), None);

        // Matching handler maps remain usable.
        let mut url = Scope::default();
        url.mapping_policy
            .handlers
            .push(Handler::add("cgi".into(), "cgi-script".into()));
        let mut target = Scope::default();
        target
            .mapping_policy
            .handlers
            .push(Handler::add("cgi".into(), "CGI-SCRIPT".into()));
        target.restrict_with(&url);
        assert_eq!(
            effective_handler(&target, b"upload.cgi"),
            Some("cgi-script")
        );

        // `*` is a literal extension in Apache, not a wildcard.
        let mut url = Scope::default();
        url.mapping_policy
            .handlers
            .push(Handler::add("*".into(), "cgi-script".into()));
        let mut target = Scope::default();
        target
            .mapping_policy
            .handlers
            .push(Handler::add("*".into(), "cgi-script".into()));
        target.restrict_with(&url);
        assert_eq!(effective_handler(&target, b"upload.anything"), None);
        assert_eq!(effective_handler(&target, b"upload.*"), Some("cgi-script"));
        let mut target = Scope::default();
        target
            .mapping_policy
            .handlers
            .push(Handler::add("*".into(), "proxy:fcgi://localhost".into()));
        target.restrict_with(&url);
        assert_eq!(effective_handler(&target, b"upload.anything"), None);
        assert_eq!(effective_handler(&target, b"upload.*"), None);

        // Two matching RemoveHandler operations stay removed.
        let mut url = Scope::default();
        url.mapping_policy
            .handlers
            .push(Handler::remove("cgi".into()));
        let mut target = Scope::default();
        target
            .mapping_policy
            .handlers
            .push(Handler::remove("cgi".into()));
        target.restrict_with(&url);
        assert_eq!(effective_handler(&target, b"upload.cgi"), None);

        // Lexical filters are retained even when the target does not repeat
        // them.
        let mut url = Scope::default();
        url.mapping_policy
            .unsupported_filters
            .push("INCLUDES".into());
        let mut target = Scope::default();
        target.restrict_with(&url);
        assert_eq!(target.mapping_policy.unsupported_filters, vec!["INCLUDES"]);

        // Extension-scoped filters also survive a rewrite so an unsupported
        // processor cannot be bypassed by changing the target identity.
        let mut url = Scope::default();
        url.compression_policy
            .unsupported_filter_rules
            .push(UnsupportedFilterRule::ByExt(
                "INCLUDES".into(),
                vec![".shtml".into()],
            ));
        let mut target = Scope::default();
        target.restrict_policy_with(&url);
        assert_eq!(
            target.compression_policy.unsupported_filter_rules,
            vec![UnsupportedFilterRule::ByExt(
                "INCLUDES".into(),
                vec![".shtml".into()]
            )]
        );
    }

    #[test]
    fn rewrite_original_policy_keeps_the_target_handler_extension() {
        let mut original = Scope::default();
        original.options.push_add(Options::EXEC_CGI);
        original
            .mapping_policy
            .handlers
            .push(Handler::remove("cgi".into()));

        let mut rewritten = Scope::default();
        rewritten.options.push_add(Options::EXEC_CGI);
        rewritten
            .mapping_policy
            .handlers
            .push(Handler::add("cgi".into(), "cgi-script".into()));

        rewritten.restrict_policy_with(&original);
        assert!(rewritten.effective_options().contains(Options::EXEC_CGI));
        // The rewrite intentionally selected a CGI filename; the original
        // URL's RemoveHandler does not erase the new target's handler map.
        assert_eq!(
            effective_handler(&rewritten, b"target.cgi"),
            Some("cgi-script")
        );
    }
}

/// Strip a port from an HTTP authority without corrupting IPv6 literals.
fn authority_host(host: &str) -> &str {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(host);
    }
    if host.matches(':').count() == 1 {
        return host.split(':').next().unwrap_or(host);
    }
    host
}

impl Config {
    /// Select the virtual host for a connection.  `host` is the Host header
    /// value (possibly with port), `port` the local listening port.
    fn remoteip_proxy_class(&self, ip: IpAddr) -> vapache_verified::RemoteIpProxyClass {
        let ip = crate::access::canonical_ip(ip);
        self.remoteip_proxies
            .iter()
            .find(|proxy| crate::access::ip_in_net(ip, proxy.network, proxy.bits))
            .map(|proxy| {
                if proxy.internal {
                    vapache_verified::RemoteIpProxyClass::Internal
                } else {
                    vapache_verified::RemoteIpProxyClass::Trusted
                }
            })
            .unwrap_or(vapache_verified::RemoteIpProxyClass::Untrusted)
    }

    /// Transport peers explicitly trusted to present RemoteIP identities are
    /// gateways for many clients, not one client for fairness accounting.
    pub fn transport_peer_is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.remoteip_header.is_some()
            && self.remoteip_proxy_class(ip) != vapache_verified::RemoteIpProxyClass::Untrusted
    }

    /// Apache 2.4.69's exact external-chain address rule from
    /// `mod_remoteip.c`: reject five IPv4 private/local ranges and accept only
    /// IPv6 global-unicast 2000::/3. IPv4-mapped IPv6 is canonicalized first.
    fn remoteip_candidate_is_public(ip: IpAddr) -> bool {
        match crate::access::canonical_ip(ip) {
            IpAddr::V4(ip) => {
                let [a, b, _, _] = ip.octets();
                !(a == 10
                    || a == 127
                    || (a == 169 && b == 254)
                    || (a == 172 && b & 0xf0 == 16)
                    || (a == 192 && b == 168))
            }
            IpAddr::V6(ip) => ip.octets()[0] & 0xe0 == 0x20,
        }
    }

    /// Apply Apache `mod_remoteip` client-address rewriting. The immediate
    /// peer must be configured as an internal or trusted proxy; this retains
    /// vapache's fail-closed behavior for `RemoteIPHeader` without a trust
    /// list while matching Apache once a list is present.
    pub fn client_addr(
        &self,
        peer: std::net::SocketAddr,
        req: &crate::http::Request,
    ) -> std::net::SocketAddr {
        let value = self
            .remoteip_header
            .as_ref()
            .and_then(|header| req.header(&header.to_ascii_lowercase()));
        self.client_addr_with_remoteip_value(peer, value)
    }

    /// HTTP/2 needs the effective identity immediately after validating the
    /// header block, before it admits a potentially slow request body.
    pub fn client_addr_from_headers(
        &self,
        peer: std::net::SocketAddr,
        headers: &crate::http::Headers,
    ) -> std::net::SocketAddr {
        let value = self
            .remoteip_header
            .as_ref()
            .and_then(|header| headers.get(&header.to_ascii_lowercase()));
        self.client_addr_with_remoteip_value(peer, value)
    }

    fn client_addr_with_remoteip_value(
        &self,
        peer: std::net::SocketAddr,
        value: Option<&[u8]>,
    ) -> std::net::SocketAddr {
        let peer = crate::access::canonical_socket_addr(peer);
        if self.remoteip_header.is_none() {
            return peer;
        }
        if self.remoteip_proxies.is_empty() {
            return peer;
        }
        let Some(value) = value else {
            return peer;
        };
        let text = String::from_utf8_lossy(value);
        // Apache walks the list right-to-left. The current presenter must be
        // trusted for every hop; malformed/empty entries terminate the walk,
        // and an external trusted chain cannot present a private address.
        let mut current = peer.ip();
        let mut selected = peer;
        let mut chain_internal = true;
        for part in text.split(',').rev() {
            let presenter = self.remoteip_proxy_class(current);
            let next_internal = crate::verified::remoteip_next_internal(chain_internal, presenter);
            let part = part.trim_matches(' ');
            let Ok(candidate) = part.parse::<IpAddr>() else {
                debug_assert!(!crate::verified::remoteip_candidate_admit(
                    presenter,
                    next_internal,
                    false,
                    false,
                ));
                break;
            };
            let candidate = crate::access::canonical_ip(candidate);
            if !crate::verified::remoteip_candidate_admit(
                presenter,
                next_internal,
                true,
                Self::remoteip_candidate_is_public(candidate),
            ) {
                break;
            }
            selected = std::net::SocketAddr::new(candidate, peer.port());
            current = candidate;
            chain_internal = next_internal;
        }
        selected
    }

    fn vhost_port_matches(v: &VHost, port: u16) -> bool {
        v.ports.iter().any(|p| *p == 0 || *p == port)
    }

    fn vhost_address_text(addr: &str) -> &str {
        authority_host(addr)
    }

    fn vhost_address_is_wildcard(addr: &str) -> bool {
        let host = Self::vhost_address_text(addr);
        host.is_empty() || host == "*" || host.starts_with("_default_")
    }

    pub(crate) fn vhost_address_is_specific(v: &VHost, local_ip: IpAddr, port: u16) -> bool {
        v.addrs.iter().any(|addr| {
            (vhost_port(addr) == 0 || vhost_port(addr) == port)
                && !Self::vhost_address_is_wildcard(addr)
                && Self::vhost_address_text(addr)
                    .parse::<IpAddr>()
                    .map(crate::access::canonical_ip)
                    .is_ok_and(|bound| bound == crate::access::canonical_ip(local_ip))
        })
    }

    /// Concrete destination identities that need distinct TLS configurations
    /// when one wildcard listener accepts connections for several local IPs.
    pub(crate) fn vhost_specific_addresses(&self, port: u16) -> Vec<IpAddr> {
        let mut addresses = HashSet::new();
        for vhost in &self.vhosts {
            for address in &vhost.addrs {
                if vhost_port(address) != 0 && vhost_port(address) != port {
                    continue;
                }
                if Self::vhost_address_is_wildcard(address) {
                    continue;
                }
                if let Ok(ip) = Self::vhost_address_text(address).parse::<IpAddr>() {
                    addresses.insert(crate::access::canonical_ip(ip));
                }
            }
        }
        let mut addresses: Vec<_> = addresses.into_iter().collect();
        addresses.sort_unstable();
        addresses
    }

    pub(crate) fn vhost_address_applies(v: &VHost, local_ip: IpAddr, port: u16) -> bool {
        if v.addrs.is_empty() {
            return true;
        }
        v.addrs.iter().any(|addr| {
            if vhost_port(addr) != 0 && vhost_port(addr) != port {
                return false;
            }
            let host = Self::vhost_address_text(addr);
            let wildcard = Self::vhost_address_is_wildcard(addr);
            let bound = if wildcard {
                None
            } else {
                host.parse::<IpAddr>().ok().map(crate::access::canonical_ip)
            };
            let same = bound == Some(crate::access::canonical_ip(local_ip));
            crate::verified::vhost_address_admit(!wildcard, wildcard, same)
        })
    }

    /// Select the virtual host for a connection.  `local_ip` is the
    /// destination address the connection arrived on, `port` the local
    /// listening port and `host` the Host header value (possibly with port).
    /// Address-bound vhosts are never candidates on a different destination
    /// address, and an exact-address vhost takes precedence over wildcard
    /// vhosts exactly as Apache's address/port buckets do (F48/I45).
    pub fn select_vhost(
        &self,
        local_ip: Option<IpAddr>,
        port: u16,
        host: Option<&str>,
    ) -> Option<&VHost> {
        let has_bucket = |address| {
            self.vhost_index
                .buckets
                .contains_key(&VHostBucketKey { address, port })
                || self
                    .vhost_index
                    .buckets
                    .contains_key(&VHostBucketKey { address, port: 0 })
        };
        let address = match local_ip.map(crate::access::canonical_ip) {
            None => VHostAddressKey::NoAddress,
            Some(ip) if has_bucket(VHostAddressKey::Exact(ip)) => VHostAddressKey::Exact(ip),
            Some(_) => VHostAddressKey::Wildcard,
        };
        if let Some(bucket) = self
            .vhost_index
            .buckets
            .get(&VHostBucketKey { address, port })
            .or_else(|| {
                self.vhost_index
                    .buckets
                    .get(&VHostBucketKey { address, port: 0 })
            })
        {
            return bucket
                .select(&self.vhosts, host)
                .and_then(|index| self.vhosts.get(index));
        }
        // Public Config fields are retained for source compatibility with
        // embedders and tests that construct/mutate a Config manually. Normal
        // loader output always has a bucket for every listener, so remote
        // requests never take this compatibility path.
        let port_candidates: Vec<&VHost> = self
            .vhosts
            .iter()
            .filter(|v| v.addrs.is_empty() || Self::vhost_port_matches(v, port))
            .collect();
        if port_candidates.is_empty() {
            return None;
        }
        let candidates: Vec<&VHost> = match local_ip {
            Some(local_ip) => {
                let exact: Vec<&VHost> = port_candidates
                    .iter()
                    .copied()
                    .filter(|v| Self::vhost_address_is_specific(v, local_ip, port))
                    .collect();
                let exact_available = !exact.is_empty();
                port_candidates
                    .into_iter()
                    .filter(|v| {
                        let candidate_exact = Self::vhost_address_is_specific(v, local_ip, port);
                        crate::verified::vhost_address_precedence(exact_available, candidate_exact)
                            && Self::vhost_address_applies(v, local_ip, port)
                    })
                    .collect()
            }
            None => port_candidates,
        };
        if candidates.is_empty() {
            return None;
        }
        if let Some(h) = host {
            let bare = authority_host(h);
            let matches: Vec<bool> = candidates.iter().map(|v| v.matches_name(bare)).collect();
            if let Some(index) = crate::verified::first_true_index(&matches) {
                return Some(candidates[index]);
            }
        }
        // Apache uses the first configured vhost for the address as default.
        Some(candidates[0])
    }

    /// Rebuild the compiled virtual-host index after directly mutating `vhosts`
    /// or `listeners` on an embedded configuration.
    pub fn rebuild_vhost_index(&mut self) {
        self.vhost_index = Arc::new(VHostIndex::build(&self.vhosts, &self.listeners));
    }

    pub(crate) fn vhost_position(&self, vhost: &VHost) -> Option<usize> {
        let width = std::mem::size_of::<VHost>();
        let start = self.vhosts.as_ptr() as usize;
        let address = std::ptr::from_ref(vhost) as usize;
        let offset = address.checked_sub(start)?;
        if width == 0 || offset % width != 0 {
            return None;
        }
        let index = offset / width;
        (index < self.vhosts.len()).then_some(index)
    }

    pub fn resolve_log_format(&self, name: &str) -> String {
        if name.starts_with('"') && name.ends_with('"') && name.len() >= 2 {
            name[1..name.len() - 1].to_string()
        } else {
            self.log_formats
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.to_string())
        }
    }

    /// True when the compiled configuration can dispatch a CGI request.
    /// Used to avoid starting CGI worker processes for static-only servers.
    pub fn has_cgi(&self) -> bool {
        self.cgi_path_info_possible
    }

    fn override_scan(&self) -> bool {
        let enabled = |s: &Scope| s.override_policy.is_enabled();
        enabled(&self.global)
            || self.global_rules.iter().any(|r| enabled(&r.delta))
            || self
                .vhosts
                .iter()
                .any(|v| enabled(&v.scope) || v.rules.iter().any(|r| enabled(&r.delta)))
    }

    /// Collect the directory prefixes where `.htaccess` handling can apply.
    /// A request whose filesystem path is not below one of these prefixes (and
    /// which is not covered by `override_anywhere`) cannot read any access file,
    /// so the request path can skip the whole directory walk.
    fn override_paths(&self) -> (Vec<PathBuf>, bool) {
        fn enabled(s: &Scope) -> bool {
            s.override_policy.is_enabled()
        }
        fn collect(rule: &ScopeRule, prefixes: &mut Vec<PathBuf>, anywhere: &mut bool) {
            if enabled(&rule.delta) {
                match &rule.kind {
                    MatchKind::Directory(path) => prefixes.push(path.clone()),
                    _ => *anywhere = true,
                }
            }
            for nested in &rule.nested {
                collect(nested, prefixes, anywhere);
            }
        }

        let mut prefixes = Vec::new();
        let mut anywhere = false;
        if enabled(&self.global) {
            anywhere = true;
        }
        for rule in &self.global_rules {
            collect(rule, &mut prefixes, &mut anywhere);
        }
        for vhost in &self.vhosts {
            if enabled(&vhost.scope) {
                anywhere = true;
            }
            for rule in &vhost.rules {
                collect(rule, &mut prefixes, &mut anywhere);
            }
        }
        prefixes.sort();
        prefixes.dedup();
        // A parent prefix subsumes all literal children.  Keeping every
        // `<Directory>` that enables overrides would make the per-request
        // access-file gate scan a large list for deeply nested trees.
        let mut collapsed: Vec<PathBuf> = Vec::new();
        for candidate in prefixes {
            let wildcard = {
                use std::os::unix::ffi::OsStrExt;
                candidate
                    .as_os_str()
                    .as_bytes()
                    .iter()
                    .any(|b| matches!(b, b'*' | b'?' | b'['))
            };
            if !wildcard
                && collapsed.iter().any(|parent| {
                    use std::os::unix::ffi::OsStrExt;
                    let parent_wildcard = parent
                        .as_os_str()
                        .as_bytes()
                        .iter()
                        .any(|b| matches!(b, b'*' | b'?' | b'['));
                    !parent_wildcard && candidate.starts_with(parent)
                })
            {
                continue;
            }
            collapsed.push(candidate);
        }
        (collapsed, anywhere)
    }

    /// True when `.htaccess` handling can apply to this filesystem path.
    /// Wildcard `<Directory>` patterns are matched with the same logic as the
    /// request-time rule matcher; a plain `starts_with` would silently skip
    /// override-enabled trees such as `<Directory "/srv/*/public">`.
    pub fn override_applicable(&self, fs_path: &Path) -> bool {
        if !self.override_enabled {
            return true;
        }
        if self.override_anywhere {
            return true;
        }
        self.override_prefixes.iter().any(|prefix| {
            use std::os::unix::ffi::OsStrExt;
            if prefix
                .as_os_str()
                .as_bytes()
                .iter()
                .any(|b| matches!(b, b'*' | b'?' | b'['))
            {
                directory_wildcard_matches(prefix, fs_path)
            } else {
                // Literal prefixes are ancestors of the request path.  Avoid
                // the metadata probe in `directory_wildcard_matches`, which
                // otherwise stats the request target once per configured
                // override prefix on every request.
                fs_path.starts_with(prefix)
            }
        })
    }

    /// Request-metered form of [`Self::override_applicable`].  This prefilter
    /// runs while a request plan is being built, before the ordinary policy
    /// phases; it must therefore consume the same aggregate work budget as
    /// the matchers it decides whether to invoke.
    pub fn override_applicable_req(
        &self,
        fs_path: &Path,
        req: &crate::http::Request,
    ) -> Result<bool, &'static str> {
        if !self.override_enabled || self.override_anywhere {
            req.charge_policy_work(1)?;
            return Ok(true);
        }
        for prefix in &self.override_prefixes {
            use std::os::unix::ffi::OsStrExt;
            let pattern = prefix.as_os_str().as_bytes();
            if pattern
                .iter()
                .any(|byte| matches!(byte, b'*' | b'?' | b'['))
            {
                if directory_wildcard_matches_req(prefix, fs_path, req)? {
                    return Ok(true);
                }
            } else {
                req.charge_policy_work(
                    (pattern.len() as u64)
                        .saturating_add(fs_path.as_os_str().as_bytes().len() as u64)
                        .saturating_add(1),
                )?;
                if fs_path.starts_with(prefix) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// True when an access file could affect this request.  When false the
    /// dispatcher can use the one-pass Directory merge and skip the per-
    /// directory walk entirely.
    pub fn htaccess_may_apply(&self, fs_path: &Path) -> bool {
        self.capability_enabled(Capability::AccessFiles)
            && self.override_enabled
            && self.override_applicable(fs_path)
    }

    pub fn htaccess_may_apply_req(
        &self,
        fs_path: &Path,
        req: &crate::http::Request,
    ) -> Result<bool, &'static str> {
        if !self.capability_enabled(Capability::AccessFiles) || !self.override_enabled {
            req.charge_policy_work(1)?;
            return Ok(false);
        }
        self.override_applicable_req(fs_path, req)
    }

    /// Per-directory prefilter for the ancestor walk.  An access file in
    /// `dir` can participate only when `dir` is at or below a directory whose
    /// effective policy enables overrides.  Literal override prefixes are
    /// compared without filesystem metadata; a wildcard prefix conservatively
    /// admits the walk so the existing effective-policy check decides.
    pub(crate) fn access_file_dir_applicable(&self, dir: &Path) -> bool {
        if !self.capability_enabled(Capability::AccessFiles) || !self.override_enabled {
            return false;
        }
        if self.override_anywhere {
            return true;
        }
        self.override_prefixes.iter().any(|prefix| {
            use std::os::unix::ffi::OsStrExt;
            if prefix
                .as_os_str()
                .as_bytes()
                .iter()
                .any(|b| matches!(b, b'*' | b'?' | b'['))
            {
                // Wildcard/pattern sections cannot be decided by a cheap
                // prefix check; keep the established matcher for them.
                return true;
            }
            dir.starts_with(prefix)
        })
    }

    pub(crate) fn access_file_dir_applicable_req(
        &self,
        dir: &Path,
        req: &crate::http::Request,
    ) -> Result<bool, &'static str> {
        if !self.capability_enabled(Capability::AccessFiles) || !self.override_enabled {
            req.charge_policy_work(1)?;
            return Ok(false);
        }
        if self.override_anywhere {
            req.charge_policy_work(1)?;
            return Ok(true);
        }
        for prefix in &self.override_prefixes {
            use std::os::unix::ffi::OsStrExt;
            let pattern = prefix.as_os_str().as_bytes();
            if pattern
                .iter()
                .any(|byte| matches!(byte, b'*' | b'?' | b'['))
            {
                req.charge_policy_work(1)?;
                return Ok(true);
            }
            req.charge_policy_work(
                (pattern.len() as u64)
                    .saturating_add(dir.as_os_str().as_bytes().len() as u64)
                    .saturating_add(1),
            )?;
            if dir.starts_with(prefix) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The effective server header value for this configuration.
    pub fn server_header(&self) -> String {
        self.server_software.clone()
    }

    /// Compute the effective scope for a filesystem path and URL path.
    pub fn effective_scope(&self, vhost: Option<&VHost>, fs_path: &Path, url_path: &str) -> Scope {
        let base = vhost.map(|v| &v.scope).unwrap_or(&self.global);
        let mut s = base.clone();
        let rules: &[ScopeRule] = vhost
            .map(|v| v.rules.as_slice())
            .unwrap_or(self.global_rules.as_slice());
        let fname = fs_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        apply_rules_config(rules, &mut s, fs_path, url_path, &fname);
        s
    }

    /// Cached request-independent scope for a directory.  `collect_layers`
    /// only needs the inherited override policy for each ancestor; recomputing
    /// the full scope per request is unnecessary.
    pub fn effective_scope_cached(
        &self,
        vhost: Option<&VHost>,
        dir: &Path,
        url_path: &str,
    ) -> Arc<Scope> {
        let key = (
            vhost.map(|v| v as *const VHost as usize).unwrap_or(0),
            dir.to_path_buf(),
            url_path.to_string(),
        );
        if let Ok(guard) = self.dir_scope_cache.read() {
            if let Some(scope) = guard.get(&key) {
                return scope;
            }
        }
        let scope = Arc::new(self.effective_scope(vhost, dir, url_path));
        if let Ok(mut guard) = self.dir_scope_cache.write() {
            guard.insert(key, Arc::clone(&scope));
        }
        scope
    }

    /// Metered cache-miss path used while building a live request plan. Cache
    /// hits pay only for their key; misses charge every rule matcher before
    /// constructing and retaining the request-independent scope.
    pub fn effective_scope_cached_req(
        &self,
        vhost: Option<&VHost>,
        dir: &Path,
        url_path: &str,
        req: &crate::http::Request,
    ) -> Result<Arc<Scope>, &'static str> {
        req.charge_policy_work(
            (dir.as_os_str().as_encoded_bytes().len() as u64)
                .saturating_add(url_path.len() as u64)
                .saturating_add(1),
        )?;
        let key = (
            vhost.map(|v| v as *const VHost as usize).unwrap_or(0),
            dir.to_path_buf(),
            url_path.to_string(),
        );
        if let Ok(guard) = self.dir_scope_cache.read() {
            if let Some(scope) = guard.get(&key) {
                return Ok(scope);
            }
        }
        let base = vhost.map(|v| &v.scope).unwrap_or(&self.global);
        let mut scope = base.clone();
        let rules: &[ScopeRule] = vhost
            .map(|v| v.rules.as_slice())
            .unwrap_or(self.global_rules.as_slice());
        let fname = dir
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        apply_rules_config_budgeted(rules, &mut scope, dir, url_path, &fname, req)?;
        let scope = Arc::new(scope);
        if let Ok(mut guard) = self.dir_scope_cache.write() {
            guard.insert(key, Arc::clone(&scope));
        }
        Ok(scope)
    }

    /// Apply matching `<Proxy>` / `<ProxyMatch>` container configuration to a
    /// request that is about to be proxied.  `proxy_url` is the backend URL
    /// (for example `http://backend/app/x`), matching Apache's proxy-section
    /// matching semantics.
    pub fn apply_proxy_access(
        &self,
        vhost: Option<&VHost>,
        scope: &mut Scope,
        proxy_url: &str,
        req: &crate::http::Request,
        peer: IpAddr,
        url_path: &str,
    ) {
        self.apply_proxy_access_urls(vhost, scope, &[proxy_url], req, peer, url_path);
    }

    /// Match `<Proxy>`/`<ProxyMatch>` sections against every identity the
    /// request has.  A balancer request has both the logical
    /// `balancer://cluster` identity and the concrete member URL; Apache
    /// applies sections matching either one.
    pub fn apply_proxy_access_urls(
        &self,
        vhost: Option<&VHost>,
        scope: &mut Scope,
        proxy_urls: &[&str],
        req: &crate::http::Request,
        peer: IpAddr,
        url_path: &str,
    ) {
        let containers: &[ProxyContainer] = vhost
            .map(|v| v.proxy_containers.as_slice())
            .unwrap_or(self.proxy_containers.as_slice());
        let docroot = self.documentation_root_for(vhost);
        for container in containers {
            let mut matched = false;
            for proxy_url in proxy_urls {
                let result = match &container.kind {
                    ProxyMatchKind::Wildcard(pattern) => {
                        if pattern
                            .as_bytes()
                            .iter()
                            .any(|b| matches!(b, b'*' | b'?' | b'['))
                        {
                            crate::glob::fnmatch_budgeted(
                                pattern.as_bytes(),
                                proxy_url.as_bytes(),
                                false,
                                req.policy_budget(),
                            )
                        } else {
                            req.charge_policy_work(
                                (pattern.len() as u64)
                                    .saturating_add(proxy_url.len() as u64)
                                    .saturating_add(1),
                            )
                            .map(|()| proxy_url.starts_with(pattern.as_str()))
                        }
                    }
                    ProxyMatchKind::Regex(re) => req
                        .charge_policy_work(
                            (re.as_str().len() as u64)
                                .saturating_add(proxy_url.len() as u64)
                                .saturating_add(1),
                        )
                        .map(|()| re.is_match(proxy_url.as_bytes())),
                };
                match result {
                    Ok(true) => {
                        matched = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(_) => {
                        scope.conditional_error = true;
                        return;
                    }
                }
            }
            if !matched {
                continue;
            }
            scope.merge(&container.delta);
            let mut chain_state: HashMap<usize, bool> = HashMap::new();
            apply_rules_req(
                &container.rules,
                scope,
                req,
                peer,
                &docroot,
                Path::new(""),
                url_path,
                "",
                &mut chain_state,
            );
        }
    }

    pub fn effective_scope_req(
        &self,
        vhost: Option<&VHost>,
        fs_path: &Path,
        url_path: &str,
        req: &crate::http::Request,
        peer: std::net::IpAddr,
    ) -> Scope {
        let mut deferred: Vec<ScopeRule> = Vec::new();
        let mut s =
            self.effective_scope_req_deferred(vhost, fs_path, url_path, req, peer, &mut deferred);
        deferred.sort_by_key(|rule| rule.order);
        let fname = fs_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        let docroot = self.documentation_root_for(vhost);
        let mut chain_state: HashMap<usize, bool> = HashMap::new();
        apply_deferred_req(
            &mut s,
            &deferred,
            req,
            peer,
            &docroot,
            fs_path,
            url_path,
            &fname,
            &mut chain_state,
        );
        s
    }

    /// Start a request scope at the inherited base and collect only the
    /// top-level Files, Location and conditional rules.  Literal Directory
    /// rules are applied by `policy_ref::effective_scope` as it walks each
    /// directory, so they can be interleaved with that directory's access
    /// files exactly as Apache does.
    pub fn effective_scope_req_base_deferred(
        &self,
        vhost: Option<&VHost>,
        fs_path: &Path,
        url_path: &str,
        req: &crate::http::Request,
        peer: std::net::IpAddr,
        files: &mut Vec<ScopeRule>,
        locations: &mut Vec<ScopeRule>,
        conditionals: &mut Vec<ScopeRule>,
    ) -> Scope {
        let fname = fs_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        self.effective_scope_req_base_deferred_with_file_name(
            vhost,
            fs_path,
            url_path,
            req,
            peer,
            &fname,
            files,
            locations,
            conditionals,
        )
    }

    /// Collect the configuration phases while matching `<Files>` containers
    /// against an explicit filename identity.  Resolved-target authorization
    /// uses the canonical basename, but handler policy for an in-root symlink
    /// must be re-evaluated with the lexical request-mapped basename (P13).
    #[allow(clippy::too_many_arguments)]
    pub fn effective_scope_req_base_deferred_with_file_name(
        &self,
        vhost: Option<&VHost>,
        fs_path: &Path,
        url_path: &str,
        req: &crate::http::Request,
        peer: std::net::IpAddr,
        fname: &str,
        files: &mut Vec<ScopeRule>,
        locations: &mut Vec<ScopeRule>,
        conditionals: &mut Vec<ScopeRule>,
    ) -> Scope {
        let base = vhost.map(|v| &v.scope).unwrap_or(&self.global);
        let mut s = base.clone();
        let rules: &[ScopeRule] = vhost
            .map(|v| v.rules.as_slice())
            .unwrap_or(self.global_rules.as_slice());
        for rule in rules {
            let matched = match rule_kind_matches_req(&rule.kind, fs_path, url_path, fname, req) {
                Ok(matched) => matched,
                Err(_) => {
                    s.conditional_error = true;
                    break;
                }
            };
            if !matched {
                continue;
            }
            defer_rule_by_verified_phase(rule, files, locations, conditionals);
        }
        files.sort_by_key(|rule| rule.order);
        locations.sort_by_key(|rule| rule.order);
        s
    }

    /// Apply literal/wildcard `<Directory>` rules for one ancestor directory.
    pub fn apply_directory_rules_for_dir(
        &self,
        vhost: Option<&VHost>,
        scope: &mut Scope,
        req: &crate::http::Request,
        peer: std::net::IpAddr,
        dir: &Path,
        fs_path: &Path,
        url_path: &str,
        files: &mut Vec<ScopeRule>,
        locations: &mut Vec<ScopeRule>,
        conditionals: &mut Vec<ScopeRule>,
    ) {
        let rules: &[ScopeRule] = vhost
            .map(|v| v.rules.as_slice())
            .unwrap_or(self.global_rules.as_slice());
        let index = vhost
            .map(|v| &v.directory_index)
            .unwrap_or(&self.global_directory_index);
        let _ = peer;
        let mut apply_rule = |rule: &ScopeRule| {
            merge_rule_delta(scope, rule, fs_path, url_path);
            for nested in &rule.nested {
                defer_rule_by_verified_phase(nested, files, locations, conditionals);
            }
        };
        if index.wildcard.is_empty() {
            if let Some(indices) = index.exact.get(dir) {
                for &i in indices {
                    if req.charge_policy_work(1).is_err() {
                        scope.conditional_error = true;
                        return;
                    }
                    apply_rule(&rules[i]);
                }
            }
            return;
        }
        for rule in rules {
            if rule.condition.is_some() || rule.branch != ConditionBranch::Normal {
                continue;
            }
            let MatchKind::Directory(pattern) = &rule.kind else {
                continue;
            };
            let matched = match directory_pattern_matches_exact_req(pattern, dir, req) {
                Ok(matched) => matched,
                Err(_) => {
                    scope.conditional_error = true;
                    return;
                }
            };
            if !matched {
                continue;
            }
            apply_rule(rule);
        }
    }

    /// Apply `<DirectoryMatch>` rules after `<Directory>` and access files.
    pub fn apply_directory_match_rules(
        &self,
        vhost: Option<&VHost>,
        scope: &mut Scope,
        req: Option<&crate::http::Request>,
        fs_path: &Path,
        url_path: &str,
        files: &mut Vec<ScopeRule>,
        locations: &mut Vec<ScopeRule>,
        conditionals: &mut Vec<ScopeRule>,
    ) {
        let rules: &[ScopeRule] = vhost
            .map(|v| v.rules.as_slice())
            .unwrap_or(self.global_rules.as_slice());
        for rule in rules {
            if rule.condition.is_some() || rule.branch != ConditionBranch::Normal {
                continue;
            }
            let MatchKind::DirectoryMatch(re) = &rule.kind else {
                continue;
            };
            if req.is_some_and(|req| {
                req.charge_policy_work(
                    (re.as_str().len() as u64)
                        .saturating_add(fs_path.as_os_str().as_encoded_bytes().len() as u64)
                        .saturating_add(1),
                )
                .is_err()
            }) {
                scope.conditional_error = true;
                return;
            }
            if !re.is_match(fs_path.as_os_str().as_encoded_bytes()) {
                continue;
            }
            merge_rule_delta(scope, rule, fs_path, url_path);
            for nested in &rule.nested {
                defer_rule_by_verified_phase(nested, files, locations, conditionals);
            }
        }
    }

    /// Cached normal scope for paths that cannot read an access file.  Normal
    /// configuration rules do not depend on request headers or method; only
    /// Apply `<Directory>` rules that match the request-mapped path itself
    /// (F61-C).  Apache's per-directory walk compares every walked component
    /// against the configured patterns; for a regular-file request the file's
    /// own path is the final walked entry, so a `<Directory>` pattern with
    /// exactly the file path's component count governs the file too (2.4.69
    /// probe: `<Directory ".../www/[^a]*">` denies `/hello.html`).  The walk
    /// in `policy_ref` / `htaccess` only visits ancestor *directories*, so the
    /// own-path match is applied here — after the walk, before
    /// `<DirectoryMatch>`: the merge position of the deepest walked entry.
    /// A pattern's component count is fixed, so it can match at most one walk
    /// node; own-path application therefore never duplicates a per-directory
    /// merge.
    pub fn apply_directory_own_path_rules(
        &self,
        vhost: Option<&VHost>,
        scope: &mut Scope,
        req: Option<&crate::http::Request>,
        fs_path: &Path,
        url_path: &str,
        files: &mut Vec<ScopeRule>,
        locations: &mut Vec<ScopeRule>,
        conditionals: &mut Vec<ScopeRule>,
    ) {
        // When the mapped path is itself a directory the walk already
        // evaluated it as the leaf entry; re-applying here would merge the
        // section twice.
        if crate::files::is_dir_cached(fs_path) {
            return;
        }
        let rules: &[ScopeRule] = vhost
            .map(|v| v.rules.as_slice())
            .unwrap_or(self.global_rules.as_slice());
        for rule in rules {
            if rule.condition.is_some() || rule.branch != ConditionBranch::Normal {
                continue;
            }
            let MatchKind::Directory(pattern) = &rule.kind else {
                continue;
            };
            let matched = match req {
                Some(req) => match directory_pattern_matches_exact_req(pattern, fs_path, req) {
                    Ok(matched) => matched,
                    Err(_) => {
                        scope.conditional_error = true;
                        return;
                    }
                },
                None => directory_pattern_matches_exact(pattern, fs_path),
            };
            if !matched {
                continue;
            }
            merge_rule_delta(scope, rule, fs_path, url_path);
            for nested in &rule.nested {
                defer_rule_by_verified_phase(nested, files, locations, conditionals);
            }
        }
    }

    /// the deferred conditional rules do.  Cache the normal scope and the
    /// matching conditional list, then apply the conditionals per request.
    pub fn effective_scope_req_cached(
        &self,
        vhost: Option<&VHost>,
        fs_path: &Path,
        url_path: &str,
        req: &crate::http::Request,
        peer: std::net::IpAddr,
    ) -> (Scope, Arc<Vec<ScopeRule>>) {
        let key = (
            vhost.map(|v| v as *const VHost as usize).unwrap_or(0),
            fs_path.to_path_buf(),
            url_path.to_string(),
        );
        if let Ok(guard) = self.policy_cache.read() {
            if let Some(cached) = guard.get(&key) {
                return (cached.scope.clone(), Arc::clone(&cached.conditionals));
            }
        }
        let mut conditionals = Vec::new();
        let scope = self.effective_scope_req_deferred(
            vhost,
            fs_path,
            url_path,
            req,
            peer,
            &mut conditionals,
        );
        let conditionals = Arc::new(conditionals);
        if let Ok(mut guard) = self.policy_cache.write() {
            guard.insert(
                key,
                Arc::new(CachedPolicy {
                    scope: scope.clone(),
                    conditionals: Arc::clone(&conditionals),
                }),
            );
        }
        (scope, conditionals)
    }

    pub fn effective_scope_req_deferred(
        &self,
        vhost: Option<&VHost>,
        fs_path: &Path,
        url_path: &str,
        req: &crate::http::Request,
        peer: std::net::IpAddr,
        deferred: &mut Vec<ScopeRule>,
    ) -> Scope {
        let (scope, conditionals) =
            crate::policy_ref::effective_scope_req(self, vhost, fs_path, url_path, req, peer);
        deferred.extend(conditionals);
        scope
    }

    /// Human-readable inventory of the matching top-level rules in canonical
    /// merge order.  This is for `--explain`; it does not evaluate runtime
    /// conditions or access-file sections.
    pub fn rule_inventory(
        &self,
        vhost: Option<&VHost>,
        fs_path: &Path,
        url_path: &str,
        req: &crate::http::Request,
        peer: std::net::IpAddr,
    ) -> Vec<String> {
        let rules: &[ScopeRule] = vhost
            .map(|v| v.rules.as_slice())
            .unwrap_or(self.global_rules.as_slice());
        let fname = fs_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        let base = vhost.map(|v| &v.scope).unwrap_or(&self.global);
        let env = base.authorization_env(req, url_path, peer);
        let docroot = self.documentation_root_for(vhost);
        let mut chain_state = HashMap::new();
        let mut out = Vec::new();
        fn walk(
            rules: &[ScopeRule],
            depth: usize,
            fs_path: &Path,
            url_path: &str,
            fname: &str,
            req: &crate::http::Request,
            env: &[(String, Vec<u8>)],
            peer: std::net::IpAddr,
            docroot: &Path,
            chain_state: &mut HashMap<usize, bool>,
            out: &mut Vec<String>,
        ) {
            for rule in rules {
                if !rule_kind_matches(&rule.kind, fs_path, url_path, fname) {
                    continue;
                }
                let conditional =
                    rule.condition.is_some() || rule.branch != ConditionBranch::Normal;
                let (matched, condition_error) = if conditional {
                    match rule_condition_result(
                        rule,
                        req,
                        env,
                        peer,
                        docroot,
                        url_path,
                        Some(fs_path),
                        chain_state,
                    ) {
                        Ok(matched) => (matched, None),
                        Err(error) => (false, Some(error)),
                    }
                } else {
                    (true, None)
                };
                let condition = if let Some(error) = condition_error {
                    format!(" condition=error({error})")
                } else if conditional {
                    format!(" condition={matched}")
                } else {
                    String::new()
                };
                out.push(format!(
                    "{} {:?} order={} kind={:?}{condition} nested={}",
                    " ".repeat(depth),
                    rule.phase(),
                    rule.order,
                    rule.kind,
                    rule.nested.len()
                ));
                if matched {
                    walk(
                        &rule.nested,
                        depth + 1,
                        fs_path,
                        url_path,
                        fname,
                        req,
                        env,
                        peer,
                        docroot,
                        chain_state,
                        out,
                    );
                }
            }
        }
        walk(
            rules,
            0,
            fs_path,
            url_path,
            &fname,
            req,
            &env,
            peer,
            &docroot,
            &mut chain_state,
            &mut out,
        );
        out
    }

    pub fn documentation_root_for(&self, vhost: Option<&VHost>) -> PathBuf {
        vhost
            .and_then(|v| v.scope.content_policy.document_root.clone())
            .or_else(|| self.global.content_policy.document_root.clone())
            .unwrap_or_else(|| self.document_root.clone())
    }

    pub fn directory_index_for(&self, scope: &Scope) -> Vec<String> {
        scope
            .content_policy
            .directory_index
            .clone()
            .unwrap_or_else(|| self.directory_index.clone())
    }

    pub fn access_file_names_for(&self, scope: &Scope) -> Vec<String> {
        scope
            .content_policy
            .access_file_names
            .clone()
            .unwrap_or_else(|| self.access_file_names.clone())
    }
}

pub(crate) fn vhost_port(addr: &str) -> u16 {
    let a = addr.trim();
    if a.starts_with("_default_") {
        return a
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(0);
    }
    if a.starts_with('[') {
        return a
            .rsplit_once("]:")
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(0);
    }
    match a.rsplit_once(':') {
        Some((_, p)) => p.parse().unwrap_or(0),
        None => 80,
    }
}

/// Precomputed index for literal `<Directory>` rules.  Wildcard patterns stay
/// in a fallback list because their match order is part of configuration
/// semantics.
#[derive(Debug, Clone, Default)]
pub struct DirectoryRuleIndex {
    exact: HashMap<PathBuf, Vec<usize>>,
    wildcard: Vec<usize>,
}

impl DirectoryRuleIndex {
    fn build(rules: &[ScopeRule]) -> Self {
        use std::os::unix::ffi::OsStrExt;
        let mut index = Self::default();
        for (i, rule) in rules.iter().enumerate() {
            if rule.condition.is_some() || rule.branch != ConditionBranch::Normal {
                continue;
            }
            let MatchKind::Directory(pattern) = &rule.kind else {
                continue;
            };
            let wildcard = pattern
                .as_os_str()
                .as_bytes()
                .iter()
                .any(|b| matches!(b, b'*' | b'?' | b'['));
            if wildcard {
                index.wildcard.push(i);
            } else {
                index.exact.entry(pattern.clone()).or_default().push(i);
            }
        }
        index
    }
}

// ---------------------------------------------------------------------------
// Pass-11 regression kernels (F61/F62/F63/F64)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pass11_kernel_tests {
    use super::*;

    // F61-A/A2/B: a `<Location>` argument with shell wildcards compiles to
    // the kernel matcher at parse time; the `~` regex form and the
    // `<Location ~>`-alone configuration error follow Apache's parse rules.

    fn location_kind(args: &[&str]) -> Result<MatchKind, String> {
        compile_location_pattern(&args.iter().map(|s| s.to_string()).collect::<Vec<String>>())
    }

    fn matched(kind: &MatchKind, url_path: &str) -> bool {
        rule_kind_matches(kind, Path::new("/srv/www/file"), url_path, "file")
    }

    #[test]
    fn location_wildcard_compiles_to_the_kernel_and_stays_component_bounded() {
        let kind = location_kind(&["/admin/*"]).unwrap();
        assert!(matches!(kind, MatchKind::LocationGlob(_)));
        // The kernel match is component-bounded and anchored: a sibling
        // script inside /admin is covered, deeper paths are not, and the
        // pattern cannot leak past the /admin prefix.
        assert!(matched(&kind, "/admin/run.cgi"));
        assert!(!matched(&kind, "/admin/a/b.cgi"));
        assert!(!matched(&kind, "/administry"));
        // `*` never crosses a `/`; `?` covers exactly one character inside
        // the component.
        let one = location_kind(&["/admin/?.cgi"]).unwrap();
        assert!(matched(&one, "/admin/x.cgi"));
        assert!(!matched(&one, "/admin/xy.cgi"));
        let class = location_kind(&["/admin/[a-z]un*"]).unwrap();
        assert!(matched(&class, "/admin/run.cgi"));
        // The wildcard never bridges the bare directory: `/zdir/*` matches
        // `/zdir/run.cgi` and the trailing-slash form (2.4.69 probe with
        // `DirectorySlash Off`), but not `/zdir` itself.
        let dir_star = location_kind(&["/zdir/*"]).unwrap();
        assert!(matched(&dir_star, "/zdir/run.cgi"));
        assert!(matched(&dir_star, "/zdir/"));
        assert!(!matched(&dir_star, "/zdir"));
    }

    #[test]
    fn location_regex_and_literal_forms_are_untouched() {
        let kind = location_kind(&["~", "^/nomatch/"]).unwrap();
        assert!(matches!(kind, MatchKind::LocationMatch(_)));
        let kind = location_kind(&["/admin"]).unwrap();
        assert!(matches!(kind, MatchKind::Location(_)));
        // `<Location ~>` with no expression is a configuration error (fail
        // closed), never an inert literal section.
        assert!(location_kind(&["~"]).is_err());
        assert!(location_kind(&[]).is_err());
        // A malformed regex is a configuration error too.
        assert!(location_kind(&["~", "(?=x"]).is_err());
    }

    #[test]
    fn legacy_tilde_section_forms_have_narrow_arity() {
        for name in ["directory", "location", "files"] {
            assert!(validate_config_section_arity(name, &["~".into(), "^x$".into()]).is_ok());
            assert!(validate_config_section_arity(name, &["x".into(), "y".into()]).is_err());
            assert!(validate_config_section_arity(name, &["~".into()]).is_err());
        }
        assert!(matches!(
            compile_files_pattern(&["~".into(), "^secret\\.".into()]).unwrap(),
            MatchKind::FilesMatch(_)
        ));
        assert!(compile_files_pattern(&["~".into()]).is_err());
    }

    // F62/F62b: `<Files>` class negation honors BOTH markers; `?` covers
    // exactly one character and `*` stays inside the basename.

    #[test]
    fn files_glob_negates_classes_with_bang_and_caret() {
        for pattern in ["[^a]*.cgi", "[!a]*.cgi"] {
            let kind = compile_files_pattern(&[pattern.into()]).unwrap();
            assert!(
                matches!(kind, MatchKind::FilesGlob(_)),
                "expected a kernel glob for {pattern}"
            );
            // The match is on the basename: a member name stays positive and
            // a non-member is negated into a match — with BOTH markers.
            assert!(
                rule_kind_matches(&kind, Path::new("/srv/zdir.cgi"), "/zdir.cgi", "zdir.cgi"),
                "{pattern} must negate and match zdir.cgi"
            );
            assert!(
                !rule_kind_matches(&kind, Path::new("/srv/adir.cgi"), "/adir.cgi", "adir.cgi"),
                "{pattern} must not match its own class member"
            );
        }
        // `?.cgi` matches 5 characters, not 7.
        let kind = compile_files_pattern(&["?.cgi".into()]).unwrap();
        assert!(rule_kind_matches(
            &kind,
            Path::new("/x.cgi"),
            "/x.cgi",
            "x.cgi"
        ));
        assert!(!rule_kind_matches(
            &kind,
            Path::new("/longer.cgi"),
            "/longer.cgi",
            "longer.cgi"
        ));
        // `*x*` matches within the basename.
        let kind = compile_files_pattern(&["*x*".into()]).unwrap();
        assert!(rule_kind_matches(
            &kind,
            Path::new("/a/bx.c"),
            "/a/bx.c",
            "bx.c"
        ));
        assert!(!rule_kind_matches(
            &kind,
            Path::new("/a/b.c"),
            "/a/b.c",
            "b.c"
        ));
    }

    // F64: `SetHandler` precedence — it wins over AddHandler regardless of
    // directive order, inheritance and merge direction.

    fn handler_scope(text: &str) -> Scope {
        let cfg = load_text_direct(&format!("Listen 127.0.0.1:0\n{text}"));
        cfg.effective_scope(None, Path::new("/srv/www/x.cgi"), "/x.cgi")
    }

    fn load_text_direct(text: &str) -> Config {
        static NEXT_FIXTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let fixture = NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("vapache-pass11-{}-{fixture}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("httpd.conf");
        std::fs::write(&path, format!("{}{text}", TEST_CAPABILITIES)).unwrap();
        Config::load(&path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    #[test]
    fn fastcgi_stable_path_policy_is_explicit_global_and_fail_closed() {
        let cfg = load_text_direct(
            "Listen 127.0.0.1:0\nVapacheFastCGIStablePath On unix:/run/php/a.sock 33 0 0 1001 0\nVapacheFastCGIStablePath On unix:/run/php/b.sock 34 0 0\n",
        );
        assert_eq!(
            cfg.fastcgi_stable_paths,
            Some(vec![
                FastCgiStablePathPolicy {
                    endpoint: FastCgiEndpoint::Unix(PathBuf::from("/run/php/a.sock")),
                    backend_uid: 33,
                    endpoint_owner_uid: Some(0),
                    trusted_owner_uids: vec![0, 1001],
                },
                FastCgiStablePathPolicy {
                    endpoint: FastCgiEndpoint::Unix(PathBuf::from("/run/php/b.sock")),
                    backend_uid: 34,
                    endpoint_owner_uid: Some(0),
                    trusted_owner_uids: vec![0],
                },
            ])
        );
        let cfg = load_text_direct(
            "Listen 127.0.0.1:0\nVapacheFastCGIStablePath On unix:/run/php/a.sock 33 0 0\nVapacheFastCGIStablePath Off\n",
        );
        assert_eq!(cfg.fastcgi_stable_paths, None);

        let dir = std::env::temp_dir().join(format!(
            "vapache-fastcgi-stable-config-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (i, text) in [
            "VapacheFastCGIStablePath On unix:/run/php/a.sock 0 0 0\n",
            "VapacheFastCGIStablePath On unix:/run/php/a.sock nope 0 0\n",
            "VapacheFastCGIStablePath On unix:relative.sock 33 0 0\n",
            "VapacheFastCGIStablePath On unix:/run/php/a.sock 33 - 0\n",
            "VapacheFastCGIStablePath On fcgi://127.0.0.1:9000 33 - 0\n",
            "VapacheFastCGIStablePath On fcgi://127.0.0.1:9000 33 0 0\n",
            "VapacheFastCGIStablePath On unix:/run/php/a.sock 33 0 0\nVapacheFastCGIStablePath On unix:/run/php/a.sock 34 0 0\n",
            "VapacheFastCGIStablePath Off 33\n",
            "<Directory /srv>\nVapacheFastCGIStablePath On unix:/run/php/a.sock 33 0 0\n</Directory>\n",
            "<VirtualHost *:80>\nVapacheFastCGIStablePath On unix:/run/php/a.sock 33 0 0\n</VirtualHost>\n",
        ]
        .into_iter()
        .enumerate()
        {
            let path = dir.join(format!("invalid-{i}.conf"));
            std::fs::write(&path, format!("Listen 127.0.0.1:0\n{text}")).unwrap();
            assert!(
                Config::load(&path, &dir, &HashMap::new(), &HashMap::new(), false).is_err(),
                "configuration unexpectedly accepted: {text}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn aggregate_resource_limits_are_positive_and_global() {
        let cfg = load_text_direct(
            "Listen 127.0.0.1:0\nVapacheMaxSpoolBytes 4096\nVapacheMaxSpoolFiles 3\nVapacheMaxDynamicRequests 2\nVapacheMaxFastCGIOutput 1024\n",
        );
        assert_eq!(cfg.max_spool_bytes, 4096);
        assert_eq!(cfg.max_spool_files, 3);
        assert_eq!(cfg.max_dynamic_requests, 2);
        assert_eq!(cfg.max_fastcgi_output, 1024);
        for text in [
            "VapacheMaxSpoolBytes 0\n",
            "VapacheMaxSpoolFiles nope\n",
            "VapacheMaxDynamicRequests 1 2\n",
            "<VirtualHost *:80>\nVapacheMaxFastCGIOutput 1\n</VirtualHost>\n",
        ] {
            let dir = std::env::temp_dir()
                .join(format!("vapache-resource-config-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("invalid.conf");
            std::fs::write(&path, format!("Listen 127.0.0.1:0\n{text}")).unwrap();
            assert!(Config::load(&path, &dir, &HashMap::new(), &HashMap::new(), false).is_err());
        }
    }

    #[test]
    fn request_worker_configuration_has_an_implementation_ceiling() {
        let cfg = load_text_direct(&format!(
            "Listen 127.0.0.1:0\nServerLimit {MAX_IMPLEMENTED_REQUEST_WORKERS}\nMaxRequestWorkers {MAX_IMPLEMENTED_REQUEST_WORKERS}\n"
        ));
        assert_eq!(cfg.max_request_workers, MAX_IMPLEMENTED_REQUEST_WORKERS);

        for text in [
            format!(
                "ServerLimit {}\nMaxRequestWorkers 1\n",
                MAX_IMPLEMENTED_REQUEST_WORKERS + 1
            ),
            format!(
                "ServerLimit {MAX_IMPLEMENTED_REQUEST_WORKERS}\nMaxRequestWorkers {}\n",
                MAX_IMPLEMENTED_REQUEST_WORKERS + 1
            ),
        ] {
            let dir = std::env::temp_dir().join(format!(
                "vapache-worker-ceiling-{}-{}",
                std::process::id(),
                text.len()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("invalid.conf");
            std::fs::write(&path, format!("Listen 127.0.0.1:0\n{text}")).unwrap();
            assert!(Config::load(&path, &dir, &HashMap::new(), &HashMap::new(), false).is_err());
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn set_handler_beats_add_handler_in_both_orders() {
        assert_eq!(SetHandler::parse("handler").name(), Some("handler"));
        assert_eq!(SetHandler::parse("NONE").name(), None);
        for text in [
            "<Directory /srv>\nSetHandler default-handler\nAddHandler cgi-script .cgi\n</Directory>\n",
            "<Directory /srv>\nAddHandler cgi-script .cgi\nSetHandler default-handler\n</Directory>\n",
        ] {
            let scope = handler_scope(text);
            assert_eq!(
                effective_handler(&scope, b"x.cgi"),
                Some("default-handler"),
                "SetHandler must win: {text}"
            );
        }
        // The reverse force: SetHandler cgi-script wins over a RemoveHandler.
        let scope = handler_scope(
            "<Directory /srv>\nRemoveHandler .cgi\nSetHandler cgi-script\n</Directory>\n",
        );
        assert_eq!(effective_handler(&scope, b"x.cgi"), Some("cgi-script"));
    }

    #[test]
    fn handler_extensions_require_a_real_suffix_and_removals_win() {
        let mut scope = Scope::default();
        scope
            .mapping_policy
            .handlers
            .push(Handler::add("cgi".into(), "cgi-script".into()));
        for name in [b"cgi".as_slice(), b".cgi", b"..cgi"] {
            assert_eq!(effective_handler(&scope, name), None, "{name:?}");
        }
        assert_eq!(effective_handler(&scope, b"..."), None);
        for name in [b"run.cgi".as_slice(), b"run.cgi.txt", b"run.cgi."] {
            assert_eq!(
                effective_handler(&scope, name),
                Some("cgi-script"),
                "{name:?}"
            );
        }
        assert_eq!(
            effective_handler(&scope, b"run.\xff.cgi"),
            Some("cgi-script")
        );

        scope
            .mapping_policy
            .handlers
            .push(Handler::add("*".into(), "literal-star".into()));
        assert_eq!(effective_handler(&scope, b"run.txt"), None);
        assert_eq!(effective_handler(&scope, b"run.*"), Some("literal-star"));

        for handlers in [
            vec![
                Handler::remove("cgi".into()),
                Handler::add("cgi".into(), "cgi-script".into()),
            ],
            vec![
                Handler::add("cgi".into(), "cgi-script".into()),
                Handler::remove("cgi".into()),
            ],
        ] {
            let mut denied = Scope::default();
            denied.mapping_policy.handlers = handlers;
            assert_eq!(effective_handler(&denied, b"run.cgi"), None);
        }

        let parsed = handler_scope("<Directory /srv>\nAddHandler cgi-script ..cgi\n</Directory>\n");
        assert_eq!(parsed.mapping_policy.handlers[0].ext, ".cgi");
        assert_eq!(effective_handler(&parsed, b"run.cgi"), None);
    }

    #[test]
    fn set_handler_none_falls_back_to_the_extension_table() {
        // A child `SetHandler None` clears the parent's force; the extension
        // table then applies (2.4.69 probe: the AddHandler grant returns).
        let cfg = load_text_direct(
            "Listen 127.0.0.1:0\n\
             <Directory /srv>\n\
             SetHandler default-handler\n\
             </Directory>\n\
             <Directory /srv/sub>\n\
             SetHandler None\n\
             AddHandler cgi-script .cgi\n\
             </Directory>\n",
        );
        let s = cfg.effective_scope(None, Path::new("/srv/sub/x.cgi"), "/sub/x.cgi");
        assert_eq!(s.mapping_policy.set_handler, Some(SetHandler::None_));
        assert_eq!(effective_handler(&s, b"x.cgi"), Some("cgi-script"));
        // Without the child override the parent force still governs.
        let s = cfg.effective_scope(None, Path::new("/srv/www/x.cgi"), "/x.cgi");
        assert_eq!(
            s.mapping_policy.set_handler,
            Some(SetHandler::Name("default-handler".into()))
        );
        assert_eq!(effective_handler(&s, b"x.cgi"), Some("default-handler"));
    }

    #[test]
    fn restricted_scopes_conjoin_set_handler_forces() {
        let mut base = Scope::default();
        base.mapping_policy.set_handler = Some(SetHandler::Name("default-handler".into()));
        let mut target = Scope::default();
        target
            .mapping_policy
            .handlers
            .push(Handler::add("upload".into(), "cgi-script".into()));
        // F64: the attacker chain (an .htaccess `AddHandler` upload) cannot
        // execute when the URL identity forces another handler.
        target.restrict_with(&base);
        assert_eq!(
            effective_handler(&target, b"shell.upload"),
            Some("default-handler")
        );
        // An explicit target `SetHandler None` cannot clear the force either.
        let mut target = Scope::default();
        target.mapping_policy.set_handler = Some(SetHandler::None_);
        target
            .mapping_policy
            .handlers
            .push(Handler::add("upload".into(), "cgi-script".into()));
        target.restrict_with(&base);
        assert_eq!(
            effective_handler(&target, b"shell.upload"),
            Some("default-handler")
        );
        // Conflicting forces degrade to no force (the conjoined extension
        // table still governs), never to one side's name.
        let mut conflicting = Scope::default();
        conflicting.mapping_policy.set_handler = Some(SetHandler::Name("cgi-script".into()));
        conflicting.restrict_with(&base);
        assert_eq!(
            conflicting.mapping_policy.set_handler,
            Some(SetHandler::None_)
        );
        // A target-only force wins when the URL identity has none.
        let mut target_only = Scope::default();
        target_only.mapping_policy.set_handler = Some(SetHandler::Name("cgi-script".into()));
        target_only.restrict_with(&Scope::default());
        assert_eq!(
            target_only.mapping_policy.set_handler,
            Some(SetHandler::Name("cgi-script".into()))
        );

        let mut denied = Scope::default();
        denied.mapping_policy.set_handler = Some(SetHandler::Name("cgi-script".into()));
        let mut url_none = Scope::default();
        url_none.mapping_policy.set_handler = Some(SetHandler::None_);
        denied.restrict_with(&url_none);
        assert_eq!(
            denied.mapping_policy.set_handler,
            Some(SetHandler::Name("none".into()))
        );
    }

    #[test]
    fn request_policy_cache_is_byte_bounded_without_wholesale_clear() {
        let mut cache = BoundedPolicyCache::<Scope>::default();
        for index in 0..(POLICY_CACHE_MAX_ENTRIES + 32) {
            cache.insert(
                (
                    0,
                    PathBuf::from(format!("/tmp/{index}")),
                    format!("/{}-{index}", "x".repeat(8192)),
                ),
                Arc::new(Scope::default()),
            );
        }
        assert!(cache.entries.len() <= POLICY_CACHE_MAX_ENTRIES);
        assert!(cache.bytes <= POLICY_CACHE_MAX_BYTES);
        assert!(!cache.entries.is_empty());
    }
}
