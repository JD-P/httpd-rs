//! Native FastCGI responder for PHP-FPM and compatible backends.
//!
//! Supports the common Apache `mod_proxy_fcgi` forms:
//!
//! ```text
//! ProxyPassMatch ^/(.*\.php(/.*)?)$ unix:/run/php/php-fpm.sock|fcgi://localhost/var/www/html/
//! SetHandler "proxy:unix:/run/php/php-fpm.sock|fcgi://localhost"
//! SetHandler "proxy:fcgi://127.0.0.1:9000"
//! ```
//!
//! The implementation is deliberately buffered: a FastCGI response is parsed
//! through the same validated CGI header path as local CGI.  That keeps header
//! splitting, status handling and compression consistent across both paths.

use crate::cgi::{self, CgiContext};
use crate::config::{Config, FastCgiEndpoint, FastCgiStablePathPolicy, Scope};
use crate::http::{Body, Request, Response};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::{FromRawFd, RawFd};
#[cfg(test)]
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const FCGI_VERSION: u8 = 1;
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;
const FCGI_RESPONDER: u16 = 1;
const DEFAULT_MAX_FASTCGI_OUTPUT: u64 = 64 * 1024 * 1024;
const FASTCGI_SPOOL_THRESHOLD: usize = 1024 * 1024;
const MAX_FASTCGI_RECORDS: u64 = 8192;
const MAX_FASTCGI_FRAMING_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
enum Transport {
    Unix(PathBuf),
    Tcp(String, u16),
}

#[derive(Clone, Debug)]
pub struct Backend {
    transport: Transport,
    prefix: String,
}

impl Backend {
    fn endpoint(&self) -> FastCgiEndpoint {
        match &self.transport {
            Transport::Unix(path) => FastCgiEndpoint::Unix(path.clone()),
            Transport::Tcp(host, port) => FastCgiEndpoint::Tcp {
                host: host.to_ascii_lowercase(),
                port: *port,
            },
        }
    }
}

mod lexical_script_path {
    use super::{script_from_prefix, split_path_info_with_request, Backend};
    use std::path::{Path, PathBuf};

    /// Path identity presented to the FastCGI backend. The tuple field is
    /// private to this child module, so production code cannot wrap an
    /// authorization/canonical path and call it lexical. Every value comes
    /// from the request mapping constructor below (P15/P17).
    #[derive(Clone, Debug)]
    pub(super) struct LexicalScriptPath(PathBuf);

    impl LexicalScriptPath {
        pub(super) fn from_mapping(
            backend: &Backend,
            root: &Path,
            rel: &Path,
        ) -> Option<(Self, PathBuf)> {
            let (path, base) = script_from_prefix(backend, root, rel)?;
            Some((Self(path), base))
        }

        pub(super) fn split_path_info(
            self,
            url_path: &str,
            base: &Path,
            req: Option<&crate::http::Request>,
        ) -> Option<(Self, String, String)> {
            let (path, script_name, path_info) =
                split_path_info_with_request(self.0, url_path, base, req)?;
            Some((Self(path), script_name, path_info))
        }

        pub(super) fn matches_mapping(&self, backend: &Backend, root: &Path, rel: &Path) -> bool {
            script_from_prefix(backend, root, rel)
                .map(|(expected, _)| expected == self.0)
                .unwrap_or(false)
        }

        pub(super) fn as_path(&self) -> &Path {
            &self.0
        }

        #[cfg(test)]
        pub(super) fn for_test(path: PathBuf) -> Self {
            Self(path)
        }
    }
}

use lexical_script_path::LexicalScriptPath;

#[derive(Clone, Debug)]
pub struct Target {
    backend: Backend,
    script_filename: LexicalScriptPath,
    pub script_name: String,
    pub path_info: String,
    pub route_order: usize,
    pub logical_url: Option<String>,
}

impl Target {
    pub(crate) fn script_filename(&self) -> &Path {
        self.script_filename.as_path()
    }

    #[cfg(test)]
    pub(crate) fn replace_script_filename_for_test(&mut self, path: PathBuf) {
        self.script_filename = LexicalScriptPath::for_test(path);
    }

    /// Exact FastCGI transport plus both script identities used for resource
    /// binding. `script_filename` is the lexical Apache-compatible value sent
    /// to the backend; `authorized_path` is the canonical opened object whose
    /// inode and policy were authorized (P15-A).
    pub(crate) fn binding_key(&self, authorized_path: &Path) -> String {
        let transport = match &self.backend.transport {
            Transport::Unix(path) => format!("unix:{}", path.display()),
            Transport::Tcp(host, port) => format!("tcp:{host}:{port}"),
        };
        format!(
            "{transport}|lexical={}|authorized={}|{}|{}",
            self.script_filename().display(),
            authorized_path.display(),
            self.script_name,
            self.path_info
        )
    }
}

/// Descriptor-first binding for the local script object named by a FastCGI
/// target.  The backend still receives `SCRIPT_FILENAME` (the FastCGI
/// protocol has no descriptor-passing primitive), but selection,
/// authorization and the last pre-send identity check all use this opened
/// inode.
pub(crate) struct ScriptBinding {
    pub(crate) file: File,
    pub(crate) meta: std::fs::Metadata,
    pub(crate) actual_path: PathBuf,
}

pub(crate) fn open_script(
    target: &Target,
    root: &Path,
    follow_symlinks: bool,
    owner_match_only: bool,
) -> Option<ScriptBinding> {
    let base = fastcgi_script_base(&target.backend, root);
    let rel = target.script_filename().strip_prefix(&base).ok()?;
    let crate::files::Target::File { file, meta } =
        crate::files::resolve_target_checked(&base, rel, follow_symlinks, owner_match_only)
    else {
        return None;
    };
    let actual_path = crate::files::fd_path(&file)?;
    let actual_base = std::fs::canonicalize(&base).ok()?;
    if !script_under_base(&actual_path, &actual_base) {
        return None; // coverage:ignore-line -- resolve_target_checked enforces beneath base
    }
    Some(ScriptBinding {
        file,
        meta,
        actual_path,
    })
}

fn parse_backend(value: &str) -> Option<Backend> {
    let value = value.trim();
    let value = value.strip_prefix("proxy:").unwrap_or(value);
    if let Some(rest) = value.strip_prefix("unix:") {
        let (sock, url) = match rest.split_once('|') {
            Some((sock, url)) => (sock, url),
            None => (rest, ""),
        };
        if sock.is_empty() {
            return None;
        }
        let prefix = if url.is_empty() {
            String::new()
        } else {
            let url = url.strip_prefix("fcgi://")?;
            let (_, _, path) = split_host_path(url)?;
            path
        };
        return Some(Backend {
            transport: Transport::Unix(PathBuf::from(sock)),
            prefix,
        });
    }
    let rest = value.strip_prefix("fcgi://")?;
    let (host, port, path) = split_host_path(rest)?;
    Some(Backend {
        transport: Transport::Tcp(host, port),
        prefix: path,
    })
}

fn split_host_path(rest: &str) -> Option<(String, u16, String)> {
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, String::new()),
    };
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = rest[..close].to_string();
        let suffix = &rest[close + 1..];
        let port = if suffix.is_empty() {
            9000
        } else {
            suffix.strip_prefix(':')?.parse().ok()?
        };
        (host, port)
    } else {
        if hostport.matches(':').count() > 1 {
            return None;
        }
        match hostport.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), port.parse().ok()?),
            None => (hostport.to_string(), 9000),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path))
}

fn clean_script_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        use std::path::Component::*;
        match component {
            Prefix(_) | RootDir => out.push(component.as_os_str()),
            CurDir => {}
            ParentDir => {
                out.pop();
            }
            Normal(name) => out.push(name),
        }
    }
    out
}

/// Component-aware containment consumed by FastCGI script construction and
/// the `PATH_INFO` ancestor walk.  This is the verified kernel shared with
/// alias/rewrite mapping; `/srv/www2/x.php` is not below `/srv/www`.
fn script_under_base(script: &Path, base: &Path) -> bool {
    vapache_verified::path_under_base(
        script.as_os_str().as_encoded_bytes(),
        base.as_os_str().as_encoded_bytes(),
    )
}

/// Stable directory that bounds a FastCGI script target.  A configured
/// `fcgi://.../prefix/` names the base; a `$1` template is bounded by the
/// literal prefix before the first capture.  With no prefix the request's
/// document/alias root is the base.
fn fastcgi_script_base(backend: &Backend, root: &Path) -> PathBuf {
    let raw = if let Some(cut) = backend.prefix.find("$1") {
        backend.prefix[..cut].trim_end_matches('/')
    } else if !backend.prefix.is_empty() && backend.prefix != "/" {
        backend.prefix.trim_end_matches('/')
    } else {
        return clean_script_path(root);
    };
    if raw.is_empty() {
        return clean_script_path(root);
    }
    let raw = PathBuf::from(raw);
    let base = if raw.is_absolute() {
        raw
    } else {
        root.join(raw)
    };
    clean_script_path(&base)
}

fn script_from_prefix(backend: &Backend, root: &Path, rel: &Path) -> Option<(PathBuf, PathBuf)> {
    let rel_text = rel.to_string_lossy().trim_start_matches('/').to_string();
    let raw = if backend.prefix.contains("$1") {
        PathBuf::from(backend.prefix.replace("$1", &rel_text))
    } else if !backend.prefix.is_empty() && backend.prefix != "/" {
        PathBuf::from(format!(
            "{}/{}",
            backend.prefix.trim_end_matches('/'),
            rel_text
        ))
    } else {
        root.join(rel)
    };
    let raw = if raw.is_absolute() {
        raw
    } else {
        root.join(raw)
    };
    let base = fastcgi_script_base(backend, root);
    let script = clean_script_path(&raw);
    // A capture, suffix or template must never turn the script filename into
    // an absolute path outside the configured FastCGI/docroot base.
    if !script_under_base(&script, &base) {
        return None;
    }
    Some((script, base))
}

fn contained_after_resolving_symlinks(candidate: &Path, base: &Path) -> bool {
    let Ok(base) = std::fs::canonicalize(base) else {
        return false;
    };
    let Ok(candidate) = std::fs::canonicalize(candidate) else {
        return false;
    };
    script_under_base(&candidate, &base)
}

/// Split `PATH_INFO` from a FastCGI script target by finding the longest
/// existing file prefix, matching PHP-FPM's `ProxyPassMatch` convention.  This
/// also makes the authorization target the real script rather than the
/// synthesized `/index.php/extra` path.  The ancestor walk is bounded by the
/// configured script base and every selected file is resolved to reject
/// symlinks that leave that base while preserving the requested script path
/// for policy evaluation.
#[cfg(test)]
fn split_path_info(
    script_filename: PathBuf,
    url_path: &str,
    base: &Path,
) -> Option<(PathBuf, String, String)> {
    split_path_info_with_request(script_filename, url_path, base, None)
}

fn split_path_info_with_request(
    script_filename: PathBuf,
    url_path: &str,
    base: &Path,
    req: Option<&Request>,
) -> Option<(PathBuf, String, String)> {
    let script_filename = clean_script_path(&script_filename);
    if !script_under_base(&script_filename, base) {
        return None;
    }
    // FastCGI paths can be synthesized from regex captures rather than the
    // ordinary document-root mapping. Admit them against the same global
    // component/cumulative-prefix bound before doing any filesystem walk.
    if crate::util::validate_policy_path(&script_filename).is_err() {
        if let Some(req) = req {
            let _ = req.charge_policy_work(u64::MAX);
        }
        return None;
    }
    let charge_probe = |path: &Path| {
        req.is_none_or(|req| {
            req.charge_policy_work(
                (path.as_os_str().as_encoded_bytes().len() as u64).saturating_add(1),
            )
            .is_ok()
        })
    };
    if !charge_probe(&script_filename) {
        return None;
    }
    if script_filename.is_file() {
        if !contained_after_resolving_symlinks(&script_filename, base) {
            return None;
        }
        return Some((script_filename, url_path.to_string(), String::new()));
    }
    let original = script_filename.clone();
    let mut candidate = script_filename;
    let mut suffix = Vec::new();
    loop {
        // Never walk above the configured base, even when an ancestor happens
        // to be a regular file (for example /bin/sh).
        if let Some(name) = candidate.file_name() {
            suffix.push(name.to_string_lossy().into_owned());
        }
        if !candidate.pop() || !script_under_base(&candidate, base) {
            break;
        }
        if !charge_probe(&candidate) {
            return None;
        }
        if candidate.is_file() {
            if !contained_after_resolving_symlinks(&candidate, base) {
                return None;
            }
            suffix.reverse();
            let info = format!("/{}", suffix.join("/"));
            let name = url_path.strip_suffix(&info).unwrap_or(url_path).to_string();
            return Some((candidate, name, info));
        }
    }
    script_under_base(&original, base).then_some((original, url_path.to_string(), String::new()))
}

fn prefix_suffix<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    crate::util::route_prefix_suffix(prefix, path)
}

/// Match a `ProxyPassMatch` (or a prefix `ProxyPass` with a FastCGI backend)
/// against the final URL path.
pub fn match_proxy(scope: &Scope, url_path: &str, root: &Path) -> Option<Target> {
    match_proxy_inner(scope, url_path, root, None)
}

pub(crate) fn match_proxy_for_request(
    scope: &Scope,
    url_path: &str,
    root: &Path,
    req: &Request,
) -> Option<Target> {
    match_proxy_inner(scope, url_path, root, Some(req))
}

fn match_proxy_inner(
    scope: &Scope,
    url_path: &str,
    root: &Path,
    req: Option<&Request>,
) -> Option<Target> {
    let mut best: Option<Target> = None;
    for rule in &scope.proxy_policy.proxy_passes {
        if req.is_some_and(|req| {
            req.charge_policy_work(
                (rule.prefix.len() as u64)
                    .saturating_add(url_path.len() as u64)
                    .saturating_add(1),
            )
            .is_err()
        }) {
            return None;
        }
        let Some(suffix) = prefix_suffix(&rule.prefix, url_path) else {
            continue;
        };
        let Some(backend) = parse_backend(&rule.backend) else {
            continue;
        };
        let rel = PathBuf::from(suffix);
        let Some((script_filename, base)) = LexicalScriptPath::from_mapping(&backend, root, &rel)
        else {
            continue;
        };
        let Some((script_filename, script_name, path_info)) =
            script_filename.split_path_info(url_path, &base, req)
        else {
            continue;
        };
        let candidate = Target {
            backend,
            script_filename,
            script_name,
            path_info,
            route_order: rule.route_order,
            logical_url: Some(format!(
                "{}/{}",
                rule.backend.trim_end_matches('/'),
                suffix.trim_start_matches('/')
            )),
        };
        if best
            .as_ref()
            .map(|b| candidate.route_order < b.route_order)
            .unwrap_or(true)
        {
            best = Some(candidate);
        }
    }
    for rule in &scope.proxy_policy.proxy_rules {
        if req.is_some_and(|req| {
            req.charge_policy_work(
                (rule.pattern.as_str().len() as u64)
                    .saturating_add(url_path.len() as u64)
                    .saturating_add(1),
            )
            .is_err()
        }) {
            return None;
        }
        let caps = match rule.pattern.captures(url_path.as_bytes()) {
            Some(c) => c,
            None => continue,
        };
        let backend = match parse_backend(&rule.backend) {
            Some(b) => b,
            None => continue,
        };
        let rel_text = caps
            .get(1)
            .or_else(|| caps.get(0))
            .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
            .unwrap_or_else(|| url_path.to_string());
        let rel_text = rel_text.trim_start_matches('/');
        let rel_capture = PathBuf::from(rel_text);
        let Some((script_filename, base)) =
            LexicalScriptPath::from_mapping(&backend, root, &rel_capture)
        else {
            continue;
        };
        let Some((script_filename, script_name, path_info)) =
            script_filename.split_path_info(url_path, &base, req)
        else {
            continue;
        };
        let capture = caps
            .get(1)
            .or_else(|| caps.get(0))
            .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
            .unwrap_or_else(|| url_path.to_string());
        let logical_url = rule.backend.replace("$1", &capture);
        let candidate = Target {
            backend,
            script_filename,
            script_name,
            path_info,
            route_order: rule.route_order,
            logical_url: Some(logical_url),
        };
        if best
            .as_ref()
            .map(|b| candidate.route_order < b.route_order)
            .unwrap_or(true)
        {
            best = Some(candidate);
        }
    }
    best
}

/// Match a `SetHandler "proxy:fcgi://..."` handler for an existing file.
pub fn handler_target(scope: &Scope, root: &Path, rel: &Path, url_path: &str) -> Option<Target> {
    let name = rel.file_name().map(|n| n.as_encoded_bytes()).unwrap_or(b"");
    let handler = crate::config::effective_handler(scope, name)?;
    if !handler.starts_with("proxy:") {
        return None;
    }
    let backend = parse_backend(handler)?;
    let (script_filename, base) = LexicalScriptPath::from_mapping(&backend, root, rel)?;
    if script_filename.as_path().is_file()
        && !contained_after_resolving_symlinks(script_filename.as_path(), &base)
    {
        return None;
    }
    Some(Target {
        backend,
        script_filename,
        script_name: url_path.to_string(),
        path_info: String::new(),
        route_order: usize::MAX,
        logical_url: Some(handler.to_string()),
    })
}

/// Handler selection for a resolved file. `lexical_path` and `name` are the
/// request-mapped identities used for the FastCGI wire path and handler
/// classification. `actual_path` is the canonical opened object and is used
/// only for containment and authorization (P13/P15/P17).
pub(crate) fn handler_target_for_file(
    scope: &Scope,
    root: &Path,
    url_path: &str,
    lexical_path: &Path,
    actual_path: &Path,
    name: &[u8],
) -> Option<Target> {
    let handler = crate::config::effective_handler(scope, name)?;
    if !handler.starts_with("proxy:") {
        return None;
    }
    let backend = parse_backend(handler)?;
    let rel = lexical_path.strip_prefix(root).ok()?;
    let (script_filename, base) = LexicalScriptPath::from_mapping(&backend, root, rel)?;
    let authorized_path = clean_script_path(actual_path);
    let name_is_lexical = lexical_path
        .file_name()
        .map(|value| value.as_encoded_bytes())
        .unwrap_or(b"")
        == name;
    if !vapache_verified::fastcgi_resolved_target_admit(
        name_is_lexical,
        script_filename.matches_mapping(&backend, root, rel),
        script_under_base(script_filename.as_path(), &base),
        script_under_base(&authorized_path, &base),
    ) {
        return None;
    }
    if script_filename.as_path().is_file()
        && !contained_after_resolving_symlinks(script_filename.as_path(), &base)
    {
        return None;
    }
    Some(Target {
        backend,
        script_filename,
        script_name: url_path.to_string(),
        path_info: String::new(),
        route_order: usize::MAX,
        logical_url: Some(handler.to_string()),
    })
}

fn stable_policy_for<'a>(
    cfg: &'a Config,
    backend: &Backend,
) -> io::Result<Option<&'a FastCgiStablePathPolicy>> {
    let Some(policies) = &cfg.fastcgi_stable_paths else {
        return if vapache_verified::capability_admit(
            cfg.capability_enabled(crate::config::Capability::UnstableFastCgiPaths),
            true,
        ) {
            Ok(None)
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "FastCGI requires VapacheFastCGIStablePath; enabling UnstableFastCgiPaths explicitly accepts the external pathname race",
            ))
        };
    };
    policies
        .iter()
        .find(|policy| policy.endpoint == backend.endpoint())
        .map(Some)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "FastCGI backend has no exact stable-path policy",
            )
        })
}

fn validate_unix_endpoint(
    policy: &FastCgiStablePathPolicy,
    path: &Path,
) -> io::Result<std::fs::Metadata> {
    let Some(parent) = path.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "FastCGI Unix endpoint has no parent directory",
        ));
    };
    enforce_stable_fastcgi_path(policy, parent)?;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_socket() || Some(meta.uid()) != policy.endpoint_owner_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "FastCGI Unix endpoint type or owner changed",
        ));
    }
    if path_has_posix_acl(path)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "FastCGI Unix endpoint has a POSIX ACL",
        ));
    }
    Ok(meta)
}

fn connect_unix_timeout(path: &Path, deadline: Instant) -> io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: every bit pattern is valid for sockaddr_un; this temporary is
    // used only to obtain the platform sun_path capacity.
    let capacity = unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
        .sun_path
        .len();
    if bytes.is_empty() || bytes.len() >= capacity || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid FastCGI Unix socket path",
        ));
    }
    // SAFETY: socket has no pointer operands. A successful descriptor is
    // immediately placed under the guard below.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    struct FdGuard(RawFd);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            // SAFETY: FdGuard exclusively owns this successfully-created fd.
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let guard = FdGuard(fd);
    // SAFETY: zero is a valid initial representation for sockaddr_un and its
    // family/path fields are initialized before the kernel observes it.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // SAFETY: bytes was checked strictly shorter than sun_path above, and the
    // source and destination are distinct live allocations.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            address.sun_path.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        );
    }
    let address_len = std::mem::offset_of!(libc::sockaddr_un, sun_path)
        .saturating_add(bytes.len())
        .saturating_add(1) as libc::socklen_t;
    // SAFETY: address remains live for the call and address_len covers only
    // the initialized family, pathname bytes and trailing zero byte.
    let connected = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            address_len,
        )
    };
    if connected != 0 {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(code) if code == libc::EINPROGRESS || code == libc::EAGAIN
        ) {
            return Err(error);
        }
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "FastCGI Unix connection deadline exceeded",
                ));
            }
            let wait = remaining.as_millis().max(1).min(i32::MAX as u128) as i32;
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: poll points to one live pollfd, matching nfds=1.
            let result = unsafe { libc::poll(&mut poll, 1, wait) };
            if result == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "FastCGI Unix connection deadline exceeded",
                ));
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let mut socket_error: libc::c_int = 0;
            let mut length = std::mem::size_of_val(&socket_error) as libc::socklen_t;
            // SAFETY: both output pointers are live and length describes the
            // exact c_int buffer supplied to getsockopt.
            if unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut socket_error as *mut libc::c_int).cast(),
                    &mut length,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if socket_error != 0 {
                return Err(io::Error::from_raw_os_error(socket_error));
            }
            break;
        }
    }
    // SAFETY: fd remains exclusively owned by guard and both fcntl commands
    // use the argument shape required by F_GETFL/F_SETFL.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    std::mem::forget(guard);
    // SAFETY: guard ownership was deliberately transferred after every
    // fallible setup step; UnixStream is now the descriptor's sole owner.
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

fn connect(
    backend: &Backend,
    timeout: Duration,
    policy: Option<&FastCgiStablePathPolicy>,
) -> io::Result<Box<dyn ReadWrite>> {
    let deadline = Instant::now() + timeout;
    match &backend.transport {
        Transport::Unix(path) => {
            let before = policy
                .map(|policy| validate_unix_endpoint(policy, path))
                .transpose()?;
            let s = connect_unix_timeout(path, deadline)?;
            if let (Some(policy), Some(before)) = (policy, before) {
                let after = validate_unix_endpoint(policy, path)?;
                if before.dev() != after.dev()
                    || before.ino() != after.ino()
                    || before.uid() != after.uid()
                    || before.mode() != after.mode()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "FastCGI Unix endpoint changed during connect",
                    ));
                }
            }
            let quantum = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(1));
            if quantum.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "FastCGI Unix connection deadline exceeded",
                ));
            }
            s.set_read_timeout(Some(quantum))?;
            s.set_write_timeout(Some(quantum))?;
            Ok(Box::new(DeadlineStream {
                inner: Box::new(s),
                deadline,
            }))
        }
        Transport::Tcp(host, port) => {
            if policy.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "strict FastCGI policy requires an authenticated Unix socket backend",
                ));
            }
            let mut last = None;
            let remaining = deadline.saturating_duration_since(Instant::now());
            let addrs = crate::proxy::resolve_backend_addrs(host, *port, remaining)?;
            for addr in addrs {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match TcpStream::connect_timeout(&addr, remaining) {
                    Ok(s) => {
                        let quantum = deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_secs(1));
                        if quantum.is_zero() {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "FastCGI connection deadline exceeded",
                            ));
                        }
                        s.set_read_timeout(Some(quantum))?;
                        s.set_write_timeout(Some(quantum))?;
                        return Ok(Box::new(DeadlineStream {
                            inner: Box::new(s),
                            deadline,
                        }));
                    }
                    Err(e) => last = Some(e),
                }
            }
            Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address")))
        }
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

struct DeadlineStream {
    inner: Box<dyn ReadWrite>,
    deadline: Instant,
}

impl DeadlineStream {
    fn timeout_error(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "FastCGI exchange deadline exceeded",
        )
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(self.timeout_error());
            }
            match self.inner.read(buf) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(self.timeout_error());
            }
            match self.inner.write(buf) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(self.timeout_error());
            }
            match self.inner.flush() {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
}

fn put_len(out: &mut Vec<u8>, n: usize) {
    if n < 128 {
        out.push(n as u8);
    } else {
        out.extend_from_slice(&((n as u32) | 0x8000_0000).to_be_bytes());
    }
}

fn put_param(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    put_len(out, name.len());
    put_len(out, value.len());
    out.extend_from_slice(name);
    out.extend_from_slice(value);
}

fn record(out: &mut Vec<u8>, ty: u8, id: u16, content: &[u8]) {
    let pad = (8 - content.len() % 8) % 8;
    out.push(FCGI_VERSION);
    out.push(ty);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.push(pad as u8);
    out.push(0);
    out.extend_from_slice(content);
    out.extend(std::iter::repeat(0).take(pad));
}

fn env_from_base(base: &CgiContext) -> Vec<(OsString, OsString)> {
    cgi::build_env(base)
}

fn build_params(env: &[(OsString, OsString)]) -> Vec<u8> {
    let mut params = Vec::new();
    for (k, v) in env {
        put_param(
            &mut params,
            k.as_os_str().as_bytes(),
            v.as_os_str().as_bytes(),
        );
    }
    params
}

fn send_request(stream: &mut dyn ReadWrite, params: &[u8], body: &mut dyn Read) -> io::Result<()> {
    let mut out = Vec::new();
    let mut begin = vec![0u8; 8];
    begin[0..2].copy_from_slice(&FCGI_RESPONDER.to_be_bytes());
    record(&mut out, FCGI_BEGIN_REQUEST, 1, &begin);
    for chunk in params.chunks(60_000) {
        record(&mut out, FCGI_PARAMS, 1, chunk);
    }
    record(&mut out, FCGI_PARAMS, 1, &[]);
    stream.write_all(&out)?;
    let mut chunk = vec![0u8; 60_000];
    loop {
        let n = body.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let mut record_bytes = Vec::new();
        record(&mut record_bytes, FCGI_STDIN, 1, &chunk[..n]);
        stream.write_all(&record_bytes)?;
    }
    let mut end = Vec::new();
    record(&mut end, FCGI_STDIN, 1, &[]);
    stream.write_all(&end)
}

enum Spool {
    Memory(Vec<u8>),
    File {
        file: File,
        len: u64,
        lease: Option<crate::resource::SpoolLease>,
    },
}

impl Spool {
    fn len(&self) -> u64 {
        match self {
            Spool::Memory(v) => v.len() as u64,
            Spool::File { len, .. } => *len,
        }
    }

    fn push(&mut self, data: &[u8]) -> io::Result<()> {
        self.push_budgeted(data, None)
    }

    fn push_budgeted(
        &mut self,
        data: &[u8],
        budget: Option<(
            &std::sync::Arc<crate::resource::ResourceBudget>,
            &crate::resource::ResourceContext,
            u64,
            u64,
        )>,
    ) -> io::Result<()> {
        match self {
            Spool::Memory(v) => {
                if v.len().saturating_add(data.len()) > FASTCGI_SPOOL_THRESHOLD {
                    let mut lease = if let Some((budget, context, max_bytes, max_files)) = budget {
                        let mut lease = budget.try_spool_in(max_bytes, max_files, context)?;
                        lease.reserve(v.len() as u64 + data.len() as u64)?;
                        Some(lease)
                    } else {
                        None
                    };
                    let mut file = temp_file()?;
                    file.write_all(v)?;
                    file.write_all(data)?;
                    let len = v.len() as u64 + data.len() as u64;
                    *self = Spool::File {
                        file,
                        len,
                        lease: lease.take(),
                    };
                } else {
                    v.extend_from_slice(data);
                }
            }
            Spool::File { file, len, lease } => {
                if let Some(lease) = lease {
                    lease.reserve(data.len() as u64)?;
                }
                file.write_all(data)?;
                *len = len.saturating_add(data.len() as u64);
            }
        }
        Ok(())
    }
}

/// Create a private, unlinked spool file.  `create_new` makes the open atomic
/// with respect to a pre-created symlink or file at the candidate name; the
/// process/counter name is therefore safe even in a shared temp directory.
/// The bounded retry handles an attacker squatting a candidate without
/// following it (F43/I41).
fn secure_temp_file_at(dir: &Path, seed: u64, start: u64) -> io::Result<File> {
    let pid = std::process::id();
    let mut last = None;
    for offset in 0..32 {
        let attempt = start.saturating_add(offset);
        let name = if attempt == 0 {
            format!("vapache-fastcgi-{pid}-{seed}.body")
        } else {
            format!("vapache-fastcgi-{pid}-{seed}-{attempt}.body")
        };
        let path = dir.join(name);
        match OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                let _ = std::fs::remove_file(&path);
                return Ok(file);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                last = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "spool name collision")))
}

fn secure_temp_file(dir: &Path, seed: u64) -> io::Result<File> {
    secure_temp_file_at(dir, seed, 0)
}

fn temp_file() -> io::Result<File> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    secure_temp_file(&std::env::temp_dir(), n)
}

fn response_from_spool(spool: Spool, version: crate::http::Version) -> io::Result<Response> {
    match spool {
        Spool::Memory(data) => cgi::parse_cgi_response(&data, version)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid FastCGI response")),
        Spool::File {
            mut file,
            len,
            lease,
        } => {
            file.seek(SeekFrom::Start(0))?;
            let prefix_len = len.min(128 * 1024) as usize;
            let mut prefix = vec![0u8; prefix_len];
            file.read_exact(&mut prefix)?;
            let head_end = prefix
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .or_else(|| prefix.windows(2).position(|w| w == b"\n\n").map(|p| p + 2))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "FastCGI headers too large")
                })?;
            let mut head = prefix[..head_end].to_vec();
            if !head.ends_with(b"\r\n\r\n") {
                head.extend_from_slice(b"\r\n\r\n");
            }
            let mut response = cgi::parse_cgi_response(&head, version).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid FastCGI response")
            })?;
            let body_len = len.saturating_sub(head_end as u64);
            if response.status == 204 || response.status == 304 || body_len == 0 {
                response.body = Body::Empty;
            } else {
                response.body = Body::File {
                    file,
                    offset: head_end as u64,
                    len: body_len,
                };
            }
            if let Some(lease) = lease {
                response.hold_spool(lease);
            }
            Ok(response)
        }
    }
}

fn read_response_with_limit(
    stream: &mut dyn ReadWrite,
    max_output: u64,
) -> io::Result<(Spool, Vec<u8>)> {
    read_response_with_budget(stream, max_output, None)
}

fn read_response_with_budget(
    stream: &mut dyn ReadWrite,
    max_output: u64,
    budget: Option<(
        &std::sync::Arc<crate::resource::ResourceBudget>,
        &crate::resource::ResourceContext,
        u64,
        u64,
    )>,
) -> io::Result<(Spool, Vec<u8>)> {
    let mut spool = Spool::Memory(Vec::new());
    let mut stderr = Vec::new();
    let mut records = 0u64;
    let mut framing_bytes = 0u64;
    loop {
        let mut header = [0u8; 8];
        stream.read_exact(&mut header)?;
        if header[0] != FCGI_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad FastCGI version",
            ));
        }
        let ty = header[1];
        let len = u16::from_be_bytes([header[4], header[5]]) as usize;
        let pad = header[6] as usize;
        records = records.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "FastCGI record count overflow")
        })?;
        let control_bytes = match ty {
            FCGI_STDOUT => 0,
            FCGI_STDERR => len.saturating_sub((64 * 1024usize).saturating_sub(stderr.len())) as u64,
            _ => len as u64,
        };
        framing_bytes = framing_bytes
            .checked_add(8 + pad as u64)
            .and_then(|bytes| bytes.checked_add(control_bytes))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "FastCGI framing overflow")
            })?;
        if records > MAX_FASTCGI_RECORDS || framing_bytes > MAX_FASTCGI_FRAMING_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FastCGI framing budget exceeded",
            ));
        }
        let mut content = vec![0u8; len + pad];
        stream.read_exact(&mut content)?;
        content.truncate(len);
        match ty {
            FCGI_STDOUT => {
                if spool.len() > max_output
                    || content.len() as u64 > max_output.saturating_sub(spool.len())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "FastCGI output too large",
                    ));
                }
                spool.push_budgeted(&content, budget)?;
            }
            FCGI_STDERR => {
                let take = content
                    .len()
                    .min((64 * 1024usize).saturating_sub(stderr.len()));
                stderr.extend_from_slice(&content[..take]);
            }
            FCGI_END_REQUEST => return Ok((spool, stderr)),
            _ => {}
        }
    }
}

fn read_response(stream: &mut dyn ReadWrite) -> io::Result<(Spool, Vec<u8>)> {
    read_response_with_limit(stream, DEFAULT_MAX_FASTCGI_OUTPUT)
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_fastcgi_records(data: &[u8]) {
    let mut cursor = Cursor::new(data.to_vec());
    let _ = read_response_with_limit(&mut cursor, 1024 * 1024);
}

/// Execute a FastCGI request.  `base` supplies the request and connection
/// metadata; `target` supplies the backend and SCRIPT_FILENAME.
pub fn execute(base: &CgiContext, scope: &Scope, target: &Target) -> Response {
    execute_inner(base, scope, target, None)
}

/// Execute only while the target pathname still resolves to the exact script
/// inode selected and authorized by the dispatcher.
pub(crate) fn execute_bound(
    base: &CgiContext,
    scope: &Scope,
    target: &Target,
    binding: &ScriptBinding,
) -> Response {
    execute_inner(base, scope, target, Some(binding))
}

fn retain_script_path_binding(target: &Target, binding: &ScriptBinding) -> io::Result<File> {
    let selected = binding.file.metadata()?;
    let current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(target.script_filename())?;
    let current_meta = current.metadata()?;
    let same_selected =
        selected.dev() == binding.meta.dev() && selected.ino() == binding.meta.ino();
    let same_path =
        current_meta.dev() == binding.meta.dev() && current_meta.ino() == binding.meta.ino();
    let lexical_inode_bound = vapache_verified::descriptor_snapshot_admit(
        selected.is_file() && current_meta.is_file(),
        same_selected && same_path,
        true,
        true,
    );
    if !vapache_verified::fastcgi_script_identity_admit(
        selected.dev() == binding.meta.dev() && selected.ino() == binding.meta.ino(),
        lexical_inode_bound,
        true,
        true,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "FastCGI script inode changed after authorization",
        ));
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn path_has_posix_acl(path: &Path) -> io::Result<bool> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL byte in FastCGI stable path",
        )
    })?;
    for name in ["system.posix_acl_access", "system.posix_acl_default"] {
        let name = std::ffi::CString::new(name).expect("static xattr name");
        // SAFETY: path/name are live NUL-terminated strings. Linux permits a
        // null value pointer with size zero for this length-only query.
        let len = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if len > 0 {
            return Ok(true);
        }
        if len == 0 {
            continue;
        }
        let err = io::Error::last_os_error();
        let code = err.raw_os_error();
        if code == Some(libc::ENODATA)
            || code == Some(libc::ENOTSUP)
            || code == Some(libc::EOPNOTSUPP)
        {
            continue;
        }
        return Err(err);
    }
    Ok(false)
}

#[cfg(not(target_os = "linux"))]
fn path_has_posix_acl(_path: &Path) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "FastCGI POSIX ACL validation is unavailable on this platform",
    ))
}

fn stable_fastcgi_component(
    policy: &FastCgiStablePathPolicy,
    path: &Path,
    meta: &std::fs::Metadata,
) -> io::Result<()> {
    let uid = meta.uid();
    let mode = meta.mode();
    let symlink = meta.file_type().is_symlink();
    let has_acl = !symlink && path_has_posix_acl(path)?;
    let admitted = vapache_verified::fastcgi_stable_component_admit(
        policy.backend_uid == 0,
        policy.trusted_owner_uids.contains(&uid),
        uid == policy.backend_uid,
        mode & 0o022 != 0,
        symlink,
        has_acl,
    );
    if admitted {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "FastCGI stable-path policy rejected {} (uid={uid}, mode={:04o}, acl={has_acl})",
                path.display(),
                mode & 0o7777
            ),
        ))
    }
}

/// Check every lexical/canonical pathname component. A symlink's own mode is
/// ignored (Unix reports meaningless 0777 bits), but its owner and containing
/// directory are checked, and the canonical target is checked separately.
fn enforce_stable_fastcgi_path(policy: &FastCgiStablePathPolicy, path: &Path) -> io::Result<()> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "FastCGI stable-path policy requires an absolute script path",
        ));
    }
    let mut current = PathBuf::from("/");
    stable_fastcgi_component(policy, &current, &std::fs::symlink_metadata(&current)?)?;
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => current.push(name),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "FastCGI stable-path policy rejects non-normal path components",
                ));
            }
        }
        let meta = std::fs::symlink_metadata(&current)?;
        stable_fastcgi_component(policy, &current, &meta)?;
    }
    Ok(())
}

fn fastcgi_error_response(
    base: &CgiContext,
    scope: &Scope,
    target: &Target,
    status: u16,
) -> Response {
    crate::files::error_response(
        base.cfg,
        base.vhost,
        scope,
        status,
        base.req,
        &target.script_name,
        base.local_port,
        base.host,
        base.remote_ip
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        base.local_ip,
    )
}

fn execute_inner(
    base: &CgiContext,
    scope: &Scope,
    target: &Target,
    binding: Option<&ScriptBinding>,
) -> Response {
    #[cfg(test)]
    let fallback_context;
    let resource_context = match base.req.resource_context() {
        Some(context) => context,
        #[cfg(test)]
        None => {
            fallback_context = base.cfg.resource_budget.context(
                base.remote_ip
                    .parse()
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            );
            &fallback_context
        }
        #[cfg(not(test))]
        None => return fastcgi_error_response(base, scope, target, 503),
    };
    let _dynamic_lease = match base.cfg.resource_budget.try_dynamic_descriptors_in(
        resource_context,
        base.cfg.max_dynamic_requests,
        1,
    ) {
        Ok(lease) => lease,
        Err(e) => {
            eprintln!("vapache FastCGI admission error: {e}");
            return fastcgi_error_response(base, scope, target, 503);
        }
    };
    let mut env = env_from_base(base);
    // The FastCGI target, not the base request mapping, is authoritative for
    // the script and PATH_INFO.  Remove all four derived values before adding
    // the exact target values so a stale mapping cannot be sent twice or win
    // in a backend that takes the first duplicate parameter.
    env.retain(|(k, _)| {
        !matches!(
            k.to_str(),
            Some("SCRIPT_FILENAME" | "SCRIPT_NAME" | "PATH_INFO" | "PATH_TRANSLATED")
        )
    });
    env.push((
        OsString::from("SCRIPT_FILENAME"),
        OsString::from(target.script_filename().as_os_str()),
    ));
    env.push((
        OsString::from("SCRIPT_NAME"),
        OsString::from(target.script_name.clone()),
    ));
    if !target.path_info.is_empty() {
        env.push((
            OsString::from("PATH_INFO"),
            OsString::from(target.path_info.clone()),
        ));
        env.push((
            OsString::from("PATH_TRANSLATED"),
            OsString::from(
                base.docroot
                    .join(target.path_info.trim_start_matches('/'))
                    .to_string_lossy()
                    .into_owned(),
            ),
        ));
    }
    let result = (|| -> io::Result<Response> {
        let timeout = base.cfg.timeout.max(Duration::from_secs(5));
        let policy = stable_policy_for(base.cfg, &target.backend)?;
        let mut stream = connect(&target.backend, timeout, policy)?;
        let params = build_params(&env);
        if let Some(policy) = policy {
            enforce_stable_fastcgi_path(policy, target.script_filename())?;
            if let Some(binding) = binding {
                enforce_stable_fastcgi_path(policy, &binding.actual_path)?;
            }
        }
        // Connect first, then keep both the originally selected descriptor and
        // a last-moment open of SCRIPT_FILENAME alive through the exchange.
        // A slow backend connection therefore cannot widen the check-to-send
        // window. The protocol cannot make PHP-FPM consume our fd, but this
        // closes vapache's own select/authorize/use gap and fails if the
        // pathname changed before parameters are emitted.
        let _path_binding = if let Some(binding) = binding {
            Some(retain_script_path_binding(target, binding)?)
        } else {
            None
        };
        if let Some(reader) = base.req.body_reader() {
            let mut reader = reader?;
            send_request(&mut stream, &params, &mut reader)?;
        } else {
            let mut reader = Cursor::new(base.req.body.as_slice());
            send_request(&mut stream, &params, &mut reader)?;
        }
        let (spool, stderr) = read_response_with_budget(
            &mut stream,
            base.cfg.max_fastcgi_output,
            Some((
                &base.cfg.resource_budget,
                resource_context,
                base.cfg.max_spool_bytes,
                base.cfg.max_spool_files,
            )),
        )?;
        if !stderr.is_empty() {
            eprintln!(
                "vapache FastCGI stderr: {}",
                String::from_utf8_lossy(&stderr).trim()
            );
        }
        response_from_spool(spool, base.req.version)
    })();

    match result {
        Ok(mut r) => {
            crate::compression::finalize_budgeted(
                scope,
                base.req,
                &mut r,
                target.script_name.as_bytes(),
                &base.cfg.resource_budget,
            );
            r
        }
        Err(e) => {
            eprintln!("vapache FastCGI error: {e}");
            fastcgi_error_response(base, scope, target, 502)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::sync::{Arc, Mutex};

    fn config(root: &Path) -> Config {
        let path = root.join("httpd.conf");
        fs::write(
            &path,
            format!("{}Listen 127.0.0.1:0\n", crate::config::TEST_CAPABILITIES),
        )
        .unwrap();
        Config::load(&path, root, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    #[test]
    fn strict_fastcgi_path_policy_checks_backend_write_reachability() {
        let policy = FastCgiStablePathPolicy {
            endpoint: FastCgiEndpoint::Unix(PathBuf::from("/run/php/test.sock")),
            backend_uid: 33,
            endpoint_owner_uid: Some(0),
            trusted_owner_uids: vec![0],
        };
        enforce_stable_fastcgi_path(&policy, Path::new("/etc/passwd"))
            .expect("root-owned system path should be stable for uid 33");
        assert!(enforce_stable_fastcgi_path(&policy, Path::new("/tmp")).is_err());
        assert!(enforce_stable_fastcgi_path(&policy, Path::new("relative.php")).is_err());

        assert!(!vapache_verified::fastcgi_stable_component_admit(
            false, true, true, false, false, false
        ));
        assert!(!vapache_verified::fastcgi_stable_component_admit(
            false, true, false, true, false, false
        ));
        assert!(vapache_verified::fastcgi_stable_component_admit(
            false, true, false, false, false, false
        ));
        assert!(vapache_verified::fastcgi_stable_component_admit(
            false, true, true, true, true, false
        ));
        assert!(!vapache_verified::fastcgi_stable_component_admit(
            false, true, false, false, false, true
        ));

        let tcp_backend = parse_backend("fcgi://127.0.0.1:9000").unwrap();
        let tcp_policy = FastCgiStablePathPolicy {
            endpoint: FastCgiEndpoint::Tcp {
                host: "127.0.0.1".into(),
                port: 9000,
            },
            backend_uid: 33,
            endpoint_owner_uid: None,
            trusted_owner_uids: vec![0],
        };
        let err = connect(&tcp_backend, Duration::from_millis(1), Some(&tcp_policy))
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn pathname_only_fastcgi_handoff_requires_explicit_capability() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("vapache-fcgi-capability-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let mut cfg = config(&root);
        let backend = parse_backend("fcgi://127.0.0.1:9000").unwrap();

        cfg.capabilities
            .set(crate::config::Capability::UnstableFastCgiPaths, false);
        let error = stable_policy_for(&cfg, &backend).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        cfg.capabilities
            .set(crate::config::Capability::UnstableFastCgiPaths, true);
        assert!(stable_policy_for(&cfg, &backend).unwrap().is_none());
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_policy_binds_exact_endpoint_owner_and_rejects_posix_acls() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("vapache-fcgi-policy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        let socket = dir.join("php.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let euid = unsafe { libc::geteuid() } as u32;
        let backend_uid = if euid == 33 { 34 } else { 33 };
        let policy = FastCgiStablePathPolicy {
            endpoint: FastCgiEndpoint::Unix(socket.clone()),
            backend_uid,
            endpoint_owner_uid: Some(euid),
            trusted_owner_uids: vec![0, euid],
        };
        let mut cfg = config(&dir);
        cfg.fastcgi_stable_paths = Some(vec![policy.clone()]);
        let backend =
            parse_backend(&format!("unix:{}|fcgi://localhost", socket.display())).unwrap();
        assert!(stable_policy_for(&cfg, &backend).unwrap().is_some());
        let unregistered = parse_backend("fcgi://127.0.0.1:9000").unwrap();
        assert!(stable_policy_for(&cfg, &unregistered).is_err());

        let accept = std::thread::spawn(move || listener.accept().unwrap());
        connect(&backend, Duration::from_secs(2), Some(&policy)).unwrap();
        drop(accept.join().unwrap());

        let file = dir.join("script.php");
        fs::write(&file, "<?php\n").unwrap();
        let mut acl = Vec::new();
        acl.extend_from_slice(&2u32.to_le_bytes());
        for (tag, perm, id) in [
            (0x01u16, 0x06u16, u32::MAX),
            (0x02u16, 0x04u16, 65_534u32),
            (0x04u16, 0x04u16, u32::MAX),
            (0x10u16, 0x04u16, u32::MAX),
            (0x20u16, 0x04u16, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&perm.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        let file_c = std::ffi::CString::new(file.as_os_str().as_bytes()).unwrap();
        let name = std::ffi::CString::new("system.posix_acl_access").unwrap();
        assert_eq!(
            unsafe {
                libc::setxattr(
                    file_c.as_ptr(),
                    name.as_ptr(),
                    acl.as_ptr().cast(),
                    acl.len(),
                    0,
                )
            },
            0
        );
        assert!(path_has_posix_acl(&file).unwrap());
        assert!(enforce_stable_fastcgi_path(&policy, &file).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn final_script_binding_survives_concurrent_atomic_swaps() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("vapache-fcgi-race-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        let script = dir.join("index.php");
        let other = dir.join("attacker.php");
        fs::write(&script, "SAFE\n").unwrap();
        fs::write(&other, "ATTACKER\n").unwrap();
        let selected = File::open(&script).unwrap();
        let selected_meta = selected.metadata().unwrap();
        let binding = ScriptBinding {
            file: selected,
            meta: selected_meta,
            actual_path: fs::canonicalize(&script).unwrap(),
        };
        let target = Target {
            backend: parse_backend("fcgi://127.0.0.1:9000").unwrap(),
            script_filename: LexicalScriptPath::for_test(script.clone()),
            script_name: "/index.php".into(),
            path_info: String::new(),
            route_order: 0,
            logical_url: None,
        };
        let script_c = std::ffi::CString::new(script.as_os_str().as_bytes()).unwrap();
        let other_c = std::ffi::CString::new(other.as_os_str().as_bytes()).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let attacker_stop = Arc::clone(&stop);
        let attacker = std::thread::spawn(move || {
            while !attacker_stop.load(Ordering::Relaxed) {
                let rc = unsafe {
                    libc::syscall(
                        libc::SYS_renameat2,
                        libc::AT_FDCWD,
                        script_c.as_ptr(),
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
            if let Ok(retained) = retain_script_path_binding(&target, &binding) {
                let meta = retained.metadata().unwrap();
                assert_eq!(
                    (meta.dev(), meta.ino()),
                    (binding.meta.dev(), binding.meta.ino())
                );
            }
        }
        stop.store(true, Ordering::Relaxed);
        attacker.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn spool_temp_file_never_follows_a_preexisting_symlink() {
        let dir =
            std::env::temp_dir().join(format!("vapache-fcgi-spool-safe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("overwrite-target");
        fs::write(&target, b"ORIGINAL TARGET CONTENT\n").unwrap();
        let predicted = dir.join(format!("vapache-fastcgi-{}-0.body", std::process::id()));
        std::os::unix::fs::symlink(&target, &predicted).unwrap();
        let mut file = secure_temp_file_at(&dir, 0, 0).expect("collision-safe spool");
        file.write_all(b"ATTACKER BODY").unwrap();
        drop(file);
        assert_eq!(
            fs::read(&target).unwrap(),
            b"ORIGINAL TARGET CONTENT\n",
            "the symlink target must not be truncated"
        );
        assert!(predicted.is_symlink(), "the planted symlink is left alone");
        // The retry names are ordinary private files and were unlinked.
        let leaked: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains("-0-"))
            .collect();
        assert!(leaked.iter().all(|e| e.path().symlink_metadata().is_err()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn spool_temp_file_reports_open_errors_and_collision_exhaustion() {
        let missing =
            std::env::temp_dir().join(format!("vapache-fcgi-spool-missing-{}", std::process::id()));
        let _ = fs::remove_dir_all(&missing);
        assert!(secure_temp_file_at(&missing, 1, 0).is_err());

        let dir =
            std::env::temp_dir().join(format!("vapache-fcgi-spool-full-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pid = std::process::id();
        for attempt in 0..32 {
            let name = if attempt == 0 {
                format!("vapache-fastcgi-{pid}-99.body")
            } else {
                format!("vapache-fastcgi-{pid}-99-{attempt}.body")
            };
            fs::write(dir.join(name), b"squatter").unwrap();
        }
        assert!(secure_temp_file_at(&dir, 99, 0).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn spool_temp_file_is_private_and_unlinked() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("vapache-fcgi-spool-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = secure_temp_file_at(&dir, 7, 0).unwrap();
        let mode = file.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(fs::read_dir(&dir).unwrap().next().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    fn request(path: &str) -> Request {
        Request {
            method: "GET".into(),
            target: path.as_bytes().to_vec(),
            raw_path: path.as_bytes().to_vec(),
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

    fn mock_fastcgi(
        listener: UnixListener,
        seen: Arc<Mutex<Vec<u8>>>,
        payload: Option<Vec<u8>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            loop {
                let mut header = [0u8; 8];
                if stream.read_exact(&mut header).is_err() {
                    break;
                }
                let ty = header[1];
                let len = u16::from_be_bytes([header[4], header[5]]) as usize;
                let pad = header[6] as usize;
                let mut content = vec![0u8; len + pad];
                stream.read_exact(&mut content).unwrap();
                content.truncate(len);
                if ty == FCGI_PARAMS {
                    seen.lock().unwrap().extend_from_slice(&content);
                }
                if ty == FCGI_STDIN && len == 0 {
                    break;
                }
            }
            let mut out = Vec::new();
            record(
                &mut out,
                FCGI_STDOUT,
                1,
                b"Content-Type: text/plain\r\n\r\n",
            );
            if let Some(payload) = payload {
                for chunk in payload.chunks(60_000) {
                    record(&mut out, FCGI_STDOUT, 1, chunk);
                }
            } else {
                record(&mut out, FCGI_STDOUT, 1, b"fastcgi ok\n");
            }
            record(&mut out, FCGI_STDOUT, 1, &[]);
            record(&mut out, FCGI_END_REQUEST, 1, &[0u8; 8]);
            stream.write_all(&out).unwrap();
        })
    }

    #[test]
    fn parses_and_executes_unix_fastcgi() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("fcgi.sock");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = mock_fastcgi(listener, seen.clone(), None);
        let cfg = config(&dir);
        let req = request("/index.php");
        let backend = parse_backend(&format!(
            "unix:{}|fcgi://localhost/var/www/html/",
            sock.display()
        ))
        .unwrap();
        let target = Target {
            backend,
            script_filename: LexicalScriptPath::for_test(PathBuf::from("/var/www/html/index.php")),
            script_name: "/index.php".into(),
            path_info: String::new(),
            route_order: 0,
            logical_url: None,
        };
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new(""),
            script_name: "/index.php",
            path_info: "",
            docroot: &dir,
            remote_ip: "127.0.0.1",
            remote_port: 12345,
            local_ip: "127.0.0.1",
            local_port: 8080,
            https: false,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &[],
            remote_user: Some("alice"),
            auth_type: Some("Basic"),
            script_file: None,
        };
        let resp = execute(&ctx, &cfg.global, &target);
        assert_eq!(resp.status, 200);
        match resp.body {
            Body::Bytes(b) => assert_eq!(b, b"fastcgi ok\n"),
            _ => panic!("expected bytes"),
        }
        let params = String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
        assert!(params.contains("SCRIPT_FILENAME"));
        assert!(params.contains("/var/www/html/index.php"));
        assert!(params.contains("REMOTE_USER"));
        assert!(params.contains("alice"));
        assert!(params.contains("AUTH_TYPE"));
        assert!(params.contains("Basic"));
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fastcgi_response_limits_and_protocol_errors() {
        let mut input = Vec::new();
        for _ in 0..16 {
            record(&mut input, FCGI_STDERR, 1, &vec![b'x'; 16 * 1024]);
        }
        record(&mut input, FCGI_END_REQUEST, 1, &[0u8; 8]);
        let mut cursor = Cursor::new(input);
        let (_spool, stderr) = read_response(&mut cursor).expect("bounded stderr");
        assert!(
            stderr.len() <= 64 * 1024,
            "FastCGI stderr must be capped, got {} bytes",
            stderr.len()
        );

        let mut bad_version = Cursor::new(vec![0u8; 8]);
        assert!(read_response(&mut bad_version).is_err());
    }

    #[test]
    fn fastcgi_target_overrides_script_and_path_info_exactly_once() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-env-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("fcgi.sock");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = mock_fastcgi(listener, seen.clone(), None);
        let cfg = config(&dir);
        let req = request("/index.php/info");
        let backend = parse_backend(&format!(
            "unix:{}|fcgi://localhost/var/www/html/",
            sock.display()
        ))
        .unwrap();
        let target = Target {
            backend,
            script_filename: LexicalScriptPath::for_test(PathBuf::from("/var/www/html/index.php")),
            script_name: "/index.php".into(),
            path_info: "/info".into(),
            route_order: 0,
            logical_url: None,
        };
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new(""),
            script_name: "/index.php/info",
            path_info: "/info",
            docroot: &dir,
            remote_ip: "127.0.0.1",
            remote_port: 12345,
            local_ip: "127.0.0.1",
            local_port: 8080,
            https: false,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &[],
            remote_user: None,
            auth_type: None,
            script_file: None,
        };
        let resp = execute(&ctx, &cfg.global, &target);
        assert_eq!(resp.status, 200);
        let params = seen.lock().unwrap();
        let count = |needle: &[u8]| {
            params
                .windows(needle.len())
                .filter(|w| *w == needle)
                .count()
        };
        assert_eq!(count(b"SCRIPT_FILENAME"), 1);
        assert_eq!(count(b"SCRIPT_NAME"), 1);
        assert_eq!(count(b"PATH_INFO"), 1);
        assert_eq!(count(b"PATH_TRANSLATED"), 1);
        assert!(String::from_utf8_lossy(&params).contains("/var/www/html/index.php"));
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn large_fastcgi_output_uses_a_file_backed_body() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-large-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("fcgi.sock");
        let payload = vec![b'q'; 2 * 1024 * 1024];
        let expected = payload.len();
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = mock_fastcgi(listener, Arc::new(Mutex::new(Vec::new())), Some(payload));
        let cfg = config(&dir);
        let req = request("/index.php");
        let backend = parse_backend(&format!(
            "unix:{}|fcgi://localhost/var/www/html/",
            sock.display()
        ))
        .unwrap();
        let target = Target {
            backend,
            script_filename: LexicalScriptPath::for_test(PathBuf::from("/var/www/html/index.php")),
            script_name: "/index.php".into(),
            path_info: String::new(),
            route_order: 0,
            logical_url: None,
        };
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new(""),
            script_name: "/index.php",
            path_info: "",
            docroot: &dir,
            remote_ip: "127.0.0.1",
            remote_port: 12345,
            local_ip: "127.0.0.1",
            local_port: 8080,
            https: false,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &[],
            remote_user: None,
            auth_type: None,
            script_file: None,
        };
        let resp = execute(&ctx, &cfg.global, &target);
        assert_eq!(resp.status, 200);
        match resp.body {
            Body::File { len, .. } => assert_eq!(len as usize, expected),
            _ => panic!("expected file-backed body"),
        }
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn backend_forms_are_parsed() {
        assert!(parse_backend("proxy:fcgi://127.0.0.1:9000/var/www").is_some());
        assert!(parse_backend("unix:/run/php.sock|fcgi://localhost").is_some());
        assert!(parse_backend("http://example.com").is_none());
    }

    #[test]
    fn backend_parser_and_binding_edges() {
        let unix = parse_backend("unix:/tmp/php.sock").unwrap();
        assert!(matches!(&unix.transport, Transport::Unix(p) if p == Path::new("/tmp/php.sock")));
        assert!(unix.prefix.is_empty());

        let unix_url = parse_backend("unix:/tmp/php.sock|fcgi://localhost/var/www").unwrap();
        assert_eq!(unix_url.prefix, "/var/www");
        assert!(parse_backend("unix:|fcgi://localhost/").is_none());
        assert!(parse_backend("unix:/tmp/php.sock|http://localhost/").is_none());

        let tcp = parse_backend("fcgi://localhost").unwrap();
        assert!(matches!(&tcp.transport, Transport::Tcp(host, 9000) if host == "localhost"));
        assert!(tcp.prefix.is_empty());
        let tcp_path = parse_backend("fcgi://localhost:9001/var/www").unwrap();
        assert_eq!(tcp_path.prefix, "/var/www");
        assert!(matches!(&tcp_path.transport, Transport::Tcp(_, 9001)));
        assert!(parse_backend("fcgi://:9000/").is_none());
        assert!(parse_backend("fcgi://localhost:notaport/").is_none());
        assert!(parse_backend("http://example.com").is_none());

        let unix_target = Target {
            backend: unix,
            script_filename: LexicalScriptPath::for_test(PathBuf::from("/srv/index.php")),
            script_name: "/index.php".into(),
            path_info: String::new(),
            route_order: 0,
            logical_url: None,
        };
        let key = unix_target.binding_key(Path::new("/srv/real/index.php"));
        assert!(key.starts_with("unix:/tmp/php.sock|"));
        assert!(key.contains("lexical=/srv/index.php|authorized=/srv/real/index.php"));
        let tcp_target = Target {
            backend: tcp_path,
            script_filename: LexicalScriptPath::for_test(PathBuf::from("/srv/index.php")),
            script_name: "/index.php".into(),
            path_info: "/info".into(),
            route_order: 0,
            logical_url: None,
        };
        assert!(tcp_target
            .binding_key(Path::new("/srv/index.php"))
            .starts_with("tcp:localhost:9001|"));
    }

    #[test]
    fn script_base_and_prefix_edges() {
        let root = Path::new("/srv/www");
        let backend = |prefix: &str| Backend {
            transport: Transport::Unix(PathBuf::from("/tmp/php.sock")),
            prefix: prefix.into(),
        };
        assert_eq!(
            fastcgi_script_base(&backend("$1"), root),
            Path::new("/srv/www")
        );
        assert_eq!(
            fastcgi_script_base(&backend("www/$1"), root),
            Path::new("/srv/www/www")
        );
        assert_eq!(
            fastcgi_script_base(&backend("/"), root),
            Path::new("/srv/www")
        );
        assert_eq!(
            fastcgi_script_base(&backend("/abs/$1"), root),
            Path::new("/abs")
        );

        let (script, base) =
            script_from_prefix(&backend("www"), root, Path::new("index.php")).unwrap();
        assert_eq!(script, Path::new("/srv/www/www/index.php"));
        assert_eq!(base, Path::new("/srv/www/www"));
        let (script, base) =
            script_from_prefix(&backend("$1"), root, Path::new("index.php")).unwrap();
        assert_eq!(script, Path::new("/srv/www/index.php"));
        assert_eq!(base, root);
        let (script, _) = script_from_prefix(&backend("/"), root, Path::new("index.php")).unwrap();
        assert_eq!(script, Path::new("/srv/www/index.php"));

        assert_eq!(
            clean_script_path(Path::new("a/./b/../c")),
            PathBuf::from("a/c")
        );
        assert_eq!(clean_script_path(Path::new("./a")), PathBuf::from("a"));
    }

    #[test]
    fn containment_and_path_info_edges() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-path-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let base = dir.join("www");
        fs::create_dir_all(base.join("dir")).unwrap();
        fs::write(base.join("index.php"), "<?php\n").unwrap();
        fs::write(base.join("dir").join("script.php"), "<?php\n").unwrap();

        assert!(!contained_after_resolving_symlinks(
            &base.join("missing"),
            &base
        ));
        assert!(!contained_after_resolving_symlinks(
            &base,
            &base.join("missing")
        ));

        let (script, name, info) =
            split_path_info(base.join("index.php"), "/index.php", &base).unwrap();
        assert_eq!(script, base.join("index.php"));
        assert_eq!(name, "/index.php");
        assert!(info.is_empty());

        let (script, name, info) = split_path_info(
            base.join("dir/script.php/info"),
            "/dir/script.php/info",
            &base,
        )
        .unwrap();
        assert_eq!(script, base.join("dir/script.php"));
        assert_eq!(name, "/dir/script.php");
        assert_eq!(info, "/info");

        // An ancestor selected by the PATH_INFO walk must also resolve inside
        // the base.
        fs::write(dir.join("outside.php"), "<?php\n").unwrap();
        std::os::unix::fs::symlink(dir.join("outside.php"), base.join("dir").join("link.php"))
            .unwrap();
        assert!(
            split_path_info(base.join("dir/link.php/info"), "/dir/link.php/info", &base).is_none()
        );

        // The base directory itself is not a file; the walk stops before its
        // parent and falls back to the contained lexical target.
        assert!(split_path_info(base.clone(), "/", &base).is_some());
        // Root base exercises the "candidate has no parent" walk terminator.
        assert!(
            split_path_info(PathBuf::from("/definitely-missing"), "/x", Path::new("/")).is_some()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn match_proxy_and_handler_target_edges() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-match-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let root = dir.join("www");
        let outside = dir.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("index.php"), "<?php\n").unwrap();
        fs::write(outside.join("secret.php"), "<?php\n").unwrap();
        std::os::unix::fs::symlink(outside.join("secret.php"), root.join("link.php")).unwrap();

        let valid = format!("unix:/tmp/php.sock|fcgi://localhost{}/", root.display());
        let mut scope = Scope::default();
        let mut pass = |prefix: &str, backend: &str, order: usize| {
            scope
                .proxy_policy
                .proxy_passes
                .push(crate::config::ProxyPassRule {
                    prefix: prefix.into(),
                    backend: backend.into(),
                    sticky_cookie: None,
                    fail_on_status: Vec::new(),
                    route_order: order,
                });
        };
        pass("/bad", "http://example.test/", 0);
        pass("/escape", &valid, 0);
        pass("/link", "unix:/tmp/php.sock|fcgi://localhost", 0);
        pass("/ok", "unix:/tmp/php.sock|fcgi://localhost", 1);
        pass("/ok", &valid, 0);
        let target = match_proxy(&scope, "/ok/index.php", &root).unwrap();
        assert_eq!(target.route_order, 0);
        assert_eq!(target.script_filename(), root.join("index.php"));
        assert!(target.logical_url.as_deref().unwrap().starts_with("unix:"));
        assert!(match_proxy(&scope, "/escape/../outside/secret.php", &root).is_none());
        assert!(match_proxy(&scope, "/link/link.php", &root).is_none());
        let budgeted = request("/ok/index.php");
        assert!(match_proxy_for_request(&scope, "/ok/index.php", &root, &budgeted).is_some());
        assert!(budgeted.policy_budget().charged_work() > 0);
        let exhausted = request("/ok/index.php");
        exhausted
            .charge_policy_work(crate::resource::MAX_POLICY_WORK_UNITS)
            .unwrap();
        assert!(match_proxy_for_request(&scope, "/ok/index.php", &root, &exhausted).is_none());
        assert!(exhausted.policy_budget_failed());

        let mut regex_scope = Scope::default();
        let mut rule = |pattern: &str, backend: &str, order: usize| {
            regex_scope
                .proxy_policy
                .proxy_rules
                .push(crate::config::ProxyRule {
                    pattern: std::sync::Arc::new(regex::bytes::Regex::new(pattern).unwrap()),
                    backend: backend.into(),
                    route_order: order,
                });
        };
        rule("^/nomatch$", "unix:/tmp/php.sock|fcgi://localhost", 0);
        rule("^/badregex$", "http://example.test/", 0);
        rule("^/escape/(.*)$", &valid, 0);
        rule("^/nogroup$", "unix:/tmp/php.sock|fcgi://localhost", 0);
        rule("^/link/(.*)$", "unix:/tmp/php.sock|fcgi://localhost", 0);
        rule("^/ok/(.*)$", "unix:/tmp/php.sock|fcgi://localhost", 1);
        rule("^/ok/(.*)$", &format!("{valid}$1"), 0);
        let regex_target = match_proxy(&regex_scope, "/ok/index.php", &root).unwrap();
        assert_eq!(regex_target.route_order, 0);
        assert_eq!(regex_target.script_filename(), root.join("index.php"));
        assert!(match_proxy(&regex_scope, "/badregex", &root).is_none());
        assert!(match_proxy(&regex_scope, "/escape/../outside/secret.php", &root).is_none());
        assert!(match_proxy(&regex_scope, "/nogroup", &root).is_some());
        assert!(match_proxy(&regex_scope, "/link/link.php", &root).is_none());

        assert_eq!(prefix_suffix("/x", "/x"), Some(""));
        assert_eq!(prefix_suffix("/x", "/x/y"), Some("y"));
        assert_eq!(prefix_suffix("/app/", "/app/index.php"), Some("index.php"));
        assert_eq!(prefix_suffix("/", "/index.php"), Some("index.php"));
        assert_eq!(prefix_suffix("/x", "/xy"), None);
        assert_eq!(prefix_suffix("/x", "/other"), None);

        let handler_scope = |handler: &str| {
            let mut scope = Scope::default();
            scope
                .mapping_policy
                .handlers
                .push(crate::config::Handler::add("php".into(), handler.into()));
            scope
        };
        assert!(handler_target(
            &Scope::default(),
            &root,
            Path::new("index.php"),
            "/index.php"
        )
        .is_none());
        assert!(handler_target(
            &handler_scope("default-handler"),
            &root,
            Path::new("index.php"),
            "/index.php"
        )
        .is_none());
        assert!(handler_target(
            &handler_scope("proxy:http://example.test/"),
            &root,
            Path::new("index.php"),
            "/index.php"
        )
        .is_none());
        let proxy_handler = format!("proxy:{valid}");
        assert!(handler_target(
            &handler_scope(&proxy_handler),
            &root,
            Path::new("link.php"),
            "/link.php"
        )
        .is_none());
        let handler = handler_target(
            &handler_scope(&proxy_handler),
            &root,
            Path::new("index.php"),
            "/index.php",
        )
        .unwrap();
        assert_eq!(handler.script_filename(), root.join("index.php"));
        assert_eq!(handler.logical_url.as_deref(), Some(proxy_handler.as_str()));
        // The resolved-target variant rejects a target outside the configured
        // FastCGI base and a symlink whose real target escapes it.
        assert!(handler_target_for_file(
            &handler_scope(&proxy_handler),
            &root,
            "/secret.php",
            &root.join("secret.php"),
            &outside.join("secret.php"),
            b"secret.php",
        )
        .is_none());
        assert!(handler_target_for_file(
            &handler_scope(&proxy_handler),
            &root,
            "/link.php",
            &root.join("link.php"),
            &root.join("link.php"),
            b"link.php",
        )
        .is_none());
        assert!(handler_target_for_file(
            &handler_scope(&proxy_handler),
            &root,
            "/index.php",
            &root.join("index.php"),
            &root.join("index.php"),
            b"index.php",
        )
        .is_some());
        let mut extension_scope = Scope::default();
        extension_scope
            .mapping_policy
            .handlers
            .push(crate::config::Handler::add(
                "php".into(),
                proxy_handler.clone(),
            ));
        assert!(handler_target_for_file(
            &extension_scope,
            &root,
            "/link.txt",
            &root.join("link.txt"),
            &root.join("index.php"),
            b"link.txt",
        )
        .is_none());
        assert!(handler_target_for_file(
            &extension_scope,
            &root,
            "/index.php",
            &root.join("index.php"),
            &root.join("index.php"),
            b"index.php",
        )
        .is_some());

        // P17: SetHandler classification may cover a non-PHP lexical name,
        // but the backend must still receive that lexical path. The canonical
        // descriptor target remains a separate authorization identity.
        std::os::unix::fs::symlink("index.php", root.join("link.txt")).unwrap();
        let mut forced_scope = Scope::default();
        forced_scope.mapping_policy.set_handler =
            Some(crate::config::SetHandler::Name(proxy_handler.clone()));
        let resolved = handler_target_for_file(
            &forced_scope,
            &root,
            "/link.txt",
            &root.join("link.txt"),
            &root.join("index.php"),
            b"link.txt",
        )
        .unwrap();
        assert_eq!(resolved.script_filename(), root.join("link.txt"));
        assert!(resolved.script_filename.matches_mapping(
            &parse_backend(&proxy_handler).unwrap(),
            &root,
            Path::new("link.txt"),
        ));
        let forged_canonical = LexicalScriptPath::for_test(root.join("index.php"));
        assert!(!forged_canonical.matches_mapping(
            &parse_backend(&proxy_handler).unwrap(),
            &root,
            Path::new("link.txt"),
        ));
        assert!(handler_target_for_file(
            &forced_scope,
            &root,
            "/link.txt",
            &root.join("link.txt"),
            &root.join("index.php"),
            b"index.php",
        )
        .is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    struct Sink(Vec<u8>);

    impl Read for Sink {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tcp_transport_connect_success_and_failure() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let backend = Backend {
            transport: Transport::Tcp("127.0.0.1".into(), port),
            prefix: String::new(),
        };
        assert!(connect(&backend, Duration::from_secs(2), None).is_ok());
        handle.join().unwrap();

        let dead = Backend {
            transport: Transport::Tcp("127.0.0.1".into(), 1),
            prefix: String::new(),
        };
        assert!(connect(&dead, Duration::from_millis(100), None).is_err());
    }

    #[test]
    fn record_encoding_and_streamed_body_edges() {
        let mut len = Vec::new();
        put_len(&mut len, 127);
        assert_eq!(len.len(), 1);
        put_len(&mut len, 128);
        assert_eq!(len.len(), 5);

        let mut params = Vec::new();
        put_param(&mut params, b"K", b"V");
        assert!(!params.is_empty());
        let long_params = build_params(&[(
            OsString::from("k".repeat(200)),
            OsString::from("v".repeat(200)),
        )]);
        assert!(long_params.len() > 400);

        let mut sink = Sink(Vec::new());
        let body = vec![b'b'; 130_000];
        send_request(
            &mut sink,
            &vec![b'p'; 130_000],
            &mut Cursor::new(body.clone()),
        )
        .unwrap();
        assert!(sink.0.len() > body.len());
        assert_eq!(sink.0[0], FCGI_VERSION);
        assert!(sink.0.windows(2).any(|w| w == [FCGI_VERSION, FCGI_PARAMS]));

        let mut empty_records = Vec::new();
        for _ in 0..=MAX_FASTCGI_RECORDS {
            record(&mut empty_records, FCGI_STDERR, 1, &[]);
        }
        let error =
            read_response_with_limit(&mut Cursor::new(empty_records), DEFAULT_MAX_FASTCGI_OUTPUT)
                .err()
                .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let mut ignored_records = Vec::new();
        for _ in 0..32 {
            record(&mut ignored_records, 99, 1, &vec![0; u16::MAX as usize]);
        }
        let error = read_response_with_limit(
            &mut Cursor::new(ignored_records),
            DEFAULT_MAX_FASTCGI_OUTPUT,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let mut stderr = Vec::new();
        for _ in 0..20 {
            record(&mut stderr, FCGI_STDERR, 1, &vec![b'e'; u16::MAX as usize]);
        }
        let error = read_response_with_limit(&mut Cursor::new(stderr), DEFAULT_MAX_FASTCGI_OUTPUT)
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    fn spool_from_bytes(data: &[u8]) -> Spool {
        let mut file = temp_file().unwrap();
        file.write_all(data).unwrap();
        Spool::File {
            file,
            len: data.len() as u64,
            lease: None,
        }
    }

    #[test]
    fn spool_and_response_conversion_edges() {
        let mut spool = Spool::Memory(Vec::new());
        assert_eq!(spool.len(), 0);
        spool.push(b"abc").unwrap();
        assert_eq!(spool.len(), 3);
        let large = vec![b'x'; FASTCGI_SPOOL_THRESHOLD + 1];
        spool.push(&large).unwrap();
        assert!(matches!(spool, Spool::File { .. }));
        spool.push(b"z").unwrap();
        assert_eq!(spool.len(), 3 + large.len() as u64 + 1);

        let memory = response_from_spool(
            Spool::Memory(b"Content-Type: text/plain\r\n\r\nhello".to_vec()),
            crate::http::Version::Http11,
        )
        .unwrap();
        assert_eq!(memory.body_len(), 5);
        assert!(response_from_spool(
            Spool::Memory(b"not-a-response".to_vec()),
            crate::http::Version::Http11
        )
        .is_err());

        let file = response_from_spool(
            spool_from_bytes(b"Content-Type: text/plain\r\n\r\nhello"),
            crate::http::Version::Http11,
        )
        .unwrap();
        assert!(matches!(file.body, Body::File { len: 5, .. }));

        let lf_only = response_from_spool(
            spool_from_bytes(b"Content-Type: text/plain\n\nhello"),
            crate::http::Version::Http11,
        )
        .unwrap();
        assert!(matches!(lf_only.body, Body::File { len: 5, .. }));

        let no_header = response_from_spool(
            spool_from_bytes(b"no header separator"),
            crate::http::Version::Http11,
        );
        assert!(no_header.is_err());

        let empty = response_from_spool(
            spool_from_bytes(b"Status: 204 No Content\r\n\r\n"),
            crate::http::Version::Http11,
        )
        .unwrap();
        assert!(matches!(empty.body, Body::Empty));

        assert!(response_from_spool(
            spool_from_bytes(b"Content-Type\r\n\r\n"),
            crate::http::Version::Http11
        )
        .is_err());
    }

    #[test]
    fn response_reader_unknown_records_and_output_limit() {
        let mut input = Vec::new();
        record(&mut input, 99, 1, b"ignored");
        record(&mut input, FCGI_END_REQUEST, 1, &[0u8; 8]);
        let mut cursor = Cursor::new(input);
        let (spool, stderr) = read_response(&mut cursor).unwrap();
        assert_eq!(spool.len(), 0);
        assert!(stderr.is_empty());

        let mut input = Vec::new();
        record(&mut input, FCGI_STDOUT, 1, b"12345678");
        record(&mut input, FCGI_END_REQUEST, 1, &[0u8; 8]);
        let mut cursor = Cursor::new(input);
        assert!(read_response_with_limit(&mut cursor, 4).is_err());

        let mut input = Vec::new();
        for _ in 0..8 {
            record(&mut input, FCGI_STDERR, 1, &vec![b'e'; 16 * 1024]);
        }
        record(&mut input, FCGI_END_REQUEST, 1, &[0u8; 8]);
        let mut cursor = Cursor::new(input);
        let (_, stderr) = read_response(&mut cursor).unwrap();
        assert!(stderr.len() <= 64 * 1024);
    }

    #[test]
    fn fastcgi_response_spool_holds_aggregate_budget_until_response_drop() {
        let mut payload = b"Content-Type: text/plain\r\n\r\n".to_vec();
        payload.extend(std::iter::repeat(b'x').take(FASTCGI_SPOOL_THRESHOLD + 32));
        let mut input = Vec::new();
        for chunk in payload.chunks(60_000) {
            record(&mut input, FCGI_STDOUT, 1, chunk);
        }
        record(&mut input, FCGI_END_REQUEST, 1, &[0u8; 8]);
        let budget = Arc::new(crate::resource::ResourceBudget::default());
        let context = budget.context("192.0.2.1".parse().unwrap());
        let mut cursor = Cursor::new(input);
        let (spool, _) = read_response_with_budget(
            &mut cursor,
            2 * 1024 * 1024,
            Some((&budget, &context, 8 * 1024 * 1024, 1)),
        )
        .unwrap();
        assert_eq!(budget.usage().1, 1);
        let response = response_from_spool(spool, crate::http::Version::Http11).unwrap();
        assert_eq!(budget.usage().1, 1);
        drop(response);
        assert_eq!(budget.usage(), (0, 0, 0));
    }

    fn mock_fastcgi_with_stderr(listener: UnixListener) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            loop {
                let mut header = [0u8; 8];
                if stream.read_exact(&mut header).is_err() {
                    break;
                }
                let ty = header[1];
                let len = u16::from_be_bytes([header[4], header[5]]) as usize;
                let pad = header[6] as usize;
                let mut content = vec![0u8; len + pad];
                stream.read_exact(&mut content).unwrap();
                if ty == FCGI_STDIN && len == 0 {
                    break;
                }
            }
            let mut out = Vec::new();
            record(&mut out, FCGI_STDERR, 1, b"backend diagnostic\n");
            record(
                &mut out,
                FCGI_STDOUT,
                1,
                b"Content-Type: text/plain\r\n\r\nok\n",
            );
            record(&mut out, FCGI_STDOUT, 1, &[]);
            record(&mut out, FCGI_END_REQUEST, 1, &[0u8; 8]);
            stream.write_all(&out).unwrap();
        })
    }

    #[test]
    fn execute_error_stderr_and_spooled_body_paths() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-exec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let req = request("/index.php");

        let missing = Target {
            backend: parse_backend("unix:/definitely/missing.sock|fcgi://localhost").unwrap(),
            script_filename: LexicalScriptPath::for_test(dir.join("index.php")),
            script_name: "/index.php".into(),
            path_info: String::new(),
            route_order: 0,
            logical_url: None,
        };
        let mut ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new(""),
            script_name: "/index.php",
            path_info: "",
            docroot: &dir,
            remote_ip: "not-an-ip",
            remote_port: 12345,
            local_ip: "127.0.0.1",
            local_port: 8080,
            https: false,
            server_name: "localhost",
            host: "localhost",
            follow_symlinks: false,
            env: &[],
            remote_user: None,
            auth_type: None,
            script_file: None,
        };
        assert_eq!(execute(&ctx, &cfg.global, &missing).status, 502);

        let sock = dir.join("fcgi.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = mock_fastcgi_with_stderr(listener);
        let target = Target {
            backend: parse_backend(&format!("unix:{}|fcgi://localhost", sock.display())).unwrap(),
            script_filename: LexicalScriptPath::for_test(dir.join("index.php")),
            script_name: "/index.php".into(),
            path_info: String::new(),
            route_order: 0,
            logical_url: None,
        };
        assert_eq!(execute(&ctx, &cfg.global, &target).status, 200);
        handle.join().unwrap();
        let _ = fs::remove_file(&sock);

        // Exercise the spooled request-body path through the same worker.
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = mock_fastcgi(listener, Arc::new(Mutex::new(Vec::new())), None);
        let body = vec![b'b'; 1_500_000];
        let mut wire = format!(
            "POST /index.php HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        wire.extend_from_slice(&body);
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        let spooled = crate::http::read_request(
            &mut cursor,
            &mut buf,
            &crate::http::Limits::default(),
            |_| {},
        )
        .unwrap()
        .unwrap();
        assert!(spooled.body_spool.is_some());
        ctx.req = &spooled;
        assert_eq!(execute(&ctx, &cfg.global, &target).status, 200);
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fastcgi_script_targets_cannot_escape_the_configured_base() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-base-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let root = dir.join("www");
        let outside = dir.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("index.php"), "<?php\n").unwrap();
        fs::write(outside.join("secret.php"), "<?php\n").unwrap();
        let sibling = dir.join("www2");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(sibling.join("secret.php"), "<?php\n").unwrap();

        let prefix = parse_backend(&format!(
            "unix:/run/php.sock|fcgi://localhost{}/",
            root.display()
        ))
        .unwrap();
        let (script, base) = script_from_prefix(&prefix, &root, Path::new("index.php")).unwrap();
        assert_eq!(script, root.join("index.php"));
        assert!(script.starts_with(&base));
        assert!(
            script_from_prefix(&prefix, &root, Path::new("../../outside/secret.php")).is_none()
        );
        // `/…/www2` shares a byte prefix with `/…/www` but is not a child.
        assert!(split_path_info(sibling.join("secret.php"), "/x", &base).is_none());

        let template = parse_backend(&format!(
            "unix:/run/php.sock|fcgi://localhost{}/$1",
            root.display()
        ))
        .unwrap();
        assert!(script_from_prefix(&template, &root, Path::new("../outside/secret.php")).is_none());

        let no_prefix = parse_backend("unix:/run/php.sock|fcgi://localhost").unwrap();
        let (script, base) = script_from_prefix(&no_prefix, &root, Path::new("index.php")).unwrap();
        assert_eq!(script, root.join("index.php"));
        assert!(split_path_info(script.clone(), "/index.php/info", &base).is_some());
        // Even a caller-supplied target outside the base is rejected, and the
        // PATH_INFO ancestor walk cannot select an ancestor file such as
        // /bin/sh above the document root.
        assert!(split_path_info(outside.join("secret.php"), "/x", &base).is_none());
        assert!(split_path_info(root.join("../outside/secret.php/info"), "/x", &base).is_none());
        std::os::unix::fs::symlink(outside.join("secret.php"), root.join("link.php")).unwrap();
        assert!(split_path_info(root.join("link.php"), "/link.php", &base).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fastcgi_binding_rejects_a_swapped_script_inode() {
        let dir = std::env::temp_dir().join(format!("vapache-fcgi-inode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("index.php");
        let old = dir.join("selected.php");
        fs::write(&script, "<?php echo 'selected';\n").unwrap();
        let target = Target {
            backend: parse_backend("fcgi://127.0.0.1:9000/").unwrap(),
            script_filename: LexicalScriptPath::for_test(script.clone()),
            script_name: "/index.php".into(),
            path_info: String::new(),
            route_order: 0,
            logical_url: None,
        };
        let non_file_target = Target {
            script_filename: LexicalScriptPath::for_test(dir.clone()),
            ..target.clone()
        };
        assert!(open_script(&non_file_target, &dir, true, false).is_none());
        let binding = open_script(&target, &dir, true, false).expect("opened script");
        fs::rename(&script, &old).unwrap();
        fs::write(&script, "<?php echo 'replacement';\n").unwrap();
        assert!(retain_script_path_binding(&target, &binding).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
