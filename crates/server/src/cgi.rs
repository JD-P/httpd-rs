//! CGI/1.1 execution.
//!
//! Scripts are executed directly with `execve` (never through a shell), with a
//! minimal, explicitly constructed environment, `PR_SET_NO_NEW_PRIVS`, a new
//! session, resource limits, a watchdog that kills the process group on
//! timeout, and bounded output.  Response headers emitted by the script are
//! parsed and re-serialized through the same validated header path as native
//! responses, preventing response splitting.

use crate::config::{Config, VHost};
use crate::http::{Headers, Request, RequestBodyReader, Response, Version};
use crate::util::trim_ascii;
use crate::verified::valid_token;
use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

const MAX_OUTPUT: usize = 8 * 1024 * 1024;
const MAX_HEADER: usize = 64 * 1024;
const MAX_STDERR: usize = 64 * 1024;
const CGI_BODY_IN_MEMORY: u64 = 1024 * 1024;

/// Request body for CGI execution.  The HTTP reader already spools bodies
/// above 1 MiB to an unlinked file; keep them there through the worker
/// protocol instead of materializing the whole body in each process.
enum BodySource {
    Bytes(Vec<u8>),
    File(File),
    Stream {
        reader: Mutex<Option<RequestBodyReader>>,
        len: u64,
    },
}

impl BodySource {
    fn len(&self) -> u64 {
        match self {
            BodySource::Bytes(bytes) => bytes.len() as u64,
            BodySource::File(file) => file.metadata().map(|m| m.len()).unwrap_or(0),
            BodySource::Stream { len, .. } => *len,
        }
    }

    fn reader(&self) -> std::io::Result<Box<dyn Read + Send>> {
        match self {
            BodySource::Bytes(bytes) => Ok(Box::new(std::io::Cursor::new(bytes.clone()))),
            BodySource::File(file) => {
                let mut clone = file.try_clone()?;
                clone.seek(SeekFrom::Start(0))?;
                Ok(Box::new(clone))
            }
            BodySource::Stream { reader, .. } => reader
                .lock()
                .map_err(|_| std::io::Error::other("CGI body stream lock poisoned"))?
                .take()
                .map(|reader| Box::new(reader) as Box<dyn Read + Send>)
                .ok_or_else(|| std::io::Error::other("CGI body stream already consumed")),
        }
    }
}

pub struct ScriptTarget {
    pub rel_script: PathBuf,
    pub file: File,
    pub meta: Metadata,
    pub path_info: String,
}

/// Find the executable prefix of a mapped path, splitting `PATH_INFO` the way
/// Apache's mod_cgi does when the trailing path does not exist.
pub fn find_script(root: &Path, rel: &Path, follow: bool) -> Option<ScriptTarget> {
    find_script_checked_inner(root, rel, follow, false, None)
}

pub fn find_script_checked(
    root: &Path,
    rel: &Path,
    follow: bool,
    owner_match_only: bool,
) -> Option<ScriptTarget> {
    find_script_checked_inner(root, rel, follow, owner_match_only, None)
}

pub(crate) fn find_script_checked_for_request(
    root: &Path,
    rel: &Path,
    follow: bool,
    owner_match_only: bool,
    req: &Request,
) -> Option<ScriptTarget> {
    find_script_checked_inner(root, rel, follow, owner_match_only, Some(req))
}

fn find_script_checked_inner(
    root: &Path,
    rel: &Path,
    follow: bool,
    owner_match_only: bool,
    req: Option<&Request>,
) -> Option<ScriptTarget> {
    let comps: Vec<&std::ffi::OsStr> = rel.iter().collect();
    if comps.len() > crate::util::MAX_POLICY_PATH_COMPONENTS {
        if let Some(req) = req {
            let _ = req.charge_policy_work(u64::MAX);
        }
        return None;
    }
    // Mutate one buffer while shortening it instead of rebuilding every
    // prefix.  Kernel probes are additionally charged by prefix length, so
    // CGI-enabled configurations retain a request-local bound even when most
    // of the candidate prefixes do not exist.
    let mut prefix = rel.to_path_buf();
    let mut n = comps.len();
    while n > 0 {
        if req.is_some_and(|req| {
            req.charge_policy_work(
                (prefix.as_os_str().as_encoded_bytes().len() as u64).saturating_add(1),
            )
            .is_err()
        }) {
            return None;
        }
        if let crate::files::Target::File { file, meta, .. } =
            crate::files::resolve_target_checked(root, &prefix, follow, owner_match_only)
        {
            let info = comps[n..]
                .iter()
                .map(|c| c.to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            return Some(ScriptTarget {
                rel_script: prefix,
                file,
                meta,
                path_info: if info.is_empty() {
                    String::new()
                } else {
                    format!("/{info}")
                },
            });
        }
        prefix.pop();
        n -= 1;
    }
    None
}

pub struct CgiContext<'a> {
    pub cfg: &'a Config,
    pub vhost: Option<&'a VHost>,
    pub req: &'a Request,
    pub root: &'a Path,
    pub script_rel: &'a Path,
    pub script_name: &'a str,
    pub path_info: &'a str,
    pub docroot: &'a Path,
    pub remote_ip: &'a str,
    pub remote_port: u16,
    pub local_ip: &'a str,
    pub local_port: u16,
    /// True when the request arrived over a TLS listener.
    pub https: bool,
    pub server_name: &'a str,
    pub host: &'a str,
    pub follow_symlinks: bool,
    pub env: &'a [(String, Vec<u8>)],
    /// Authenticated user from the access grant, exported as `REMOTE_USER`.
    pub remote_user: Option<&'a str>,
    /// Authentication scheme (for example `Basic`) exported as `AUTH_TYPE`.
    pub auth_type: Option<&'a str>,
    /// Opened script descriptor, when the caller already authorized a
    /// specific inode.  Execution uses `/proc/self/fd` so the path cannot be
    /// swapped between authorization and exec.
    pub script_file: Option<&'a File>,
}

fn sanitize_env_value(v: &[u8]) -> String {
    // NUL cannot appear in an environment variable; replace other non-UTF8
    // bytes lossily.  CR/LF in headers are rejected by the HTTP parser.
    String::from_utf8_lossy(v).replace('\0', "")
}

/// Names whose values are calculated from the request, connection or
/// authenticated identity.  A `SetEnv`/rewrite environment entry must not
/// replace them: that is the CVE-2025-65082 boundary.  `HTTP_*` covers all
/// request-derived CGI header variables.
fn reserved_cgi_env(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    matches!(
        name.as_str(),
        "GATEWAY_INTERFACE"
            | "SERVER_SOFTWARE"
            | "SERVER_PROTOCOL"
            | "SERVER_NAME"
            | "SERVER_ADDR"
            | "SERVER_PORT"
            | "SERVER_ADMIN"
            | "DOCUMENT_ROOT"
            | "REQUEST_METHOD"
            | "REQUEST_URI"
            | "REQUEST_SCHEME"
            | "QUERY_STRING"
            | "SCRIPT_NAME"
            | "SCRIPT_FILENAME"
            | "PATH_INFO"
            | "PATH_TRANSLATED"
            | "REMOTE_ADDR"
            | "REMOTE_PORT"
            | "REMOTE_HOST"
            | "REMOTE_USER"
            | "AUTH_TYPE"
            | "CONTENT_TYPE"
            | "CONTENT_LENGTH"
            | "REDIRECT_STATUS"
            | "HTTPS"
    ) || name.starts_with("HTTP_")
}

pub(crate) fn build_env(ctx: &CgiContext) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    // CGI environment values are byte strings on Unix. Preserve the exact
    // query instead of collapsing distinct octets through lossy UTF-8.
    env.push((
        OsString::from("QUERY_STRING"),
        OsString::from_vec(ctx.req.query.clone()),
    ));
    let mut put = |k: &str, v: String| env.push((OsString::from(k), OsString::from(v)));
    put("GATEWAY_INTERFACE", "CGI/1.1".into());
    put("SERVER_SOFTWARE", ctx.cfg.server_header());
    put("SERVER_PROTOCOL", ctx.req.version.as_str().to_string());
    put("SERVER_NAME", ctx.server_name.to_string());
    put("SERVER_ADDR", ctx.local_ip.to_string());
    put("SERVER_PORT", ctx.local_port.to_string());
    put(
        "SERVER_ADMIN",
        ctx.vhost
            .and_then(|vhost| vhost.server_admin.clone())
            .unwrap_or_else(|| ctx.cfg.server_admin.clone()),
    );
    put("DOCUMENT_ROOT", ctx.docroot.to_string_lossy().into_owned());
    put("REQUEST_METHOD", ctx.req.method.clone());
    // Apache's CGI REQUEST_URI is the canonical URL path, without the query
    // string.  Never export the raw request-line target (F57).  The script
    // name has already had PATH_INFO removed when it is nonempty.
    let request_uri = if !ctx.path_info.is_empty() && !ctx.script_name.ends_with(ctx.path_info) {
        format!("{}{}", ctx.script_name, ctx.path_info)
    } else {
        ctx.script_name.to_string()
    };
    put("REQUEST_URI", request_uri);
    put("SCRIPT_NAME", ctx.script_name.to_string());
    put(
        "SCRIPT_FILENAME",
        ctx.root.join(ctx.script_rel).to_string_lossy().into_owned(),
    );
    if !ctx.path_info.is_empty() {
        put("PATH_INFO", ctx.path_info.to_string());
        let pi = ctx.path_info.trim_start_matches('/');
        put(
            "PATH_TRANSLATED",
            ctx.docroot.join(pi).to_string_lossy().into_owned(),
        );
    }
    put("REMOTE_ADDR", ctx.remote_ip.to_string());
    put("REMOTE_PORT", ctx.remote_port.to_string());
    put("REMOTE_HOST", ctx.remote_ip.to_string());
    if let Some(user) = ctx.remote_user.filter(|user| !user.is_empty()) {
        put("REMOTE_USER", user.to_string());
        if let Some(auth_type) = ctx.auth_type.filter(|kind| !kind.is_empty()) {
            put("AUTH_TYPE", auth_type.to_string());
        }
    }
    put(
        "REQUEST_SCHEME",
        if ctx.https { "https" } else { "http" }.into(),
    );
    if ctx.https {
        put("HTTPS", "on".into());
    }
    put("REDIRECT_STATUS", "200".into());
    put("PATH", "/usr/local/bin:/usr/bin:/bin".into());
    put("LANG", "C".into());
    put("TZ", "UTC".into());

    if let Some(ct) = ctx.req.header("content-type") {
        put("CONTENT_TYPE", sanitize_env_value(ct));
    }
    if let Some(cl) = ctx.req.header("content-length") {
        put("CONTENT_LENGTH", sanitize_env_value(cl));
    } else if ctx.req.body_len() > 0 {
        put("CONTENT_LENGTH", ctx.req.body_len().to_string());
    }
    for (name, value) in ctx.req.headers.iter() {
        if matches!(
            name,
            "content-type" | "content-length" | "connection" | "proxy"
        ) {
            continue;
        }
        // httpoxy: a request header named Proxy must never become HTTP_PROXY.
        let env_name = format!("HTTP_{}", name.to_ascii_uppercase().replace('-', "_"));
        if valid_token(env_name.as_bytes()) {
            put(&env_name, sanitize_env_value(value));
        }
    }
    if let Some(auth) = ctx.req.header("authorization") {
        // Never expose credentials as HTTP_AUTHORIZATION to CGI; Apache uses
        // AUTH_TYPE/REMOTE_USER after authentication.
        env.retain(|(k, _)| k != "HTTP_AUTHORIZATION");
        let _ = auth;
    }
    for (k, v) in ctx.env {
        // Do not let a configured/rewrite environment entry shadow values
        // computed from the request.  Custom non-CGI variables remain
        // available to the application.
        let key_valid = !k.is_empty() && !k.contains('=') && !k.as_bytes().contains(&0);
        if !vapache_verified::cgi_env_entry_admit(key_valid, reserved_cgi_env(k)) {
            continue;
        }
        env.retain(|(n, _)| n != k.as_str());
        if v.contains(&0) {
            continue;
        }
        env.push((OsString::from(k), OsString::from_vec(v.clone())));
    }
    env
}

pub fn execute(ctx: &CgiContext) -> Response {
    #[cfg(test)]
    let fallback_context;
    let resource_context = match ctx.req.resource_context() {
        Some(context) => context,
        #[cfg(test)]
        None => {
            fallback_context = ctx.cfg.resource_budget.context(
                ctx.remote_ip
                    .parse()
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            );
            &fallback_context
        }
        #[cfg(not(test))]
        None => {
            eprintln!("vapached: CGI request has no resource scope");
            return cgi_status_error(ctx, 503);
        }
    };
    let _dynamic_lease = match ctx.cfg.resource_budget.try_dynamic_descriptors_in(
        resource_context,
        ctx.cfg.max_dynamic_requests,
        4,
    ) {
        Ok(lease) => lease,
        Err(e) => {
            eprintln!("vapached: CGI admission failed: {e}");
            return cgi_status_error(ctx, 503);
        }
    };
    let original_path = ctx.root.join(ctx.script_rel);
    let cwd = original_path
        .parent()
        .unwrap_or(Path::new("/"))
        .to_path_buf();
    let env = build_env(ctx);
    // Keep large bodies on their existing spool file.  Only the small
    // in-memory case is copied, so concurrent CGI POSTs no longer multiply
    // LimitRequestBody-sized allocations.
    let body = match ctx.req.body_reader() {
        Some(Ok(RequestBodyReader::File(file))) => BodySource::File(file),
        Some(Ok(reader)) => BodySource::Stream {
            reader: Mutex::new(Some(reader)),
            len: ctx.req.body_len(),
        },
        _ => BodySource::Bytes(ctx.req.body.clone()),
    };

    // Every production CGI request goes through the pre-forked worker pool.
    // The worker reopens the path and verifies the authorized dev/inode
    // immediately before exec. Never downgrade to spawning from the large,
    // multithreaded daemon when the pool is absent or saturated: temporarily
    // making the script descriptor inheritable there races every other spawn.
    let worker_identity = match ctx.script_file {
        Some(file) => match file.metadata() {
            Ok(meta) => Some((meta.dev(), meta.ino())),
            Err(_) => return cgi_error(ctx),
        },
        None => None,
    };

    #[cfg(test)]
    return execute_direct_for_test(
        ctx,
        &original_path,
        &cwd,
        &env,
        &body,
        worker_identity,
        resource_context,
    );

    #[cfg(not(test))]
    if let Some(pool) = POOL.get() {
        execute_via_pool(
            pool,
            ctx,
            &original_path,
            &cwd,
            &env,
            &body,
            worker_identity,
            resource_context,
        )
    } else {
        eprintln!("vapached: CGI worker pool is unavailable");
        cgi_status_error(ctx, 503)
    }
}

#[cfg(test)]
fn execute_direct_for_test(
    ctx: &CgiContext,
    path: &Path,
    cwd: &Path,
    env: &[(OsString, OsString)],
    body: &BodySource,
    expected: Option<(u64, u64)>,
    resource_context: &crate::resource::ResourceContext,
) -> Response {
    let mut response_lease = match ctx
        .cfg
        .resource_budget
        .try_response_bytes_in(resource_context)
    {
        Ok(lease) => lease,
        Err(_) => return cgi_status_error(ctx, 503),
    };
    match run_local(
        &path,
        &cwd,
        &env,
        &body,
        ctx.cfg.timeout,
        expected,
        Some(&mut response_lease),
        ctx.req.request_scope(),
    ) {
        Ok((out, stderr)) => {
            if !stderr.trim().is_empty() {
                eprintln!("CGI stderr: {}", stderr.trim());
            }
            if response_lease.reserve(out.len() as u64).is_err() {
                return cgi_status_error(ctx, 503);
            }
            let parsed = parse_cgi_response(&out, ctx.req.version);
            // The second reservation covers the parser's body copy while the
            // complete CGI wire buffer is still live. Drop that source before
            // shrinking the lease to the retained representation.
            drop(out);
            match parsed {
                Ok(mut r) => {
                    response_lease.release(response_lease.bytes().saturating_sub(r.body_len()));
                    r.hold_resident(response_lease);
                    r
                }
                Err(()) => cgi_error(ctx),
            }
        }
        Err(e) => {
            eprintln!("vapached: CGI failed: {e}");
            cgi_error(ctx)
        }
    }
}

fn execute_via_pool(
    pool: &CgiPool,
    ctx: &CgiContext,
    path: &Path,
    cwd: &Path,
    env: &[(OsString, OsString)],
    body: &BodySource,
    expected: Option<(u64, u64)>,
    resource_context: &crate::resource::ResourceContext,
) -> Response {
    let stream_body = matches!(body, BodySource::Stream { .. });
    let mut worker_spool_lease = match body {
        BodySource::File(_) | BodySource::Stream { .. } => {
            let mut lease = match ctx.cfg.resource_budget.try_spool_in(
                ctx.cfg.max_spool_bytes,
                ctx.cfg.max_spool_files,
                resource_context,
            ) {
                Ok(lease) => lease,
                Err(e) => {
                    eprintln!("vapached: CGI worker spool admission failed: {e}");
                    return cgi_status_error(ctx, 503);
                }
            };
            if !stream_body {
                if let Err(e) = lease.reserve(body.len()) {
                    eprintln!("vapached: CGI worker spool admission failed: {e}");
                    return cgi_status_error(ctx, 503);
                }
            }
            Some(lease)
        }
        BodySource::Bytes(_) => None,
    };
    let Some(mut worker) = pool.take() else {
        return cgi_status_error(ctx, 503);
    };
    let mut response_lease = match ctx
        .cfg
        .resource_budget
        .try_response_bytes_in(resource_context)
    {
        Ok(lease) => lease,
        Err(_) => {
            worker.terminate();
            return cgi_status_error(ctx, 503);
        }
    };
    let incremental_spool = stream_body.then(|| worker_spool_lease.as_mut()).flatten();
    match exchange(
        &mut worker.stream,
        path,
        cwd,
        env,
        body,
        ctx.cfg.timeout,
        expected,
        Some(&mut response_lease),
        incremental_spool,
        ctx.req.request_scope(),
    ) {
        Ok((out, stderr)) => {
            pool.put(worker);
            if !stderr.trim().is_empty() {
                eprintln!("CGI stderr: {}", stderr.trim());
            }
            if response_lease.reserve(out.len() as u64).is_err() {
                return cgi_status_error(ctx, 503);
            }
            let parsed = parse_cgi_response(&out, ctx.req.version);
            drop(out);
            match parsed {
                Ok(mut r) => {
                    response_lease.release(response_lease.bytes().saturating_sub(r.body_len()));
                    r.hold_resident(response_lease);
                    r
                }
                Err(()) => cgi_error(ctx),
            }
        }
        Err(e) => {
            // Do not retry locally: the script may already have run.
            worker.terminate();
            eprintln!("vapached: CGI worker failed: {e}");
            cgi_error(ctx)
        }
    }
}

fn cgi_error(ctx: &CgiContext) -> Response {
    cgi_status_error(ctx, 500)
}

fn cgi_status_error(ctx: &CgiContext, status: u16) -> Response {
    crate::files::error_response(
        ctx.cfg,
        ctx.vhost,
        &crate::config::Scope::default(),
        status,
        ctx.req,
        ctx.script_name,
        ctx.local_port,
        ctx.host,
        ctx.remote_ip
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        ctx.local_ip,
    )
}

const WORKER_FD: i32 = 3;
const MAX_WORKER_BODY: u64 = 2 * 1024 * 1024 * 1024;
const MAX_WORKER_ENV: u32 = 4096;
const MAX_WORKER_PATH: u32 = 64 * 1024;

struct CgiWorker {
    stream: UnixStream,
    child: Child,
}

impl CgiWorker {
    fn terminate(mut self) {
        let pid = self.child.id() as i32;
        drop(self.stream);
        kill_group(pid);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct CgiPool {
    workers: Mutex<Vec<CgiWorker>>,
    ready: Condvar,
    closed: AtomicBool,
}

static POOL: OnceLock<CgiPool> = OnceLock::new();

impl CgiPool {
    fn take(&self) -> Option<CgiWorker> {
        let mut guard = self.workers.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::Relaxed) {
            return None;
        }
        if guard.is_empty() {
            let (next, _) = self
                .ready
                .wait_timeout(guard, Duration::from_millis(500))
                .unwrap_or_else(|e| e.into_inner());
            guard = next;
        }
        guard.pop()
    }

    fn put(&self, worker: CgiWorker) {
        let mut guard = self.workers.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::Relaxed) {
            drop(guard);
            worker.terminate();
            return;
        }
        guard.push(worker);
        self.ready.notify_one();
    }
}

/// Ask idle CGI workers to exit and wait briefly for their coverage/output
/// streams to close cleanly.  Called during server shutdown so a SIGTERM does
/// not truncate a worker's LLVM profile or leave children behind.
pub fn shutdown_pool() {
    if let Some(pool) = POOL.get() {
        shutdown_pool_inner(pool);
    }
}

fn shutdown_pool_inner(pool: &CgiPool) {
    pool.closed.store(true, Ordering::SeqCst);
    pool.ready.notify_all();
    let workers = {
        let mut guard = pool.workers.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
    };
    for worker in workers {
        worker.terminate();
    }
}

/// Create the CGI worker pool.  Called from the main process before it drops
/// privileges, so workers can exec a binary that lives in a root-only
/// directory and then drop to the configured user themselves.
pub fn init_pool(cfg: &Config) -> Result<(), String> {
    if POOL.get().is_some() {
        return Ok(());
    }
    let (uid, gid) = worker_ids(&cfg.user, &cfg.group)?;
    let pool = start_pool(uid, gid, &cfg.user)?;
    POOL.set(pool)
        .map_err(|_| "CGI worker pool already initialized".to_string())
}

fn worker_ids(user: &str, group: &str) -> Result<(u32, u32), String> {
    worker_ids_for(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        user,
        group,
    )
}

fn worker_ids_for(euid: u32, egid: u32, user: &str, group: &str) -> Result<(u32, u32), String> {
    if euid != 0 {
        return Ok((euid, egid));
    }
    let uid = if let Ok(n) = user.parse::<u32>() {
        n
    } else {
        let cuser = std::ffi::CString::new(user).map_err(|_| "invalid CGI user".to_string())?;
        let pw = unsafe { libc::getpwnam(cuser.as_ptr()) };
        if pw.is_null() {
            return Err(format!("CGI user '{user}' not found"));
        }
        unsafe { (*pw).pw_uid }
    };
    let gid = if let Ok(n) = group.parse::<u32>() {
        n
    } else {
        let cgroup = std::ffi::CString::new(group).map_err(|_| "invalid CGI group".to_string())?;
        let gr = unsafe { libc::getgrnam(cgroup.as_ptr()) };
        if gr.is_null() {
            return Err(format!("CGI group '{group}' not found"));
        }
        unsafe { (*gr).gr_gid }
    };
    if uid == 0 || gid == 0 {
        return Err("refusing to run CGI workers as root user/group".into());
    }
    Ok((uid, gid))
}

fn prepare_worker_fd(child_fd: i32, target: i32, parent_pid: libc::pid_t) -> std::io::Result<()> {
    crate::process::bind_to_parent(parent_pid)?;
    crate::process::cloexec_unrelated_descriptors()?;
    if unsafe { libc::dup2(child_fd, target) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    crate::process::set_cloexec(target, false)
}

fn child_process_setup(
    timeout: Duration,
    retained_fd: Option<i32>,
    parent_pid: libc::pid_t,
) -> std::io::Result<()> {
    crate::process::bind_to_parent(parent_pid)?;
    crate::process::cloexec_unrelated_descriptors()?;
    if let Some(fd) = retained_fd {
        crate::process::set_cloexec(fd, false)?;
    }
    unsafe {
        if libc::setsid() < 0 {
            return Err(std::io::Error::last_os_error());
        }
        libc::umask(0o022);
    }
    crate::process::no_new_privileges()?;
    crate::process::disable_dumping()?;
    crate::process::set_limit(libc::RLIMIT_CPU, timeout.as_secs().max(1))?;
    crate::process::set_limit(libc::RLIMIT_FSIZE, MAX_OUTPUT as u64)?;
    crate::process::set_limit(libc::RLIMIT_NOFILE, 128)?;
    Ok(())
}

fn start_pool(uid: u32, gid: u32, user: &str) -> Result<CgiPool, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find own executable: {e}"))?;
    // Start enough workers for the common concurrent CGI fan-out.  Each one is
    // a tiny single-threaded process that waits on a socket when idle.
    let count = std::thread::available_parallelism()
        .map(|n| n.get() * 4)
        .unwrap_or(8)
        .clamp(8, 64);
    start_pool_with_exe(&exe, uid, gid, user, count)
}

fn start_pool_with_exe(
    exe: &Path,
    uid: u32,
    gid: u32,
    user: &str,
    count: usize,
) -> Result<CgiPool, String> {
    let parent_pid = unsafe { libc::getpid() };
    let mut workers = Vec::with_capacity(count);
    for _ in 0..count {
        match start_pool_worker(exe, uid, gid, user, parent_pid) {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                for worker in workers {
                    worker.terminate();
                }
                return Err(error);
            }
        }
    }
    Ok(CgiPool {
        workers: Mutex::new(workers),
        ready: Condvar::new(),
        closed: AtomicBool::new(false),
    })
}

fn start_pool_worker(
    exe: &Path,
    uid: u32,
    gid: u32,
    user: &str,
    parent_pid: libc::pid_t,
) -> Result<CgiWorker, String> {
    let (parent, child) =
        UnixStream::pair().map_err(|e| format!("cannot create CGI worker socket: {e}"))?;
    parent
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    parent
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    let child_fd = child.as_raw_fd();
    let mut cmd = Command::new(exe);
    cmd.arg("--cgi-worker")
        .arg(uid.to_string())
        .arg(gid.to_string())
        .arg(user)
        .arg(parent_pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear();
    // Keep coverage collection working in the isolated worker. This is the
    // only environment variable inherited, and only when the operator
    // explicitly set a profile path.
    if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
        cmd.env("LLVM_PROFILE_FILE", profile);
    }
    // Keep the descriptor across this exec (the worker needs it). The worker
    // sets FD_CLOEXEC itself before spawning scripts.
    unsafe {
        cmd.pre_exec(move || prepare_worker_fd(child_fd, WORKER_FD, parent_pid));
    }
    let proc = cmd
        .spawn()
        .map_err(|e| format!("cannot spawn CGI worker: {e}"))?;
    drop(child);
    let mut worker = CgiWorker {
        stream: parent,
        child: proc,
    };
    // The worker signals readiness only after it has dropped privileges and
    // installed its limits. This catches an incomplete isolation setup before
    // any request can be handed to the process.
    let mut ready = [0u8; 1];
    if let Err(error) = worker.stream.read_exact(&mut ready) {
        worker.terminate();
        return Err(format!("CGI worker did not start: {error}"));
    }
    if ready != [1] {
        worker.terminate();
        return Err("CGI worker failed its isolation setup".into());
    }
    Ok(worker)
}

fn drop_worker_privileges(uid: u32, gid: u32, user: &str) -> bool {
    drop_worker_privileges_for(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        uid,
        gid,
        user,
    )
}

fn drop_worker_privileges_for(euid: u32, egid: u32, uid: u32, gid: u32, user: &str) -> bool {
    if uid == 0 || gid == 0 {
        return false;
    }
    if euid != 0 {
        return euid == uid && egid == gid;
    }
    if !init_worker_groups(user, gid) {
        return false;
    }
    unsafe {
        if libc::setresgid(gid, gid, gid) != 0 || libc::setresuid(uid, uid, uid) != 0 {
            return false;
        }
    }
    true
}

fn init_worker_groups(user: &str, gid: u32) -> bool {
    if user.parse::<u32>().is_ok() {
        return unsafe { libc::setgroups(0, std::ptr::null()) == 0 };
    }
    let Ok(cuser) = std::ffi::CString::new(user) else {
        return false;
    };
    let pw = unsafe { libc::getpwnam(cuser.as_ptr()) };
    if pw.is_null() {
        return false;
    }
    unsafe { libc::initgroups(cuser.as_ptr(), gid as libc::gid_t) == 0 }
}

/// CGI worker process entry point.  It is spawned once per pool slot and is
/// deliberately tiny and single-threaded until it has completed a request, so
/// fork/exec avoids copying the main server's address space and TLB entries.
pub fn worker_main(fd: i32, uid: u32, gid: u32, user: &str, parent_pid: libc::pid_t) {
    if crate::process::bind_to_parent(parent_pid).is_err() || unsafe { libc::setsid() } < 0 {
        std::process::exit(1);
    }
    unsafe { libc::umask(0o022) };
    if !drop_worker_privileges(uid, gid, user) {
        std::process::exit(1);
    }
    if crate::process::no_new_privileges().is_err()
        || crate::process::disable_dumping().is_err()
        || crate::process::set_limit(libc::RLIMIT_CPU, 3600).is_err()
        || crate::process::set_limit(libc::RLIMIT_FSIZE, MAX_OUTPUT as u64).is_err()
        || crate::process::set_limit(libc::RLIMIT_NOFILE, 128).is_err()
    {
        std::process::exit(1);
    }
    // The worker owns the control socket, but CGI scripts spawned by the
    // worker must not inherit it.  Marking it close-on-exec here (after the
    // worker's own exec) keeps the socket alive for the worker loop while
    // excluding it from every script descriptor set.
    let Some(mut stream) = stream_from_fd(fd) else {
        return;
    };
    if stream.write_all(&[1]).is_err() {
        return;
    }
    while worker_request(&mut stream).unwrap_or(false) {}
}

fn stream_from_fd(fd: i32) -> Option<UnixStream> {
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return None;
    }
    Some(unsafe { UnixStream::from_raw_fd(fd) })
}

fn worker_request(stream: &mut UnixStream) -> Result<bool, String> {
    let script = match read_bytes(stream, MAX_WORKER_PATH, true)? {
        Some(v) => PathBuf::from(OsString::from_vec(v)),
        None => return Ok(false),
    };
    let has_identity = read_u8(stream)? != 0;
    let expected = if has_identity {
        Some((read_u64(stream)?, read_u64(stream)?))
    } else {
        None
    };
    let cwd = PathBuf::from(OsString::from_vec(
        read_bytes(stream, MAX_WORKER_PATH, false)?.unwrap_or_default(),
    ));
    let env_count = read_u32(stream)?;
    if env_count > MAX_WORKER_ENV {
        return Err("too many CGI environment entries".into());
    }
    let mut env = Vec::with_capacity(env_count as usize);
    for _ in 0..env_count {
        let k = read_bytes(stream, MAX_WORKER_PATH, false)?.unwrap_or_default();
        let v = read_bytes(stream, MAX_WORKER_PATH, false)?.unwrap_or_default();
        env.push((OsString::from_vec(k), OsString::from_vec(v)));
    }
    let body_len = read_u64(stream)?;
    if body_len > MAX_WORKER_BODY {
        return Err("CGI request body too large".into());
    }
    let body = if body_len == 0 {
        BodySource::Bytes(Vec::new())
    } else if body_len <= CGI_BODY_IN_MEMORY {
        let mut body = vec![0u8; body_len as usize];
        stream
            .read_exact(&mut body)
            .map_err(|e| format!("short CGI body: {e}"))?;
        BodySource::Bytes(body)
    } else {
        let mut file =
            crate::http::spool_file().map_err(|e| format!("cannot spool CGI body: {e}"))?;
        let mut remaining = body_len;
        let mut chunk = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let want = remaining.min(chunk.len() as u64) as usize;
            stream
                .read_exact(&mut chunk[..want])
                .map_err(|e| format!("short CGI body: {e}"))?;
            file.write_all(&chunk[..want])
                .map_err(|e| format!("cannot spool CGI body: {e}"))?;
            remaining -= want as u64;
        }
        BodySource::File(file)
    };
    let timeout = Duration::from_secs(read_u64(stream)?.clamp(1, 3600));

    let result = run_local(&script, &cwd, &env, &body, timeout, expected, None, None);
    match result {
        Ok((out, stderr)) => {
            write_u8(stream, 1)?;
            write_bytes(stream, &out)?;
            write_bytes(stream, stderr.as_bytes())?;
        }
        Err(e) => {
            write_u8(stream, 0)?;
            write_bytes(stream, &[])?;
            write_bytes(stream, e.as_bytes())?;
        }
    }
    stream.flush().map_err(|e| e.to_string())?;
    Ok(true)
}

fn send_timeout(stream: &mut impl Write, timeout: Duration) -> Result<(), String> {
    match write_u64(stream, timeout.as_secs().max(1)) {
        Ok(()) => {
            let _ = stream.flush();
            Ok(())
        }
        Err(e) if e.contains("Broken pipe") => Ok(()),
        Err(e) => Err(e),
    }
}

struct CgiExchangeStream<'a> {
    inner: &'a mut UnixStream,
    deadline: Instant,
    scope: Option<crate::resource::RequestScope>,
}

impl CgiExchangeStream<'_> {
    fn interrupted(&self) -> Option<std::io::Error> {
        if self
            .scope
            .as_ref()
            .is_some_and(crate::resource::RequestScope::is_cancelled)
        {
            Some(std::io::Error::new(
                // `read_exact`/`write_all` transparently retry Interrupted;
                // cancellation must be terminal for the worker protocol.
                std::io::ErrorKind::ConnectionAborted,
                "CGI request scope cancelled",
            ))
        } else if Instant::now() >= self.deadline {
            Some(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "CGI worker exchange deadline exceeded",
            ))
        } else {
            None
        }
    }
}

impl Read for CgiExchangeStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(error) = self.interrupted() {
                return Err(error);
            }
            match self.inner.read(buf) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                result => return result,
            }
        }
    }
}

impl Write for CgiExchangeStream<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            if let Some(error) = self.interrupted() {
                return Err(error);
            }
            match self.inner.write(buf) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        loop {
            if let Some(error) = self.interrupted() {
                return Err(error);
            }
            match self.inner.flush() {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                result => return result,
            }
        }
    }
}

fn exchange(
    stream: &mut UnixStream,
    path: &Path,
    cwd: &Path,
    env: &[(OsString, OsString)],
    body: &BodySource,
    timeout: Duration,
    expected: Option<(u64, u64)>,
    response_lease: Option<&mut crate::resource::ResidentLease>,
    mut request_spool_lease: Option<&mut crate::resource::SpoolLease>,
    request_scope: Option<&crate::resource::RequestScope>,
) -> Result<(Vec<u8>, String), String> {
    let quantum = timeout.min(Duration::from_millis(100));
    stream
        .set_read_timeout(Some(quantum))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(quantum))
        .map_err(|error| error.to_string())?;
    let mut stream = CgiExchangeStream {
        inner: stream,
        deadline: Instant::now() + timeout,
        scope: request_scope.cloned(),
    };
    write_bytes(&mut stream, path.as_os_str().as_bytes())?;
    match expected {
        Some((dev, ino)) => {
            write_u8(&mut stream, 1)?;
            write_u64(&mut stream, dev)?;
            write_u64(&mut stream, ino)?;
        }
        None => write_u8(&mut stream, 0)?,
    }
    write_bytes(&mut stream, cwd.as_os_str().as_bytes())?;
    write_u32(&mut stream, env.len() as u32)?;
    for (k, v) in env {
        write_bytes(&mut stream, k.as_os_str().as_bytes())?;
        write_bytes(&mut stream, v.as_os_str().as_bytes())?;
    }
    let body_len = body.len();
    write_u64(&mut stream, body_len)?;
    let mut reader = body.reader().map_err(|e| e.to_string())?;
    let mut copied = 0u64;
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut chunk).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        if let Some(lease) = request_spool_lease.as_mut() {
            lease.reserve(read as u64).map_err(|e| e.to_string())?;
        }
        stream
            .write_all(&chunk[..read])
            .map_err(|e| e.to_string())?;
        copied += read as u64;
    }
    if copied != body_len {
        return Err("short CGI body".into());
    }
    // A worker that already produced its full response may close as soon as
    // the body is consumed; a broken pipe on the final metadata write does not
    // invalidate the response we can still read.
    send_timeout(&mut stream, timeout)?;

    let ok = read_u8(&mut stream)?;
    let out = read_bytes_budgeted(&mut stream, MAX_OUTPUT as u32, false, response_lease)?
        .unwrap_or_default();
    let err = read_bytes(&mut stream, MAX_STDERR as u32, false)?.unwrap_or_default();
    let err = String::from_utf8_lossy(&err).into_owned();
    if ok == 0 {
        return Err(if err.is_empty() {
            "CGI worker reported failure".into()
        } else {
            err
        });
    }
    Ok((out, err))
}

fn write_u8(w: &mut impl Write, v: u8) -> Result<(), String> {
    w.write_all(&[v]).map_err(|e| e.to_string())
}

fn write_u32(w: &mut impl Write, v: u32) -> Result<(), String> {
    w.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}

fn write_u64(w: &mut impl Write, v: u64) -> Result<(), String> {
    w.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}

fn read_u8(r: &mut impl Read) -> Result<u8, String> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(b[0])
}

fn read_u32(r: &mut impl Read) -> Result<u32, String> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64(r: &mut impl Read) -> Result<u64, String> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes(b))
}

fn write_bytes(w: &mut impl Write, data: &[u8]) -> Result<(), String> {
    write_u32(w, data.len() as u32)?;
    w.write_all(data).map_err(|e| e.to_string())
}

fn read_bytes(r: &mut impl Read, limit: u32, eof_ok: bool) -> Result<Option<Vec<u8>>, String> {
    read_bytes_budgeted(r, limit, eof_ok, None)
}

fn read_bytes_budgeted(
    r: &mut impl Read,
    limit: u32,
    eof_ok: bool,
    mut resident: Option<&mut crate::resource::ResidentLease>,
) -> Result<Option<Vec<u8>>, String> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if eof_ok && e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.to_string()),
    }
    let len = u32::from_le_bytes(len);
    if !vapache_verified::cgi_field_len_ok(len, limit) {
        return Err("CGI worker message field too large".into());
    }
    if let Some(lease) = resident.as_mut() {
        lease
            .reserve(len as u64)
            .map_err(|_| "CGI response memory capacity exhausted".to_string())?;
    }
    let mut data = vec![0u8; len as usize];
    r.read_exact(&mut data).map_err(|e| e.to_string())?;
    Ok(Some(data))
}

fn inheritable_fd_path(file: &File) -> Result<PathBuf, String> {
    let fd = file.as_raw_fd();
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err("cannot inspect CGI script descriptor".into());
    }
    Ok(PathBuf::from(format!("/proc/self/fd/{fd}")))
}

fn feed_stdin(
    stdin: std::process::ChildStdin,
    body: &BodySource,
    body_len: u64,
    deadline: Instant,
    request_scope: Option<crate::resource::RequestScope>,
) -> Option<std::thread::JoinHandle<()>> {
    let mut stdin = stdin;
    if body_len == 0 {
        drop(stdin);
        None
    } else {
        let Ok(mut reader) = body.reader() else {
            drop(stdin);
            return None;
        };
        Some(std::thread::spawn(move || {
            let Ok(flags) = rustix::fs::fcntl_getfl(&stdin) else {
                return;
            };
            if rustix::fs::fcntl_setfl(&stdin, flags | rustix::fs::OFlags::NONBLOCK).is_err() {
                return;
            }
            let mut chunk = [0u8; 64 * 1024];
            let mut start = 0usize;
            let mut end = 0usize;
            loop {
                if request_scope
                    .as_ref()
                    .is_some_and(crate::resource::RequestScope::is_cancelled)
                {
                    return;
                }
                if Instant::now() >= deadline {
                    return;
                }
                if start == end {
                    match reader.read(&mut chunk) {
                        Ok(0) => return,
                        Ok(read) => {
                            start = 0;
                            end = read;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => return,
                    }
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                let timeout =
                    rustix::event::Timespec::try_from(remaining.min(Duration::from_millis(100)))
                        .unwrap_or(rustix::event::Timespec {
                            tv_sec: 0,
                            tv_nsec: 100_000_000,
                        });
                let mut poll = rustix::event::PollFd::from_borrowed_fd(
                    stdin.as_fd(),
                    rustix::event::PollFlags::OUT,
                );
                let result =
                    match rustix::event::poll(std::slice::from_mut(&mut poll), Some(&timeout))
                        .map_err(std::io::Error::from)
                    {
                        Ok(result) => result,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                            continue;
                        }
                        Err(_) => return,
                    };
                if result == 0 {
                    continue;
                }
                match stdin.write(&chunk[start..end]) {
                    Ok(0) => return,
                    Ok(written) => start += written,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                        ) => {}
                    Err(_) => return,
                }
            }
        }))
    }
}

fn run_local(
    path: &Path,
    cwd: &Path,
    env: &[(OsString, OsString)],
    body: &BodySource,
    timeout: Duration,
    expected: Option<(u64, u64)>,
    mut response_lease: Option<&mut crate::resource::ResidentLease>,
    request_scope: Option<&crate::resource::RequestScope>,
) -> Result<(Vec<u8>, String), String> {
    let mut verified_script: Option<File> = None;
    let mut retained_fd = None;
    let exec_path: PathBuf = if let Some((dev, ino)) = expected {
        let file = File::open(path)
            .map_err(|e| format!("cannot reopen CGI script {}: {e}", path.display()))?;
        let meta = file
            .metadata()
            .map_err(|e| format!("cannot stat reopened CGI script: {e}"))?;
        if meta.dev() != dev || meta.ino() != ino {
            return Err("CGI script inode changed after authorization".into());
        }
        let fd_path = inheritable_fd_path(&file)?;
        retained_fd = Some(file.as_raw_fd());
        verified_script = Some(file);
        fd_path
    } else {
        path.to_path_buf()
    };
    let mut cmd = Command::new(&exec_path);
    cmd.current_dir(cwd);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    let parent_pid = unsafe { libc::getpid() };
    unsafe {
        cmd.pre_exec(move || child_process_setup(timeout, retained_fd, parent_pid));
    }
    let spawn_result = crate::fault::hit("cgi.spawn")
        .map_err(|e| format!("cannot execute {}: {e}", path.display()))
        .and_then(|()| {
            cmd.spawn()
                .map_err(|e| format!("cannot execute {}: {e}", path.display()))
        });
    let mut child = spawn_result?;
    drop(verified_script);
    let pid = child.id() as i32;
    let deadline = Instant::now() + timeout;

    // Feed stdin.  Empty GET bodies just close the pipe.  Only larger bodies
    // need a writer thread; it is joined before this worker forks again.
    let body_len = body.len();
    let stdin_thread = child
        .stdin
        .take()
        .and_then(|stdin| feed_stdin(stdin, body, body_len, deadline, request_scope.cloned()));
    let stderr_scope = request_scope.cloned();
    let stderr_thread = child.stderr.take().map(|e| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = read_limited_with_deadline(
                e,
                deadline,
                &mut buf,
                MAX_STDERR,
                true,
                None,
                stderr_scope.as_ref(),
            );
            buf
        })
    });

    let mut out = Vec::new();
    let read_result = child
        .stdout
        .take()
        .ok_or_else(|| "CGI stdout unavailable".to_string())
        .and_then(|stdout| {
            read_with_deadline(
                stdout,
                deadline,
                &mut out,
                response_lease.as_deref_mut(),
                request_scope,
            )
        });
    let waited = if read_result.is_ok() {
        wait_with_deadline(&mut child, pid, deadline, request_scope)
    } else {
        kill_group(pid);
        let _ = child.wait();
        Err("CGI timed out or wrote too much output".to_string())
    };
    if let Some(t) = stdin_thread {
        let _ = t.join();
    }
    let stderr = stderr_thread
        .and_then(|h| h.join().ok())
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    match (read_result, waited) {
        (Ok(()), Ok(())) => Ok((out, stderr)),
        (Err(e), _) => Err(e),
        (_, Err(e)) => Err(e),
    }
}

fn kill_group(pid: i32) {
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
        libc::kill(pid, libc::SIGKILL);
    }
}

fn wait_with_deadline(
    child: &mut Child,
    pid: i32,
    deadline: Instant,
    request_scope: Option<&crate::resource::RequestScope>,
) -> Result<(), String> {
    loop {
        if request_scope.is_some_and(crate::resource::RequestScope::is_cancelled) {
            kill_group(pid);
            let _ = child.wait();
            return Err("CGI request scope cancelled".into());
        }
        if Instant::now() >= deadline {
            kill_group(pid);
            let _ = child.wait();
            return Err("CGI timeout".into());
        }
        let exited = match crate::process::child_exited_unreaped(pid) {
            Ok(exited) => exited,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                kill_group(pid);
                let _ = child.wait();
                return Err(format!("cannot observe CGI process: {error}"));
            }
        };
        if exited {
            // Keep the direct child unreaped until after the group signal.
            // That prevents its numeric PID/PGID from being recycled for an
            // unrelated process group between wait and cleanup.
            kill_group(pid);
            let _ = child.wait();
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn poll_result(rc: i32, error: std::io::Error) -> Result<bool, String> {
    if rc < 0 {
        if error.kind() == std::io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error.to_string());
    }
    Ok(rc > 0)
}

fn read_with_deadline(
    reader: impl Read + AsRawFd,
    deadline: Instant,
    out: &mut Vec<u8>,
    resident: Option<&mut crate::resource::ResidentLease>,
    request_scope: Option<&crate::resource::RequestScope>,
) -> Result<(), String> {
    read_limited_with_deadline(
        reader,
        deadline,
        out,
        MAX_OUTPUT,
        false,
        resident,
        request_scope,
    )
}

fn read_limited_with_deadline(
    mut reader: impl Read + AsRawFd,
    deadline: Instant,
    out: &mut Vec<u8>,
    limit: usize,
    truncate_at_limit: bool,
    mut resident: Option<&mut crate::resource::ResidentLease>,
    request_scope: Option<&crate::resource::RequestScope>,
) -> Result<(), String> {
    let fd = reader.as_raw_fd();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        if request_scope.is_some_and(crate::resource::RequestScope::is_cancelled) {
            return Err("CGI request scope cancelled".into());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err("CGI timeout".into());
        }
        let remaining = deadline.saturating_duration_since(now);
        let wait_ms = remaining.as_millis().min(100) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, wait_ms) };
        if !poll_result(rc, std::io::Error::last_os_error())? {
            continue;
        }
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                if out.len().saturating_add(n) > limit {
                    return Err("CGI output too large".into());
                }
                if let Some(lease) = resident.as_mut() {
                    lease
                        .reserve(n as u64)
                        .map_err(|_| "CGI response memory capacity exhausted".to_string())?;
                }
                out.extend_from_slice(&chunk[..n]);
                if truncate_at_limit && out.len() == limit {
                    return Ok(());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
}

pub(crate) fn parse_cgi_response(data: &[u8], version: Version) -> Result<Response, ()> {
    let (head, body) = split_cgi_head(data).ok_or(())?;
    let mut status = 200u16;
    let mut headers = Headers::default();
    let mut location: Option<Vec<u8>> = None;
    let mut connection_tokens: Vec<String> = Vec::new();
    let mut saw_status = false;
    let mut saw_location = false;
    let mut saw_connection = false;
    for line in head.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let colon = line.iter().position(|&b| b == b':').ok_or(())?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(());
        }
        let value = trim_ascii(&line[colon + 1..]);
        if !vapache_verified::proxy_response_header_admit(name, value) {
            return Err(());
        }
        let lname = std::str::from_utf8(name)
            .map_err(|_| ())?
            .to_ascii_lowercase();
        if lname == "status" {
            if saw_status {
                return Err(());
            }
            let s = std::str::from_utf8(value).map_err(|_| ())?;
            let code = s.split_whitespace().next().ok_or(())?;
            status = code.parse().map_err(|_| ())?;
            if !vapache_verified::cgi_response_status_admit(status) {
                return Err(());
            }
            saw_status = true;
            continue;
        }
        if lname == "connection" {
            if saw_connection {
                return Err(());
            }
            saw_connection = true;
            for raw in value.split(|byte| *byte == b',') {
                let token = trim_ascii(raw);
                if token.is_empty() || !valid_token(token) {
                    return Err(());
                }
                let token = std::str::from_utf8(token)
                    .map_err(|_| ())?
                    .to_ascii_lowercase();
                if connection_tokens.iter().any(|existing| existing == &token) {
                    return Err(());
                }
                connection_tokens.push(token);
            }
            continue;
        }
        let framing = lname == "content-length" || lname == "transfer-encoding";
        let hop_by_hop = matches!(
            lname.as_str(),
            "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "upgrade"
        );
        if !vapache_verified::cgi_response_header_admit(framing, hop_by_hop, false) {
            continue;
        }
        if lname == "location" {
            if saw_location {
                return Err(());
            }
            saw_location = true;
            location = Some(value.to_vec());
        }
        headers.push(&lname, value.to_vec());
    }
    let framing_nominated = connection_tokens.iter().any(|token| {
        matches!(
            token.as_str(),
            "status" | "content-length" | "transfer-encoding" | "connection"
        )
    });
    let end_to_end_nominated = connection_tokens.iter().any(|token| {
        !matches!(
            token.as_str(),
            "close" | "keep-alive" | "proxy-connection" | "te" | "trailer" | "upgrade"
        )
    });
    let connection_disposition =
        vapache_verified::backend_connection_disposition(framing_nominated, end_to_end_nominated);
    if connection_disposition == vapache_verified::BackendConnectionDisposition::Reject {
        return Err(());
    }
    for token in &connection_tokens {
        if !vapache_verified::cgi_response_header_admit(false, false, true) {
            headers.remove(token);
        }
    }
    if connection_tokens
        .iter()
        .any(|token| token.eq_ignore_ascii_case("location"))
    {
        location = None;
    }
    if let Some(loc) = location {
        if !saw_status {
            status = 302;
        }
        headers.insert("location", loc);
    }
    if !headers.contains("content-type") && status != 204 && status != 205 && status != 304 {
        headers.insert("content-type", b"text/html".to_vec());
    }
    let body = if status == 204 || status == 205 || status == 304 {
        Vec::new()
    } else {
        body.to_vec()
    };
    let mut r = Response::new(status);
    r.headers = headers
        .iter()
        .map(|(n, v)| {
            (
                std::borrow::Cow::Owned(canonical_header_name(n)),
                v.to_vec(),
            )
        })
        .collect();
    r.body = crate::http::Body::Bytes(body);
    if !vapache_verified::backend_shared_cache_admit(connection_disposition) {
        r.forbid_shared_cache();
    }
    if !crate::http::response_headers_valid(&r) {
        return Err(());
    }
    let _ = version;
    Ok(r)
}

fn canonical_header_name(lname: &str) -> String {
    lname
        .split('-')
        .map(|p| {
            let mut c = p.chars();
            match c.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_cgi_response(data: &[u8]) {
    if let Ok(response) = parse_cgi_response(data, Version::Http11) {
        let _ = crate::http::response_cache_control(&response);
    }
}

/// Return the end of the first CGI header delimiter on the byte stream.
/// CGI permits either CRLF or LF line endings. Selecting by delimiter type
/// before position can skip an earlier LF boundary and promote attacker-
/// controlled body lines into response headers.
pub(crate) fn cgi_head_end(data: &[u8]) -> Option<usize> {
    let crlf = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|start| (start, 4usize));
    let lf = data
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|start| (start, 2usize));
    let (start, width) = match (crlf, lf) {
        (Some(left), Some(right)) => {
            if left.0 <= right.0 {
                left
            } else {
                right
            }
        }
        (Some(delimiter), None) | (None, Some(delimiter)) => delimiter,
        (None, None) => return None,
    };
    (start <= MAX_HEADER).then_some(start + width)
}

fn split_cgi_head(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = cgi_head_end(data)?;
    let width = if end >= 4 && &data[end - 4..end] == b"\r\n\r\n" {
        4
    } else {
        2
    };
    Some((&data[..end - width], &data[end..]))
}

/// Decide whether a filename should be handled by CGI given the scopes and
/// handler map (F65/I66).  Execution requires BOTH the CGI classification
/// and the filesystem grant: a `ScriptAlias` only supplies classification
/// (and an unconditional filesystem grant) — a `SetHandler default-handler`
/// (or any other non-`cgi-script` force, regardless of parse order or
/// inheritance, F64) suppresses execution, and without a forced handler a
/// scope without `Options ExecCGI` never executes either.
pub fn is_cgi(cfg: &Config, scope: &crate::config::Scope, name: &[u8], script_alias: bool) -> bool {
    let _ = cfg;
    let options = scope.effective_options();
    let exec_allowed = script_alias || options.contains(crate::config::Options::EXEC_CGI);
    let (handler_bound, handler_is_cgi) = match crate::config::effective_handler(scope, name) {
        Some(handler) => (true, handler.eq_ignore_ascii_case("cgi-script")),
        None => (false, false),
    };
    // F64/I62: when the scope forces a handler the force always binds — the
    // extension table can neither remove it nor add execution past it.
    let forced = matches!(
        scope.mapping_policy.set_handler,
        Some(crate::config::SetHandler::Name(_))
    );
    debug_assert!(vapache_verified::set_handler_precedence_admit(
        forced,
        handler_bound
    ));
    vapache_verified::cgi_exec_admit(handler_bound, handler_is_cgi, script_alias, exec_allowed)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Body, Headers};
    use std::collections::HashMap;
    use std::fs;
    use std::io::Cursor;

    fn tempdir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("vapache-cgi-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn config(root: &Path) -> Config {
        let path = root.join("httpd.conf");
        fs::write(
            &path,
            format!("{}Listen 127.0.0.1:0\n", crate::config::TEST_CAPABILITIES),
        )
        .unwrap();
        Config::load(&path, root, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    fn request(path: &str, body: Vec<u8>) -> Request {
        Request {
            method: "GET".into(),
            target: path.as_bytes().to_vec(),
            raw_path: path.as_bytes().to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Headers::default(),
            body,
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }

    #[test]
    fn execute_falls_back_without_pool_and_parses_cgi_output() {
        let dir = tempdir("fallback");
        let cfg = config(&dir);
        script(
            &dir,
            "hello.sh",
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nhello\\n'\n",
        );
        let req = request("/hello.sh", Vec::new());
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new("hello.sh"),
            script_name: "/hello.sh",
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
        let resp = execute(&ctx);
        assert_eq!(resp.status, 200);
        match resp.body {
            Body::Bytes(b) => assert_eq!(b, b"hello\n"),
            _ => panic!("expected an in-memory CGI body"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn execute_with_opened_script_fd() {
        let dir = tempdir("opened");
        let cfg = config(&dir);
        let path = script(
            &dir,
            "opened.sh",
            "#!/bin/sh\nprintf 'Content-Type: text/plain\r\n\r\nopened\n'\n",
        );
        let file = File::open(&path).unwrap();
        let req = request("/opened.sh", Vec::new());
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new("opened.sh"),
            script_name: "/opened.sh",
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
            script_file: Some(&file),
        };
        let resp = execute(&ctx);
        assert_eq!(resp.status, 200);
        match resp.body {
            Body::Bytes(b) => assert_eq!(b, b"opened\n"),
            _ => panic!("expected an in-memory CGI body"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn configured_environment_cannot_override_calculated_cgi_variables() {
        let dir = tempdir("env-reserved");
        let cfg = config(&dir);
        let mut req = request("/cgi-bin/env.sh?x=1", Vec::new());
        req.query = b"x=\xff".to_vec();
        let extra = vec![
            ("REQUEST_METHOD".into(), b"POST".to_vec()),
            ("HTTP_HOST".into(), b"evil.test".to_vec()),
            ("SCRIPT_FILENAME".into(), b"/etc/passwd".to_vec()),
            ("CUSTOM_VALUE".into(), b"ok".to_vec()),
        ];
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new("cgi-bin/env.sh"),
            script_name: "/cgi-bin/env.sh",
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
            env: &extra,
            remote_user: None,
            auth_type: None,
            script_file: None,
        };
        let env = build_env(&ctx);
        let get = |name: &str| {
            env.iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.to_string_lossy().into_owned())
                .unwrap()
        };
        assert_eq!(get("REQUEST_METHOD"), "GET");
        assert_eq!(get("REQUEST_URI"), "/cgi-bin/env.sh");
        assert_eq!(
            get("SCRIPT_FILENAME"),
            dir.join("cgi-bin/env.sh").to_string_lossy()
        );
        assert_eq!(get("CUSTOM_VALUE"), "ok");
        assert_eq!(
            env.iter()
                .find(|(key, _)| key == "QUERY_STRING")
                .map(|(_, value)| value.as_os_str().as_bytes()),
            Some(b"x=\xff".as_slice())
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn virtual_host_server_admin_is_exported_without_cross_tenant_fallback() {
        let dir = tempdir("vhost-server-admin");
        let path = dir.join("httpd.conf");
        fs::write(
            &path,
            format!(
                "{}Listen 127.0.0.1:19083\n\
                 ServerAdmin global@example.test\n\
                 <VirtualHost *:19083>\n\
                 ServerName tenant.test\n\
                 ServerAdmin tenant@example.test\n\
                 </VirtualHost>\n",
                crate::config::TEST_CAPABILITIES
            ),
        )
        .unwrap();
        let cfg = Config::load(&path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let req = request("/cgi-bin/env.sh", Vec::new());
        let mut ctx = test_ctx(&cfg, &req, &dir, Path::new("cgi-bin/env.sh"), None);
        ctx.vhost = cfg.vhosts.first();
        let env = build_env(&ctx);
        assert_eq!(
            env.iter()
                .find(|(name, _)| name == "SERVER_ADMIN")
                .map(|(_, value)| value.to_string_lossy().into_owned())
                .as_deref(),
            Some("tenant@example.test")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn authenticated_identity_is_exported_as_remote_user_and_auth_type() {
        let dir = tempdir("remote-user");
        let cfg = config(&dir);
        let req = request("/cgi-bin/who.sh", Vec::new());
        let extra = vec![
            ("REMOTE_USER".into(), b"attacker".to_vec()),
            ("AUTH_TYPE".into(), b"None".to_vec()),
        ];
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new("cgi-bin/who.sh"),
            script_name: "/cgi-bin/who.sh",
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
            env: &extra,
            remote_user: Some("alice"),
            auth_type: Some("Basic"),
            script_file: None,
        };
        let env = build_env(&ctx);
        let get = |name: &str| {
            env.iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.to_string_lossy().into_owned())
        };
        assert_eq!(get("REMOTE_USER").as_deref(), Some("alice"));
        assert_eq!(get("AUTH_TYPE").as_deref(), Some("Basic"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_cgi_headers_are_rejected() {
        let mut data = b"X-Test: ".to_vec();
        data.extend(std::iter::repeat(b'a').take(MAX_HEADER + 1));
        data.extend_from_slice(b"\r\n\r\n");
        assert!(parse_cgi_response(&data, Version::Http11).is_err());
    }

    #[test]
    fn malformed_cgi_output_becomes_500() {
        let dir = tempdir("malformed");
        let cfg = config(&dir);
        script(
            &dir,
            "bad.sh",
            "#!/bin/sh\nprintf 'not a cgi response\\n'\n",
        );
        let req = request("/bad.sh", Vec::new());
        let ctx = CgiContext {
            cfg: &cfg,
            vhost: None,
            req: &req,
            root: &dir,
            script_rel: Path::new("bad.sh"),
            script_name: "/bad.sh",
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
        assert_eq!(execute(&ctx).status, 500);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_timeout_kills_the_process_group() {
        let dir = tempdir("timeout");
        let p = script(&dir, "slow.sh", "#!/bin/sh\nsleep 5\n");
        let start = Instant::now();
        let result = run_local(
            &p,
            &dir,
            &[],
            &BodySource::Bytes(Vec::new()),
            Duration::from_millis(50),
            None,
            None,
            None,
        );
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cgi_exec_closes_an_unrelated_inheritable_descriptor() {
        let dir = tempdir("descriptor-isolation");
        let path = script(
            &dir,
            "fds.sh",
            "#!/bin/sh\nif [ -e \"/proc/self/fd/$LEAK_FD\" ]; then value=leaked; else value=isolated; fi\nprintf 'Content-Type: text/plain\\r\\n\\r\\n%s\\n' \"$value\"\n",
        );
        let sentinel = File::open("/dev/null").unwrap();
        let sentinel_fd = sentinel.as_raw_fd();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let ok = crate::process::set_cloexec(sentinel_fd, false).is_ok()
                && run_local(
                    &path,
                    &dir,
                    &[(
                        OsString::from("LEAK_FD"),
                        OsString::from(sentinel_fd.to_string()),
                    )],
                    &BodySource::Bytes(Vec::new()),
                    Duration::from_secs(1),
                    None,
                    None,
                    None,
                )
                .is_ok_and(|(output, _)| output.ends_with(b"isolated\n"));
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn cgi_execution_and_worker_exchange_observe_request_cancellation() {
        let dir = tempdir("request-cancel");
        let path = script(&dir, "slow.sh", "#!/bin/sh\nsleep 5\n");
        let budget = std::sync::Arc::new(crate::resource::ResourceBudget::default());
        let scope = crate::resource::RequestScope::new(
            budget.context(std::net::IpAddr::from([127, 0, 0, 1])),
        );
        let cancel = scope.clone();
        let cancellation = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            cancel.cancel();
        });
        let started = Instant::now();
        let error = run_local(
            &path,
            &dir,
            &[],
            &BodySource::Bytes(Vec::new()),
            Duration::from_secs(5),
            None,
            None,
            Some(&scope),
        )
        .unwrap_err();
        cancellation.join().unwrap();
        assert!(error.contains("cancelled"));
        assert!(started.elapsed() < Duration::from_secs(1));

        let scope = crate::resource::RequestScope::new(
            budget.context(std::net::IpAddr::from([127, 0, 0, 1])),
        );
        let cancel = scope.clone();
        let cancellation = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            cancel.cancel();
        });
        let (mut parent, _worker) = UnixStream::pair().unwrap();
        let started = Instant::now();
        let error = exchange(
            &mut parent,
            Path::new("/bin/true"),
            Path::new("/"),
            &[],
            &BodySource::Bytes(Vec::new()),
            Duration::from_secs(5),
            None,
            None,
            None,
            Some(&scope),
        )
        .unwrap_err();
        cancellation.join().unwrap();
        assert!(error.contains("cancelled"));
        assert!(started.elapsed() < Duration::from_secs(1));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn injected_cgi_spawn_failure_is_propagated() {
        let _fault_guard = crate::fault::test_guard();
        let dir = tempdir("spawn-failpoint");
        let path = script(
            &dir,
            "unreached.sh",
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\n'\n",
        );
        crate::fault::configure("cgi.spawn", 0, std::io::ErrorKind::PermissionDenied);
        let error = run_local(
            &path,
            &dir,
            &[],
            &BodySource::Bytes(Vec::new()),
            Duration::from_secs(1),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(error.contains("injected failure at cgi.spawn"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn protocol_lengths_are_bounded() {
        let mut oversize = Cursor::new(vec![5u8, 0, 0, 0, 0]);
        assert!(read_bytes(&mut oversize, 4, false).is_err());

        let mut eof = Cursor::new(Vec::<u8>::new());
        assert_eq!(read_bytes(&mut eof, 4, true).unwrap(), None);
        assert!(read_bytes(&mut eof, 4, false).is_err());
    }

    #[test]
    fn exchange_propagates_worker_success_and_failure() {
        let (mut parent, child) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            let mut child = child;
            // Let the client finish writing the request before this minimal
            // fake worker replies and closes.
            std::thread::sleep(Duration::from_millis(50));
            write_u8(&mut child, 1).unwrap();
            write_bytes(&mut child, b"out").unwrap();
            write_bytes(&mut child, b"").unwrap();
            child.flush().unwrap();
        });
        let (out, err) = exchange(
            &mut parent,
            Path::new("/bin/true"),
            Path::new("/"),
            &[],
            &BodySource::Bytes(Vec::new()),
            Duration::from_secs(1),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(out, b"out");
        assert_eq!(err, "");
        fake.join().unwrap();

        let (mut parent, child) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            let mut child = child;
            std::thread::sleep(Duration::from_millis(50));
            write_u8(&mut child, 0).unwrap();
            write_bytes(&mut child, b"").unwrap();
            write_bytes(&mut child, b"boom").unwrap();
            child.flush().unwrap();
        });
        let err = exchange(
            &mut parent,
            Path::new("/bin/true"),
            Path::new("/"),
            &[],
            &BodySource::Bytes(Vec::new()),
            Duration::from_secs(1),
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err, "boom");
        fake.join().unwrap();
    }

    #[test]
    fn worker_request_handles_eof_and_bad_counts() {
        let (mut parent, child) = UnixStream::pair().unwrap();
        drop(child);
        assert!(matches!(worker_request(&mut parent), Ok(false)));

        let (mut parent, mut child) = UnixStream::pair().unwrap();
        write_bytes(&mut child, b"/bin/true").unwrap();
        write_u8(&mut child, 0).unwrap();
        write_bytes(&mut child, b"/").unwrap();
        write_u32(&mut child, MAX_WORKER_ENV + 1).unwrap();
        child.flush().unwrap();
        assert!(worker_request(&mut parent).is_err());
        drop(child);
    }

    #[test]
    fn worker_ids_reject_unknown_names() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        assert!(worker_ids("no-such-vapache-user-xyz", "www-data").is_err());
        assert!(worker_ids("www-data", "no-such-vapache-group-xyz").is_err());
        assert!(worker_ids("www-data", "www-data").is_ok());
        assert!(worker_ids("33", "33").is_ok());
    }

    struct ErrorWriter(&'static str);

    impl Write for ErrorWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, self.0))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct BadFd;

    impl Read for BadFd {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl AsRawFd for BadFd {
        fn as_raw_fd(&self) -> i32 {
            999_999
        }
    }

    struct SeqRead {
        file: File,
        stage: usize,
    }

    impl Read for SeqRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.stage += 1;
            match self.stage {
                1 => Err(std::io::Error::from(std::io::ErrorKind::Interrupted)),
                2 => Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
                _ => {
                    let _ = buf;
                    Err(std::io::Error::from(std::io::ErrorKind::Other))
                }
            }
        }
    }

    impl AsRawFd for SeqRead {
        fn as_raw_fd(&self) -> i32 {
            self.file.as_raw_fd()
        }
    }

    struct FloodRead {
        file: File,
    }

    impl Read for FloodRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let len = buf.len().min(64 * 1024);
            buf[..len].fill(b'x');
            Ok(len)
        }
    }

    impl AsRawFd for FloodRead {
        fn as_raw_fd(&self) -> i32 {
            self.file.as_raw_fd()
        }
    }

    fn closed_file(path: &Path) -> File {
        // Keep the path argument so tests read as "the authorized file is
        // closed", but return a deterministic invalid descriptor.  Closing a
        // real high descriptor and handing its number to another thread lets a
        // parallel test reuse that fd before fcntl() runs, which made the
        // bad-descriptor assertions flaky.
        let _ = File::open(path).unwrap();
        unsafe { File::from_raw_fd(i32::MAX) }
    }

    fn response_header<'a>(resp: &'a Response, name: &str) -> Option<&'a [u8]> {
        resp.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    fn test_ctx<'a>(
        cfg: &'a Config,
        req: &'a Request,
        root: &'a Path,
        script_rel: &'a Path,
        script_file: Option<&'a File>,
    ) -> CgiContext<'a> {
        CgiContext {
            cfg,
            vhost: None,
            req,
            root,
            script_rel,
            script_name: "/test",
            path_info: "",
            docroot: root,
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
            script_file,
        }
    }

    #[test]
    fn find_script_body_sources_and_auth_header_filtering() {
        let dir = tempdir("sources");
        let cfg = config(&dir);
        let path = script(
            &dir,
            "hello.sh",
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nhello\\n'\n",
        );
        let found = find_script(&dir, Path::new("hello.sh"), false).unwrap();
        assert_eq!(found.rel_script, Path::new("hello.sh"));
        assert!(found.path_info.is_empty());

        let bytes = BodySource::Bytes(b"abc".to_vec());
        assert_eq!(bytes.len(), 3);
        let mut reader = bytes.reader().unwrap();
        let mut got = String::new();
        reader.read_to_string(&mut got).unwrap();
        assert_eq!(got, "abc");

        let file = File::open(&path).unwrap();
        let file_body = BodySource::File(file);
        assert_eq!(file_body.len(), path.metadata().unwrap().len());
        assert!(file_body.reader().is_ok());

        let mut req = request("/test", b"body".to_vec());
        req.headers.push("Authorization", "Basic c2VjcmV0");
        req.headers.push("Content-Type", "text/plain");
        req.headers.push("Content-Length", "4");
        let ctx = test_ctx(&cfg, &req, &dir, Path::new("hello.sh"), None);
        let env = build_env(&ctx);
        assert!(!env.iter().any(|(name, _)| name == "HTTP_AUTHORIZATION"));
        assert!(
            env.iter()
                .any(|(name, value)| name == "CONTENT_TYPE"
                    && value.to_string_lossy() == "text/plain")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn script_prefix_search_is_component_and_request_work_bounded() {
        let dir = tempdir("prefix-budget");
        let mut deep = PathBuf::new();
        for _ in 0..=crate::util::MAX_POLICY_PATH_COMPONENTS {
            deep.push("x");
        }
        assert!(find_script_checked(&dir, &deep, false, false).is_none());

        let req = request("/missing/path", Vec::new());
        req.charge_policy_work(crate::resource::MAX_POLICY_WORK_UNITS)
            .unwrap();
        assert!(find_script_checked_for_request(
            &dir,
            Path::new("missing/path"),
            false,
            false,
            &req,
        )
        .is_none());
        assert!(req.policy_budget_failed());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn execute_local_stderr_missing_script_and_bad_script_fd() {
        let dir = tempdir("execute-edges");
        let cfg = config(&dir);
        script(
            &dir,
            "stderr.sh",
            "#!/bin/sh\nprintf 'warn\\n' >&2\nprintf 'Content-Type: text/plain\\r\\n\\r\\nok\\n'\n",
        );
        let req = request("/stderr.sh", Vec::new());
        let ctx = test_ctx(&cfg, &req, &dir, Path::new("stderr.sh"), None);
        assert_eq!(execute(&ctx).status, 200);

        let missing = test_ctx(&cfg, &req, &dir, Path::new("missing.sh"), None);
        assert_eq!(execute(&missing).status, 500);

        let bad_file = std::mem::ManuallyDrop::new(closed_file(&dir.join("stderr.sh")));
        let bad = test_ctx(&cfg, &req, &dir, Path::new("stderr.sh"), Some(&*bad_file));
        assert_eq!(execute(&bad).status, 500);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_cgi_response_edge_cases() {
        for data in [
            &b"Bad_Name: x\r\n\r\n"[..],
            b"X: a\rb\r\n\r\n",
            b"X: a\x01b\r\n\r\n",
            b"Status: 99 Nope\r\n\r\n",
            b"Status: 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
            b"Status: nope\r\n\r\n",
            b"Status: 200 OK\r\nStatus: 201 Created\r\n\r\n",
            b"Location: /one\r\nLocation: /two\r\n\r\n",
            b"Connection: X-Hop,,close\r\nX-Hop: value\r\n\r\n",
            b"Connection: Status\r\nStatus: 200 OK\r\n\r\n",
            b"MissingColon\r\n\r\n",
        ] {
            assert!(parse_cgi_response(data, Version::Http11).is_err());
        }

        let framed = parse_cgi_response(
            b"Content-Length: 99\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nKeep-Alive: timeout=5\r\nContent-Type: text/plain\r\n\r\nbody",
            Version::Http11,
        )
        .unwrap();
        assert_eq!(framed.status, 200);
        assert!(response_header(&framed, "content-length").is_none());
        assert!(response_header(&framed, "connection").is_none());

        let hop = parse_cgi_response(
            b"Connection: X-Secret, Upgrade\r\nX-Secret: leak\r\nUpgrade: websocket\r\nTE: trailers\r\nProxy-Authorization: secret\r\nProxy-Connection: close\r\nContent-Type: text/plain\r\n\r\nbody",
            Version::Http11,
        )
        .unwrap();
        for name in [
            "connection",
            "x-secret",
            "upgrade",
            "te",
            "proxy-authorization",
            "proxy-connection",
        ] {
            assert!(response_header(&hop, name).is_none(), "{name}");
        }
        assert!(!hop.shared_cache_eligible());
        let nominated_location = parse_cgi_response(
            b"Connection: Location\r\nLocation: /hidden\r\n\r\nbody",
            Version::Http11,
        )
        .unwrap();
        assert_eq!(nominated_location.status, 200);
        assert!(response_header(&nominated_location, "location").is_none());
        assert!(!nominated_location.shared_cache_eligible());

        let ordinary_connection = parse_cgi_response(
            b"Connection: close\r\nContent-Type: text/plain\r\n\r\nbody",
            Version::Http11,
        )
        .unwrap();
        assert!(ordinary_connection.shared_cache_eligible());

        let location = parse_cgi_response(b"Location: /next\r\n\r\n", Version::Http11).unwrap();
        assert_eq!(location.status, 302);
        assert_eq!(response_header(&location, "location"), Some(&b"/next"[..]));

        let no_type = parse_cgi_response(b"X-Test: yes\r\n\r\nbody", Version::Http11).unwrap();
        assert_eq!(
            response_header(&no_type, "content-type"),
            Some(&b"text/html"[..])
        );

        let reset = parse_cgi_response(
            b"Status: 205 Reset Content\r\nContent-Type: text/plain\r\n\r\nbody",
            Version::Http11,
        )
        .unwrap();
        assert_eq!(reset.status, 205);
        assert!(matches!(reset.body, Body::Bytes(ref body) if body.is_empty()));

        let empty_part = parse_cgi_response(
            b"X--Y: v\r\nContent-Type: text/plain\r\n\r\n",
            Version::Http11,
        )
        .unwrap();
        assert!(response_header(&empty_part, "x--y").is_some());

        // The first delimiter wins regardless of line-ending style. A later
        // CRLF delimiter in attacker-controlled body bytes must remain body,
        // never become Status/Location response metadata.
        let mixed = parse_cgi_response(
            b"Content-Type: text/plain\n\nStatus: 302 Found\r\nLocation: /injected\r\n\r\nbody",
            Version::Http11,
        )
        .unwrap();
        assert_eq!(mixed.status, 200);
        assert!(response_header(&mixed, "location").is_none());
        match mixed.body {
            Body::Bytes(body) => assert_eq!(
                body,
                b"Status: 302 Found\r\nLocation: /injected\r\n\r\nbody"
            ),
            _ => panic!("expected in-memory CGI body"),
        }

        let mut lf = b"X-Test: ".to_vec();
        lf.extend(std::iter::repeat(b'a').take(MAX_HEADER + 1));
        lf.extend_from_slice(b"\n\n");
        assert!(parse_cgi_response(&lf, Version::Http11).is_err());
    }

    #[test]
    fn worker_ids_for_and_pool_primitives() {
        assert_eq!(
            worker_ids_for(1000, 1001, "ignored", "ignored").unwrap(),
            (1000, 1001)
        );
        assert_eq!(worker_ids_for(0, 0, "123", "456").unwrap(), (123, 456));
        assert!(worker_ids_for(0, 0, "bad\0user", "0").is_err());
        assert!(worker_ids_for(0, 0, "no-such-vapache-user-xyz", "0").is_err());
        assert!(worker_ids_for(0, 0, "root", "root").is_err());
        assert!(worker_ids_for(0, 0, "0", "bad\0group").is_err());
        assert!(worker_ids_for(0, 0, "0", "no-such-vapache-group-xyz").is_err());
        assert!(!init_worker_groups("bad\0user", 0));
        assert!(!init_worker_groups("no-such-vapache-user-xyz", 0));

        let (parent, child) = UnixStream::pair().unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let parent_pid = unsafe { libc::getppid() };
            let ok = prepare_worker_fd(child.as_raw_fd(), 99, parent_pid).is_ok();
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(libc::WEXITSTATUS(status), 0);
        drop(parent);
        drop(child);
        assert!(crate::process::set_cloexec(-1, false).is_err());

        let empty = CgiPool {
            workers: Mutex::new(Vec::new()),
            ready: Condvar::new(),
            closed: AtomicBool::new(true),
        };
        assert!(empty.take().is_none());

        let waiting = CgiPool {
            workers: Mutex::new(Vec::new()),
            ready: Condvar::new(),
            closed: AtomicBool::new(false),
        };
        assert!(waiting.take().is_none());

        let dir = tempdir("empty-pool");
        let cfg = config(&dir);
        let req = request("/missing.cgi", Vec::new());
        let ctx = test_ctx(&cfg, &req, &dir, Path::new("missing.cgi"), None);
        let resource_context = cfg.resource_budget.context("127.0.0.1".parse().unwrap());
        assert_eq!(
            execute_via_pool(
                &waiting,
                &ctx,
                &dir.join("missing.cgi"),
                &dir,
                &[],
                &BodySource::Bytes(Vec::new()),
                None,
                &resource_context,
            )
            .status,
            503
        );
        let _ = fs::remove_dir_all(&dir);

        let closed = CgiPool {
            workers: Mutex::new(Vec::new()),
            ready: Condvar::new(),
            closed: AtomicBool::new(true),
        };
        let (stream, _peer) = UnixStream::pair().unwrap();
        let mut child = Command::new("/bin/true").spawn().unwrap();
        let _ = child.wait();
        closed.put(CgiWorker { stream, child });

        let (stream, _peer) = UnixStream::pair().unwrap();
        let child = Command::new("/bin/true").spawn().unwrap();
        let pool = CgiPool {
            workers: Mutex::new(vec![CgiWorker { stream, child }]),
            ready: Condvar::new(),
            closed: AtomicBool::new(false),
        };
        shutdown_pool_inner(&pool);
        assert!(pool.workers.lock().unwrap().is_empty());
    }

    #[test]
    fn worker_pool_startup_and_execute_helper_paths() {
        let dir = tempdir("pool-startup");
        let cfg = config(&dir);
        let good = script(
            &dir,
            "worker-good.sh",
            "#!/bin/sh\nprintf '\\1' >&3\ncat <&3 >/dev/null\n",
        );
        let pool = start_pool_with_exe(&good, 0, 0, "root", 1).unwrap();
        shutdown_pool_inner(&pool);

        let bad = script(&dir, "worker-bad.sh", "#!/bin/sh\nprintf '\\2' >&3\n");
        assert!(start_pool_with_exe(&bad, 0, 0, "root", 1).is_err());

        // Exercise the worker branch through a local pool and fake responder.
        let path = script(
            &dir,
            "ok.sh",
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nok\\n'\n",
        );
        let req = request("/ok.sh", Vec::new());
        let ctx = test_ctx(&cfg, &req, &dir, Path::new("ok.sh"), None);
        let (parent, mut child) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            write_u8(&mut child, 1).unwrap();
            write_bytes(&mut child, b"Content-Type: text/plain\r\n\r\nok\n").unwrap();
            write_bytes(&mut child, b"warn").unwrap();
            child.flush().unwrap();
            std::thread::sleep(Duration::from_millis(30));
            write_u8(&mut child, 1).unwrap();
            write_bytes(&mut child, b"not a cgi response").unwrap();
            write_bytes(&mut child, b"").unwrap();
            child.flush().unwrap();
        });
        let pool = CgiPool {
            workers: Mutex::new(vec![CgiWorker {
                stream: parent,
                child: Command::new("/bin/true").spawn().unwrap(),
            }]),
            ready: Condvar::new(),
            closed: AtomicBool::new(false),
        };
        let resource_context = cfg.resource_budget.context("127.0.0.1".parse().unwrap());
        let resp = execute_via_pool(
            &pool,
            &ctx,
            &path,
            &dir,
            &[],
            &BodySource::Bytes(Vec::new()),
            None,
            &resource_context,
        );
        assert_eq!(resp.status, 200);
        let resp = execute_via_pool(
            &pool,
            &ctx,
            &path,
            &dir,
            &[],
            &BodySource::Bytes(Vec::new()),
            None,
            &resource_context,
        );
        assert_eq!(resp.status, 500);
        fake.join().unwrap();
        shutdown_pool_inner(&pool);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn global_pool_guard_and_feed_stdin_edges() {
        let dir = tempdir("global-pool");
        let cfg = config(&dir);
        let _ = POOL.set(CgiPool {
            workers: Mutex::new(Vec::new()),
            ready: Condvar::new(),
            closed: AtomicBool::new(true),
        });
        assert!(init_pool(&cfg).is_ok());
        shutdown_pool();

        let bad =
            std::mem::ManuallyDrop::new(BodySource::File(closed_file(&dir.join("httpd.conf"))));
        let (stream, _peer) = UnixStream::pair().unwrap();
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        assert!(feed_stdin(
            stdin,
            &bad,
            64 * 1024,
            Instant::now() + Duration::from_millis(100),
            None,
        )
        .is_none());
        let _ = child.wait();
        drop(stream);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn exchange_short_body_empty_error_and_timeout_writer() {
        let mut broken = ErrorWriter("Broken pipe");
        assert!(send_timeout(&mut broken, Duration::from_secs(1)).is_ok());
        let mut failed = ErrorWriter("disk full");
        assert_eq!(
            send_timeout(&mut failed, Duration::from_secs(1)).unwrap_err(),
            "disk full"
        );

        let (mut parent, child) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            let mut child = child;
            std::thread::sleep(Duration::from_millis(30));
            write_u8(&mut child, 0).unwrap();
            write_bytes(&mut child, b"").unwrap();
            write_bytes(&mut child, b"").unwrap();
            child.flush().unwrap();
        });
        let err = exchange(
            &mut parent,
            Path::new("/bin/true"),
            Path::new("/"),
            &[],
            &BodySource::Bytes(Vec::new()),
            Duration::from_secs(1),
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err, "CGI worker reported failure");
        fake.join().unwrap();

        // A pseudo-file can report a larger stat size than the bytes it
        // returns, exercising the short-body guard.
        let candidates = [
            "/sys/kernel/osrelease",
            "/sys/devices/system/cpu/online",
            "/proc/sys/kernel/hostname",
        ];
        let pseudo = candidates.iter().find_map(|path| {
            let file = File::open(path).ok()?;
            let len = file.metadata().ok()?.len();
            let actual = fs::read(path).ok()?.len() as u64;
            (len > actual).then_some((file, len))
        });
        if let Some((file, _len)) = pseudo {
            let (mut parent, _child) = UnixStream::pair().unwrap();
            let err = exchange(
                &mut parent,
                Path::new("/bin/true"),
                Path::new("/"),
                &[],
                &BodySource::File(file),
                Duration::from_secs(1),
                None,
                None,
                None,
                None,
            )
            .unwrap_err();
            assert_eq!(err, "short CGI body");
        }
    }

    #[test]
    fn worker_request_spools_large_bodies_and_rejects_oversize() {
        let dir = tempdir("worker-spool");
        let cfg = config(&dir);
        let _ = cfg;
        let script_path = script(
            &dir,
            "drain.sh",
            "#!/bin/sh\ncat >/dev/null\nprintf 'Content-Type: text/plain\\r\\n\\r\\nok\\n'\n",
        );
        let (mut parent, mut child) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || worker_request(&mut child));
        let body = vec![b'x'; CGI_BODY_IN_MEMORY as usize + 10];
        write_bytes(&mut parent, script_path.as_os_str().as_bytes()).unwrap();
        write_u8(&mut parent, 0).unwrap();
        write_bytes(&mut parent, dir.as_os_str().as_bytes()).unwrap();
        write_u32(&mut parent, 0).unwrap();
        write_u64(&mut parent, body.len() as u64).unwrap();
        parent.write_all(&body).unwrap();
        write_u64(&mut parent, 1).unwrap();
        parent.flush().unwrap();
        assert_eq!(read_u8(&mut parent).unwrap(), 1);
        assert!(read_bytes(&mut parent, MAX_OUTPUT as u32, false)
            .unwrap()
            .is_some());
        assert!(read_bytes(&mut parent, MAX_STDERR as u32, false)
            .unwrap()
            .is_some());
        assert!(worker.join().unwrap().unwrap());

        let (mut parent, mut child) = UnixStream::pair().unwrap();
        write_bytes(&mut child, b"/bin/true").unwrap();
        write_u8(&mut child, 0).unwrap();
        write_bytes(&mut child, b"/").unwrap();
        write_u32(&mut child, 0).unwrap();
        write_u64(&mut child, MAX_WORKER_BODY + 1).unwrap();
        child.flush().unwrap();
        assert!(worker_request(&mut parent).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_local_inode_large_body_timeout_and_readers() {
        let dir = tempdir("run-local-edges");
        let cfg = config(&dir);
        let _ = cfg;
        let path = script(
            &dir,
            "ok.sh",
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nok\\n'\n",
        );
        let closed = std::mem::ManuallyDrop::new(closed_file(&path));
        assert!(inheritable_fd_path(&closed).is_err());
        assert!(run_local(
            &path,
            &dir,
            &[],
            &BodySource::Bytes(Vec::new()),
            Duration::from_secs(1),
            Some((0, 0)),
            None,
            None,
        )
        .is_err());

        let drain = script(&dir, "drain.sh", "#!/bin/sh\ncat >/dev/null\n");
        assert!(run_local(
            &drain,
            &dir,
            &[],
            &BodySource::Bytes(vec![b'x'; 32 * 1024]),
            Duration::from_secs(1),
            None,
            None,
            None,
        )
        .is_ok());

        let slow = script(
            &dir,
            "slow-output.sh",
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nslow\\n'\nexec 1>&-\nsleep 5\n",
        );
        assert!(run_local(
            &slow,
            &dir,
            &[],
            &BodySource::Bytes(Vec::new()),
            Duration::from_millis(50),
            None,
            None,
            None,
        )
        .is_err());

        // A CGI descendant can create a new session and retain all three pipe
        // descriptors after the authorized script exits. The daemon must still
        // return at its deadline instead of joining a permanently blocked pipe
        // helper. The orphan is deliberately short-lived so the test cleans up
        // without relying on the process-group kill it is testing around.
        let escaped = script(
            &dir,
            "escaped-pipes.sh",
            "#!/bin/sh\nsetsid sh -c 'sleep 1' &\nprintf 'Content-Type: text/plain\\r\\n\\r\\nescaped\\n'\n",
        );
        let escaped_started = Instant::now();
        assert!(run_local(
            &escaped,
            &dir,
            &[],
            &BodySource::Bytes(vec![b'x'; 32 * 1024]),
            Duration::from_millis(75),
            None,
            None,
            None,
        )
        .is_err());
        assert!(escaped_started.elapsed() < Duration::from_millis(750));

        let mut out = Vec::new();
        assert!(read_with_deadline(
            BadFd,
            Instant::now() + Duration::from_millis(100),
            &mut out,
            None,
            None,
        )
        .is_ok());
        assert!(!poll_result(-1, std::io::Error::from(std::io::ErrorKind::Interrupted)).unwrap());
        assert!(poll_result(-1, std::io::Error::from(std::io::ErrorKind::Other)).is_err());
        assert!(!poll_result(0, std::io::Error::from(std::io::ErrorKind::Other)).unwrap());
        assert!(poll_result(1, std::io::Error::from(std::io::ErrorKind::Other)).unwrap());
        let null = File::open("/dev/null").unwrap();
        let mut seq = SeqRead {
            file: File::open("/dev/null").unwrap(),
            stage: 0,
        };
        assert!(read_with_deadline(
            seq,
            Instant::now() + Duration::from_millis(100),
            &mut out,
            None,
            None,
        )
        .is_err());
        drop(null);
        let mut flood = FloodRead {
            file: File::open("/dev/null").unwrap(),
        };
        assert_eq!(
            read_with_deadline(
                flood,
                Instant::now() + Duration::from_secs(10),
                &mut out,
                None,
                None,
            )
            .unwrap_err(),
            "CGI output too large"
        );

        assert!(split_cgi_head(b"X-Test: y\n\nbody").is_some());
        assert_eq!(
            cgi_head_end(b"X: y\n\nbody\r\n\r\nmore"),
            Some(b"X: y\n\n".len())
        );
        assert_eq!(
            cgi_head_end(b"X: y\r\n\r\nbody\n\nmore"),
            Some(b"X: y\r\n\r\n".len())
        );
        let mut lf = b"X-Test: ".to_vec();
        lf.extend(std::iter::repeat(b'a').take(MAX_HEADER + 1));
        lf.extend_from_slice(b"\n\n");
        assert!(split_cgi_head(&lf).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn child_process_and_worker_main_paths() {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let setup =
                child_process_setup(Duration::from_secs(1), None, unsafe { libc::getppid() })
                    .is_ok();
            let euid = unsafe { libc::geteuid() };
            let egid = unsafe { libc::getegid() };
            let (uid, gid, user) = if euid == 0 {
                (65_534, 65_534, "nobody")
            } else {
                (euid, egid, "ignored")
            };
            let dropped = drop_worker_privileges(uid, gid, user);
            let rejected = drop_worker_privileges(u32::MAX, u32::MAX, "no-such-user");
            std::process::exit(if setup && dropped && !rejected { 0 } else { 1 });
        }
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);

        // Exercise the root-mode privilege-drop branch in disposable
        // children.  The first keeps the child's real ids; the second uses an
        // impossible gid so the syscall failure is observed without changing
        // the test runner's credentials.
        if unsafe { libc::geteuid() } == 0 {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                std::process::exit(
                    if drop_worker_privileges_for(0, 0, 65_534, 65_534, "nobody") {
                        0
                    } else {
                        1
                    },
                );
            }
            let mut status = 0;
            unsafe {
                libc::waitpid(pid, &mut status, 0);
            }
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }

        assert_eq!(
            drop_worker_privileges_for(1000, 1001, 1000, 1001, "ignored"),
            true
        );
        assert_eq!(
            drop_worker_privileges_for(1000, 1001, 1000, 1002, "ignored"),
            false
        );
        assert!(stream_from_fd(-1).is_none());
        assert!(stream_from_fd(999_999).is_none());

        // Normal worker loop: readiness, then EOF ends it cleanly.
        let (parent, child) = UnixStream::pair().unwrap();
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        let (worker_uid, worker_gid, worker_user) = if euid == 0 {
            (65_534, 65_534, "nobody")
        } else {
            (euid, egid, "ignored")
        };
        let owner = unsafe { libc::getpid() };
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            drop(parent);
            worker_main(
                child.as_raw_fd(),
                worker_uid,
                worker_gid,
                worker_user,
                owner,
            );
            std::process::exit(0);
        }
        drop(child);
        let mut ready = [0u8; 1];
        let mut parent = parent;
        parent.read_exact(&mut ready).unwrap();
        assert_eq!(ready, [1]);
        drop(parent);
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
        assert_eq!(libc::WEXITSTATUS(status), 0);

        // Write failure when the peer disappears before readiness.
        let (parent, child) = UnixStream::pair().unwrap();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            drop(parent);
            worker_main(
                child.as_raw_fd(),
                worker_uid,
                worker_gid,
                worker_user,
                owner,
            );
            std::process::exit(0);
        }
        drop(parent);
        drop(child);
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
        assert_eq!(libc::WEXITSTATUS(status), 0);

        // An invalid control fd returns cleanly after privilege setup.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            worker_main(-1, worker_uid, worker_gid, worker_user, owner);
            std::process::exit(0);
        }
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
        assert_eq!(libc::WEXITSTATUS(status), 0);

        // Privilege failure exits the worker process with status 1.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            worker_main(-1, u32::MAX, u32::MAX, "no-such-user", owner);
            std::process::exit(0);
        }
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
        assert_eq!(libc::WEXITSTATUS(status), 1);
    }
}

#[cfg(test)]
mod pass11_kernel_tests {
    use super::*;
    use crate::config::{Options, Scope, SetHandler};

    fn tempdir(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("vapache-cgi-matrix-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn config(root: &Path) -> Config {
        let path = root.join("httpd.conf");
        std::fs::write(
            &path,
            format!("{}Listen 127.0.0.1:0\n", crate::config::TEST_CAPABILITIES),
        )
        .unwrap();
        Config::load(
            &path,
            root,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            false,
        )
        .unwrap()
    }

    fn cgi_scope(options: Options, text: &str) -> Scope {
        let cfg_text = format!(
            "{}Listen 127.0.0.1:0\n{text}",
            crate::config::TEST_CAPABILITIES
        );
        let dir = std::env::temp_dir().join(format!("vapache-cgi-matrix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("httpd.conf");
        std::fs::write(&path, cfg_text).unwrap();
        let cfg = Config::load(
            &path,
            &dir,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            false,
        )
        .unwrap();
        // Layer the parsed scope onto a default one the same way dispatch
        // does, so `SetHandler`/`AddHandler` land in the merged mapping.
        // The ExecCGI bits go in AFTER the merge: `merge_child` lets the
        // child's options policy win, which would otherwise drop them.
        let mut merged = cfg.effective_scope(None, Path::new("/srv/www/x.cgi"), "/x.cgi");
        merged.options.push_add(options.0);
        merged
    }

    #[test]
    fn cgi_classification_matrix() {
        let dir = tempdir("matrix");
        let cfg = config(&dir);
        // Baseline: Options ExecCGI + AddHandler classifies and executes.
        let s = cgi_scope(
            Options(Options::EXEC_CGI),
            "<Directory /srv>\nAddHandler cgi-script .cgi\n</Directory>\n",
        );
        assert!(is_cgi(&cfg, &s, b"x.cgi", false));
        assert!(!is_cgi(&cfg, &s, b"x.txt", false));
        // No ExecCGI: never, even with the handler present.
        let s = cgi_scope(
            Options::empty(),
            "<Directory /srv>\nAddHandler cgi-script .cgi\n</Directory>\n",
        );
        assert!(!is_cgi(&cfg, &s, b"x.cgi", false));
        // F65: ScriptAlias executes without Options ExecCGI...
        let s = cgi_scope(Options::empty(), "<Directory /srv>\n</Directory>\n");
        assert!(is_cgi(&cfg, &s, b"x.cgi", true));
        // ...but a SetHandler force suppresses it regardless: default-handler
        // serves the source of a script inside a ScriptAlias directory.
        let s = cgi_scope(
            Options::empty(),
            "<Directory /srv>\nSetHandler default-handler\n</Directory>\n",
        );
        assert!(!is_cgi(&cfg, &s, b"x.cgi", true));
        // A non-CGI force in a plain ExecCGI directory also suppresses.
        let s = cgi_scope(
            Options(Options::EXEC_CGI),
            "<Directory /srv>\nAddHandler cgi-script .cgi\nSetHandler default-handler\n</Directory>\n",
        );
        assert!(!is_cgi(&cfg, &s, b"x.cgi", false));
        // SetHandler None unforces: the extension table applies again (the
        // ExecCGI option still has to be present for execution).
        let s = cgi_scope(
            Options(Options::EXEC_CGI),
            "<Directory /srv>\nSetHandler None\nAddHandler cgi-script .cgi\n</Directory>\n",
        );
        assert!(is_cgi(&cfg, &s, b"x.cgi", false));
        // ExecCGI alone (no handler, no ScriptAlias) still never executes:
        // classification needs a handler or a ScriptAlias.
        let s = cgi_scope(
            Options(Options::EXEC_CGI),
            "<Directory /srv>\n</Directory>\n",
        );
        assert!(!is_cgi(&cfg, &s, b"x.cgi", false));
        // ScriptAlias + an AddHandler'ed non-cgi extension does not execute.
        let s = cgi_scope(
            Options::empty(),
            "<Directory /srv>\nAddHandler cgi-script .cgi\n</Directory>\n",
        );
        // ScriptAlias classifies every file in the directory as a script,
        // handler or not (Apache semantics): even an unknown extension runs.
        assert!(is_cgi(&cfg, &s, b"x.txt", true));
        // The classification still needs SOME binding: ScriptAlias absent,
        // ExecCGI present, no handler → static.
        assert!(!is_cgi(&cfg, &s, b"x.txt", false));
        let _ = SetHandler::parse("None");
    }
}
