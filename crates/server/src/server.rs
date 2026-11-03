//! Listener management and request dispatch.

use crate::access::{self, Access};
use crate::cgi::{self, CgiContext};
use crate::config::{
    Capability, Config, EncodedSlashes, Options, Scope, VHost, MAX_IMPLEMENTED_REQUEST_WORKERS,
};
use crate::fastcgi;
use crate::files::{
    directory_index_name, error_response, mime_type, resolve_target_checked, serve_directory,
    serve_file, simple_html, Target,
};
use crate::http::{
    preflight_request_head, prepare_streaming_request_body, pump_streaming_request_body,
    read_request_body_async, read_request_head_with_reservation, read_request_with_reservation,
    write_response, write_response_async, write_response_async_plain, Body, Limits, ParseError,
    ParsedRequestHead, ReadError, Request, Response, ResponseOptions, ResponseWrite, Version,
};
use crate::log::{AccessEntry, Logger};
use crate::proxy;
use crate::request_plan::{CanonicalTarget, RequestPlan};
use crate::util::is_canonical_path;
use crate::verified::{normalize_uri_path, percent_decode_path};
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::Mutex;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Bound {
    pub listener: TcpListener,
    pub port: u16,
    pub addr: String,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pending_tls: Option<crate::tls::PreparedServerConfig>,
}

fn listener_local_ip(l: &crate::config::ListenSpec) -> Option<IpAddr> {
    let ip = l.addr.parse::<IpAddr>().ok()?;
    if ip.is_unspecified() {
        None
    } else {
        Some(access::canonical_ip(ip))
    }
}

fn first_resolved_addr(mut addrs: impl Iterator<Item = SocketAddr>) -> io::Result<SocketAddr> {
    addrs
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no address"))
}

/// Bind all configured listeners.  Called while still privileged so ports
/// below 1024 work, before dropping to the configured user.
pub fn bind(cfg: &Config) -> io::Result<Vec<Bound>> {
    crate::files::require_secure_path_resolution()?;
    crate::cache::prepare(cfg);
    crate::ocsp::prepare_cache_dir(&cfg.server_root.join(".vapache-ocsp-cache"))?;
    let mut out = Vec::new();
    for l in &cfg.listeners {
        let addr_str = if l.addr == "*" { "0.0.0.0" } else { &l.addr };
        let sock_addr = if let Ok(ip) = addr_str.parse::<IpAddr>() {
            SocketAddr::new(ip, l.port)
        } else {
            use std::net::ToSocketAddrs;
            let addrs = (addr_str, l.port).to_socket_addrs()?;
            first_resolved_addr(addrs)?
        };
        let pending_tls = crate::tls::prepare_server_config(cfg, l.port, listener_local_ip(l))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let tls = pending_tls.config();
        let listener = bind_reuse(sock_addr, cfg.listen_backlog)?;
        out.push(Bound {
            listener,
            port: l.port,
            addr: l.addr.clone(),
            tls,
            pending_tls: Some(pending_tls),
        });
    }
    Ok(out)
}

/// Start every background subsystem only after daemonization has completed.
/// Forking a Rust process after OCSP/health-check threads exist can strand
/// locked mutexes in the child and always discards those worker threads.
pub fn activate_background(cfg: &Config, bound: &mut [Bound]) -> io::Result<()> {
    if cfg.listeners.len() != bound.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "listener set changed before background activation",
        ));
    }
    // Validate the complete set before activating even the first candidate.
    for (listener, active) in cfg.listeners.iter().zip(bound.iter()) {
        if listener.port != active.port || listener.addr != active.addr {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "listener identity changed before background activation",
            ));
        }
        if active.pending_tls.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS generation was already activated",
            ));
        }
    }
    for active in bound.iter_mut() {
        if let Some(mut pending) = active.pending_tls.take() {
            pending.activate();
        }
    }
    crate::cache::prepare(cfg);
    crate::proxy::start_health_checks(cfg);
    Ok(())
}

/// Rebuild per-generation listener handles against an existing bound set.
/// The original listeners stay open across reloads, which keeps privileged
/// ports usable after the daemon has dropped root.
pub fn rebind(cfg: &Config, previous: &[Bound]) -> io::Result<Vec<Bound>> {
    if cfg.listeners.len() != previous.len() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "changing Listen directives requires a full restart",
        ));
    }
    let mut out = Vec::with_capacity(previous.len());
    for (l, old) in cfg.listeners.iter().zip(previous) {
        if l.port != old.port || l.addr != old.addr {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "changing Listen directives requires a full restart",
            ));
        }
        let listener = old.listener.try_clone()?;
        let pending_tls = crate::tls::prepare_server_config(cfg, l.port, listener_local_ip(l))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let tls = pending_tls.config();
        out.push(Bound {
            listener,
            port: l.port,
            addr: l.addr.clone(),
            tls,
            pending_tls: Some(pending_tls),
        });
    }
    // The OCSP cache is a privileged startup resource prepared by `bind`.
    // Reload runs after privilege drop and must not try to recreate a
    // root-owned cache directory; cache misses and refresh persistence already
    // fail softly while every response is validated before use.
    Ok(out)
}

fn create_tcp_socket(domain: libc::c_int) -> io::Result<libc::c_int> {
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn bind_fd(
    fd: libc::c_int,
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<()> {
    let rc = unsafe { libc::bind(fd, storage as *const _ as *const libc::sockaddr, len) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn listen_fd(fd: libc::c_int, backlog: i32) -> io::Result<()> {
    if unsafe { libc::listen(fd, backlog.max(1)) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn finish_listener(fd: libc::c_int, backlog: i32) -> io::Result<TcpListener> {
    if let Err(e) = listen_fd(fd, backlog) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    use std::os::unix::io::FromRawFd;
    Ok(unsafe { TcpListener::from_raw_fd(fd) })
}

fn bind_reuse(addr: SocketAddr, backlog: i32) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = create_tcp_socket(domain)?;
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        );
    }
    let storage = sockaddr_storage(addr);
    if let Err(e) = bind_fd(fd, &storage.0, storage.1) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    finish_listener(fd, backlog)
}

fn sockaddr_storage(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
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
        SocketAddr::V6(v6) => {
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

static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
static ADMISSION_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
const MAX_CONNECTIONS_PER_CLIENT: usize = 32;
const MAX_PENDING_CONNECTIONS: usize = 2_048;
const MAX_PENDING_PER_CLIENT: usize = 8;
const MAX_PENDING_PER_TRUSTED_PROXY: usize = 32;
const ACCEPT_BATCH: usize = 64;
const MAX_CONCURRENT_TLS_HANDSHAKES: usize = 64;
const MAX_TLS_HANDSHAKES_PER_SECOND: usize = 128;
const MAX_TLS_HANDSHAKES_PER_CLIENT_PER_SECOND: usize = 64;

fn listener_index(first: usize, offset: usize, count: usize) -> usize {
    debug_assert!(count > 0);
    (first + offset) % count
}

pub fn active_connections() -> usize {
    ACTIVE_CONNECTIONS.load(Ordering::Relaxed)
}

fn admission_thread_count() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(2)
        .clamp(2, 16)
}

fn admission_runtime() -> io::Result<&'static tokio::runtime::Runtime> {
    if let Some(runtime) = ADMISSION_RUNTIME.get() {
        return Ok(runtime);
    }
    let threads = admission_thread_count();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        // HTTP/1 connections and HTTP/2 filesystem dispatch use Tokio's
        // reusable blocking pool. Admission counters bound queued work; this
        // implementation ceiling prevents configuration from making the pool
        // unbounded while leaving room for the separately capped H2 reads.
        .max_blocking_threads(MAX_IMPLEMENTED_REQUEST_WORKERS + 64)
        .thread_name("vapache-io")
        .enable_io()
        .enable_time()
        .build()?;
    let _ = ADMISSION_RUNTIME.set(runtime);
    Ok(ADMISSION_RUNTIME
        .get()
        .expect("admission runtime was initialized"))
}

pub struct Server {
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    stop: Arc<AtomicBool>,
}

impl Server {
    pub fn new(cfg: Arc<Config>, logger: Arc<Logger>) -> Self {
        Server {
            cfg,
            logger,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    pub fn run(&self, bound: &[Bound]) -> io::Result<()> {
        self.run_with_poll(bound, |pollfds| {
            let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, 100) };
            poll_result(
                rc,
                io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EINVAL),
            )
        })
    }

    fn run_with_poll<F>(&self, bound: &[Bound], mut poll_fn: F) -> io::Result<()>
    where
        F: FnMut(&mut [libc::pollfd]) -> io::Result<()>,
    {
        if self.cfg.capability_audit_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "capability-audit configuration is not runnable",
            ));
        }
        for b in bound {
            b.listener.set_nonblocking(true)?;
        }
        let runtime = admission_runtime()?;
        let mut pollfds: Vec<libc::pollfd> = bound
            .iter()
            .map(|b| libc::pollfd {
                fd: b.listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let mut first_listener = 0usize;
        let pending_limit = pending_connection_limit(self.cfg.max_request_workers) as u64;
        let worker_limit = self.cfg.max_request_workers.max(1) as u64;
        let mut listeners_paused = false;
        while !self.stop.load(Ordering::Relaxed) {
            if listeners_paused {
                if self
                    .cfg
                    .resource_budget
                    .listener_pressure_below_low(pending_limit, worker_limit)
                {
                    listeners_paused = false;
                }
            } else if self
                .cfg
                .resource_budget
                .listener_pressure_high(pending_limit, worker_limit)
            {
                listeners_paused = true;
            }
            for pollfd in &mut pollfds {
                pollfd.events = if listeners_paused { 0 } else { libc::POLLIN };
                pollfd.revents = 0;
            }
            poll_fn(&mut pollfds)?;
            if listeners_paused {
                continue;
            }
            for offset in 0..bound.len() {
                let i = listener_index(first_listener, offset, bound.len());
                let b = &bound[i];
                if pollfds[i].revents & libc::POLLIN == 0 {
                    continue;
                }
                for _ in 0..ACCEPT_BATCH {
                    if self
                        .cfg
                        .resource_budget
                        .listener_pressure_high(pending_limit, worker_limit)
                    {
                        listeners_paused = true;
                        break;
                    }
                    match b.listener.accept() {
                        Ok((stream, peer)) => {
                            let local = stream.local_addr().ok().map(access::canonical_socket_addr);
                            let peer = access::canonical_socket_addr(peer);
                            let cfg = self.cfg.clone();
                            let logger = self.logger.clone();
                            let descriptor_guard = match cfg.resource_budget.try_descriptor() {
                                Ok(guard) => guard,
                                Err(_) => {
                                    reject_busy_connection(stream, b.tls.is_some(), &self.cfg);
                                    listeners_paused = true;
                                    break;
                                }
                            };
                            let trusted_proxy = cfg.transport_peer_is_trusted_proxy(peer.ip());
                            let transport_context = cfg.resource_budget.context(peer.ip());
                            let Some(pending_guard) = try_reserve_pending_connection(
                                &transport_context,
                                pending_connection_limit(cfg.max_request_workers),
                                if trusted_proxy {
                                    MAX_PENDING_PER_TRUSTED_PROXY
                                } else {
                                    MAX_PENDING_PER_CLIENT
                                },
                            ) else {
                                reject_busy_connection(stream, b.tls.is_some(), &self.cfg);
                                continue;
                            };
                            let lifetime_guard = ConnectionLifetimeGuard::new();
                            let port = local.map(|l| l.port()).unwrap_or(b.port);
                            let local_ip = local
                                .map(|l| l.ip().to_string())
                                .unwrap_or_else(|| "127.0.0.1".into());
                            let tls = b.tls.clone();
                            runtime.spawn(async move {
                                let _ = admit_connection(
                                    cfg,
                                    logger,
                                    stream,
                                    peer,
                                    local_ip,
                                    port,
                                    tls,
                                    pending_guard,
                                    lifetime_guard,
                                    descriptor_guard,
                                )
                                .await;
                            });
                        }
                        Err(e) => match accept_error_action(&e) {
                            AcceptAction::Continue => continue,
                            AcceptAction::Backoff => {
                                std::thread::sleep(Duration::from_millis(50));
                                break;
                            }
                            AcceptAction::Break => break,
                        },
                    }
                }
            }
            if !bound.is_empty() {
                first_listener = (first_listener + 1) % bound.len();
            }
        }
        Ok(())
    }
}

struct ConnectionLifetimeGuard;

impl ConnectionLifetimeGuard {
    fn new() -> Self {
        ACTIVE_CONNECTIONS.fetch_add(1, Ordering::AcqRel);
        Self
    }
}

impl Drop for ConnectionLifetimeGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

struct WorkerGuard {
    _quota: crate::resource::SlotLease,
}

struct BodyWorkerGuard {
    _quota: crate::resource::SlotLease,
}

fn per_client_connection_limit(limit: usize) -> usize {
    (limit / 2 + limit % 2).clamp(1, MAX_CONNECTIONS_PER_CLIENT)
}

fn pending_connection_limit(worker_limit: usize) -> usize {
    worker_limit
        .max(1)
        .saturating_mul(2)
        .clamp(64, MAX_PENDING_CONNECTIONS)
}

fn body_worker_limit(worker_limit: usize) -> usize {
    (worker_limit.max(1) / 4).clamp(1, 128)
}

fn try_reserve_quota(
    context: &crate::resource::ResourceContext,
    kind: crate::resource::SlotKind,
    global_limit: usize,
    client_limit: usize,
) -> Option<crate::resource::SlotLease> {
    context
        .slot(
            kind,
            global_limit.max(1) as u64,
            Some(client_limit.max(1) as u64),
            Some(1),
            "connection admission limit reached",
        )
        .ok()
}

fn try_reserve_pending_connection(
    context: &crate::resource::ResourceContext,
    global_limit: usize,
    client_limit: usize,
) -> Option<crate::resource::SlotLease> {
    try_reserve_quota(
        context,
        crate::resource::SlotKind::PendingConnection,
        global_limit,
        client_limit,
    )
}

fn try_reserve_body_worker(
    context: &crate::resource::ResourceContext,
    limit: usize,
) -> Option<BodyWorkerGuard> {
    let body_limit = body_worker_limit(limit);
    let client_limit = (body_limit.saturating_add(3) / 4).max(1);
    try_reserve_quota(
        context,
        crate::resource::SlotKind::RequestBodyWorker,
        body_limit,
        client_limit,
    )
    .map(|quota| BodyWorkerGuard { _quota: quota })
}

fn try_reserve_worker(
    context: &crate::resource::ResourceContext,
    limit: usize,
) -> Option<WorkerGuard> {
    try_reserve_quota(
        context,
        crate::resource::SlotKind::RequestWorker,
        limit,
        per_client_connection_limit(limit),
    )
    .map(|quota| WorkerGuard { _quota: quota })
}

fn try_reserve_h2_connection(
    context: &crate::resource::ResourceContext,
    limit: usize,
) -> Option<crate::resource::SlotLease> {
    try_reserve_quota(
        context,
        crate::resource::SlotKind::H2Connection,
        limit,
        per_client_connection_limit(limit),
    )
}

fn try_reserve_h1_connection(
    context: &crate::resource::ResourceContext,
    limit: usize,
) -> Option<crate::resource::SlotLease> {
    try_reserve_quota(
        context,
        crate::resource::SlotKind::H1Connection,
        pending_connection_limit(limit),
        MAX_CONNECTIONS_PER_CLIENT,
    )
}

fn tls_handshake_limit() -> usize {
    // Waiting handshakes are asynchronous, so this ceiling primarily bounds
    // their state. CPU work is independently bounded by the rate gate below.
    // Keeping the ceiling at the minimum pending-socket budget avoids making
    // one slow handshake serialize an otherwise healthy low-core server.
    MAX_CONCURRENT_TLS_HANDSHAKES
}

fn try_reserve_tls_handshake(
    context: &crate::resource::ResourceContext,
) -> Option<crate::resource::SlotLease> {
    context
        .budget()
        .try_tls_handshake(
            context,
            tls_handshake_limit() as u64,
            MAX_TLS_HANDSHAKES_PER_SECOND as u64,
            MAX_TLS_HANDSHAKES_PER_CLIENT_PER_SECOND as u64,
        )
        .ok()
}

fn keep_alive_capacity_available(budget: &crate::resource::ResourceBudget, limit: usize) -> bool {
    let limit = limit.max(1);
    let reserve = (limit / 4).max(1);
    budget.slot_usage(crate::resource::SlotKind::RequestWorker)
        < limit.saturating_sub(reserve) as u64
}

fn spawn_connection_worker<F, T>(work: F) -> io::Result<tokio::task::JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    crate::fault::hit("server.connection.spawn")?;
    let handle = tokio::runtime::Handle::try_current().map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotConnected,
            format!("connection worker runtime unavailable: {error}"),
        )
    })?;
    Ok(handle.spawn_blocking(work))
}

fn poll_result(rc: libc::c_int, errno: i32) -> io::Result<()> {
    if rc >= 0 {
        return Ok(());
    }
    let e = io::Error::from_raw_os_error(errno);
    if e.kind() == io::ErrorKind::Interrupted {
        Ok(())
    } else {
        Err(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptAction {
    Break,
    Continue,
    Backoff,
}

fn accept_error_action(e: &io::Error) -> AcceptAction {
    if matches!(e.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE)) {
        return AcceptAction::Backoff;
    }
    match e.kind() {
        io::ErrorKind::WouldBlock => AcceptAction::Break,
        io::ErrorKind::Interrupted => AcceptAction::Continue,
        _ => AcceptAction::Break,
    }
}

fn reject_busy_connection(mut stream: TcpStream, tls: bool, cfg: &Config) {
    if tls {
        return;
    }
    let _ = write_response(
        &mut stream,
        &mut simple_html(503, "Server busy", None),
        &ResponseOptions {
            server_header: &cfg.server_header(),
            keep_alive: false,
            head_only: false,
            protocol: Version::Http11,
            request_keep_alive: false,
            write_timeout: cfg.timeout,
        },
    );
}

trait Conn: Read + Write {
    fn set_read_timeout(&mut self, _timeout: Option<Duration>) {}
    fn try_clone_tcp(&self) -> Option<TcpStream> {
        None
    }
    fn take_tls_stream(
        &mut self,
    ) -> Option<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        tokio::runtime::Handle,
    )> {
        None
    }
}

impl Conn for TcpStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        let _ = TcpStream::set_read_timeout(self, timeout);
    }

    fn try_clone_tcp(&self) -> Option<TcpStream> {
        self.try_clone().ok()
    }
}

fn write_ws_error<C: ResponseWrite>(
    stream: &mut C,
    cfg: &Config,
    status: u16,
    message: &[u8],
) -> io::Result<()> {
    let mut r = Response::bytes(status, "text/html; charset=iso-8859-1", message.to_vec());
    r.headers.push(("Connection".into(), b"close".to_vec()));
    write_response(
        stream,
        &mut r,
        &ResponseOptions {
            server_header: &cfg.server_header(),
            keep_alive: false,
            head_only: false,
            protocol: Version::Http11,
            request_keep_alive: false,
            write_timeout: cfg.timeout,
        },
    )?;
    Ok(())
}

fn write_ws_response<C: ResponseWrite>(
    stream: &mut C,
    cfg: &Config,
    response: &mut Response,
) -> io::Result<()> {
    write_response(
        stream,
        response,
        &ResponseOptions {
            server_header: &cfg.server_header(),
            keep_alive: false,
            head_only: false,
            protocol: Version::Http11,
            request_keep_alive: false,
            write_timeout: cfg.timeout,
        },
    )
    .map(|_| ())
}

fn request_limits(cfg: &Config, tls: bool) -> Limits {
    Limits {
        request_line: cfg.limit_request_line,
        fields: cfg.limit_request_fields,
        field_size: cfg.limit_request_field_size,
        body: cfg.limit_request_body,
        header_timeout: cfg.request_header_timeout.max(Duration::from_secs(1)),
        body_timeout: cfg.request_body_timeout.max(Duration::from_secs(1)),
        header_min_rate: cfg.request_header_min_rate,
        body_min_rate: cfg.request_body_min_rate,
        resource_budget: cfg.resource_budget.clone(),
        max_spool_bytes: cfg.max_spool_bytes,
        max_spool_files: cfg.max_spool_files,
        https: tls,
        allow_absolute_request_target: cfg.capability_enabled(Capability::AbsoluteRequestTarget),
        allow_request_trailers: cfg.capability_enabled(Capability::RequestTrailers),
    }
}

fn handle_connection_inner<C: Conn + ResponseWrite>(
    cfg: &Config,
    logger: &Logger,
    stream: &mut C,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    tls: bool,
    buf: &mut Vec<u8>,
    mut initial_reservation: Option<crate::resource::ResidentLease>,
    mut initial_body_guard: Option<BodyWorkerGuard>,
    mut initial_resource_context: Option<crate::resource::ResourceContext>,
    mut request_worker: Option<WorkerGuard>,
    mut general_connection: Option<crate::resource::SlotLease>,
    served: &mut usize,
    single_request: bool,
) -> io::Result<bool> {
    let limits = request_limits(cfg, tls);
    // Configure the transport once rather than paying a setsockopt on every
    // keep-alive response. The explicit write deadline remains the fallback
    // on kernels and transports without the progress-wakeup option.
    stream.configure_progress_wakeups();
    // `Timeout` applies to the first request; idle keep-alive connections use
    // `KeepAliveTimeout`.
    stream.set_read_timeout(Some(cfg.request_header_timeout.max(Duration::from_secs(1))));
    loop {
        if *served == 0 {
            stream.set_read_timeout(Some(cfg.request_header_timeout.max(Duration::from_secs(1))));
        } else if !single_request
            && cfg
                .resource_budget
                .try_request_parse_rate(peer.ip())
                .is_err()
        {
            let mut response = Response::bytes(
                503,
                "text/html; charset=iso-8859-1",
                b"Request rate capacity is temporarily exhausted\n".to_vec(),
            );
            response
                .headers
                .push(("Connection".into(), b"close".to_vec()));
            let _ = write_response(
                stream,
                &mut response,
                &ResponseOptions {
                    server_header: &cfg.server_header(),
                    keep_alive: false,
                    head_only: false,
                    protocol: Version::Http11,
                    request_keep_alive: false,
                    write_timeout: cfg.timeout,
                },
            );
            return Ok(false);
        }
        let started = Instant::now();
        let reservation = if *served == 0 || single_request {
            initial_reservation.take()
        } else {
            None
        };
        let mut body_guard = if *served == 0 || single_request {
            initial_body_guard.take()
        } else {
            None
        };
        let pre_identity_context = cfg.resource_budget.context(peer.ip());
        let _pre_identity_guard = crate::resource::enter_resource_context(pre_identity_context);
        let req = match read_request_with_reservation(
            stream,
            buf,
            &limits,
            |stream, request| {
                let effective = cfg.client_addr(peer, request);
                if request_has_body(request) && !cfg.body_handlers_possible() {
                    // A startup-compiled policy bit proves this generation has
                    // no CGI/FastCGI/proxy/body-consuming handler. Reject any
                    // body before reading or spooling it; allowed static
                    // methods get 400 while unsupported methods retain 405.
                    return Err(ReadError::Parse(
                        if matches!(request.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
                            ParseError::BadRequest(
                                "request body is not accepted by a static-only configuration",
                            )
                        } else {
                            ParseError::MethodNotAllowed
                        },
                    ));
                }
                stream.set_read_timeout(Some(cfg.request_body_timeout.max(Duration::from_secs(1))));
                let (context, rate_pre_admitted) = if *served == 0 || single_request {
                    match initial_resource_context.take() {
                        // The asynchronous admission path parsed this exact
                        // head and consumed its request-rate token before it
                        // acquired a blocking worker. Do not charge it again
                        // when ownership crosses into the worker.
                        Some(context) => (context, true),
                        None => (cfg.resource_budget.context(effective.ip()), false),
                    }
                } else {
                    (cfg.resource_budget.context(effective.ip()), false)
                };
                if !rate_pre_admitted {
                    cfg.resource_budget.try_request_rate(&context)?;
                }
                if request_has_body(request) && body_guard.is_none() {
                    body_guard = Some(
                        try_reserve_body_worker(&context, cfg.max_request_workers).ok_or_else(
                            || {
                                io::Error::new(
                                    io::ErrorKind::WouldBlock,
                                    "slow request-body capacity exhausted",
                                )
                            },
                        )?,
                    );
                }
                Ok(Some(context))
            },
            reservation,
        ) {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(false),
            Err(ReadError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::StorageFull
                        | io::ErrorKind::OutOfMemory
                        | io::ErrorKind::WouldBlock
                ) =>
            {
                // Aggregate request-body capacity is a temporary service
                // condition, not a malformed connection.  Report it
                // explicitly so clients can retry instead of observing a
                // silent reset.
                let mut r = Response::bytes(
                    503,
                    "text/html; charset=iso-8859-1",
                    b"Request body capacity is temporarily exhausted\n".to_vec(),
                );
                r.headers.push(("Connection".into(), b"close".to_vec()));
                let _ = write_response(
                    stream,
                    &mut r,
                    &ResponseOptions {
                        server_header: &cfg.server_header(),
                        keep_alive: false,
                        head_only: false,
                        protocol: Version::Http11,
                        request_keep_alive: false,
                        write_timeout: cfg.timeout,
                    },
                );
                return Ok(false);
            }
            Err(ReadError::Io(e)) => return Err(e),
            Err(ReadError::Parse(e)) => {
                let status = e.status();
                let body = error_body(&e);
                let mut r =
                    Response::bytes(status, "text/html; charset=iso-8859-1", body.into_bytes());
                if matches!(e, ParseError::MethodNotAllowed) {
                    r.headers
                        .push(("Allow".into(), b"GET, HEAD, OPTIONS".to_vec()));
                }
                r.headers.push(("Connection".into(), b"close".to_vec()));
                let _ = write_response(
                    stream,
                    &mut r,
                    &ResponseOptions {
                        server_header: &cfg.server_header(),
                        keep_alive: false,
                        head_only: false,
                        protocol: Version::Http11,
                        request_keep_alive: false,
                        write_timeout: cfg.timeout,
                    },
                );
                return Ok(false);
            }
        };
        drop(_pre_identity_guard);
        let _request_scope_guard = req.request_scope().map(|scope| scope.guard());
        // This lease protects only the slow body-read phase. The parsed body
        // has independent resident/spool accounting while dispatch runs.
        drop(body_guard);
        let peer = cfg.client_addr(peer, &req);
        let remote_ip = peer.ip().to_string();
        let bytes_in = req.target.len() as u64 + req.body_len();

        // WebSocket upgrades need the raw connection after the 101 response;
        // the normal Response pipeline only supports buffered bodies.
        if proxy::is_websocket(&req) {
            // Upgrade routing performs scope evaluation, access-file parsing,
            // rewrite processing and proxy authorization before ordinary
            // dispatch. Bind those helpers to the same validated request
            // hierarchy instead of letting them fail closed or create a
            // second, protocol-specific resource scope.
            let resource_context = req
                .resource_context()
                .cloned()
                .unwrap_or_else(|| cfg.resource_budget.context(peer.ip()));
            let _resource_context_guard = crate::resource::enter_resource_context(resource_context);
            let host = host_header(&req).unwrap_or("");
            let vhost = cfg.select_vhost(
                local_ip.parse().ok(),
                local_port,
                if host.is_empty() { None } else { Some(host) },
            );
            let ws_server_name = server_name_for_public(&cfg, &req, &local_ip, local_port);
            let _ws_server_name_guard = crate::expr::set_server_name(&ws_server_name);
            // The upgrade path must use the same canonical path as ordinary
            // dispatch.  Raw paths containing dot segments or encoded
            // separators would otherwise let the proxy/ACL see a different
            // resource from the one the upstream eventually resolves.
            let allow_encoded = cfg.encoded_slashes == EncodedSlashes::On;
            let decoded = match percent_decode_path(&req.raw_path, allow_encoded) {
                Some(d) => d,
                None => {
                    let _ = write_ws_error(stream, &cfg, 400, b"bad request path");
                    return Ok(false);
                }
            };
            let norm = match normalize_uri_path(&decoded) {
                Some(n)
                    if vapache_verified::canonical_path_text_admit(
                        is_canonical_path(&n),
                        std::str::from_utf8(&n).is_ok(),
                    ) =>
                {
                    n
                }
                _ => {
                    let _ = write_ws_error(stream, &cfg, 400, b"bad request path");
                    return Ok(false);
                }
            };
            let trailing_slash = decoded.len() > 1 && decoded.ends_with(b"/");
            let mut url_path = match String::from_utf8(norm.clone()) {
                Ok(path) => path,
                Err(_) => {
                    let _ = write_ws_error(stream, &cfg, 400, b"request path is not UTF-8");
                    return Ok(false);
                }
            };
            if trailing_slash && url_path != "/" {
                url_path.push('/');
            }
            let Some((root, rel, _script_alias)) = map_path(&cfg, vhost, &norm) else {
                let _ = write_ws_error(stream, &cfg, 404, b"no mapping");
                return Ok(false);
            };
            let fs_path = root.join(&rel);
            let (mut scope, config_conditionals, htaccess_conditionals) =
                match evaluate_scope_for_path(
                    &cfg,
                    vhost,
                    &fs_path,
                    &url_path,
                    &req,
                    peer.ip(),
                    &root,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("vapached: .htaccess error: {e}");
                        let _ = write_ws_error(stream, &cfg, 500, b"access-file error");
                        return Ok(false);
                    }
                };
            apply_scope_conditionals(
                &cfg,
                vhost,
                &mut scope,
                &config_conditionals,
                &htaccess_conditionals,
                &fs_path,
                &url_path,
                &req,
                peer.ip(),
            );

            // Apply rewrite rules before selecting the upstream.  A rule that
            // forbids, redirects or internally rewrites the upgrade must not be
            // skipped.  Only an unchanged request or an explicit proxy rewrite
            // is allowed to continue here; other outcomes fail closed.
            let rewrite_ctx = crate::rewrite::Context {
                url_path: &url_path,
                fs_path: &fs_path,
                docroot: &root,
                server_root: &cfg.server_root,
                query: &req.query,
                peer: peer.ip(),
                port: local_port,
                https: tls,
                server_name: &server_name_for_public(&cfg, &req, &local_ip, local_port),
            };
            let mut rewritten_target = None;
            match crate::rewrite::process(&scope, &req, &rewrite_ctx) {
                crate::rewrite::Outcome::None => {}
                crate::rewrite::Outcome::Forbidden => {
                    let _ = write_ws_error(stream, &cfg, 403, b"forbidden");
                    return Ok(false);
                }
                crate::rewrite::Outcome::Gone => {
                    let _ = write_ws_error(stream, &cfg, 410, b"gone");
                    return Ok(false);
                }
                crate::rewrite::Outcome::Error(e) => {
                    eprintln!("vapached: websocket rewrite error: {e}");
                    let _ = write_ws_error(stream, &cfg, 500, b"rewrite error");
                    return Ok(false);
                }
                crate::rewrite::Outcome::Redirect { .. } => {
                    let _ = write_ws_error(stream, &cfg, 403, b"upgrade redirect unsupported");
                    return Ok(false);
                }
                crate::rewrite::Outcome::Internal { .. } => {
                    let _ = write_ws_error(stream, &cfg, 403, b"upgrade rewrite unsupported");
                    return Ok(false);
                }
                crate::rewrite::Outcome::Proxy { url, effects } => {
                    apply_rewrite_effects(&mut scope, &effects);
                    match proxy::target_from_url(&cfg, &scope, &url, &req) {
                        Some(target) => rewritten_target = Some(target),
                        None => {
                            let _ = write_ws_error(stream, &cfg, 502, b"bad proxy target");
                            return Ok(false);
                        }
                    }
                }
            }

            let ws_target = rewritten_target
                .or_else(|| proxy::match_target_req(&cfg, &scope, &url_path, Some(&req)));
            if let Some(target) = ws_target {
                let mut proxy_urls = vec![target.proxy_url.as_str()];
                if let Some(logical) = target.logical_url.as_deref() {
                    proxy_urls.push(logical);
                }
                cfg.apply_proxy_access_urls(
                    vhost,
                    &mut scope,
                    &proxy_urls,
                    &req,
                    peer.ip(),
                    &url_path,
                );
                if let Some(mut resp) = helper_method_not_allowed(
                    &cfg,
                    vhost,
                    &scope,
                    &req,
                    &url_path,
                    local_port,
                    &server_name_for_public(&cfg, &req, &local_ip, local_port),
                    peer.ip(),
                    &local_ip,
                ) {
                    let _ = write_ws_response(stream, &cfg, &mut resp);
                    return Ok(false);
                }
                let mut resource = access::ResourceKey::request(
                    vhost,
                    &req,
                    &url_path,
                    Some(&fs_path),
                    Some(target.proxy_url.as_str()),
                );
                let _grant = match helper_access_response(
                    &cfg,
                    vhost,
                    &scope,
                    &req,
                    &url_path,
                    &fs_path,
                    local_port,
                    &server_name_for_public(&cfg, &req, &local_ip, local_port),
                    peer.ip(),
                    &local_ip,
                    &mut resource,
                ) {
                    Ok(grant) => grant,
                    Err(mut resp) => {
                        let _ = write_ws_response(stream, &cfg, &mut resp);
                        return Ok(false);
                    }
                };
                if let Some((tls, handle)) = stream.take_tls_stream() {
                    // The TLS stream has been consumed by the tunnel; there is
                    // no safe way to inject a response here.
                    // Request-worker admission protects parsing, policy, and
                    // the upgrade decision.  The independently bounded
                    // WebSocket lease protects the long-lived tunnel, so do
                    // not pin a scarce request worker for the tunnel lifetime.
                    drop(request_worker.take());
                    let _ = handle.block_on(proxy::websocket_async_with_connection(
                        &cfg,
                        &scope,
                        &req,
                        &target,
                        &_grant,
                        &resource,
                        tls,
                        peer,
                        true,
                        host,
                        &buf,
                        general_connection.take(),
                    ));
                    return Ok(false);
                }
                if let Some(client) = stream.try_clone_tcp() {
                    client.set_nonblocking(true)?;
                    drop(request_worker.take());
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_io()
                        .enable_time()
                        .build()?;
                    let cfg_ref = cfg;
                    let scope_ref = &scope;
                    let req_ref = &req;
                    let target_ref = &target;
                    let buf_ref = &buf;
                    let result = rt.block_on(async move {
                        let tcp = tokio::net::TcpStream::from_std(client)?;
                        proxy::websocket_async_with_connection(
                            cfg_ref,
                            scope_ref,
                            req_ref,
                            target_ref,
                            &_grant,
                            &resource,
                            tcp,
                            peer,
                            false,
                            host,
                            buf_ref,
                            general_connection.take(),
                        )
                        .await
                    });
                    if let Err(error) = result {
                        let status = if error.kind() == io::ErrorKind::WouldBlock {
                            503
                        } else {
                            502
                        };
                        let _ = write_ws_error(stream, &cfg, status, b"WebSocket upstream failed");
                    }
                    return Ok(false);
                }
                let _ = write_ws_error(stream, &cfg, 501, b"WebSocket transport is not supported");
                return Ok(false);
            }
        }

        let (mut resp, remote_user) =
            dispatch_with_scheme_and_identity(&cfg, &req, peer, &local_ip, local_port, tls);
        if !crate::http::response_headers_admitted(&resp) {
            resp = Response::policy_error();
        }
        if resp.ensure_file_descriptor(&cfg.resource_budget).is_err() {
            resp = Response::memory_overload();
        }
        if resp.attribute_spool_client(peer.ip()).is_err() {
            resp = Response::memory_overload();
        }
        if resp
            .admit_resident_for(&cfg.resource_budget, peer.ip())
            .is_err()
        {
            resp = Response::memory_overload();
            let _ = resp.admit_resident_for(&cfg.resource_budget, peer.ip());
        }
        let keep_alive = cfg.keep_alive
            && req.keep_alive
            // The asynchronous production path returns after one response and
            // parks the socket without its worker. The capacity check remains
            // for the synchronous test/compatibility loop, where keeping the
            // connection alive also retains the current blocking worker.
            && (single_request
                || keep_alive_capacity_available(&cfg.resource_budget, cfg.max_request_workers))
            && (cfg.max_keep_alive_requests == 0
                || *served + 1 < cfg.max_keep_alive_requests);
        let mut opts = ResponseOptions {
            server_header: &cfg.server_header(),
            keep_alive,
            head_only: req.is_head(),
            protocol: req.version,
            request_keep_alive: req.keep_alive,
            write_timeout: cfg.timeout,
        };
        if !keep_alive {
            opts.keep_alive = false;
        }
        let body_sent = match write_response(stream, &mut resp, &opts) {
            Ok(sent) => sent,
            // The head or body was partially written, or the response failed
            // its own framing checks.  Reusing this connection would let the
            // next response be read as a continuation of this body.
            Err(_) => return Ok(false),
        };
        crate::status::hit(body_sent);
        if logger.wants_access_log() {
            let host = host_header(&req).unwrap_or("");
            let server_name = server_name_for(&cfg, &req, &local_ip, local_port);
            let vhost_idx = cfg
                .select_vhost(
                    local_ip.parse().ok(),
                    local_port,
                    if host.is_empty() { None } else { Some(host) },
                )
                .and_then(|v| cfg.vhosts.iter().position(|x| std::ptr::eq(x, v)));
            logger.access(&AccessEntry {
                remote_ip: &remote_ip,
                remote_port: peer.port(),
                local_ip,
                local_port,
                server_name: &server_name,
                method: &req.method,
                uri: &req.target,
                remote_user: remote_user.as_deref(),
                protocol: req.version.as_str(),
                status: resp.status,
                bytes_sent: body_sent,
                bytes_in,
                referer: req.header_str("referer").unwrap_or(""),
                user_agent: req.header_str("user-agent").unwrap_or(""),
                host,
                vhost_index: vhost_idx,
                started,
            });
        }
        *served += 1;
        if !keep_alive {
            return Ok(false);
        }
        if single_request {
            return Ok(true);
        }
        if *served == 1 {
            stream.set_read_timeout(Some(cfg.keep_alive_timeout));
        }
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn handle_connection<C: Conn + ResponseWrite>(
    cfg: &Config,
    logger: &Logger,
    stream: &mut C,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    tls: bool,
    mut buf: Vec<u8>,
    initial_reservation: Option<crate::resource::ResidentLease>,
    initial_body_guard: Option<BodyWorkerGuard>,
    initial_resource_context: Option<crate::resource::ResourceContext>,
) -> io::Result<()> {
    let mut served = 0;
    handle_connection_inner(
        cfg,
        logger,
        stream,
        peer,
        local_ip,
        local_port,
        tls,
        &mut buf,
        initial_reservation,
        initial_body_guard,
        initial_resource_context,
        None,
        None,
        &mut served,
        false,
    )
    .map(|_| ())
}

/// Blocking adapter for an async TLS stream.  Every read/write is bounded by
/// a timeout so an idle TLS client cannot pin one of the server's connection
/// threads forever.  The adapter runs on a `spawn_blocking` thread, so a
/// nested `Handle::block_on` is safe and is the same mechanism `SyncIoBridge`
/// uses internally.
struct TlsH1 {
    stream: Option<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
    handle: tokio::runtime::Handle,
    read_timeout: Duration,
    write_deadline: Option<Instant>,
}

fn timed_io<T>(result: Option<io::Result<T>>, message: &str) -> io::Result<T> {
    match result {
        Some(r) => r,
        None => Err(io::Error::new(io::ErrorKind::TimedOut, message)),
    }
}

impl TlsH1 {
    fn new(
        stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            stream: Some(stream),
            handle,
            read_timeout: Duration::from_secs(20),
            write_deadline: None,
        }
    }

    fn remaining_write_time(&self) -> io::Result<Duration> {
        self.write_deadline
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(30))
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TLS response write deadline exceeded",
                )
            })
    }

    fn into_inner(self) -> Option<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
        self.stream
    }
}

impl Read for TlsH1 {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let handle = self.handle.clone();
        let timeout = self.read_timeout;
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TLS stream closed"))?;
        handle.block_on(async move {
            timed_io(
                tokio::time::timeout(timeout, stream.read(buf)).await.ok(),
                "TLS read timeout",
            )
        })
    }
}

impl Write for TlsH1 {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let handle = self.handle.clone();
        let timeout = self.remaining_write_time()?;
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TLS stream closed"))?;
        handle.block_on(async move {
            timed_io(
                tokio::time::timeout(timeout, stream.write(buf)).await.ok(),
                "TLS write timeout",
            )
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        let handle = self.handle.clone();
        let timeout = self.remaining_write_time()?;
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TLS stream closed"))?;
        handle.block_on(async move {
            timed_io(
                tokio::time::timeout(timeout, stream.flush()).await.ok(),
                "TLS flush timeout",
            )
        })
    }
}

impl Conn for TlsH1 {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        if let Some(timeout) = timeout {
            self.read_timeout = timeout;
        }
    }

    fn take_tls_stream(
        &mut self,
    ) -> Option<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        tokio::runtime::Handle,
    )> {
        self.stream.take().map(|s| (s, self.handle.clone()))
    }
}
impl ResponseWrite for TlsH1 {
    fn configure_progress_wakeups(&self) {
        if let Some(stream) = &self.stream {
            // Configure the TCP transport without exposing it through
            // `deadline_fd`, which would let response bytes bypass TLS.
            let _ = crate::http::configure_response_progress_wakeups(stream.get_ref().0.as_fd());
        }
    }

    fn set_write_deadline(&mut self, deadline: Option<Instant>) {
        self.write_deadline = deadline;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsHttpProtocol {
    Http2,
    Http11,
}

fn admitted_tls_http_protocol(
    allows_h2: bool,
    allows_http11: bool,
    negotiated: Option<&[u8]>,
) -> io::Result<TlsHttpProtocol> {
    match negotiated {
        Some(b"h2") if allows_h2 => Ok(TlsHttpProtocol::Http2),
        Some(b"http/1.1") if allows_http11 => Ok(TlsHttpProtocol::Http11),
        // HTTP/1.1 predates ALPN, so omission remains a valid HTTP/1.1
        // fallback only when the listener explicitly permits HTTP/1.1.
        None if allows_http11 => Ok(TlsHttpProtocol::Http11),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS client did not negotiate an enabled HTTP protocol",
        )),
    }
}

fn admission_reason(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Request Rejected",
    }
}

async fn try_reject_h1_async<S>(stream: &mut S, cfg: &Config, status: u16) -> io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let reason = admission_reason(status);
    let body = format!("{status} {reason}\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let deadline = cfg
        .timeout
        .max(Duration::from_millis(100))
        .min(Duration::from_secs(2));
    tokio::time::timeout(deadline, async {
        stream.write_all(response.as_bytes()).await?;
        stream.shutdown().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "rejection write timed out"))?
}

async fn reject_h1_async<S>(stream: &mut S, cfg: &Config, status: u16)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let _ = try_reject_h1_async(stream, cfg, status).await;
}

async fn read_request_head<S>(
    stream: &mut S,
    timeout: Duration,
    resource_budget: Arc<crate::resource::ResourceBudget>,
    client: IpAddr,
    mut bytes: Vec<u8>,
) -> io::Result<(Vec<u8>, usize, crate::resource::ResidentLease)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    tokio::time::timeout(timeout.max(Duration::from_secs(1)), async {
        let mut resident = resource_budget.try_request_bytes_for(client);
        // A pipelined prefix was retained from the preceding request. Charge
        // it to this admission before doing more I/O or parsing; failure closes
        // the connection without processing unaccounted input.
        resident.reserve(bytes.len() as u64)?;
        loop {
            if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                let head_end = position + 4;
                if head_end > crate::http::MAX_HEAD_TOTAL {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request head is too large",
                    ));
                }
                // Match `read_request`'s parser-copy charge before preflight
                // creates owned method/target/header values.
                resident.reserve(head_end as u64)?;
                return Ok((bytes, head_end, resident));
            }
            if bytes.len() > crate::http::MAX_HEAD_TOTAL {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request head is too large",
                ));
            }
            let mut chunk = [0u8; 8 * 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before request head",
                ));
            }
            resident.reserve(read as u64)?;
            bytes.extend_from_slice(&chunk[..read]);
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request header timed out"))?
}

async fn read_first_request_head<S>(
    stream: &mut S,
    timeout: Duration,
    resource_budget: Arc<crate::resource::ResourceBudget>,
    client: IpAddr,
) -> io::Result<(Vec<u8>, usize, crate::resource::ResidentLease)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    read_request_head(
        stream,
        timeout,
        resource_budget,
        client,
        Vec::with_capacity(8 * 1024),
    )
    .await
}

async fn read_keepalive_request_head<S>(
    stream: &mut S,
    idle_timeout: Duration,
    header_timeout: Duration,
    resource_budget: Arc<crate::resource::ResourceBudget>,
    client: IpAddr,
    mut buffered: Vec<u8>,
) -> io::Result<(Vec<u8>, usize, crate::resource::ResidentLease)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    if buffered.is_empty() {
        let mut chunk = [0u8; 8 * 1024];
        let read = tokio::time::timeout(idle_timeout, stream.read(&mut chunk))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "keep-alive idle timeout"))??;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "keep-alive connection closed",
            ));
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
    read_request_head(stream, header_timeout, resource_budget, client, buffered).await
}

fn request_has_body(request: &Request) -> bool {
    !matches!(request.framing, crate::verified::BodyFraming::None)
}

struct H1Admission {
    context: crate::resource::ResourceContext,
    has_body: bool,
    websocket: bool,
}

fn preflight_h1_admission(
    cfg: &Config,
    peer: SocketAddr,
    bytes: &[u8],
    head_end: usize,
    tls: bool,
) -> Result<H1Admission, u16> {
    let limits = request_limits(cfg, tls);
    let request = preflight_request_head(&bytes[..head_end], &limits).map_err(|e| e.status())?;
    let effective = cfg.client_addr(peer, &request);
    let context = cfg.resource_budget.context(effective.ip());
    cfg.resource_budget
        .try_request_rate(&context)
        .map_err(|_| 503u16)?;
    Ok(H1Admission {
        context,
        has_body: request_has_body(&request),
        websocket: proxy::is_websocket(&request),
    })
}

struct H1DeferredResponse {
    request: Request,
    response: Response,
    remote_user: Option<String>,
    peer: SocketAddr,
    started: Instant,
    keep_alive: bool,
    linger_unread_body: bool,
    phase: RequestPhaseToken,
    _scope_guard: Option<crate::resource::RequestScopeGuard>,
}

#[derive(Clone, Copy, Debug)]
struct RequestPhaseToken {
    phase: vapache_verified::RequestPhase,
}

impl RequestPhaseToken {
    fn head() -> Self {
        Self {
            phase: vapache_verified::RequestPhase::Head,
        }
    }

    fn advance(&mut self, event: vapache_verified::RequestPhaseEvent) {
        self.phase = vapache_verified::request_phase_step(self.phase, event)
            .expect("illegal request phase transition");
    }
}

async fn reject_h1_body_phase<S>(
    stream: &mut S,
    cfg: &Config,
    status: u16,
    phase: &mut RequestPhaseToken,
) where
    S: tokio::io::AsyncWrite + Unpin,
{
    phase.advance(vapache_verified::RequestPhaseEvent::BodyErrorResponse);
    let event = if try_reject_h1_async(stream, cfg, status).await.is_ok() {
        vapache_verified::RequestPhaseEvent::OutputComplete
    } else {
        vapache_verified::RequestPhaseEvent::Cancel
    };
    phase.advance(event);
}

enum H1WorkerPhase {
    NeedBody {
        head: ParsedRequestHead,
        body_guard: BodyWorkerGuard,
        handler: PreparedHandler,
        remote_user: Option<String>,
        scope_guard: Option<crate::resource::RequestScopeGuard>,
        started: Instant,
        phase: RequestPhaseToken,
    },
    DrainBody {
        head: ParsedRequestHead,
        body_guard: BodyWorkerGuard,
        response: Response,
        remote_user: Option<String>,
        scope_guard: Option<crate::resource::RequestScopeGuard>,
        started: Instant,
        phase: RequestPhaseToken,
    },
    Backend {
        request: Request,
        handler: PreparedHandler,
        remote_user: Option<String>,
        scope_guard: Option<crate::resource::RequestScopeGuard>,
        started: Instant,
        phase: RequestPhaseToken,
    },
    Response(H1DeferredResponse),
}

#[allow(clippy::too_many_arguments)]
fn finish_h1_response(
    cfg: &Config,
    mut request: Request,
    mut response: Response,
    remote_user: Option<String>,
    peer: SocketAddr,
    started: Instant,
    served: usize,
    force_close: bool,
    scope_guard: Option<crate::resource::RequestScopeGuard>,
    phase: RequestPhaseToken,
) -> H1DeferredResponse {
    if !crate::http::response_headers_admitted(&response) {
        response = Response::policy_error();
    }
    let effective = cfg.client_addr(peer, &request);
    if response
        .ensure_file_descriptor(&cfg.resource_budget)
        .is_err()
    {
        response = Response::memory_overload();
    }
    if response.attribute_spool_client(effective.ip()).is_err() {
        response = Response::memory_overload();
    }
    if response
        .admit_resident_for(&cfg.resource_budget, effective.ip())
        .is_err()
    {
        response = Response::memory_overload();
        let _ = response.admit_resident_for(&cfg.resource_budget, effective.ip());
    }
    let keep_alive = !force_close
        && cfg.keep_alive
        && request.keep_alive
        && (cfg.max_keep_alive_requests == 0 || served + 1 < cfg.max_keep_alive_requests);
    if !keep_alive {
        request.keep_alive = false;
    }
    let linger_unread_body = force_close && request_has_body(&request);
    H1DeferredResponse {
        request,
        response,
        remote_user,
        peer: effective,
        started,
        keep_alive,
        linger_unread_body,
        phase,
        _scope_guard: scope_guard,
    }
}

#[allow(clippy::too_many_arguments)]
fn process_h1_request_phase<C: Conn + ResponseWrite>(
    cfg: &Config,
    stream: &mut C,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    tls: bool,
    buf: &mut Vec<u8>,
    reservation: crate::resource::ResidentLease,
    body_guard: Option<BodyWorkerGuard>,
    resource_context: crate::resource::ResourceContext,
    served: usize,
) -> Result<H1WorkerPhase, ReadError> {
    let started = Instant::now();
    let limits = request_limits(cfg, tls);
    let Some(mut head) = read_request_head_with_reservation(
        stream,
        buf,
        &limits,
        |_stream, _request| Ok(Some(resource_context)),
        Some(reservation),
    )?
    else {
        return Err(ReadError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed before admitted request",
        )));
    };
    let scope_guard = head.request().request_scope().map(|scope| scope.guard());
    let dispatch_peer = cfg.client_addr(peer, head.request());
    let mut phase = RequestPhaseToken::head();
    if request_has_body(head.request()) {
        match probe_request_body(
            cfg,
            head.request_mut(),
            dispatch_peer,
            local_ip,
            local_port,
            tls,
        ) {
            BodyRouteDecision::Read {
                handler,
                remote_user,
            } => {
                let Some(body_guard) = body_guard else {
                    return Err(ReadError::Io(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "request body capacity unavailable",
                    )));
                };
                phase.advance(vapache_verified::RequestPhaseEvent::RouteNeedsBody);
                return Ok(H1WorkerPhase::NeedBody {
                    head,
                    body_guard,
                    handler,
                    remote_user,
                    scope_guard,
                    started,
                    phase,
                });
            }
            BodyRouteDecision::Drain(response, remote_user) => {
                let Some(body_guard) = body_guard else {
                    return Err(ReadError::Io(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "request body capacity unavailable",
                    )));
                };
                phase.advance(vapache_verified::RequestPhaseEvent::RouteNeedsDrain);
                return Ok(H1WorkerPhase::DrainBody {
                    head,
                    body_guard,
                    response,
                    remote_user,
                    scope_guard,
                    started,
                    phase,
                });
            }
            BodyRouteDecision::Respond(response, remote_user) => {
                phase.advance(vapache_verified::RequestPhaseEvent::EarlyResponse);
                let request = head.finish_without_body();
                return Ok(H1WorkerPhase::Response(finish_h1_response(
                    cfg,
                    request,
                    response,
                    remote_user,
                    peer,
                    started,
                    served,
                    true,
                    scope_guard,
                    phase,
                )));
            }
        }
    }

    drop(body_guard);
    let mut request = head.finish_without_body();
    match probe_prepared_handler(cfg, &mut request, dispatch_peer, local_ip, local_port, tls) {
        PreparedRouteDecision::Prepared {
            handler,
            remote_user,
        } => {
            phase.advance(vapache_verified::RequestPhaseEvent::RoutePrepared);
            Ok(H1WorkerPhase::Backend {
                request,
                handler,
                remote_user,
                scope_guard,
                started,
                phase,
            })
        }
        PreparedRouteDecision::Respond(response, remote_user) => {
            phase.advance(vapache_verified::RequestPhaseEvent::RouteReady);
            phase.advance(vapache_verified::RequestPhaseEvent::DispatchComplete);
            Ok(H1WorkerPhase::Response(finish_h1_response(
                cfg,
                request,
                response,
                remote_user,
                peer,
                started,
                served,
                false,
                scope_guard,
                phase,
            )))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_h1_backend_phase(
    cfg: &Config,
    mut request: Request,
    peer: SocketAddr,
    _local_ip: &str,
    local_port: u16,
    tls: bool,
    started: Instant,
    served: usize,
    handler: PreparedHandler,
    remote_user: Option<String>,
    scope_guard: Option<crate::resource::RequestScopeGuard>,
    mut phase: RequestPhaseToken,
) -> H1DeferredResponse {
    if phase.phase == vapache_verified::RequestPhase::Body {
        phase.advance(vapache_verified::RequestPhaseEvent::BodyComplete);
    }
    let response = execute_prepared_handler(cfg, &mut request, peer, local_port, tls, handler);
    phase.advance(vapache_verified::RequestPhaseEvent::BackendComplete);
    finish_h1_response(
        cfg,
        request,
        response,
        remote_user,
        peer,
        started,
        served,
        false,
        scope_guard,
        phase,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_h1_drained_body(
    cfg: &Config,
    mut request: Request,
    response: Response,
    remote_user: Option<String>,
    peer: SocketAddr,
    started: Instant,
    served: usize,
    scope_guard: Option<crate::resource::RequestScopeGuard>,
    mut phase: RequestPhaseToken,
) -> H1DeferredResponse {
    request.discard_body();
    phase.advance(vapache_verified::RequestPhaseEvent::BodyDiscarded);
    finish_h1_response(
        cfg,
        request,
        response,
        remote_user,
        peer,
        started,
        served,
        false,
        scope_guard,
        phase,
    )
}

async fn read_h1_body_phase<S>(
    stream: &mut S,
    buffered: &mut Vec<u8>,
    cfg: &Config,
    tls: bool,
    head: ParsedRequestHead,
    phase: &mut RequestPhaseToken,
) -> io::Result<Option<Request>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match read_request_body_async(stream, buffered, &request_limits(cfg, tls), head).await {
        Ok(request) => Ok(Some(request)),
        Err(ReadError::Parse(error)) => {
            reject_h1_body_phase(stream, cfg, error.status(), phase).await;
            Ok(None)
        }
        Err(ReadError::Io(error))
            if matches!(
                error.kind(),
                io::ErrorKind::OutOfMemory | io::ErrorKind::StorageFull | io::ErrorKind::WouldBlock
            ) =>
        {
            reject_h1_body_phase(stream, cfg, 503, phase).await;
            Ok(None)
        }
        Err(ReadError::Io(error)) if error.kind() == io::ErrorKind::TimedOut => {
            reject_h1_body_phase(stream, cfg, 408, phase).await;
            Ok(None)
        }
        Err(ReadError::Io(error)) => {
            phase.advance(vapache_verified::RequestPhaseEvent::Cancel);
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_streaming_h1_body_phase<S>(
    stream: &mut S,
    buffered: &mut Vec<u8>,
    cfg: &Config,
    head: ParsedRequestHead,
    body_guard: BodyWorkerGuard,
    peer: SocketAddr,
    local_port: u16,
    tls: bool,
    started: Instant,
    served: usize,
    handler: PreparedHandler,
    remote_user: Option<String>,
    scope_guard: Option<crate::resource::RequestScopeGuard>,
    mut phase: RequestPhaseToken,
) -> io::Result<H1DeferredResponse>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let limits = request_limits(cfg, tls);
    let (request, pump) = match prepare_streaming_request_body(head, &limits) {
        Ok(prepared) => prepared,
        Err((request, error)) => {
            let status = if matches!(
                error.kind(),
                io::ErrorKind::OutOfMemory | io::ErrorKind::StorageFull | io::ErrorKind::WouldBlock
            ) {
                503
            } else {
                400
            };
            phase.advance(vapache_verified::RequestPhaseEvent::BodyErrorResponse);
            drop(body_guard);
            return Ok(finish_h1_response(
                cfg,
                request,
                Response::bytes(
                    status,
                    "text/plain; charset=UTF-8",
                    b"Request body could not be admitted\n".to_vec(),
                ),
                remote_user,
                peer,
                started,
                served,
                true,
                scope_guard,
                phase,
            ));
        }
    };
    let mut rejected_request = request.clone();
    phase.advance(vapache_verified::RequestPhaseEvent::BackendStarted);
    let cfg_worker = cfg.clone();
    let mut backend = spawn_connection_worker(move || {
        let mut request = request;
        let response =
            execute_prepared_handler(&cfg_worker, &mut request, peer, local_port, tls, handler);
        (request, response)
    })?;
    let mut body = Box::pin(pump_streaming_request_body(stream, buffered, &limits, pump));

    let (request, response, body_complete) = tokio::select! {
        biased;
        result = &mut backend => {
            let (request, response) = result
                .map_err(|error| io::Error::other(format!("HTTP/1 backend failed: {error}")))?;
            (request, response, false)
        }
        result = &mut body => {
            match result {
                Ok(()) => {
                    let (request, response) = backend.await
                        .map_err(|error| io::Error::other(format!("HTTP/1 backend failed: {error}")))?;
                    (request, response, true)
                }
                // A backend is allowed to reject an upload without consuming
                // it. Its response wins, but the connection cannot be reused
                // because unread request bytes remain on the wire.
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                    let (request, response) = backend.await
                        .map_err(|join| io::Error::other(format!("HTTP/1 backend failed: {join}")))?;
                    (request, response, false)
                }
                Err(error) => {
                    if let Some(scope) = rejected_request.request_scope() {
                        scope.cancel();
                    }
                    drop(backend);
                    rejected_request.clear_streaming_body();
                    let status = match error.kind() {
                        io::ErrorKind::TimedOut => 408,
                        io::ErrorKind::OutOfMemory
                        | io::ErrorKind::StorageFull
                        | io::ErrorKind::WouldBlock => 503,
                        _ => 400,
                    };
                    let response = Response::bytes(
                        status,
                        "text/plain; charset=UTF-8",
                        b"Request body could not be consumed\n".to_vec(),
                    );
                    phase.advance(vapache_verified::RequestPhaseEvent::BodyErrorResponse);
                    drop(body_guard);
                    return Ok(finish_h1_response(
                        cfg,
                        rejected_request,
                        response,
                        remote_user,
                        peer,
                        started,
                        served,
                        true,
                        scope_guard,
                        phase,
                    ));
                }
            }
        }
    };
    drop(body_guard);
    phase.advance(vapache_verified::RequestPhaseEvent::BackendComplete);
    Ok(finish_h1_response(
        cfg,
        request,
        response,
        remote_user,
        peer,
        started,
        served,
        !body_complete,
        scope_guard,
        phase,
    ))
}

fn log_h1_response(
    cfg: &Config,
    logger: &Logger,
    local_ip: &str,
    local_port: u16,
    deferred: &H1DeferredResponse,
    body_sent: u64,
) {
    crate::status::hit(body_sent);
    if !logger.wants_access_log() {
        return;
    }
    let request = &deferred.request;
    let host = host_header(request).unwrap_or("");
    let server_name = server_name_for(cfg, request, local_ip, local_port);
    let vhost_idx = cfg
        .select_vhost(
            local_ip.parse().ok(),
            local_port,
            if host.is_empty() { None } else { Some(host) },
        )
        .and_then(|vhost| cfg.vhosts.iter().position(|item| std::ptr::eq(item, vhost)));
    let remote_ip = deferred.peer.ip().to_string();
    logger.access(&AccessEntry {
        remote_ip: &remote_ip,
        remote_port: deferred.peer.port(),
        local_ip,
        local_port,
        server_name: &server_name,
        method: &request.method,
        uri: &request.target,
        remote_user: deferred.remote_user.as_deref(),
        protocol: request.version.as_str(),
        status: deferred.response.status,
        bytes_sent: body_sent,
        bytes_in: request.target.len() as u64 + request.body_len(),
        referer: request.header_str("referer").unwrap_or(""),
        user_agent: request.header_str("user-agent").unwrap_or(""),
        host,
        vhost_index: vhost_idx,
        started: deferred.started,
    });
}

/// Finish a rejected upload without letting unread request bytes become a TCP
/// reset that can erase the response. The drain has both a byte ceiling and
/// an absolute deadline, so an attacker cannot turn graceful close into a new
/// connection-retention primitive.
async fn bounded_lingering_close<S>(stream: &mut S, buffered: &mut Vec<u8>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    const MAX_DRAIN: usize = 64 * 1024;
    const MAX_TIME: Duration = Duration::from_millis(250);

    let _ = tokio::time::timeout(MAX_TIME, stream.shutdown()).await;
    let mut drained = buffered.len().min(MAX_DRAIN);
    buffered.clear();
    let deadline = tokio::time::Instant::now() + MAX_TIME;
    let mut chunk = [0u8; 4096];
    while drained < MAX_DRAIN {
        let want = (MAX_DRAIN - drained).min(chunk.len());
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk[..want])).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(read)) => drained += read,
        }
    }
}

async fn send_h1_response<S>(
    stream: &mut S,
    cfg: &Config,
    logger: &Logger,
    local_ip: &str,
    local_port: u16,
    deferred: &mut H1DeferredResponse,
    established_guard: &mut Option<crate::resource::SlotLease>,
) -> io::Result<(u64, bool)>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let server_header = cfg.server_header();
    let options = ResponseOptions {
        server_header: &server_header,
        keep_alive: deferred.keep_alive,
        head_only: deferred.request.is_head(),
        protocol: deferred.request.version,
        request_keep_alive: deferred.request.keep_alive,
        write_timeout: cfg.timeout,
    };
    let scope = deferred.request.request_scope().cloned();
    let context = scope
        .as_ref()
        .map(|scope| scope.context().clone())
        .ok_or_else(|| io::Error::other("HTTP/1 response lost its resource context"))?;
    let general = established_guard
        .take()
        .ok_or_else(|| io::Error::other("HTTP/1 response lost its connection admission"))?;
    let mut output = crate::resource::SlowOutputAdmission::tracked_h1(context, general);
    let result = write_response_async(
        stream,
        &mut deferred.response,
        &options,
        scope.as_ref(),
        &mut output,
    )
    .await;
    let was_slow = output.is_slow();
    *established_guard = output.finish_h1();
    match result {
        Ok(sent) => {
            deferred
                .phase
                .advance(vapache_verified::RequestPhaseEvent::OutputComplete);
            log_h1_response(cfg, logger, local_ip, local_port, deferred, sent);
            Ok((sent, was_slow))
        }
        Err(error) => {
            deferred
                .phase
                .advance(vapache_verified::RequestPhaseEvent::Cancel);
            if let Some(scope) = scope {
                scope.cancel();
            }
            Err(error)
        }
    }
}

async fn send_h1_response_plain(
    stream: &mut tokio::net::TcpStream,
    cfg: &Config,
    logger: &Logger,
    local_ip: &str,
    local_port: u16,
    deferred: &mut H1DeferredResponse,
    established_guard: &mut Option<crate::resource::SlotLease>,
) -> io::Result<(u64, bool)> {
    let server_header = cfg.server_header();
    let options = ResponseOptions {
        server_header: &server_header,
        keep_alive: deferred.keep_alive,
        head_only: deferred.request.is_head(),
        protocol: deferred.request.version,
        request_keep_alive: deferred.request.keep_alive,
        write_timeout: cfg.timeout,
    };
    let scope = deferred.request.request_scope().cloned();
    let context = scope
        .as_ref()
        .map(|scope| scope.context().clone())
        .ok_or_else(|| io::Error::other("HTTP/1 response lost its resource context"))?;
    let general = established_guard
        .take()
        .ok_or_else(|| io::Error::other("HTTP/1 response lost its connection admission"))?;
    let mut output = crate::resource::SlowOutputAdmission::tracked_h1(context, general);
    let result = write_response_async_plain(
        stream,
        &mut deferred.response,
        &options,
        scope.as_ref(),
        &mut output,
    )
    .await;
    let was_slow = output.is_slow();
    *established_guard = output.finish_h1();
    match result {
        Ok(sent) => {
            deferred
                .phase
                .advance(vapache_verified::RequestPhaseEvent::OutputComplete);
            log_h1_response(cfg, logger, local_ip, local_port, deferred, sent);
            Ok((sent, was_slow))
        }
        Err(error) => {
            deferred
                .phase
                .advance(vapache_verified::RequestPhaseEvent::Cancel);
            if let Some(scope) = scope {
                scope.cancel();
            }
            Err(error)
        }
    }
}

async fn admit_plain_connection(
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    stream: TcpStream,
    peer: SocketAddr,
    local_ip: String,
    local_port: u16,
    pending_guard: crate::resource::SlotLease,
    lifetime_guard: ConnectionLifetimeGuard,
    descriptor_guard: crate::resource::DescriptorLease,
) -> io::Result<()> {
    let _lifetime_guard = lifetime_guard;
    let _descriptor_guard = descriptor_guard;
    stream.set_nonblocking(true)?;
    let mut stream = tokio::net::TcpStream::from_std(stream)?;
    if cfg
        .resource_budget
        .try_request_parse_rate(peer.ip())
        .is_err()
    {
        reject_h1_async(&mut stream, &cfg, 503).await;
        return Ok(());
    }
    let (mut initial, mut head_end, mut resident) = match read_first_request_head(
        &mut stream,
        cfg.request_header_timeout,
        cfg.resource_budget.clone(),
        peer.ip(),
    )
    .await
    {
        Ok(head) => head,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            reject_h1_async(&mut stream, &cfg, 431).await;
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
            reject_h1_async(&mut stream, &cfg, 503).await;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let first_admission = match preflight_h1_admission(&cfg, peer, &initial, head_end, false) {
        Ok(admission) => admission,
        Err(status) => {
            reject_h1_async(&mut stream, &cfg, status).await;
            return Ok(());
        }
    };
    let Some(established_guard) =
        try_reserve_h1_connection(&first_admission.context, cfg.max_request_workers)
    else {
        reject_h1_async(&mut stream, &cfg, 503).await;
        return Ok(());
    };
    let mut established_guard = Some(established_guard);
    drop(pending_guard);
    let mut served = 0usize;
    let mut next_admission = Some(first_admission);
    loop {
        let admission = match next_admission.take() {
            Some(admission) => admission,
            None => match preflight_h1_admission(&cfg, peer, &initial, head_end, false) {
                Ok(admission) => admission,
                Err(status) => {
                    reject_h1_async(&mut stream, &cfg, status).await;
                    return Ok(());
                }
            },
        };
        let body_guard = if admission.has_body {
            match try_reserve_body_worker(&admission.context, cfg.max_request_workers) {
                Some(guard) => Some(guard),
                None => {
                    reject_h1_async(&mut stream, &cfg, 503).await;
                    return Ok(());
                }
            }
        } else {
            None
        };
        let Some(worker_guard) =
            try_reserve_worker(&admission.context, cfg.max_request_workers.max(1))
        else {
            reject_h1_async(&mut stream, &cfg, 503).await;
            return Ok(());
        };
        let blocking = stream.into_std()?;
        blocking.set_nonblocking(false)?;
        blocking.set_nodelay(true).ok();
        let cfg_worker = cfg.clone();
        let logger_worker = logger.clone();
        let local_ip_worker = local_ip.clone();
        let mut request_buf = initial;
        let websocket_connection_guard = admission
            .websocket
            .then(|| established_guard.take())
            .flatten();
        let result = if admission.websocket {
            spawn_connection_worker(move || {
                let mut blocking = blocking;
                let result = handle_connection_inner(
                    &cfg_worker,
                    &logger_worker,
                    &mut blocking,
                    peer,
                    &local_ip_worker,
                    local_port,
                    false,
                    &mut request_buf,
                    Some(resident),
                    body_guard,
                    Some(admission.context),
                    Some(worker_guard),
                    websocket_connection_guard,
                    &mut served,
                    true,
                );
                (blocking, request_buf, None, result.map(|_| ()))
            })?
            .await
            .map_err(|error| io::Error::other(format!("HTTP/1 worker failed: {error}")))?
        } else {
            spawn_connection_worker(move || {
                let _worker_guard = worker_guard;
                let mut blocking = blocking;
                let phase = process_h1_request_phase(
                    &cfg_worker,
                    &mut blocking,
                    peer,
                    &local_ip_worker,
                    local_port,
                    false,
                    &mut request_buf,
                    resident,
                    body_guard,
                    admission.context,
                    served,
                );
                (blocking, request_buf, Some(phase), Ok(()))
            })?
            .await
            .map_err(|error| io::Error::other(format!("HTTP/1 worker failed: {error}")))?
        };
        let (blocking, mut buffered, phase, legacy) = result;
        legacy?;
        if phase.is_none() {
            return Ok(());
        }
        blocking.set_nonblocking(true)?;
        stream = tokio::net::TcpStream::from_std(blocking)?;
        let mut deferred = match phase.expect("non-WebSocket worker returned a phase") {
            Ok(H1WorkerPhase::Response(deferred)) => deferred,
            Ok(H1WorkerPhase::Backend {
                request,
                handler,
                remote_user,
                scope_guard,
                started,
                phase,
            }) => {
                let cfg_worker = cfg.clone();
                let local_ip_worker = local_ip.clone();
                spawn_connection_worker(move || {
                    dispatch_h1_backend_phase(
                        &cfg_worker,
                        request,
                        peer,
                        &local_ip_worker,
                        local_port,
                        false,
                        started,
                        served,
                        handler,
                        remote_user,
                        scope_guard,
                        phase,
                    )
                })?
                .await
                .map_err(|error| io::Error::other(format!("HTTP/1 backend failed: {error}")))?
            }
            Ok(H1WorkerPhase::DrainBody {
                head,
                body_guard,
                response,
                remote_user,
                scope_guard,
                started,
                mut phase,
            }) => {
                let Some(request) =
                    read_h1_body_phase(&mut stream, &mut buffered, &cfg, false, head, &mut phase)
                        .await?
                else {
                    return Ok(());
                };
                drop(body_guard);
                finish_h1_drained_body(
                    &cfg,
                    request,
                    response,
                    remote_user,
                    peer,
                    started,
                    served,
                    scope_guard,
                    phase,
                )
            }
            Ok(H1WorkerPhase::NeedBody {
                head,
                body_guard,
                handler,
                remote_user,
                scope_guard,
                started,
                mut phase,
            }) => {
                if matches!(
                    head.request().framing,
                    crate::verified::BodyFraming::Length(length)
                        if length > crate::http::MAX_REQUEST_BODY_IN_MEMORY
                ) {
                    dispatch_streaming_h1_body_phase(
                        &mut stream,
                        &mut buffered,
                        &cfg,
                        head,
                        body_guard,
                        peer,
                        local_port,
                        false,
                        started,
                        served,
                        handler,
                        remote_user,
                        scope_guard,
                        phase,
                    )
                    .await?
                } else {
                    let request = match read_request_body_async(
                        &mut stream,
                        &mut buffered,
                        &request_limits(&cfg, false),
                        head,
                    )
                    .await
                    {
                        Ok(request) => request,
                        Err(ReadError::Parse(error)) => {
                            reject_h1_body_phase(&mut stream, &cfg, error.status(), &mut phase)
                                .await;
                            return Ok(());
                        }
                        Err(ReadError::Io(error))
                            if matches!(
                                error.kind(),
                                io::ErrorKind::OutOfMemory
                                    | io::ErrorKind::StorageFull
                                    | io::ErrorKind::WouldBlock
                            ) =>
                        {
                            reject_h1_body_phase(&mut stream, &cfg, 503, &mut phase).await;
                            return Ok(());
                        }
                        Err(ReadError::Io(error)) if error.kind() == io::ErrorKind::TimedOut => {
                            reject_h1_body_phase(&mut stream, &cfg, 408, &mut phase).await;
                            return Ok(());
                        }
                        Err(ReadError::Io(error)) => {
                            phase.advance(vapache_verified::RequestPhaseEvent::Cancel);
                            return Err(error);
                        }
                    };
                    drop(body_guard);
                    let cfg_worker = cfg.clone();
                    let local_ip_worker = local_ip.clone();
                    spawn_connection_worker(move || {
                        dispatch_h1_backend_phase(
                            &cfg_worker,
                            request,
                            peer,
                            &local_ip_worker,
                            local_port,
                            false,
                            started,
                            served,
                            handler,
                            remote_user,
                            scope_guard,
                            phase,
                        )
                    })?
                    .await
                    .map_err(|error| io::Error::other(format!("HTTP/1 dispatch failed: {error}")))?
                }
            }
            Err(ReadError::Parse(error)) => {
                reject_h1_async(&mut stream, &cfg, error.status()).await;
                return Ok(());
            }
            Err(ReadError::Io(error)) => return Err(error),
        };
        let was_slow = match send_h1_response_plain(
            &mut stream,
            &cfg,
            &logger,
            &local_ip,
            local_port,
            &mut deferred,
            &mut established_guard,
        )
        .await
        {
            Ok((_, was_slow)) => was_slow,
            Err(_) => return Ok(()),
        };
        served += 1;
        let reusable = deferred.keep_alive;
        let linger_unread_body = deferred.linger_unread_body;
        drop(deferred);
        if was_slow || !reusable {
            if linger_unread_body {
                bounded_lingering_close(&mut stream, &mut buffered).await;
            }
            return Ok(());
        }
        if cfg
            .resource_budget
            .try_request_parse_rate(peer.ip())
            .is_err()
        {
            reject_h1_async(&mut stream, &cfg, 503).await;
            return Ok(());
        }
        (initial, head_end, resident) = match read_keepalive_request_head(
            &mut stream,
            cfg.keep_alive_timeout,
            cfg.request_header_timeout,
            cfg.resource_budget.clone(),
            peer.ip(),
            buffered,
        )
        .await
        {
            Ok(head) => head,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                reject_h1_async(&mut stream, &cfg, 431).await;
                return Ok(());
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::UnexpectedEof
                ) =>
            {
                return Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
                reject_h1_async(&mut stream, &cfg, 503).await;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
    }
}

async fn admit_tls_connection(
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    stream: TcpStream,
    peer: SocketAddr,
    local_ip: String,
    local_port: u16,
    tls_config: Arc<rustls::ServerConfig>,
    pending_guard: crate::resource::SlotLease,
    lifetime_guard: ConnectionLifetimeGuard,
    descriptor_guard: crate::resource::DescriptorLease,
) -> io::Result<()> {
    let _descriptor_guard = descriptor_guard;
    let transport_context = cfg.resource_budget.context(peer.ip());
    let handshake_guard = try_reserve_tls_handshake(&transport_context).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "TLS handshake capacity exhausted",
        )
    })?;
    let allows_h2 = tls_config
        .alpn_protocols
        .iter()
        .any(|protocol| protocol == b"h2");
    let allows_http11 = tls_config
        .alpn_protocols
        .iter()
        .any(|protocol| protocol == b"http/1.1");
    stream.set_nodelay(true).ok();
    stream.set_nonblocking(true)?;
    let tcp = tokio::net::TcpStream::from_std(stream)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    let mut tls = tokio::time::timeout(Duration::from_secs(20), acceptor.accept(tcp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
    drop(handshake_guard);
    let alpn = tls.get_ref().1.alpn_protocol();
    match admitted_tls_http_protocol(allows_h2, allows_http11, alpn)? {
        TlsHttpProtocol::Http2 => {
            let connection_limit = cfg.max_request_workers.max(1);
            let h2_context = transport_context.clone();
            return crate::h2::serve(cfg, logger, tls, peer, local_ip, local_port, move || {
                let established = try_reserve_h2_connection(&h2_context, connection_limit)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::WouldBlock, "HTTP/2 connection limit reached")
                    })?;
                drop(pending_guard);
                Ok((lifetime_guard, established))
            })
            .await;
        }
        TlsHttpProtocol::Http11 => {}
    }

    if cfg
        .resource_budget
        .try_request_parse_rate(peer.ip())
        .is_err()
    {
        reject_h1_async(&mut tls, &cfg, 503).await;
        return Ok(());
    }

    let (mut initial, mut head_end, mut resident) = match read_first_request_head(
        &mut tls,
        cfg.request_header_timeout,
        cfg.resource_budget.clone(),
        peer.ip(),
    )
    .await
    {
        Ok(head) => head,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            reject_h1_async(&mut tls, &cfg, 431).await;
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
            reject_h1_async(&mut tls, &cfg, 503).await;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let first_admission = match preflight_h1_admission(&cfg, peer, &initial, head_end, true) {
        Ok(admission) => admission,
        Err(status) => {
            reject_h1_async(&mut tls, &cfg, status).await;
            return Ok(());
        }
    };
    let Some(established_guard) =
        try_reserve_h1_connection(&first_admission.context, cfg.max_request_workers)
    else {
        reject_h1_async(&mut tls, &cfg, 503).await;
        return Ok(());
    };
    let mut established_guard = Some(established_guard);
    drop(pending_guard);
    let _lifetime_guard = lifetime_guard;
    let runtime_handle = tokio::runtime::Handle::current();
    let mut served = 0usize;
    let mut next_admission = Some(first_admission);
    loop {
        let admission = match next_admission.take() {
            Some(admission) => admission,
            None => match preflight_h1_admission(&cfg, peer, &initial, head_end, true) {
                Ok(admission) => admission,
                Err(status) => {
                    reject_h1_async(&mut tls, &cfg, status).await;
                    return Ok(());
                }
            },
        };
        let body_guard = if admission.has_body {
            match try_reserve_body_worker(&admission.context, cfg.max_request_workers) {
                Some(guard) => Some(guard),
                None => {
                    reject_h1_async(&mut tls, &cfg, 503).await;
                    return Ok(());
                }
            }
        } else {
            None
        };
        let Some(worker_guard) =
            try_reserve_worker(&admission.context, cfg.max_request_workers.max(1))
        else {
            reject_h1_async(&mut tls, &cfg, 503).await;
            return Ok(());
        };
        let bridge = TlsH1::new(tls, runtime_handle.clone());
        let cfg_worker = cfg.clone();
        let logger_worker = logger.clone();
        let local_ip_worker = local_ip.clone();
        let mut request_buf = initial;
        let websocket_connection_guard = admission
            .websocket
            .then(|| established_guard.take())
            .flatten();
        let result = if admission.websocket {
            spawn_connection_worker(move || {
                let mut bridge = bridge;
                let result = handle_connection_inner(
                    &cfg_worker,
                    &logger_worker,
                    &mut bridge,
                    peer,
                    &local_ip_worker,
                    local_port,
                    true,
                    &mut request_buf,
                    Some(resident),
                    body_guard,
                    Some(admission.context),
                    Some(worker_guard),
                    websocket_connection_guard,
                    &mut served,
                    true,
                );
                (bridge, request_buf, None, result.map(|_| ()))
            })?
            .await
            .map_err(|error| io::Error::other(format!("TLS HTTP/1 worker failed: {error}")))?
        } else {
            spawn_connection_worker(move || {
                let _worker_guard = worker_guard;
                let mut bridge = bridge;
                let phase = process_h1_request_phase(
                    &cfg_worker,
                    &mut bridge,
                    peer,
                    &local_ip_worker,
                    local_port,
                    true,
                    &mut request_buf,
                    resident,
                    body_guard,
                    admission.context,
                    served,
                );
                (bridge, request_buf, Some(phase), Ok(()))
            })?
            .await
            .map_err(|error| io::Error::other(format!("TLS HTTP/1 worker failed: {error}")))?
        };
        let (bridge, mut buffered, phase, legacy) = result;
        legacy?;
        if phase.is_none() {
            return Ok(());
        }
        let Some(next_tls) = bridge.into_inner() else {
            return Ok(());
        };
        tls = next_tls;
        let mut deferred = match phase.expect("non-WebSocket worker returned a phase") {
            Ok(H1WorkerPhase::Response(deferred)) => deferred,
            Ok(H1WorkerPhase::Backend {
                request,
                handler,
                remote_user,
                scope_guard,
                started,
                phase,
            }) => {
                let cfg_worker = cfg.clone();
                let local_ip_worker = local_ip.clone();
                spawn_connection_worker(move || {
                    dispatch_h1_backend_phase(
                        &cfg_worker,
                        request,
                        peer,
                        &local_ip_worker,
                        local_port,
                        true,
                        started,
                        served,
                        handler,
                        remote_user,
                        scope_guard,
                        phase,
                    )
                })?
                .await
                .map_err(|error| io::Error::other(format!("TLS HTTP/1 backend failed: {error}")))?
            }
            Ok(H1WorkerPhase::DrainBody {
                head,
                body_guard,
                response,
                remote_user,
                scope_guard,
                started,
                mut phase,
            }) => {
                let Some(request) =
                    read_h1_body_phase(&mut tls, &mut buffered, &cfg, true, head, &mut phase)
                        .await?
                else {
                    return Ok(());
                };
                drop(body_guard);
                finish_h1_drained_body(
                    &cfg,
                    request,
                    response,
                    remote_user,
                    peer,
                    started,
                    served,
                    scope_guard,
                    phase,
                )
            }
            Ok(H1WorkerPhase::NeedBody {
                head,
                body_guard,
                handler,
                remote_user,
                scope_guard,
                started,
                mut phase,
            }) => {
                if matches!(
                    head.request().framing,
                    crate::verified::BodyFraming::Length(length)
                        if length > crate::http::MAX_REQUEST_BODY_IN_MEMORY
                ) {
                    dispatch_streaming_h1_body_phase(
                        &mut tls,
                        &mut buffered,
                        &cfg,
                        head,
                        body_guard,
                        peer,
                        local_port,
                        true,
                        started,
                        served,
                        handler,
                        remote_user,
                        scope_guard,
                        phase,
                    )
                    .await?
                } else {
                    let request = match read_request_body_async(
                        &mut tls,
                        &mut buffered,
                        &request_limits(&cfg, true),
                        head,
                    )
                    .await
                    {
                        Ok(request) => request,
                        Err(ReadError::Parse(error)) => {
                            reject_h1_body_phase(&mut tls, &cfg, error.status(), &mut phase).await;
                            return Ok(());
                        }
                        Err(ReadError::Io(error))
                            if matches!(
                                error.kind(),
                                io::ErrorKind::OutOfMemory
                                    | io::ErrorKind::StorageFull
                                    | io::ErrorKind::WouldBlock
                            ) =>
                        {
                            reject_h1_body_phase(&mut tls, &cfg, 503, &mut phase).await;
                            return Ok(());
                        }
                        Err(ReadError::Io(error)) if error.kind() == io::ErrorKind::TimedOut => {
                            reject_h1_body_phase(&mut tls, &cfg, 408, &mut phase).await;
                            return Ok(());
                        }
                        Err(ReadError::Io(error)) => {
                            phase.advance(vapache_verified::RequestPhaseEvent::Cancel);
                            return Err(error);
                        }
                    };
                    drop(body_guard);
                    let cfg_worker = cfg.clone();
                    let local_ip_worker = local_ip.clone();
                    spawn_connection_worker(move || {
                        dispatch_h1_backend_phase(
                            &cfg_worker,
                            request,
                            peer,
                            &local_ip_worker,
                            local_port,
                            true,
                            started,
                            served,
                            handler,
                            remote_user,
                            scope_guard,
                            phase,
                        )
                    })?
                    .await
                    .map_err(|error| {
                        io::Error::other(format!("TLS HTTP/1 dispatch failed: {error}"))
                    })?
                }
            }
            Err(ReadError::Parse(error)) => {
                reject_h1_async(&mut tls, &cfg, error.status()).await;
                return Ok(());
            }
            Err(ReadError::Io(error)) => return Err(error),
        };
        let was_slow = match send_h1_response(
            &mut tls,
            &cfg,
            &logger,
            &local_ip,
            local_port,
            &mut deferred,
            &mut established_guard,
        )
        .await
        {
            Ok((_, was_slow)) => was_slow,
            Err(_) => return Ok(()),
        };
        served += 1;
        let reusable = deferred.keep_alive;
        let linger_unread_body = deferred.linger_unread_body;
        drop(deferred);
        if was_slow || !reusable {
            if linger_unread_body {
                bounded_lingering_close(&mut tls, &mut buffered).await;
            }
            return Ok(());
        }
        if cfg
            .resource_budget
            .try_request_parse_rate(peer.ip())
            .is_err()
        {
            reject_h1_async(&mut tls, &cfg, 503).await;
            return Ok(());
        }
        (initial, head_end, resident) = match read_keepalive_request_head(
            &mut tls,
            cfg.keep_alive_timeout,
            cfg.request_header_timeout,
            cfg.resource_budget.clone(),
            peer.ip(),
            buffered,
        )
        .await
        {
            Ok(head) => head,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                reject_h1_async(&mut tls, &cfg, 431).await;
                return Ok(());
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::UnexpectedEof
                ) =>
            {
                return Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
                reject_h1_async(&mut tls, &cfg, 503).await;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
    }
}

#[allow(clippy::too_many_arguments)]
async fn admit_connection(
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    stream: TcpStream,
    peer: SocketAddr,
    local_ip: String,
    local_port: u16,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    pending_guard: crate::resource::SlotLease,
    lifetime_guard: ConnectionLifetimeGuard,
    descriptor_guard: crate::resource::DescriptorLease,
) -> io::Result<()> {
    if let Some(tls_config) = tls_config {
        admit_tls_connection(
            cfg,
            logger,
            stream,
            peer,
            local_ip,
            local_port,
            tls_config,
            pending_guard,
            lifetime_guard,
            descriptor_guard,
        )
        .await
    } else {
        admit_plain_connection(
            cfg,
            logger,
            stream,
            peer,
            local_ip,
            local_port,
            pending_guard,
            lifetime_guard,
            descriptor_guard,
        )
        .await
    }
}

fn error_body(e: &ParseError) -> String {
    let status = e.status();
    format!(
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>{status} {}</title>\n</head><body>\n<h1>{}</h1>\n<p>{}</p>\n</body></html>\n",
        crate::http::reason_phrase(status),
        crate::http::reason_phrase(status),
        crate::util::html_escape(e.message().as_bytes())
    )
}

fn host_header(req: &Request) -> Option<&str> {
    req.header_str("host").and_then(|h| {
        let t = h.trim();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    })
}

fn allowed_methods(cfg: &Config) -> Vec<&'static str> {
    let mut methods = vec!["GET", "HEAD", "POST", "OPTIONS"];
    if cfg.trace_enable && cfg.capability_enabled(Capability::Trace) {
        methods.push("TRACE");
    }
    methods
}

fn allow_header(cfg: &Config) -> String {
    allowed_methods(cfg).join(", ")
}

fn options_response(cfg: &Config, scope: &Scope, mime: Option<String>) -> Response {
    let mut r = Response::new(200);
    r.headers
        .push(("Allow".into(), allow_header(cfg).into_bytes()));
    r.headers.push(("Content-Length".into(), b"0".to_vec()));
    if let Some(mime) = mime {
        r.headers.push(("Content-Type".into(), mime.into_bytes()));
    }
    if scope.header_policy.apply(&mut r.headers, true).is_err() {
        return Response::policy_error();
    }
    crate::compression::finalize_metadata(scope, &mut r);
    r
}

fn helper_method_not_allowed(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    req: &Request,
    url_path: &str,
    local_port: u16,
    server_name: &str,
    peer: std::net::IpAddr,
    local_ip: &str,
) -> Option<Response> {
    if scope.method_allowed(&req.method) {
        return None;
    }
    let mut r = error_response(
        cfg,
        vhost,
        scope,
        405,
        req,
        url_path,
        local_port,
        server_name,
        peer,
        local_ip,
    );
    if let Some(allow) = scope.allow_methods_header() {
        r.headers.push(("Allow".into(), allow.into_bytes()));
    }
    Some(r)
}

fn authenticated_access_result(access: Access) -> Access {
    match access {
        Access::AuthRequired => Access::Denied,
        other => other,
    }
}

fn helper_access_response(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    req: &Request,
    url_path: &str,
    fs_path: &Path,
    local_port: u16,
    server_name: &str,
    peer: std::net::IpAddr,
    local_ip: &str,
    resource: &mut access::ResourceKey,
) -> Result<access::AccessGrant, Response> {
    // F63/I63: the mapped filesystem path binds `%{REQUEST_FILENAME}` in
    // `Require expr`.
    let mut access = access::check(scope, req, peer, None, url_path, Some(fs_path));
    if access == Access::AuthRequired {
        if let Some(identity) = crate::auth::authenticate(
            scope,
            req,
            cfg.capability_enabled(Capability::MutableAuthFiles),
        ) {
            resource.identity = Some(identity.user.clone());
            access = authenticated_access_result(access::check(
                scope,
                req,
                peer,
                Some(&identity),
                url_path,
                Some(fs_path),
            ));
        }
    }
    match access {
        Access::Allowed => {
            Ok(access::grant_if_allowed(access, resource.clone()).expect("allowed grant"))
        }
        Access::Denied => Err(error_response(
            cfg,
            vhost,
            scope,
            403,
            req,
            url_path,
            local_port,
            server_name,
            peer,
            local_ip,
        )),
        Access::Misconfigured => Err(error_response(
            cfg,
            vhost,
            scope,
            500,
            req,
            url_path,
            local_port,
            server_name,
            peer,
            local_ip,
        )),
        Access::AuthRequired => {
            let mut r = error_response(
                cfg,
                vhost,
                scope,
                401,
                req,
                url_path,
                local_port,
                server_name,
                peer,
                local_ip,
            );
            let realm: String = scope
                .authorization
                .auth_name
                .as_deref()
                .unwrap_or("Restricted")
                .chars()
                .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
                .collect();
            r.headers.push((
                "WWW-Authenticate".into(),
                format!("Basic realm=\"{realm}\"").into_bytes(),
            ));
            Err(r)
        }
    }
}

fn absolute_url_scheme(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    path: &str,
    server_name: &str,
    port: u16,
    https: bool,
) -> String {
    let authority = if cfg.use_canonical_name {
        // `UseCanonicalName On` pins redirects to the configured ServerName;
        // the client Host header must not turn them into open redirects.
        // Apache uses the directive verbatim, including any explicit port, and
        // does not append the listening port to a bare ServerName.
        vhost
            .and_then(|v| v.server_name.as_deref())
            .or(cfg.server_name.as_deref())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                if (!https && port == 80) || (https && port == 443) {
                    server_name.to_string()
                } else {
                    format!("{server_name}:{port}")
                }
            })
    } else {
        req.header_str("host")
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                if (!https && port == 80) || (https && port == 443) {
                    server_name.to_string()
                } else {
                    format!("{server_name}:{port}")
                }
            })
    };
    format!(
        "{}://{authority}{path}",
        if https { "https" } else { "http" }
    )
}

fn canonicalize_rewrite_path(path: &str) -> Option<String> {
    let trailing = path.len() > 1 && path.ends_with('/');
    let norm = normalize_uri_path(path.as_bytes())?;
    let mut out = String::from_utf8_lossy(&norm).into_owned();
    if trailing && out != "/" {
        out.push('/');
    }
    Some(out)
}

fn strip_port(h: &str) -> &str {
    if let Some(rest) = h.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    if h.matches(':').count() == 1 {
        h.split(':').next().unwrap_or(h)
    } else {
        h
    }
}

fn server_name_for(cfg: &Config, req: &Request, local_ip: &str, port: u16) -> String {
    if let Some(v) = cfg.select_vhost(local_ip.parse().ok(), port, host_header(req)) {
        if let Some(n) = &v.server_name {
            return strip_port(n).to_string();
        }
    }
    if cfg.use_canonical_name {
        if let Some(name) = &cfg.server_name {
            return strip_port(name).to_string();
        }
    }
    if let Some(h) = host_header(req) {
        return strip_port(h).to_string();
    }
    cfg.server_name
        .clone()
        .unwrap_or_else(|| "localhost".to_string())
}

pub(crate) fn server_name_for_public(
    cfg: &Config,
    req: &Request,
    local_ip: &str,
    port: u16,
) -> String {
    server_name_for(cfg, req, local_ip, port)
}

pub fn dispatch(
    cfg: &Config,
    req: &Request,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
) -> Response {
    dispatch_with_scheme(cfg, req, peer, local_ip, local_port, false)
}

pub(crate) fn dispatch_with_scheme(
    cfg: &Config,
    req: &Request,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    tls: bool,
) -> Response {
    dispatch_with_scheme_and_identity(cfg, req, peer, local_ip, local_port, tls).0
}

pub(crate) fn dispatch_with_scheme_and_identity(
    cfg: &Config,
    req: &Request,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    tls: bool,
) -> (Response, Option<String>) {
    crate::auth::reset_request_identity();
    let context = req
        .resource_context()
        .cloned()
        .unwrap_or_else(|| cfg.resource_budget.context(peer.ip()));
    let response = crate::resource::with_resource_context(context, || {
        crate::expr::with_connection(tls, local_port, || {
            dispatch_inner_request(cfg, req, peer, local_ip, local_port)
        })
    });
    let remote_user = crate::auth::take_request_identity();
    (response, remote_user)
}

pub(crate) enum BodyRouteDecision {
    Read {
        handler: PreparedHandler,
        remote_user: Option<String>,
    },
    Drain(Response, Option<String>),
    Respond(Response, Option<String>),
}

pub(crate) enum PreparedRouteDecision {
    Prepared {
        handler: PreparedHandler,
        remote_user: Option<String>,
    },
    Respond(Response, Option<String>),
}

/// Fully authorized, side-effect-free dynamic sink selected by the routing
/// phase.  Keeping this as an explicit IR makes the route/body boundary
/// inspectable and prevents a second rewrite/authentication pass after upload.
pub(crate) enum PreparedHandler {
    /// Complete the outer dispatch operations only after the dynamic sink has
    /// produced its real status and headers. Cache stores and unsafe-method
    /// invalidation must never be decided from the prepared marker response.
    FinalizeDispatch {
        handler: Box<PreparedHandler>,
        vhost_index: Option<usize>,
        cache: Option<Box<crate::cache::CacheContext>>,
        host: String,
        peer: std::net::IpAddr,
        invalidation_path: String,
    },
    /// A local ErrorDocument is an explicit response transformation: execute
    /// its handler, preserve the original error status, then apply the outer
    /// error response's header and compression policy.
    FinalizeErrorDocument {
        handler: Box<PreparedHandler>,
        scope: Scope,
        status: u16,
        url_path: String,
        port: u16,
        host: String,
    },
    Proxy {
        vhost_index: Option<usize>,
        scope: Scope,
        target: proxy::Target,
        peer: SocketAddr,
        local_port: u16,
        https: bool,
        server_name: String,
        local_ip: String,
        grant: access::AccessGrant,
        resource: access::ResourceKey,
        url_path: String,
        query_override: Option<Vec<u8>>,
    },
    FastCgi {
        vhost_index: Option<usize>,
        scope: Scope,
        target: fastcgi::Target,
        peer: SocketAddr,
        local_port: u16,
        server_name: String,
        local_ip: String,
        grant: access::AccessGrant,
        resource: access::ResourceKey,
        url_path: String,
        mapping_root: PathBuf,
    },
    Cgi {
        vhost_index: Option<usize>,
        scope: Scope,
        peer: SocketAddr,
        local_port: u16,
        server_name: String,
        local_ip: String,
        grant: access::AccessGrant,
        resource: access::ResourceKey,
        root: PathBuf,
        script_rel: PathBuf,
        url_path: String,
        path_info: String,
        script_name: String,
        script_file: std::fs::File,
        script_meta: std::fs::Metadata,
        _descriptor_lease: crate::resource::DescriptorLease,
    },
}

impl PreparedHandler {
    fn kind(&self) -> vapache_verified::PreparedHandlerKind {
        match self {
            PreparedHandler::FinalizeDispatch { handler, .. }
            | PreparedHandler::FinalizeErrorDocument { handler, .. } => handler.kind(),
            PreparedHandler::Proxy { .. } => vapache_verified::PreparedHandlerKind::Proxy,
            PreparedHandler::FastCgi { .. } => vapache_verified::PreparedHandlerKind::FastCgi,
            PreparedHandler::Cgi { .. } => vapache_verified::PreparedHandlerKind::Cgi,
        }
    }

    fn execute(self, cfg: &Config, req: &mut Request) -> Response {
        match self {
            PreparedHandler::FinalizeDispatch {
                handler,
                vhost_index,
                cache,
                host,
                peer,
                invalidation_path,
            } => {
                let mut response = handler.execute(cfg, req);
                let vhost = vhost_index.and_then(|index| cfg.vhosts.get(index));
                if let Some(cache) = cache {
                    crate::cache::store(
                        cfg,
                        vhost,
                        req,
                        &host,
                        &cache.path,
                        &cache.scope,
                        peer,
                        &mut response,
                        &cache.grant,
                        &cache.key,
                        &cache.target,
                    );
                }
                let unsafe_method =
                    !matches!(req.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE");
                if vapache_verified::cache_invalidation_status_admit(unsafe_method, response.status)
                {
                    crate::cache::invalidate(cfg, &host, &invalidation_path);
                }
                response
            }
            PreparedHandler::FinalizeErrorDocument {
                handler,
                scope,
                status,
                url_path,
                port,
                host,
            } => {
                let response = handler.execute(cfg, req);
                crate::files::finalize_prepared_error_document(
                    cfg, &scope, status, req, &url_path, port, &host, response,
                )
            }
            PreparedHandler::Proxy {
                vhost_index,
                scope,
                target,
                peer,
                local_port,
                https,
                server_name,
                local_ip,
                grant,
                resource,
                url_path,
                query_override,
            } => {
                let vhost = vhost_index.and_then(|index| cfg.vhosts.get(index));
                let original_query =
                    query_override.map(|query| std::mem::replace(&mut req.query, query));
                let response = proxy::execute(
                    cfg,
                    vhost,
                    &scope,
                    req,
                    &url_path,
                    &target,
                    peer,
                    local_port,
                    https,
                    &server_name,
                    &local_ip,
                    &grant,
                    &resource,
                );
                if let Some(original_query) = original_query {
                    req.query = original_query;
                }
                response
            }
            PreparedHandler::FastCgi {
                vhost_index,
                scope,
                target,
                peer,
                local_port,
                server_name,
                local_ip,
                grant,
                resource,
                url_path,
                mapping_root,
            } => {
                let vhost = vhost_index.and_then(|index| cfg.vhosts.get(index));
                run_fastcgi(
                    cfg,
                    vhost,
                    req,
                    &url_path,
                    &server_name,
                    peer,
                    &local_ip,
                    local_port,
                    &scope,
                    &target,
                    &grant,
                    &resource,
                    &mapping_root,
                )
            }
            PreparedHandler::Cgi {
                vhost_index,
                scope,
                peer,
                local_port,
                server_name,
                local_ip,
                grant,
                resource,
                root,
                script_rel,
                url_path,
                path_info,
                script_name,
                script_file,
                script_meta,
                _descriptor_lease,
            } => {
                let vhost = vhost_index.and_then(|index| cfg.vhosts.get(index));
                run_cgi(
                    cfg,
                    vhost,
                    req,
                    &root,
                    &script_rel,
                    &url_path,
                    &path_info,
                    &script_name,
                    &server_name,
                    peer,
                    &local_ip,
                    local_port,
                    &scope,
                    &grant,
                    &resource,
                    Some(&script_file),
                    Some(&script_meta),
                )
            }
        }
    }
}

/// Execute the normal request policy pipeline without allowing a content
/// handler to perform side effects. Dynamic handlers return typed IR only
/// after their final route and authorization grants have been established.
pub(crate) fn probe_prepared_handler(
    cfg: &Config,
    req: &mut Request,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    tls: bool,
) -> PreparedRouteDecision {
    req.set_handler_probe(true);
    let (mut response, remote_user) =
        dispatch_with_scheme_and_identity(cfg, req, peer, local_ip, local_port, tls);
    req.set_handler_probe(false);
    if response.has_prepared_handler() {
        let handler = response
            .take_prepared_handler()
            .expect("prepared route response retained its handler");
        return PreparedRouteDecision::Prepared {
            handler,
            remote_user,
        };
    }
    PreparedRouteDecision::Respond(response, remote_user)
}

/// Body acquisition is admitted only after routing. Dynamic sinks receive the
/// body; successful static routes drain it under the same bounds so a safe
/// HTTP/1 keep-alive connection can remain synchronized with Apache.
pub(crate) fn probe_request_body(
    cfg: &Config,
    req: &mut Request,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    tls: bool,
) -> BodyRouteDecision {
    let (response, remote_user) =
        match probe_prepared_handler(cfg, req, peer, local_ip, local_port, tls) {
            PreparedRouteDecision::Prepared {
                handler,
                remote_user,
            } => {
                return BodyRouteDecision::Read {
                    handler,
                    remote_user,
                };
            }
            PreparedRouteDecision::Respond(response, remote_user) => (response, remote_user),
        };
    if (200..300).contains(&response.status) {
        BodyRouteDecision::Drain(response, remote_user)
    } else {
        BodyRouteDecision::Respond(response, remote_user)
    }
}

pub(crate) fn execute_prepared_handler(
    cfg: &Config,
    req: &mut Request,
    peer: SocketAddr,
    local_port: u16,
    tls: bool,
    handler: PreparedHandler,
) -> Response {
    crate::files::reset_local_error_document_response();
    debug_assert!(vapache_verified::prepared_handler_needs_dynamic_lease(
        handler.kind()
    ));
    let context = req
        .resource_context()
        .cloned()
        .unwrap_or_else(|| cfg.resource_budget.context(peer.ip()));
    crate::resource::with_resource_context(context, || {
        crate::expr::with_connection(tls, local_port, || handler.execute(cfg, req))
    })
}

fn selected_vhost_index(cfg: &Config, vhost: Option<&VHost>) -> Option<usize> {
    vhost.and_then(|selected| {
        cfg.vhosts
            .iter()
            .position(|candidate| std::ptr::eq(candidate, selected))
    })
}

fn dispatch_inner_request(
    cfg: &Config,
    req: &Request,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
) -> Response {
    // Each outer request starts without error-document provenance; the
    // internal subrequest sets it before this request's cache store runs.
    crate::files::reset_local_error_document_response();
    // Memoize repeated metadata probes for this request only.  The guard drops
    // on every return path, so the next request cannot observe stale state.
    let _metadata_guard = crate::files::request_metadata_scope();
    let host = host_header(req).unwrap_or("");
    let path = String::from_utf8_lossy(&req.raw_path).into_owned();
    let vhost = cfg.select_vhost(
        local_ip.parse().ok(),
        local_port,
        if host.is_empty() { None } else { Some(host) },
    );
    let https_for_cache = crate::expr::request_is_https();
    let server_name_for_cache = server_name_for(cfg, req, local_ip, local_port);
    let _server_name_guard = crate::expr::set_server_name(&server_name_for_cache);
    let allow_encoded = cfg.encoded_slashes == EncodedSlashes::On;
    let initial_plan = match RequestPlan::from_request(cfg, vhost, req, allow_encoded) {
        Ok(plan) => Some(plan),
        Err(crate::request_plan::CanonicalErrorOrPlan::Canonical(error)) => {
            return error_response(
                cfg,
                vhost,
                vhost.map(|v| &v.scope).unwrap_or(&cfg.global),
                error.status(),
                req,
                &path,
                local_port,
                &server_name_for_cache,
                peer.ip(),
                local_ip,
            );
        }
        // Preserve the dispatcher's detailed mapping/access-file response.
        Err(crate::request_plan::CanonicalErrorOrPlan::Plan(_)) => None,
    };
    let invalidation_path = initial_plan
        .as_ref()
        .map(|plan| plan.url_path().to_string());
    let probing_body =
        req.handler_probe() && !matches!(req.framing, crate::verified::BodyFraming::None);
    let mut cache_scope = (!probing_body)
        .then_some(())
        .and_then(|()| initial_plan.as_ref())
        .and_then(|plan| {
            crate::cache::request_scope_with_plan(
                cfg,
                vhost,
                req,
                peer.ip(),
                plan,
                &path,
                local_port,
                https_for_cache,
                &server_name_for_cache,
                host,
                local_ip,
            )
        });
    if let (Some(plan), Some(cache_ctx)) = (&initial_plan, &cache_scope) {
        let trailing_slash = plan.url_path().len() > 1 && plan.url_path().ends_with('/');
        let same_representation_path = cache_ctx.path == plan.url_path();
        let regular_file = cache_ctx.target.is_file();
        if !vapache_verified::cache_trailing_slash_target_admit(
            trailing_slash,
            same_representation_path,
            regular_file,
        ) {
            // P26-A: lookup used to run before dispatch's trailing-slash
            // static-file rejection, so a persisted pre-fix 200 bypassed the
            // new 404. Dynamic PATH_INFO and DirectoryIndex targets have a
            // different representation path and remain eligible.
            cache_scope = None;
        }
    }
    if let Some(cache_ctx) = &cache_scope {
        if let Some(resp) = crate::cache::lookup(
            cfg,
            vhost,
            req,
            host,
            &cache_ctx.path,
            &cache_ctx.scope,
            peer.ip(),
            &cache_ctx.grant,
            &cache_ctx.key,
            &cache_ctx.target,
        ) {
            return resp;
        }
    }
    let mut resp = dispatch_inner(
        cfg,
        req,
        peer,
        local_ip,
        local_port,
        vhost,
        &server_name_for_cache,
        initial_plan,
    );
    if resp.has_prepared_handler() {
        let finalize = resp
            .take_prepared_handler()
            .expect("prepared dispatch response retained its handler");
        let finalizer = PreparedHandler::FinalizeDispatch {
            handler: Box::new(finalize),
            vhost_index: selected_vhost_index(cfg, vhost),
            cache: cache_scope.map(Box::new),
            host: host.to_string(),
            peer: peer.ip(),
            invalidation_path: invalidation_path.as_deref().unwrap_or(&path).to_string(),
        };
        resp = Response::prepared_handler(finalizer);
    } else {
        if let Some(cache_ctx) = cache_scope {
            crate::cache::store(
                cfg,
                vhost,
                req,
                host,
                &cache_ctx.path,
                &cache_ctx.scope,
                peer.ip(),
                &mut resp,
                &cache_ctx.grant,
                &cache_ctx.key,
                &cache_ctx.target,
            );
        }
        let unsafe_method = !matches!(req.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE");
        if vapache_verified::cache_invalidation_status_admit(unsafe_method, resp.status) {
            crate::cache::invalidate(cfg, host, invalidation_path.as_deref().unwrap_or(&path));
        }
    }
    resp
}

/// Perform an internal subrequest (DirectoryIndex or a local ErrorDocument)
/// through the normal dispatcher so handlers, access rules and `.htaccess`
/// overrides are applied exactly as for a client request.
pub(crate) fn internal_dispatch(
    cfg: &Config,
    req: &Request,
    url: &str,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
) -> Response {
    let mut internal = req.clone();
    let mut target = url.as_bytes().to_vec();
    if !internal.query.is_empty() {
        target.push(b'?');
        target.extend_from_slice(&internal.query);
    }
    internal.target = target;
    internal.raw_path = url.as_bytes().to_vec();
    internal.clear_body_for_internal_subrequest();
    internal.framing = crate::verified::BodyFraming::None;
    internal.expect_continue = false;
    internal.headers.remove("content-length");
    internal.headers.remove("transfer-encoding");
    internal.headers.remove("expect");
    let host = host_header(&internal).unwrap_or("");
    let vhost = cfg.select_vhost(
        local_ip.parse().ok(),
        local_port,
        if host.is_empty() { None } else { Some(host) },
    );
    let server_name = server_name_for(cfg, &internal, local_ip, local_port);
    dispatch_inner(
        cfg,
        &internal,
        peer,
        local_ip,
        local_port,
        vhost,
        &server_name,
        None,
    )
}

/// Evaluate the full configuration/access-file scope for one filesystem and
/// URL path.  Used by the upgrade path and after a rewrite selects a different
/// filesystem target, so both see the same policy as ordinary dispatch.
fn evaluate_scope_for_path(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    url_path: &str,
    req: &Request,
    peer: IpAddr,
    mapping_root: &Path,
) -> Result<
    (
        Scope,
        Vec<crate::config::ScopeRule>,
        Vec<crate::config::ScopeRule>,
    ),
    String,
> {
    let evaluated = evaluate_scope_identities_for_path(
        cfg,
        vhost,
        fs_path,
        None,
        url_path,
        req,
        peer,
        mapping_root,
    )?;
    Ok((
        evaluated.scope,
        evaluated.config_conditionals,
        evaluated.htaccess_conditionals,
    ))
}

struct PathScopeIdentities {
    scope: Scope,
    config_conditionals: Vec<crate::config::ScopeRule>,
    htaccess_conditionals: Vec<crate::config::ScopeRule>,
    handler_scope: Option<crate::request_plan::EvaluatedScope>,
}

/// Evaluate canonical authorization and optional lexical handler identities
/// from one immutable RequestPlan.  In particular, both views consume the
/// same parsed access-file layers, avoiding a second filesystem/config walk
/// between authorization and handler selection.
#[allow(clippy::too_many_arguments)]
fn evaluate_scope_identities_for_path(
    cfg: &Config,
    vhost: Option<&VHost>,
    fs_path: &Path,
    lexical_handler_path: Option<&Path>,
    url_path: &str,
    req: &Request,
    peer: IpAddr,
    mapping_root: &Path,
) -> Result<PathScopeIdentities, String> {
    let target = CanonicalTarget::from_url_path(url_path)
        .ok_or_else(|| format!("invalid canonical URL path '{url_path}'"))?;
    let plan = RequestPlan::from_fs_target_for_request(
        cfg,
        vhost,
        target,
        mapping_root.to_path_buf(),
        fs_path.to_path_buf(),
        false,
        req,
    )
    .map_err(|error| match error {
        // from_fs_target() never performs URL mapping, so only AccessFiles
        // can occur here.
        crate::request_plan::PlanError::Unmapped => "target has no URL mapping".to_string(), // coverage:ignore-line
        crate::request_plan::PlanError::AccessFiles(e)
        | crate::request_plan::PlanError::PolicyLimit(e) => e,
    })?;
    let evaluated = plan.evaluate_scope(cfg, vhost, req, peer);
    let handler_scope = lexical_handler_path.map(|lexical_path| {
        let file_name = lexical_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        plan.evaluate_scope_with_file_name(cfg, vhost, req, peer, &file_name)
    });
    Ok(PathScopeIdentities {
        scope: evaluated.scope,
        config_conditionals: (*evaluated.config_conditionals).clone(),
        htaccess_conditionals: (*evaluated.access_conditionals).clone(),
        handler_scope,
    })
}

fn replace_handler_policy(target: &mut Scope, lexical: &Scope) {
    target.mapping_policy.handlers = lexical.mapping_policy.handlers.clone();
    target.mapping_policy.set_handler = lexical.mapping_policy.set_handler.clone();
}

/// Re-authorize a resolved file/directory target and bind the grant to the
/// opened inode.  If the descriptor resolves to a different path (symlink),
/// re-evaluate Directory/Files/.htaccess policy for that path before binding.
#[allow(clippy::too_many_arguments)]
fn bind_target_grant(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    grant: &access::AccessGrant,
    fs_path: &Path,
    actual_path: &Path,
    mapping_root: &Path,
    meta: &std::fs::Metadata,
    url_path: &str,
    req: &Request,
    peer: IpAddr,
    local_port: u16,
    server_name: &str,
    local_ip: &str,
    rewrite_effects: &crate::rewrite::Effects,
) -> Result<(access::AccessGrant, access::ResourceKey, Scope), Response> {
    if actual_path == fs_path {
        let mut key = access::ResourceKey::request(vhost, req, url_path, Some(actual_path), None);
        key.identity = grant.key().identity.clone();
        return match grant.bind_file(&key, meta) {
            Some(bound) => {
                let key = bound.key().clone();
                Ok((bound, key, scope.clone()))
            }
            None => Err(error_response(
                cfg,
                vhost,
                scope,
                500,
                req,
                url_path,
                local_port,
                server_name,
                peer,
                local_ip,
            )),
        };
    }

    let evaluated = match evaluate_scope_identities_for_path(
        cfg,
        vhost,
        actual_path,
        Some(fs_path),
        url_path,
        req,
        peer,
        mapping_root,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vapached: target scope error: {e}");
            return Err(error_response(
                cfg,
                vhost,
                scope,
                500,
                req,
                url_path,
                local_port,
                server_name,
                peer,
                local_ip,
            ));
        }
    };
    let mut target_scope = evaluated.scope;
    let config_conditionals = evaluated.config_conditionals;
    let htaccess_conditionals = evaluated.htaccess_conditionals;
    apply_rewrite_effects(&mut target_scope, rewrite_effects);
    apply_scope_conditionals(
        cfg,
        vhost,
        &mut target_scope,
        &config_conditionals,
        &htaccess_conditionals,
        actual_path,
        url_path,
        req,
        peer,
    );
    let mut handler_scope = evaluated
        .handler_scope
        .expect("resolved target evaluation requested a lexical handler identity");
    apply_rewrite_effects(&mut handler_scope.scope, rewrite_effects);
    let lexical_name = fs_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    crate::request_plan::apply_conditionals_with_file_name(
        cfg,
        vhost,
        &mut handler_scope.scope,
        &handler_scope.config_conditionals,
        &handler_scope.access_conditionals,
        actual_path,
        url_path,
        req,
        peer,
        &lexical_name,
    );
    replace_handler_policy(&mut target_scope, &handler_scope.scope);
    debug_assert!(vapache_verified::handler_scope_lexical_admit(
        actual_path != fs_path, // coverage:ignore-line -- assertion-only invariant input
        true,
    ));
    // The canonical target may add restrictions but it must never replace the
    // policy of the URL that selected it.  Apache keeps the URL-mapped
    // `<Directory>`/access-file execution policy across a symlink; replacing
    // the scope here let `Options -ExecCGI`, `-Indexes`, `RemoveHandler` and
    // `AllowOverride None` disappear (F60/I61).
    target_scope.restrict_with(scope);
    let mut key = access::ResourceKey::request(vhost, req, url_path, Some(actual_path), None);
    let target_grant = match helper_access_response(
        cfg,
        vhost,
        &target_scope,
        req,
        url_path,
        &actual_path,
        local_port,
        server_name,
        peer,
        local_ip,
        &mut key,
    ) {
        Ok(g) => g,
        Err(r) => return Err(r),
    };
    match target_grant.bind_file(&key, meta) {
        Some(bound) => {
            let key = bound.key().clone();
            Ok((bound, key, target_scope))
        }
        // coverage:ignore-start
        None => Err(error_response(
            cfg,
            vhost,
            scope,
            500,
            req,
            url_path,
            local_port,
            server_name,
            peer,
            local_ip,
        )),
        // coverage:ignore-stop
    }
}

/// Re-evaluate policy for a target selected by a transform (PATH_INFO split,
/// FastCGI script resolution, alias target).  The returned grant is bound to
/// the target path and, for CGIs, to the opened inode by the caller.
#[allow(clippy::too_many_arguments)]
fn authorize_resolved_target(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    peer: IpAddr,
    target_fs: &Path,
    target_url: &str,
    base_scope: &Scope,
    proxy_url: Option<&str>,
    mapping_root: &Path,
    local_port: u16,
    server_name: &str,
    local_ip: &str,
) -> Result<(access::AccessGrant, access::ResourceKey, Scope), Response> {
    let lexical_target_plan = match CanonicalTarget::from_url_path(target_url)
        .ok_or_else(|| format!("invalid canonical target URL '{target_url}'"))
        .and_then(|target| {
            RequestPlan::resolve_for_request(cfg, vhost, target, req)
                .map_err(|error| format!("target URL has no mapping: {error:?}"))
        }) {
        Ok(plan) => plan,
        // coverage:ignore-start
        Err(e) => {
            eprintln!("vapached: target URL scope error: {e}");
            return Err(error_response(
                cfg,
                vhost,
                &cfg.global,
                500,
                req,
                target_url,
                local_port,
                server_name,
                peer,
                local_ip,
            ));
        } // coverage:ignore-stop
    };
    let lexical_differs = lexical_target_plan.fs_path() != target_fs;
    let evaluated = match evaluate_scope_identities_for_path(
        cfg,
        vhost,
        target_fs,
        lexical_differs.then_some(lexical_target_plan.fs_path()),
        target_url,
        req,
        peer,
        mapping_root,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vapached: target scope error: {e}");
            return Err(error_response(
                cfg,
                vhost,
                &cfg.global,
                500,
                req,
                target_url,
                local_port,
                server_name,
                peer,
                local_ip,
            ));
        }
    };
    let mut target_scope = evaluated.scope;
    let config_conditionals = evaluated.config_conditionals;
    let htaccess_conditionals = evaluated.htaccess_conditionals;
    apply_scope_conditionals(
        cfg,
        vhost,
        &mut target_scope,
        &config_conditionals,
        &htaccess_conditionals,
        target_fs,
        target_url,
        req,
        peer,
    );
    if let Some(mut handler_scope) = evaluated.handler_scope {
        let lexical_name = lexical_target_plan
            .fs_path()
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        crate::request_plan::apply_conditionals_with_file_name(
            cfg,
            vhost,
            &mut handler_scope.scope,
            &handler_scope.config_conditionals,
            &handler_scope.access_conditionals,
            target_fs,
            target_url,
            req,
            peer,
            &lexical_name,
        );
        replace_handler_policy(&mut target_scope, &handler_scope.scope);
        debug_assert!(vapache_verified::handler_scope_lexical_admit(
            lexical_differs, // coverage:ignore-line -- assertion-only invariant input
            true,
        ));
    }
    // A transform-selected target (PATH_INFO, FastCGI, DirectorySlash, alias
    // target) has a lexical target URL and a canonical filesystem target.
    // Meet those two identities, then retain the original request URL's
    // non-handler policy (the selected target may legitimately use a different
    // filename extension, so its handler map comes from the target URL)
    // (F60/I61).
    let lexical_target_scope = lexical_target_plan.effective_scope(cfg, vhost, req, peer);
    target_scope.restrict_with(&lexical_target_scope);
    target_scope.restrict_policy_with(base_scope);
    let mut key = access::ResourceKey::request(vhost, req, target_url, Some(target_fs), proxy_url);
    let grant = helper_access_response(
        cfg,
        vhost,
        &target_scope,
        req,
        target_url,
        &target_fs,
        local_port,
        server_name,
        peer,
        local_ip,
        &mut key,
    )?;
    Ok((grant, key, target_scope))
}

fn apply_scope_conditionals(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &mut Scope,
    config_conditionals: &[crate::config::ScopeRule],
    htaccess_conditionals: &[crate::config::ScopeRule],
    fs_path: &Path,
    url_path: &str,
    req: &Request,
    peer: IpAddr,
) {
    crate::request_plan::apply_conditionals(
        cfg,
        vhost,
        scope,
        config_conditionals,
        htaccess_conditionals,
        fs_path,
        url_path,
        req,
        peer,
    );
}

/// Enforce the original URL's access policy against an already-evaluated
/// scope.  The scope still came from the same dispatcher and the same
/// access-file/config identities; this only avoids recomputing it when the
/// rewrite did not change the request environment.
#[allow(clippy::too_many_arguments)]
fn authorize_original_scope(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    url_path: &str,
    fs_path: &Path,
    local_port: u16,
    server_name: &str,
    peer: SocketAddr,
    local_ip: &str,
    scope: &Scope,
) -> Result<(), Response> {
    let mut original_resource =
        access::ResourceKey::request(vhost, req, url_path, Some(fs_path), None);
    helper_access_response(
        cfg,
        vhost,
        scope,
        req,
        url_path,
        fs_path,
        local_port,
        server_name,
        peer.ip(),
        local_ip,
        &mut original_resource,
    )
    .map(|_| ())
}

/// Re-authorize the URL the client actually requested after an internal
/// rewrite changed the target.  Apache keeps `<Location>`/`<LocationMatch>`
/// policy for the original URL across internal rewrites, including when the
/// rewrite chain ends in a proxy or redirect rather than a static file.
#[allow(clippy::too_many_arguments)]
fn authorize_original_request(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    url_path: &str,
    fs_path: &Path,
    mapping_root: &Path,
    local_port: u16,
    server_name: &str,
    peer: SocketAddr,
    local_ip: &str,
    rewrite_effects: &crate::rewrite::Effects,
) -> Result<Scope, Response> {
    let (mut original_scope, config_conditionals, htaccess_conditionals) =
        match evaluate_scope_for_path(cfg, vhost, fs_path, url_path, req, peer.ip(), mapping_root) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("vapached: original URL scope error after rewrite: {e}");
                return Err(error_response(
                    cfg,
                    vhost,
                    &cfg.global,
                    500,
                    req,
                    url_path,
                    local_port,
                    server_name,
                    peer.ip(),
                    local_ip,
                ));
            }
        };
    // Rewrite `[E=...]` effects apply before authorization.  The original URL
    // gate must see the same environment as the final target scope; otherwise
    // an original-URL `Require expr`/`SetEnvIf` rule can be bypassed by a
    // rewrite that changes the environment.
    apply_rewrite_effects(&mut original_scope, rewrite_effects);
    apply_scope_conditionals(
        cfg,
        vhost,
        &mut original_scope,
        &config_conditionals,
        &htaccess_conditionals,
        fs_path,
        url_path,
        req,
        peer.ip(),
    );
    authorize_original_scope(
        cfg,
        vhost,
        req,
        url_path,
        fs_path,
        local_port,
        server_name,
        peer,
        local_ip,
        &original_scope,
    )?;
    Ok(original_scope)
}

fn dispatch_inner(
    cfg: &Config,
    req: &Request,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    vhost: Option<&VHost>,
    server_name: &str,
    initial_plan: Option<RequestPlan>,
) -> Response {
    if cfg.capability_audit_only {
        return Response::new(500);
    }
    // Methods we do not implement at all are 501, matching Apache.  Known
    // methods that are invalid for a particular resource (for example POST
    // to a static file) are handled below with 405.
    const KNOWN_METHODS: &[&str] = &[
        "GET", "HEAD", "POST", "OPTIONS", "TRACE", "PUT", "DELETE", "CONNECT", "PATCH",
    ];
    if !KNOWN_METHODS.contains(&req.method.as_str()) {
        let mut r = error_response(
            cfg,
            vhost,
            &vhost.map(|v| &v.scope).unwrap_or(&cfg.global),
            501,
            req,
            &String::from_utf8_lossy(&req.raw_path),
            local_port,
            &server_name,
            peer.ip(),
            local_ip,
        );
        r.headers
            .push(("Allow".into(), allow_header(cfg).into_bytes()));
        return r;
    }

    // RFC 9112 permits the asterisk-form request target only for OPTIONS.
    // Mapping it to `/` for GET/HEAD would serve the root resource under a
    // request-target spelling that URL policy never sees.
    if req.raw_path == b"*" && req.method != "OPTIONS" {
        return error_response(
            cfg,
            vhost,
            &vhost.map(|v| &v.scope).unwrap_or(&cfg.global),
            400,
            req,
            "*",
            local_port,
            server_name,
            peer.ip(),
            local_ip,
        );
    }

    if req.method == "TRACE" {
        if !vapache_verified::capability_admit(cfg.capability_enabled(Capability::Trace), true)
            || !cfg.trace_enable
        {
            let mut r = error_response(
                cfg,
                vhost,
                &vhost.map(|v| &v.scope).unwrap_or(&cfg.global),
                405,
                req,
                &String::from_utf8_lossy(&req.raw_path),
                local_port,
                &server_name,
                peer.ip(),
                local_ip,
            );
            r.headers
                .push(("Allow".into(), allow_header(cfg).into_bytes()));
            return r;
        }
        let mut body = format!("TRACE / {} HTTP/1.1\r\n", req.method);
        for (n, v) in req.headers.iter() {
            body.push_str(&format!("{}: {}\r\n", n, String::from_utf8_lossy(v)));
        }
        body.push_str("\r\n");
        return Response::bytes(200, "message/http", body.into_bytes());
    }

    let base_scope = vhost.map(|v| &v.scope).unwrap_or(&cfg.global);

    // `OPTIONS *` is server-wide and does not resolve a path.  Resource
    // OPTIONS requests continue through access control and path mapping so
    // they cannot bypass a Require rule or report the wrong media type.
    if req.method == "OPTIONS" && req.raw_path == b"*" {
        return options_response(cfg, base_scope, None);
    }

    // Build one immutable request plan and reuse it for cache and dispatch.
    // The initial plan was already built by `dispatch_inner_request` when the
    // outer request was cacheable; internal subrequests build it here.
    let allow_encoded = cfg.encoded_slashes == EncodedSlashes::On;
    let plan = match initial_plan {
        Some(plan) => plan,
        None => {
            let target = match CanonicalTarget::from_request(req, allow_encoded) {
                Ok(target) => target,
                Err(error) => {
                    return error_response(
                        cfg,
                        vhost,
                        base_scope,
                        error.status(),
                        req,
                        &String::from_utf8_lossy(&req.raw_path),
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    )
                }
            };
            match RequestPlan::resolve_for_request(cfg, vhost, target, req) {
                Ok(plan) => plan,
                Err(crate::request_plan::PlanError::Unmapped) => {
                    return error_response(
                        cfg,
                        vhost,
                        base_scope,
                        404,
                        req,
                        &String::from_utf8_lossy(&req.raw_path),
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    )
                }
                Err(crate::request_plan::PlanError::AccessFiles(e)) => {
                    eprintln!("vapached: .htaccess error: {e}");
                    return error_response(
                        cfg,
                        vhost,
                        base_scope,
                        500,
                        req,
                        &String::from_utf8_lossy(&req.raw_path),
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                }
                Err(crate::request_plan::PlanError::PolicyLimit(e)) => {
                    eprintln!("vapached: request policy path limit: {e}");
                    return error_response(
                        cfg,
                        vhost,
                        base_scope,
                        414,
                        req,
                        &String::from_utf8_lossy(&req.raw_path),
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                }
            }
        }
    };
    let original_req = req;
    let original_url_path = plan.url_path().to_string();
    let original_root = plan.root().to_path_buf();
    let original_fs_path = plan.fs_path().to_path_buf();

    // Rewrites may change the URL, so resolve the target and its override
    // scope first, then restart resolution with the rewritten path.  A hard
    // limit prevents pathological rewrite loops from consuming a worker.
    let mut owned_req: Option<Request> = None;
    let mut plan = plan;
    let mut norm = plan.target().norm.clone();
    let mut url_path = original_url_path.clone();
    let mut rewrite_rounds = 0usize;
    let mut stop_rewriting = false;
    let mut rewrite_effects = crate::rewrite::Effects::default();
    let mut rewrite_filesystem: Option<PathBuf> = None;
    // The first loop iteration evaluates the original URL with no rewrite
    // effects.  If a later internal rewrite leaves the environment and query
    // unchanged, that exact scope can authorize the original URL again instead
    // of rebuilding the same plan and access-file layers from disk.
    let mut original_scope_snapshot: Option<Scope> = None;
    let https = crate::expr::request_is_https();
    let (mut root, mut rel, mut script_alias);
    let mut fs_path;
    let mut scope;
    loop {
        root = plan.root().to_path_buf();
        rel = plan.rel().to_path_buf();
        script_alias = plan.script_alias();
        fs_path = plan.fs_path().to_path_buf();
        // After a rewrite has changed the query, the target scope must be
        // evaluated with the rewritten request context.  The original URL is
        // still reauthorized separately with `original_req`.
        let current_req = owned_req.as_ref().unwrap_or(req);
        let mut evaluated = plan.evaluate_scope(cfg, vhost, current_req, peer.ip());
        apply_rewrite_effects(&mut evaluated.scope, &rewrite_effects);
        evaluated.apply_conditionals(cfg, vhost, &fs_path, &url_path, current_req, peer.ip());
        scope = evaluated.scope;
        if stop_rewriting {
            break;
        }
        let current_req = owned_req.as_ref().unwrap_or(req);
        let rewrite_ctx = crate::rewrite::Context::for_plan(
            &plan,
            &cfg.server_root,
            &current_req.query,
            peer.ip(),
            local_port,
            https,
            &server_name,
        );
        match crate::rewrite::process(&scope, current_req, &rewrite_ctx) {
            crate::rewrite::Outcome::None => break,
            crate::rewrite::Outcome::Forbidden => {
                return error_response(
                    cfg,
                    vhost,
                    &scope,
                    403,
                    current_req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                )
            }
            crate::rewrite::Outcome::Gone => {
                return error_response(
                    cfg,
                    vhost,
                    &scope,
                    410,
                    current_req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                )
            }
            crate::rewrite::Outcome::Error(e) => {
                eprintln!("vapached: rewrite error: {e}");
                return error_response(
                    cfg,
                    vhost,
                    &scope,
                    500,
                    current_req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                );
            }
            crate::rewrite::Outcome::Proxy { url, effects } => {
                apply_rewrite_effects(&mut scope, &effects);
                let (url_path_part, query) = match url.split_once('?') {
                    Some((path, query)) => (path, query),
                    None => (url.as_str(), ""),
                };
                let Some(target) = proxy::target_from_url(cfg, &scope, url_path_part, current_req)
                else {
                    return error_response(
                        cfg,
                        vhost,
                        &scope,
                        502,
                        current_req,
                        &url_path,
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                };
                let mut proxy_urls = vec![target.proxy_url.as_str()];
                if let Some(logical) = target.logical_url.as_deref() {
                    proxy_urls.push(logical);
                }
                cfg.apply_proxy_access_urls(
                    vhost,
                    &mut scope,
                    &proxy_urls,
                    current_req,
                    peer.ip(),
                    &url_path,
                );
                if let Some(r) = helper_method_not_allowed(
                    cfg,
                    vhost,
                    &scope,
                    current_req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                ) {
                    return r;
                }
                let mut resource = access::ResourceKey::request(
                    vhost,
                    current_req,
                    &url_path,
                    None,
                    Some(target.proxy_url.as_str()),
                );
                let _grant = match helper_access_response(
                    cfg,
                    vhost,
                    &scope,
                    current_req,
                    &url_path,
                    &original_fs_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                    &mut resource,
                ) {
                    Ok(grant) => grant,
                    Err(r) => return r,
                };
                // A terminal proxy outcome returns before the post-loop
                // original-URL check.  Enforce the original URL policy here
                // as well; otherwise `/admin -> /front -> [P]` bypasses
                // `<Location "/admin">`.
                if original_url_path != url_path
                    || original_fs_path != fs_path
                    || original_req.query != current_req.query
                    || !rewrite_effects.is_empty()
                {
                    let reusable = rewrite_effects.is_empty()
                        && current_req.query == original_req.query
                        && original_scope_snapshot.is_some();
                    if reusable {
                        let original_scope =
                            original_scope_snapshot.as_ref().expect("checked above");
                        if let Err(r) = authorize_original_scope(
                            cfg,
                            vhost,
                            original_req,
                            &original_url_path,
                            &original_fs_path,
                            local_port,
                            &server_name,
                            peer,
                            local_ip,
                            original_scope,
                        ) {
                            return r; // coverage:ignore-line - filesystem race
                        }
                    } else if let Err(r) = authorize_original_request(
                        cfg,
                        vhost,
                        original_req,
                        &original_url_path,
                        &original_fs_path,
                        &original_root,
                        local_port,
                        &server_name,
                        peer,
                        local_ip,
                        &rewrite_effects,
                    ) {
                        // The original scope was already evaluated before
                        // rewrite processing; only a concurrent access-file
                        // mutation can make this second evaluation fail.
                        return r; // coverage:ignore-line - filesystem race
                    }
                }
                if current_req.handler_probe() {
                    return Response::prepared_handler(PreparedHandler::Proxy {
                        vhost_index: selected_vhost_index(cfg, vhost),
                        scope,
                        target,
                        peer,
                        local_port,
                        https,
                        server_name: server_name.to_string(),
                        local_ip: local_ip.to_string(),
                        grant: _grant,
                        resource,
                        url_path: url_path_part.to_string(),
                        query_override: Some(query.as_bytes().to_vec()),
                    });
                }
                let mut proxy_req = current_req.clone();
                proxy_req.query = query.as_bytes().to_vec();
                return proxy::execute(
                    cfg,
                    vhost,
                    &scope,
                    &proxy_req,
                    url_path_part,
                    &target,
                    peer,
                    local_port,
                    https,
                    &server_name,
                    local_ip,
                    &_grant,
                    &resource,
                );
            }
            crate::rewrite::Outcome::Redirect {
                status,
                location,
                effects,
            } => {
                rewrite_effects.merge(effects);
                apply_rewrite_effects(&mut scope, &rewrite_effects);
                // A positive redirect is also a terminal outcome.  Do not let
                // it escape the original URL's authorization after a rewrite.
                if status < 400
                    && (original_url_path != url_path
                        || original_fs_path != fs_path
                        || original_req.query != current_req.query
                        || !rewrite_effects.is_empty())
                {
                    let reusable = rewrite_effects.is_empty()
                        && current_req.query == original_req.query
                        && original_scope_snapshot.is_some();
                    if reusable {
                        let original_scope =
                            original_scope_snapshot.as_ref().expect("checked above");
                        if let Err(r) = authorize_original_scope(
                            cfg,
                            vhost,
                            original_req,
                            &original_url_path,
                            &original_fs_path,
                            local_port,
                            &server_name,
                            peer,
                            local_ip,
                            original_scope,
                        ) {
                            return r; // coverage:ignore-line - filesystem race
                        }
                    } else if let Err(r) = authorize_original_request(
                        cfg,
                        vhost,
                        original_req,
                        &original_url_path,
                        &original_fs_path,
                        &original_root,
                        local_port,
                        &server_name,
                        peer,
                        local_ip,
                        &rewrite_effects,
                    ) {
                        // The original scope was already evaluated before
                        // rewrite processing; only a concurrent access-file
                        // mutation can make this second evaluation fail.
                        return r; // coverage:ignore-line - filesystem race
                    }
                }
                let location = if location.starts_with("//") {
                    format!("{}:{}", if https { "https" } else { "http" }, location)
                } else if location.starts_with('/') {
                    absolute_url_scheme(
                        cfg,
                        vhost,
                        current_req,
                        &location,
                        &server_name,
                        local_port,
                        https,
                    )
                } else {
                    location
                };
                let mut r = simple_html(
                    status,
                    &format!("The document has moved to {location}"),
                    Some(&location),
                );
                if current_req.method == "HEAD" {
                    r.body = Body::Empty;
                }
                if scope
                    .header_policy
                    .apply(&mut r.headers, r.status < 400)
                    .is_err()
                {
                    return Response::policy_error();
                }
                crate::compression::finalize_budgeted(
                    &scope,
                    current_req,
                    &mut r,
                    url_path.as_bytes(),
                    &cfg.resource_budget,
                );
                return r;
            }
            crate::rewrite::Outcome::Internal {
                path,
                query,
                final_pass,
                effects,
                filesystem,
            } => {
                // The filesystem override is per-round: a later round without
                // a file target must clear the earlier round's target so only
                // the final round's filesystem selection can be applied (F68).
                let round_effects_empty = effects.is_empty();
                rewrite_filesystem = filesystem;
                rewrite_effects.merge(effects);
                rewrite_rounds += 1;
                if rewrite_rounds > 10 {
                    return error_response(
                        cfg,
                        vhost,
                        &scope,
                        500,
                        current_req,
                        &url_path,
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                }
                let Some(canonical) = canonicalize_rewrite_path(&path) else {
                    return error_response(
                        cfg,
                        vhost,
                        &scope,
                        400,
                        current_req,
                        &url_path,
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                };
                if canonical == url_path && query == current_req.query {
                    break;
                }
                if original_scope_snapshot.is_none()
                    && round_effects_empty
                    && rewrite_effects.is_empty()
                    && url_path == original_url_path
                    && fs_path == original_fs_path
                    && current_req.query == original_req.query
                {
                    // This is still the first round and no `[E=...]` effect or
                    // query mutation has changed the environment.  Reuse the
                    // exact scope already used for rewrite selection instead
                    // of walking the same configuration and access files again
                    // after the loop.
                    original_scope_snapshot = Some(std::mem::take(&mut scope));
                }
                if query != current_req.query {
                    let mut r = current_req.clone();
                    r.query = query;
                    owned_req = Some(r);
                }
                url_path = canonical;
                norm = url_path.as_bytes().to_vec();
                // Rebuild the immutable plan for the rewritten URL.  The next
                // loop iteration must use the same mapping/layer identities
                // that dispatch will authorize and serve.
                let target = CanonicalTarget::from_normalized(norm.clone(), url_path.clone());
                plan = match RequestPlan::resolve_for_request(
                    cfg,
                    vhost,
                    target,
                    owned_req.as_ref().unwrap_or(req),
                ) {
                    Ok(plan) => plan,
                    Err(crate::request_plan::PlanError::Unmapped) => {
                        return error_response(
                            cfg,
                            vhost,
                            base_scope,
                            404,
                            owned_req.as_ref().unwrap_or(req),
                            &url_path,
                            local_port,
                            &server_name,
                            peer.ip(),
                            local_ip,
                        )
                    }
                    Err(crate::request_plan::PlanError::AccessFiles(e)) => {
                        eprintln!("vapached: .htaccess error: {e}");
                        return error_response(
                            cfg,
                            vhost,
                            base_scope,
                            500,
                            owned_req.as_ref().unwrap_or(req),
                            &url_path,
                            local_port,
                            &server_name,
                            peer.ip(),
                            local_ip,
                        );
                    }
                    Err(crate::request_plan::PlanError::PolicyLimit(e)) => {
                        eprintln!("vapached: rewritten policy path limit: {e}");
                        return error_response(
                            cfg,
                            vhost,
                            base_scope,
                            414,
                            owned_req.as_ref().unwrap_or(req),
                            &url_path,
                            local_port,
                            &server_name,
                            peer.ip(),
                            local_ip,
                        );
                    }
                };
                stop_rewriting = final_pass;
            }
        }
    }
    let req: &Request = owned_req.as_ref().unwrap_or(req);
    apply_rewrite_effects(&mut scope, &rewrite_effects);
    if let Some(filesystem) = rewrite_filesystem {
        root = filesystem
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        rel = PathBuf::from(
            filesystem
                .file_name()
                .map(|n| n.to_os_string())
                .unwrap_or_default(),
        );
        fs_path = root.join(&rel);
        // The rewrite changed the filesystem target after the scope was
        // evaluated for the URL mapping.  Re-evaluate against the target so
        // <Directory>, <Files> and target .htaccess policy cannot be skipped.
        match evaluate_scope_for_path(cfg, vhost, &fs_path, &url_path, req, peer.ip(), &root) {
            Ok((mut target_scope, config_conditionals, htaccess_conditionals)) => {
                apply_rewrite_effects(&mut target_scope, &rewrite_effects);
                apply_scope_conditionals(
                    cfg,
                    vhost,
                    &mut target_scope,
                    &config_conditionals,
                    &htaccess_conditionals,
                    &fs_path,
                    &url_path,
                    req,
                    peer.ip(),
                );
                // A rewrite-selected filesystem target has the same two
                // identities as a symlink target: the rewritten URL scope and
                // the canonical file scope.  Meet them instead of replacing
                // the URL policy (F60/I61).
                target_scope.restrict_with(&scope);
                scope = target_scope;
            }
            Err(e) => {
                eprintln!("vapached: target scope error after rewrite: {e}");
                return error_response(
                    cfg,
                    vhost,
                    &scope,
                    500,
                    req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                );
            }
        }
    }

    // An internal rewrite must not erase authorization attached to the URL the
    // client actually requested.  Apache keeps `<Location>`/`<LocationMatch>`
    // policy for the original URL across internal rewrites; require both the
    // original URL scope and the final target scope to allow the request.
    if original_url_path != url_path
        || original_fs_path != fs_path
        || original_req.query != req.query
        || !rewrite_effects.is_empty()
    {
        let snapshot = if rewrite_effects.is_empty() && req.query == original_req.query {
            original_scope_snapshot.take()
        } else {
            None
        };
        let original_scope = if let Some(original_scope) = snapshot {
            if let Err(r) = authorize_original_scope(
                cfg,
                vhost,
                original_req,
                &original_url_path,
                &original_fs_path,
                local_port,
                &server_name,
                peer,
                local_ip,
                &original_scope,
            ) {
                return r; // coverage:ignore-line - filesystem race
            }
            original_scope
        } else {
            match authorize_original_request(
                cfg,
                vhost,
                original_req,
                &original_url_path,
                &original_fs_path,
                &original_root,
                local_port,
                &server_name,
                peer,
                local_ip,
                &rewrite_effects,
            ) {
                Ok(scope) => scope,
                // The original scope was successfully evaluated before rewrite;
                // this can differ only if an access file changes concurrently.
                Err(r) => return r, // coverage:ignore-line - filesystem race
            }
        };
        // An internal rewrite may change the URL, but it must not launder the
        // original URL's execution/listing policy.  Conjoin policy (not the
        // handler map, because the rewrite may legitimately select a new
        // extension) with the final target scope; the target bind later meets
        // the canonical scope too (F60/I61).
        scope.restrict_policy_with(&original_scope);
    }

    // Redirects are evaluated after rewrites but before access control and
    // filesystem mapping, matching Apache's URL translation order.
    if let Some((red, loc)) = match_redirect(&scope, &url_path, Some(req)) {
        let loc = if loc.is_empty() {
            String::new()
        } else if loc.starts_with('/') {
            absolute_url_scheme(cfg, vhost, req, &loc, &server_name, local_port, https)
        } else {
            loc
        };
        let mut r = if loc.is_empty() {
            simple_html(red.status, "", None)
        } else {
            simple_html(
                red.status,
                &format!("The document has moved to {loc}"),
                Some(&loc),
            )
        };
        if req.method == "HEAD" {
            r.body = Body::Empty;
        }
        if scope
            .header_policy
            .apply(&mut r.headers, r.status < 400)
            .is_err()
        {
            return Response::policy_error();
        }
        crate::compression::finalize_budgeted(
            &scope,
            req,
            &mut r,
            url_path.as_bytes(),
            &cfg.resource_budget,
        );
        return r;
    }
    if req.policy_budget_failed() {
        return Response::policy_error();
    }

    let proxy_target = proxy::match_target_req(cfg, &scope, &url_path, Some(req));
    if req.policy_budget_failed() {
        return Response::policy_error();
    }
    let fastcgi_target = fastcgi::match_proxy_for_request(&scope, &url_path, &root, req);
    if req.policy_budget_failed() {
        return Response::policy_error();
    }
    // Apache resolves prefix and regex proxy routes in configuration order.
    // Selecting FastCGI first regardless of order lets a regex PHP route
    // capture a URL that an earlier `ProxyPass` sends to an upstream gateway.
    let fastcgi_wins = match (&fastcgi_target, &proxy_target) {
        (Some(f), Some(p)) => f.route_order < p.route_order,
        (Some(_), None) => true,
        _ => false,
    };
    // Only the selected route's proxy identity participates in `<Proxy>`
    // authorization; a losing later route must not deny it.
    let mut selected_proxy_urls: Vec<String> = Vec::new();
    if fastcgi_wins {
        if let Some(logical) = fastcgi_target
            .as_ref()
            .and_then(|target| target.logical_url.as_deref())
        {
            cfg.apply_proxy_access_urls(vhost, &mut scope, &[logical], req, peer.ip(), &url_path);
        }
        if let Some(target) = &fastcgi_target {
            if let Some(logical) = &target.logical_url {
                selected_proxy_urls.push(logical.clone());
            }
        }
    } else if let Some(target) = &proxy_target {
        let mut proxy_urls = vec![target.proxy_url.as_str()];
        if let Some(logical) = target.logical_url.as_deref() {
            proxy_urls.push(logical);
        }
        cfg.apply_proxy_access_urls(vhost, &mut scope, &proxy_urls, req, peer.ip(), &url_path);
        selected_proxy_urls.push(target.proxy_url.clone());
        if let Some(logical) = &target.logical_url {
            selected_proxy_urls.push(logical.clone());
        }
    }

    let selected_proxy_route = fastcgi_wins || proxy_target.is_some();
    if selected_proxy_route {
        // Apache does not perform a per-directory access-file walk for a
        // ProxyPass/ProxyPassMatch request.  Keep the ordinary combined scope
        // for compatibility (an access file may still narrow access), but
        // independently require the configuration-only Directory/Files/
        // Location/If/Proxy scope to authorize the route.  Thus an access-file
        // grant can never erase an operator Location deny (P18-B2).
        let (mut operator_scope, operator_conditionals) =
            crate::policy_ref::effective_scope_req(cfg, vhost, &fs_path, &url_path, req, peer.ip());
        apply_rewrite_effects(&mut operator_scope, &rewrite_effects);
        crate::policy_ref::apply_conditionals(
            cfg,
            vhost,
            &mut operator_scope,
            &operator_conditionals,
            &fs_path,
            &url_path,
            req,
            peer.ip(),
        );
        let proxy_identities: Vec<&str> = selected_proxy_urls.iter().map(String::as_str).collect();
        cfg.apply_proxy_access_urls(
            vhost,
            &mut operator_scope,
            &proxy_identities,
            req,
            peer.ip(),
            &url_path,
        );
        if let Some(r) = helper_method_not_allowed(
            cfg,
            vhost,
            &operator_scope,
            req,
            &url_path,
            local_port,
            &server_name,
            peer.ip(),
            local_ip,
        ) {
            return r;
        }
        let mut operator_resource = access::ResourceKey::request(
            vhost,
            req,
            &url_path,
            Some(&fs_path),
            selected_proxy_urls.first().map(String::as_str),
        );
        let operator_access = helper_access_response(
            cfg,
            vhost,
            &operator_scope,
            req,
            &url_path,
            &fs_path,
            local_port,
            &server_name,
            peer.ip(),
            local_ip,
            &mut operator_resource,
        );
        if !vapache_verified::proxy_operator_acl_admit(true, operator_access.is_ok()) {
            return operator_access
                .err()
                .expect("verified proxy ACL rejection has an error response");
        }
    }

    if let Some(r) = helper_method_not_allowed(
        cfg,
        vhost,
        &scope,
        req,
        &url_path,
        local_port,
        &server_name,
        peer.ip(),
        local_ip,
    ) {
        return r;
    }
    let mut resource = access::ResourceKey::request(
        vhost,
        req,
        &url_path,
        Some(&fs_path),
        selected_proxy_urls.first().map(String::as_str),
    );
    let mut grant = match helper_access_response(
        cfg,
        vhost,
        &scope,
        req,
        &url_path,
        &fs_path,
        local_port,
        &server_name,
        peer.ip(),
        local_ip,
        &mut resource,
    ) {
        Ok(grant) => grant,
        Err(r) => return r,
    };

    // F64/I62: `SetHandler server-status` lives in the precedence field, not
    // in the extension table.  Consult the effective handler as well; either
    // source may select the status page.
    // F64/I62: `SetHandler server-status` lives in the precedence field, not
    // in the extension table.  Consult the effective handler as well; either
    // source may select the status page.
    let status_name: Vec<u8> = fs_path
        .file_name()
        .map(|n| n.as_encoded_bytes().to_vec())
        .unwrap_or_default();
    let status_forced = crate::config::effective_handler(&scope, &status_name)
        .is_some_and(|h| h.eq_ignore_ascii_case("server-status"));
    if status_forced
        || scope
            .mapping_policy
            .handlers
            .iter()
            .any(|h| h.handler.eq_ignore_ascii_case("server-status"))
    {
        if !vapache_verified::capability_admit(
            cfg.capability_enabled(Capability::ServerStatus),
            true,
        ) {
            return error_response(
                cfg,
                vhost,
                &scope,
                403,
                req,
                &url_path,
                local_port,
                &server_name,
                peer.ip(),
                local_ip,
            );
        }
        let auto = req.query.eq_ignore_ascii_case(b"auto");
        return crate::status::response(auto);
    }

    if fastcgi_wins {
        if let Some(target) = fastcgi_target {
            if req.handler_probe() {
                return Response::prepared_handler(PreparedHandler::FastCgi {
                    vhost_index: selected_vhost_index(cfg, vhost),
                    scope,
                    target,
                    peer,
                    local_port,
                    server_name: server_name.to_string(),
                    local_ip: local_ip.to_string(),
                    grant,
                    resource,
                    url_path: url_path.clone(),
                    mapping_root: root,
                });
            }
            return run_fastcgi(
                cfg,
                vhost,
                req,
                &url_path,
                &server_name,
                peer,
                local_ip,
                local_port,
                &scope,
                &target,
                &grant,
                &resource,
                &root,
            );
        }
    }

    if let Some(target) = proxy_target {
        if req.handler_probe() {
            return Response::prepared_handler(PreparedHandler::Proxy {
                vhost_index: selected_vhost_index(cfg, vhost),
                scope,
                target,
                peer,
                local_port,
                https,
                server_name: server_name.to_string(),
                local_ip: local_ip.to_string(),
                grant,
                resource,
                url_path: url_path.clone(),
                query_override: None,
            });
        }
        return proxy::execute(
            cfg,
            vhost,
            &scope,
            req,
            &url_path,
            &target,
            peer,
            local_port,
            https,
            &server_name,
            local_ip,
            &grant,
            &resource,
        );
    }
    if !fastcgi_wins
        && proxy_target.is_none()
        && proxy::balancer_unavailable(cfg, &scope, &url_path)
    {
        return error_response(
            cfg,
            vhost,
            &scope,
            503,
            req,
            &url_path,
            local_port,
            &server_name,
            peer.ip(),
            local_ip,
        );
    }

    let follow_symlinks = scope.effective_options().contains(Options::FOLLOW_SYMLINKS);
    let owner_match_only = !follow_symlinks
        && scope
            .effective_options()
            .contains(Options::SYMLINKS_IF_OWNER_MATCH);
    let follow = follow_symlinks || owner_match_only;

    match resolve_target_checked(&root, &rel, follow, owner_match_only) {
        Target::File { file, meta } => {
            // Re-authorize and bind the actual opened target before selecting
            // any handler.  A symlink must not inherit the lexical URL's
            // policy (F41/I39).
            let Some(actual_path) = crate::files::fd_path_cow(&file, &fs_path) else {
                return error_response(
                    cfg,
                    vhost,
                    &scope,
                    500,
                    req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                );
            };
            let (target_grant, target_resource, target_scope) = match bind_target_grant(
                cfg,
                vhost,
                &scope,
                &grant,
                &fs_path,
                actual_path.as_ref(),
                &root,
                &meta,
                &url_path,
                req,
                peer.ip(),
                local_port,
                &server_name,
                local_ip,
                &rewrite_effects,
            ) {
                Ok(v) => v,
                Err(r) => return r,
            };
            let scope = &target_scope;
            let grant = &target_grant;
            let resource = &target_resource;
            // Handler, MIME and dispatch decisions bind to the lexical
            // request-mapped filename (F69/I70): an in-root symlink whose
            // canonical target has a different basename (for example
            // `link.txt -> secret.cgi`) must keep the lexical extension for
            // handler and MIME classification.  Authorization and
            // containment still bind to the resolved target below.
            let name = fs_path
                .file_name()
                .or_else(|| actual_path.file_name())
                .or_else(|| rel.file_name())
                .map(|n| n.as_encoded_bytes())
                .unwrap_or(b"");
            let name_is_lexical = name
                == fs_path
                    .file_name()
                    .map(|n| n.as_encoded_bytes())
                    .unwrap_or(b"");
            debug_assert!(vapache_verified::handler_identity_lexical_admit(
                actual_path.as_ref() != fs_path.as_path(),
                name_is_lexical,
            ));
            let script_root = actual_path.parent().unwrap_or(root.as_path()).to_path_buf();
            let script_rel = actual_path
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_default();
            if req.method == "OPTIONS" {
                return options_response(cfg, scope, mime_type(cfg, scope, name));
            }
            let media_type = mime_type(cfg, scope, name);
            let mut unsupported_filters = scope.mapping_policy.unsupported_filters.clone();
            for filter in
                crate::compression::unsupported_filters(scope, media_type.as_deref(), name)
            {
                if !unsupported_filters
                    .iter()
                    .any(|known| known.eq_ignore_ascii_case(&filter))
                {
                    unsupported_filters.push(filter);
                }
            }
            if !unsupported_filters.is_empty() {
                eprintln!(
                    "vapached: unsupported output filter(s) {:?} for {}",
                    unsupported_filters, url_path
                );
                return error_response(
                    cfg,
                    vhost,
                    scope,
                    500,
                    req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                );
            }
            if let Some(target) = fastcgi::handler_target_for_file(
                scope,
                &root,
                &url_path,
                &fs_path,
                actual_path.as_ref(),
                name,
            ) {
                if req.handler_probe() {
                    return Response::prepared_handler(PreparedHandler::FastCgi {
                        vhost_index: selected_vhost_index(cfg, vhost),
                        scope: target_scope,
                        target,
                        peer,
                        local_port,
                        server_name: server_name.to_string(),
                        local_ip: local_ip.to_string(),
                        grant: target_grant,
                        resource: target_resource,
                        url_path: url_path.clone(),
                        mapping_root: root,
                    });
                }
                return run_fastcgi(
                    cfg,
                    vhost,
                    req,
                    &url_path,
                    &server_name,
                    peer,
                    local_ip,
                    local_port,
                    scope,
                    &target,
                    grant,
                    resource,
                    &root,
                );
            }
            if cgi::is_cgi(cfg, scope, name, script_alias) {
                if req.handler_probe() {
                    let descriptor_lease = match cfg.resource_budget.try_descriptor() {
                        Ok(lease) => lease,
                        Err(_) => return Response::memory_overload(),
                    };
                    return Response::prepared_handler(PreparedHandler::Cgi {
                        vhost_index: selected_vhost_index(cfg, vhost),
                        scope: target_scope,
                        peer,
                        local_port,
                        server_name: server_name.to_string(),
                        local_ip: local_ip.to_string(),
                        grant: target_grant,
                        resource: target_resource,
                        root: script_root,
                        script_rel,
                        url_path: url_path.clone(),
                        path_info: String::new(),
                        script_name: url_path.clone(),
                        script_file: file,
                        script_meta: meta,
                        _descriptor_lease: descriptor_lease,
                    });
                }
                return run_cgi(
                    cfg,
                    vhost,
                    req,
                    &script_root,
                    &script_rel,
                    &url_path,
                    "",
                    &url_path,
                    &server_name,
                    peer,
                    local_ip,
                    local_port,
                    scope,
                    grant,
                    resource,
                    Some(&file),
                    Some(&meta),
                );
            }
            if let Some(handler) = crate::config::effective_handler(scope, name) {
                let handler = handler.trim();
                if handler.eq_ignore_ascii_case("cgi-script") {
                    // The handler is configured but `Options ExecCGI` is off.
                    // Apache denies the request; a 500 here would not match,
                    // but never fall through to static source disclosure.
                    return error_response(
                        cfg,
                        vhost,
                        scope,
                        403,
                        req,
                        &url_path,
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                }
                if !handler.is_empty()
                    && !handler.eq_ignore_ascii_case("default-handler")
                    && !handler.eq_ignore_ascii_case("none")
                {
                    eprintln!(
                        "vapached: unsupported handler '{}' for {}",
                        handler, url_path
                    );
                    return error_response(
                        cfg,
                        vhost,
                        scope,
                        500,
                        req,
                        &url_path,
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                }
            }
            // A trailing slash asserts a directory-like target. Once all
            // real CGI/FastCGI handlers have had the opportunity to consume
            // PATH_INFO, never serve a regular file through that spelling:
            // URL-anchored authorization intentionally distinguishes
            // `/file` from `/file/`.
            if url_path.len() > 1 && url_path.ends_with('/') {
                return error_response(
                    cfg,
                    vhost,
                    scope,
                    404,
                    req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                );
            }
            if !matches!(req.method.as_str(), "GET" | "HEAD") {
                let mut r = error_response(
                    cfg,
                    vhost,
                    scope,
                    405,
                    req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                );
                r.headers
                    .push(("Allow".into(), b"GET, HEAD, OPTIONS".to_vec()));
                return r;
            }
            serve_file(
                cfg,
                scope,
                req,
                file,
                &meta,
                actual_path.as_ref(),
                name,
                peer.ip(),
                local_ip,
                &target_grant,
                &target_resource,
            )
        }
        Target::Directory { file, meta } => {
            if req.method == "OPTIONS" {
                return options_response(cfg, &scope, None);
            }
            if req.method != "GET" && req.method != "HEAD" {
                let mut r = error_response(
                    cfg,
                    vhost,
                    &scope,
                    405,
                    req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                );
                r.headers
                    .push(("Allow".into(), b"GET, HEAD, OPTIONS".to_vec()));
                return r;
            }
            // With `DirectorySlash Off`, Apache does not redirect `/dir` to
            // `/dir/`.  Authorization must still use the canonical directory
            // URL, otherwise `<Location "/dir/">` is skipped and an autoindex
            // listing for the protected directory leaks its entries.
            let mut auth_url = url_path.clone();
            if !url_path.ends_with('/') && !scope.content_policy.directory_slash.unwrap_or(true) {
                let canonical = format!("{}/", url_path.trim_end_matches('/'));
                match authorize_resolved_target(
                    cfg,
                    vhost,
                    req,
                    peer.ip(),
                    &fs_path,
                    &canonical,
                    &scope,
                    None,
                    &root,
                    local_port,
                    &server_name,
                    local_ip,
                ) {
                    Ok((target_grant, _target_resource, target_scope)) => {
                        scope = target_scope;
                        grant = target_grant;
                        auth_url = canonical;
                    }
                    Err(r) => return r,
                }
            }
            if let Some(name) =
                directory_index_name(cfg, &scope, req, &file, &auth_url, &req.raw_path)
            {
                let index_url = format!(
                    "{}/{}",
                    auth_url.trim_end_matches('/'),
                    String::from_utf8_lossy(&name)
                );
                return internal_dispatch(cfg, req, &index_url, peer, local_ip, local_port);
            }
            let Some(actual_path) = crate::files::fd_path_cow(&file, &fs_path) else {
                return error_response(
                    cfg,
                    vhost,
                    &scope,
                    500,
                    req,
                    &url_path,
                    local_port,
                    &server_name,
                    peer.ip(),
                    local_ip,
                );
            };
            let (target_grant, target_resource, target_scope) = match bind_target_grant(
                cfg,
                vhost,
                &scope,
                &grant,
                &fs_path,
                actual_path.as_ref(),
                &root,
                &meta,
                &auth_url,
                req,
                peer.ip(),
                local_port,
                &server_name,
                local_ip,
                &rewrite_effects,
            ) {
                Ok(v) => v,
                Err(r) => return r, // coverage:ignore-line
            };
            serve_directory(
                cfg,
                vhost,
                &target_scope,
                req,
                file,
                &meta,
                actual_path.as_ref(),
                &url_path,
                &req.raw_path,
                &server_name,
                local_port,
                peer.ip(),
                local_ip,
                &target_grant,
                &target_resource,
            )
        }
        Target::Forbidden => error_response(
            cfg,
            vhost,
            &scope,
            403,
            req,
            &url_path,
            local_port,
            &server_name,
            peer.ip(),
            local_ip,
        ),
        Target::NotFound => {
            if req.method == "OPTIONS" {
                return options_response(cfg, &scope, None);
            }
            // CGI PATH_INFO: try progressively shorter script names.  The
            // requested suffix must not select the handler: `/protected.sh/x.cgi`
            // is only executable when `protected.sh` itself is configured as a
            // CGI script.  Policy is then re-evaluated for the actual script
            // path before the script inode is executed.
            let script_target = if cfg.cgi_path_info_possible() {
                cgi::find_script_checked_for_request(&root, &rel, follow, owner_match_only, req)
            } else {
                None
            };
            if let Some(st) = script_target {
                let lexical_script = root.join(&st.rel_script);
                let Some(actual_path) = crate::files::fd_path_cow(&st.file, &lexical_script) else {
                    return error_response(
                        cfg,
                        vhost,
                        &scope,
                        500,
                        req,
                        &url_path,
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                };
                let actual_name = st
                    .rel_script
                    .file_name()
                    .or_else(|| actual_path.file_name())
                    .map(|n| n.as_encoded_bytes())
                    .unwrap_or(b"");
                debug_assert!(vapache_verified::handler_identity_lexical_admit(
                    actual_path.as_ref() != lexical_script.as_path(),
                    actual_name
                        == st
                            .rel_script
                            .file_name()
                            .map(|n| n.as_encoded_bytes())
                            .unwrap_or(b""),
                ));
                let script_name = if st.path_info.is_empty() {
                    url_path.clone() // coverage:ignore-line
                } else {
                    url_path
                        .strip_suffix(&st.path_info)
                        .unwrap_or(&url_path)
                        .to_string()
                };
                let requested_base = norm.rsplit(|b| *b == b'/').next().unwrap_or(&norm);
                let path_info_selected_cgi = cgi::is_cgi(cfg, &scope, requested_base, false);
                let selected = cgi::is_cgi(cfg, &scope, actual_name, script_alias);
                if selected {
                    // Authorize the actual opened target, not the lexical
                    // `st.rel_script`: a public symlink to a denied script
                    // must not execute with the public directory's policy
                    // (F41/I39), including with PATH_INFO.
                    let (target_grant, target_resource, target_scope) =
                        match authorize_resolved_target(
                            cfg,
                            vhost,
                            req,
                            peer.ip(),
                            actual_path.as_ref(),
                            &script_name,
                            &scope,
                            None,
                            &root,
                            local_port,
                            &server_name,
                            local_ip,
                        ) {
                            Ok(v) => v,
                            Err(r) => return r,
                        };
                    let script_root = actual_path.parent().unwrap_or(root.as_path()).to_path_buf();
                    let script_rel = actual_path
                        .file_name()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| st.rel_script.clone());
                    if cgi::is_cgi(cfg, &target_scope, actual_name, script_alias) {
                        if req.handler_probe() {
                            let descriptor_lease = match cfg.resource_budget.try_descriptor() {
                                Ok(lease) => lease,
                                Err(_) => return Response::memory_overload(),
                            };
                            return Response::prepared_handler(PreparedHandler::Cgi {
                                vhost_index: selected_vhost_index(cfg, vhost),
                                scope: target_scope,
                                peer,
                                local_port,
                                server_name: server_name.to_string(),
                                local_ip: local_ip.to_string(),
                                grant: target_grant,
                                resource: target_resource,
                                root: script_root,
                                script_rel,
                                url_path: url_path.clone(),
                                path_info: st.path_info,
                                script_name,
                                script_file: st.file,
                                script_meta: st.meta,
                                _descriptor_lease: descriptor_lease,
                            });
                        }
                        return run_cgi(
                            cfg,
                            vhost,
                            req,
                            &script_root,
                            &script_rel,
                            &url_path,
                            &st.path_info,
                            &script_name,
                            &server_name,
                            peer,
                            local_ip,
                            local_port,
                            &target_scope,
                            &target_grant,
                            &target_resource,
                            Some(&st.file),
                            Some(&st.meta),
                        );
                    }
                }
                if path_info_selected_cgi {
                    // A suffix such as `/.cgi` must not turn an arbitrary
                    // executable into a script.  Fail closed rather than
                    // falling through to a different handler.
                    return error_response(
                        cfg,
                        vhost,
                        &scope,
                        403,
                        req,
                        &url_path,
                        local_port,
                        &server_name,
                        peer.ip(),
                        local_ip,
                    );
                }
            }
            error_response(
                cfg,
                vhost,
                &scope,
                404,
                req,
                &url_path,
                local_port,
                &server_name,
                peer.ip(),
                local_ip,
            )
        }
    }
}

pub fn map_path(
    cfg: &Config,
    vhost: Option<&VHost>,
    norm: &[u8],
) -> Option<(PathBuf, PathBuf, bool)> {
    let url = String::from_utf8_lossy(norm);
    let base_scope = vhost.map(|v| &v.scope).unwrap_or(&cfg.global);
    // Apache's alias table is ordered: the first matching `Alias`,
    // `ScriptAlias`, `AliasMatch` or `ScriptAliasMatch` wins.  A later, more
    // specific alias that overlaps an earlier one never matches.
    for a in &base_scope.mapping_policy.aliases {
        if a.regex.is_none() {
            if let Some(rest) = alias_remainder(&a.virtual_path, &url) {
                let rest_rel = PathBuf::from(rest.trim_start_matches('/'));
                // A prefix Alias/ScriptAlias may name a single regular file.
                // Using the file itself as the root and an empty `rel` hid the
                // target basename from handler/MIME selection and skipped the
                // target directory's `.htaccess` (F39).  Split the file target
                // into its parent directory plus its own name.
                if a.fs_path.is_file() {
                    let name = a.fs_path.file_name().unwrap_or(OsStr::new(""));
                    let parent = a.fs_path.parent().unwrap_or(Path::new("/"));
                    let mut rel = PathBuf::from(name);
                    if !rest_rel.as_os_str().is_empty() {
                        rel.push(rest_rel);
                    }
                    return Some((parent.to_path_buf(), rel, a.script));
                }
                return Some((a.fs_path.clone(), rest_rel, a.script));
            }
            continue;
        }
        let regex = a
            .regex
            .as_ref()
            .expect("regex alias was checked before the prefix branch");
        let Some(caps) = regex.captures(url.as_bytes()) else {
            continue;
        };
        let Some(template) = &a.target_template else {
            continue;
        };
        let expanded = crate::util::expand_regex_captures(template, &caps)?;
        let target = PathBuf::from(&expanded);
        let target = if target.is_absolute() {
            target
        } else {
            cfg.server_root.join(target)
        };
        let target = clean_alias_path(&target);
        // A regex alias may only resolve inside the stable alias base derived
        // from its replacement prefix.  Falling back to `target.parent()` as a
        // new root would silently change both the served object and the
        // `<Directory>`/`.htaccess` authorization base.  The component-aware
        // byte check is the verified kernel; `strip_prefix` remains the
        // allocation-free way to obtain the relative target after admission.
        if a.fs_path.as_os_str().is_empty()
            || !crate::verified::path_under_base(
                target.as_os_str().as_encoded_bytes(),
                a.fs_path.as_os_str().as_encoded_bytes(),
            )
        {
            return None;
        }
        let Ok(rel) = target.strip_prefix(&a.fs_path) else {
            return None; // coverage:ignore-line
        };
        let rel = rel.to_path_buf();
        // A regex replacement ending in `/` can still resolve to a regular
        // file (for example `/srv/private/wallet.dat/`).  Apache accepts this
        // and applies the target directory's `.htaccess`; mapping it as
        // `(file, "")` hid the basename and skipped that walk (F47/I44).
        // Split an exact file target into its parent and basename just like
        // the prefix-alias branch.
        if rel.as_os_str().is_empty() && target.is_file() {
            let name = target.file_name().unwrap_or(OsStr::new(""));
            let parent = target.parent().unwrap_or(Path::new("/"));
            return Some((parent.to_path_buf(), PathBuf::from(name), a.script));
        }
        return Some((a.fs_path.clone(), rel, a.script));
    }
    let root = cfg.documentation_root_for(vhost);
    let rel = PathBuf::from(OsStr::from_bytes(&norm[1..]));
    Some((root, rel, false))
}

fn clean_alias_path(p: &Path) -> PathBuf {
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
    out
}

fn alias_remainder(alias: &str, url: &str) -> Option<String> {
    if alias.ends_with('/') {
        if url.starts_with(alias) {
            return Some(url[alias.len()..].to_string());
        }
        // Apache also matches the alias directory without the trailing slash
        // so it can issue a redirect.
        let trimmed = alias.trim_end_matches('/');
        if url == trimmed {
            return Some(String::new());
        }
        return None;
    }
    if url == alias {
        Some(String::new())
    } else if let Some(rest) = url.strip_prefix(alias) {
        if rest.starts_with('/') {
            Some(rest.to_string())
        } else {
            None
        }
    } else {
        None
    }
}

fn match_redirect<'a>(
    scope: &'a Scope,
    url: &str,
    req: Option<&Request>,
) -> Option<(&'a crate::config::Redirect, String)> {
    // Redirect and RedirectMatch share one ordered table, matching Apache's
    // first-match behavior (a later overlapping redirect is unreachable).
    for r in &scope.mapping_policy.redirects {
        if let Some(regex) = &r.regex {
            let Some(caps) = regex.captures(url.as_bytes()) else {
                continue;
            };
            let Some(location) = crate::util::expand_regex_captures(&r.to, &caps) else {
                if let Some(req) = req {
                    let _ = req.charge_policy_expansion(u64::MAX);
                }
                return None;
            };
            if let Some(req) = req {
                if req.charge_policy_expansion(location.len() as u64).is_err() {
                    return None;
                }
            }
            return Some((r, location));
        }
        let m = if r.from.ends_with('/') {
            url.starts_with(&r.from)
        } else {
            url == r.from || url.starts_with(&format!("{}/", r.from))
        };
        if m {
            let suffix = if r.from.ends_with('/') {
                &url[r.from.len()..]
            } else if url.len() > r.from.len() {
                &url[r.from.len()..]
            } else {
                ""
            };
            return Some((r, format!("{}{}", r.to, suffix)));
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn run_fastcgi(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    url_path: &str,
    server_name: &str,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    scope: &Scope,
    target: &fastcgi::Target,
    _grant: &crate::access::AccessGrant,
    _resource: &crate::access::ResourceKey,
    mapping_root: &Path,
) -> Response {
    if !vapache_verified::capability_admit(cfg.capability_enabled(Capability::FastCgi), true) {
        return error_response(
            cfg,
            vhost,
            scope,
            403,
            req,
            url_path,
            local_port,
            server_name,
            peer.ip(),
            local_ip,
        );
    }
    // `ProxyPassMatch`/`SetHandler` can resolve PATH_INFO to a real script
    // whose own `<Files>`/`<Directory>` policy differs from the requested URL.
    // Re-evaluate policy for the script target before binding the backend.
    // Resolve the actual script through an opened descriptor first. The
    // canonical object is the authorization identity, but Apache forwards the
    // lexical split prefix as SCRIPT_FILENAME and lets PHP-FPM apply
    // `security.limit_extensions` to that name. Conflating the two identities
    // bypassed the backend's own gate (P15-A).
    let target = target.clone();
    let follow = scope.effective_options().contains(Options::FOLLOW_SYMLINKS);
    let owner_match_only = !follow
        && scope
            .effective_options()
            .contains(Options::SYMLINKS_IF_OWNER_MATCH);
    let Some(script_binding) = fastcgi::open_script(
        &target,
        mapping_root,
        follow || owner_match_only,
        owner_match_only,
    ) else {
        return error_response(
            cfg,
            vhost,
            scope,
            403,
            req,
            url_path,
            local_port,
            server_name,
            peer.ip(),
            local_ip,
        );
    };
    let lexical_script_url = if target.path_info.is_empty() {
        url_path.to_string()
    } else {
        url_path
            .strip_suffix(&target.path_info)
            .unwrap_or(url_path)
            .to_string()
    };
    let authorized_path = script_binding.actual_path.clone();
    let docroot = cfg.documentation_root_for(vhost);
    let canonical_docroot = std::fs::canonicalize(&docroot).unwrap_or(docroot.clone());
    let script_url = authorized_path
        .strip_prefix(&canonical_docroot)
        .ok()
        .map(|relative| {
            let relative = relative.to_string_lossy();
            format!("/{}", relative.trim_start_matches('/'))
        })
        .unwrap_or(lexical_script_url);
    let proxy_identity = format!(
        "lexical={}|authorized={}",
        target.script_filename().display(),
        authorized_path.display()
    );
    let (target_grant, target_resource, target_scope) = match authorize_resolved_target(
        cfg,
        vhost,
        req,
        peer.ip(),
        &authorized_path,
        &script_url,
        scope,
        Some(&proxy_identity),
        mapping_root,
        local_port,
        server_name,
        local_ip,
    ) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let scope = &target_scope;
    let grant = &target_grant;
    let resource = &target_resource;
    let backend_binding = target.binding_key(&authorized_path);
    let backend_binds_both =
        backend_binding.contains("|lexical=") && backend_binding.contains("|authorized=");
    // coverage:ignore-start
    let Some(file_bound) = grant.bind_file(resource, &script_binding.meta) else {
        return error_response(
            cfg,
            vhost,
            scope,
            500,
            req,
            url_path,
            local_port,
            server_name,
            peer.ip(),
            local_ip,
        );
    };
    let file_resource = file_bound.key().clone();
    let Some(bound) = file_bound.bind_backend(&file_resource, backend_binding) else {
        return error_response(
            cfg,
            vhost,
            scope,
            500,
            req,
            url_path,
            local_port,
            server_name,
            peer.ip(),
            local_ip,
        );
    };
    let expected = bound.key().clone();
    if !bound.require_sink(&expected, vapache_verified::TransformSink::FastCgi)
        || !vapache_verified::fastcgi_script_identity_admit(
            expected.fs_path.as_deref() == Some(authorized_path.as_path()),
            script_binding.meta.dev() == expected.file_dev.unwrap_or_default()
                && script_binding.meta.ino() == expected.file_ino.unwrap_or_default(),
            true,
            backend_binds_both,
        )
    {
        return error_response(
            cfg,
            vhost,
            scope,
            500,
            req,
            url_path,
            local_port,
            server_name,
            peer.ip(),
            local_ip,
        );
    }
    // coverage:ignore-stop
    let remote_user = bound.key().identity.as_deref();
    let auth_type = remote_user.and_then(|_| {
        scope
            .authorization
            .auth_type
            .as_deref()
            .filter(|kind| kind.eq_ignore_ascii_case("basic"))
            .map(|_| "Basic")
    });
    let ctx = CgiContext {
        cfg,
        vhost,
        req,
        root: &docroot,
        script_rel: Path::new(""),
        script_name: url_path,
        path_info: &target.path_info,
        docroot: &docroot,
        remote_ip: &peer.ip().to_string(),
        remote_port: peer.port(),
        local_ip,
        local_port,
        https: crate::expr::request_is_https(),
        server_name,
        host: server_name,
        follow_symlinks: true,
        env: &scope.fastcgi_env(req, url_path, peer.ip()),
        remote_user,
        auth_type,
        script_file: None,
    };
    let mut r = fastcgi::execute_bound(&ctx, scope, &target, &script_binding);
    if scope
        .header_policy
        .apply(&mut r.headers, r.status < 400)
        .is_err()
    {
        return Response::policy_error();
    }
    r
}

#[allow(clippy::too_many_arguments)]
fn run_cgi(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    root: &Path,
    script_rel: &Path,
    url_path: &str,
    path_info: &str,
    script_name: &str,
    server_name: &str,
    peer: SocketAddr,
    local_ip: &str,
    local_port: u16,
    scope: &Scope,
    grant: &crate::access::AccessGrant,
    resource: &crate::access::ResourceKey,
    script_file: Option<&std::fs::File>,
    script_meta: Option<&std::fs::Metadata>,
) -> Response {
    if !vapache_verified::capability_admit(cfg.capability_enabled(Capability::Cgi), true) {
        return error_response(
            cfg,
            vhost,
            scope,
            403,
            req,
            url_path,
            local_port,
            server_name,
            peer.ip(),
            local_ip,
        );
    }
    // CGI is an execution sink: a pathname-only grant is never sufficient.
    // The descriptor and metadata originate from the same open, and the
    // verified sink gate requires the resulting inode-bound capability.
    let (Some(script_file), Some(meta)) = (script_file, script_meta) else {
        return error_response(
            cfg,
            vhost,
            scope,
            500,
            req,
            script_name,
            local_port,
            server_name,
            peer.ip(),
            local_ip,
        );
    };
    // coverage:ignore-start
    let Some(bound) = grant.bind_file(resource, meta) else {
        return error_response(
            cfg,
            vhost,
            scope,
            500,
            req,
            script_name,
            local_port,
            server_name,
            peer.ip(),
            local_ip,
        );
    };
    let mut expected = resource.clone();
    expected.file_dev = Some(meta.dev());
    expected.file_ino = Some(meta.ino());
    if !bound.require_sink(&expected, vapache_verified::TransformSink::LocalCgi) {
        return error_response(
            cfg,
            vhost,
            scope,
            500,
            req,
            script_name,
            local_port,
            server_name,
            peer.ip(),
            local_ip,
        );
    }
    // coverage:ignore-stop
    let follow = scope.effective_options().contains(Options::FOLLOW_SYMLINKS)
        || scope
            .effective_options()
            .contains(Options::SYMLINKS_IF_OWNER_MATCH);
    let docroot = cfg.documentation_root_for(vhost);
    let remote_user = bound.key().identity.as_deref();
    let auth_type = remote_user.and_then(|_| {
        scope
            .authorization
            .auth_type
            .as_deref()
            .filter(|kind| kind.eq_ignore_ascii_case("basic"))
            .map(|_| "Basic")
    });
    let ctx = CgiContext {
        cfg,
        vhost,
        req,
        root,
        script_rel,
        script_name,
        path_info,
        docroot: &docroot,
        remote_ip: &peer.ip().to_string(),
        remote_port: peer.port(),
        local_ip,
        local_port,
        https: crate::expr::request_is_https(),
        server_name,
        host: server_name,
        follow_symlinks: follow,
        env: &scope.request_env(req, url_path, peer.ip()),
        remote_user,
        auth_type,
        script_file: Some(script_file),
    };
    let mut r = cgi::execute(&ctx);
    if scope
        .header_policy
        .apply(&mut r.headers, r.status < 400)
        .is_err()
    {
        return Response::policy_error();
    }
    crate::compression::finalize_budgeted(
        scope,
        req,
        &mut r,
        script_name.as_bytes(),
        &cfg.resource_budget,
    );
    r
}

fn apply_rewrite_effects(scope: &mut crate::config::Scope, effects: &crate::rewrite::Effects) {
    for (name, value) in &effects.env {
        scope
            .environment_policy
            .rewrite_env
            .retain(|entry| entry.value.0 != *name);
        scope
            .environment_policy
            .rewrite_unset_env
            .retain(|entry| entry.value != *name);
        match value {
            Some(value) => {
                scope
                    .environment_policy
                    .rewrite_env
                    .push(crate::scope_policy::Originated::main((
                        name.clone(),
                        value.clone(),
                    )))
            }
            None => scope
                .environment_policy
                .rewrite_unset_env
                .push(crate::scope_policy::Originated::main(name.clone())),
        }
    }
    for effect in &effects.late_env {
        let (name, value) = &effect.value;
        scope
            .environment_policy
            .rewrite_late_env
            .retain(|entry| entry.value.0 != *name || entry.origin != effect.origin);
        scope
            .environment_policy
            .rewrite_late_unset_env
            .retain(|entry| entry.value != *name || entry.origin != effect.origin);
        match value {
            Some(value) => {
                scope
                    .environment_policy
                    .rewrite_late_env
                    .push(crate::scope_policy::Originated {
                        origin: effect.origin,
                        value: (name.clone(), value.clone()),
                    })
            }
            None => scope.environment_policy.rewrite_late_unset_env.push(
                crate::scope_policy::Originated {
                    origin: effect.origin,
                    value: name.clone(),
                },
            ),
        }
    }
    for name in &effects.vary {
        if !scope
            .header_policy
            .vary
            .iter()
            .any(|v| v.eq_ignore_ascii_case(name))
        {
            scope.header_policy.vary.push(name.clone());
        }
    }
    for cookie in &effects.cookies {
        if !scope.header_policy.cookies.contains(cookie) {
            scope.header_policy.cookies.push(cookie.clone());
        }
    }
    if let Some(handler) = &effects.handler {
        // F64: a rewrite `[H=...]` sets the same precedence field a
        // `SetHandler` directive would — a forced handler beats the
        // extension table regardless of parse order.
        scope.mapping_policy.set_handler = Some(crate::config::SetHandler::Name(handler.clone()));
    }
    if let Some(content_type) = &effects.content_type {
        scope.content_policy.force_type = Some(content_type.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Admission counters are intentionally process-wide.  Serialize the few
    // tests that fill or overwrite them so the normal parallel test runner
    // observes the same isolation as separate server processes.
    static ADMISSION_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn alias_boundaries() {
        assert_eq!(
            alias_remainder("/icons/", "/icons/a.png"),
            Some("a.png".into())
        );
        assert_eq!(alias_remainder("/icons/", "/icons"), Some("".into()));
        assert_eq!(alias_remainder("/icons/", "/iconsx"), None);
        assert_eq!(alias_remainder("/foo", "/foo/bar"), Some("/bar".into()));
        assert_eq!(alias_remainder("/foo", "/foobar"), None);
    }

    #[test]
    fn verified_path_containment_uses_component_boundaries() {
        assert!(vapache_verified::path_under_base(
            b"/srv/www/a.txt",
            b"/srv/www"
        ));
        assert!(vapache_verified::path_under_base(b"/srv/www", b"/srv/www"));
        assert!(vapache_verified::path_under_base(
            b"/srv/www/a.txt",
            b"/srv/www/"
        ));
        assert!(vapache_verified::path_under_base(b"/etc/passwd", b"/"));
        assert!(!vapache_verified::path_under_base(
            b"/srv/www2/a.txt",
            b"/srv/www"
        ));
        assert!(!vapache_verified::path_under_base(b"/srv/w", b"/srv/www"));
        assert!(!vapache_verified::path_under_base(b"/srv/www", b""));
    }

    #[test]
    fn regex_alias_and_redirect_expand_captures() {
        let dir = std::env::temp_dir().join(format!("vapache-server-map-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        std::fs::write(
            &conf,
            "Listen 127.0.0.1:0\n\
             Alias /foo/ \"/srv/a/\"\n\
             Alias /foo/bar/ \"/srv/b/\"\n\
             AliasMatch \"^/pub/(.*)$\" \"/srv/private/$1\"\n\
             RedirectMatch 404 \"^/secret/(.*)$\"\n",
        )
        .unwrap();
        let cfg =
            Config::load(&conf, &dir, &Default::default(), &Default::default(), false).unwrap();
        let (root, rel, script) = map_path(&cfg, None, b"/pub/a/b.txt").unwrap();
        assert_eq!(root, PathBuf::from("/srv/private"));
        assert_eq!(rel, PathBuf::from("a/b.txt"));
        assert!(!script);
        // The first overlapping prefix alias wins, even though the second is
        // more specific.
        let (root, rel, _) = map_path(&cfg, None, b"/foo/bar/x").unwrap();
        assert_eq!(root, PathBuf::from("/srv/a"));
        assert_eq!(rel, PathBuf::from("bar/x"));
        let (red, location) = match_redirect(&cfg.global, "/secret/file", None).unwrap();
        assert_eq!(red.status, 404);
        assert!(location.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn single_file_prefix_aliases_split_parent_and_basename() {
        let dir =
            std::env::temp_dir().join(format!("vapache-server-file-alias-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("private")).unwrap();
        let file = dir.join("private").join("secret.cgi");
        std::fs::write(&file, "#!/bin/sh\n").unwrap();
        let conf = dir.join("httpd.conf");
        std::fs::write(
            &conf,
            format!(
                "{}Listen 127.0.0.1:0\n\
                 Alias /run \"{}\"\n\
                 ScriptAlias /exec \"{}\"\n",
                crate::config::TEST_CAPABILITIES,
                file.display(),
                file.display()
            ),
        )
        .unwrap();
        let cfg =
            Config::load(&conf, &dir, &Default::default(), &Default::default(), false).unwrap();
        for (url, script) in [(b"/run".as_slice(), false), (b"/exec".as_slice(), true)] {
            let (root, rel, got_script) = map_path(&cfg, None, url).unwrap();
            assert_eq!(root, dir.join("private"));
            assert_eq!(rel, PathBuf::from("secret.cgi"));
            assert_eq!(got_script, script);
        }
        // A suffix remains below the file name and therefore cannot turn the
        // file target into a directory traversal.
        let (root, rel, _) = map_path(&cfg, None, b"/run/extra").unwrap();
        assert_eq!(root, dir.join("private"));
        assert_eq!(rel, PathBuf::from("secret.cgi/extra"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn regex_alias_file_targets_split_even_with_trailing_slash() {
        let dir = std::env::temp_dir().join(format!(
            "vapache-server-regex-file-alias-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("private")).unwrap();
        let wallet = dir.join("private").join("wallet.dat");
        std::fs::write(&wallet, "WALLET\n").unwrap();
        let cgi = dir.join("private").join("secret.cgi");
        std::fs::write(&cgi, "#!/bin/sh\n").unwrap();
        let conf = dir.join("httpd.conf");
        std::fs::write(
            &conf,
            format!(
                "{}Listen 127.0.0.1:0\n\
                 AliasMatch \"^/wallet$\" \"{}/\"\n\
                 ScriptAliasMatch \"^/run$\" \"{}/\"\n\
                 AliasMatch \"^/wallet-noslash$\" \"{}\"\n\
                 ScriptAliasMatch \"^/run-noslash$\" \"{}\"\n",
                crate::config::TEST_CAPABILITIES,
                wallet.display(),
                cgi.display(),
                wallet.display(),
                cgi.display()
            ),
        )
        .unwrap();
        let cfg =
            Config::load(&conf, &dir, &Default::default(), &Default::default(), false).unwrap();
        for (url, name, script) in [
            (b"/wallet".as_slice(), "wallet.dat", false),
            (b"/run".as_slice(), "secret.cgi", true),
            (b"/wallet-noslash".as_slice(), "wallet.dat", false),
            (b"/run-noslash".as_slice(), "secret.cgi", true),
        ] {
            let (root, rel, got_script) = map_path(&cfg, None, url).unwrap();
            assert_eq!(root, dir.join("private"), "{url:?}");
            assert_eq!(rel, PathBuf::from(name), "{url:?}");
            assert_eq!(got_script, script, "{url:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn regex_alias_cannot_re_root_outside_its_configured_base() {
        let dir = std::env::temp_dir().join(format!(
            "vapache-server-alias-escape-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        std::fs::write(
            &conf,
            format!(
                "ServerRoot \"{}\"\n\
                 Listen 127.0.0.1:0\n\
                 AliasMatch \"^/capture(.*)$\" \"$1\"\n\
                 AliasMatch \"^/fixed$\" \"/srv/fixed/index.html\"\n",
                dir.display()
            ),
        )
        .unwrap();
        let cfg =
            Config::load(&conf, &dir, &Default::default(), &Default::default(), false).unwrap();
        // Capture-only replacements have no stable base at all: both an
        // outside path and a ServerRoot secret must fail closed (F42/I40).
        assert!(map_path(&cfg, None, b"/capture/tmp/elsewhere/secret.txt").is_none());
        let inside = format!("/capture{}/secret.txt", dir.display());
        assert!(map_path(&cfg, None, inside.as_bytes()).is_none());
        let capture = cfg
            .global
            .mapping_policy
            .aliases
            .iter()
            .find(|a| a.target_template.as_deref() == Some("$1"))
            .expect("capture-only alias");
        assert!(capture.fs_path.as_os_str().is_empty());
        // A fixed absolute target still maps relative to its stable parent.
        let (root, rel, _) = map_path(&cfg, None, b"/fixed").unwrap();
        assert_eq!(root, PathBuf::from("/srv/fixed"));
        assert_eq!(rel, PathBuf::from("index.html"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn cov_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("vapache-server-cov-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("www")).unwrap();
        dir
    }

    fn cov_config(root: &Path, body: &str) -> Config {
        let conf = root.join("httpd.conf");
        std::fs::write(
            &conf,
            format!(
                "{}ServerRoot \"{}\"\n\
                 Listen 127.0.0.1:0\n\
                 ServerName localhost\n\
                 PidFile \"{}/httpd.pid\"\n\
                 ErrorLog \"{}/error.log\"\n\
                 LogLevel warn\n\
                 DocumentRoot \"{}/www\"\n\
                 {}",
                crate::config::TEST_CAPABILITIES,
                root.display(),
                root.display(),
                root.display(),
                root.display(),
                body
            ),
        )
        .unwrap();
        Config::load(&conf, root, &Default::default(), &Default::default(), false).unwrap()
    }

    fn cov_capability_audit_config(root: &Path, body: &str) -> Config {
        let conf = root.join("httpd.conf");
        std::fs::write(
            &conf,
            format!(
                "ServerRoot \"{}\"\n\
                 Listen 127.0.0.1:0\n\
                 ServerName localhost\n\
                 ErrorLog \"{}/error.log\"\n\
                 DocumentRoot \"{}/www\"\n\
                 {}",
                root.display(),
                root.display(),
                root.display(),
                body
            ),
        )
        .unwrap();
        Config::load_capability_audit(&conf, root, &Default::default(), &Default::default(), false)
            .unwrap()
    }

    fn cov_req(method: &str, path: &str) -> Request {
        Request {
            method: method.into(),
            target: path.as_bytes().to_vec(),
            raw_path: path.as_bytes().to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Default::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: false,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn cov_peer() -> SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }

    #[test]
    fn actual_connection_tls_state_controls_absolute_redirect_scheme() {
        let dir = cov_dir("connection-scheme");
        std::fs::create_dir(dir.join("www/directory")).unwrap();
        let cfg = cov_config(&dir, "");
        let mut req = cov_req("GET", "/directory");
        req.headers.insert("host", b"example.test".to_vec());

        let clear = dispatch_with_scheme(&cfg, &req, cov_peer(), "127.0.0.1", 443, false);
        assert!(clear.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("location") && value == b"http://example.test/directory/"
        }));

        let tls = dispatch_with_scheme(&cfg, &req, cov_peer(), "127.0.0.1", 8443, true);
        assert!(tls.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("location") && value == b"https://example.test/directory/"
        }));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[derive(Default)]
    struct CovWriter(Vec<u8>);

    impl Write for CovWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl ResponseWrite for CovWriter {}

    struct CovFailWriter;
    impl Write for CovFailWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl ResponseWrite for CovFailWriter {}

    struct CovDefaultConn;
    impl Read for CovDefaultConn {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }
    impl Write for CovDefaultConn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Conn for CovDefaultConn {}
    impl ResponseWrite for CovDefaultConn {}

    struct ScriptConn {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
        fail_write: bool,
        tcp_clone: Option<TcpStream>,
    }

    impl ScriptConn {
        fn new(input: &[u8]) -> Self {
            Self {
                input: std::io::Cursor::new(input.to_vec()),
                output: Vec::new(),
                fail_write: false,
                tcp_clone: None,
            }
        }
    }

    impl Read for ScriptConn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            std::io::Read::read(&mut self.input, buf)
        }
    }

    impl Write for ScriptConn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
            }
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Conn for ScriptConn {
        fn try_clone_tcp(&self) -> Option<TcpStream> {
            self.tcp_clone.as_ref().and_then(|s| s.try_clone().ok())
        }
    }
    impl ResponseWrite for ScriptConn {}

    fn cov_logger(cfg: &Config) -> Logger {
        Logger::new(cfg).unwrap()
    }

    #[test]
    fn coverage_server_support_and_failure_helpers() {
        assert_eq!(
            admitted_tls_http_protocol(true, true, Some(b"h2")).unwrap(),
            TlsHttpProtocol::Http2
        );
        assert_eq!(
            admitted_tls_http_protocol(true, true, Some(b"http/1.1")).unwrap(),
            TlsHttpProtocol::Http11
        );
        assert_eq!(
            admitted_tls_http_protocol(false, true, None).unwrap(),
            TlsHttpProtocol::Http11
        );
        assert!(admitted_tls_http_protocol(true, false, None).is_err());
        assert!(admitted_tls_http_protocol(true, false, Some(b"http/1.1")).is_err());
        assert!(admitted_tls_http_protocol(false, true, Some(b"h2")).is_err());
        assert!(admitted_tls_http_protocol(true, true, Some(b"unknown")).is_err());

        assert!(first_resolved_addr(std::iter::empty()).is_err());
        assert_eq!(
            first_resolved_addr(vec!["127.0.0.1:80".parse::<SocketAddr>().unwrap()].into_iter())
                .unwrap()
                .port(),
            80
        );
        assert!(create_tcp_socket(-1).is_err());
        assert!(poll_result(0, 0).is_ok());
        assert!(poll_result(-1, libc::EINTR).is_ok());
        assert_eq!(
            poll_result(-1, libc::EFAULT).unwrap_err().raw_os_error(),
            Some(libc::EFAULT)
        );
        assert_eq!(
            accept_error_action(&io::Error::from(io::ErrorKind::WouldBlock)),
            AcceptAction::Break
        );
        assert_eq!(
            accept_error_action(&io::Error::from(io::ErrorKind::Interrupted)),
            AcceptAction::Continue
        );
        assert_eq!(
            accept_error_action(&io::Error::from(io::ErrorKind::ConnectionReset)),
            AcceptAction::Break
        );
        assert_eq!(
            accept_error_action(&io::Error::from_raw_os_error(libc::EMFILE)),
            AcceptAction::Backoff
        );
        assert_eq!(
            timed_io::<u8>(None, "timeout").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(timed_io(Some(Ok(7)), "timeout").unwrap(), 7);
        assert_eq!(
            authenticated_access_result(Access::AuthRequired),
            Access::Denied
        );
        assert_eq!(
            authenticated_access_result(Access::Allowed),
            Access::Allowed
        );
        assert!(
            timed_io::<u8>(Some(Err(io::Error::from(io::ErrorKind::Other))), "timeout").is_err()
        );

        let dir = cov_dir("helpers");
        let cfg = cov_config(&dir, "");
        let mut server = Server::new(Arc::new(cfg.clone()), Arc::new(cov_logger(&cfg)));
        assert!(!server.stop_flag().load(Ordering::Relaxed));
        server.stop_flag().store(true, Ordering::Relaxed);
        assert!(server.stop_flag().load(Ordering::Relaxed));
        assert_eq!(active_connections(), active_connections());

        let mut cfg_trace = cfg.clone();
        cfg_trace.trace_enable = true;
        assert!(allowed_methods(&cfg_trace).contains(&"TRACE"));
        assert!(!allowed_methods(&cfg).contains(&"TRACE"));
        assert!(allow_header(&cfg_trace).contains("TRACE"));

        let mut req = cov_req("GET", "/");
        assert_eq!(host_header(&req), None);
        req.headers.insert("host", b"  ".to_vec());
        assert_eq!(host_header(&req), None);
        req.headers.insert("host", b" example.test:80 ".to_vec());
        assert_eq!(host_header(&req), Some("example.test:80"));
        assert_eq!(strip_port("[::1]:8080"), "::1");
        assert_eq!(strip_port("example.test:8080"), "example.test");
        assert_eq!(strip_port("example.test"), "example.test");

        let no_host = cov_req("GET", "/");
        let vhost_name = VHost {
            addrs: vec!["*:80".into()],
            ports: vec![80],
            server_name: Some("vhost.test:80".into()),
            aliases: Vec::new(),
            scope: Scope::default(),
            delta: Scope::default(),
            rules: Vec::new(),
            directory_index: Default::default(),
            proxy_containers: Vec::new(),
            custom_logs: Vec::new(),
            error_log: None,
            server_admin: None,
            protocols: cfg.protocols.clone(),
            ssl: Default::default(),
        };
        let mut cfg_name = cfg.clone();
        cfg_name.vhosts = vec![vhost_name.clone()];
        assert_eq!(
            server_name_for(&cfg_name, &no_host, "127.0.0.1", 80),
            "vhost.test"
        );

        let mut cfg_canonical = cfg.clone();
        cfg_canonical.use_canonical_name = true;
        cfg_canonical.server_name = Some("canonical.test:8080".into());
        assert_eq!(
            server_name_for(&cfg_canonical, &no_host, "127.0.0.1", 80),
            "canonical.test"
        );
        cfg_canonical.server_name = None;
        assert_eq!(
            server_name_for(&cfg_canonical, &no_host, "127.0.0.1", 8080),
            "localhost"
        );
        let mut cfg_host = cfg.clone();
        cfg_host.server_name = None;
        assert_eq!(
            server_name_for(&cfg_host, &req, "127.0.0.1", 8080),
            "example.test"
        );
        assert_eq!(
            server_name_for(&cfg_host, &no_host, "127.0.0.1", 8080),
            "localhost"
        );

        let mut req_abs = cov_req("GET", "/");
        req_abs.headers.insert("host", b"client.test".to_vec());
        let mut cfg_abs = cfg.clone();
        assert_eq!(
            absolute_url_scheme(&cfg_abs, None, &req_abs, "/x", "server.test", 8080, false),
            "http://client.test/x"
        );
        req_abs.headers = Default::default();
        assert_eq!(
            absolute_url_scheme(&cfg_abs, None, &req_abs, "/x", "server.test", 8080, false),
            "http://server.test:8080/x"
        );
        assert_eq!(
            absolute_url_scheme(&cfg_abs, None, &req_abs, "/x", "server.test", 80, false),
            "http://server.test/x"
        );
        assert_eq!(
            absolute_url_scheme(&cfg_abs, None, &req_abs, "/x", "server.test", 443, true),
            "https://server.test/x"
        );
        cfg_abs.use_canonical_name = true;
        cfg_abs.server_name = Some("cfg.test".into());
        assert_eq!(
            absolute_url_scheme(
                &cfg_abs,
                Some(&vhost_name),
                &req_abs,
                "/x",
                "server.test",
                8080,
                true
            ),
            "https://vhost.test:80/x"
        );
        cfg_abs.vhosts.clear();
        assert_eq!(
            absolute_url_scheme(&cfg_abs, None, &req_abs, "/x", "server.test", 8443, true),
            "https://cfg.test/x"
        );
        cfg_abs.server_name = Some("  ".into());
        assert_eq!(
            absolute_url_scheme(&cfg_abs, None, &req_abs, "/x", "server.test", 8443, true),
            "https://server.test:8443/x"
        );
        assert_eq!(
            absolute_url_scheme(&cfg_abs, None, &req_abs, "/x", "server.test", 80, false),
            "http://server.test/x"
        );
        cfg_abs.server_name = Some("cfg.test".into());
        cfg_abs.vhosts = vec![VHost {
            server_name: Some(" ".into()),
            ..vhost_name.clone()
        }];
        assert_eq!(
            absolute_url_scheme(
                &cfg_abs,
                cfg_abs.vhosts.first(),
                &req_abs,
                "/x",
                "server.test",
                8443,
                true
            ),
            "https://server.test:8443/x"
        );

        assert_eq!(canonicalize_rewrite_path("relative"), None);
        assert_eq!(canonicalize_rewrite_path("/a/b/").as_deref(), Some("/a/b/"));
        assert_eq!(canonicalize_rewrite_path("/a/../b").as_deref(), Some("/b"));
        assert_eq!(canonicalize_rewrite_path("/").as_deref(), Some("/"));

        let cleaned = clean_alias_path(Path::new("/a/./b/../c"));
        assert_eq!(cleaned, PathBuf::from("/a/c"));
        assert_eq!(clean_alias_path(Path::new("/..")), PathBuf::from("/"));
        assert_eq!(clean_alias_path(Path::new(".")), PathBuf::new());

        let cfg_dispatch = cfg.clone();
        let resp = dispatch(
            &cfg_dispatch,
            &cov_req("GET", "/missing"),
            cov_peer(),
            "127.0.0.1",
            80,
        );
        assert_eq!(resp.status, 404);

        let mut scope = Scope::default();
        scope
            .mapping_policy
            .redirects
            .push(crate::config::Redirect {
                from: String::new(),
                to: "/never".into(),
                status: 301,
                regex: Some(Arc::new(crate::config::compile_regex("^/nope$").unwrap())),
            });
        scope
            .mapping_policy
            .redirects
            .push(crate::config::Redirect {
                from: "/plain".into(),
                to: "/dest".into(),
                status: 302,
                regex: None,
            });
        let (red, loc) = match_redirect(&scope, "/plain", None).unwrap();
        assert_eq!(red.status, 302);
        assert_eq!(loc, "/dest");
        scope.mapping_policy.redirects.clear();
        scope
            .mapping_policy
            .redirects
            .push(crate::config::Redirect {
                from: "/d/".into(),
                to: "/to/".into(),
                status: 301,
                regex: None,
            });
        let (_, loc) = match_redirect(&scope, "/d/x", None).unwrap();
        assert_eq!(loc, "/to/x");
        let (_, loc) = match_redirect(&scope, "/d/", None).unwrap();
        assert_eq!(loc, "/to/");
        scope.mapping_policy.redirects.clear();
        scope
            .mapping_policy
            .redirects
            .push(crate::config::Redirect {
                from: "/exact".into(),
                to: "/to".into(),
                status: 302,
                regex: None,
            });
        let (_, loc) = match_redirect(&scope, "/exact", None).unwrap();
        assert_eq!(loc, "/to");
        assert!(match_redirect(&scope, "/nothing", None).is_none());
        scope.mapping_policy.redirects.clear();
        scope
            .mapping_policy
            .redirects
            .push(crate::config::Redirect {
                from: String::new(),
                to: String::new(),
                status: 404,
                regex: Some(Arc::new(crate::config::compile_regex("^/empty$").unwrap())),
            });
        let (_, loc) = match_redirect(&scope, "/empty", None).unwrap();
        assert!(loc.is_empty());

        let mut scope = Scope::default();
        scope
            .environment_policy
            .set_env
            .push(crate::scope_policy::Originated::main((
                "OLD".into(),
                "1".into(),
            )));
        scope
            .environment_policy
            .unset_env
            .push(crate::scope_policy::Originated::main("GONE".into()));
        scope.header_policy.vary.push("Accept".into());
        scope.header_policy.cookies.push("a=1".into());
        scope
            .mapping_policy
            .handlers
            .push(crate::config::Handler::add("*".into(), "old".into()));
        let effects = crate::rewrite::Effects {
            env: vec![
                ("OLD".into(), Some(b"2".to_vec())),
                ("GONE".into(), Some(b"3".to_vec())),
                ("NEW".into(), None),
            ],
            late_env: vec![crate::scope_policy::Originated::main((
                "LATE".into(),
                Some(b"4".to_vec()),
            ))],
            cookies: vec!["a=1".into(), "b=2".into()],
            handler: Some("new".into()),
            content_type: Some("text/plain".into()),
            vary: vec!["Accept".into(), "X-Test".into()],
        };
        apply_rewrite_effects(&mut scope, &effects);
        assert_eq!(
            scope
                .environment_policy
                .rewrite_env
                .iter()
                .find(|entry| entry.value.0 == "OLD")
                .unwrap()
                .value
                .1,
            b"2"
        );
        assert!(scope
            .environment_policy
            .rewrite_unset_env
            .iter()
            .any(|entry| entry.value == "NEW"));
        assert!(scope
            .environment_policy
            .rewrite_env
            .iter()
            .any(|entry| entry.value.0 == "GONE" && entry.value.1 == b"3"));
        assert!(scope
            .environment_policy
            .rewrite_late_env
            .iter()
            .any(|entry| entry.value.0 == "LATE" && entry.value.1 == b"4"));
        assert_eq!(scope.header_policy.vary, vec!["Accept", "X-Test"]);
        assert_eq!(scope.header_policy.cookies, vec!["a=1", "b=2"]);
        assert!(scope
            .mapping_policy
            .handlers
            .iter()
            .any(|h| h.handler == "old"));
        // F64: a rewrite `[H=...]` forces the same precedence field a
        // `SetHandler` directive would.
        assert_eq!(
            scope.mapping_policy.set_handler,
            Some(crate::config::SetHandler::Name("new".into()))
        );
        assert_eq!(
            scope.content_policy.force_type.as_deref(),
            Some("text/plain")
        );

        let alias_cfg = cov_config(
            &dir,
            "Alias /prefix /srv/prefix\nAliasMatch \"^/match/(.*)$\" \"/srv/match/$1\"\n",
        );
        let (root, rel, _) = map_path(&alias_cfg, None, b"/other.txt").unwrap();
        assert_eq!(root, dir.join("www"));
        assert_eq!(rel, PathBuf::from("other.txt"));
        let mut manual_cfg = cfg.clone();
        manual_cfg
            .global
            .mapping_policy
            .aliases
            .push(crate::config::Alias {
                virtual_path: String::new(),
                fs_path: PathBuf::from("/srv/unused"),
                script: false,
                regex: Some(Arc::new(crate::config::compile_regex("^/other").unwrap())),
                target_template: None,
            });
        let (root, rel, _) = map_path(&manual_cfg, None, b"/other.txt").unwrap();
        assert_eq!(root, dir.join("www"));
        assert_eq!(rel, PathBuf::from("other.txt"));
        manual_cfg
            .global
            .mapping_policy
            .aliases
            .push(crate::config::Alias {
                virtual_path: String::new(),
                fs_path: dir.join("relative"),
                script: false,
                regex: Some(Arc::new(
                    crate::config::compile_regex("^/relative/(.*)$").unwrap(),
                )),
                target_template: Some("relative/$1".into()),
            });
        let (root, rel, _) = map_path(&manual_cfg, None, b"/relative/file.txt").unwrap();
        assert_eq!(root, dir.join("relative"));
        assert_eq!(rel, PathBuf::from("file.txt"));

        let mut writer = CovWriter::default();
        assert!(write_ws_error(&mut writer, &cfg, 400, b"bad").is_ok());
        assert!(String::from_utf8_lossy(&writer.0).contains("400"));
        assert!(write_ws_error(&mut CovFailWriter, &cfg, 400, b"bad").is_err());
        let mut writer = CovWriter::default();
        let mut response = Response::bytes(200, "text/plain", b"ok".to_vec());
        assert!(write_ws_response(&mut writer, &cfg, &mut response).is_ok());
        assert!(String::from_utf8_lossy(&writer.0).contains("200"));
        let mut response = Response::bytes(200, "text/plain", b"ok".to_vec());
        assert!(write_ws_response(&mut CovFailWriter, &cfg, &mut response).is_err());

        let mut conn = CovDefaultConn;
        conn.set_read_timeout(Some(Duration::from_secs(1)));
        assert!(conn.try_clone_tcp().is_none());
        assert!(conn.take_tls_stream().is_none());
        assert_eq!(conn.write(b"x").unwrap(), 1);
        assert_eq!(conn.flush().unwrap(), ());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn connection_spawn_failure_releases_reserved_slot() {
        let _test_guard = ADMISSION_TEST_LOCK.lock().unwrap();
        let _fault_guard = crate::fault::test_guard();
        let budget = Arc::new(crate::resource::ResourceBudget::default());
        let context = budget.context(IpAddr::from([192, 0, 2, 1]));
        let before = budget.slot_usage(crate::resource::SlotKind::RequestWorker);
        let guard = try_reserve_worker(&context, usize::MAX).unwrap();
        crate::fault::configure(
            "server.connection.spawn",
            0,
            std::io::ErrorKind::OutOfMemory,
        );
        assert!(spawn_connection_worker(move || drop(guard)).is_err());
        assert_eq!(
            budget.slot_usage(crate::resource::SlotKind::RequestWorker),
            before
        );
        crate::fault::clear();
    }

    #[test]
    fn per_client_connection_limit_is_enforced_and_released() {
        let _test_guard = ADMISSION_TEST_LOCK.lock().unwrap();
        assert_eq!(per_client_connection_limit(0), 1);
        assert_eq!(per_client_connection_limit(1), 1);
        assert_eq!(per_client_connection_limit(2), 1);
        assert_eq!(per_client_connection_limit(3), 2);
        assert_eq!(per_client_connection_limit(64), 32);
        assert_eq!(per_client_connection_limit(usize::MAX), 32);
        let client = IpAddr::from([192, 0, 2, 99]);
        let other = IpAddr::from([192, 0, 2, 100]);
        let limit = usize::MAX;
        let budget = Arc::new(crate::resource::ResourceBudget::default());
        let leases: Vec<_> = (0..per_client_connection_limit(limit))
            .map(|_| try_reserve_worker(&budget.context(client), limit).unwrap())
            .collect();
        assert!(try_reserve_worker(&budget.context(client), limit).is_none());
        assert!(try_reserve_worker(&budget.context(other), limit).is_some());
        drop(leases);
        assert!(try_reserve_worker(&budget.context(client), limit).is_some());

        let ipv6: IpAddr = "2001:db8:10:20::1".parse().unwrap();
        let rotated: IpAddr = "2001:db8:10:20:ffff::1".parse().unwrap();
        let other_prefix: IpAddr = "2001:db8:10:21::1".parse().unwrap();
        let leases: Vec<_> = (0..per_client_connection_limit(limit))
            .map(|_| try_reserve_worker(&budget.context(ipv6), limit).unwrap())
            .collect();
        assert!(try_reserve_worker(&budget.context(rotated), limit).is_none());
        assert!(try_reserve_worker(&budget.context(other_prefix), limit).is_some());
        drop(leases);

        let body_limit = 64;
        let body_share = body_worker_limit(body_limit).div_ceil(4);
        let bodies: Vec<_> = (0..body_share)
            .map(|_| try_reserve_body_worker(&budget.context(client), body_limit).unwrap())
            .collect();
        assert!(try_reserve_body_worker(&budget.context(client), body_limit).is_none());
        assert!(try_reserve_body_worker(&budget.context(other), body_limit).is_some());
        drop(bodies);
        assert!(try_reserve_body_worker(&budget.context(client), body_limit).is_some());
    }

    #[test]
    fn admission_limits_reserve_capacity_and_rotate_listeners() {
        assert_eq!(pending_connection_limit(1), 64);
        assert_eq!(pending_connection_limit(128), 256);
        assert_eq!(
            pending_connection_limit(usize::MAX),
            MAX_PENDING_CONNECTIONS
        );
        assert_eq!(body_worker_limit(1), 1);
        assert_eq!(body_worker_limit(16), 4);
        assert_eq!(body_worker_limit(1024), 128);
        assert_eq!(ACCEPT_BATCH, 64);

        assert_eq!(tls_handshake_limit(), MAX_CONCURRENT_TLS_HANDSHAKES);
        let now = Instant::now();
        let client = IpAddr::from([192, 0, 2, 1]);
        let other = IpAddr::from([192, 0, 2, 2]);
        let budget = crate::resource::ResourceBudget::default();
        for _ in 0..MAX_TLS_HANDSHAKES_PER_CLIENT_PER_SECOND {
            assert!(budget.test_rate_admit(
                false,
                Some(client),
                now,
                MAX_TLS_HANDSHAKES_PER_SECOND as u64,
                MAX_TLS_HANDSHAKES_PER_CLIENT_PER_SECOND as u64,
            ));
        }
        assert!(!budget.test_rate_admit(false, Some(client), now, 128, 64));
        assert!(budget.test_rate_admit(false, Some(other), now, 128, 64));
        assert!(budget.test_rate_admit(false, Some(client), now + Duration::from_secs(1), 128, 64,));

        let global_rate = crate::resource::ResourceBudget::default();
        for n in 0..MAX_TLS_HANDSHAKES_PER_SECOND {
            let ip = IpAddr::from([198, 51, (n / 256) as u8, (n % 256) as u8]);
            assert!(global_rate.test_rate_admit(false, Some(ip), now, 128, 64));
        }
        assert!(!global_rate.test_rate_admit(
            false,
            Some(IpAddr::from([203, 0, 113, 1])),
            now,
            128,
            64,
        ));

        assert_eq!(listener_index(0, 0, 3), 0);
        assert_eq!(listener_index(0, 1, 3), 1);
        assert_eq!(listener_index(1, 0, 3), 1);
        assert_eq!(listener_index(1, 2, 3), 0);
        assert_eq!(listener_index(2, 0, 3), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_admission_head_is_bounded_and_preserves_body_bytes() {
        let input = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nbody";
        let mut reader = &input[..];
        let budget = Arc::new(crate::resource::ResourceBudget::default());
        let (bytes, head_end, resident) = read_first_request_head(
            &mut reader,
            Duration::from_secs(1),
            budget.clone(),
            IpAddr::from([127, 0, 0, 1]),
        )
        .await
        .unwrap();
        assert_eq!(&bytes[..head_end], &input[..head_end]);
        assert_eq!(&bytes[head_end..], b"body");
        assert_eq!(resident.bytes(), input.len() as u64 + head_end as u64);
        let charged = resident.bytes();
        let mut limits = Limits::default();
        limits.resource_budget = budget.clone();
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        let mut buf = bytes;
        let request = read_request_with_reservation(
            &mut cursor,
            &mut buf,
            &limits,
            |_, _| Ok(None),
            Some(resident),
        )
        .unwrap()
        .unwrap();
        assert_eq!(request.body, b"body");
        assert_eq!(budget.extended_usage().1, charged + 4);
        drop(request);
        assert_eq!(budget.extended_usage().1, 0);

        let mut oversized = vec![b'a'; crate::http::MAX_HEAD_TOTAL + 1];
        oversized.extend_from_slice(b"\r\n\r\n");
        let mut reader = oversized.as_slice();
        let error = read_first_request_head(
            &mut reader,
            Duration::from_secs(1),
            Arc::new(crate::resource::ResourceBudget::default()),
            IpAddr::from([127, 0, 0, 1]),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    fn cov_ws_request(path: &str) -> String {
        format!(
            "GET {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
    }

    fn cov_run_conn(cfg: &Config, request: &str, port: u16) -> (String, io::Result<()>) {
        let mut conn = ScriptConn::new(request.as_bytes());
        let logger = cov_logger(cfg);
        let result = handle_connection(
            cfg,
            &logger,
            &mut conn,
            cov_peer(),
            "127.0.0.1",
            port,
            false,
            Vec::new(),
            None,
            None,
            None,
        );
        (String::from_utf8_lossy(&conn.output).into_owned(), result)
    }

    fn cov_status(text: &str) -> u16 {
        text.split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    #[test]
    fn keep_alive_request_bodies_reenter_the_slow_body_admission_gate() {
        let _test_guard = ADMISSION_TEST_LOCK.lock().unwrap();
        let dir = cov_dir("keepalive-body-admission");
        std::fs::write(dir.join("www/file.txt"), "hello\n").unwrap();
        let mut cfg = cov_config(&dir, "");
        cfg.body_handlers_possible = true;
        cfg.max_request_workers = 4;
        let saturated_context = cfg.resource_budget.context(cov_peer().ip());
        let saturated =
            try_reserve_body_worker(&saturated_context, cfg.max_request_workers).unwrap();
        let request = "GET /file.txt HTTP/1.1\r\nHost: localhost\r\n\r\n\
                       POST /file.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody";
        let (response, result) = cov_run_conn(&cfg, request, 80);
        result.unwrap();
        assert_eq!(response.matches("HTTP/1.1 200").count(), 1, "{response}");
        assert_eq!(response.matches("HTTP/1.1 503").count(), 1, "{response}");
        drop(saturated);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn static_only_post_is_rejected_before_body_ingestion() {
        let dir = cov_dir("static-body-early-reject");
        std::fs::write(dir.join("www/file.txt"), "hello\n").unwrap();
        let cfg = cov_config(&dir, "");
        assert!(!cfg.body_handlers_possible());
        let request =
            "POST /file.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000000000\r\n\r\n";
        let (response, result) = cov_run_conn(&cfg, request, 80);
        result.unwrap();
        assert_eq!(cov_status(&response), 405, "{response}");
        assert_eq!(cfg.resource_budget.usage(), (0, 0, 0));

        let request = "GET /file.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n";
        let (response, result) = cov_run_conn(&cfg, request, 80);
        result.unwrap();
        assert_eq!(cov_status(&response), 400, "{response}");
        assert_eq!(cfg.resource_budget.usage(), (0, 0, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saturated_response_read_budget_does_not_replace_http1_file_response() {
        let dir = cov_dir("p30-http1-read-scope");
        let body = vec![b'p'; 100 * 1024];
        std::fs::write(dir.join("www/large.bin"), &body).unwrap();
        let cfg = cov_config(&dir, "");
        let read_leases: Vec<_> = (0..crate::resource::MAX_RESPONSE_BODY_READS)
            .map(|_| cfg.resource_budget.try_response_body_read().unwrap())
            .collect();
        assert!(cfg.resource_budget.try_response_body_read().is_err());

        let mut conn = ScriptConn::new(
            b"GET /large.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        handle_connection(
            &cfg,
            &cov_logger(&cfg),
            &mut conn,
            cov_peer(),
            "127.0.0.1",
            80,
            false,
            Vec::new(),
            None,
            None,
            None,
        )
        .unwrap();
        let (head, response_body) = conn.output.split_at(
            conn.output
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .unwrap()
                + 4,
        );
        assert!(head.starts_with(b"HTTP/1.1 200 OK"));
        assert_eq!(response_body, body);
        assert_eq!(
            cfg.resource_budget.extended_usage().3,
            read_leases.len() as u64
        );
        drop(read_leases);
        assert_eq!(cfg.resource_budget.extended_usage().3, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_handle_connection_websocket_paths() {
        let dir = cov_dir("ws");
        std::fs::write(dir.join("www/file.txt"), "hello\n").unwrap();
        let cfg = cov_config(&dir, "");
        let mut normal = ScriptConn::new(
            b"GET /file.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        let logger = cov_logger(&cfg);
        handle_connection(
            &cfg,
            &logger,
            &mut normal,
            cov_peer(),
            "127.0.0.1",
            80,
            false,
            Vec::new(),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(cov_status(&String::from_utf8_lossy(&normal.output)), 200);

        let mut failing = ScriptConn::new(
            b"GET /file.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        failing.fail_write = true;
        assert!(handle_connection(
            &cfg,
            &logger,
            &mut failing,
            cov_peer(),
            "127.0.0.1",
            80,
            false,
            Vec::new(),
            None,
            None,
            None,
        )
        .is_ok());

        for path in ["/%zz", "*"] {
            let (text, result) = cov_run_conn(&cfg, &cov_ws_request(path), 80);
            result.unwrap();
            assert_eq!(cov_status(&text), 400, "{path}: {text}");
        }
        let mut raw_ws = b"GET /".to_vec();
        raw_ws.push(0xff);
        raw_ws.extend_from_slice(
            b" HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n\
              Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        );
        let mut raw_conn = ScriptConn::new(&raw_ws);
        handle_connection(
            &cfg,
            &logger,
            &mut raw_conn,
            cov_peer(),
            "127.0.0.1",
            80,
            false,
            Vec::new(),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(cov_status(&String::from_utf8_lossy(&raw_conn.output)), 400);

        let map_cfg = cov_config(&dir, "AliasMatch \"^/escape(.*)$\" \"$1\"\n");
        let (text, result) = cov_run_conn(&map_cfg, &cov_ws_request("/escape/tmp/elsewhere"), 80);
        result.unwrap();
        assert_eq!(cov_status(&text), 404, "{text}");

        std::fs::create_dir_all(dir.join("www/bad")).unwrap();
        std::fs::write(dir.join("www/bad/file.txt"), "x\n").unwrap();
        std::fs::write(dir.join("www/bad/.htaccess"), "Header \"unterminated\n").unwrap();
        let ht_cfg = cov_config(
            &dir,
            &format!(
                "<Directory \"{}/www/bad\">\nAllowOverride All\n</Directory>\n",
                dir.display()
            ),
        );
        let (text, result) = cov_run_conn(&ht_cfg, &cov_ws_request("/bad/file.txt"), 80);
        result.unwrap();
        assert_eq!(cov_status(&text), 500, "{text}");

        let rewrite_cfg = cov_config(
            &dir,
            "RewriteEngine On\n\
             RewriteRule ^/wsforbid$ - [F]\n\
             RewriteRule ^/wsgone$ - [G]\n\
             RewriteRule ^/wsloop$ /wsloop [N]\n\
             RewriteRule ^/wsredirect$ /target [R=302]\n\
             RewriteRule ^/wsinternal$ /file.txt [L]\n\
             RewriteRule ^/wsproxy$ http://127.0.0.1:9/echo [P]\n\
             RewriteRule ^/wsproxy/$ http://127.0.0.1:9/echo [P]\n\
             RewriteRule ^/wsbadproxy$ not-a-url [P]\n",
        );
        for (path, expected) in [
            ("/wsforbid", 403),
            ("/wsgone", 410),
            ("/wsloop", 500),
            ("/wsredirect", 403),
            ("/wsinternal", 403),
            ("/wsproxy", 501),
            ("/wsproxy/", 501),
            ("/wsbadproxy", 502),
        ] {
            let (text, result) = cov_run_conn(&rewrite_cfg, &cov_ws_request(path), 80);
            result.unwrap();
            assert_eq!(cov_status(&text), expected, "{path}: {text}");
        }

        let limit_cfg = cov_config(
            &dir,
            "RewriteEngine On\n\
             RewriteRule ^/wsproxy$ http://127.0.0.1:9/echo [P]\n\
             <Location \"/wsproxy\">\nAllowMethods POST\n</Location>\n",
        );
        let (text, result) = cov_run_conn(&limit_cfg, &cov_ws_request("/wsproxy"), 80);
        result.unwrap();
        assert_eq!(cov_status(&text), 405, "{text}");

        let deny_cfg = cov_config(
            &dir,
            "RewriteEngine On\n\
             RewriteRule ^/wsproxy$ http://127.0.0.1:9/echo [P]\n\
             <Location \"/wsproxy\">\nRequire all denied\n</Location>\n",
        );
        let (text, result) = cov_run_conn(&deny_cfg, &cov_ws_request("/wsproxy"), 80);
        result.unwrap();
        assert_eq!(cov_status(&text), 403, "{text}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exhausted_request_spool_returns_503_instead_of_dropping_connection() {
        let dir = cov_dir("spool-503");
        let mut cfg = cov_config(&dir, "");
        cfg.body_handlers_possible = true;
        cfg.max_spool_bytes = 1024;
        cfg.max_spool_files = 1;
        let body_len = crate::http::MAX_REQUEST_BODY_IN_MEMORY + 1;
        let mut wire = format!(
            "POST /file.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: {body_len}\r\n\r\n"
        )
        .into_bytes();
        wire.extend(std::iter::repeat_n(b'x', body_len as usize));
        let mut conn = ScriptConn::new(&wire);
        handle_connection(
            &cfg,
            &cov_logger(&cfg),
            &mut conn,
            cov_peer(),
            "127.0.0.1",
            80,
            false,
            Vec::new(),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(cov_status(&String::from_utf8_lossy(&conn.output)), 503);
        assert_eq!(cfg.resource_budget.usage(), (0, 0, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn cov_dispatch(cfg: &Config, method: &str, path: &str) -> Response {
        let req = cov_req(method, path);
        dispatch(cfg, &req, cov_peer(), "127.0.0.1", 80)
    }

    #[test]
    fn deep_static_policy_paths_return_414_without_harming_dispatch() {
        let dir = cov_dir("p29-deep-static-path");
        std::fs::write(dir.join("www/ok.txt"), "ok\n").unwrap();
        let cfg = cov_config(&dir, "");
        assert!(!cfg.cgi_path_info_possible());
        let deep = format!("/{}missing", "x/".repeat(300));
        assert_eq!(cov_dispatch(&cfg, "GET", &deep).status, 414);
        assert_eq!(cov_dispatch(&cfg, "GET", "/ok.txt").status, 200);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn access_file_rewrite_cannot_expand_into_an_unbounded_policy_walk() {
        let dir = cov_dir("p29-rewrite-path");
        std::fs::create_dir(dir.join("www/rw")).unwrap();
        std::fs::write(dir.join("www/ok.txt"), "ok\n").unwrap();
        std::fs::write(
            dir.join("www/rw/.htaccess"),
            format!(
                "RewriteEngine On\nRewriteRule ^(.*)$ /x/{} [L]\n",
                "$1".repeat(80)
            ),
        )
        .unwrap();
        let cfg = cov_config(
            &dir,
            &format!(
                "<Directory \"{}/www/rw\">\nAllowOverride FileInfo\nRequire all granted\n</Directory>\n",
                dir.display()
            ),
        );
        let attack = format!("/rw/{}a", "a/".repeat(250));
        assert_eq!(cov_dispatch(&cfg, "GET", &attack).status, 414);
        assert_eq!(cov_dispatch(&cfg, "GET", "/ok.txt").status, 200);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn dispatch_returns_authenticated_identity_for_access_logging() {
        use base64::Engine as _;
        use sha1::{Digest, Sha1};

        let dir = cov_dir("access-log-identity");
        std::fs::write(dir.join("www/file.txt"), "ok\n").unwrap();
        let mut hasher = Sha1::new();
        hasher.update(b"secret");
        let digest = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        let htpasswd = dir.join(".htpasswd");
        std::fs::write(&htpasswd, format!("alice:{{SHA}}{digest}\n")).unwrap();
        let cfg = cov_config(
            &dir,
            &format!(
                "<Directory \"{}/www\">\n\
                 AuthType Basic\n\
                 AuthName test\n\
                 AuthUserFile \"{}\"\n\
                 Require valid-user\n\
                 </Directory>\n",
                dir.display(),
                htpasswd.display(),
            ),
        );
        let mut req = cov_req("GET", "/file.txt");
        let token = base64::engine::general_purpose::STANDARD.encode(b"alice:secret");
        req.headers
            .insert("authorization", format!("Basic {token}").into_bytes());

        let (response, remote_user) =
            dispatch_with_scheme_and_identity(&cfg, &req, cov_peer(), "127.0.0.1", 80, false);
        assert_eq!(response.status, 200);
        assert_eq!(remote_user.as_deref(), Some("alice"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn final_sinks_recheck_disabled_compatibility_capabilities() {
        use std::os::unix::fs::PermissionsExt;

        let dir = cov_dir("disabled-capability-sinks");
        std::fs::create_dir_all(dir.join("www/listing")).unwrap();
        std::fs::create_dir_all(dir.join("cgi-bin")).unwrap();
        std::fs::write(dir.join("www/listing/item.txt"), "item\n").unwrap();
        std::fs::write(dir.join("www/status"), "not status\n").unwrap();
        std::fs::write(dir.join("www/script.php"), "<?php\n").unwrap();
        let script = dir.join("cgi-bin/run.cgi");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nran\\n'\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let cfg = cov_config(
            &dir,
            &format!(
                "TraceEnable On\n\
                 <Location /status>\nSetHandler server-status\n</Location>\n\
                 <Directory \"{}/www/listing\">\nOptions Indexes\n</Directory>\n\
                 ScriptAlias /cgi-bin/ \"{}/cgi-bin/\"\n\
                 ProxyPassMatch ^/(.*\\.php)$ \"unix:/tmp/vapache-missing.sock|fcgi://localhost{}/www/\"\n",
                dir.display(),
                dir.display(),
                dir.display(),
            ),
        );

        let audit_only = cov_capability_audit_config(&dir, "TraceEnable On\n");
        assert_eq!(cov_dispatch(&audit_only, "GET", "/").status, 500);
        let audit_server = Server::new(
            Arc::new(audit_only.clone()),
            Arc::new(cov_logger(&audit_only)),
        );
        assert_eq!(
            audit_server.run(&[]).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        let mut disabled = cfg.clone();
        disabled.capabilities.set(Capability::Trace, false);
        assert_eq!(cov_dispatch(&disabled, "TRACE", "/").status, 405);

        let mut disabled = cfg.clone();
        disabled.capabilities.set(Capability::ServerStatus, false);
        assert_eq!(cov_dispatch(&disabled, "GET", "/status").status, 403);

        let mut disabled = cfg.clone();
        disabled.capabilities.set(Capability::AutoIndex, false);
        assert_eq!(cov_dispatch(&disabled, "GET", "/listing/").status, 403);

        let mut disabled = cfg.clone();
        disabled.capabilities.set(Capability::Cgi, false);
        assert_eq!(
            cov_dispatch(&disabled, "GET", "/cgi-bin/run.cgi").status,
            403
        );

        let mut disabled = cfg;
        disabled.capabilities.set(Capability::FastCgi, false);
        assert_eq!(cov_dispatch(&disabled, "GET", "/script.php").status, 403);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_dispatch_protocol_and_redirect_edges() {
        let dir = cov_dir("dispatch-protocol");
        std::fs::write(dir.join("www/file.txt"), "hello\n").unwrap();
        let cfg = cov_config(
            &dir,
            "TraceEnable On\n\
             Header always set X-Static-Policy present\n\
             Redirect 302 /redir /dest\n\
             Redirect 404 /gone\n\
             Redirect 302 /relrel dest\n\
             RedirectMatch 404 ^/empty$\n",
        );
        let mut req = cov_req("TRACE", "/");
        req.headers.insert("x-test", b"yes".to_vec());
        let resp = dispatch(&cfg, &req, cov_peer(), "127.0.0.1", 80);
        assert_eq!(resp.status, 200);
        let body = match resp.body {
            Body::Bytes(b) => b,
            _ => panic!("trace body"),
        };
        assert!(String::from_utf8_lossy(&body).contains("x-test: yes"));

        for path in ["*", "/file.txt"] {
            let response = cov_dispatch(&cfg, "OPTIONS", path);
            assert_eq!(response.status, 200);
            assert!(response.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("x-static-policy") && value == b"present"
            }));
        }
        assert_eq!(cov_dispatch(&cfg, "GET", "*").status, 400);
        assert_eq!(cov_dispatch(&cfg, "HEAD", "*").status, 400);
        assert_eq!(cov_dispatch(&cfg, "GET", "/file.txt/").status, 404);

        let mut metadata_scope = Scope::default();
        metadata_scope.header_policy.vary.push("Origin".into());
        metadata_scope.header_policy.cookies.push("a=1".into());
        metadata_scope.header_policy.expires_active = Some(true);
        metadata_scope.header_policy.expires_default = Some("access plus 1 hour".into());
        let metadata = options_response(&cfg, &metadata_scope, Some("text/plain".into()));
        for name in ["vary", "set-cookie", "expires", "cache-control"] {
            assert!(metadata
                .headers
                .iter()
                .any(|(header, _)| header.eq_ignore_ascii_case(name)));
        }

        let mut cfg_no_trace = cov_config(&dir, "TraceEnable Off\n");
        assert_eq!(cov_dispatch(&cfg_no_trace, "TRACE", "/").status, 405);
        cfg_no_trace.trace_enable = false;
        assert_eq!(cov_dispatch(&cfg, "BREW", "/").status, 501);
        assert_eq!(cov_dispatch(&cfg, "OPTIONS", "*").status, 200);
        let mut star = cov_req("GET", "/");
        star.raw_path = b"*".to_vec();
        star.target = b"*".to_vec();
        assert_eq!(
            dispatch(&cfg, &star, cov_peer(), "127.0.0.1", 80).status,
            400
        );
        assert_eq!(cov_dispatch(&cfg, "GET", "/%zz").status, 404);
        let mut non_utf8 = cov_req("GET", "/");
        non_utf8.target = b"/\xff".to_vec();
        non_utf8.raw_path = b"/\xff".to_vec();
        assert_eq!(
            dispatch(&cfg, &non_utf8, cov_peer(), "127.0.0.1", 80).status,
            400
        );
        non_utf8.method = "BREW".into();
        assert_eq!(
            dispatch(&cfg, &non_utf8, cov_peer(), "127.0.0.1", 80).status,
            400
        );
        assert_eq!(cov_dispatch(&cfg, "GET", "/redir").status, 302);
        assert_eq!(cov_dispatch(&cfg, "GET", "/redir/x").status, 302);
        assert_eq!(cov_dispatch(&cfg, "GET", "/gone").status, 404);
        let rel = cov_dispatch(&cfg, "GET", "/relrel");
        assert_eq!(rel.status, 302);
        assert!(rel
            .headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("location") && v == b"dest"));
        let head = cov_dispatch(&cfg, "HEAD", "/redir");
        assert_eq!(head.status, 302);
        assert_eq!(head.body_len(), 0);
        let empty = cov_dispatch(&cfg, "GET", "/empty");
        assert_eq!(empty.status, 404);

        let proto_cfg = cov_config(
            &dir,
            "RewriteEngine On\nRewriteRule ^/proto$ //example.com/x [R=302]\n",
        );
        let proto = cov_dispatch(&proto_cfg, "GET", "/proto");
        assert_eq!(proto.status, 302);
        assert!(proto
            .headers
            .iter()
            .any(|(n, v)| { n.eq_ignore_ascii_case("location") && v == b"http://example.com/x" }));

        let map_cfg = cov_config(
            &dir,
            "Alias /nomatch /srv/nomatch\n\
             AliasMatch \"^/some/(.*)$\" \"/srv/$1\"\n\
             AliasMatch \"^/bad(.*)$\" \"$1\"\n\
             RewriteEngine On\n\
             RewriteRule ^/rmap$ /bad/tmp/elsewhere [L]\n",
        );
        assert_eq!(cov_dispatch(&map_cfg, "GET", "/file.txt").status, 200);
        assert_eq!(
            cov_dispatch(&map_cfg, "GET", "/bad/tmp/elsewhere").status,
            404
        );
        assert_eq!(cov_dispatch(&map_cfg, "GET", "/rmap").status, 404);

        let end_cfg = cov_config(
            &dir,
            "RewriteEngine On\nRewriteRule ^/end$ /file.txt [END]\n",
        );
        assert_eq!(cov_dispatch(&end_cfg, "GET", "/end").status, 200);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_dispatch_rewrite_failures_and_proxy_gate() {
        let dir = cov_dir("dispatch-rewrites");
        std::fs::write(dir.join("www/file.txt"), "hello\n").unwrap();
        std::fs::create_dir_all(dir.join("www/bad")).unwrap();
        std::fs::write(dir.join("www/bad/.htaccess"), "Header \"unterminated\n").unwrap();
        let cfg = cov_config(
            &dir,
            &format!(
                "RewriteEngine On\n\
                 RewriteRule ^/forbid$ - [F]\n\
                 RewriteRule ^/gone$ - [G]\n\
                 RewriteRule ^/loop$ /loop [N]\n\
                 RewriteRule ^/redirect$ /file.txt [R=302]\n\
                 RewriteRule ^/internal$ /file.txt [L]\n\
                 RewriteRule ^/badrewrite$ /bad/x [L]\n\
                 RewriteRule ^/query$ /file.txt?covered=1 [L]\n\
                 RewriteRule ^/proxybad$ not-a-url [P]\n\
                 RewriteRule ^/proxy$ http://127.0.0.1:9/echo [P]\n\
                 <Directory \"{}/www/bad\">\nAllowOverride All\n</Directory>\n",
                dir.display()
            ),
        );
        assert_eq!(cov_dispatch(&cfg, "GET", "/forbid").status, 403);
        assert_eq!(cov_dispatch(&cfg, "GET", "/gone").status, 410);
        assert_eq!(cov_dispatch(&cfg, "GET", "/loop").status, 500);
        assert_eq!(cov_dispatch(&cfg, "GET", "/redirect").status, 302);
        assert_eq!(cov_dispatch(&cfg, "GET", "/internal").status, 200);
        assert_eq!(cov_dispatch(&cfg, "GET", "/badrewrite").status, 500);
        assert_eq!(cov_dispatch(&cfg, "GET", "/query").status, 200);
        assert_eq!(cov_dispatch(&cfg, "GET", "/proxybad").status, 502);
        assert!(matches!(
            cov_dispatch(&cfg, "GET", "/proxy").status,
            200 | 502
        ));

        let gated_cfg = cov_config(
            &dir,
            "RewriteEngine On\n\
             RewriteRule ^/guard$ /stage [L]\n\
             RewriteRule ^/stage$ http://127.0.0.1:9/echo [P]\n\
             <Location \"/guard\">\nRequire all denied\n</Location>\n",
        );
        assert_eq!(cov_dispatch(&gated_cfg, "GET", "/guard").status, 403);

        let method_cfg = cov_config(
            &dir,
            "RewriteEngine On\n\
             RewriteRule ^/proxy$ http://127.0.0.1:9/echo [P]\n\
             <Location \"/proxy\">\nAllowMethods POST\n</Location>\n",
        );
        assert_eq!(cov_dispatch(&method_cfg, "GET", "/proxy").status, 405);

        let redirect_gate_cfg = cov_config(
            &dir,
            "RewriteEngine On\n\
             RewriteRule ^/guardredir$ /stage-redir [L]\n\
             RewriteRule ^/stage-redir$ http://127.0.0.1:9/echo [P]\n\
             <Location \"/guardredir\">\nRequire all denied\n</Location>\n",
        );
        assert_eq!(
            cov_dispatch(&redirect_gate_cfg, "GET", "/guardredir").status,
            403
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_target_binding_and_script_error_paths() {
        let dir = cov_dir("target-errors");
        std::fs::create_dir_all(dir.join("www/bad")).unwrap();
        std::fs::write(dir.join("www/a.txt"), "a\n").unwrap();
        std::fs::write(dir.join("www/bad/file.txt"), "bad\n").unwrap();
        std::fs::write(dir.join("www/bad/.htaccess"), "Header \"unterminated\n").unwrap();
        let cfg = cov_config(
            &dir,
            &format!(
                "<Directory \"{}/www/bad\">\nAllowOverride All\n</Directory>\n",
                dir.display()
            ),
        );
        let req = cov_req("GET", "/a.txt");
        let peer = cov_peer().ip();
        let map_root = cfg.documentation_root_for(None);
        let fs_path = dir.join("www/a.txt");
        let meta = std::fs::metadata(&fs_path).unwrap();
        let scope = Scope::default();
        let other = access::ResourceKey::request(None, &req, "/other", None, None);
        let grant = access::check_grant(&scope, &req, peer, None, "/x", None, other).unwrap();
        let effects = crate::rewrite::Effects::default();
        let (_, _, _) = (grant.key(), &scope, &effects);
        let err = bind_target_grant(
            &cfg,
            None,
            &scope,
            &grant,
            &fs_path,
            &fs_path,
            &map_root,
            &meta,
            "/a.txt",
            &req,
            peer,
            80,
            "localhost",
            "127.0.0.1",
            &effects,
        )
        .err()
        .expect("mismatched grant");
        assert_eq!(err.status, 500);

        let target = dir.join("www/bad/file.txt");
        let target_meta = std::fs::metadata(&target).unwrap();
        let wildcard = access::test_grant();
        let err = bind_target_grant(
            &cfg,
            None,
            &scope,
            &wildcard,
            &fs_path,
            &target,
            &map_root,
            &target_meta,
            "/a.txt",
            &req,
            peer,
            80,
            "localhost",
            "127.0.0.1",
            &effects,
        )
        .err()
        .expect("target scope error");
        assert_eq!(err.status, 500);

        let err = authorize_resolved_target(
            &cfg,
            None,
            &req,
            peer,
            &target,
            "/bad/file.txt",
            &scope,
            None,
            &map_root,
            80,
            "localhost",
            "127.0.0.1",
        )
        .err()
        .expect("resolved target error");
        assert_eq!(err.status, 500);

        let err = authorize_original_request(
            &cfg,
            None,
            &req,
            "/bad/file.txt",
            &target,
            &map_root,
            80,
            "localhost",
            cov_peer(),
            "127.0.0.1",
            &effects,
        )
        .err()
        .expect("original target error");
        assert_eq!(err.status, 500);

        let script = dir.join("www/script.cgi");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nok\\n'\n",
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        let script_file = std::fs::File::open(&script).unwrap();
        let script_meta = script_file.metadata().unwrap();
        let script_req = cov_req("GET", "/script.cgi");
        let script_resource =
            access::ResourceKey::request(None, &script_req, "/script.cgi", Some(&script), None);
        let script_grant = access::check_grant(
            &scope,
            &script_req,
            peer,
            None,
            "/script.cgi",
            None,
            script_resource.clone(),
        )
        .unwrap();
        let err = run_cgi(
            &cfg,
            None,
            &script_req,
            &dir.join("www"),
            Path::new("script.cgi"),
            "/script.cgi",
            "",
            "/script.cgi",
            "localhost",
            cov_peer(),
            "127.0.0.1",
            80,
            &scope,
            &grant,
            &script_resource,
            None,
            None,
        );
        assert_eq!(err.status, 500);

        let mut symlink_scope = Scope::default();
        symlink_scope.options.push_remove(Options::FOLLOW_SYMLINKS);
        symlink_scope
            .options
            .push_add(Options::SYMLINKS_IF_OWNER_MATCH);
        let script_grant = access::check_grant(
            &symlink_scope,
            &script_req,
            peer,
            None,
            "/script.cgi",
            None,
            script_resource.clone(),
        )
        .unwrap();
        let resp = run_cgi(
            &cfg,
            None,
            &script_req,
            &dir.join("www"),
            Path::new("script.cgi"),
            "/script.cgi",
            "",
            "/script.cgi",
            "localhost",
            cov_peer(),
            "127.0.0.1",
            80,
            &symlink_scope,
            &script_grant,
            &script_resource,
            Some(&script_file),
            Some(&script_meta),
        );
        assert_eq!(resp.status, 200);

        let mut auth_scope = Scope::default();
        auth_scope.authorization.auth_type = Some("Basic".into());
        auth_scope.authorization.add_require(
            crate::config::RequireNode::Provider(crate::config::Require::AllGranted),
            None,
        );
        let mut auth_resource =
            access::ResourceKey::request(None, &script_req, "/script.cgi", Some(&script), None);
        auth_resource.identity = Some("alice".into());
        let auth_grant = access::check_grant(
            &auth_scope,
            &script_req,
            peer,
            None,
            "/script.cgi",
            None,
            auth_resource.clone(),
        )
        .unwrap();
        let resp = run_cgi(
            &cfg,
            None,
            &script_req,
            &dir.join("www"),
            Path::new("script.cgi"),
            "/script.cgi",
            "",
            "/script.cgi",
            "localhost",
            cov_peer(),
            "127.0.0.1",
            80,
            &auth_scope,
            &auth_grant,
            &auth_resource,
            Some(&script_file),
            Some(&script_meta),
        );
        assert_eq!(resp.status, 200);

        let mut digest_scope = Scope::default();
        digest_scope.authorization.auth_type = Some("Digest".into());
        let resp = run_cgi(
            &cfg,
            None,
            &script_req,
            &dir.join("www"),
            Path::new("script.cgi"),
            "/script.cgi",
            "",
            "/script.cgi",
            "localhost",
            cov_peer(),
            "127.0.0.1",
            80,
            &digest_scope,
            &auth_grant,
            &auth_resource,
            Some(&script_file),
            Some(&script_meta),
        );
        assert_eq!(resp.status, 200);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_server_run_loop_busy_and_poll_errors() {
        let _test_guard = ADMISSION_TEST_LOCK.lock().unwrap();
        let dir = cov_dir("run-loop");
        let mut cfg = cov_config(&dir, "");
        cfg.max_request_workers = 1;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bound = vec![Bound {
            listener,
            port: addr.port(),
            addr: "127.0.0.1".into(),
            tls: None,
            pending_tls: None,
        }];
        let server = Server::new(Arc::new(cfg.clone()), Arc::new(cov_logger(&cfg)));
        let err = server
            .run_with_poll(&bound, |_| Err(io::Error::from_raw_os_error(libc::EFAULT)))
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EFAULT));

        let saturated_context = cfg.resource_budget.context(cov_peer().ip());
        let saturated = try_reserve_worker(&saturated_context, 1).unwrap();
        let stop = server.stop_flag();
        let handle = std::thread::spawn(move || {
            server.run_with_poll(&bound, |pollfds| {
                let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, 20) };
                poll_result(
                    rc,
                    io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EINVAL),
                )
            })
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut text = String::new();
        client.read_to_string(&mut text).unwrap();
        assert!(text.contains("503"), "{text}");
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();
        drop(saturated);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idle_http1_keepalive_releases_request_worker() {
        let _test_guard = ADMISSION_TEST_LOCK.lock().unwrap();
        let dir = cov_dir("event-keepalive");
        std::fs::write(dir.join("www/index.html"), "ok\n").unwrap();
        let mut cfg = cov_config(&dir, "KeepAlive On\nKeepAliveTimeout 5\n");
        cfg.max_request_workers = 1;
        let budget = cfg.resource_budget.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bound = vec![Bound {
            listener,
            port: addr.port(),
            addr: "127.0.0.1".into(),
            tls: None,
            pending_tls: None,
        }];
        let server = Server::new(Arc::new(cfg.clone()), Arc::new(cov_logger(&cfg)));
        let stop = server.stop_flag();
        let handle = std::thread::spawn(move || server.run(&bound));
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        fn read_head(stream: &mut TcpStream) -> Vec<u8> {
            let mut response = Vec::new();
            let mut byte = [0u8; 1];
            while !response.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                response.push(byte[0]);
            }
            response
        }

        client
            .write_all(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let first = read_head(&mut client);
        assert!(String::from_utf8_lossy(&first).starts_with("HTTP/1.1 200"));
        for _ in 0..100 {
            if budget.slot_usage(crate::resource::SlotKind::RequestWorker) == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            budget.slot_usage(crate::resource::SlotKind::RequestWorker),
            0,
            "an idle keep-alive socket retained its request worker"
        );
        assert_eq!(
            budget.slot_usage(crate::resource::SlotKind::H1Connection),
            1
        );

        client
            .write_all(b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let second = read_head(&mut client);
        assert!(String::from_utf8_lossy(&second).starts_with("HTTP/1.1 200"));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn body_policy_runs_before_continue_or_upload() {
        let _test_guard = ADMISSION_TEST_LOCK.lock().unwrap();
        let dir = cov_dir("lazy-body-policy");
        std::fs::write(dir.join("www/index.html"), "not reachable\n").unwrap();
        let mut cfg = cov_config(&dir, "<Location \"/\">\nRequire all denied\n</Location>\n");
        cfg.max_request_workers = 2;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bound = vec![Bound {
            listener,
            port: addr.port(),
            addr: "127.0.0.1".into(),
            tls: None,
            pending_tls: None,
        }];
        let server = Server::new(Arc::new(cfg.clone()), Arc::new(cov_logger(&cfg)));
        let stop = server.stop_flag();
        let handle = std::thread::spawn(move || server.run(&bound));

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(!response.contains("100 Continue"), "{response}");

        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepared_body_handler_does_not_repeat_policy_compilation() {
        let dir = cov_dir("prepared-body-handler");
        let cfg = cov_config(&dir, "ProxyPass /upload http://127.0.0.1:9/\n");
        let peer = cov_peer();
        let mut request = cov_req("POST", "/upload");
        request.framing = crate::verified::BodyFraming::Length(4);
        request
            .headers
            .bind_request_scope(crate::resource::RequestScope::new(
                cfg.resource_budget.context(peer.ip()),
            ));

        let (handler, remote_user) =
            match probe_request_body(&cfg, &mut request, peer, "127.0.0.1", 80, false) {
                BodyRouteDecision::Read {
                    handler,
                    remote_user,
                } => (handler, remote_user),
                BodyRouteDecision::Drain(_, _) => panic!("proxy route selected static drain"),
                BodyRouteDecision::Respond(response, _) => {
                    panic!("proxy body route returned {}", response.status)
                }
            };
        let compiled_work = request.policy_budget().charged_work();
        request.body = b"body".to_vec();
        let response = execute_prepared_handler(&cfg, &mut request, peer, 80, false, handler);
        assert_eq!(response.status, 502);
        assert!(remote_user.is_none());
        assert_eq!(
            request.policy_budget().charged_work(),
            compiled_work,
            "executing a prepared body handler repeated route/policy work"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn http1_body_timeout_completes_the_error_output_phase() {
        let _test_guard = ADMISSION_TEST_LOCK.lock().unwrap();
        let dir = cov_dir("http1-body-timeout");
        let mut cfg = cov_config(&dir, "ProxyPass /upload http://127.0.0.1:9/\n");
        cfg.request_body_timeout = Duration::ZERO;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bound = vec![Bound {
            listener,
            port: addr.port(),
            addr: "127.0.0.1".into(),
            tls: None,
            pending_tls: None,
        }];
        let server = Server::new(Arc::new(cfg.clone()), Arc::new(cov_logger(&cfg)));
        let stop = server.stop_flag();
        let handle = std::thread::spawn(move || server.run(&bound));

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(
                b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 408 Request Timeout"),
            "{response}"
        );

        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn slow_output_does_not_retain_the_only_request_worker() {
        let _test_guard = ADMISSION_TEST_LOCK.lock().unwrap();
        let dir = cov_dir("async-output-worker");
        std::fs::write(dir.join("www/index.html"), "ok\n").unwrap();
        std::fs::write(dir.join("www/large.bin"), vec![b'x'; 16 * 1024 * 1024]).unwrap();
        let mut cfg = cov_config(&dir, "");
        cfg.max_request_workers = 1;
        let budget = cfg.resource_budget.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bound = vec![Bound {
            listener,
            port: addr.port(),
            addr: "127.0.0.1".into(),
            tls: None,
            pending_tls: None,
        }];
        let server = Server::new(Arc::new(cfg.clone()), Arc::new(cov_logger(&cfg)));
        let stop = server.stop_flag();
        let handle = std::thread::spawn(move || server.run(&bound));

        let mut slow = TcpStream::connect(addr).unwrap();
        slow.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        slow.write_all(b"GET /large.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut first_byte = [0u8; 1];
        slow.read_exact(&mut first_byte).unwrap();
        assert_eq!(first_byte, [b'H']);
        for _ in 0..200 {
            if budget.slot_usage(crate::resource::SlotKind::RequestWorker) == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            budget.slot_usage(crate::resource::SlotKind::RequestWorker),
            0,
            "slow downstream retained the request worker"
        );

        let mut fast = TcpStream::connect(addr).unwrap();
        fast.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        fast.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        fast.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("ok\n"), "{response}");

        drop(slow);
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn slow_proxy_backend_does_not_retain_the_only_request_worker() {
        let _test_guard = ADMISSION_TEST_LOCK.lock().unwrap();
        let dir = cov_dir("async-backend-worker");
        std::fs::write(dir.join("www/index.html"), "ok\n").unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let (accepted_tx, accepted_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let upstream_thread = std::thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            accepted_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nslow\n",
                )
                .unwrap();
        });

        let mut cfg = cov_config(
            &dir,
            &format!("ProxyPass /slow http://127.0.0.1:{upstream_port}/\n"),
        );
        cfg.max_request_workers = 1;
        let budget = cfg.resource_budget.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bound = vec![Bound {
            listener,
            port: addr.port(),
            addr: "127.0.0.1".into(),
            tls: None,
            pending_tls: None,
        }];
        let server = Server::new(Arc::new(cfg.clone()), Arc::new(cov_logger(&cfg)));
        let stop = server.stop_flag();
        let server_thread = std::thread::spawn(move || server.run(&bound));
        let slow_client = std::thread::spawn(move || {
            let mut client = TcpStream::connect(addr).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            client
                .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            response
        });
        accepted_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        for _ in 0..100 {
            if budget.slot_usage(crate::resource::SlotKind::RequestWorker) == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            budget.slot_usage(crate::resource::SlotKind::RequestWorker),
            0,
            "a stalled proxy backend retained the request worker"
        );

        let mut fast = TcpStream::connect(addr).unwrap();
        fast.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        fast.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        fast.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("ok\n"), "{response}");

        release_tx.send(()).unwrap();
        assert!(slow_client.join().unwrap().starts_with("HTTP/1.1 200"));
        upstream_thread.join().unwrap();
        stop.store(true, Ordering::SeqCst);
        server_thread.join().unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn large_proxy_upload_streams_through_the_bounded_body_channel() {
        let _test_guard = ADMISSION_TEST_LOCK.lock().unwrap();
        let dir = cov_dir("streaming-proxy-upload");
        let body_len = crate::http::MAX_REQUEST_BODY_IN_MEMORY as usize + 64 * 1024;
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_thread = std::thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let mut request_head = Vec::new();
            let mut byte = [0u8; 1];
            while !request_head.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                request_head.push(byte[0]);
            }
            assert!(String::from_utf8_lossy(&request_head)
                .contains(&format!("Content-Length: {body_len}")));
            let mut received = 0usize;
            let mut chunk = [0u8; 64 * 1024];
            while received < body_len {
                let want = chunk.len().min(body_len - received);
                let read = socket.read(&mut chunk[..want]).unwrap();
                assert_ne!(read, 0);
                assert!(chunk[..read].iter().all(|byte| *byte == b'u'));
                received += read;
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")
                .unwrap();
        });

        let mut cfg = cov_config(
            &dir,
            &format!("ProxyPass /upload http://127.0.0.1:{upstream_port}/upload\n"),
        );
        cfg.max_request_workers = 1;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bound = vec![Bound {
            listener,
            port: addr.port(),
            addr: "127.0.0.1".into(),
            tls: None,
            pending_tls: None,
        }];
        let server = Server::new(Arc::new(cfg.clone()), Arc::new(cov_logger(&cfg)));
        let stop = server.stop_flag();
        let server_thread = std::thread::spawn(move || server.run(&bound));
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        client
            .write_all(
                format!(
                    "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .unwrap();
        client.write_all(&vec![b'u'; body_len]).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("ok\n"), "{response}");

        upstream_thread.join().unwrap();
        stop.store(true, Ordering::SeqCst);
        server_thread.join().unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn websocket_tunnel_does_not_retain_the_only_request_worker() {
        let _test_guard = ADMISSION_TEST_LOCK.lock().unwrap();
        let dir = cov_dir("websocket-worker-release");
        std::fs::write(dir.join("www/index.html"), "ok\n").unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let (upgraded_tx, upgraded_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let upstream_thread = std::thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            socket
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                )
                .unwrap();
            upgraded_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });

        let mut cfg = cov_config(
            &dir,
            &format!("ProxyPass /ws http://127.0.0.1:{upstream_port}/ws\n"),
        );
        cfg.max_request_workers = 1;
        let budget = cfg.resource_budget.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bound = vec![Bound {
            listener,
            port: addr.port(),
            addr: "127.0.0.1".into(),
            tls: None,
            pending_tls: None,
        }];
        let server = Server::new(Arc::new(cfg.clone()), Arc::new(cov_logger(&cfg)));
        let stop = server.stop_flag();
        let server_thread = std::thread::spawn(move || server.run(&bound));

        let mut websocket = TcpStream::connect(addr).unwrap();
        websocket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        websocket
            .write_all(cov_ws_request("/ws").as_bytes())
            .unwrap();
        let mut response_head = Vec::new();
        let mut byte = [0u8; 1];
        while !response_head.ends_with(b"\r\n\r\n") {
            websocket.read_exact(&mut byte).unwrap();
            response_head.push(byte[0]);
        }
        assert!(response_head.starts_with(b"HTTP/1.1 101"));
        upgraded_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        for _ in 0..100 {
            if budget.slot_usage(crate::resource::SlotKind::RequestWorker) == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            budget.slot_usage(crate::resource::SlotKind::RequestWorker),
            0,
            "a WebSocket tunnel retained the request worker"
        );
        assert_eq!(budget.websocket_usage(), 1);
        assert_eq!(
            budget.slot_usage(crate::resource::SlotKind::H1Connection),
            0,
            "a WebSocket tunnel retained general HTTP/1 connection capacity"
        );

        let mut fast = TcpStream::connect(addr).unwrap();
        fast.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        fast.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        fast.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        release_tx.send(()).unwrap();
        drop(websocket);
        upstream_thread.join().unwrap();
        stop.store(true, Ordering::SeqCst);
        server_thread.join().unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_dispatch_file_directory_handler_and_balancer_edges() {
        let dir = cov_dir("dispatch-files");
        for name in ["dir", "listing", "noslash", "noslash-ok"] {
            std::fs::create_dir_all(dir.join("www").join(name)).unwrap();
        }
        std::fs::write(dir.join("www/file.txt"), "file\n").unwrap();
        std::fs::write(dir.join("www/filter.txt"), "filter\n").unwrap();
        std::fs::write(dir.join("www/handler.txt"), "handler\n").unwrap();
        std::fs::write(dir.join("www/dir/index.html"), "index\n").unwrap();
        std::fs::write(dir.join("www/listing/a.txt"), "a\n").unwrap();
        std::fs::write(dir.join("www/noslash/a.txt"), "a\n").unwrap();
        std::fs::write(dir.join("www/noslash-ok/a.txt"), "a\n").unwrap();
        std::fs::write(
            dir.join("www/handler.cgi"),
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nok\\n'\n",
        )
        .unwrap();
        let cfg = cov_config(
            &dir,
            &format!(
                "AddHandler cgi-script .cgi\n\
                 <Location \"/filter.txt\">\nSetOutputFilter INCLUDES\n</Location>\n\
                 <Location \"/handler.txt\">\nSetHandler mystery\n</Location>\n\
                 <Directory \"{}/www/listing\">\nOptions +Indexes\n</Directory>\n\
                 <Directory \"{}/www/noslash\">\nOptions +Indexes\nDirectorySlash Off\n</Directory>\n\
                 <Directory \"{}/www/noslash-ok\">\nOptions +Indexes\nDirectorySlash Off\n</Directory>\n\
                 <Location \"/noslash/\">\nRequire all denied\n</Location>\n",
                dir.display(),
                dir.display(),
                dir.display()
            ),
        );
        assert_eq!(cov_dispatch(&cfg, "GET", "/dir/").status, 200);
        assert_eq!(cov_dispatch(&cfg, "GET", "/listing/").status, 200);
        assert_eq!(cov_dispatch(&cfg, "POST", "/dir").status, 405);
        assert_eq!(cov_dispatch(&cfg, "OPTIONS", "/dir").status, 200);
        assert_eq!(cov_dispatch(&cfg, "POST", "/file.txt").status, 405);
        assert_eq!(cov_dispatch(&cfg, "GET", "/filter.txt").status, 500);
        assert_eq!(cov_dispatch(&cfg, "GET", "/handler.txt").status, 500);
        assert_eq!(cov_dispatch(&cfg, "GET", "/handler.cgi").status, 403);
        assert_eq!(cov_dispatch(&cfg, "GET", "/noslash").status, 403);
        assert_eq!(cov_dispatch(&cfg, "GET", "/noslash-ok").status, 200);

        let symlink_cfg = cov_config(
            &dir,
            &format!(
                "<Directory \"{}/www\">\nOptions -FollowSymLinks +SymLinksIfOwnerMatch\n</Directory>\n",
                dir.display()
            ),
        );
        assert_eq!(cov_dispatch(&symlink_cfg, "GET", "/file.txt").status, 200);

        let balancer_cfg = cov_config(
            &dir,
            "<Proxy balancer://empty>\n</Proxy>\nProxyPass /bal balancer://empty\n",
        );
        assert_eq!(cov_dispatch(&balancer_cfg, "GET", "/bal").status, 503);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_dispatch_fastcgi_and_proxy_route_edges() {
        let dir = cov_dir("dispatch-fastcgi");
        std::fs::write(dir.join("www/script.php"), "<?php\n").unwrap();
        std::fs::create_dir_all(dir.join("www/script.php.d")).unwrap();
        let fastcgi_cfg = cov_config(
            &dir,
            &format!(
                "ProxyPassMatch ^/(.*\\.php(/.*)?)$ \"unix:/tmp/vapache-missing.sock|fcgi://localhost{}/www/\"\n",
                dir.display()
            ),
        );
        let status = cov_dispatch(&fastcgi_cfg, "GET", "/script.php").status;
        assert!(matches!(status, 500 | 502 | 503), "{status}");
        let status = cov_dispatch(&fastcgi_cfg, "GET", "/script.php/info").status;
        assert!(matches!(status, 500 | 502 | 503 | 404), "{status}");

        let mixed_cfg = cov_config(
            &dir,
            &format!(
                "ProxyPass /script.php http://127.0.0.1:9/\n\
                 ProxyPassMatch ^/(.*\\.php(/.*)?)$ \"unix:/tmp/vapache-missing.sock|fcgi://localhost{}/www/\"\n",
                dir.display()
            ),
        );
        let status = cov_dispatch(&mixed_cfg, "GET", "/script.php").status;
        assert!(matches!(status, 200 | 500 | 502 | 503), "{status}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn script_alias_path_info_respects_forced_non_cgi_handler() {
        let dir = cov_dir("script-alias-handler");
        let scripts = dir.join("cgi-bin");
        std::fs::create_dir_all(&scripts).unwrap();
        let marker = dir.join("executed");
        let script = scripts.join("run.cgi");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf owned > '{}'\nprintf 'Content-Type: text/plain\\r\\n\\r\\nowned\\n'\n",
                marker.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        let cfg = cov_config(
            &dir,
            &format!(
                "ScriptAlias /cgi-bin/ \"{}/\"\n\
                 <Directory \"{}\">\n\
                 SetHandler default-handler\n\
                 Require all granted\n\
                 </Directory>\n",
                scripts.display(),
                scripts.display(),
            ),
        );
        assert_ne!(
            cov_dispatch(&cfg, "GET", "/cgi-bin/run.cgi/info").status,
            200
        );
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auth_type_without_require_returns_server_error() {
        let dir = cov_dir("auth-without-require");
        std::fs::write(dir.join("www/file.txt"), "public\n").unwrap();
        let cfg = cov_config(
            &dir,
            &format!(
                "<Directory \"{}/www\">\nAuthType Basic\nAuthName restricted\n</Directory>\n",
                dir.display()
            ),
        );
        assert_eq!(cov_dispatch(&cfg, "GET", "/file.txt").status, 500);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_dispatch_rewrite_redirect_and_pathinfo_edges() {
        let dir = cov_dir("dispatch-rewrite-edges");
        std::fs::create_dir_all(dir.join("www/bad")).unwrap();
        std::fs::write(dir.join("www/file.txt"), "file\n").unwrap();
        std::fs::write(dir.join("www/bad/file.txt"), "bad\n").unwrap();
        std::fs::write(dir.join("www/bad/.htaccess"), "Header \"unterminated\n").unwrap();
        std::fs::write(
            dir.join("www/script.cgi"),
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nok\\n'\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("www/bad/script.cgi"),
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nbad\\n'\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("bad/script.cgi", dir.join("www/link.cgi")).unwrap();
        std::fs::write(dir.join("www/protected.sh"), "#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        for name in ["script.cgi", "protected.sh", "bad/script.cgi"] {
            let path = dir.join("www").join(name);
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
        }
        let cfg = cov_config(
            &dir,
            &format!(
                "<Directory \"{}/www\">\nOptions +ExecCGI\n</Directory>\n\
                 <Directory \"{}/www/bad\">\nAllowOverride All\n</Directory>\n\
                 AddHandler cgi-script .cgi\n\
                 RewriteEngine On\n\
                 RewriteRule ^/okstage$ /okproxy [L,E=STAGE:1]\n\
                 RewriteRule ^/okproxy$ http://127.0.0.1:9/echo [P]\n\
                 RewriteRule ^/okredir$ /file.txt [R=302,E=REDIR:1]\n\
                 RewriteRule ^/extredir$ http://example.com/x [R=302]\n\
                 RewriteRule ^/relrewrite$ relative [R=302]\n\
                 RewriteRule ^/round0$ /round1 [L]\n\
                 RewriteRule ^/round1$ /round2 [L]\n\
                 RewriteRule ^/round2$ /round3 [L]\n\
                 RewriteRule ^/round3$ /round4 [L]\n\
                 RewriteRule ^/round4$ /round5 [L]\n\
                 RewriteRule ^/round5$ /round6 [L]\n\
                 RewriteRule ^/round6$ /round7 [L]\n\
                 RewriteRule ^/round7$ /round8 [L]\n\
                 RewriteRule ^/round8$ /round9 [L]\n\
                 RewriteRule ^/round9$ /round10 [L]\n\
                 RewriteRule ^/round10$ /round11 [L]\n\
                 RewriteRule ^/round11$ /file.txt [L]\n\
                 RewriteRule ^/badcanon$ /.. [L]\n\
                 RewriteRule ^/tofs$ \"{}/www/bad/file.txt\" [L]\n",
                dir.display(),
                dir.display(),
                dir.display()
            ),
        );
        let status = cov_dispatch(&cfg, "GET", "/okstage").status;
        assert!(matches!(status, 200 | 502), "{status}");
        assert_eq!(cov_dispatch(&cfg, "GET", "/okredir").status, 302);
        assert_eq!(cov_dispatch(&cfg, "HEAD", "/okredir").status, 302);
        let ext = cov_dispatch(&cfg, "GET", "/extredir");
        assert_eq!(ext.status, 302);
        assert!(ext
            .headers
            .iter()
            .any(|(n, v)| { n.eq_ignore_ascii_case("location") && v == b"http://example.com/x" }));
        assert_eq!(cov_dispatch(&cfg, "GET", "/relrewrite").status, 302);
        assert_eq!(cov_dispatch(&cfg, "GET", "/round0").status, 500);
        assert_eq!(cov_dispatch(&cfg, "GET", "/badcanon").status, 400);
        assert_eq!(cov_dispatch(&cfg, "GET", "/tofs").status, 500);
        assert_eq!(cov_dispatch(&cfg, "GET", "/script.cgi/info").status, 200);
        assert_eq!(cov_dispatch(&cfg, "GET", "/link.cgi/info").status, 500);
        // A hidden, dot-only final path component is not an extension and
        // cannot classify the preceding script for CGI execution.
        assert_eq!(cov_dispatch(&cfg, "GET", "/protected.sh/.cgi").status, 404);
        assert_eq!(
            cov_dispatch(&cfg, "GET", "/protected.sh/child.cgi").status,
            403
        );

        let mut manual = cov_config(&dir, "");
        manual
            .global
            .mapping_policy
            .redirects
            .push(crate::config::Redirect {
                from: "/directempty".into(),
                to: String::new(),
                status: 404,
                regex: None,
            });
        manual
            .global
            .mapping_policy
            .redirects
            .push(crate::config::Redirect {
                from: "/directrel".into(),
                to: "relative-target".into(),
                status: 302,
                regex: None,
            });
        let empty = cov_dispatch(&manual, "GET", "/directempty");
        assert_eq!(empty.status, 404);
        let rel = cov_dispatch(&manual, "GET", "/directrel");
        assert_eq!(rel.status, 302);
        assert!(rel
            .headers
            .iter()
            .any(|(n, v)| { n.eq_ignore_ascii_case("location") && v == b"relative-target" }));
        let head = cov_dispatch(&manual, "HEAD", "/directrel");
        assert_eq!(head.status, 302);
        assert_eq!(head.body_len(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_run_fastcgi_pathinfo_and_auth() {
        use base64::Engine as _;
        use sha1::{Digest, Sha1};
        let dir = cov_dir("fastcgi-direct");
        let script = dir.join("www/script.php");
        std::fs::write(&script, "<?php\n").unwrap();
        let mut hasher = Sha1::new();
        hasher.update(b"secret");
        let digest = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        let htpasswd = dir.join(".htpasswd");
        std::fs::write(&htpasswd, format!("alice:{{SHA}}{digest}\n")).unwrap();
        let cfg = cov_config(
            &dir,
            &format!(
                "<Directory \"{}/www\">\n\
                 AuthType Basic\n\
                 AuthName \"realm\"\n\
                 AuthUserFile \"{}\"\n\
                 Require valid-user\n\
                 Options -FollowSymLinks +SymLinksIfOwnerMatch\n\
                 </Directory>\n\
                 ProxyPassMatch ^/(.*\\.php(/.*)?)$ \"unix:/tmp/vapache-missing.sock|fcgi://localhost{}/www/\"\n",
                dir.display(),
                htpasswd.display(),
                dir.display()
            ),
        );
        let scope = cfg.effective_scope(None, &script, "/script.php/info");
        let target = fastcgi::match_proxy(&scope, "/script.php/info", &dir.join("www"))
            .expect("fastcgi target");
        assert_eq!(target.path_info, "/info");
        let mut req = cov_req("GET", "/script.php/info");
        let token = base64::engine::general_purpose::STANDARD.encode(b"alice:secret");
        req.headers
            .insert("authorization", format!("Basic {token}").into_bytes());
        let resource = access::ResourceKey::request(
            None,
            &req,
            "/script.php/info",
            Some(&script),
            Some("fcgi"),
        );
        let resp = run_fastcgi(
            &cfg,
            None,
            &req,
            "/script.php/info",
            "localhost",
            cov_peer(),
            "127.0.0.1",
            80,
            &scope,
            &target,
            &access::test_grant(),
            &resource,
            &cfg.documentation_root_for(None),
        );
        assert!(matches!(resp.status, 500 | 502 | 503), "{}", resp.status);

        let mut missing_target = target.clone();
        missing_target.replace_script_filename_for_test(dir.join("www/missing.php"));
        let resp = run_fastcgi(
            &cfg,
            None,
            &req,
            "/missing.php",
            "localhost",
            cov_peer(),
            "127.0.0.1",
            80,
            &scope,
            &missing_target,
            &access::test_grant(),
            &resource,
            &cfg.documentation_root_for(None),
        );
        assert_eq!(resp.status, 403);

        let unauthorized = cov_req("GET", "/script.php/info");
        let resp = run_fastcgi(
            &cfg,
            None,
            &unauthorized,
            "/script.php/info",
            "localhost",
            cov_peer(),
            "127.0.0.1",
            80,
            &scope,
            &target,
            &access::test_grant(),
            &resource,
            &cfg.documentation_root_for(None),
        );
        assert_eq!(resp.status, 401);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxied_route_requires_configuration_only_location_acl() {
        let dir = cov_dir("proxy-operator-acl");
        std::fs::write(dir.join("www/script.php"), "<?php\n").unwrap();
        std::fs::write(
            dir.join("www/.htaccess"),
            "<If \"true\">\nRequire all granted\n</If>\n",
        )
        .unwrap();
        let cfg = cov_config(
            &dir,
            &format!(
                "<Directory \"{}/www\">\nAllowOverride AuthConfig\n</Directory>\n\
                 <Location \"/script.php\">\nRequire all denied\n</Location>\n\
                 ProxyPassMatch ^/(.*\\.php)$ \"unix:/tmp/vapache-missing.sock|fcgi://localhost{}/www/\"\n",
                dir.display(),
                dir.display(),
            ),
        );
        // Reaching the deliberately missing backend would produce 5xx.  A
        // 403 proves the access-file grant cannot erase the operator ACL.
        assert_eq!(cov_dispatch(&cfg, "GET", "/script.php").status, 403);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn htaccess_iffile_is_frozen_at_parse_time_without_skipping_files_acl() {
        let dir = cov_dir("iffile-phase-acl");
        std::fs::write(dir.join("flag"), "server-root marker\n").unwrap();
        std::fs::write(dir.join("www/flag"), "document-root marker\n").unwrap();
        std::fs::write(dir.join("www/secret.txt"), "secret\n").unwrap();
        std::fs::write(
            dir.join("www/.htaccess"),
            "<IfFile \"flag\">\nRequire all granted\n</IfFile>\n",
        )
        .unwrap();
        let cfg = cov_config(
            &dir,
            &format!(
                "<Directory \"{}/www\">\n\
                 AllowOverride AuthConfig\n\
                 <Files \"secret.txt\">\nRequire all denied\n</Files>\n\
                 </Directory>\n",
                dir.display(),
            ),
        );

        // The access-file grant is a directory-phase rule.  Apache freezes
        // IfFile while reading the file, relative to ServerRoot, and still
        // applies the later Files phase; it must not become a final override.
        assert_eq!(cov_dispatch(&cfg, "GET", "/secret.txt").status, 403);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_directory_slash_reauthorization_error() {
        let dir = cov_dir("directory-slash");
        std::fs::create_dir_all(dir.join("www/protected")).unwrap();
        std::fs::write(dir.join("www/protected/a.txt"), "a\n").unwrap();
        let mut cfg = cov_config(
            &dir,
            "<Location \"/protected/\">\nRequire all denied\n</Location>\n",
        );
        cfg.global.content_policy.directory_slash = Some(false);
        assert_eq!(cov_dispatch(&cfg, "GET", "/protected").status, 403);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_bind_rebind_and_listener_errors() {
        let dir = cov_dir("bind");
        let cfg = cov_config(&dir, "");
        let bound = bind(&cfg).unwrap();
        assert_eq!(bound.len(), 1);
        let rebound = rebind(&cfg, &bound).unwrap();
        assert_eq!(rebound.len(), 1);

        let mut cfg_many = cfg.clone();
        cfg_many.listeners.push(crate::config::ListenSpec {
            raw: "127.0.0.1:0".into(),
            addr: "127.0.0.1".into(),
            port: 0,
        });
        assert_eq!(
            rebind(&cfg_many, &bound)
                .err()
                .expect("rebind error")
                .kind(),
            io::ErrorKind::Unsupported
        );
        let mut cfg_mismatch = cfg.clone();
        cfg_mismatch.listeners[0].port = cfg.listeners[0].port.wrapping_add(1);
        assert_eq!(
            rebind(&cfg_mismatch, &bound)
                .err()
                .expect("rebind error")
                .kind(),
            io::ErrorKind::Unsupported
        );
        let mut cfg_addr = cfg.clone();
        cfg_addr.listeners[0].addr = "127.0.0.2".into();
        assert_eq!(
            rebind(&cfg_addr, &bound)
                .err()
                .expect("rebind error")
                .kind(),
            io::ErrorKind::Unsupported
        );

        let hostname_cfg = cov_config(&dir, "");
        let mut hostname_cfg = hostname_cfg;
        hostname_cfg.listeners[0].addr = "localhost".into();
        assert!(bind(&hostname_cfg).is_ok());

        let mut bad_cfg = cfg.clone();
        bad_cfg.listeners[0].addr = "bad host name".into();
        assert!(bind(&bad_cfg).is_err());
        let mut empty_cfg = cfg.clone();
        empty_cfg.listeners[0].addr = "".into();
        assert!(bind(&empty_cfg).is_err());

        let actual = bound[0].listener.local_addr().unwrap();
        let mut duplicate_cfg = cfg.clone();
        duplicate_cfg.listeners[0].addr = actual.ip().to_string();
        duplicate_cfg.listeners[0].port = actual.port();
        assert!(bind(&duplicate_cfg).is_err());

        let datagram = std::os::unix::net::UnixDatagram::unbound().unwrap();
        assert!(listen_fd(datagram.as_raw_fd(), 1).is_err());
        let datagram = std::os::unix::net::UnixDatagram::unbound().unwrap();
        use std::os::unix::io::IntoRawFd;
        assert!(finish_listener(datagram.into_raw_fd(), 1).is_err());

        let (v4, v6) = (
            sockaddr_storage("127.0.0.1:80".parse().unwrap()),
            sockaddr_storage("[::1]:80".parse().unwrap()),
        );
        assert!(v4.1 > 0 && v6.1 > 0);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        reject_busy_connection(server_stream, false, &cfg);
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut text = String::new();
        (&client).read_to_string(&mut text).unwrap();
        assert!(text.contains("503"));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        reject_busy_connection(server_stream, true, &cfg);
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(client.read(&mut buf).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
