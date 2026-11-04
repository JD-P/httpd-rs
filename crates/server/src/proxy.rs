//! Minimal HTTP/1.1 reverse proxy for `ProxyPass`/`ProxyPassReverse`.
//!
//! Covers HTTP and HTTPS upstreams, prefix/regex routing, chunked or
//! fixed-length bodies, `Location` rewriting, round-robin `balancer://`
//! members, compression and WebSocket tunneling over TCP/TLS.  Health checks,
//! failover and connection pooling are follow-ups.

use crate::config::{
    Balancer, BalancerMember, Config, HealthTemplate, ProxyReverseRule, Scope, VHost,
};
use crate::http::{Body, Request, Response, Version};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConnection, RootCertStore, StreamOwned};
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_PROXY_HEAD: usize = 64 * 1024;
const MAX_PROXY_BODY: usize = 64 * 1024 * 1024;
const MAX_PROXY_BODY_IN_MEMORY: usize = 256 * 1024;
const MAX_WEBSOCKET_NEGOTIATION_ITEMS: usize = 64;
const MAX_WEBSOCKET_EXTENSION_PARAMS: usize = 32;
const MAX_PROXY_CA_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PROXY_ADDRESSES: usize = 32;
const WEBSOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// A backend name is resolved once for each immutable configuration
/// generation. DNS remains an input to configuration, not a mutable routing
/// authority which can retarget an already-authorized request. TLS adds a
/// second, cryptographic identity check but consumes the same bound transport.
const MAX_BACKEND_IDENTITIES: usize = 1024;

/// Resolver authority owned by exactly one immutable configuration. Clones of
/// that configuration share this object; background health/OCSP work may keep
/// only this bounded transport state alive, never another generation's map.
#[derive(Debug)]
pub(crate) struct BackendIdentityRegistry {
    generation: u64,
    identities: Mutex<HashMap<(String, u16), Vec<SocketAddr>>>,
}

impl BackendIdentityRegistry {
    pub(crate) fn new(generation: u64) -> Self {
        Self {
            generation,
            identities: Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
fn test_backend_identities() -> BackendIdentityRegistry {
    BackendIdentityRegistry::new(0)
}

struct ProxyBodyCollector {
    memory: Vec<u8>,
    file: Option<std::fs::File>,
    lease: Option<crate::resource::SpoolLease>,
    resident: Option<crate::resource::ResidentLease>,
    len: usize,
    budget: Arc<crate::resource::ResourceBudget>,
    context: crate::resource::ResourceContext,
    max_spool_bytes: u64,
    max_spool_files: u64,
}

impl ProxyBodyCollector {
    fn new(
        budget: Arc<crate::resource::ResourceBudget>,
        context: crate::resource::ResourceContext,
        max_spool_bytes: u64,
        max_spool_files: u64,
    ) -> std::io::Result<Self> {
        Ok(Self {
            memory: Vec::new(),
            file: None,
            lease: None,
            resident: Some(budget.try_response_bytes_in(&context)?),
            len: 0,
            budget,
            context,
            max_spool_bytes,
            max_spool_files,
        })
    }

    fn push(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let next = self
            .len
            .checked_add(bytes.len())
            .filter(|next| *next <= MAX_PROXY_BODY)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::FileTooLarge, "proxy body too large")
            })?;
        if self.file.is_none() && next <= MAX_PROXY_BODY_IN_MEMORY {
            self.resident
                .as_mut()
                .expect("in-memory proxy body owns a resident lease")
                .reserve(bytes.len() as u64)?;
            self.memory.extend_from_slice(bytes);
            self.len = next;
            return Ok(());
        }
        if self.file.is_none() {
            let mut lease = self.budget.try_spool_in(
                self.max_spool_bytes,
                self.max_spool_files,
                &self.context,
            )?;
            lease.reserve(next as u64)?;
            let mut file = crate::http::spool_file()?;
            file.write_all(&self.memory)?;
            file.write_all(bytes)?;
            self.memory.clear();
            self.file = Some(file);
            self.lease = Some(lease);
        } else {
            self.lease
                .as_mut()
                .expect("proxy spool owns a lease")
                .reserve(bytes.len() as u64)?;
            self.file
                .as_mut()
                .expect("proxy spool owns a file")
                .write_all(bytes)?;
        }
        self.len = next;
        Ok(())
    }

    fn finish(
        mut self,
    ) -> std::io::Result<(
        Body,
        Option<crate::resource::SpoolLease>,
        Option<crate::resource::ResidentLease>,
    )> {
        match (self.file.take(), self.lease.take()) {
            (Some(mut file), Some(lease)) => {
                file.seek(SeekFrom::Start(0))?;
                Ok((
                    Body::File {
                        file,
                        offset: 0,
                        len: self.len as u64,
                    },
                    Some(lease),
                    None,
                ))
            }
            (None, None) if self.memory.is_empty() => Ok((Body::Empty, None, None)),
            (None, None) => Ok((
                Body::Bytes(std::mem::take(&mut self.memory)),
                None,
                self.resident.take(),
            )),
            _ => unreachable!("proxy spool file and lease are created together"),
        }
    }
}

trait ProxyBodySink {
    fn len(&self) -> usize;
    fn push_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()>;
}

impl ProxyBodySink for Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

impl ProxyBodySink for ProxyBodyCollector {
    fn len(&self) -> usize {
        self.len
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.push(bytes)
    }
}

#[derive(Clone, Debug)]
struct HttpBackend {
    host: String,
    port: u16,
    base: String,
    tls: bool,
}

trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

struct DeadlineStream {
    inner: Box<dyn ReadWrite>,
    deadline: Instant,
    scope: Option<crate::resource::RequestScope>,
}

impl DeadlineStream {
    fn timed_out(&self) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "proxy exchange deadline exceeded",
        )
    }

    fn cancelled(&self) -> Option<std::io::Error> {
        self.scope
            .as_ref()
            .is_some_and(crate::resource::RequestScope::is_cancelled)
            .then(|| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "proxy request scope cancelled",
                )
            })
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(error) = self.cancelled() {
                return Err(error);
            }
            if Instant::now() >= self.deadline {
                return Err(self.timed_out());
            }
            match crate::fault::hit("proxy.read").and_then(|()| self.inner.read(buf)) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            if let Some(error) = self.cancelled() {
                return Err(error);
            }
            if Instant::now() >= self.deadline {
                return Err(self.timed_out());
            }
            match crate::fault::hit("proxy.write").and_then(|()| self.inner.write(buf)) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        loop {
            if let Some(error) = self.cancelled() {
                return Err(error);
            }
            if Instant::now() >= self.deadline {
                return Err(self.timed_out());
            }
            match crate::fault::hit("proxy.flush").and_then(|()| self.inner.flush()) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
}

#[derive(Clone)]
pub struct Target {
    backend: HttpBackend,
    path: String,
    suffix: String,
    reverse: Vec<ProxyReverseRule>,
    balancer: Option<String>,
    fail_on_status: Vec<u16>,
    /// Backend URL used for `<Proxy>` / `<ProxyMatch>` matching.
    pub proxy_url: String,
    /// Configured front-end URL (`balancer://...` or the rule's backend).
    /// `<Proxy>` sections are matched against this identity as well as the
    /// concrete member selected for the request.
    pub logical_url: Option<String>,
    /// Position in the merged proxy route table.
    pub route_order: usize,
}

impl Target {
    /// Exact backend/path identity used for resource binding.
    pub(crate) fn binding_key(&self) -> String {
        let key = vapache_verified::proxy_target_key(
            self.backend.host.as_bytes(),
            self.backend.port,
            self.backend.tls,
            self.path.as_bytes(),
        );
        key.iter().map(|b| format!("{b:02x}")).collect()
    }
}

const MAX_PROXY_HEADERS: usize = 200;
const MAX_PROXY_LINE: usize = 16 * 1024;
const MAX_PROXY_TRAILER_BYTES: usize = 64 * 1024;
const MAX_PROXY_TRAILERS: usize = 64;

fn canonical_proxy_url(backend: &HttpBackend, path: &str) -> String {
    let scheme = if backend.tls { "https" } else { "http" };
    let default_port = if backend.tls { 443 } else { 80 };
    let authority = if backend.port == default_port {
        backend.host.clone()
    } else {
        format!("{}:{}", backend.host, backend.port)
    };
    let path = if path.is_empty() { "/" } else { path };
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    format!("{scheme}://{authority}{path}")
}

fn parse_http_url(value: &str) -> Option<HttpBackend> {
    let value = value.trim();
    let (rest, tls, default_port) = if let Some(rest) = value.strip_prefix("http://") {
        (rest, false, 80)
    } else if let Some(rest) = value.strip_prefix("https://") {
        (rest, true, 443)
    } else if let Some(rest) = value.strip_prefix("ws://") {
        (rest, false, 80)
    } else if let Some(rest) = value.strip_prefix("wss://") {
        (rest, true, 443)
    } else {
        return None;
    };
    let (authority, base) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    // Bracketed IPv6 literals contain colons; do not split them as a port.
    let (host, port) = if let Some(inside) = authority.strip_prefix('[') {
        let (host, after) = inside.split_once(']')?;
        let port = if let Some(port) = after.strip_prefix(':') {
            port.parse().ok()?
        } else if after.is_empty() {
            default_port
        } else {
            return None;
        };
        (format!("[{host}]"), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), default_port),
        }
    };
    if host.is_empty() || !valid_backend_host(&host) {
        return None;
    }
    Some(HttpBackend {
        host,
        port,
        base,
        tls,
    })
}

/// A backend authority is configuration- or rewrite-derived.  Reject control
/// bytes and request-line delimiters before the host can be interpolated into
/// an upstream request line or `Host`/`X-Forwarded-*` field.
fn valid_backend_host(host: &str) -> bool {
    !host.is_empty()
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        })
}

fn valid_forwarded_host(host: &str) -> bool {
    !host.is_empty()
        && !host.bytes().any(|b| b <= b' ' || b == 0x7f)
        && crate::verified::sanitize_header_value(host.as_bytes()).is_some()
}

fn tls_server_name(
    host: &str,
) -> Result<ServerName<'static>, rustls::pki_types::InvalidDnsNameError> {
    // URL authorities retain IPv6 brackets for Host/request serialization;
    // Rustls expects the underlying IP literal when constructing the
    // certificate-verification identity.
    let identity = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    ServerName::try_from(identity.to_string())
}

fn dead_map() -> &'static Mutex<HashMap<String, std::time::Instant>> {
    static DEAD: OnceLock<Mutex<HashMap<String, std::time::Instant>>> = OnceLock::new();
    DEAD.get_or_init(|| Mutex::new(HashMap::new()))
}

fn mark_dead(generation: u64, name: &str, member: &str) {
    let mut guard = dead_map().lock().unwrap_or_else(|e| e.into_inner());
    guard.insert(
        format!("{generation}|{name}|{member}"),
        std::time::Instant::now(),
    );
}

fn is_dead(generation: u64, name: &str, member: &str) -> bool {
    let key = parse_http_url(member)
        .map(|b| format!("{generation}|{name}|{}:{}", b.host, b.port))
        .unwrap_or_else(|| format!("{generation}|{name}|{member}"));
    let guard = dead_map().lock().unwrap_or_else(|e| e.into_inner());
    guard
        .get(&key)
        .map(|t| t.elapsed() < std::time::Duration::from_secs(10))
        .unwrap_or(false)
}

#[derive(Default)]
struct MemberHealth {
    healthy: bool,
    passes: u32,
    fails: u32,
}

#[derive(Clone)]
struct HealthSpec {
    backend_identities: Arc<BackendIdentityRegistry>,
    key: String,
    url: String,
    method: String,
    uri: String,
    interval: Duration,
    passes: u32,
    fails: u32,
    ca_file: Option<std::path::PathBuf>,
    ca_trust: crate::files::AdminFileTrust,
}

fn health_map() -> &'static Mutex<HashMap<String, MemberHealth>> {
    static HEALTH: OnceLock<Mutex<HashMap<String, MemberHealth>>> = OnceLock::new();
    HEALTH.get_or_init(|| Mutex::new(HashMap::new()))
}

struct HealthGeneration {
    id: u64,
    signature: String,
    stop: Arc<AtomicBool>,
}

fn health_generation() -> &'static Mutex<Option<HealthGeneration>> {
    static GENERATION: OnceLock<Mutex<Option<HealthGeneration>>> = OnceLock::new();
    GENERATION.get_or_init(|| Mutex::new(None))
}

fn balancer_counters() -> &'static Mutex<HashMap<String, usize>> {
    static COUNTERS: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
    COUNTERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Called by the last clone of an immutable Config generation. Mutable
/// routing observations live exactly as long as requests which can still use
/// that Config, so repeated administrative reloads cannot leak state.
pub(crate) fn drop_generation_state(generation: u64) {
    let prefix = format!("{generation}|");
    dead_map()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .retain(|key, _| !key.starts_with(&prefix));
    health_map()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .retain(|key, _| !key.starts_with(&prefix));
    balancer_counters()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .retain(|key, _| !key.starts_with(&prefix));
    let mut active = health_generation()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if active.as_ref().is_some_and(|state| state.id == generation) {
        if let Some(state) = active.take() {
            state.stop.store(true, Ordering::Release);
        }
    }
}

fn health_key(generation: u64, name: &str, member: &str) -> String {
    format!("{generation}|{name}|{member}")
}

fn member_is_healthy(generation: u64, name: &str, member: &str) -> bool {
    let guard = health_map().lock().unwrap_or_else(|e| e.into_inner());
    guard
        .get(&health_key(generation, name, member))
        .map(|h| h.healthy)
        .unwrap_or(true)
}

fn update_health(spec: &HealthSpec, ok: bool) {
    let mut guard = health_map().lock().unwrap_or_else(|e| e.into_inner());
    let entry = guard
        .entry(spec.key.clone())
        .or_insert_with(|| MemberHealth {
            healthy: true,
            passes: 0,
            fails: 0,
        });
    if ok {
        entry.passes = entry.passes.saturating_add(1);
        entry.fails = 0;
        if entry.passes >= spec.passes.max(1) {
            entry.healthy = true;
        }
    } else {
        entry.fails = entry.fails.saturating_add(1);
        entry.passes = 0;
        if entry.fails >= spec.fails.max(1) {
            entry.healthy = false;
        }
    }
}

fn balancer_specs(cfg: &Config, balancer: &Balancer) -> Vec<HealthSpec> {
    if !balancer.health_enabled() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for member in &balancer.members {
        let template = member
            .template
            .as_ref()
            .and_then(|name| cfg.health_templates.get(name));
        let health = template.unwrap_or(&balancer.health) as &HealthTemplate;
        let method = member
            .hcmethod
            .clone()
            .or_else(|| health.method.clone())
            .unwrap_or_else(|| "GET".into());
        let uri = member
            .hcuri
            .clone()
            .or_else(|| health.uri.clone())
            .unwrap_or_else(|| "/".into());
        let interval = member
            .hcinterval
            .or(health.interval)
            .unwrap_or(Duration::from_secs(5));
        let passes = member.hcpasses.or(health.passes).unwrap_or(1);
        let fails = member.hcfails.or(health.fails).unwrap_or(1);
        out.push(HealthSpec {
            backend_identities: Arc::clone(&cfg.backend_identities),
            key: health_key(cfg.generation, &balancer.name, &member.url),
            url: member.url.clone(),
            method,
            uri,
            interval,
            passes,
            fails,
            ca_file: cfg.global.proxy_policy.proxy_ca_file.clone(),
            ca_trust: cfg.global.proxy_policy.proxy_ca_trust,
        });
    }
    out
}

/// Start background active health checks for every balancer that has a
/// health-check template or member parameters.  The server calls this before
/// dropping privileges; the lightweight checker threads only use TCP.
pub fn start_health_checks(cfg: &Config) {
    let mut groups = Vec::new();
    let mut signature = String::new();
    for balancer in &cfg.balancers {
        let specs = balancer_specs(cfg, balancer);
        if specs.is_empty() {
            continue;
        }
        signature.push_str(&balancer.name);
        for spec in &specs {
            use std::fmt::Write as _;
            let _ = write!(
                signature,
                "\0{}\0{}\0{}\0{:?}\0{}\0{}\0{:?}",
                spec.url,
                spec.method,
                spec.uri,
                spec.interval,
                spec.passes,
                spec.fails,
                spec.ca_file,
            );
        }
        groups.push(specs);
    }

    let generation = health_generation();
    let stop = {
        let mut current = generation.lock().unwrap_or_else(|error| error.into_inner());
        if current
            .as_ref()
            .is_some_and(|running| running.id == cfg.generation && running.signature == signature)
        {
            return;
        }
        if let Some(running) = current.take() {
            running.stop.store(true, Ordering::Release);
        }
        let stop = Arc::new(AtomicBool::new(false));
        *current = Some(HealthGeneration {
            id: cfg.generation,
            signature,
            stop: Arc::clone(&stop),
        });
        stop
    };
    // Retain the old namespace while its already-admitted requests drain.
    // The new generation cannot observe it because every key includes the
    // immutable Config identity. The last old Config clone removes that
    // namespace and its counters after the overlap window closes.

    for specs in groups {
        let stop = Arc::clone(&stop);
        let _ = std::thread::Builder::new()
            .name("proxy-health".into())
            .spawn(move || loop {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                for spec in &specs {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let ok = check_health(spec);
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    update_health(spec, ok);
                }
                let wait = specs
                    .iter()
                    .map(|s| s.interval)
                    .min()
                    .unwrap_or(Duration::from_secs(5))
                    .max(Duration::from_millis(250));
                let deadline = std::time::Instant::now() + wait;
                while !stop.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                    std::thread::sleep(
                        Duration::from_millis(100)
                            .min(deadline.saturating_duration_since(std::time::Instant::now())),
                    );
                }
            });
    }
}

fn check_health(spec: &HealthSpec) -> bool {
    let Some(backend) = parse_http_url(&spec.url) else {
        return false;
    };
    let mut scope = Scope::default();
    scope.proxy_policy.proxy_ca_file = spec.ca_file.clone();
    scope.proxy_policy.proxy_ca_trust = spec.ca_trust;
    let timeout = Duration::from_secs(5);
    let deadline = Instant::now() + timeout;
    let Ok(stream) = connect(
        &backend,
        &scope,
        &spec.backend_identities,
        timeout,
        deadline,
        None,
    ) else {
        return false;
    };
    check_health_stream(stream, spec, &backend)
}

fn check_health_stream(
    mut stream: Box<dyn ReadWrite>,
    spec: &HealthSpec,
    backend: &HttpBackend,
) -> bool {
    let path = encode_proxy_path(&join_path(&backend.base, &spec.uri));
    let method = match spec.method.to_ascii_uppercase().as_str() {
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        _ => "GET",
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        backend.host, backend.port
    )
    .into_bytes();
    let Ok(head) = ValidatedProxyHead::new(request, backend, None) else {
        return false;
    };
    if stream.write_all(head.as_bytes()).is_err() {
        return false;
    }
    let mut reader = BufReader::new(stream);
    match read_line(&mut reader) {
        Ok(line) => std::str::from_utf8(&line)
            .ok()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|status| status.parse::<u16>().ok())
            .is_some_and(|status| (200..400).contains(&status)),
        Err(_) => false,
    }
}

fn sticky_route(
    balancer: &Balancer,
    req: Option<&Request>,
    override_cookie: Option<&str>,
) -> Option<String> {
    let cookie_names: Vec<&str> = override_cookie
        .or(balancer.sticky_cookie.as_deref())?
        .split('|')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let cookie = req?.header("cookie")?;
    for pair in cookie.split(|byte| *byte == b';') {
        let pair = trim_ascii_bytes(pair);
        let Some(eq) = pair.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let name = trim_ascii_bytes(&pair[..eq]);
        let value = trim_ascii_bytes(&pair[eq + 1..]);
        if !cookie_names
            .iter()
            .any(|candidate| name.eq_ignore_ascii_case(candidate.as_bytes()))
        {
            continue;
        }
        let sep = balancer.sticky_sep.as_deref().unwrap_or(".");
        if !sep.is_empty() {
            if let Some(at) = value
                .windows(sep.len())
                .rposition(|window| window == sep.as_bytes())
            {
                return String::from_utf8(value[at + sep.len()..].to_vec()).ok();
            }
        }
        return String::from_utf8(value.to_vec()).ok();
    }
    None
}

fn trim_ascii_bytes(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn next_balancer_member(
    generation: u64,
    balancer: &Balancer,
    req: Option<&Request>,
    exclude: Option<&HashSet<String>>,
    sticky_override: Option<&str>,
) -> Option<HttpBackend> {
    if balancer.members.is_empty() {
        return None;
    }
    let active = balancer.health_enabled();
    let is_excluded = |m: &BalancerMember| {
        exclude
            .and_then(|set| parse_http_url(&m.url).map(|b| set.contains(&backend_key(&b))))
            .unwrap_or(false)
    };
    let available = |m: &&BalancerMember| {
        (!active || member_is_healthy(generation, &balancer.name, &m.url)) && !is_excluded(m)
    };
    if let Some(route) = sticky_route(balancer, req, sticky_override) {
        if let Some(member) = balancer.members.iter().find(|m| {
            m.route.as_deref() == Some(route.as_str())
                && (!active || member_is_healthy(generation, &balancer.name, &m.url))
                && !is_dead(generation, &balancer.name, &m.url)
                && !is_excluded(m)
        }) {
            return parse_http_url(&member.url);
        }
    }
    let mut viable: Vec<&BalancerMember> = balancer.members.iter().filter(available).collect();
    if viable.is_empty() {
        return None;
    }
    let not_dead: Vec<&BalancerMember> = viable
        .iter()
        .copied()
        .filter(|m| !is_dead(generation, &balancer.name, &m.url))
        .collect();
    if !not_dead.is_empty() {
        viable = not_dead;
    }
    let mut guard = balancer_counters()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let counter_key = format!("{generation}|{}", balancer.name);
    let start = *guard.entry(counter_key.clone()).or_insert(0);
    let index = start % viable.len();
    *guard.entry(counter_key).or_insert(0) = start.wrapping_add(1);
    parse_http_url(&viable[index].url)
}

fn resolve_backend(
    cfg: &Config,
    raw: &str,
    suffix: &str,
    req: Option<&Request>,
    sticky_override: Option<&str>,
) -> Option<(HttpBackend, String)> {
    if let Some(name) = raw.trim().strip_prefix("balancer://") {
        let name = name.trim_end_matches('/');
        let balancer = cfg.balancers.iter().find(|b| b.name == name)?;
        let backend = next_balancer_member(cfg.generation, balancer, req, None, sticky_override)?;
        let path = join_path(&backend.base, suffix);
        return Some((backend, path));
    }
    let backend = parse_http_url(raw)?;
    let path = join_path(&backend.base, suffix);
    Some((backend, path))
}

fn join_path(base: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        return base.to_string();
    }
    if base == "/" {
        format!("/{suffix}")
    } else {
        format!(
            "{}/{}",
            base.trim_end_matches('/'),
            suffix.trim_start_matches('/')
        )
    }
}

fn prefix_suffix<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    crate::util::route_prefix_suffix(prefix, path)
}

/// Resolve an absolute URL produced by `RewriteRule ... [P]`.  The query
/// string is handled by the caller (it is forwarded separately from the
/// request), so only the path portion belongs in `Target`.
pub fn target_from_url(cfg: &Config, scope: &Scope, url: &str, req: &Request) -> Option<Target> {
    let path_part = url.split_once('?').map(|(p, _)| p).unwrap_or(url);
    let (backend, path) = resolve_backend(cfg, path_part, "", Some(req), None)?;
    let balancer = path_part
        .trim()
        .strip_prefix("balancer://")
        .map(|name| name.trim_end_matches('/').to_string());
    let fail_on_status = balancer
        .as_ref()
        .and_then(|name| cfg.balancers.iter().find(|b| b.name == *name))
        .map(|b| b.fail_on_status.clone())
        .unwrap_or_default();
    let proxy_url = canonical_proxy_url(&backend, &path);
    Some(Target {
        path,
        suffix: String::new(),
        backend,
        reverse: scope.proxy_policy.proxy_reverses.clone(),
        balancer,
        fail_on_status,
        proxy_url,
        logical_url: Some(path_part.to_string()),
        route_order: usize::MAX,
    })
}

/// True when the request matches a balancer route but every member is
/// currently unhealthy.  Apollo-style callers use this to return 503 rather
/// than accidentally falling through to a document-root 404.
pub fn balancer_unavailable(cfg: &Config, scope: &Scope, url_path: &str) -> bool {
    for rule in &scope.proxy_policy.proxy_passes {
        if prefix_suffix(&rule.prefix, url_path).is_none() {
            continue;
        }
        if rule.backend.trim_start().starts_with("balancer://")
            && resolve_backend(cfg, &rule.backend, "", None, None).is_none()
        {
            return true;
        }
    }
    for rule in &scope.proxy_policy.proxy_rules {
        if !rule.pattern.is_match(url_path.as_bytes()) {
            continue;
        }
        if rule.backend.trim_start().starts_with("balancer://")
            && resolve_backend(cfg, &rule.backend, "", None, None).is_none()
        {
            return true;
        }
    }
    false
}

pub fn match_target(cfg: &Config, scope: &Scope, url_path: &str) -> Option<Target> {
    match_target_req(cfg, scope, url_path, None)
}

/// True when the URL matches a configured proxy route, without selecting a
/// backend or advancing balancer state.
pub fn matches_route(scope: &Scope, url_path: &str) -> bool {
    scope
        .proxy_policy
        .proxy_passes
        .iter()
        .any(|rule| prefix_suffix(&rule.prefix, url_path).is_some())
        || scope
            .proxy_policy
            .proxy_rules
            .iter()
            .any(|rule| rule.pattern.is_match(url_path.as_bytes()))
}

/// Request-metered route predicate for policy/cache paths that must classify
/// a proxy without selecting a backend or advancing balancer state.
pub(crate) fn matches_route_req(
    scope: &Scope,
    url_path: &str,
    req: &Request,
) -> Result<bool, &'static str> {
    for rule in &scope.proxy_policy.proxy_passes {
        req.charge_policy_work(
            (rule.prefix.len() as u64)
                .saturating_add(url_path.len() as u64)
                .saturating_add(1),
        )?;
        if prefix_suffix(&rule.prefix, url_path).is_some() {
            return Ok(true);
        }
    }
    for rule in &scope.proxy_policy.proxy_rules {
        req.charge_policy_work(
            (rule.pattern.as_str().len() as u64)
                .saturating_add(url_path.len() as u64)
                .saturating_add(1),
        )?;
        if rule.pattern.is_match(url_path.as_bytes()) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn match_target_req(
    cfg: &Config,
    scope: &Scope,
    url_path: &str,
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
        let Some((backend, path)) = resolve_backend(
            cfg,
            &rule.backend,
            suffix,
            req,
            rule.sticky_cookie.as_deref(),
        ) else {
            continue;
        };
        {
            let balancer = rule
                .backend
                .strip_prefix("balancer://")
                .map(|n| n.trim_end_matches('/').to_string());
            let fail_on_status = balancer
                .as_ref()
                .and_then(|name| cfg.balancers.iter().find(|b| b.name == *name))
                .map(|b| b.fail_on_status.clone())
                .unwrap_or_default();
            let proxy_url = canonical_proxy_url(&backend, &path);
            let logical_url = format!(
                "{}/{}",
                rule.backend.trim_end_matches('/'),
                suffix.trim_start_matches('/')
            );
            let candidate = Target {
                path,
                suffix: suffix.to_string(),
                backend,
                reverse: scope.proxy_policy.proxy_reverses.clone(),
                balancer,
                fail_on_status,
                proxy_url,
                logical_url: Some(logical_url),
                route_order: rule.route_order,
            };
            if best
                .as_ref()
                .map(|b| candidate.route_order < b.route_order)
                .unwrap_or(true)
            {
                best = Some(candidate);
            }
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
        let Some(caps) = rule.pattern.captures(url_path.as_bytes()) else {
            continue;
        };
        let captured = caps
            .get(1)
            .or_else(|| caps.get(0))
            .and_then(|m| std::str::from_utf8(m.as_bytes()).ok().map(str::to_owned))
            .unwrap_or_else(|| url_path.to_string());
        let captured = captured.trim_start_matches('/');
        let replaces = (0..caps.len()).any(|index| rule.backend.contains(&format!("${index}")));
        let Some(raw) = crate::util::expand_regex_captures(&rule.backend, &caps) else {
            if let Some(req) = req {
                let _ = req.charge_policy_expansion(u64::MAX);
            }
            return None;
        };
        if let Some(req) = req {
            if req.charge_policy_expansion(raw.len() as u64).is_err() {
                return None;
            }
        }
        if let Some((backend, path)) =
            resolve_backend(cfg, &raw, if replaces { "" } else { captured }, req, None)
        {
            let path = if replaces {
                parse_http_url(&path).map(|b| b.base).unwrap_or(path)
            } else {
                path
            };
            let balancer = rule
                .backend
                .strip_prefix("balancer://")
                .map(|n| n.trim_end_matches('/').to_string());
            let fail_on_status = balancer
                .as_ref()
                .and_then(|name| cfg.balancers.iter().find(|b| b.name == *name))
                .map(|b| b.fail_on_status.clone())
                .unwrap_or_default();
            let proxy_url = canonical_proxy_url(&backend, &path);
            let candidate = Target {
                path,
                suffix: if replaces {
                    String::new()
                } else {
                    captured.to_string()
                },
                backend,
                reverse: scope.proxy_policy.proxy_reverses.clone(),
                balancer,
                fail_on_status,
                proxy_url,
                logical_url: Some(raw.clone()),
                route_order: rule.route_order,
            };
            if best
                .as_ref()
                .map(|b| candidate.route_order < b.route_order)
                .unwrap_or(true)
            {
                best = Some(candidate);
            }
        }
    }
    best
}

fn encode_proxy_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if b <= b' '
            || b >= 0x7f
            || matches!(
                b,
                b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}' | b'%' | b'?' | b'#'
            )
        {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        } else {
            out.push(b as char);
        }
    }
    out
}

/// A reverse proxy cannot infer how every upstream interprets semicolon path
/// parameters.  Servlet containers commonly strip them from each segment,
/// which can turn `/public/..;x/admin` into `/admin` after Vapache has already
/// routed and authorized the former identity.  Refuse that ambiguous boundary
/// instead of forwarding one byte representation under two security names.
fn proxy_path_identity_safe(front_path: &str, upstream_path: &str) -> bool {
    crate::verified::proxy_path_representation_admit(
        front_path.as_bytes(),
        upstream_path.as_bytes(),
    )
}

/// Final serialization gate for an upstream request head.  Every value that
/// can come from configuration, a rewrite or a request is checked with the
/// same token/header predicates used for native responses before `write_all`.
fn validate_proxy_head(head: &[u8]) -> std::io::Result<()> {
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidInput, "unsafe proxy head");
    if !head.ends_with(b"\r\n\r\n") {
        return Err(invalid());
    }
    let mut raw_lines = head.split(|byte| *byte == b'\n').peekable();
    let request = raw_lines
        .next()
        .and_then(|line| line.strip_suffix(b"\r"))
        .ok_or_else(invalid)?;
    let mut parts = request.split(|byte| *byte == b' ');
    let method = parts.next().ok_or_else(invalid)?;
    let target = parts.next().ok_or_else(invalid)?;
    let version = parts.next().ok_or_else(invalid)?;
    if parts.next().is_some() || !crate::verified::proxy_request_line_admit(method, target, version)
    {
        return Err(invalid());
    }
    let mut terminated = false;
    while let Some(raw_line) = raw_lines.next() {
        // split() yields one empty element after the final LF. It is valid
        // only after the one header terminator; an earlier lone LF or a field
        // after the terminator would give the backend a different message
        // boundary than the validator.
        if raw_line.is_empty() {
            if terminated && raw_lines.peek().is_none() {
                continue;
            }
            return Err(invalid());
        }
        let line = raw_line.strip_suffix(b"\r").ok_or_else(invalid)?;
        if line.is_empty() {
            if terminated {
                return Err(invalid());
            }
            terminated = true;
            continue;
        }
        if terminated {
            return Err(invalid());
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(invalid)?;
        let (name, rest) = line.split_at(colon);
        let value = &rest[1..];
        if !crate::verified::proxy_header_admit(name, value) {
            return Err(invalid());
        }
    }
    if terminated {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// A proxy head that passed the verified serialization gate.  Upstream write
/// sites take this type rather than raw bytes, so the "validate before
/// every write" rule is visible at the call site and cannot be skipped by
/// accident when a new path is added.
struct ValidatedProxyHead(Vec<u8>);

impl ValidatedProxyHead {
    /// Validate the *sources* of the authority text as well as the finished
    /// head.  Checking only the final string is not enough: a host value
    /// containing CRLF followed by a syntactically valid `Name: value` line
    /// looks like an ordinary additional header.  The component checks make
    /// that shape unrepresentable even if a future parser/rewrite supplies it.
    fn new(
        head: Vec<u8>,
        backend: &HttpBackend,
        forwarded_host: Option<&str>,
    ) -> std::io::Result<Self> {
        if !valid_backend_host(&backend.host) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsafe proxy backend host",
            ));
        }
        if let Some(host) = forwarded_host {
            if !valid_forwarded_host(host) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "unsafe X-Forwarded-Host",
                ));
            }
        }
        validate_proxy_head(&head)?;
        Ok(Self(head))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn append_proxy_header(head: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    head.extend_from_slice(name);
    head.extend_from_slice(b": ");
    head.extend_from_slice(value);
    head.extend_from_slice(b"\r\n");
}

fn hop_by_hop(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
}

fn forwarded_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("x-forwarded-for")
        || name.eq_ignore_ascii_case("forwarded")
        || name.eq_ignore_ascii_case("x-forwarded-proto")
        || name.eq_ignore_ascii_case("x-forwarded-host")
        || name.eq_ignore_ascii_case("x-real-ip")
}

fn connection_tokens(value: &[u8]) -> Vec<String> {
    value
        .split(|byte| *byte == b',')
        .map(trim_ascii_bytes)
        .filter(|token| crate::verified::valid_token(token))
        .filter_map(|token| String::from_utf8(token.to_ascii_lowercase()).ok())
        .collect()
}

fn request_connection_tokens(req: &Request) -> Vec<String> {
    let mut tokens = Vec::new();
    for name in ["connection", "proxy-connection"] {
        if let Some(value) = req.header(name) {
            tokens.extend(connection_tokens(value));
        }
    }
    tokens
}

fn read_line(reader: &mut impl BufRead) -> std::io::Result<Vec<u8>> {
    // `BufRead::read_until` only reports the limit after allocating the whole
    // peer-controlled line.  Inspect the reader's existing buffer and refuse
    // excess bytes before copying them into our allocation instead.
    let mut line = Vec::with_capacity(MAX_PROXY_LINE.min(1024));
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof",
            ));
        }
        if let Some(end) = available.iter().position(|byte| *byte == b'\n') {
            let take = end + 1;
            if line.len().saturating_add(take) > MAX_PROXY_LINE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "proxy line too long",
                ));
            }
            line.extend_from_slice(&available[..take]);
            reader.consume(take);
            break;
        }
        if line.len().saturating_add(available.len()) > MAX_PROXY_LINE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "proxy line too long",
            ));
        }
        let take = available.len();
        line.extend_from_slice(available);
        reader.consume(take);
    }
    if !line.ends_with(b"\r\n") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "proxy line is not CRLF terminated",
        ));
    }
    line.truncate(line.len() - 2);
    Ok(line)
}

fn parse_proxy_status_line(line: &[u8]) -> Option<u16> {
    crate::verified::proxy_response_status_line_parse(line)
}

fn read_chunked(reader: &mut impl BufRead, out: &mut impl ProxyBodySink) -> std::io::Result<()> {
    let mut framing_budget = crate::http::ChunkFramingBudget::default();
    loop {
        let line = read_line(reader)?;
        let size = crate::http::parse_chunk_size_line(&line)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunk"))?;
        framing_budget.charge(line.len(), size != 0)?;
        if size == 0 {
            // Bound both trailer bytes and count; an untrusted backend must
            // not be able to turn trailers into an unbounded read.
            let mut trailer_bytes = 0usize;
            let mut trailer_count = 0usize;
            loop {
                let line = read_line(reader)?;
                if line.is_empty() {
                    return Ok(());
                }
                if !crate::http::valid_trailer_field(&line) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid proxy trailer",
                    ));
                }
                trailer_count += 1;
                trailer_bytes = trailer_bytes.saturating_add(line.len() + 2);
                if trailer_count > MAX_PROXY_TRAILERS || trailer_bytes > MAX_PROXY_TRAILER_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "proxy trailers too large",
                    ));
                }
            }
        }
        out.len()
            .checked_add(size)
            .filter(|end| *end <= MAX_PROXY_BODY)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::FileTooLarge, "proxy body too large")
            })?;
        let mut remaining = size;
        let mut chunk = [0u8; 64 * 1024];
        while remaining > 0 {
            let take = remaining.min(chunk.len());
            reader.read_exact(&mut chunk[..take])?;
            out.push_bytes(&chunk[..take])?;
            remaining -= take;
        }
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad chunk crlf",
            ));
        }
    }
}

fn rewrite_location(location: &mut Vec<u8>, reverse: &[ProxyReverseRule]) {
    for rule in reverse {
        let backend = rule.backend.trim_end_matches('/').as_bytes();
        if location.starts_with(backend) {
            let rest = location[backend.len()..].to_vec();
            let mut rewritten = rule.front.trim_end_matches('/').as_bytes().to_vec();
            if rest.is_empty() {
                rewritten.push(b'/');
            } else if rest.starts_with(b"/") {
                rewritten.extend_from_slice(&rest);
            } else {
                return;
            }
            *location = rewritten;
            return;
        }
    }
}

fn error(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    req: &Request,
    path: &str,
    port: u16,
    host: &str,
    peer: std::net::IpAddr,
    local_ip: &str,
) -> Response {
    crate::files::error_response(
        cfg, vhost, scope, 502, req, path, port, host, peer, local_ip,
    )
}

pub fn is_websocket(req: &Request) -> bool {
    if req.method != "GET"
        || req.version != Version::Http11
        || req.expect_continue
        || !matches!(req.framing, crate::verified::BodyFraming::None)
    {
        return false;
    }
    let upgrade = req
        .header("upgrade")
        .map(|v| {
            v.split(|b| *b == b',')
                .any(|token| trim_ascii_bytes(token).eq_ignore_ascii_case(b"websocket"))
        })
        .unwrap_or(false);
    let connection = req
        .header("connection")
        .map(|v| {
            v.split(|b| *b == b',')
                .any(|token| trim_ascii_bytes(token).eq_ignore_ascii_case(b"upgrade"))
        })
        .unwrap_or(false);
    let version_ok = req
        .header("sec-websocket-version")
        .map(trim_ascii_bytes)
        .map(|v| v == b"13")
        .unwrap_or(false);
    let key_len = req
        .header("sec-websocket-key")
        .map(trim_ascii_bytes)
        .and_then(|key| {
            STANDARD
                .decode(key)
                .or_else(|_| STANDARD_NO_PAD.decode(key))
                .ok()
        })
        .map(|key| key.len() == 16)
        .unwrap_or(false);
    upgrade && connection && version_ok && key_len
}

fn websocket_accept(key: &str) -> Option<String> {
    let key = key.trim();
    let decoded = STANDARD
        .decode(key)
        .or_else(|_| STANDARD_NO_PAD.decode(key))
        .ok()?;
    if decoded.len() != 16 {
        return None;
    }
    // RFC 6455 hashes the base64 text of the client key, not its decoded bytes.
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    Some(STANDARD.encode(hasher.finalize()))
}

struct AsyncResponseHead {
    head: Vec<u8>,
    initial: Vec<u8>,
}

async fn read_async_head<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<AsyncResponseHead> {
    let mut response = Vec::new();
    loop {
        if let Some(p) = response.windows(4).position(|w| w == b"\r\n\r\n") {
            let end = p + 4;
            if end > MAX_PROXY_HEAD {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "websocket headers too large",
                ));
            }
            let initial = response.split_off(end);
            return Ok(AsyncResponseHead {
                head: response,
                initial,
            });
        }
        if response.len() > MAX_PROXY_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "websocket headers too large",
            ));
        }
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "websocket upstream closed",
            ));
        }
        response.extend_from_slice(&buf[..n]);
    }
}

fn strict_connection_options(value: &[u8]) -> Option<crate::http::ResponseHeaderSanitizer> {
    let mut options = crate::http::ResponseHeaderSanitizer::new();
    options.add_connection_value(value).ok()?;
    Some(options)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WebSocketExtension {
    name: Vec<u8>,
    params: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WebSocketOffer {
    protocols: Vec<Vec<u8>>,
    extensions: Vec<WebSocketExtension>,
}

fn invalid_websocket_negotiation(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn skip_websocket_ows(value: &[u8], cursor: &mut usize) {
    while value
        .get(*cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        *cursor += 1;
    }
}

fn parse_websocket_token<'a>(value: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let start = *cursor;
    while value
        .get(*cursor)
        .is_some_and(|byte| crate::verified::valid_token(std::slice::from_ref(byte)))
    {
        *cursor += 1;
    }
    (*cursor > start).then_some(&value[start..*cursor])
}

fn parse_websocket_quoted(value: &[u8], cursor: &mut usize) -> Option<Vec<u8>> {
    if value.get(*cursor) != Some(&b'"') {
        return None;
    }
    *cursor += 1;
    let mut decoded = Vec::new();
    while let Some(byte) = value.get(*cursor).copied() {
        *cursor += 1;
        match byte {
            b'"' => return Some(decoded),
            b'\\' => {
                let escaped = value.get(*cursor).copied()?;
                if !(escaped == b'\t' || (b' '..=b'~').contains(&escaped) || escaped >= 0x80) {
                    return None;
                }
                *cursor += 1;
                decoded.push(escaped);
            }
            b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' => decoded.push(byte),
            0x80..=0xff => decoded.push(byte),
            _ => return None,
        }
    }
    None
}

fn parse_websocket_protocol_values<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
) -> std::io::Result<Vec<Vec<u8>>> {
    let mut protocols: Vec<Vec<u8>> = Vec::new();
    for value in values {
        for raw in value.split(|byte| *byte == b',') {
            let protocol = trim_ascii_bytes(raw);
            if !crate::verified::valid_token(protocol)
                || protocols.iter().any(|seen| seen.as_slice() == protocol)
                || protocols.len() >= MAX_WEBSOCKET_NEGOTIATION_ITEMS
            {
                return Err(invalid_websocket_negotiation(
                    "invalid or duplicate WebSocket subprotocol",
                ));
            }
            protocols.push(protocol.to_vec());
        }
    }
    Ok(protocols)
}

fn parse_websocket_extension_values<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
) -> std::io::Result<Vec<WebSocketExtension>> {
    let mut extensions = Vec::new();
    for value in values {
        let mut cursor = 0usize;
        skip_websocket_ows(value, &mut cursor);
        if cursor == value.len() {
            return Err(invalid_websocket_negotiation(
                "empty WebSocket extension offer",
            ));
        }
        loop {
            if extensions.len() >= MAX_WEBSOCKET_NEGOTIATION_ITEMS {
                return Err(invalid_websocket_negotiation(
                    "too many WebSocket extension offers",
                ));
            }
            let name = parse_websocket_token(value, &mut cursor)
                .ok_or_else(|| invalid_websocket_negotiation("invalid WebSocket extension"))?
                .to_vec();
            let mut params: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
            skip_websocket_ows(value, &mut cursor);
            while value.get(cursor) == Some(&b';') {
                cursor += 1;
                skip_websocket_ows(value, &mut cursor);
                let param_name = parse_websocket_token(value, &mut cursor)
                    .ok_or_else(|| {
                        invalid_websocket_negotiation("invalid WebSocket extension parameter")
                    })?
                    .to_vec();
                if params.len() >= MAX_WEBSOCKET_EXTENSION_PARAMS
                    || params.iter().any(|(seen, _)| {
                        seen.as_slice().eq_ignore_ascii_case(param_name.as_slice())
                    })
                {
                    return Err(invalid_websocket_negotiation(
                        "duplicate or excessive WebSocket extension parameter",
                    ));
                }
                skip_websocket_ows(value, &mut cursor);
                let param_value = if value.get(cursor) == Some(&b'=') {
                    cursor += 1;
                    skip_websocket_ows(value, &mut cursor);
                    let parsed = if value.get(cursor) == Some(&b'"') {
                        parse_websocket_quoted(value, &mut cursor)
                            .filter(|decoded| crate::verified::valid_token(decoded))
                    } else {
                        parse_websocket_token(value, &mut cursor).map(<[u8]>::to_vec)
                    }
                    .ok_or_else(|| {
                        invalid_websocket_negotiation("invalid WebSocket extension parameter value")
                    })?;
                    Some(parsed)
                } else {
                    None
                };
                params.push((param_name, param_value));
                skip_websocket_ows(value, &mut cursor);
            }
            extensions.push(WebSocketExtension { name, params });
            match value.get(cursor) {
                None => break,
                Some(b',') => {
                    cursor += 1;
                    skip_websocket_ows(value, &mut cursor);
                    if cursor == value.len() {
                        return Err(invalid_websocket_negotiation(
                            "trailing comma in WebSocket extensions",
                        ));
                    }
                }
                _ => {
                    return Err(invalid_websocket_negotiation(
                        "invalid WebSocket extension separator",
                    ));
                }
            }
        }
    }
    Ok(extensions)
}

fn websocket_offer(req: &Request) -> std::io::Result<WebSocketOffer> {
    Ok(WebSocketOffer {
        protocols: parse_websocket_protocol_values(req.headers.get_all("sec-websocket-protocol"))?,
        extensions: parse_websocket_extension_values(
            req.headers.get_all("sec-websocket-extensions"),
        )?,
    })
}

/// Validate optional negotiation fields before routing or opening an upstream
/// connection. The core Upgrade fields are checked by [`is_websocket`].
pub fn websocket_negotiation_offer_valid(req: &Request) -> bool {
    websocket_offer(req).is_ok()
}

fn append_websocket_extensions(out: &mut Vec<u8>, extensions: &[WebSocketExtension]) {
    let mut value = Vec::new();
    for (extension_index, extension) in extensions.iter().enumerate() {
        if extension_index != 0 {
            value.extend_from_slice(b", ");
        }
        value.extend_from_slice(&extension.name);
        for (name, parameter) in &extension.params {
            value.extend_from_slice(b"; ");
            value.extend_from_slice(name);
            let Some(parameter) = parameter else {
                continue;
            };
            value.push(b'=');
            if crate::verified::valid_token(parameter) {
                value.extend_from_slice(parameter);
            } else {
                value.push(b'"');
                for byte in parameter {
                    if matches!(byte, b'"' | b'\\') {
                        value.push(b'\\');
                    }
                    value.push(*byte);
                }
                value.push(b'"');
            }
        }
    }
    append_proxy_header(out, b"Sec-WebSocket-Extensions", &value);
}

fn websocket_response_status(head: &[u8]) -> std::io::Result<u16> {
    let mut reader = BufReader::new(std::io::Cursor::new(head));
    let status_line = read_line(&mut reader)?;
    if !status_line.starts_with(b"HTTP/1.1 ") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "websocket backend response is not HTTP/1.1",
        ));
    }
    parse_proxy_status_line(&status_line).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad websocket backend status",
        )
    })
}

/// Reconstruct a WebSocket switching response instead of forwarding the
/// backend's raw HTTP/1 bytes. A 101 changes the protocol interpretation of
/// every following octet, so duplicate handshake fields or CL/TE metadata are
/// response-desynchronization hazards even when the required first value is
/// correct.
fn canonical_websocket_switching_head(
    head: &[u8],
    expected_accept: &str,
    offer: &WebSocketOffer,
) -> std::io::Result<Vec<u8>> {
    let mut reader = BufReader::new(std::io::Cursor::new(head));
    let status_line = read_line(&mut reader)?;
    if !status_line.starts_with(b"HTTP/1.1 ") || parse_proxy_status_line(&status_line) != Some(101)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "websocket backend did not switch protocols",
        ));
    }

    let mut saw_upgrade = false;
    let mut saw_connection = false;
    let mut saw_accept = false;
    let mut selected_protocol = None;
    let mut extension_fields = Vec::new();
    let mut forwarded = Vec::new();
    let mut header_count = 0usize;
    loop {
        let line = read_line(&mut reader)?;
        if line.is_empty() {
            break;
        }
        header_count = header_count.saturating_add(1);
        if !crate::verified::response_header_budget_admit(
            header_count as u64,
            head.len() as u64,
            MAX_PROXY_HEADERS as u64,
            MAX_PROXY_HEAD as u64,
        ) {
            return Err(invalid_websocket_negotiation(
                "WebSocket response headers exceed budget",
            ));
        }
        let colon = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed websocket backend header",
            )
        })?;
        let name = &line[..colon];
        let value = trim_ascii_bytes(&line[colon + 1..]);
        if !crate::verified::proxy_response_header_admit(name, value) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid websocket backend header",
            ));
        }
        let lower = name.to_ascii_lowercase();
        match lower.as_slice() {
            b"upgrade" => {
                let canonical = strict_connection_options(value).is_some_and(|options| {
                    options.connection_option_count() == 1
                        && options.has_connection_option("websocket")
                });
                if saw_upgrade || !canonical {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "ambiguous websocket Upgrade header",
                    ));
                }
                saw_upgrade = true;
            }
            b"connection" => {
                let canonical = strict_connection_options(value).is_some_and(|options| {
                    options.connection_option_count() == 1
                        && options.has_connection_option("upgrade")
                });
                if saw_connection || !canonical {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "ambiguous websocket Connection header",
                    ));
                }
                saw_connection = true;
            }
            b"sec-websocket-accept" => {
                if saw_accept || value != expected_accept.as_bytes() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid websocket accept value",
                    ));
                }
                saw_accept = true;
            }
            b"sec-websocket-protocol" => {
                let protocols = parse_websocket_protocol_values([value])?;
                let protocol = protocols.first();
                let offered = protocol.is_some_and(|protocol| {
                    offer
                        .protocols
                        .iter()
                        .any(|candidate| candidate == protocol)
                });
                if !crate::verified::websocket_negotiation_selection_admit(
                    protocols.len() == 1,
                    offered,
                    selected_protocol.is_some(),
                ) {
                    return Err(invalid_websocket_negotiation(
                        "unoffered or ambiguous WebSocket subprotocol",
                    ));
                }
                selected_protocol = protocol.cloned();
            }
            b"sec-websocket-extensions" => extension_fields.push(value.to_vec()),
            b"sec-websocket-key" | b"sec-websocket-version" => {
                return Err(invalid_websocket_negotiation(
                    "request-only field in WebSocket switching response",
                ));
            }
            b"content-length"
            | b"transfer-encoding"
            | b"proxy-connection"
            | b"keep-alive"
            | b"proxy-authenticate"
            | b"proxy-authorization"
            | b"trailer"
            | b"te" => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "framing metadata in websocket switching response",
                ));
            }
            _ => forwarded.push((name.to_vec(), value.to_vec())),
        }
    }
    if !saw_upgrade || !saw_connection || !saw_accept {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "incomplete websocket switching response",
        ));
    }

    let selected_extensions =
        parse_websocket_extension_values(extension_fields.iter().map(Vec::as_slice))?;
    let mut admitted_extensions: Vec<WebSocketExtension> = Vec::new();
    for extension in selected_extensions {
        let offered = offer.extensions.iter().any(|candidate| {
            candidate
                .name
                .as_slice()
                .eq_ignore_ascii_case(extension.name.as_slice())
        });
        let duplicate = admitted_extensions.iter().any(|candidate| {
            candidate
                .name
                .as_slice()
                .eq_ignore_ascii_case(extension.name.as_slice())
        });
        if !crate::verified::websocket_negotiation_selection_admit(true, offered, duplicate) {
            return Err(invalid_websocket_negotiation(
                "unoffered or duplicate WebSocket extension selection",
            ));
        }
        admitted_extensions.push(extension);
    }

    let mut canonical =
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            .to_vec();
    append_proxy_header(
        &mut canonical,
        b"Sec-WebSocket-Accept",
        expected_accept.as_bytes(),
    );
    if let Some(protocol) = selected_protocol {
        append_proxy_header(&mut canonical, b"Sec-WebSocket-Protocol", &protocol);
    }
    if !admitted_extensions.is_empty() {
        append_websocket_extensions(&mut canonical, &admitted_extensions);
    }
    for (name, value) in forwarded {
        append_proxy_header(&mut canonical, &name, &value);
    }
    canonical.extend_from_slice(b"\r\n");
    if !crate::verified::response_header_budget_admit(
        header_count as u64,
        canonical.len() as u64,
        MAX_PROXY_HEADERS as u64,
        MAX_PROXY_HEAD as u64,
    ) {
        return Err(invalid_websocket_negotiation(
            "canonical WebSocket response exceeds budget",
        ));
    }
    Ok(canonical)
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

struct DnsJob {
    host: String,
    port: u16,
    deadline: Instant,
    reply: mpsc::Sender<std::io::Result<Vec<SocketAddr>>>,
}

fn isolated_dns_lookup(
    job: &DnsJob,
    unreaped: &mut Vec<std::process::Child>,
) -> std::io::Result<Vec<SocketAddr>> {
    unreaped.retain_mut(|child| match child.try_wait() {
        Ok(Some(_)) => false,
        Ok(None) | Err(_) => true,
    });
    if unreaped.len() >= 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "too many unreaped resolver helpers",
        ));
    }
    let remaining = job.deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "proxy DNS request expired in queue",
        ));
    }
    let current_executable = std::env::current_exe()?;
    // Unit tests run from target/*/deps/vapached-<hash>; the sibling daemon
    // binary still owns the hidden resolver entrypoint.
    let executable = current_executable
        .parent()
        .filter(|parent| parent.file_name().is_some_and(|name| name == "deps"))
        .and_then(Path::parent)
        .map(|parent| parent.join("vapached"))
        .filter(|candidate| candidate.is_file())
        .unwrap_or(current_executable);
    let mut child = std::process::Command::new(executable)
        .arg("--vapache-resolver-worker")
        .arg(&job.host)
        .arg(job.port.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .env_clear()
        .spawn()?;
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "proxy DNS lookup failed",
                ));
            }
            let output = child.wait_with_output()?;
            let text = std::str::from_utf8(&output.stdout).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid resolver output")
            })?;
            let mut addresses = Vec::new();
            for line in text.lines() {
                if addresses.len() == MAX_PROXY_ADDRESSES {
                    break;
                }
                let address = line.parse::<SocketAddr>().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid resolver address")
                })?;
                if address.port() != job.port {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "resolver returned the wrong port",
                    ));
                }
                addresses.push(address);
            }
            if addresses.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "proxy DNS lookup returned no addresses",
                ));
            }
            return Ok(addresses);
        }
        if Instant::now() >= job.deadline {
            let _ = child.kill();
            // Never block the fixed worker waiting for a wedged system
            // resolver. Reap immediately when possible; otherwise retain a
            // bounded handle and retry before this worker's next job.
            if !child.try_wait().is_ok_and(|status| status.is_some()) {
                unreaped.push(child);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "proxy DNS timeout",
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn dns_sender() -> &'static SyncSender<DnsJob> {
    static DNS: OnceLock<SyncSender<DnsJob>> = OnceLock::new();
    DNS.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<DnsJob>(64);
        let rx = Arc::new(Mutex::new(rx));
        for index in 0..8 {
            let rx = rx.clone();
            let _ = std::thread::Builder::new()
                .name(format!("proxy-dns-{index}"))
                .spawn(move || {
                    let mut unreaped = Vec::new();
                    loop {
                        let job = {
                            let guard = rx.lock().unwrap_or_else(|error| error.into_inner());
                            guard.recv()
                        };
                        let Ok(job) = job else {
                            break;
                        };
                        let result = isolated_dns_lookup(&job, &mut unreaped);
                        let _ = job.reply.send(result);
                    }
                });
        }
        tx
    })
}

fn literal_backend_addrs(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    if host.eq_ignore_ascii_case("localhost") {
        return Some(vec![
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port),
        ]);
    }
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| vec![SocketAddr::new(ip, port)])
}

fn submit_dns(
    host: &str,
    port: u16,
    timeout: Duration,
) -> std::io::Result<Receiver<std::io::Result<Vec<SocketAddr>>>> {
    let (reply, rx) = mpsc::channel();
    dns_sender()
        .try_send(DnsJob {
            host: host.to_string(),
            port,
            deadline: Instant::now() + timeout,
            reply,
        })
        .map_err(|error| match error {
            TrySendError::Full(_) => {
                std::io::Error::new(std::io::ErrorKind::WouldBlock, "proxy DNS queue is full")
            }
            TrySendError::Disconnected(_) => std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "proxy DNS workers are unavailable",
            ),
        })?;
    Ok(rx)
}

fn backend_identity_key(host: &str, port: u16) -> (String, u16) {
    (host.to_ascii_lowercase(), port)
}

fn bound_backend_identity(
    registry: &BackendIdentityRegistry,
    host: &str,
    port: u16,
) -> Option<Vec<SocketAddr>> {
    registry
        .identities
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(&backend_identity_key(host, port))
        .cloned()
}

/// Atomically establish the DNS result which belongs to this configuration
/// generation. Concurrent first lookups may complete with different answers;
/// only the first result becomes authoritative and every caller receives it.
fn bind_backend_identity(
    registry: &BackendIdentityRegistry,
    host: &str,
    port: u16,
    addresses: Vec<SocketAddr>,
) -> std::io::Result<Vec<SocketAddr>> {
    let key = backend_identity_key(host, port);
    let mut identities = registry
        .identities
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(bound) = identities.get(&key) {
        return Ok(bound.clone());
    }
    if identities.len() >= MAX_BACKEND_IDENTITIES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "backend identity table is full",
        ));
    }
    let resolver_result_valid = !addresses.is_empty()
        && addresses.len() <= MAX_PROXY_ADDRESSES
        && addresses.iter().all(|address| address.port() == port);
    if !vapache_verified::backend_resolution_binding_admit(
        registry.generation,
        registry.generation,
        resolver_result_valid,
    ) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "resolver returned an invalid backend identity",
        ));
    }
    identities.insert(key, addresses.clone());
    Ok(addresses)
}

fn connected_endpoint_admitted(actual: SocketAddr, selected: SocketAddr) -> bool {
    vapache_verified::backend_connected_endpoint_admit(actual == selected, true)
}

pub(crate) fn resolve_backend_addrs(
    registry: &BackendIdentityRegistry,
    host: &str,
    port: u16,
    timeout: Duration,
) -> std::io::Result<Vec<SocketAddr>> {
    resolve_backend_addrs_cancellable(registry, host, port, timeout, None)
}

pub(crate) fn resolve_backend_addrs_cancellable(
    registry: &BackendIdentityRegistry,
    host: &str,
    port: u16,
    timeout: Duration,
    request_scope: Option<&crate::resource::RequestScope>,
) -> std::io::Result<Vec<SocketAddr>> {
    if request_scope.is_some_and(crate::resource::RequestScope::is_cancelled) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "proxy request scope cancelled",
        ));
    }
    if let Some(addresses) = literal_backend_addrs(host, port) {
        return Ok(addresses);
    }
    if let Some(addresses) = bound_backend_identity(registry, host, port) {
        return Ok(addresses);
    }
    let rx = submit_dns(host, port, timeout)?;
    let deadline = Instant::now() + timeout;
    let addresses = loop {
        if request_scope.is_some_and(crate::resource::RequestScope::is_cancelled) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "proxy request scope cancelled",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "proxy DNS timeout",
            ));
        }
        match rx.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(result) => break result?,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "proxy DNS worker stopped",
                ));
            }
        }
    };
    bind_backend_identity(registry, host, port, addresses)
}

async fn resolve_backend_addrs_async(
    registry: &BackendIdentityRegistry,
    host: &str,
    port: u16,
    timeout: Duration,
) -> std::io::Result<Vec<SocketAddr>> {
    if let Some(addresses) = literal_backend_addrs(host, port) {
        return Ok(addresses);
    }
    if let Some(addresses) = bound_backend_identity(registry, host, port) {
        return Ok(addresses);
    }
    let rx = submit_dns(host, port, timeout)?;
    let deadline = Instant::now() + timeout;
    loop {
        match rx.try_recv() {
            Ok(result) => {
                let addresses = result?;
                return bind_backend_identity(registry, host, port, addresses);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "proxy DNS worker stopped",
                ))
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "proxy DNS timeout",
            ));
        }
        tokio::time::sleep(remaining.min(Duration::from_millis(5))).await;
    }
}

/// Entrypoint for the disposable resolver process. The parent validates this
/// line-oriented protocol and kills the process if libc's resolver wedges.
pub fn resolver_worker_main(host: &str, port: u16) -> std::io::Result<()> {
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid resolver hostname",
        ));
    }
    let mut seen = HashSet::new();
    for address in (host, port).to_socket_addrs()?.take(MAX_PROXY_ADDRESSES) {
        if seen.insert(address) {
            println!("{address}");
        }
    }
    (!seen.is_empty()).then_some(()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "resolver returned no addresses",
        )
    })
}

async fn connect_async(
    backend: &HttpBackend,
    scope: &Scope,
    backend_identities: &BackendIdentityRegistry,
    timeout: Duration,
) -> std::io::Result<Box<dyn AsyncReadWrite>> {
    let deadline = Instant::now() + timeout;
    let mut stream = None;
    for addr in
        resolve_backend_addrs_async(backend_identities, &backend.host, backend.port, timeout)
            .await?
    {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(s)) if connected_endpoint_admitted(s.peer_addr()?, addr) => {
                stream = Some(s);
                break;
            }
            _ => {}
        }
    }
    let stream = stream.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "cannot connect upstream")
    })?;
    crate::resource::configure_transport_fd(&stream)?;
    stream.set_nodelay(true)?;
    if !backend.tls {
        return Ok(Box::new(stream));
    }
    let name = tls_server_name(&backend.host)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad TLS host"))?;
    let connector = tokio_rustls::TlsConnector::from(client_config(scope)?);
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "proxy connection timeout",
        ));
    }
    let tls = tokio::time::timeout(remaining, connector.connect(name, stream))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timeout")
        })??;
    Ok(Box::new(tls))
}

async fn websocket_copy_idle<A, B>(
    client: &mut A,
    upstream: &mut B,
    idle: Duration,
    mut generation_retired: Option<tokio::sync::watch::Receiver<bool>>,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut client_buf = [0u8; 16 * 1024];
    let mut upstream_buf = [0u8; 16 * 1024];
    loop {
        tokio::select! {
            result = async {
                generation_retired.as_mut().expect("guarded retirement receiver").changed().await
            }, if generation_retired.is_some() => {
                let retired = generation_retired
                    .as_ref()
                    .is_none_or(|state| *state.borrow());
                if result.is_err() || !vapache_verified::configuration_generation_admit(retired) {
                    let _ = client.shutdown().await;
                    let _ = upstream.shutdown().await;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "configuration generation retired",
                    ));
                }
            }
            result = client.read(&mut client_buf) => {
                let read = result?;
                if read == 0 {
                    let _ = upstream.shutdown().await;
                    return Ok(());
                }
                tokio::time::timeout(idle, upstream.write_all(&client_buf[..read]))
                    .await
                    .map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "WebSocket upstream write timeout",
                    ))??;
            }
            result = upstream.read(&mut upstream_buf) => {
                let read = result?;
                if read == 0 {
                    let _ = client.shutdown().await;
                    return Ok(());
                }
                tokio::time::timeout(idle, client.write_all(&upstream_buf[..read]))
                    .await
                    .map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "WebSocket client write timeout",
                    ))??;
            }
            _ = tokio::time::sleep(idle) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "WebSocket tunnel idle timeout",
                ));
            }
        }
    }
}

/// Tunnel a WebSocket upgrade over any combination of clear/TLS client and
/// clear/TLS upstream.  The caller supplies the already-parsed request and
/// any bytes buffered after its headers.
#[allow(clippy::too_many_arguments)]
pub async fn websocket_async<S>(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    target: &Target,
    grant: &crate::access::AccessGrant,
    resource: &crate::access::ResourceKey,
    client: S,
    peer: SocketAddr,
    https: bool,
    host: &str,
    initial: &[u8],
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    websocket_async_with_connection(
        cfg, scope, req, target, grant, resource, client, peer, https, host, initial, None, None,
    )
    .await
}

/// Server-side upgrade entry point. The ordinary HTTP/1 connection lease is
/// surrendered only after the dedicated WebSocket lease has been acquired,
/// preserving continuous accounting without double-charging the long-lived
/// tunnel against general request capacity.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn websocket_async_with_connection<S>(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    target: &Target,
    grant: &crate::access::AccessGrant,
    resource: &crate::access::ResourceKey,
    mut client: S,
    peer: SocketAddr,
    https: bool,
    host: &str,
    initial: &[u8],
    general_connection: Option<crate::resource::SlotLease>,
    generation_retired: Option<tokio::sync::watch::Receiver<bool>>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if generation_retired
        .as_ref()
        .is_some_and(|retired| !vapache_verified::configuration_generation_admit(*retired.borrow()))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "configuration generation retired",
        ));
    }
    // Parse the client's complete optional negotiation surface before any
    // routing side effect or upstream connection. The resulting typed offer
    // is the authority used to validate the backend's 101 selection.
    let websocket_offer = websocket_offer(req)?;
    if !proxy_path_identity_safe(&resource.url_path, &target.path)
        || target.path.bytes().any(|byte| byte < b' ' || byte == 0x7f)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ambiguous or invalid websocket target path",
        ));
    }
    let Some(bound) = grant.bind_proxy(
        resource,
        &target.backend.host,
        target.backend.port,
        target.backend.tls,
        &target.path,
    ) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "access grant does not cover websocket target",
        ));
    };
    let expected = bound.key().clone();
    if !bound.require_proxy_sink(
        &expected,
        &target.backend.host,
        target.backend.port,
        target.backend.tls,
        &target.path,
    ) || resource.proxy_url.as_deref() != Some(target.proxy_url.as_str())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "access grant does not cover websocket target",
        ));
    }
    let client_ip = crate::access::canonical_ip(peer.ip());
    let _websocket_lease = cfg.resource_budget.try_websocket_for(client_ip)?;
    drop(general_connection);
    let timeout = cfg.timeout.max(Duration::from_secs(5));
    let mut upstream =
        connect_async(&target.backend, scope, &cfg.backend_identities, timeout).await?;
    // `Target::path` is the decoded authorization identity. Re-encode bytes
    // that could be interpreted as delimiters or a second escape by the
    // upstream, exactly as the ordinary reverse-proxy path does.
    let mut path = encode_proxy_path(&target.path).into_bytes();
    if !req.query.is_empty() {
        path.push(b'?');
        path.extend_from_slice(&req.query);
    }
    let mut head = b"GET ".to_vec();
    head.extend_from_slice(&path);
    head.extend_from_slice(
        format!(
            " HTTP/1.1\r\nHost: {}:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
            target.backend.host, target.backend.port
        )
        .as_bytes(),
    );
    let request_tokens = request_connection_tokens(req);
    for (name, value) in req.headers.iter() {
        if hop_by_hop(name)
            || forwarded_header(name)
            || request_tokens
                .iter()
                .any(|token| token == &name.to_ascii_lowercase())
            || name.eq_ignore_ascii_case("expect")
        {
            continue;
        }
        append_proxy_header(&mut head, name.as_bytes(), value);
    }
    append_proxy_header(
        &mut head,
        b"X-Forwarded-For",
        peer.ip().to_string().as_bytes(),
    );
    append_proxy_header(
        &mut head,
        b"X-Forwarded-Proto",
        if https { b"https" } else { b"http" },
    );
    if !host.is_empty() && !valid_forwarded_host(host) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsafe X-Forwarded-Host",
        ));
    }
    if !host.is_empty() {
        append_proxy_header(&mut head, b"X-Forwarded-Host", host.as_bytes());
    }
    head.extend_from_slice(b"\r\n");
    let head = ValidatedProxyHead::new(
        head,
        &target.backend,
        if host.is_empty() { None } else { Some(host) },
    )?;
    tokio::time::timeout(timeout, upstream.write_all(head.as_bytes()))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "WebSocket request timeout")
        })??;
    let response = tokio::time::timeout(timeout, read_async_head(&mut upstream))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "WebSocket handshake timeout")
        })??;
    if generation_retired
        .as_ref()
        .is_some_and(|retired| !vapache_verified::configuration_generation_admit(*retired.borrow()))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "configuration generation retired",
        ));
    }
    let status = websocket_response_status(&response.head)?;
    if status == 101 {
        let key = req.header_str("sec-websocket-key").unwrap_or("");
        let expected = websocket_accept(key).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid WebSocket client key",
            )
        })?;
        let canonical =
            canonical_websocket_switching_head(&response.head, &expected, &websocket_offer)?;
        tokio::time::timeout(timeout, client.write_all(&canonical))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "WebSocket response timeout")
            })??;
        if !response.initial.is_empty() {
            tokio::time::timeout(timeout, client.write_all(&response.initial))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "WebSocket initial response timeout",
                    )
                })??;
        }
    } else {
        if status < 200 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected interim websocket backend response",
            ));
        }
        // No backend body has been consumed. Reconstruct a complete
        // zero-length response rather than forwarding CL/TE metadata that
        // would make the client wait for or reinterpret bytes we do not own.
        let rejection = format!(
            "HTTP/1.1 {status} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            crate::http::reason_phrase(status)
        );
        tokio::time::timeout(timeout, client.write_all(rejection.as_bytes()))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "WebSocket response timeout")
            })??;
        return Ok(());
    }
    if !initial.is_empty() {
        tokio::time::timeout(timeout, upstream.write_all(initial))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "WebSocket initial data timeout",
                )
            })??;
    }
    client.flush().await?;
    // Once 101 has reached the client an HTTP error can no longer be sent.
    // Tunnel closure (including the idle deadline) is the protocol-correct
    // failure signal, so consume the transport error here.
    let _ = websocket_copy_idle(
        &mut client,
        upstream.as_mut(),
        WEBSOCKET_IDLE_TIMEOUT,
        generation_retired,
    )
    .await;
    Ok(())
}

fn build_client_config(scope: &Scope) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = &scope.proxy_policy.proxy_ca_file {
        let data = crate::files::read_admin_file_with_trust(
            path,
            MAX_PROXY_CA_BYTES,
            scope.proxy_policy.proxy_ca_trust,
        )
        .map_err(|error| format!("cannot read proxy CA {}: {error}", path.display()))?;
        let mut added = 0usize;
        for cert in CertificateDer::pem_slice_iter(&data) {
            let cert =
                cert.map_err(|error| format!("cannot parse proxy CA {}: {error}", path.display()))?;
            roots
                .add(cert)
                .map_err(|error| format!("cannot add proxy CA {}: {error}", path.display()))?;
            added += 1;
        }
        if added == 0 {
            return Err(format!(
                "proxy CA {} contains no certificates",
                path.display()
            ));
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.enable_early_data = false;
    config.enable_secret_extraction = false;
    Ok(Arc::new(config))
}

fn client_config(scope: &Scope) -> std::io::Result<Arc<rustls::ClientConfig>> {
    scope
        .proxy_policy
        .tls_config_cache
        .get_or_init(|| build_client_config(scope))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn connect_tcp(
    backend: &HttpBackend,
    backend_identities: &BackendIdentityRegistry,
    timeout: Duration,
    scope: Option<&crate::resource::RequestScope>,
) -> std::io::Result<TcpStream> {
    crate::fault::hit("proxy.connect")?;
    if scope.is_some_and(crate::resource::RequestScope::is_cancelled) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "proxy request scope cancelled",
        ));
    }
    let deadline = Instant::now() + timeout;
    let mut tcp = None;
    let mut last = None;
    for addr in resolve_backend_addrs_cancellable(
        backend_identities,
        &backend.host,
        backend.port,
        timeout,
        scope,
    )? {
        loop {
            if scope.is_some_and(crate::resource::RequestScope::is_cancelled) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "proxy request scope cancelled",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match TcpStream::connect_timeout(&addr, remaining.min(Duration::from_secs(1))) {
                Ok(stream) if connected_endpoint_admitted(stream.peer_addr()?, addr) => {
                    tcp = Some(stream);
                    break;
                }
                Ok(_) => {
                    last = Some(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "connected proxy peer differs from bound backend identity",
                    ));
                    break;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::TimedOut
                        && Instant::now() < deadline =>
                {
                    last = Some(error);
                }
                Err(error) => {
                    last = Some(error);
                    break;
                }
            }
        }
        if tcp.is_some() {
            break;
        }
    }
    let tcp = tcp.ok_or_else(|| {
        last.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address"))
    })?;
    crate::resource::configure_transport_fd(&tcp)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "proxy connection timeout",
        ));
    }
    let quantum = remaining.min(Duration::from_secs(1));
    tcp.set_read_timeout(Some(quantum))?;
    tcp.set_write_timeout(Some(quantum))?;
    Ok(tcp)
}

fn connect(
    backend: &HttpBackend,
    scope: &Scope,
    backend_identities: &BackendIdentityRegistry,
    timeout: Duration,
    deadline: Instant,
    request_scope: Option<&crate::resource::RequestScope>,
) -> std::io::Result<Box<dyn ReadWrite>> {
    let tcp = connect_tcp(backend, backend_identities, timeout, request_scope)?;
    let inner: Box<dyn ReadWrite> = if !backend.tls {
        Box::new(tcp)
    } else {
        let name = tls_server_name(&backend.host)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad TLS host"))?;
        let conn = ClientConnection::new(client_config(scope)?, name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Box::new(StreamOwned::new(conn, tcp))
    };
    Ok(Box::new(DeadlineStream {
        inner,
        deadline,
        scope: request_scope.cloned(),
    }))
}

fn backend_key(backend: &HttpBackend) -> String {
    format!(
        "{}:{}:{}",
        backend.host,
        backend.port,
        if backend.tls { "tls" } else { "plain" }
    )
}

fn proxy_method_is_idempotent(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "TRACE"
    )
}

struct PoolBodyReader {
    inner: Option<BufReader<Box<dyn ReadWrite>>>,
    remaining: u64,
}

impl PoolBodyReader {
    fn finish(&mut self) {
        self.inner.take();
    }
}

impl Read for PoolBodyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            self.finish();
            return Ok(0);
        }
        let want = (self.remaining as usize).min(buf.len());
        let Some(reader) = self.inner.as_mut() else {
            return Ok(0);
        };
        let n = reader.read(&mut buf[..want])?;
        if n == 0 {
            self.remaining = 0;
            self.finish();
            return Ok(0);
        }
        self.remaining -= n as u64;
        if self.remaining == 0 {
            self.finish();
        }
        Ok(n)
    }
}

impl Drop for PoolBodyReader {
    fn drop(&mut self) {
        if self.remaining == 0 {
            self.finish();
        }
    }
}

#[cfg(any(test, feature = "fuzzing"))]
fn proxy_once(
    stream: Box<dyn ReadWrite>,
    target: &Target,
    req: &Request,
    scope: &Scope,
    url_path: &str,
    peer: SocketAddr,
    https: bool,
    host: &str,
) -> std::io::Result<(Response, Option<Box<dyn ReadWrite>>)> {
    // Parser fuzzing and focused unit tests do not own a full Config. Keep
    // their accounting bounded and isolated from production configuration.
    static TEST_BUDGET: OnceLock<Arc<crate::resource::ResourceBudget>> = OnceLock::new();
    let budget = TEST_BUDGET.get_or_init(|| Arc::new(crate::resource::ResourceBudget::default()));
    proxy_once_budgeted(
        stream,
        budget,
        (MAX_PROXY_BODY as u64 + 1).saturating_mul(4),
        32,
        target,
        req,
        scope,
        url_path,
        peer,
        https,
        host,
    )
}

#[allow(clippy::too_many_arguments)]
fn proxy_once_budgeted(
    mut stream: Box<dyn ReadWrite>,
    resource_budget: &Arc<crate::resource::ResourceBudget>,
    max_spool_bytes: u64,
    max_spool_files: u64,
    target: &Target,
    req: &Request,
    scope: &Scope,
    url_path: &str,
    peer: SocketAddr,
    https: bool,
    host: &str,
) -> std::io::Result<(Response, Option<Box<dyn ReadWrite>>)> {
    #[cfg(any(test, feature = "fuzzing"))]
    let fallback_context;
    let resource_context = match req.resource_context() {
        Some(context) => context,
        None => {
            #[cfg(any(test, feature = "fuzzing"))]
            {
                fallback_context = resource_budget.context(peer.ip());
                &fallback_context
            }
            #[cfg(not(any(test, feature = "fuzzing")))]
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "proxy request has no resource scope",
                ));
            }
        }
    };
    if !proxy_path_identity_safe(&target.path, &target.path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ambiguous proxy target path",
        ));
    }
    let mut path = encode_proxy_path(&target.path).into_bytes();
    if !req.query.is_empty() {
        path.push(b'?');
        path.extend_from_slice(&req.query);
    }
    let mut head = Vec::new();
    head.extend_from_slice(req.method.as_bytes());
    head.push(b' ');
    head.extend_from_slice(&path);
    head.extend_from_slice(
        format!(
            " HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n",
            target.backend.host, target.backend.port
        )
        .as_bytes(),
    );
    let body_len = req.body_len();
    if body_len > 0 {
        append_proxy_header(
            &mut head,
            b"Content-Length",
            body_len.to_string().as_bytes(),
        );
    }
    let request_tokens = request_connection_tokens(req);
    for (name, value) in req.headers.iter() {
        if hop_by_hop(name)
            || forwarded_header(name)
            || request_tokens
                .iter()
                .any(|token| token == &name.to_ascii_lowercase())
            || name.eq_ignore_ascii_case("expect")
        {
            continue;
        }
        append_proxy_header(&mut head, name.as_bytes(), value);
    }
    append_proxy_header(
        &mut head,
        b"X-Forwarded-For",
        peer.ip().to_string().as_bytes(),
    );
    append_proxy_header(
        &mut head,
        b"X-Forwarded-Proto",
        if https { b"https" } else { b"http" },
    );
    if !host.is_empty() && !valid_forwarded_host(host) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsafe X-Forwarded-Host",
        ));
    }
    if !host.is_empty() {
        append_proxy_header(&mut head, b"X-Forwarded-Host", host.as_bytes());
    }
    head.extend_from_slice(b"\r\n");
    let head = ValidatedProxyHead::new(
        head,
        &target.backend,
        if host.is_empty() { None } else { Some(host) },
    )?;
    stream.write_all(head.as_bytes())?;
    if let Some(reader) = req.body_reader() {
        let mut reader = reader?;
        std::io::copy(&mut reader, &mut stream)?;
    } else if !req.body.is_empty() {
        stream.write_all(&req.body)?;
    }

    let mut reader = BufReader::new(stream);
    let status_line = read_line(&mut reader)?;
    let status = parse_proxy_status_line(&status_line)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad status"))?;
    // A normal proxy response cannot be an interim/upgrade response.  The
    // WebSocket path has a separate exact 101 handshake.  Refusing these here
    // prevents a backend from smuggling a second response through the body
    // path.
    if (100..200).contains(&status) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected interim proxy response",
        ));
    }
    let mut headers: Vec<(String, Vec<u8>)> = Vec::new();
    let mut framing_headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut header_sanitizer = crate::http::ResponseHeaderSanitizer::new();
    let mut header_count = 0usize;
    let mut head_bytes = status_line.len();
    loop {
        let line = read_line(&mut reader)?;
        if line.is_empty() {
            break;
        }
        header_count += 1;
        head_bytes += line.len() + 2;
        if header_count > MAX_PROXY_HEADERS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "too many proxy headers",
            ));
        }
        if head_bytes > MAX_PROXY_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "proxy headers too large",
            ));
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed proxy response header",
            ));
        };
        // RFC 9112 forbids whitespace between a field name and its colon.
        // Trimming here would make this proxy accept a different message
        // shape from stricter downstream recipients.
        let name = &line[..colon];
        let value = trim_ascii_bytes(&line[colon + 1..]);
        if !crate::verified::proxy_response_header_admit(name, value) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid proxy response header",
            ));
        }
        framing_headers.push((name.to_ascii_lowercase(), value.to_vec()));
        let name = String::from_utf8(name.to_ascii_lowercase()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid proxy response header name",
            )
        })?;
        if name == "content-length" {
            continue;
        }
        if name == "transfer-encoding" {
            continue;
        }
        if name == "connection" {
            header_sanitizer.add_connection_value(value)?;
            continue;
        }
        if header_sanitizer.is_hop_by_hop(&name) || name == "host" {
            continue;
        }
        if name == "location" {
            let Some(mut clean) = crate::verified::sanitize_header_value(value) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid proxy Location header value",
                ));
            };
            rewrite_location(&mut clean, &target.reverse);
            headers.push((name, clean));
            continue;
        }
        let Some(clean) = crate::verified::sanitize_header_value(value) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid proxy response header value",
            ));
        };
        headers.push((name, clean));
    }
    let connection_disposition = vapache_verified::backend_connection_disposition(
        header_sanitizer.nominates_framing(),
        header_sanitizer.nominates_end_to_end(),
    );
    if connection_disposition == vapache_verified::BackendConnectionDisposition::Reject {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "backend Connection field nominates response framing",
        ));
    }
    headers.retain(|(name, _)| !header_sanitizer.is_hop_by_hop(name));
    let framing =
        crate::verified::proxy_response_framing(req.method == "HEAD", status, &framing_headers)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "ambiguous proxy response framing",
                )
            })?;
    let (no_body, content_length, chunked) = match framing {
        crate::verified::ProxyResponseFraming::NoBody => (true, None, false),
        crate::verified::ProxyResponseFraming::Length(length) => {
            let length = usize::try_from(length).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::FileTooLarge, "proxy body too large")
            })?;
            (false, Some(length), false)
        }
        crate::verified::ProxyResponseFraming::Chunked => (false, None, true),
        crate::verified::ProxyResponseFraming::Eof => (false, None, false),
    };
    if (300..400).contains(&status) {
        // Apache's proxy reverse rules also cover relative Location values.
        if let Some((_, value)) = headers.iter_mut().find(|(n, _)| n == "location") {
            rewrite_location(value, &target.reverse);
        }
    }
    if !no_body && content_length.is_some_and(|length| length > MAX_PROXY_BODY) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            "proxy body too large",
        ));
    }
    // Large fixed-length upstream bodies are forwarded without buffering the
    // whole response in memory.  The pool connection is returned only after
    // the body reader reaches EOF, preserving HTTP/1.1 framing.
    const STREAM_THRESHOLD: usize = 256 * 1024;
    if !no_body && !chunked {
        if let Some(n) = content_length.filter(|n| *n > STREAM_THRESHOLD) {
            let body = PoolBodyReader {
                inner: Some(reader),
                remaining: n as u64,
            };
            let mut response = Response::new(status);
            response.headers = headers
                .into_iter()
                .map(|(n, v)| (std::borrow::Cow::Owned(n), v))
                .collect();
            if !vapache_verified::backend_shared_cache_admit(connection_disposition) {
                response.forbid_shared_cache();
            }
            response.body = Body::Stream {
                reader: Box::new(body),
                len: n as u64,
            };
            if scope
                .header_policy
                .apply(&mut response.headers, response.status < 400)
                .is_err()
            {
                return Ok((Response::policy_error(), None));
            }
            crate::compression::finalize_budgeted(
                scope,
                req,
                &mut response,
                url_path.as_bytes(),
                resource_budget,
            );
            return Ok((response, None));
        }
    }
    let mut body = Vec::new();
    let mut collected_body = None;
    let mut spool_lease = None;
    let mut response_resident = None;
    if !no_body {
        if chunked {
            let mut collector = ProxyBodyCollector::new(
                Arc::clone(resource_budget),
                resource_context.clone(),
                max_spool_bytes,
                max_spool_files,
            )?;
            read_chunked(&mut reader, &mut collector)?;
            let (collected, lease, resident) = collector.finish()?;
            collected_body = Some(collected);
            spool_lease = lease;
            response_resident = resident;
        } else if let Some(n) = content_length {
            let mut resident = resource_budget.try_response_bytes_in(resource_context)?;
            resident.reserve(n as u64)?;
            body.resize(n, 0);
            reader.read_exact(&mut body)?;
            response_resident = Some(resident);
        } else {
            let mut collector = ProxyBodyCollector::new(
                Arc::clone(resource_budget),
                resource_context.clone(),
                max_spool_bytes,
                max_spool_files,
            )?;
            let mut chunk = [0u8; 64 * 1024];
            loop {
                let read = reader.read(&mut chunk)?;
                if read == 0 {
                    break;
                }
                collector.push(&chunk[..read])?;
            }
            let (collected, lease, resident) = collector.finish()?;
            collected_body = Some(collected);
            spool_lease = lease;
            response_resident = resident;
        }
    }
    let mut response = Response::new(status);
    response.headers = headers
        .into_iter()
        .map(|(n, v)| (std::borrow::Cow::Owned(n), v))
        .collect();
    if !vapache_verified::backend_shared_cache_admit(connection_disposition) {
        response.forbid_shared_cache();
    }
    response.body = collected_body.unwrap_or_else(|| {
        if body.is_empty() {
            Body::Empty
        } else {
            Body::Bytes(body)
        }
    });
    if let Some(lease) = spool_lease {
        response.hold_spool(lease);
    }
    if let Some(lease) = response_resident {
        response.hold_resident(lease);
    }
    if scope
        .header_policy
        .apply(&mut response.headers, response.status < 400)
        .is_err()
    {
        return Ok((Response::policy_error(), None));
    }
    crate::compression::finalize_budgeted(
        scope,
        req,
        &mut response,
        url_path.as_bytes(),
        resource_budget,
    );
    Ok((response, None))
}

/// Drive the complete upstream response parser without opening a socket.
/// Writes made by `proxy_once` are discarded while reads come from the fuzz
/// input, so framing, header filtering, chunk decoding and streaming-body
/// setup all use the production path.
#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_proxy_response(data: &[u8]) {
    struct FuzzIo {
        input: std::io::Cursor<Vec<u8>>,
    }

    impl Read for FuzzIo {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.input, output)
        }
    }

    impl Write for FuzzIo {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            Ok(input.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let target = Target {
        backend: HttpBackend {
            host: "127.0.0.1".into(),
            port: 80,
            base: "/".into(),
            tls: false,
        },
        path: "/".into(),
        suffix: String::new(),
        reverse: Vec::new(),
        balancer: None,
        fail_on_status: Vec::new(),
        proxy_url: "http://127.0.0.1/".into(),
        logical_url: None,
        route_order: 0,
    };
    let request = Request {
        method: "GET".into(),
        target: b"/".to_vec(),
        raw_path: b"/".to_vec(),
        query: Vec::new(),
        version: crate::http::Version::Http11,
        headers: crate::http::Headers::default(),
        body: Vec::new(),
        body_spool: None,
        keep_alive: true,
        expect_continue: false,
        framing: crate::verified::BodyFraming::None,
    };
    let io = FuzzIo {
        input: std::io::Cursor::new(data.to_vec()),
    };
    if let Ok((response, _)) = proxy_once(
        Box::new(io),
        &target,
        &request,
        &Scope::default(),
        "/",
        "127.0.0.1:1".parse().expect("static socket address"),
        false,
        "localhost",
    ) {
        let _ = crate::http::response_cache_control(&response);
    }
}

/// Exercise all three untrusted WebSocket negotiation grammars: client
/// subprotocol offers, extension offers/selections, and the backend's raw 101
/// response. The fixed offer deliberately contains multiple alternatives so
/// the fuzzer can reach admitted as well as rejected selection paths.
#[cfg(feature = "fuzzing")]
pub fn fuzz_websocket_negotiation(data: &[u8]) {
    let _ = parse_websocket_protocol_values([data]);
    let _ = parse_websocket_extension_values([data]);
    let offer = WebSocketOffer {
        protocols: vec![b"chat".to_vec(), b"superchat".to_vec()],
        extensions: parse_websocket_extension_values([
            b"permessage-deflate; client_max_window_bits, x-test; mode=safe".as_slice(),
        ])
        .expect("static WebSocket offer is valid"),
    };
    let _ = canonical_websocket_switching_head(data, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &offer);
    let mut structured = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n".to_vec();
    if !data.is_empty() {
        structured.extend_from_slice(data);
        structured.extend_from_slice(b"\r\n");
    }
    structured.extend_from_slice(b"\r\n");
    let _ = canonical_websocket_switching_head(&structured, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &offer);
}

fn alternate_target(
    cfg: &Config,
    target: &Target,
    tried: &HashSet<String>,
    req: &Request,
) -> Option<Target> {
    let name = target.balancer.as_ref()?;
    let balancer = cfg.balancers.iter().find(|b| b.name == *name)?;
    let backend = next_balancer_member(cfg.generation, balancer, Some(req), Some(tried), None)?;
    let path = join_path(&backend.base, &target.suffix);
    let proxy_url = canonical_proxy_url(&backend, &path);
    Some(Target {
        path,
        suffix: target.suffix.clone(),
        backend,
        reverse: target.reverse.clone(),
        balancer: Some(name.clone()),
        fail_on_status: balancer.fail_on_status.clone(),
        proxy_url,
        logical_url: target.logical_url.clone(),
        route_order: target.route_order,
    })
}

/// Re-authorize a balancer failover member.  A grant for member A must not be
/// reused for member B when the members have different `<Proxy>` policy.
#[allow(clippy::too_many_arguments)]
fn authorize_failover(
    cfg: &Config,
    vhost: Option<&VHost>,
    proxy_base_scope: &Scope,
    req: &Request,
    url_path: &str,
    target: &Target,
    peer: SocketAddr,
    resource: &crate::access::ResourceKey,
) -> Option<(
    Scope,
    crate::access::AccessGrant,
    crate::access::ResourceKey,
)> {
    // Never merge a new member into the previous member's effective scope.
    // In particular, AuthMerging Or would otherwise let member A's grant
    // weaken member B's deny. Rebuild logical-balancer and concrete-member
    // policy from the route's pristine pre-<Proxy> scope every time.
    let mut next_scope = proxy_base_scope.clone();
    let mut proxy_urls = vec![target.proxy_url.as_str()];
    if let Some(logical) = target.logical_url.as_deref() {
        proxy_urls.push(logical);
    }
    cfg.apply_proxy_access_urls(
        vhost,
        &mut next_scope,
        &proxy_urls,
        req,
        peer.ip(),
        url_path,
    );
    let mut identity = None;
    // F63/I63: a proxied request has no filesystem target of its own; the
    // resource key's fs_path (the URL-mapped source path) is bound when the
    // dispatcher had one, and absent otherwise — unbound filesystem
    // variables then fail closed in the evaluator.
    let mut access = crate::access::check(
        &next_scope,
        req,
        peer.ip(),
        None,
        url_path,
        resource.fs_path.as_deref(),
    );
    if access == crate::access::Access::AuthRequired {
        if let Some(id) = crate::auth::authenticate(
            &next_scope,
            req,
            cfg.capability_enabled(crate::config::Capability::MutableAuthFiles),
        ) {
            identity = Some(id);
            access = crate::access::check(
                &next_scope,
                req,
                peer.ip(),
                identity.as_ref(),
                url_path,
                resource.fs_path.as_deref(),
            );
        }
    }
    if access != crate::access::Access::Allowed {
        return None;
    }
    let mut next_resource = crate::access::ResourceKey::request(
        vhost,
        req,
        url_path,
        resource.fs_path.as_deref(),
        Some(target.proxy_url.as_str()),
    );
    next_resource.identity = identity
        .map(|i| i.user)
        .or_else(|| resource.identity.clone())
        .or_else(|| req.authenticated_identity());
    let grant = crate::access::grant_if_allowed(access, next_resource.clone())?;
    let bound = grant.bind_proxy(
        &next_resource,
        &target.backend.host,
        target.backend.port,
        target.backend.tls,
        &target.path,
    )?;
    let expected = bound.key().clone();
    debug_assert!(
        bound.require_proxy_sink(
            &expected,
            &target.backend.host,
            target.backend.port,
            target.backend.tls,
            &target.path,
        ),
        "failover grant does not cover bound backend"
    );
    Some((next_scope, bound, expected))
}

pub fn execute(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    req: &Request,
    url_path: &str,
    target: &Target,
    peer: SocketAddr,
    local_port: u16,
    https: bool,
    host: &str,
    local_ip: &str,
    grant: &crate::access::AccessGrant,
    resource: &crate::access::ResourceKey,
) -> Response {
    execute_with_proxy_base(
        cfg, vhost, scope, scope, req, url_path, target, peer, local_port, https, host, local_ip,
        grant, resource,
    )
}

/// Execute a proxy route while retaining the policy scope that existed before
/// the selected balancer member's `<Proxy>` containers were merged. Ordinary
/// direct callers may use [`execute`]; the server dispatcher supplies this
/// explicit base so failover cannot inherit policy from the failed member.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_with_proxy_base(
    cfg: &Config,
    vhost: Option<&VHost>,
    proxy_base_scope: &Scope,
    scope: &Scope,
    req: &Request,
    url_path: &str,
    target: &Target,
    peer: SocketAddr,
    local_port: u16,
    https: bool,
    host: &str,
    local_ip: &str,
    grant: &crate::access::AccessGrant,
    resource: &crate::access::ResourceKey,
) -> Response {
    if !proxy_path_identity_safe(url_path, &target.path) {
        return crate::files::error_response(
            cfg,
            vhost,
            scope,
            400,
            req,
            url_path,
            local_port,
            host,
            peer.ip(),
            local_ip,
        );
    }
    #[cfg(test)]
    let fallback_context;
    let resource_context = match req.resource_context() {
        Some(context) => context,
        #[cfg(test)]
        None => {
            fallback_context = cfg.resource_budget.context(peer.ip());
            &fallback_context
        }
        #[cfg(not(test))]
        None => {
            return crate::files::error_response(
                cfg,
                vhost,
                scope,
                503,
                req,
                url_path,
                local_port,
                host,
                peer.ip(),
                local_ip,
            );
        }
    };
    let Ok(lease) = cfg.resource_budget.try_dynamic_descriptors_in(
        resource_context,
        cfg.max_dynamic_requests,
        1,
    ) else {
        return crate::files::error_response(
            cfg,
            vhost,
            scope,
            503,
            req,
            url_path,
            local_port,
            host,
            peer.ip(),
            local_ip,
        );
    };
    let mut dynamic_lease = Some(lease);
    let Some(bound) = grant.bind_proxy(
        resource,
        &target.backend.host,
        target.backend.port,
        target.backend.tls,
        &target.path,
    ) else {
        return error(
            cfg,
            vhost,
            scope,
            req,
            url_path,
            local_port,
            host,
            peer.ip(),
            local_ip,
        );
    };
    let mut active_resource = bound.key().clone();
    if !bound.require_proxy_sink(
        &active_resource,
        &target.backend.host,
        target.backend.port,
        target.backend.tls,
        &target.path,
    ) || resource.proxy_url.as_deref() != Some(target.proxy_url.as_str())
    {
        return error(
            cfg,
            vhost,
            scope,
            req,
            url_path,
            local_port,
            host,
            peer.ip(),
            local_ip,
        );
    }
    let timeout = cfg.timeout.max(Duration::from_secs(5));
    let exchange_deadline = Instant::now() + timeout;
    let mut current = target.clone();
    let mut active_scope = scope.clone();
    let mut active_grant = bound;
    let mut tried: HashSet<String> = HashSet::new();
    loop {
        let remaining = exchange_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return error(
                cfg,
                vhost,
                &active_scope,
                req,
                url_path,
                local_port,
                host,
                peer.ip(),
                local_ip,
            );
        }
        // The grant used by the sink must name the exact member currently
        // selected.  A balancer failover replaces both together.
        let binding = current.binding_key();
        if !active_grant.require_proxy_sink(
            &active_resource,
            &current.backend.host,
            current.backend.port,
            current.backend.tls,
            &current.path,
        ) || active_resource.proxy_url.as_deref() != Some(current.proxy_url.as_str())
            || active_resource.backend_target.as_deref() != Some(binding.as_str())
        {
            return error(
                cfg,
                vhost,
                &active_scope,
                req,
                url_path,
                local_port,
                host,
                peer.ip(),
                local_ip,
            );
        }
        tried.insert(backend_key(&current.backend));
        let (result, request_may_have_started) = match connect(
            &current.backend,
            &active_scope,
            &cfg.backend_identities,
            remaining,
            exchange_deadline,
            req.request_scope(),
        ) {
            Ok(stream) => (
                proxy_once_budgeted(
                    stream,
                    &cfg.resource_budget,
                    cfg.max_spool_bytes,
                    cfg.max_spool_files,
                    &current,
                    req,
                    &active_scope,
                    url_path,
                    peer,
                    https,
                    host,
                )
                .map(|(response, _)| response),
                true,
            ),
            Err(e) => (Err(e), false),
        };
        match result {
            Ok(mut response) => {
                let failed_status =
                    current.balancer.is_some() && current.fail_on_status.contains(&response.status);
                if failed_status {
                    // A complete upstream response proves the request was
                    // transmitted.  `failonstatus` must not turn POST/PATCH
                    // into implicit at-least-twice delivery.
                    if !vapache_verified::proxy_retry_admit(
                        true,
                        proxy_method_is_idempotent(&req.method),
                    ) {
                        if matches!(response.body, Body::Stream { .. }) {
                            response.hold_dynamic(
                                dynamic_lease
                                    .take()
                                    .expect("proxy stream retained its backend lease"),
                            );
                        }
                        return response;
                    }
                    if let Some(name) = &current.balancer {
                        mark_dead(
                            cfg.generation,
                            name,
                            &format!("{}:{}", current.backend.host, current.backend.port),
                        );
                    }
                    let Some(next) = alternate_target(cfg, &current, &tried, req) else {
                        if matches!(response.body, Body::Stream { .. }) {
                            response.hold_dynamic(
                                dynamic_lease
                                    .take()
                                    .expect("proxy stream retained its backend lease"),
                            );
                        }
                        return response;
                    };
                    let (next_scope, next_grant, next_resource) = match authorize_failover(
                        cfg,
                        vhost,
                        proxy_base_scope,
                        req,
                        url_path,
                        &next,
                        peer,
                        resource,
                    ) {
                        Some(v) => v,
                        None => {
                            return crate::files::error_response(
                                cfg,
                                vhost,
                                &active_scope,
                                403,
                                req,
                                url_path,
                                local_port,
                                host,
                                peer.ip(),
                                local_ip,
                            )
                        }
                    };
                    active_scope = next_scope;
                    active_grant = next_grant;
                    active_resource = next_resource;
                    current = next;
                    continue;
                }
                if matches!(response.body, Body::Stream { .. }) {
                    response.hold_dynamic(
                        dynamic_lease
                            .take()
                            .expect("proxy stream retained its backend lease"),
                    );
                }
                return response;
            }
            Err(e) => {
                eprintln!("vapache proxy error: {e}");
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::StorageFull
                        | std::io::ErrorKind::OutOfMemory
                        | std::io::ErrorKind::WouldBlock
                ) {
                    return crate::files::error_response(
                        cfg,
                        vhost,
                        &active_scope,
                        503,
                        req,
                        url_path,
                        local_port,
                        host,
                        peer.ip(),
                        local_ip,
                    );
                }
                if e.kind() == std::io::ErrorKind::FileTooLarge {
                    return crate::files::error_response(
                        cfg,
                        vhost,
                        &active_scope,
                        502,
                        req,
                        url_path,
                        local_port,
                        host,
                        peer.ip(),
                        local_ip,
                    );
                }
                if let Some(name) = &current.balancer {
                    mark_dead(
                        cfg.generation,
                        name,
                        &format!("{}:{}", current.backend.host, current.backend.port),
                    );
                }
                if !vapache_verified::proxy_retry_admit(
                    request_may_have_started,
                    proxy_method_is_idempotent(&req.method),
                ) {
                    return error(
                        cfg,
                        vhost,
                        &active_scope,
                        req,
                        url_path,
                        local_port,
                        host,
                        peer.ip(),
                        local_ip,
                    );
                }
                if let Some(next) = alternate_target(cfg, &current, &tried, req) {
                    let (next_scope, next_grant, next_resource) = match authorize_failover(
                        cfg,
                        vhost,
                        proxy_base_scope,
                        req,
                        url_path,
                        &next,
                        peer,
                        resource,
                    ) {
                        Some(v) => v,
                        None => {
                            return crate::files::error_response(
                                cfg,
                                vhost,
                                &active_scope,
                                403,
                                req,
                                url_path,
                                local_port,
                                host,
                                peer.ip(),
                                local_ip,
                            )
                        }
                    };
                    active_scope = next_scope;
                    active_grant = next_grant;
                    active_resource = next_resource;
                    current = next;
                    continue;
                }
                return error(
                    cfg,
                    vhost,
                    scope,
                    req,
                    url_path,
                    local_port,
                    host,
                    peer.ip(),
                    local_ip,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Headers, Version};
    use std::path::Path;

    #[allow(clippy::too_many_arguments)]
    fn execute(
        cfg: &Config,
        vhost: Option<&VHost>,
        scope: &Scope,
        req: &Request,
        url_path: &str,
        target: &Target,
        peer: SocketAddr,
        local_port: u16,
        https: bool,
        host: &str,
        local_ip: &str,
    ) -> Response {
        let resource = crate::access::ResourceKey::request(
            vhost,
            req,
            url_path,
            None,
            Some(target.proxy_url.as_str()),
        );
        super::execute(
            cfg,
            vhost,
            scope,
            req,
            url_path,
            target,
            peer,
            local_port,
            https,
            host,
            local_ip,
            &crate::access::test_grant(),
            &resource,
        )
    }
    use std::collections::HashMap;
    use std::fs;
    use std::net::TcpListener;

    #[test]
    fn proxy_deadline_stream_observes_request_cancellation() {
        let budget = Arc::new(crate::resource::ResourceBudget::default());
        let scope = crate::resource::RequestScope::new(
            budget.context(std::net::IpAddr::from([127, 0, 0, 1])),
        );
        scope.cancel();
        let mut stream = DeadlineStream {
            inner: Box::new(std::io::Cursor::new(b"reply".to_vec())),
            deadline: Instant::now() + Duration::from_secs(1),
            scope: Some(scope.clone()),
        };
        let mut byte = [0u8; 1];
        assert_eq!(
            stream.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            stream.write(b"x").unwrap_err().kind(),
            std::io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            stream.flush().unwrap_err().kind(),
            std::io::ErrorKind::ConnectionAborted
        );
        let backend = HttpBackend {
            host: "127.0.0.1".into(),
            port: 9,
            base: "/".into(),
            tls: false,
        };
        assert_eq!(
            connect_tcp(
                &backend,
                &test_backend_identities(),
                Duration::from_secs(1),
                Some(&scope),
            )
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            resolve_backend_addrs_cancellable(
                &test_backend_identities(),
                "cancelled.invalid",
                80,
                Duration::from_secs(1),
                Some(&scope),
            )
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::ConnectionAborted
        );
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn injected_proxy_transport_failures_retry_or_propagate() {
        let _fault_guard = crate::fault::test_guard();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut reader = DeadlineStream {
            inner: Box::new(std::io::Cursor::new(b"reply".to_vec())),
            deadline,
            scope: None,
        };
        crate::fault::configure("proxy.read", 0, std::io::ErrorKind::WouldBlock);
        let mut byte = [0u8; 1];
        assert_eq!(reader.read(&mut byte).unwrap(), 1);
        assert_eq!(byte, [b'r']);
        crate::fault::configure("proxy.read", 0, std::io::ErrorKind::ConnectionReset);
        assert_eq!(
            reader.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );

        let mut writer = DeadlineStream {
            inner: Box::new(std::io::Cursor::new(Vec::new())),
            deadline,
            scope: None,
        };
        crate::fault::configure("proxy.write", 0, std::io::ErrorKind::TimedOut);
        assert_eq!(writer.write(b"request").unwrap(), 7);
        crate::fault::configure("proxy.flush", 0, std::io::ErrorKind::WouldBlock);
        writer.flush().unwrap();

        let mut expired = DeadlineStream {
            inner: Box::new(std::io::Cursor::new(Vec::new())),
            deadline: Instant::now() - Duration::from_millis(1),
            scope: None,
        };
        assert_eq!(
            expired.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            expired.write(b"x").unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            expired.flush().unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    fn config(root: &Path) -> Config {
        let path = root.join("httpd.conf");
        fs::write(&path, "Listen 127.0.0.1:0\n").unwrap();
        Config::load(&path, root, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    fn req(path: &str) -> Request {
        Request {
            method: "GET".into(),
            target: path.as_bytes().to_vec(),
            raw_path: path.as_bytes().to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    #[test]
    fn proxies_http_and_rewrites_location() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            s.write_all(
                format!(
                    "HTTP/1.1 302 Found\r\nContent-Type: text/plain\r\nLocation: http://127.0.0.1:{port}/new\r\nContent-Length: 2\r\n\r\nok"
                )
                .as_bytes(),
            )
            .unwrap();
        });

        let dir = std::env::temp_dir().join(format!("vapache-proxy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/api".into(),
                backend: format!("http://127.0.0.1:{port}/"),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        scope
            .proxy_policy
            .proxy_reverses
            .push(crate::config::ProxyReverseRule {
                front: "/api".into(),
                backend: format!("http://127.0.0.1:{port}/"),
            });
        let target = match_target(&cfg, &scope, "/api/hello").unwrap();
        let request = req("/api/hello");
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let resp = execute(
            &cfg,
            None,
            &scope,
            &request,
            "/api/hello",
            &target,
            peer,
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(resp.status, 302);
        assert_eq!(
            resp.headers
                .iter()
                .find(|(n, _)| n == "location")
                .map(|(_, v)| v.as_slice()),
            Some(b"/api/new".as_slice())
        );
        match resp.body {
            Body::Bytes(b) => assert_eq!(b, b"ok"),
            _ => panic!("expected bytes"),
        }
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;
    use crate::http::{Headers, Version};
    use std::io::Cursor;
    use std::path::Path;

    #[allow(clippy::too_many_arguments)]
    fn execute(
        cfg: &Config,
        vhost: Option<&VHost>,
        scope: &Scope,
        req: &Request,
        url_path: &str,
        target: &Target,
        peer: SocketAddr,
        local_port: u16,
        https: bool,
        host: &str,
        local_ip: &str,
    ) -> Response {
        let resource = crate::access::ResourceKey::request(
            vhost,
            req,
            url_path,
            None,
            Some(target.proxy_url.as_str()),
        );
        super::execute(
            cfg,
            vhost,
            scope,
            req,
            url_path,
            target,
            peer,
            local_port,
            https,
            host,
            local_ip,
            &crate::access::test_grant(),
            &resource,
        )
    }
    use std::collections::HashMap;
    use std::fs;
    use std::net::TcpListener;

    fn config(root: &Path) -> Config {
        let path = root.join("httpd.conf");
        fs::write(&path, "Listen 127.0.0.1:0\n").unwrap();
        Config::load(&path, root, &HashMap::new(), &HashMap::new(), false).unwrap()
    }

    fn req(path: &str) -> Request {
        Request {
            method: "GET".into(),
            target: path.as_bytes().to_vec(),
            raw_path: path.as_bytes().to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn target(cfg: &Config, port: u16) -> Target {
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/app".into(),
                backend: format!("http://127.0.0.1:{port}/"),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        match_target(cfg, &scope, "/app/chunked").unwrap()
    }

    #[test]
    fn decodes_chunked_upstream_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).unwrap();
            s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
            )
            .unwrap();
        });
        let dir = std::env::temp_dir().join(format!("vapache-proxy-more-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let scope = {
            let mut s = Scope::default();
            s.proxy_policy
                .proxy_passes
                .push(crate::config::ProxyPassRule {
                    prefix: "/app".into(),
                    backend: format!("http://127.0.0.1:{port}/"),
                    sticky_cookie: None,
                    fail_on_status: Vec::new(),
                    route_order: 0,
                });
            s
        };
        let r = execute(
            &cfg,
            None,
            &scope,
            &req("/app/chunked"),
            "/app/chunked",
            &target(&cfg, port),
            "127.0.0.1:1".parse().unwrap(),
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(r.status, 200);
        match r.body {
            Body::Bytes(b) => assert_eq!(b, b"Wikipedia"),
            _ => panic!("expected bytes"),
        }
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn connection_failure_returns_502() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-fail-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/app".into(),
                backend: "http://127.0.0.1:1/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        let t = match_target(&cfg, &scope, "/app/x").unwrap();
        let r = execute(
            &cfg,
            None,
            &scope,
            &req("/app/x"),
            "/app/x",
            &t,
            "127.0.0.1:1".parse().unwrap(),
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(r.status, 502);
        scope.proxy_policy.proxy_passes[0].prefix = "/app/".into();
        assert!(match_target(&cfg, &scope, "/app/x").is_some());
        assert!(match_target(&cfg, &scope, "/appx").is_none());
        scope.proxy_policy.proxy_passes[0].prefix = "/".into();
        assert!(match_target(&cfg, &scope, "/anything").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn injected_proxy_connect_failure_is_propagated() {
        let _fault_guard = crate::fault::test_guard();
        let backend = HttpBackend {
            host: "127.0.0.1".into(),
            port: 80,
            base: "/".into(),
            tls: false,
        };
        crate::fault::configure("proxy.connect", 0, std::io::ErrorKind::PermissionDenied);
        let error = connect_tcp(
            &backend,
            &test_backend_identities(),
            Duration::from_secs(1),
            None,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn balancer_round_robins_between_members() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-bal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut cfg = config(&dir);
        cfg.balancers = vec![crate::config::Balancer {
            name: "cluster".into(),
            health: crate::config::HealthTemplate::default(),
            sticky_cookie: None,
            sticky_sep: None,
            fail_on_status: Vec::new(),
            members: vec![
                BalancerMember {
                    url: "http://127.0.0.1:9001/".into(),
                    ..BalancerMember::default()
                },
                BalancerMember {
                    url: "http://127.0.0.1:9002/".into(),
                    ..BalancerMember::default()
                },
            ],
        }];
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/bal".into(),
                backend: "balancer://cluster/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        let first = match_target(&cfg, &scope, "/bal/x").unwrap();
        let second = match_target(&cfg, &scope, "/bal/x").unwrap();
        assert_ne!(first.backend.port, second.backend.port);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_does_not_reuse_keepalive_connection() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let accepts_thread = accepts.clone();
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        accepts_thread.fetch_add(1, Ordering::Relaxed);
                        std::thread::spawn(move || {
                            let mut buf = Vec::new();
                            loop {
                                buf.clear();
                                let mut byte = [0u8; 1];
                                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    match stream.read(&mut byte) {
                                        Ok(0) | Err(_) => return,
                                        Ok(_) => buf.push(byte[0]),
                                    }
                                }
                                if stream
                                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        let dir = std::env::temp_dir().join(format!("vapache-proxy-pool-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/pool".into(),
                backend: format!("http://127.0.0.1:{port}/"),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        let request = req("/pool/x");
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        for _ in 0..3 {
            let target = match_target(&cfg, &scope, "/pool/x").unwrap();
            let response = execute(
                &cfg,
                None,
                &scope,
                &request,
                "/pool/x",
                &target,
                peer,
                80,
                false,
                "localhost",
                "127.0.0.1",
            );
            assert_eq!(response.status, 200);
        }
        // Pooling is deliberately disabled: a backend must not be able to
        // leave bytes that are consumed as the next response.
        assert_eq!(accepts.load(Ordering::Relaxed), 3);
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn passive_balancer_failover_skips_dead_member() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let live = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut s, _) = listener.accept().unwrap();
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).unwrap();
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .unwrap();
            }
        });
        let dir =
            std::env::temp_dir().join(format!("vapache-proxy-failover-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut cfg = config(&dir);
        cfg.balancers = vec![crate::config::Balancer {
            name: "failover".into(),
            health: crate::config::HealthTemplate::default(),
            sticky_cookie: None,
            sticky_sep: None,
            fail_on_status: Vec::new(),
            members: vec![
                BalancerMember {
                    url: "http://127.0.0.1:1/".into(),
                    ..BalancerMember::default()
                },
                BalancerMember {
                    url: format!("http://127.0.0.1:{live}/"),
                    ..BalancerMember::default()
                },
            ],
        }];
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/fo".into(),
                backend: "balancer://failover/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        let req = req("/fo/x");
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let first = match_target(&cfg, &scope, "/fo/x").unwrap();
        let r1 = execute(
            &cfg,
            None,
            &scope,
            &req,
            "/fo/x",
            &first,
            peer,
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(r1.status, 200);
        let second = match_target(&cfg, &scope, "/fo/x").unwrap();
        let r2 = execute(
            &cfg,
            None,
            &scope,
            &req,
            "/fo/x",
            &second,
            peer,
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(r2.status, 200);
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn large_fixed_length_proxy_body_is_streamed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = vec![b'z'; 300 * 1024];
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).unwrap();
            let _ = s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = s.write_all(&body);
        });
        let dir = std::env::temp_dir().join(format!("vapache-proxy-stream-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/stream".into(),
                backend: format!("http://127.0.0.1:{port}/"),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        scope
            .header_policy
            .set_headers
            .push(("X-Stream-Policy".into(), "applied".into()));
        let request = req("/stream/x");
        let target = match_target(&cfg, &scope, "/stream/x").unwrap();
        let mut response = execute(
            &cfg,
            None,
            &scope,
            &request,
            "/stream/x",
            &target,
            "127.0.0.1:1".parse().unwrap(),
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(response.status, 200);
        assert!(response.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("x-stream-policy") && value == b"applied"
        }));
        match &mut response.body {
            Body::Stream { reader, len } => {
                assert_eq!(*len, 300 * 1024);
                let mut all = Vec::new();
                reader.read_to_end(&mut all).unwrap();
                assert_eq!(all.len(), 300 * 1024);
            }
            _ => panic!("expected streamed body"),
        }
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failonstatus_retries_another_member() {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let b = TcpListener::bind("127.0.0.1:0").unwrap();
        let p1 = a.local_addr().unwrap().port();
        let p2 = b.local_addr().unwrap().port();
        let h1 = std::thread::spawn(move || {
            let (mut s, _) = a.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).unwrap();
            let _ = s
                .write_all(b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        });
        let h2 = std::thread::spawn(move || {
            let (mut s, _) = b.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).unwrap();
            let _ =
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        });
        let dir =
            std::env::temp_dir().join(format!("vapache-proxy-failstatus-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut cfg = config(&dir);
        cfg.balancers = vec![crate::config::Balancer {
            name: "failstatus".into(),
            health: crate::config::HealthTemplate::default(),
            sticky_cookie: None,
            sticky_sep: None,
            fail_on_status: vec![500],
            members: vec![
                BalancerMember {
                    url: format!("http://127.0.0.1:{p1}/"),
                    ..BalancerMember::default()
                },
                BalancerMember {
                    url: format!("http://127.0.0.1:{p2}/"),
                    ..BalancerMember::default()
                },
            ],
        }];
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/fs".into(),
                backend: "balancer://failstatus/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        let request = req("/fs/x");
        let target = match_target(&cfg, &scope, "/fs/x").unwrap();
        let response = execute(
            &cfg,
            None,
            &scope,
            &request,
            "/fs/x",
            &target,
            "127.0.0.1:1".parse().unwrap(),
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(response.status, 200);
        h1.join().unwrap();
        h2.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failover_member_must_pass_its_own_proxy_authorization() {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let live = a.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = a.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).unwrap();
            let _ = s
                .write_all(b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        });
        let dir =
            std::env::temp_dir().join(format!("vapache-proxy-failauth-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            "Listen 127.0.0.1:0\n\
             <Proxy \"http://127.0.0.1:1/*\">\n\
                 Require all denied\n\
             </Proxy>\n",
        )
        .unwrap();
        let mut cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        cfg.balancers = vec![crate::config::Balancer {
            name: "failauth".into(),
            health: crate::config::HealthTemplate::default(),
            sticky_cookie: None,
            sticky_sep: None,
            fail_on_status: vec![500],
            members: vec![
                BalancerMember {
                    url: format!("http://127.0.0.1:{live}/"),
                    ..BalancerMember::default()
                },
                BalancerMember {
                    url: "http://127.0.0.1:1/".into(),
                    ..BalancerMember::default()
                },
            ],
        }];
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/fa".into(),
                backend: "balancer://failauth/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        let request = req("/fa/x");
        let target = match_target(&cfg, &scope, "/fa/x").unwrap();
        let response = execute(
            &cfg,
            None,
            &scope,
            &request,
            "/fa/x",
            &target,
            "127.0.0.1:1".parse().unwrap(),
            80,
            false,
            "localhost",
            "127.0.0.1",
        );
        assert_eq!(response.status, 403);
        h.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sticky_session_selects_route_member() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-sticky-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut cfg = config(&dir);
        cfg.balancers = vec![crate::config::Balancer {
            name: "sticky".into(),
            health: crate::config::HealthTemplate::default(),
            sticky_cookie: Some("JSESSIONID".into()),
            sticky_sep: None,
            fail_on_status: Vec::new(),
            members: vec![
                BalancerMember {
                    url: "http://127.0.0.1:9001/".into(),
                    route: Some("node1".into()),
                    ..BalancerMember::default()
                },
                BalancerMember {
                    url: "http://127.0.0.1:9002/".into(),
                    route: Some("node2".into()),
                    ..BalancerMember::default()
                },
            ],
        }];
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/sticky".into(),
                backend: "balancer://sticky/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        let mut request = req("/sticky/x");
        request.headers.insert("cookie", "JSESSIONID=abc.node2");
        let target = match_target_req(&cfg, &scope, "/sticky/x", Some(&request)).unwrap();
        assert_eq!(target.backend.port, 9002);
        // ProxyPass can supply the sticky cookie directly.
        cfg.balancers[0].sticky_cookie = None;
        scope.proxy_policy.proxy_passes[0].sticky_cookie = Some("JSESSIONID|jsessionid".into());
        let target = match_target_req(&cfg, &scope, "/sticky/x", Some(&request)).unwrap();
        assert_eq!(target.backend.port, 9002);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_rejects_ambiguous_backend_framing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            );
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let target = Target {
            backend: HttpBackend {
                host: "127.0.0.1".into(),
                port,
                base: "/".into(),
                tls: false,
            },
            path: "/".into(),
            suffix: String::new(),
            reverse: Vec::new(),
            balancer: None,
            fail_on_status: Vec::new(),
            proxy_url: "http://127.0.0.1/".into(),
            logical_url: None,
            route_order: 0,
        };
        let request = req("/");
        let result = proxy_once(
            Box::new(stream),
            &target,
            &request,
            &Scope::default(),
            "/",
            "127.0.0.1:1".parse().unwrap(),
            false,
            "localhost",
        );
        assert!(result.is_err());
        handle.join().unwrap();
    }

    #[test]
    fn proxy_path_is_encoded_exactly_once() {
        assert_eq!(encode_proxy_path("/a%2Fb?x#y"), "/a%252Fb%3Fx%23y");
        assert_eq!(encode_proxy_path("/space here"), "/space%20here");
        assert!(proxy_path_identity_safe("/ordinary/path", "/backend/path"));
        assert!(!proxy_path_identity_safe(
            "/admin;role=user",
            "/backend/path"
        ));
        assert!(!proxy_path_identity_safe(
            "/public/path",
            "/public/..;x/admin"
        ));
    }

    #[test]
    fn canonical_proxy_url_tracks_backend_and_ipv6() {
        let backend = parse_http_url("http://[::1]:8080/base/").unwrap();
        assert_eq!(backend.host, "[::1]");
        assert_eq!(backend.port, 8080);
        assert_eq!(
            canonical_proxy_url(&backend, "/base/x"),
            "http://[::1]:8080/base/x"
        );
        let default_port = parse_http_url("https://example.test/").unwrap();
        assert_eq!(
            canonical_proxy_url(&default_port, "/x"),
            "https://example.test/x"
        );
    }

    #[test]
    fn proxy_pass_auth_url_is_the_outbound_target() {
        let dir =
            std::env::temp_dir().join(format!("vapache-proxy-auth-url-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/app".into(),
                backend: "http://127.0.0.1:9000/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        let target = match_target(&cfg, &scope, "/app/x").unwrap();
        assert_eq!(target.proxy_url, "http://127.0.0.1:9000/x");
        let expected: String = vapache_verified::proxy_target_key(b"127.0.0.1", 9000, false, b"/x")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(target.binding_key(), expected);
        let other = match_target(&cfg, &scope, "/app/y").unwrap();
        assert_ne!(target.binding_key(), other.binding_key());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn regex_proxy_pass_match_targets() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-regex-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_rules
            .push(crate::config::ProxyRule {
                pattern: std::sync::Arc::new(regex::bytes::Regex::new("^/(.*\\.php)$").unwrap()),
                backend: "http://127.0.0.1:9000/$1".into(),
                route_order: 0,
            });
        let t = match_target(&cfg, &scope, "/index.php").unwrap();
        assert_eq!(t.path, "/index.php");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prefix_and_regex_routes_share_one_configuration_order() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-order-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = config(&dir);
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/app".into(),
                backend: "http://127.0.0.1:9001/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 1,
            });
        scope
            .proxy_policy
            .proxy_rules
            .push(crate::config::ProxyRule {
                pattern: std::sync::Arc::new(regex::bytes::Regex::new("^/app/(.*)$").unwrap()),
                backend: "http://127.0.0.1:9002/$1".into(),
                route_order: 0,
            });
        let regex_first = match_target(&cfg, &scope, "/app/x").unwrap();
        assert_eq!(regex_first.backend.port, 9002);
        assert_eq!(regex_first.path, "/x");
        let metered = req("/app/x");
        assert!(match_target_req(&cfg, &scope, "/app/x", Some(&metered)).is_some());
        assert!(metered.policy_budget().charged_work() > 0);
        let classified = req("/app/x");
        assert!(matches_route_req(&scope, "/app/x", &classified).unwrap());
        assert!(classified.policy_budget().charged_work() > 0);
        let exhausted = req("/app/x");
        exhausted
            .charge_policy_work(crate::resource::MAX_POLICY_WORK_UNITS)
            .unwrap();
        assert!(match_target_req(&cfg, &scope, "/app/x", Some(&exhausted)).is_none());
        assert!(exhausted.policy_budget_failed());

        // Reversing the configuration order reverses the winner even though
        // prefix and regex routes live in separate vectors.
        scope.proxy_policy.proxy_passes[0].route_order = 0;
        scope.proxy_policy.proxy_rules[0].route_order = 1;
        let prefix_first = match_target(&cfg, &scope, "/app/x").unwrap();
        assert_eq!(prefix_first.backend.port, 9001);
        assert_eq!(prefix_first.path, "/x");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn balancer_target_keeps_logical_and_concrete_proxy_identities() {
        let dir =
            std::env::temp_dir().join(format!("vapache-proxy-balance-id-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            "Listen 127.0.0.1:0\n\
             <Proxy \"http://127.0.0.1:9001/*\">\n\
                 Require all denied\n\
             </Proxy>\n",
        )
        .unwrap();
        let mut cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        cfg.balancers = vec![crate::config::Balancer {
            name: "cluster".into(),
            health: crate::config::HealthTemplate::default(),
            sticky_cookie: None,
            sticky_sep: None,
            fail_on_status: Vec::new(),
            members: vec![BalancerMember {
                url: "http://127.0.0.1:9001/".into(),
                ..BalancerMember::default()
            }],
        }];
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/bal".into(),
                backend: "balancer://cluster/".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        let target = match_target(&cfg, &scope, "/bal/x").unwrap();
        assert_eq!(target.logical_url.as_deref(), Some("balancer://cluster/x"));
        assert_eq!(target.proxy_url, "http://127.0.0.1:9001/x");
        let logical = target.logical_url.clone().unwrap();
        let req = req("/bal/x");
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut matched = scope.clone();
        cfg.apply_proxy_access_urls(
            None,
            &mut matched,
            &[target.proxy_url.as_str(), logical.as_str()],
            &req,
            peer.ip(),
            "/bal/x",
        );
        assert_eq!(
            crate::access::check(&matched, &req, peer.ip(), None, "/bal/x", None),
            crate::access::Access::Denied,
            "concrete balancer member identity must participate in <Proxy> matching"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_framing_and_trailer_limits_fail_before_allocation() {
        // A chunk size larger than MAX_PROXY_BODY is rejected by checked_add
        // before resizing the output buffer.
        let mut out = Vec::new();
        let mut oversized = Cursor::new(b"FFFFFFFF\r\n".to_vec());
        assert!(read_chunked(&mut oversized, &mut out).is_err());

        // Too many trailer fields are bounded independently of their bytes.
        let mut trailers = b"0\r\n".to_vec();
        for i in 0..(MAX_PROXY_TRAILERS + 1) {
            trailers.extend_from_slice(format!("X-Trailer-{i}: x\r\n").as_bytes());
        }
        trailers.extend_from_slice(b"\r\n");
        let mut trailer_reader = Cursor::new(trailers);
        assert!(read_chunked(&mut trailer_reader, &mut out).is_err());

        // A backend cannot make the line reader allocate an unbounded line.
        let mut long_line = Cursor::new(vec![b'a'; MAX_PROXY_LINE + 1]);
        assert!(read_line(&mut long_line).is_err());

        // Chunk data must be followed by exactly CRLF.
        let mut bad_crlf = Cursor::new(b"1\r\naXX".to_vec());
        assert!(read_chunked(&mut bad_crlf, &mut out).is_err());
    }

    #[test]
    fn proxy_rejects_control_bytes_in_backend_host_and_serialized_head() {
        assert!(parse_http_url("http://evil.example\r\nX-Injected: yes/").is_none());
        assert!(parse_http_url("http://evil.example\n/").is_none());
        assert!(parse_http_url("http://127.0.0.1:9000/").is_some());

        let safe =
            b"GET /path HTTP/1.1\r\nHost: 127.0.0.1:9000\r\nX-Forwarded-Host: example.test\r\n\r\n";
        assert!(validate_proxy_head(safe).is_ok());
        assert!(valid_forwarded_host("example.test:8443"));
        assert!(!valid_forwarded_host("evil\r\nX-Injected: yes"));
        assert!(!valid_forwarded_host("evil\nX-Injected: yes"));
        let bad_value = b"GET /path HTTP/1.1\r\nHost: x\r\nX-Test: evil\rInjected\r\n\r\n";
        assert!(validate_proxy_head(bad_value).is_err());
        let bad_target = b"GET /path\r\nInjected HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(validate_proxy_head(bad_target).is_err());
        assert!(validate_proxy_head(b"GET /path HTTP/1.1\r\n\r\nX-Late: y\r\n\r\n").is_err());
        assert!(validate_proxy_head(b"GET /path HTTP/1.1\r\n\nX-Late: y\r\n\r\n").is_err());
        assert!(validate_proxy_head(b"GET /path HTTP/1.0\r\nHost: x\r\n\r\n").is_err());
        assert!(validate_proxy_head(b"GE T /path HTTP/1.1\r\nHost: x\r\n\r\n").is_err());
        assert!(validate_proxy_head(b"GET /path HTTP/1.1\r\nBad Name: x\r\n\r\n").is_err());
        assert!(validate_proxy_head(b"GET /path HTTP/1.1\r\nX-Test: a\0b\r\n\r\n").is_err());
        // HTAB is legal inside all header values; the verified predicate must
        // preserve it while still rejecting CTLs.
        assert!(validate_proxy_head(b"GET /path HTTP/1.1\r\nX-Test: a\tb\r\n\r\n").is_ok());
        assert!(validate_proxy_head(b"GET /raw?x=\xff HTTP/1.1\r\nX-Test: a\xffb\r\n\r\n").is_ok());
        assert!(vapache_verified::proxy_request_line_admit(
            b"GET",
            b"/path",
            b"HTTP/1.1"
        ));
        assert!(!vapache_verified::proxy_request_line_admit(
            b"GET",
            b"/pa th",
            b"HTTP/1.1"
        ));
        assert!(vapache_verified::proxy_header_admit(b"X-Test", b"a\tb"));
        assert!(!vapache_verified::proxy_header_admit(b"X-Test", b"a\rb"));
    }

    #[test]
    fn validated_proxy_head_is_the_only_path_to_an_upstream_write() {
        fn backend(host: &str) -> HttpBackend {
            HttpBackend {
                host: host.to_string(),
                port: 9000,
                base: "/".to_string(),
                tls: false,
            }
        }

        let safe = b"GET /path HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n".to_vec();
        let validated =
            ValidatedProxyHead::new(safe.clone(), &backend("127.0.0.1"), Some("example.test"))
                .unwrap();
        assert_eq!(validated.as_bytes(), safe.as_slice());
        assert!(ValidatedProxyHead::new(
            b"GET /path HTTP/1.1\r\nHost: [::1]:9000\r\n\r\n".to_vec(),
            &backend("[::1]"),
            None,
        )
        .is_ok());

        // A host value containing CRLF followed by a syntactically valid
        // header is the dangerous shape: the finished head is well-formed, so
        // only the component check can reject it.
        let injected_host = "evil\r\nX-Injected: yes";
        let head = format!("GET /path HTTP/1.1\r\nHost: {injected_host}:9000\r\n\r\n");
        assert!(validate_proxy_head(head.as_bytes()).is_ok());
        assert!(ValidatedProxyHead::new(head.into_bytes(), &backend(injected_host), None).is_err());
        for bad_backend in ["evil host", "evil/path", "evil\r\nX: y", ""] {
            assert!(
                ValidatedProxyHead::new(
                    b"GET /path HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
                    &backend(bad_backend),
                    None,
                )
                .is_err(),
                "{bad_backend:?}"
            );
        }
        for bad_forwarded in ["evil\r\nX-Injected: yes", "evil\nX: y", "evil host", ""] {
            assert!(
                ValidatedProxyHead::new(
                    b"GET /path HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n".to_vec(),
                    &backend("127.0.0.1"),
                    Some(bad_forwarded),
                )
                .is_err(),
                "{bad_forwarded:?}"
            );
        }

        for injected in [
            "GET /path HTTP/1.1\r\nHost: evil\rInjected: yes\r\n\r\n",
            "GET /path HTTP/1.1\r\nHost: evil\nInjected: yes\r\n\r\n",
            "GET /path HTTP/1.1\r\nX-Test: a\0b\r\n\r\n",
            // A second request line smuggled into the target.
            "GET /path\r\nInjected HTTP/1.1\r\nHost: x\r\n\r\n",
            // Obs-fold / whitespace before a header name.
            "GET /path HTTP/1.1\r\nHost: x\r\n X-Folded: yes\r\n\r\n",
        ] {
            assert!(
                ValidatedProxyHead::new(injected.as_bytes().to_vec(), &backend("127.0.0.1"), None)
                    .is_err(),
                "{injected:?}"
            );
        }
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::http::{Headers, Version};
    use std::io::Cursor;
    use std::net::TcpListener;

    struct MockStream {
        input: Cursor<Vec<u8>>,
    }

    impl MockStream {
        fn new(input: impl Into<Vec<u8>>) -> Self {
            Self {
                input: Cursor::new(input.into()),
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            Read::read(&mut self.input, buf)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn req(path: &str) -> Request {
        Request {
            method: "GET".into(),
            target: path.as_bytes().to_vec(),
            raw_path: path.as_bytes().to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn backend() -> HttpBackend {
        HttpBackend {
            host: "127.0.0.1".into(),
            port: 9000,
            base: "/".into(),
            tls: false,
        }
    }

    fn target() -> Target {
        let backend = backend();
        let path = "/x".to_string();
        let proxy_url = canonical_proxy_url(&backend, &path);
        Target {
            backend,
            path,
            suffix: String::new(),
            reverse: Vec::new(),
            balancer: None,
            fail_on_status: Vec::new(),
            proxy_url,
            logical_url: None,
            route_order: 0,
        }
    }

    fn run(
        response: impl Into<Vec<u8>>,
    ) -> std::io::Result<(Response, Option<Box<dyn ReadWrite>>)> {
        proxy_once(
            Box::new(MockStream::new(response)),
            &target(),
            &req("/x"),
            &Scope::default(),
            "/x",
            "127.0.0.1:1".parse().unwrap(),
            false,
            "client.example",
        )
    }

    fn invalid(response: impl Into<Vec<u8>>, what: &str) {
        invalid_kind(response, what, std::io::ErrorKind::InvalidData);
    }

    fn invalid_kind(response: impl Into<Vec<u8>>, what: &str, kind: std::io::ErrorKind) {
        match run(response) {
            Ok(_) => panic!("expected error for {what}"),
            Err(e) => assert_eq!(e.kind(), kind, "{what}: {e}"),
        }
    }

    #[test]
    fn url_and_canonical_helpers() {
        assert_eq!(
            canonical_proxy_url(&backend(), "relative"),
            "http://127.0.0.1:9000/relative"
        );
        assert_eq!(
            canonical_proxy_url(&backend(), ""),
            "http://127.0.0.1:9000/"
        );
        assert_eq!(
            canonical_proxy_url(
                &HttpBackend {
                    host: "example.test".into(),
                    port: 443,
                    base: "/".into(),
                    tls: true,
                },
                "/p"
            ),
            "https://example.test/p"
        );

        assert!(parse_http_url("ws://h").is_some_and(|b| !b.tls));
        assert!(parse_http_url("wss://h").is_some_and(|b| b.tls));
        assert_eq!(parse_http_url("http://h").unwrap().base, "/");
        assert_eq!(parse_http_url("http://h/a/b").unwrap().base, "/a/b");
        assert_eq!(parse_http_url("http://[::1]").unwrap().port, 80);
        assert_eq!(parse_http_url("https://[::1]").unwrap().port, 443);
        assert_eq!(parse_http_url("http://[::1]:8443").unwrap().port, 8443);
        assert!(parse_http_url("http://[::1]x").is_none());
        assert!(parse_http_url("ftp://h").is_none());
        assert!(parse_http_url("http://h:bad").is_none());
        assert!(parse_http_url("http://").is_none());
    }

    #[test]
    fn read_line_and_chunked_edges() {
        let mut empty = Cursor::new(Vec::<u8>::new());
        assert_eq!(
            read_line(&mut empty).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        let mut line = Cursor::new(b"a\r\n".to_vec());
        assert_eq!(read_line(&mut line).unwrap(), b"a");
        let mut raw = Cursor::new(b"a\xffb\r\n".to_vec());
        assert_eq!(read_line(&mut raw).unwrap(), b"a\xffb");
        let mut extra_cr = Cursor::new(b"a\r\r\n".to_vec());
        assert_eq!(read_line(&mut extra_cr).unwrap(), b"a\r");
        let mut bare_lf = Cursor::new(b"a\n".to_vec());
        assert_eq!(
            read_line(&mut bare_lf).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        let mut only_lf = Cursor::new(b"\n".to_vec());
        assert_eq!(
            read_line(&mut only_lf).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );

        let mut out = Vec::new();
        let mut chunked = Cursor::new(b"4\r\nWiki\r\n0\r\n\r\n".to_vec());
        read_chunked(&mut chunked, &mut out).unwrap();
        assert_eq!(out, b"Wiki");

        let mut bad_size = Cursor::new(b"zz\r\n".to_vec());
        assert!(read_chunked(&mut bad_size, &mut Vec::new()).is_err());
        let mut bad_crlf = Cursor::new(b"1\r\naX\r\n".to_vec());
        assert!(read_chunked(&mut bad_crlf, &mut Vec::new()).is_err());
        let mut too_large = Cursor::new(b"ffffffffffff\r\n".to_vec());
        assert!(read_chunked(&mut too_large, &mut Vec::new()).is_err());
        let mut trailer = Cursor::new(b"0\r\nX: y\r\n\r\n".to_vec());
        read_chunked(&mut trailer, &mut Vec::new()).unwrap();
        for wire in [
            b"1;\r\nx\r\n0\r\n\r\n".as_slice(),
            b"1;name=\"unterminated\r\nx\r\n0\r\n\r\n".as_slice(),
            b"0\r\nContent-Length: 1\r\n\r\n".as_slice(),
        ] {
            assert!(read_chunked(&mut Cursor::new(wire.to_vec()), &mut Vec::new()).is_err());
        }

        assert_eq!(parse_proxy_status_line(b"HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_proxy_status_line(b"HTTP/1.0 599"), Some(599));
        for invalid in [
            b"garbage 200 OK".as_slice(),
            b"HTTP/2.0 200 OK".as_slice(),
            b"HTTP/1.1 20 OK".as_slice(),
            b"HTTP/1.1 200\tOK".as_slice(),
            b"HTTP/1.1 200 bad\rreason".as_slice(),
        ] {
            assert_eq!(parse_proxy_status_line(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn rewrite_location_edges() {
        let reverse = vec![ProxyReverseRule {
            front: "/api".into(),
            backend: "http://b:1".into(),
        }];
        let mut exact = b"http://b:1".to_vec();
        rewrite_location(&mut exact, &reverse);
        assert_eq!(exact, b"/api/");
        let mut child = b"http://b:1/x".to_vec();
        rewrite_location(&mut child, &reverse);
        assert_eq!(child, b"/api/x");
        let mut raw_child = b"http://b:1/a\xff".to_vec();
        rewrite_location(&mut raw_child, &reverse);
        assert_eq!(raw_child, b"/api/a\xff");
        let mut other = b"http://other/x".to_vec();
        rewrite_location(&mut other, &reverse);
        assert_eq!(other, b"http://other/x");
    }

    #[test]
    fn websocket_and_header_helpers() {
        assert!(websocket_accept("not-base64").is_none());
        assert!(websocket_accept("c2hvcnQ=").is_none());
        let accept = websocket_accept("dGhlIHNhbXBsZSBub25jZQ==").unwrap();
        let good = format!(
            "HTTP/1.1 101 Anything\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\nX-Raw: abc\r\n\r\n"
        );
        let offer = WebSocketOffer::default();
        let canonical =
            canonical_websocket_switching_head(good.as_bytes(), &accept, &offer).unwrap();
        assert!(canonical.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(canonical
            .windows(b"X-Raw: abc\r\n".len())
            .any(|window| window == b"X-Raw: abc\r\n"));
        for bad in [
            format!("HTTP/1.0 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"),
            format!("HTTP/1.1 101 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nContent-Length: 0\r\n\r\n"),
            format!("HTTP/1.1 101 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nProxy-Authenticate: Basic\r\n\r\n"),
            format!("HTTP/1.1 101 OK\r\nUpgrade: websocket\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"),
            format!("HTTP/1.1 101 OK\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"),
            format!("HTTP/1.1 101 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"),
        ] {
            assert!(
                canonical_websocket_switching_head(bad.as_bytes(), &accept, &offer).is_err()
            );
        }

        assert_eq!(encode_proxy_path("/a b%\u{7f}?#"), "/a%20b%25%7F%3F%23");
        assert!(hop_by_hop("Proxy-Authorization"));
        assert!(!hop_by_hop("x-test"));
        assert!(forwarded_header("Forwarded"));
        assert!(!forwarded_header("x-test"));
        assert_eq!(
            connection_tokens(b"keep-alive, X-Hop, bad token"),
            vec!["keep-alive", "x-hop"]
        );
        assert_eq!(
            connection_tokens(b"keep-alive, \xff, X-Hop"),
            vec!["keep-alive", "x-hop"]
        );
        assert!(valid_backend_host("[::1]:80"));
        assert!(!valid_backend_host("bad host"));
        assert!(valid_forwarded_host("example.test"));
        assert!(!valid_forwarded_host("bad host"));
        assert!(!valid_forwarded_host(""));
        assert!(client_config(&Scope::default()).is_ok());
    }

    #[test]
    fn websocket_negotiation_is_typed_bounded_and_offer_bound() {
        let mut request = req("/ws");
        request
            .headers
            .push("Sec-WebSocket-Protocol", "chat, superchat");
        request.headers.push(
            "Sec-WebSocket-Extensions",
            "permessage-deflate; client_max_window_bits, x-test; mode=\"safe\"",
        );
        let offer = websocket_offer(&request).unwrap();
        assert!(websocket_negotiation_offer_valid(&request));
        let mut malformed_request = request.clone();
        malformed_request
            .headers
            .insert("Sec-WebSocket-Protocol", b"chat, chat".to_vec());
        assert!(!websocket_negotiation_offer_valid(&malformed_request));
        assert_eq!(offer.protocols, [b"chat".to_vec(), b"superchat".to_vec()]);
        assert_eq!(offer.extensions.len(), 2);

        let accept = websocket_accept("dGhlIHNhbXBsZSBub25jZQ==").unwrap();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: chat\r\nSec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=12\r\n\r\n"
        );
        let canonical =
            canonical_websocket_switching_head(response.as_bytes(), &accept, &offer).unwrap();
        assert!(canonical
            .windows(b"Sec-WebSocket-Protocol: chat\r\n".len())
            .any(|window| window == b"Sec-WebSocket-Protocol: chat\r\n"));
        assert!(canonical
            .windows(
                b"Sec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=12\r\n"
                    .len()
            )
            .any(|window| window
                == b"Sec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=12\r\n"));

        for invalid in ["chat, chat", "chat,", "chat bad", ",chat"] {
            assert!(parse_websocket_protocol_values([invalid.as_bytes()]).is_err());
        }
        for invalid in [
            "permessage-deflate; mode=",
            "permessage-deflate; mode=a; MODE=b",
            "permessage-deflate,",
            ",permessage-deflate",
            "permessage-deflate; mode=\"unterminated",
            "permessage-deflate; mode=\"safe mode\"",
            "permessage-deflate; mode=\"bad\rvalue\"",
        ] {
            assert!(parse_websocket_extension_values([invalid.as_bytes()]).is_err());
        }
        let too_many_protocols = (0..=MAX_WEBSOCKET_NEGOTIATION_ITEMS)
            .map(|index| format!("p{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_websocket_protocol_values([too_many_protocols.as_bytes()]).is_err());
        let too_many_extensions = (0..=MAX_WEBSOCKET_NEGOTIATION_ITEMS)
            .map(|index| format!("x{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_websocket_extension_values([too_many_extensions.as_bytes()]).is_err());
        let too_many_parameters = (0..=MAX_WEBSOCKET_EXTENSION_PARAMS)
            .map(|index| format!("; p{index}=v"))
            .collect::<String>();
        assert!(
            parse_websocket_extension_values([format!("x{too_many_parameters}").as_bytes()])
                .is_err()
        );

        for selected in [
            "Sec-WebSocket-Protocol: unoffered\r\n",
            "Sec-WebSocket-Protocol: chat, superchat\r\n",
            "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: chat\r\n",
            "Sec-WebSocket-Extensions: unknown\r\n",
            "Sec-WebSocket-Extensions: permessage-deflate, PERMESSAGE-DEFLATE\r\n",
            "Sec-WebSocket-Extensions: permessage-deflate; a=1; A=2\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n",
        ] {
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{selected}\r\n"
            );
            assert!(
                canonical_websocket_switching_head(response.as_bytes(), &accept, &offer).is_err()
            );
        }

        let mut excessive = String::from(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
        );
        for _ in 0..MAX_PROXY_HEADERS {
            excessive.push_str("X-Fill: x\r\n");
        }
        excessive.push_str(&format!("Sec-WebSocket-Accept: {accept}\r\n\r\n"));
        assert!(canonical_websocket_switching_head(excessive.as_bytes(), &accept, &offer).is_err());
    }

    #[test]
    fn websocket_detection() {
        let mut r = req("/ws");
        assert!(!is_websocket(&r));
        r.method = "POST".into();
        assert!(!is_websocket(&r));
        r.method = "GET".into();
        r.headers.push("Upgrade", "websocket");
        r.headers.push("Connection", "keep-alive, Upgrade");
        r.headers.push("Sec-WebSocket-Version", "13");
        r.headers
            .push("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        assert!(is_websocket(&r));
        r.version = Version::Http10;
        assert!(!is_websocket(&r));
        r.version = Version::Http11;
        r.headers
            .insert("connection", b"keep-alive, \xff, Upgrade".to_vec());
        assert!(is_websocket(&r));
        r.framing = crate::verified::BodyFraming::Length(1);
        assert!(!is_websocket(&r));
        r.framing = crate::verified::BodyFraming::None;
        r.expect_continue = true;
        assert!(!is_websocket(&r));
    }

    #[test]
    fn sticky_and_balancer_member_edges() {
        let mut balancer = Balancer {
            name: "b".into(),
            members: Vec::new(),
            health: HealthTemplate::default(),
            sticky_cookie: Some("route".into()),
            sticky_sep: Some(".".into()),
            fail_on_status: Vec::new(),
        };
        let mut r = req("/");
        r.headers.push("Cookie", "x=1; route=node.7");
        assert_eq!(
            sticky_route(&balancer, Some(&r), None).as_deref(),
            Some("7")
        );
        balancer.sticky_sep = Some(String::new());
        assert_eq!(
            sticky_route(&balancer, Some(&r), None).as_deref(),
            Some("node.7")
        );
        balancer.sticky_sep = Some(".".into());
        r.headers = Headers::default();
        r.headers.push("Cookie", "x=1; route=node");
        assert_eq!(
            sticky_route(&balancer, Some(&r), None).as_deref(),
            Some("node")
        );
        r.headers = Headers::default();
        r.headers.push("Cookie", "x=1; other=node");
        assert_eq!(sticky_route(&balancer, Some(&r), None), None);
        r.headers = Headers::default();
        r.headers.push("Cookie", "malformed; route=node.1");
        assert_eq!(
            sticky_route(&balancer, Some(&r), None).as_deref(),
            Some("1")
        );
        r.headers = Headers::default();
        r.headers
            .insert("cookie", b"bad=\xff; route=node.2".to_vec());
        assert_eq!(
            sticky_route(&balancer, Some(&r), None).as_deref(),
            Some("2")
        );
        assert_eq!(sticky_route(&balancer, None, None), None);

        assert!(next_balancer_member(0, &balancer, None, None, None).is_none());
        balancer.members.push(BalancerMember {
            url: "http://127.0.0.1:9001".into(),
            route: Some("1".into()),
            ..BalancerMember::default()
        });
        assert!(next_balancer_member(0, &balancer, Some(&r), None, None).is_some());
        // A sticky route that names no member must fall through to the
        // available-member selection rather than failing the request.
        r.headers = Headers::default();
        r.headers.push("Cookie", "route=node.2");
        assert!(next_balancer_member(0, &balancer, Some(&r), None, None).is_some());
        let mut tried = HashSet::new();
        tried.insert(backend_key(
            &parse_http_url("http://127.0.0.1:9001").unwrap(),
        ));
        assert!(next_balancer_member(0, &balancer, None, Some(&tried), None).is_none());
    }

    #[test]
    fn balancer_unavailable_and_regex_targets() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-cov-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("httpd.conf");
        std::fs::write(
            &config_path,
            "Listen 127.0.0.1:0\n<Proxy balancer://empty>\n</Proxy>\n",
        )
        .unwrap();
        let cfg =
            Config::load(&config_path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/b".into(),
                backend: "balancer://empty".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        assert!(balancer_unavailable(&cfg, &scope, "/b/x"));
        assert!(!balancer_unavailable(&cfg, &scope, "/other"));

        let mut plain = Scope::default();
        plain
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/p".into(),
                backend: "http://127.0.0.1:9000/base".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        assert!(!balancer_unavailable(&cfg, &plain, "/p/x"));

        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_rules
            .push(crate::config::ProxyRule {
                pattern: Arc::new(crate::config::compile_regex("^/r").unwrap()),
                backend: "balancer://empty".into(),
                route_order: 0,
            });
        assert!(balancer_unavailable(&cfg, &scope, "/r/x"));

        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_rules
            .push(crate::config::ProxyRule {
                pattern: Arc::new(crate::config::compile_regex("^/r/(.*)$").unwrap()),
                backend: "http://127.0.0.1:9000/base".into(),
                route_order: 0,
            });
        assert!(!balancer_unavailable(&cfg, &scope, "/r/x"));
        let t = match_target(&cfg, &scope, "/r/z").unwrap();
        assert_eq!(t.suffix, "z");
        assert_eq!(t.path, "/base/z");

        scope.proxy_policy.proxy_rules[0].backend = "http://127.0.0.1:9000/$1".into();
        let t = match_target(&cfg, &scope, "/r/z").unwrap();
        assert!(t.suffix.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn health_check_invalid_and_eof() {
        let spec = HealthSpec {
            backend_identities: Arc::new(test_backend_identities()),
            key: "k".into(),
            url: "ftp://invalid".into(),
            method: "GET".into(),
            uri: "/".into(),
            interval: Duration::from_secs(1),
            passes: 1,
            fails: 1,
            ca_file: None,
            ca_trust: crate::files::AdminFileTrust::ProcessOwned,
        };
        assert!(!check_health(&spec));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            drop(stream);
        });
        let spec = HealthSpec {
            url: format!("http://127.0.0.1:{port}/health"),
            ..spec
        };
        assert!(!check_health(&spec));
        handle.join().unwrap();
    }

    #[test]
    fn https_health_check_rejects_a_trusted_certificate_for_the_wrong_name() {
        let dir =
            std::env::temp_dir().join(format!("vapache-proxy-health-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                cert.to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("openssl");
        assert!(status.success());

        let chain = CertificateDer::pem_file_iter(&cert)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key_der = rustls::pki_types::PrivateKeyDer::from_pem_file(&key).unwrap();
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key_der)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let connection = rustls::ServerConnection::new(server_config).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, tcp);
            let mut request = [0u8; 256];
            let _ = stream.read(&mut request);
        });
        let spec = HealthSpec {
            backend_identities: Arc::new(test_backend_identities()),
            key: "tls-name".into(),
            url: format!("https://127.0.0.1:{port}/health"),
            method: "GET".into(),
            uri: "/health".into(),
            interval: Duration::from_secs(1),
            passes: 1,
            fails: 1,
            ca_file: Some(cert),
            ca_trust: crate::files::AdminFileTrust::ProcessOwned,
        };
        assert!(!check_health(&spec));
        handle.join().unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn proxy_response_error_paths() {
        invalid("HTTP/1.1\r\n\r\n", "missing status");
        invalid("garbage 200 OK\r\n\r\n", "invalid version");
        invalid("HTTP/1.1 200\tOK\r\n\r\n", "invalid status delimiter");
        invalid(
            "HTTP/1.1 200 OK\r\nContent-Length : 0\r\n\r\n",
            "whitespace before response header colon",
        );
        invalid("HTTP/1.1 99 Nope\r\n\r\n", "status range");
        invalid("HTTP/1.1 100 Continue\r\n\r\n", "interim");
        invalid("HTTP/1.1 200 OK\r\nNoColon\r\n\r\n", "malformed header");
        invalid("HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n", "bad header name");
        invalid(
            "HTTP/1.1 200 OK\r\nX-Test: bad\x01value\r\n\r\n",
            "bad header value",
        );
        invalid(
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            "duplicate length",
        );
        invalid(
            "HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n",
            "bad length",
        );
        invalid(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            "duplicate encoding",
        );
        invalid(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            "unsupported encoding",
        );
        invalid(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
            "multiple encodings",
        );
        invalid(
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "both framings",
        );
        invalid(
            "HTTP/1.1 200 OK\r\nLocation: /x\u{1}\r\n\r\n",
            "bad location",
        );
        invalid("HTTP/1.1 200 OK\r\nX-Test: a\u{1}b\r\n\r\n", "bad value");
        invalid_kind(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n",
            "chunk too large",
            std::io::ErrorKind::FileTooLarge,
        );
        invalid_kind(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                MAX_PROXY_BODY + 1
            ),
            "fixed body too large",
            std::io::ErrorKind::FileTooLarge,
        );

        let mut many = String::from("HTTP/1.1 200 OK\r\n");
        for i in 0..201 {
            many.push_str(&format!("X-{i}: y\r\n"));
        }
        many.push_str("\r\n");
        invalid(many, "too many headers");

        let mut huge = String::from("HTTP/1.1 200 OK\r\n");
        for _ in 0..5 {
            huge.push_str(&format!("X-Long: {}\r\n", "a".repeat(15_000)));
        }
        huge.push_str("\r\n");
        invalid(huge, "headers too large");
    }

    #[test]
    fn proxy_framing_kernel_validates_no_body_responses_too() {
        use vapache_verified::ProxyResponseFraming;

        let length = vec![(b"content-length".to_vec(), b"12".to_vec())];
        assert_eq!(
            vapache_verified::proxy_response_framing(false, 200, &length),
            Some(ProxyResponseFraming::Length(12))
        );
        assert_eq!(
            vapache_verified::proxy_response_framing(true, 200, &length),
            Some(ProxyResponseFraming::NoBody)
        );
        let ambiguous = vec![
            (b"content-length".to_vec(), b"12".to_vec()),
            (b"transfer-encoding".to_vec(), b"chunked".to_vec()),
        ];
        assert_eq!(
            vapache_verified::proxy_response_framing(true, 200, &ambiguous),
            None
        );
        let malformed = vec![(b"content-length".to_vec(), b"12, 12".to_vec())];
        assert_eq!(
            vapache_verified::proxy_response_framing(false, 204, &malformed),
            None
        );
        assert_eq!(
            vapache_verified::proxy_response_framing(false, 204, &length),
            None
        );
        assert_eq!(
            vapache_verified::proxy_response_framing(false, 205, &[]),
            Some(ProxyResponseFraming::NoBody)
        );
        let zero = vec![(b"content-length".to_vec(), b"0".to_vec())];
        assert_eq!(
            vapache_verified::proxy_response_framing(false, 205, &zero),
            Some(ProxyResponseFraming::NoBody)
        );
        assert_eq!(
            vapache_verified::proxy_response_framing(false, 205, &length),
            None
        );
        let chunked = vec![(b"transfer-encoding".to_vec(), b"chunked".to_vec())];
        assert_eq!(
            vapache_verified::proxy_response_framing(false, 205, &chunked),
            None
        );
    }

    #[test]
    fn proxy_response_success_and_streaming() {
        let (resp, returned) =
            run("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        assert_eq!(resp.status, 200);
        assert!(returned.is_none());
        match resp.body {
            Body::Bytes(body) => assert_eq!(body, b"ok"),
            _ => panic!("expected bytes"),
        }

        let (resp, _) = run(
            "HTTP/1.1 200 OK\r\nX-Hop: secret\r\nConnection: X-Hop\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
        assert!(!resp
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("x-hop")));
        assert!(
            run("HTTP/1.1 200 OK\r\nConnection: X-Hop,,close\r\nContent-Length: 0\r\n\r\n")
                .is_err()
        );
        assert!(
            run("HTTP/1.1 200 OK\r\nConnection: X-Hop, x-hop\r\nContent-Length: 0\r\n\r\n")
                .is_err()
        );
        assert!(
            run("HTTP/1.1 200 OK\r\nConnection: Content-Length\r\nContent-Length: 0\r\n\r\n")
                .is_err()
        );
        let (nominated, _) = run(
            "HTTP/1.1 200 OK\r\nConnection: X-Private\r\nX-Private: selected\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
        assert!(!nominated.shared_cache_eligible());
        assert!(!nominated
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("x-private")));
        let (ordinary_connection, _) =
            run("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert!(ordinary_connection.shared_cache_eligible());

        let (resp, _) = run("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").unwrap();
        assert_eq!(resp.status, 204);
        assert!(matches!(resp.body, Body::Empty));

        let (resp, _) = run("HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert_eq!(resp.status, 205);
        assert!(matches!(resp.body, Body::Empty));
        assert!(run("HTTP/1.1 205 Reset Content\r\nContent-Length: 1\r\n\r\nx").is_err());

        let (resp, _) = run("HTTP/1.1 200 OK\r\nContent-Length: 300000\r\n\r\n").unwrap();
        match resp.body {
            Body::Stream { len, .. } => assert_eq!(len, 300_000),
            _ => panic!("expected stream"),
        }

        let (resp, _) =
            run("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n")
                .unwrap();
        match resp.body {
            Body::Bytes(body) => assert_eq!(body, b"Wiki"),
            _ => panic!("expected bytes"),
        }

        let payload = vec![b'x'; MAX_PROXY_BODY_IN_MEMORY + 1];
        let mut wire = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            payload.len()
        )
        .into_bytes();
        wire.extend_from_slice(&payload);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        let (resp, _) = run(wire).unwrap();
        match resp.body {
            Body::File { mut file, len, .. } => {
                assert_eq!(len, payload.len() as u64);
                let mut got = Vec::new();
                file.read_to_end(&mut got).unwrap();
                assert_eq!(got, payload);
            }
            _ => panic!("expected a spooled chunked body"),
        }

        let mut head = req("/x");
        head.method = "HEAD".into();
        let (resp, _) = proxy_once(
            Box::new(MockStream::new(
                "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
            )),
            &target(),
            &head,
            &Scope::default(),
            "/x",
            "127.0.0.1:1".parse().unwrap(),
            false,
            "",
        )
        .unwrap();
        assert!(matches!(resp.body, Body::Empty));

        let (resp, _) =
            run("HTTP/1.1 200 OK\r\nKeep-Alive: timeout=5\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert!(!resp
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("keep-alive")));
    }

    #[test]
    fn proxy_head_and_body_reader_edges() {
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let err = match proxy_once(
            Box::new(MockStream::new(Vec::new())),
            &target(),
            &req("/x"),
            &Scope::default(),
            "/x",
            peer,
            false,
            "bad host",
        ) {
            Ok(_) => panic!("expected unsafe host rejection"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        let mut bad_target = target();
        bad_target.backend.host = "bad host".into();
        bad_target.proxy_url = canonical_proxy_url(&bad_target.backend, "/x");
        let err = match proxy_once(
            Box::new(MockStream::new(Vec::new())),
            &bad_target,
            &req("/x"),
            &Scope::default(),
            "/x",
            peer,
            false,
            "",
        ) {
            Ok(_) => panic!("expected unsafe backend rejection"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        let mut none = PoolBodyReader {
            inner: None,
            remaining: 3,
        };
        let mut buf = [0u8; 4];
        assert_eq!(none.read(&mut buf).unwrap(), 0);

        let mut eof = PoolBodyReader {
            inner: Some(BufReader::new(
                Box::new(MockStream::new(Vec::new())) as Box<dyn ReadWrite>
            )),
            remaining: 3,
        };
        assert_eq!(eof.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn unavailable_backends_are_skipped_in_matching() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-skip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("httpd.conf");
        std::fs::write(&path, "Listen 127.0.0.1:0\n").unwrap();
        let cfg = Config::load(&path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/u".into(),
                backend: "balancer://missing".into(),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        scope
            .proxy_policy
            .proxy_rules
            .push(crate::config::ProxyRule {
                pattern: Arc::new(crate::config::compile_regex("^/r").unwrap()),
                backend: "balancer://missing".into(),
                route_order: 1,
            });
        assert!(match_target(&cfg, &scope, "/u/x").is_none());
        assert!(match_target(&cfg, &scope, "/r/x").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn execute_rejects_bad_grant_identity() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-grant-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("httpd.conf");
        std::fs::write(&path, "Listen 127.0.0.1:0\n").unwrap();
        let cfg = Config::load(&path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let r = req("/x");
        let t = target();
        let scope = Scope::default();
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let resource =
            crate::access::ResourceKey::request(None, &r, "/x", None, Some(t.proxy_url.as_str()));
        let wrong = crate::access::ResourceKey::request(
            None,
            &r,
            "/other",
            None,
            Some(t.proxy_url.as_str()),
        );
        let grant = crate::access::grant_if_allowed(crate::access::Access::Allowed, wrong).unwrap();
        let resp = super::execute(
            &cfg,
            None,
            &scope,
            &r,
            "/x",
            &t,
            peer,
            80,
            false,
            "host",
            "127.0.0.1",
            &grant,
            &resource,
        );
        assert_eq!(resp.status, 502);

        let mismatched =
            crate::access::ResourceKey::request(None, &r, "/x", None, Some("http://other/x"));
        let grant =
            crate::access::grant_if_allowed(crate::access::Access::Allowed, mismatched.clone())
                .unwrap();
        let resp = super::execute(
            &cfg,
            None,
            &scope,
            &r,
            "/x",
            &t,
            peer,
            80,
            false,
            "host",
            "127.0.0.1",
            &grant,
            &mismatched,
        );
        assert_eq!(resp.status, 502);
    }

    struct FailWriter;
    impl Read for FailWriter {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }
    impl Write for FailWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn health_spec() -> HealthSpec {
        HealthSpec {
            backend_identities: Arc::new(test_backend_identities()),
            key: "k".into(),
            url: "http://127.0.0.1:1/health".into(),
            method: "HEAD".into(),
            uri: "/health".into(),
            interval: Duration::from_secs(1),
            passes: 1,
            fails: 1,
            ca_file: None,
            ca_trust: crate::files::AdminFileTrust::ProcessOwned,
        }
    }

    #[test]
    fn health_stream_branches() {
        let spec = health_spec();
        let good = HttpBackend {
            host: "127.0.0.1".into(),
            port: 1,
            base: "/".into(),
            tls: false,
        };
        assert!(check_health_stream(
            Box::new(MockStream::new("HTTP/1.1 204 No Content\r\n\r\n")),
            &spec,
            &good
        ));
        assert!(!check_health_stream(
            Box::new(MockStream::new(Vec::<u8>::new())),
            &spec,
            &good
        ));
        assert!(!check_health_stream(Box::new(FailWriter), &spec, &good));
        let bad = HttpBackend {
            host: "bad host".into(),
            ..good
        };
        assert!(!check_health_stream(
            Box::new(MockStream::new(Vec::<u8>::new())),
            &spec,
            &bad
        ));
    }

    #[test]
    fn backend_health_and_failure_state_is_generation_scoped() {
        let old_generation = u64::MAX - std::process::id() as u64;
        let new_generation = old_generation - 1;
        let name = "generation-isolation";
        let member = "http://127.0.0.1:65534";
        let mut spec = health_spec();
        spec.key = health_key(old_generation, name, member);
        update_health(&spec, false);
        mark_dead(old_generation, name, "127.0.0.1:65534");

        assert!(!member_is_healthy(old_generation, name, member));
        assert!(is_dead(old_generation, name, member));
        assert!(member_is_healthy(new_generation, name, member));
        assert!(!is_dead(new_generation, name, member));
    }

    #[test]
    fn health_check_start_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-health-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("httpd.conf");
        std::fs::write(
            &path,
            "Listen 127.0.0.1:0\n<Proxy balancer://h>\nBalancerMember http://127.0.0.1:1 hcuri=/health\nProxySet hcinterval=1s\n</Proxy>\n",
        )
        .unwrap();
        let cfg = Config::load(&path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        start_health_checks(&cfg);
        start_health_checks(&cfg);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn async_head_and_connect_edges() {
        use tokio::io::AsyncWriteExt;
        let (mut client, mut server) = tokio::io::duplex(256 * 1024);
        let writer = tokio::spawn(async move {
            let _ = server.write_all(&vec![b'a'; MAX_PROXY_HEAD + 10]).await;
        });
        assert!(read_async_head(&mut client).await.is_err());
        writer.await.unwrap();

        let mut empty = tokio::io::empty();
        assert!(read_async_head(&mut empty).await.is_err());

        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
                .await
                .unwrap();
        });
        let head = read_async_head(&mut client).await.unwrap();
        assert!(head.head.ends_with(b"\r\n\r\n"));
        assert!(head.initial.is_empty());

        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\nfirst-frame")
                .await
                .unwrap();
        });
        let head = read_async_head(&mut client).await.unwrap();
        assert_eq!(head.initial, b"first-frame");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let backend = HttpBackend {
            host: "127.0.0.1".into(),
            port,
            base: "/".into(),
            tls: false,
        };
        let err = match connect_async(
            &backend,
            &Scope::default(),
            &test_backend_identities(),
            Duration::from_millis(100),
        )
        .await
        {
            Ok(_) => panic!("expected connection failure"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn async_tls_handshake_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(250));
        });
        let backend = HttpBackend {
            host: "127.0.0.1".into(),
            port,
            base: "/".into(),
            tls: true,
        };
        let err = match connect_async(
            &backend,
            &Scope::default(),
            &test_backend_identities(),
            Duration::from_millis(50),
        )
        .await
        {
            Ok(_) => panic!("expected TLS timeout"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        handle.join().unwrap();
    }

    fn websocket_target() -> Target {
        target()
    }

    fn resource(req: &Request, proxy_url: &str) -> crate::access::ResourceKey {
        crate::access::ResourceKey::request(None, req, "/ws", None, Some(proxy_url))
    }

    async fn spawn_upstream(
        response: Vec<u8>,
        read_initial: bool,
    ) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            let _ = stream.write_all(&response).await;
            if read_initial {
                let n = stream.read(&mut buf).await.unwrap_or(0);
                request.extend_from_slice(&buf[..n]);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            request
        });
        (port, handle)
    }

    fn ws_request(key: &str) -> Request {
        let mut r = req("/ws?x=1");
        r.query = b"x=1".to_vec();
        r.headers.push("Upgrade", "websocket");
        r.headers.push("Connection", "Upgrade");
        r.headers.push("Sec-WebSocket-Version", "13");
        if !key.is_empty() {
            r.headers.push("Sec-WebSocket-Key", key);
        }
        r
    }

    fn ws_101(accept: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .into_bytes()
    }

    fn ws_context_with_path(
        port: u16,
        r: &Request,
        target_path: &str,
    ) -> (
        Arc<Config>,
        Arc<Scope>,
        Arc<Request>,
        Arc<Target>,
        Arc<crate::access::AccessGrant>,
        Arc<crate::access::ResourceKey>,
    ) {
        let dir =
            std::env::temp_dir().join(format!("vapache-proxy-wsctx-{}-{port}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("httpd.conf");
        std::fs::write(&path, "Listen 127.0.0.1:0\n").unwrap();
        let cfg = Config::load(&path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let backend = HttpBackend {
            host: "127.0.0.1".into(),
            port,
            base: "/".into(),
            tls: false,
        };
        let path = target_path.to_string();
        let proxy_url = canonical_proxy_url(&backend, &path);
        let target = Target {
            backend,
            path,
            suffix: String::new(),
            reverse: Vec::new(),
            balancer: None,
            fail_on_status: Vec::new(),
            proxy_url,
            logical_url: None,
            route_order: 0,
        };
        let resource = crate::access::ResourceKey::request(
            None,
            r,
            "/ws",
            None,
            Some(target.proxy_url.as_str()),
        );
        let grant =
            crate::access::grant_if_allowed(crate::access::Access::Allowed, resource.clone())
                .unwrap();
        (
            Arc::new(cfg),
            Arc::new(Scope::default()),
            Arc::new(r.clone()),
            Arc::new(target),
            Arc::new(grant),
            Arc::new(resource),
        )
    }

    fn ws_context(
        port: u16,
        r: &Request,
    ) -> (
        Arc<Config>,
        Arc<Scope>,
        Arc<Request>,
        Arc<Target>,
        Arc<crate::access::AccessGrant>,
        Arc<crate::access::ResourceKey>,
    ) {
        ws_context_with_path(port, r, "/ws")
    }

    #[tokio::test]
    async fn websocket_async_success_query_and_initial() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = websocket_accept(key).unwrap();
        let mut switching_response = ws_101(&accept);
        switching_response.extend_from_slice(b"first-frame");
        let (port, upstream) = spawn_upstream(switching_response, true).await;
        let mut r = ws_request(key);
        r.query = b"x=\xff".to_vec();
        r.headers.insert("x-raw", b"a\xffb".to_vec());
        let (cfg, scope, r, target, grant, resource) =
            ws_context_with_path(port, &r, "/ws/%2e?x#y z");
        let initial = b"hello".to_vec();
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            websocket_async(
                &cfg,
                &scope,
                &r,
                &target,
                &grant,
                &resource,
                server,
                "127.0.0.1:1".parse().unwrap(),
                false,
                "client.example",
                &initial,
            )
            .await
        });
        let mut response = Vec::new();
        while !response
            .windows(b"first-frame".len())
            .any(|window| window == b"first-frame")
        {
            let mut chunk = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut chunk))
                .await
                .unwrap()
                .unwrap();
            assert_ne!(n, 0);
            response.extend_from_slice(&chunk[..n]);
        }
        assert!(String::from_utf8_lossy(&response).contains("101 Switching Protocols"));
        drop(client);
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
        let request = upstream.await.unwrap();
        assert!(request
            .windows(b"GET /ws/%252e%3Fx%23y%20z?x=\xff HTTP/1.1".len())
            .any(|window| window == b"GET /ws/%252e%3Fx%23y%20z?x=\xff HTTP/1.1"));
        assert!(request
            .windows(b"x-raw: a\xffb\r\n".len())
            .any(|window| window == b"x-raw: a\xffb\r\n"));
        assert!(request.ends_with(b"hello"));
    }

    #[tokio::test]
    async fn websocket_async_binds_backend_negotiation_to_client_offer() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = websocket_accept(key).unwrap();
        let switching_response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: chat\r\nSec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n\r\nfirst-frame"
        )
        .into_bytes();
        let (port, upstream) = spawn_upstream(switching_response, false).await;
        let mut r = ws_request(key);
        r.headers.push("Sec-WebSocket-Protocol", "chat, superchat");
        r.headers.push(
            "Sec-WebSocket-Extensions",
            "permessage-deflate; client_max_window_bits",
        );
        let (cfg, scope, r, target, grant, resource) = ws_context(port, &r);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            websocket_async(
                &cfg,
                &scope,
                &r,
                &target,
                &grant,
                &resource,
                server,
                "127.0.0.1:1".parse().unwrap(),
                false,
                "client.example",
                &[],
            )
            .await
        });
        let mut response = Vec::new();
        while !response.ends_with(b"first-frame") {
            let mut chunk = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut chunk))
                .await
                .unwrap()
                .unwrap();
            assert_ne!(n, 0);
            response.extend_from_slice(&chunk[..n]);
        }
        assert!(response
            .windows(b"Sec-WebSocket-Protocol: chat\r\n".len())
            .any(|window| window == b"Sec-WebSocket-Protocol: chat\r\n"));
        assert!(response
            .windows(
                b"Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n"
                    .len()
            )
            .any(|window| {
                window
                    == b"Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n"
            }));
        drop(client);
        assert!(tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_ok());
        let request = upstream.await.unwrap();
        assert!(request
            .windows(b"sec-websocket-protocol: chat, superchat\r\n".len())
            .any(|window| window == b"sec-websocket-protocol: chat, superchat\r\n"));
    }

    #[tokio::test]
    async fn websocket_async_rejects_unoffered_backend_selection() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = websocket_accept(key).unwrap();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: admin\r\n\r\n"
        )
        .into_bytes();
        let (port, upstream) = spawn_upstream(response, false).await;
        let mut r = ws_request(key);
        r.headers.push("Sec-WebSocket-Protocol", "chat");
        let (cfg, scope, r, target, grant, resource) = ws_context(port, &r);
        let (_client, server) = tokio::io::duplex(1024);
        let error = websocket_async(
            &cfg,
            &scope,
            &r,
            &target,
            &grant,
            &resource,
            server,
            "127.0.0.1:1".parse().unwrap(),
            false,
            "client.example",
            &[],
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let _ = upstream.await;
    }

    #[tokio::test]
    async fn websocket_async_invalid_key_and_handshake() {
        let (port, upstream) = spawn_upstream(ws_101("wrong"), false).await;
        let r = ws_request("");
        let (cfg, scope, r, target, grant, resource) = ws_context(port, &r);
        let (_client, server) = tokio::io::duplex(1024);
        let err = websocket_async(
            &cfg,
            &scope,
            &r,
            &target,
            &grant,
            &resource,
            server,
            "127.0.0.1:1".parse().unwrap(),
            false,
            "client.example",
            &[],
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let _ = upstream.await;

        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let (port, upstream) = spawn_upstream(ws_101("wrong"), false).await;
        let r = ws_request(key);
        let (cfg, scope, r, target, grant, resource) = ws_context(port, &r);
        let (_client, server) = tokio::io::duplex(1024);
        let err = websocket_async(
            &cfg,
            &scope,
            &r,
            &target,
            &grant,
            &resource,
            server,
            "127.0.0.1:1".parse().unwrap(),
            false,
            "client.example",
            &[],
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let _ = upstream.await;
    }

    #[tokio::test]
    async fn websocket_async_non_upgrade_and_unsafe_host() {
        let response = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
        let (port, upstream) = spawn_upstream(response, false).await;
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let r = ws_request(key);
        let (cfg, scope, r, target, grant, resource) = ws_context(port, &r);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            websocket_async(
                &cfg,
                &scope,
                &r,
                &target,
                &grant,
                &resource,
                server,
                "127.0.0.1:1".parse().unwrap(),
                false,
                "",
                &[],
            )
            .await
        });
        let mut response = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("403"));
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
        let _ = upstream.await;

        let (port, upstream) = spawn_upstream(ws_101("x"), false).await;
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let r = ws_request(key);
        let (cfg, scope, r, target, grant, resource) = ws_context(port, &r);
        let (_client, server) = tokio::io::duplex(1024);
        let err = websocket_async(
            &cfg,
            &scope,
            &r,
            &target,
            &grant,
            &resource,
            server,
            "127.0.0.1:1".parse().unwrap(),
            false,
            "bad host",
            &[],
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let _ = upstream.await;
    }

    #[tokio::test]
    async fn websocket_grant_and_forwarded_host_errors() {
        let r = {
            let mut r = req("/ws");
            r.headers.push("Upgrade", "websocket");
            r.headers.push("Connection", "Upgrade");
            r.headers.push("Sec-WebSocket-Version", "13");
            r.headers
                .push("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
            r
        };
        let target = websocket_target();
        let dir = std::env::temp_dir().join(format!("vapache-proxy-ws-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("httpd.conf");
        std::fs::write(&path, "Listen 127.0.0.1:0\n").unwrap();
        let cfg = Config::load(&path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let scope = Scope::default();
        let (client, _server) = tokio::io::duplex(1024);

        let granted = resource(&r, "http://one.example/ws");
        let grant =
            crate::access::grant_if_allowed(crate::access::Access::Allowed, granted.clone())
                .unwrap();
        let mismatched = resource(&r, "http://two.example/ws");
        let err = websocket_async(
            &cfg,
            &scope,
            &r,
            &target,
            &grant,
            &mismatched,
            client,
            "127.0.0.1:1".parse().unwrap(),
            false,
            "client.example",
            &[],
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        let (client, _server) = tokio::io::duplex(1024);
        let matching = resource(&r, "http://two.example/ws");
        let grant =
            crate::access::grant_if_allowed(crate::access::Access::Allowed, matching.clone())
                .unwrap();
        let err = websocket_async(
            &cfg,
            &scope,
            &r,
            &target,
            &grant,
            &matching,
            client,
            "127.0.0.1:1".parse().unwrap(),
            false,
            "client.example",
            &[],
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    struct HugeStream {
        header: Cursor<Vec<u8>>,
        remaining: usize,
    }

    impl Read for HugeStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = Read::read(&mut self.header, buf)?;
            if n > 0 {
                return Ok(n);
            }
            if self.remaining == 0 {
                return Ok(0);
            }
            let n = self.remaining.min(buf.len());
            buf[..n].fill(b'a');
            self.remaining -= n;
            Ok(n)
        }
    }

    impl Write for HugeStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn spooled_body_is_copied_upstream() {
        let mut r = req("/x");
        r.body_spool = Some(Arc::new(crate::http::SpooledBody::from_bytes(b"abc")));
        let (resp, _) = proxy_once(
            Box::new(MockStream::new(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            )),
            &target(),
            &r,
            &Scope::default(),
            "/x",
            "127.0.0.1:1".parse().unwrap(),
            false,
            "",
        )
        .unwrap();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn unbounded_body_over_limit_is_rejected() {
        let huge = HugeStream {
            header: Cursor::new(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
            remaining: MAX_PROXY_BODY + 1,
        };
        let err = match proxy_once(
            Box::new(huge),
            &target(),
            &req("/x"),
            &Scope::default(),
            "/x",
            "127.0.0.1:1".parse().unwrap(),
            false,
            "",
        ) {
            Ok(_) => panic!("expected body limit error"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::FileTooLarge);
    }

    #[test]
    fn unbounded_body_within_limit_is_accepted() {
        let stream = HugeStream {
            header: Cursor::new(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
            remaining: 5,
        };
        let (resp, _) = proxy_once(
            Box::new(stream),
            &target(),
            &req("/x"),
            &Scope::default(),
            "/x",
            "127.0.0.1:1".parse().unwrap(),
            false,
            "",
        )
        .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body_len(), 5);
    }

    #[test]
    fn failover_authentication_is_required() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-auth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = dir.join("htpasswd");
        let mut hasher = Sha1::new();
        hasher.update(b"secret");
        let digest = STANDARD.encode(hasher.finalize());
        std::fs::write(&password, format!("alice:{{SHA}}{digest}\n")).unwrap();
        let port = 9;
        let config_path = dir.join("httpd.conf");
        std::fs::write(
            &config_path,
            format!(
                "VapacheCapability MutableAuthFiles On\nListen 127.0.0.1:0\n<Proxy http://127.0.0.1:{port}>\nRequire valid-user\nAuthType Basic\nAuthName test\nAuthUserFile {}\n</Proxy>\n",
                password.display()
            ),
        )
        .unwrap();
        let cfg =
            Config::load(&config_path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let backend = HttpBackend {
            host: "127.0.0.1".into(),
            port,
            base: "/".into(),
            tls: false,
        };
        let path = "/ws".to_string();
        let proxy_url = canonical_proxy_url(&backend, &path);
        let target = Target {
            backend,
            path,
            suffix: String::new(),
            reverse: Vec::new(),
            balancer: None,
            fail_on_status: Vec::new(),
            proxy_url,
            logical_url: None,
            route_order: 0,
        };
        let scope = Scope::default();
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let r = req("/ws");
        let resource = crate::access::ResourceKey::request(
            None,
            &r,
            "/ws",
            None,
            Some(target.proxy_url.as_str()),
        );
        assert!(
            authorize_failover(&cfg, None, &scope, &r, "/ws", &target, peer, &resource).is_none()
        );

        let mut authed = req("/ws");
        authed.headers.push(
            "Authorization",
            format!("Basic {}", STANDARD.encode("alice:secret")),
        );
        let resource = crate::access::ResourceKey::request(
            None,
            &authed,
            "/ws",
            None,
            Some(target.proxy_url.as_str()),
        );
        assert!(
            authorize_failover(&cfg, None, &scope, &authed, "/ws", &target, peer, &resource)
                .is_some()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failover_rebuilds_member_policy_from_pristine_route_scope() {
        let dir =
            std::env::temp_dir().join(format!("vapache-proxy-member-scope-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let first_port = 19081;
        let second_port = 19082;
        let config_path = dir.join("httpd.conf");
        std::fs::write(
            &config_path,
            format!(
                "Listen 127.0.0.1:0\n\
                 <Proxy http://127.0.0.1:{first_port}/>\n\
                 Require all granted\n\
                 </Proxy>\n\
                 <Proxy http://127.0.0.1:{second_port}/>\n\
                 AuthMerging Or\n\
                 Require all denied\n\
                 </Proxy>\n"
            ),
        )
        .unwrap();
        let cfg =
            Config::load(&config_path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let request = req("/route");
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let base = Scope::default();

        // This is the old, contaminated construction: member B is merged into
        // member A, so AuthMerging Or carries A's grant into B.
        let mut contaminated = base.clone();
        cfg.apply_proxy_access_urls(
            None,
            &mut contaminated,
            &[&format!("http://127.0.0.1:{first_port}/")],
            &request,
            peer.ip(),
            "/route",
        );
        cfg.apply_proxy_access_urls(
            None,
            &mut contaminated,
            &[&format!("http://127.0.0.1:{second_port}/")],
            &request,
            peer.ip(),
            "/route",
        );
        assert_eq!(
            crate::access::check(&contaminated, &request, peer.ip(), None, "/route", None),
            crate::access::Access::Allowed
        );

        let backend = HttpBackend {
            host: "127.0.0.1".into(),
            port: second_port,
            base: "/".into(),
            tls: false,
        };
        let path = "/route".to_string();
        let target = Target {
            proxy_url: canonical_proxy_url(&backend, &path),
            backend,
            path,
            suffix: String::new(),
            reverse: Vec::new(),
            balancer: Some("test".into()),
            fail_on_status: Vec::new(),
            logical_url: None,
            route_order: 0,
        };
        let resource = crate::access::ResourceKey::request(
            None,
            &request,
            "/route",
            None,
            Some(target.proxy_url.as_str()),
        );
        assert!(authorize_failover(
            &cfg, None, &base, &request, "/route", &target, peer, &resource,
        )
        .is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failover_to_auth_required_member_returns_403() {
        let dir = std::env::temp_dir().join(format!("vapache-proxy-fo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let password = dir.join("htpasswd");
        let mut hasher = Sha1::new();
        hasher.update(b"secret");
        let digest = STANDARD.encode(hasher.finalize());
        std::fs::write(&password, format!("alice:{{SHA}}{digest}\n")).unwrap();

        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let second_port = second.local_addr().unwrap().port();
        drop(second);
        let balancer = format!("failover-auth-{}", std::process::id());
        let config_path = dir.join("httpd.conf");
        std::fs::write(
            &config_path,
            format!(
                "VapacheCapability MutableAuthFiles On\nListen 127.0.0.1:0\n<Proxy balancer://{balancer}>\nBalancerMember http://127.0.0.1:{dead_port}\nBalancerMember http://127.0.0.1:{second_port}\n</Proxy>\n<Proxy http://127.0.0.1:{second_port}>\nRequire valid-user\nAuthType Basic\nAuthName test\nAuthUserFile {}\n</Proxy>\n",
                password.display()
            ),
        )
        .unwrap();
        let cfg =
            Config::load(&config_path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/fo".into(),
                backend: format!("balancer://{balancer}"),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        let target = match_target(&cfg, &scope, "/fo/x").unwrap();
        let r = req("/fo/x");
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let resource = crate::access::ResourceKey::request(
            None,
            &r,
            "/fo/x",
            None,
            Some(target.proxy_url.as_str()),
        );
        let grant =
            crate::access::grant_if_allowed(crate::access::Access::Allowed, resource.clone())
                .unwrap();
        let resp = super::execute(
            &cfg,
            None,
            &scope,
            &r,
            "/fo/x",
            &target,
            peer,
            80,
            false,
            "host",
            "127.0.0.1",
            &grant,
            &resource,
        );
        assert_eq!(resp.status, 403);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_status_without_alternate_returns_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let dir = std::env::temp_dir().join(format!("vapache-proxy-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let balancer = format!("failstatus-{}", std::process::id());
        let config_path = dir.join("httpd.conf");
        std::fs::write(
            &config_path,
            format!(
                "Listen 127.0.0.1:0\n<Proxy balancer://{balancer}>\nBalancerMember http://127.0.0.1:{port}\nProxySet failonstatus=503\n</Proxy>\n"
            ),
        )
        .unwrap();
        let cfg =
            Config::load(&config_path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let mut scope = Scope::default();
        scope
            .proxy_policy
            .proxy_passes
            .push(crate::config::ProxyPassRule {
                prefix: "/fs".into(),
                backend: format!("balancer://{balancer}"),
                sticky_cookie: None,
                fail_on_status: Vec::new(),
                route_order: 0,
            });
        let target = match_target(&cfg, &scope, "/fs/x").unwrap();
        let r = req("/fs/x");
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let resource = crate::access::ResourceKey::request(
            None,
            &r,
            "/fs/x",
            None,
            Some(target.proxy_url.as_str()),
        );
        let grant =
            crate::access::grant_if_allowed(crate::access::Access::Allowed, resource.clone())
                .unwrap();
        let resp = super::execute(
            &cfg,
            None,
            &scope,
            &r,
            "/fs/x",
            &target,
            peer,
            80,
            false,
            "host",
            "127.0.0.1",
            &grant,
            &resource,
        );
        assert_eq!(resp.status, 503);
        handle.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn websocket_async_rejects_unsafe_target_path() {
        let (port, upstream) = spawn_upstream(ws_101("x"), false).await;
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let r = ws_request(key);
        let dir =
            std::env::temp_dir().join(format!("vapache-proxy-wsbad-{}-{port}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("httpd.conf");
        std::fs::write(&path, "Listen 127.0.0.1:0\n").unwrap();
        let cfg =
            Arc::new(Config::load(&path, &dir, &HashMap::new(), &HashMap::new(), false).unwrap());
        let backend = HttpBackend {
            host: "127.0.0.1".into(),
            port,
            base: "/".into(),
            tls: false,
        };
        let path = "/ws\r\nX-Injected: yes".to_string();
        let proxy_url = canonical_proxy_url(&backend, &path);
        let target = Arc::new(Target {
            backend,
            path,
            suffix: String::new(),
            reverse: Vec::new(),
            balancer: None,
            fail_on_status: Vec::new(),
            proxy_url,
            logical_url: None,
            route_order: 0,
        });
        let resource = crate::access::ResourceKey::request(
            None,
            &r,
            "/ws",
            None,
            Some(target.proxy_url.as_str()),
        );
        let grant =
            crate::access::grant_if_allowed(crate::access::Access::Allowed, resource.clone())
                .unwrap();
        let scope = Arc::new(Scope::default());
        let r = Arc::new(r);
        let grant = Arc::new(grant);
        let resource = Arc::new(resource);
        let (_client, server) = tokio::io::duplex(1024);
        let err = websocket_async(
            &cfg,
            &scope,
            &r,
            &target,
            &grant,
            &resource,
            server,
            "127.0.0.1:1".parse().unwrap(),
            false,
            "client.example",
            &[],
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        upstream.abort();
        let _ = upstream.await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ambiguous_failover_never_replays_unsafe_methods() {
        for method in ["POST", "PATCH", "CONNECT", "PROPFIND"] {
            assert!(!proxy_method_is_idempotent(method));
            assert!(!vapache_verified::proxy_retry_admit(
                true,
                proxy_method_is_idempotent(method)
            ));
            assert!(vapache_verified::proxy_retry_admit(
                false,
                proxy_method_is_idempotent(method)
            ));
        }
        for method in ["GET", "HEAD", "PUT", "DELETE", "OPTIONS"] {
            assert!(vapache_verified::proxy_retry_admit(
                true,
                proxy_method_is_idempotent(method)
            ));
        }
    }

    #[test]
    fn proxy_tls_configuration_is_built_once_per_policy() {
        let scope = Scope::default();
        let first = client_config(&scope).unwrap();
        let second = client_config(&scope).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!first.enable_early_data);
        assert!(!first.enable_secret_extraction);
    }

    #[test]
    fn proxy_tls_identity_removes_only_ipv6_authority_brackets() {
        assert!(matches!(
            tls_server_name("[::1]").unwrap(),
            ServerName::IpAddress(_)
        ));
        assert!(matches!(
            tls_server_name("example.test").unwrap(),
            ServerName::DnsName(_)
        ));
        assert!(tls_server_name("bad host").is_err());
    }

    #[test]
    fn privileged_proxy_ca_rejects_service_owned_input() {
        if crate::files::effective_uid() != 0 {
            return;
        }
        let dir =
            std::env::temp_dir().join(format!("vapache-proxy-ca-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let ca = dir.join("ca.pem");
        std::fs::write(&ca, b"not a trusted administrative certificate").unwrap();
        rustix::fs::chown(&ca, Some(rustix::fs::Uid::from_raw(1)), None).unwrap();

        let mut scope = Scope::default();
        scope.proxy_policy.proxy_ca_file = Some(ca);
        scope.proxy_policy.proxy_ca_trust = crate::files::AdminFileTrust::RootOwned;
        let error = build_client_config(&scope).unwrap_err();
        assert!(error.contains("root-owned"), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn literal_proxy_resolution_is_bounded_without_dns() {
        assert_eq!(
            resolve_backend_addrs(
                &test_backend_identities(),
                "127.0.0.1",
                8080,
                Duration::ZERO,
            )
            .unwrap(),
            vec!["127.0.0.1:8080".parse().unwrap()]
        );
        assert_eq!(
            resolve_backend_addrs(&test_backend_identities(), "[::1]", 8080, Duration::ZERO,)
                .unwrap(),
            vec!["[::1]:8080".parse().unwrap()]
        );
    }

    #[test]
    fn backend_identity_is_atomic_and_generation_scoped() {
        let generation = u64::MAX - 100;
        let next_generation = generation + 1;
        let identities = Arc::new(BackendIdentityRegistry::new(generation));
        let next_identities = BackendIdentityRegistry::new(next_generation);
        let lifetime = Arc::downgrade(&identities);
        let first: SocketAddr = "192.0.2.10:8080".parse().unwrap();
        let rebound: SocketAddr = "198.51.100.20:8080".parse().unwrap();

        assert_eq!(
            bind_backend_identity(&identities, "Backend.Example", 8080, vec![first]).unwrap(),
            vec![first]
        );
        assert_eq!(
            bind_backend_identity(&identities, "backend.example", 8080, vec![rebound]).unwrap(),
            vec![first],
            "a later DNS answer must not retarget an active configuration"
        );
        assert_eq!(
            bind_backend_identity(&next_identities, "backend.example", 8080, vec![rebound])
                .unwrap(),
            vec![rebound],
            "reload is the explicit backend identity transition"
        );
        assert!(connected_endpoint_admitted(first, first));
        assert!(!connected_endpoint_admitted(rebound, first));
        assert!(bind_backend_identity(
            &identities,
            "wrong-port.example",
            8080,
            vec!["192.0.2.10:8081".parse().unwrap()],
        )
        .is_err());

        assert_eq!(
            bound_backend_identity(&next_identities, "backend.example", 8080),
            Some(vec![rebound])
        );
        drop(identities);
        assert!(
            lifetime.upgrade().is_none(),
            "generation cleanup is structural"
        );
    }

    #[test]
    fn proxy_dns_isolated_worker_and_expired_jobs_are_bounded() {
        let identities = test_backend_identities();
        let addresses =
            resolve_backend_addrs(&identities, "localhost", 8080, Duration::from_secs(2)).unwrap();
        assert!(!addresses.is_empty());
        assert!(addresses.len() <= MAX_PROXY_ADDRESSES);
        assert!(addresses.iter().all(|address| address.port() == 8080));
        assert!(resolver_worker_main("bad host", 8080).is_err());

        let (reply, _rx) = mpsc::channel();
        let expired = DnsJob {
            host: "localhost".into(),
            port: 8080,
            deadline: Instant::now() - Duration::from_millis(1),
            reply,
        };
        assert_eq!(
            isolated_dns_lookup(&expired, &mut Vec::new())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::TimedOut
        );
        if !resolver_daemon_is_built() {
            return;
        }

        // `ip6-localhost` bypasses the literal localhost fast path while still
        // resolving entirely through the host's local resolver configuration.
        let (reply, _rx) = mpsc::channel();
        let local_dns = DnsJob {
            host: "ip6-localhost".into(),
            port: 8081,
            deadline: Instant::now() + Duration::from_secs(2),
            reply,
        };
        let resolved = isolated_dns_lookup(&local_dns, &mut Vec::new()).unwrap();
        assert!(!resolved.is_empty());
        assert!(resolved.iter().all(|address| address.port() == 8081));

        let identities = BackendIdentityRegistry::new(91);
        let cached =
            resolve_backend_addrs(&identities, "ip6-localhost", 8082, Duration::from_secs(2))
                .unwrap();
        assert!(!cached.is_empty());
        assert_eq!(
            resolve_backend_addrs(&identities, "IP6-LOCALHOST", 8082, Duration::from_secs(2),)
                .unwrap(),
            cached
        );
    }

    #[tokio::test]
    async fn async_dns_resolution_uses_the_isolated_worker_and_cache() {
        if !resolver_daemon_is_built() {
            return;
        }
        let identities = BackendIdentityRegistry::new(92);
        let first =
            resolve_backend_addrs_async(&identities, "ip6-localhost", 8083, Duration::from_secs(2))
                .await
                .unwrap();
        assert!(!first.is_empty());
        assert!(first.iter().all(|address| address.port() == 8083));
        assert_eq!(
            resolve_backend_addrs_async(
                &identities,
                "IP6-LOCALHOST",
                8083,
                Duration::from_secs(2),
            )
                .await
                .unwrap(),
            first
        );
    }

    #[tokio::test]
    async fn websocket_tunnel_has_an_idle_deadline() {
        let (mut client_tunnel, _client_peer) = tokio::io::duplex(64);
        let (mut upstream_tunnel, _upstream_peer) = tokio::io::duplex(64);
        let error = websocket_copy_idle(
            &mut client_tunnel,
            &mut upstream_tunnel,
            Duration::from_millis(10),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn websocket_tunnel_closes_when_generation_retires() {
        let (mut client_tunnel, _client_peer) = tokio::io::duplex(64);
        let (mut upstream_tunnel, _upstream_peer) = tokio::io::duplex(64);
        let (signal, retired) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            signal.send_replace(true);
        });
        let error = websocket_copy_idle(
            &mut client_tunnel,
            &mut upstream_tunnel,
            Duration::from_secs(1),
            Some(retired),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
    }
}
#[cfg(test)]
fn resolver_daemon_is_built() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .filter(|parent| parent.file_name().is_some_and(|name| name == "deps"))
        .and_then(|deps| deps.parent().map(|target| target.join("vapached")))
        .is_some_and(|daemon| daemon.is_file())
}
