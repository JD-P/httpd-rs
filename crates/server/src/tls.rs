//! TLS (mod_ssl-compatible subset) using Rustls.
//!
//! Certificates are loaded while the process is still privileged and then
//! shared immutably.  TLS is fail-closed: enabling `SSLEngine` without a
//! usable certificate/key pair is a startup error, and only TLS 1.2/1.3 are
//! offered even if an old configuration mentions SSLv3/TLSv1.0.

use crate::config::{vhost_port, ClientRevocationCheck, Config, HttpProtocol, SslConfig, VHost};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig, SupportedProtocolVersion};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
use std::time::{Duration, Instant};

type SharedKey = Arc<RwLock<Arc<CertifiedKey>>>;
const MAX_TLS_CERTIFICATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TLS_PRIVATE_KEY_BYTES: u64 = 1024 * 1024;
const MAX_TLS_CRL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_BROKER_ERROR_BYTES: u64 = 1024;
const BROKER_SHUTDOWN: u32 = u32::MAX;
const DEFAULT_SESSION_CACHE_TIMEOUT: Duration = Duration::from_secs(300);

struct PrivilegedFileBroker {
    stream: UnixStream,
    paths: HashMap<PathBuf, u32>,
    pid: libc::pid_t,
}

static PRIVILEGED_FILE_BROKER: OnceLock<Mutex<PrivilegedFileBroker>> = OnceLock::new();

struct ExpiringSession {
    value: Vec<u8>,
    expires: Instant,
}

struct ExpiringSessionCache {
    entries: Mutex<HashMap<Vec<u8>, ExpiringSession>>,
    capacity: usize,
    timeout: Duration,
}

impl ExpiringSessionCache {
    fn new(capacity: usize, timeout: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity,
            timeout,
        }
    }

    fn prune_expired(entries: &mut HashMap<Vec<u8>, ExpiringSession>, now: Instant) {
        entries.retain(|_, entry| entry.expires > now);
    }
}

// Session values contain traffic secrets. Keep Debug output deliberately
// structural so an error report can never disclose cached key material.
impl std::fmt::Debug for ExpiringSessionCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len();
        formatter
            .debug_struct("ExpiringSessionCache")
            .field("entries", &count)
            .field("capacity", &self.capacity)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl rustls::server::StoresServerSessions for ExpiringSessionCache {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        if !self.can_cache() {
            return false;
        }
        let now = Instant::now();
        let Some(expires) = now.checked_add(self.timeout) else {
            return false;
        };
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        Self::prune_expired(&mut entries, now);
        if !entries.contains_key(&key) && entries.len() >= self.capacity {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, ExpiringSession { value, expires });
        true
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if entries.get(key).is_some_and(|entry| entry.expires <= now) {
            entries.remove(key);
            return None;
        }
        entries.get(key).map(|entry| entry.value.clone())
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let entry = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(key)?;
        (entry.expires > Instant::now()).then_some(entry.value)
    }

    fn can_cache(&self) -> bool {
        self.capacity > 0 && !self.timeout.is_zero()
    }
}

fn tls_file_specs(cfg: &Config) -> Vec<(PathBuf, u64)> {
    fn add(specs: &mut HashMap<PathBuf, u64>, path: &Option<PathBuf>, limit: u64) {
        if let Some(path) = path {
            specs
                .entry(path.clone())
                .and_modify(|known| *known = (*known).max(limit))
                .or_insert(limit);
        }
    }

    fn add_ssl(specs: &mut HashMap<PathBuf, u64>, ssl: &SslConfig) {
        add(specs, &ssl.cert_file, MAX_TLS_CERTIFICATE_BYTES);
        add(specs, &ssl.key_file, MAX_TLS_PRIVATE_KEY_BYTES);
        add(specs, &ssl.chain_file, MAX_TLS_CERTIFICATE_BYTES);
        add(specs, &ssl.ca_file, MAX_TLS_CERTIFICATE_BYTES);
        add(specs, &ssl.ca_revocation_file, MAX_TLS_CRL_BYTES);
    }

    let mut specs = HashMap::new();
    add_ssl(&mut specs, &cfg.ssl);
    for vhost in &cfg.vhosts {
        add_ssl(&mut specs, &vhost.ssl);
    }
    let mut specs: Vec<_> = specs.into_iter().collect();
    specs.sort_by(|(a, _), (b, _)| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));
    specs
}

/// Fork a minimal root file broker before background threads start. The
/// unprivileged request process can ask only for TLS paths authorized by the
/// root-owned startup configuration, never for an arbitrary pathname.
pub fn install_privileged_file_broker(cfg: &Config, service_uid: u32) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    if PRIVILEGED_FILE_BROKER.get().is_some() {
        return Err("privileged TLS broker was already installed".to_string());
    }
    let specs = tls_file_specs(cfg);
    if specs.is_empty() {
        return Ok(());
    }
    for (path, _) in &specs {
        crate::files::validate_admin_parents(path, service_uid).map_err(|error| {
            format!("unsafe TLS administrative path {}: {error}", path.display())
        })?;
    }

    let mut sockets = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sockets.as_mut_ptr(),
        )
    } != 0
    {
        return Err(format!(
            "cannot create privileged TLS broker socket: {}",
            std::io::Error::last_os_error()
        ));
    }
    let parent_pid = unsafe { libc::getpid() };
    let child = unsafe { libc::fork() };
    if child < 0 {
        unsafe {
            libc::close(sockets[0]);
            libc::close(sockets[1]);
        }
        return Err(format!(
            "cannot fork privileged TLS broker: {}",
            std::io::Error::last_os_error()
        ));
    }
    if child == 0 {
        unsafe {
            libc::close(sockets[0]);
        }
        privileged_broker_child(sockets[1], parent_pid, specs.clone(), service_uid);
    }

    unsafe {
        libc::close(sockets[1]);
    }
    let stream = unsafe { UnixStream::from_raw_fd(sockets[0]) };
    let paths = specs
        .iter()
        .enumerate()
        .map(|(index, (path, _))| (path.clone(), index as u32))
        .collect();
    match PRIVILEGED_FILE_BROKER.set(Mutex::new(PrivilegedFileBroker {
        stream,
        paths,
        pid: child,
    })) {
        Ok(()) => Ok(()),
        Err(broker) => {
            let mut broker = broker
                .into_inner()
                .unwrap_or_else(|error| error.into_inner());
            let _ = broker.stream.write_all(&BROKER_SHUTDOWN.to_ne_bytes());
            let _ = broker.stream.shutdown(std::net::Shutdown::Both);
            unsafe {
                libc::waitpid(broker.pid, std::ptr::null_mut(), 0);
            }
            Err("privileged TLS broker was already installed".to_string())
        }
    }
}

fn privileged_broker_child(
    fd: libc::c_int,
    parent_pid: libc::pid_t,
    specs: Vec<(PathBuf, u64)>,
    service_uid: u32,
) -> ! {
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) != 0
            || libc::getppid() != parent_pid
        {
            libc::_exit(1);
        }
        if fd != 3 {
            if libc::dup2(fd, 3) < 0 {
                libc::_exit(1);
            }
            libc::close(fd);
        }
        if libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0u32) < 0 {
            for inherited in 4..65_536 {
                libc::close(inherited);
            }
        }
        libc::close(0);
        libc::close(1);
        libc::close(2);
        if harden_privileged_broker().is_err() {
            libc::_exit(1);
        }
        let mut stream = UnixStream::from_raw_fd(3);
        privileged_broker_loop(&mut stream, &specs, service_uid);
        libc::_exit(0);
    }
}

#[cfg(target_env = "gnu")]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))]
type RlimitResource = libc::c_int;

fn set_broker_limit(resource: RlimitResource, value: libc::rlim_t) -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn harden_privileged_broker() -> std::io::Result<()> {
    restrict_privileged_broker_process()?;
    install_broker_seccomp()
}

fn restrict_privileged_broker_process() -> std::io::Result<()> {
    set_broker_limit(libc::RLIMIT_CORE, 0)?;
    set_broker_limit(libc::RLIMIT_FSIZE, 0)?;
    set_broker_limit(libc::RLIMIT_NOFILE, 4)?;
    set_broker_limit(libc::RLIMIT_CPU, 60)?;
    set_broker_limit(libc::RLIMIT_AS, 512 * 1024 * 1024)?;
    let restriction_failed = unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
    };
    if restriction_failed {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn install_broker_seccomp() -> std::io::Result<()> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;

    fn statement(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    // Keep this deliberately smaller than a general Rust process profile.
    // The helper can read immutable files and answer its one socket; it cannot
    // create sockets, execute, change identity, inspect processes, or write
    // filesystem objects even though it retains uid 0.
    let allowed = [
        libc::SYS_read,
        libc::SYS_write,
        // Rust's static-musl UnixStream implementation uses recvfrom/sendto
        // for the already-connected broker socket where glibc uses read/write.
        // The broker retains no other socket descriptor and cannot create one.
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_close,
        // Static musl uses open for File::open("/"); glibc uses openat. The
        // certificate path itself is still resolved by the openat2 policy.
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_readlinkat,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_brk,
        libc::SYS_madvise,
        libc::SYS_fcntl,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_restart_syscall,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    let mut filter = Vec::with_capacity(5 + allowed.len() * 2);
    // struct seccomp_data: syscall number at byte 0, audit arch at byte 4.
    filter.push(statement(BPF_LD_W_ABS, 4));
    filter.push(jump(BPF_JMP_JEQ_K, AUDIT_ARCH, 1, 0));
    filter.push(statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    filter.push(statement(BPF_LD_W_ABS, 0));
    for syscall in allowed {
        filter.push(jump(BPF_JMP_JEQ_K, syscall as u32, 0, 1));
        filter.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    }
    filter.push(statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &program as *const libc::sock_fprog,
        )
    } != 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn install_broker_seccomp() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the privileged TLS broker has no seccomp profile for this architecture",
    ))
}

fn privileged_broker_loop(stream: &mut UnixStream, specs: &[(PathBuf, u64)], service_uid: u32) {
    loop {
        let mut request = [0u8; 4];
        if stream.read_exact(&mut request).is_err() {
            return;
        }
        let id = u32::from_ne_bytes(request);
        if id == BROKER_SHUTDOWN {
            return;
        }
        let result = specs
            .get(id as usize)
            .ok_or_else(|| "unrecognized privileged TLS file id".to_string())
            .and_then(|(path, limit)| {
                crate::files::validate_admin_parents(path, service_uid)
                    .map_err(|error| format!("unsafe TLS path {}: {error}", path.display()))?;
                crate::files::read_admin_file_following_root_owned_final_symlink(
                    path,
                    *limit,
                    crate::files::AdminFileTrust::RootOwned,
                )
                .map_err(|error| format!("cannot read {}: {error}", path.display()))
            });
        let (status, data) = match result {
            Ok(data) => (0u8, data),
            Err(error) => {
                let mut data = error.into_bytes();
                data.truncate(MAX_BROKER_ERROR_BYTES as usize);
                (1u8, data)
            }
        };
        let mut header = [0u8; 9];
        header[0] = status;
        header[1..].copy_from_slice(&(data.len() as u64).to_ne_bytes());
        if stream
            .write_all(&header)
            .and_then(|()| stream.write_all(&data))
            .is_err()
        {
            return;
        }
    }
}

fn read_tls_admin_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let Some(broker) = PRIVILEGED_FILE_BROKER.get() else {
        return crate::files::read_admin_file_following_root_owned_final_symlink(
            path,
            max_bytes,
            crate::files::AdminFileTrust::for_current_process(),
        )
        .map_err(|error| error.to_string());
    };
    let mut broker = broker.lock().unwrap_or_else(|error| error.into_inner());
    let Some(id) = broker.paths.get(path).copied() else {
        return Err(format!(
            "TLS path {} was not authorized at startup; a full restart is required",
            path.display()
        ));
    };
    privileged_broker_read(&mut broker.stream, id, max_bytes)
}

fn privileged_broker_read(
    stream: &mut UnixStream,
    id: u32,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    stream
        .write_all(&id.to_ne_bytes())
        .map_err(|error| format!("privileged TLS broker request failed: {error}"))?;
    let mut header = [0u8; 9];
    stream
        .read_exact(&mut header)
        .map_err(|error| format!("privileged TLS broker response failed: {error}"))?;
    let len = u64::from_ne_bytes(header[1..].try_into().expect("fixed broker header"));
    let response_limit = if header[0] == 0 {
        max_bytes
    } else {
        MAX_BROKER_ERROR_BYTES
    };
    // Drain every bounded response before reporting a caller-specific size
    // violation. A configured path can serve more than one TLS role with
    // different limits, and leaving its payload unread would frame the next
    // broker response at the wrong byte.
    if len > MAX_TLS_CERTIFICATE_BYTES.max(MAX_BROKER_ERROR_BYTES) {
        return Err("privileged TLS broker returned an oversized response".into());
    }
    let mut data = vec![0; len as usize];
    stream
        .read_exact(&mut data)
        .map_err(|error| format!("privileged TLS broker response failed: {error}"))?;
    if len > response_limit {
        return Err("privileged TLS broker returned an oversized response".into());
    }
    if header[0] == 0 {
        Ok(data)
    } else {
        Err(String::from_utf8_lossy(&data).into_owned())
    }
}

pub fn shutdown_privileged_file_broker() {
    let Some(broker) = PRIVILEGED_FILE_BROKER.get() else {
        return;
    };
    let mut broker = broker.lock().unwrap_or_else(|error| error.into_inner());
    let _ = broker.stream.write_all(&BROKER_SHUTDOWN.to_ne_bytes());
    let _ = broker.stream.shutdown(std::net::Shutdown::Both);
    unsafe {
        libc::waitpid(broker.pid, std::ptr::null_mut(), 0);
    }
}

#[derive(Debug)]
struct SniResolver {
    default: SharedKey,
    names: HashMap<String, (usize, SharedKey)>,
    wildcards: Vec<(usize, String, SharedKey)>,
}

/// Security identity fixed by a completed TLS handshake.  It is immutable
/// for the lifetime of the connection and is copied into both protocol
/// adapters before any request can select a virtual host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TlsConnectionIdentity {
    sni: Option<String>,
    local_ip: Option<IpAddr>,
    port: u16,
    handshake_vhost: Option<usize>,
    client_certificate_sha256: Option<[u8; 32]>,
}

fn current_key(key: &SharedKey) -> Arc<CertifiedKey> {
    key.read().unwrap_or_else(|e| e.into_inner()).clone()
}

struct OcspRefresh {
    chain: Vec<CertificateDer<'static>>,
    force_url: Option<String>,
    timeout: Duration,
    interval: Duration,
    cache_path: PathBuf,
    resource_budget: Option<Arc<crate::resource::ResourceBudget>>,
    staple_expires: Mutex<Option<Instant>>,
    // A refresher must not keep a retired TLS generation alive forever.
    key: Weak<RwLock<Arc<CertifiedKey>>>,
}

/// A TLS generation whose certificates, keys, client verifier, and initial
/// OCSP responses have all been validated, but whose refresh threads have not
/// yet been started.  Reload can therefore discard a failed candidate without
/// giving it any process-wide side effects.
pub(crate) struct PreparedServerConfig {
    config: Option<Arc<ServerConfig>>,
    refreshes: Vec<OcspRefresh>,
}

/// TLS generations for one bound listener. A concrete listener needs one
/// generation; a wildcard listener needs a fallback plus one generation for
/// each address-specific virtual-host bucket because Rustls certificate
/// resolution does not receive the accepted socket's destination address.
pub(crate) struct PreparedListenerConfigs {
    default: PreparedServerConfig,
    exact: HashMap<IpAddr, PreparedServerConfig>,
}

impl PreparedServerConfig {
    pub(crate) fn config(&self) -> Option<Arc<ServerConfig>> {
        self.config.clone()
    }

    pub(crate) fn activate(&mut self) {
        for refresh in self.refreshes.drain(..) {
            let _ = spawn_ocsp_refresh(refresh);
        }
    }
}

impl PreparedListenerConfigs {
    pub(crate) fn configs(
        &self,
    ) -> (
        Option<Arc<ServerConfig>>,
        HashMap<IpAddr, Option<Arc<ServerConfig>>>,
    ) {
        let exact = self
            .exact
            .iter()
            .map(|(address, prepared)| (*address, prepared.config()))
            .collect();
        (self.default.config(), exact)
    }

    pub(crate) fn activate(&mut self) {
        self.default.activate();
        for prepared in self.exact.values_mut() {
            prepared.activate();
        }
    }
}

fn normalize_name(name: &str) -> String {
    let name = name.trim();
    let name = if let Some(rest) = name.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if name.matches(':').count() == 1 {
        name.split(':').next().unwrap_or(name)
    } else {
        name
    };
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn wildcard_name_matches(name: &str, pattern: &str) -> bool {
    vapache_verified::host_pattern_matches(name.as_bytes(), pattern.as_bytes())
}

impl SniResolver {
    fn add_name(&mut self, raw: &str, order: usize, key: SharedKey, pattern: bool) {
        let name = normalize_name(raw);
        if name.is_empty() {
            return;
        }
        if pattern && name.bytes().any(|byte| matches!(byte, b'*' | b'?')) {
            self.wildcards.push((order, name, key));
        } else {
            // Apache selects the first virtual host for a duplicate name.
            // Keeping the first certificate makes the TLS and HTTP routing
            // decisions agree instead of presenting a later vhost's key.
            self.names.entry(name).or_insert((order, key));
        }
    }

    fn select_key(&self, name: Option<&str>) -> Arc<CertifiedKey> {
        let Some(name) = name else {
            return current_key(&self.default);
        };
        let name = normalize_name(name);
        let mut selected = self.names.get(&name).map(|(order, key)| (*order, key));
        for (order, pattern, key) in &self.wildcards {
            if selected.is_some_and(|(selected_order, _)| selected_order <= *order) {
                continue;
            }
            if wildcard_name_matches(&name, pattern) {
                selected = Some((*order, key));
            }
        }
        selected
            .map(|(_, key)| current_key(key))
            .unwrap_or_else(|| current_key(&self.default))
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.select_key(hello.server_name()))
    }
}

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    crate::fault::hit("tls.cert.read")
        .map_err(|e| format!("cannot open certificate {}: {e}", path.display()))?;
    let data = read_tls_admin_file(path, MAX_TLS_CERTIFICATE_BYTES)
        .map_err(|e| format!("cannot open certificate {}: {e}", path.display()))?;
    let certs = CertificateDer::pem_slice_iter(&data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse certificate {}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("no PEM certificates found in {}", path.display()));
    }
    Ok(certs)
}

fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    crate::fault::hit("tls.key.read")
        .map_err(|e| format!("cannot open private key {}: {e}", path.display()))?;
    let data = read_tls_admin_file(path, MAX_TLS_PRIVATE_KEY_BYTES)
        .map_err(|e| format!("cannot open private key {}: {e}", path.display()))?;
    PrivateKeyDer::from_pem_slice(&data).map_err(|e| match e {
        PemError::NoItemsFound => format!("no PEM private key found in {}", path.display()),
        _ => format!("cannot parse private key {}: {e}", path.display()),
    })
}

fn certbot_live_lineage(path: &Path) -> Option<&str> {
    let relative = path.strip_prefix("/etc/letsencrypt/live").ok()?;
    let mut components = relative.components();
    let lineage = components.next()?.as_os_str().to_str()?;
    components.next()?;
    if components.next().is_some()
        || lineage.is_empty()
        || lineage.starts_with('-')
        || !lineage
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return None;
    }
    Some(lineage)
}

/// A Certbot live-lineage input may legitimately be named before first
/// issuance. The caller must still prove that the path is an SSL certificate
/// or key input; this helper only recognizes the conventional missing path.
pub(crate) fn missing_certbot_live_file(path: &Path) -> bool {
    certbot_live_lineage(path).is_some()
        && std::fs::metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn certbot_domain(server_name: Option<&str>) -> Option<&str> {
    let mut name = server_name?;
    if let Some((_, authority)) = name.rsplit_once("://") {
        name = authority;
    }
    if let Some((host, port)) = name.rsplit_once(':') {
        if !host.contains(':') && !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
        {
            name = host;
        }
    }
    name = name.trim_end_matches('.');
    if name.len() > 253
        || !name.contains('.')
        || name.parse::<IpAddr>().is_ok()
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    Some(name)
}

fn certbot_first_issuance_error(
    error: String,
    ssl: &SslConfig,
    server_name: Option<&str>,
) -> String {
    let missing = [ssl.cert_file.as_deref(), ssl.key_file.as_deref()]
        .into_iter()
        .flatten()
        .find(|path| {
            missing_certbot_live_file(path) && error.contains(&path.display().to_string())
        });
    let Some(path) = missing else {
        return error;
    };
    let Some(lineage) = certbot_live_lineage(path) else {
        return error;
    };
    let domain = certbot_domain(server_name).or_else(|| certbot_domain(Some(lineage)));
    let Some(domain) = domain else {
        return format!(
            "{error}\n{} is a missing Certbot live-lineage file; obtain that certificate before enabling this TLS configuration, then run `sudo vapachectl configtest` again",
            path.display()
        );
    };
    let cert_name = if lineage.eq_ignore_ascii_case(domain) {
        String::new()
    } else {
        format!(" --cert-name {lineage}")
    };
    format!(
        "{error}\n{} is a missing Certbot live-lineage file. For first issuance, obtain it before enabling this TLS configuration:\n  sudo certbot certonly --standalone{cert_name} -d {domain}\nThen run `sudo vapachectl configtest` again.",
        path.display()
    )
}

fn read_crls(path: &Path) -> Result<Vec<CertificateRevocationListDer<'static>>, String> {
    let data = read_tls_admin_file(path, MAX_TLS_CRL_BYTES)
        .map_err(|e| format!("cannot open client CRL {}: {e}", path.display()))?;
    let crls = CertificateRevocationListDer::pem_slice_iter(&data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse client CRL {}: {e}", path.display()))?;
    if crls.is_empty() {
        return Err(format!("no PEM CRLs found in {}", path.display()));
    }
    Ok(crls)
}

fn load_key(
    ssl: &SslConfig,
    provider: &CryptoProvider,
    cache_dir: Option<&Path>,
) -> Result<(Arc<CertifiedKey>, Option<OcspRefresh>), String> {
    load_key_with_ocsp(ssl, provider, cache_dir, true)
}

fn load_key_with_ocsp(
    ssl: &SslConfig,
    provider: &CryptoProvider,
    cache_dir: Option<&Path>,
    enable_ocsp: bool,
) -> Result<(Arc<CertifiedKey>, Option<OcspRefresh>), String> {
    load_key_with_ocsp_accounted(ssl, provider, cache_dir, enable_ocsp, None)
}

fn load_key_with_ocsp_accounted(
    ssl: &SslConfig,
    provider: &CryptoProvider,
    cache_dir: Option<&Path>,
    enable_ocsp: bool,
    resource_budget: Option<&Arc<crate::resource::ResourceBudget>>,
) -> Result<(Arc<CertifiedKey>, Option<OcspRefresh>), String> {
    let cert_file = ssl
        .cert_file
        .as_ref()
        .ok_or_else(|| "SSLEngine is on but SSLCertificateFile is missing".to_string())?;
    let mut chain = read_certs(cert_file)?;
    if let Some(chain_file) = &ssl.chain_file {
        chain.extend(read_certs(chain_file)?);
    }
    // Apache permits the private key to be concatenated into the certificate
    // file; fall back to that when SSLCertificateKeyFile is absent.
    let key_file = ssl.key_file.as_ref().unwrap_or(cert_file);
    let key = read_key(key_file)?;
    let mut refresh = None;
    let ocsp = if ssl.stapling && enable_ocsp {
        let timeout = if ssl.stapling_responder_timeout.is_zero() {
            Duration::from_secs(5)
        } else {
            ssl.stapling_responder_timeout
        };
        let dir = cache_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(|| std::env::temp_dir().join("vapache-ocsp-cache"));
        let cache_path = crate::ocsp::cache_path(&dir, &chain, ssl.stapling_force_url.as_deref());
        let mut cached = crate::ocsp::load_cached(&cache_path, &chain);
        if let (Some(response), Some(budget)) = (&cached, resource_budget) {
            if !crate::ocsp::account_cached(&cache_path, response.len() as u64, budget) {
                let _ = std::fs::remove_file(&cache_path);
                cached = None;
            }
        }
        let fetched =
            crate::ocsp::staple_response(&chain, ssl.stapling_force_url.as_deref(), timeout);
        let response = if let Some(fresh) = fetched {
            if let Some(budget) = resource_budget {
                crate::ocsp::save_cached_accounted(&cache_path, &chain, &fresh, budget);
            } else {
                crate::ocsp::save_cached(&cache_path, &chain, &fresh);
            }
            Some(fresh)
        } else {
            cached
        };
        let (response, staple_expires) = match response {
            Some(response) => {
                let expires = crate::ocsp::valid_response_ttl(&chain, &response)
                    .and_then(|ttl| Instant::now().checked_add(ttl));
                match expires {
                    Some(expires) => (Some(response), Some(expires)),
                    None => (None, None),
                }
            }
            None => (None, None),
        };
        if response.is_none() {
            eprintln!(
                "vapache: OCSP stapling requested but no response could be fetched for {}",
                cert_file.display()
            );
        }
        let interval = if ssl.stapling_standard_cache_timeout.is_zero() {
            Duration::from_secs(3600)
        } else {
            ssl.stapling_standard_cache_timeout
        };
        refresh = Some((chain.clone(), cache_path, interval, timeout, staple_expires));
        response
    } else {
        None
    };
    let mut certified = CertifiedKey::from_der(chain, key, provider)
        .map_err(|e| format!("invalid TLS certificate/key pair: {e}"))?;
    certified.ocsp = ocsp;
    let certified = Arc::new(certified);
    let refresh =
        refresh.map(
            |(chain, cache_path, interval, timeout, staple_expires)| OcspRefresh {
                chain,
                force_url: ssl.stapling_force_url.clone(),
                timeout,
                interval,
                cache_path,
                resource_budget: resource_budget.cloned(),
                staple_expires: Mutex::new(staple_expires),
                key: Weak::new(),
            },
        );
    Ok((certified, refresh))
}

fn apply_ocsp_response(refresh: &OcspRefresh, response: Vec<u8>) -> bool {
    let Some(expires) = crate::ocsp::valid_response_ttl(&refresh.chain, &response)
        .and_then(|ttl| Instant::now().checked_add(ttl))
    else {
        return true;
    };
    let Some(shared) = refresh.key.upgrade() else {
        return false;
    };
    if let Some(budget) = &refresh.resource_budget {
        crate::ocsp::save_cached_accounted(&refresh.cache_path, &refresh.chain, &response, budget);
    } else {
        crate::ocsp::save_cached(&refresh.cache_path, &refresh.chain, &response);
    }
    let mut guard = shared.write().unwrap_or_else(|e| e.into_inner());
    let mut key = (**guard).clone();
    key.ocsp = Some(response);
    *guard = Arc::new(key);
    *refresh
        .staple_expires
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(expires);
    true
}

fn clear_expired_ocsp(refresh: &OcspRefresh, now: Instant) -> bool {
    let expired = refresh
        .staple_expires
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .is_some_and(|expires| expires <= now);
    if !expired {
        return true;
    }
    let Some(shared) = refresh.key.upgrade() else {
        return false;
    };
    let mut guard = shared.write().unwrap_or_else(|error| error.into_inner());
    if guard.ocsp.is_some() {
        let mut key = (**guard).clone();
        key.ocsp = None;
        *guard = Arc::new(key);
    }
    *refresh
        .staple_expires
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = None;
    true
}

fn ocsp_refresh_deadline(
    now: Instant,
    interval_deadline: Instant,
    staple_expires: Option<Instant>,
) -> Instant {
    let staple_deadline = staple_expires.map(|expires| {
        let remaining = expires.saturating_duration_since(now);
        if remaining > Duration::from_secs(30) {
            let lead = (remaining / 5).min(Duration::from_secs(300));
            now.checked_add(remaining.saturating_sub(lead))
                .unwrap_or(expires)
        } else if remaining > Duration::from_secs(2) {
            now.checked_add((remaining / 2).min(Duration::from_secs(5)))
                .unwrap_or(expires)
        } else {
            expires
        }
    });
    staple_deadline
        .map(|deadline| deadline.min(interval_deadline))
        .unwrap_or(interval_deadline)
}

fn wait_for_refresh(refresh: &OcspRefresh) -> bool {
    let started = Instant::now();
    let interval_deadline = started.checked_add(refresh.interval).unwrap_or(started);
    loop {
        if refresh.key.upgrade().is_none() {
            return false;
        }
        let now = Instant::now();
        let expires = *refresh
            .staple_expires
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if expires.is_some_and(|expires| expires <= now) {
            return clear_expired_ocsp(refresh, now);
        }
        // Never wait past nextUpdate. Refresh before it when the response has
        // enough lifetime left, but avoid a retry storm when a responder keeps
        // returning the same nearly expired response.
        let deadline = ocsp_refresh_deadline(now, interval_deadline, expires);
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            return true;
        }
        // Poll generation liveness so reloads do not leave hour-long sleeper
        // threads behind.  This is not a network polling interval.
        std::thread::sleep(remaining.min(Duration::from_secs(1)));
    }
}

fn ocsp_refresh_loop<F, G>(refresh: OcspRefresh, mut fetch: F, mut keep_going: G)
where
    F: FnMut(&OcspRefresh) -> Option<Vec<u8>>,
    G: FnMut(&OcspRefresh) -> bool,
{
    while keep_going(&refresh) {
        if let Some(response) = fetch(&refresh) {
            if !apply_ocsp_response(&refresh, response) {
                break;
            }
        }
    }
}

fn spawn_ocsp_refresh(refresh: OcspRefresh) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        ocsp_refresh_loop(
            refresh,
            |refresh| {
                crate::ocsp::fetch_fresh(
                    &refresh.chain,
                    refresh.force_url.as_deref(),
                    refresh.timeout,
                )
            },
            wait_for_refresh,
        )
    })
}

pub(crate) fn protocol_policy(spec: Option<&str>) -> Result<(bool, bool), String> {
    let mut tls12 = true;
    let mut tls13 = true;
    let mut replaced = false;
    if let Some(spec) = spec {
        for raw in spec.split_whitespace() {
            let (enable, bare, name) = match raw.as_bytes().first() {
                Some(b'+') => (true, false, &raw[1..]),
                Some(b'-') => (false, false, &raw[1..]),
                _ => (true, true, raw),
            };
            // Apache: a bare protocol list replaces the default; + and -
            // modify it.  We only implement TLS 1.2/1.3.
            if bare && !replaced {
                tls12 = false;
                tls13 = false;
                replaced = true;
            }
            match name.to_ascii_lowercase().as_str() {
                "all" => {
                    tls12 = enable;
                    tls13 = enable;
                }
                "tlsv1.2" => tls12 = enable,
                "tlsv1.3" => tls13 = enable,
                // SSLv2/3 and TLS 1.0/1.1 are intentionally unsupported.
                "sslv2" | "sslv3" | "tlsv1" | "tlsv1.1" => {}
                other => {
                    return Err(format!("unsupported SSLProtocol token '{other}'"));
                }
            }
        }
    }
    if !tls12 && !tls13 {
        return Err("SSLProtocol disables both TLS 1.2 and TLS 1.3".into());
    }
    Ok((tls12, tls13))
}

fn protocol_versions(spec: Option<&str>) -> Result<Vec<&'static SupportedProtocolVersion>, String> {
    let (tls12, tls13) = protocol_policy(spec)?;
    let mut out = Vec::new();
    if tls12 {
        out.push(&rustls::version::TLS12);
    }
    if tls13 {
        out.push(&rustls::version::TLS13);
    }
    Ok(out)
}

/// Exercise the vapache-owned SNI normalization/wildcard and TLS protocol
/// policy parsers.  rustls itself has separate cryptographic fuzzing; this
/// target covers the configuration-to-resolver boundary specific to vapache.
#[cfg(feature = "fuzzing")]
pub fn fuzz_tls_policy(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let normalized = normalize_name(text);
    let _ = protocol_versions(Some(text));
    for raw_suffix in text.split(|ch: char| ch.is_ascii_whitespace() || ch == ',') {
        let suffix = normalize_name(raw_suffix.trim_start_matches("*."));
        let _ = wildcard_name_matches(&normalized, &suffix);
    }
}

fn vhost_applies(v: &VHost, port: u16, local_ip: Option<IpAddr>) -> bool {
    match local_ip {
        Some(ip) => Config::vhost_address_applies(v, ip, port),
        None => v.addrs.iter().any(|a| vhost_port(a) == port),
    }
}

/// The client-certificate policy that Rustls applies to a listener.  A single
/// `ServerConfig` has one client-certificate verifier, so vhosts that disagree
/// cannot safely share a listener: doing so would either demand a certificate
/// from a public vhost or accept one on a vhost that requires it.
fn client_policy_mode(ssl: &SslConfig) -> u8 {
    match ssl.verify_client {
        None | Some(crate::config::ClientVerify::None) => 0,
        Some(crate::config::ClientVerify::Optional) => 1,
        Some(crate::config::ClientVerify::Require) => 2,
    }
}

type ClientPolicyKey = (u8, Option<Vec<u8>>, u8, Option<Vec<u8>>);

fn client_revocation_mode(ssl: &SslConfig) -> u8 {
    match ssl.ca_revocation_check {
        None | Some(ClientRevocationCheck::None) => 0,
        Some(ClientRevocationCheck::Leaf) => 1,
        Some(ClientRevocationCheck::Chain) => 2,
    }
}

fn client_policy_key(ssl: &SslConfig) -> ClientPolicyKey {
    let mode = client_policy_mode(ssl);
    let revocation = (mode != 0)
        .then(|| client_revocation_mode(ssl))
        .unwrap_or(0);
    (
        mode,
        (mode != 0)
            .then(|| {
                ssl.ca_file
                    .as_ref()
                    .map(|path| path.as_os_str().as_bytes().to_vec())
            })
            .flatten(),
        revocation,
        (revocation != 0)
            .then(|| {
                ssl.ca_revocation_file
                    .as_ref()
                    .map(|path| path.as_os_str().as_bytes().to_vec())
            })
            .flatten(),
    )
}

fn client_policy_equal(a: &ClientPolicyKey, b: &ClientPolicyKey) -> bool {
    let (a_mode, a_ca, a_revocation, a_crl) = a;
    let (b_mode, b_ca, b_revocation, b_crl) = b;
    vapache_verified::tls_client_policy_equal(
        *a_mode,
        a_ca.is_some(),
        a_ca.as_deref().unwrap_or(&[]),
        *b_mode,
        b_ca.is_some(),
        b_ca.as_deref().unwrap_or(&[]),
    ) && vapache_verified::tls_client_revocation_policy_equal(
        *a_revocation,
        a_crl.is_some(),
        a_crl.as_deref().unwrap_or(&[]),
        *b_revocation,
        b_crl.is_some(),
        b_crl.as_deref().unwrap_or(&[]),
    )
}

fn ensure_uniform_client_policy(policies: &[&SslConfig], port: u16) -> Result<(), String> {
    let Some(first) = policies.first() else {
        return Ok(());
    };
    let expected = client_policy_key(first);
    for ssl in policies.iter().skip(1) {
        if !client_policy_equal(&expected, &client_policy_key(ssl)) {
            return Err(format!(
                "TLS port {port} has virtual hosts with different client-certificate policies; use separate Listen directives so client trust/revocation policy cannot be applied across vhosts"
            ));
        }
    }
    Ok(())
}

fn path_identity(path: Option<&Path>) -> Option<&[u8]> {
    path.map(|path| path.as_os_str().as_bytes())
}

/// Apache's default secure SNI policy permits a Host-selected vhost transition
/// only when the handshake-relevant authentication and public-key policy is
/// identical.  Listener-wide settings are already required to be uniform;
/// retaining them here makes this comparison complete even for directly
/// constructed embedding configurations.
fn tls_vhost_policy_equal(a: &SslConfig, b: &SslConfig) -> bool {
    let a_key = a.key_file.as_deref().or(a.cert_file.as_deref());
    let b_key = b.key_file.as_deref().or(b.cert_file.as_deref());
    let protocols_equal = matches!(
        (
            protocol_policy(a.protocols.as_deref()),
            protocol_policy(b.protocols.as_deref())
        ),
        (Ok(a), Ok(b)) if a == b
    );
    client_policy_equal(&client_policy_key(a), &client_policy_key(b))
        && protocols_equal
        && a.engine == b.engine
        && path_identity(a.cert_file.as_deref()) == path_identity(b.cert_file.as_deref())
        && path_identity(a_key) == path_identity(b_key)
        && path_identity(a.chain_file.as_deref()) == path_identity(b.chain_file.as_deref())
        && a.cipher_suite == b.cipher_suite
        && a.honor_cipher_order.unwrap_or(false) == b.honor_cipher_order.unwrap_or(false)
        && a.session_cache.unwrap_or(true) == b.session_cache.unwrap_or(true)
        && a.session_cache_timeout
            .unwrap_or(DEFAULT_SESSION_CACHE_TIMEOUT)
            == b.session_cache_timeout
                .unwrap_or(DEFAULT_SESSION_CACHE_TIMEOUT)
        && a.session_tickets.unwrap_or(true) == b.session_tickets.unwrap_or(true)
}

impl TlsConnectionIdentity {
    fn from_parts(
        cfg: &Config,
        local_ip: Option<IpAddr>,
        port: u16,
        sni: Option<&str>,
        client_certificate: Option<&[u8]>,
    ) -> Result<Self, String> {
        let sni = sni.map(normalize_name).filter(|name| !name.is_empty());
        let handshake_vhost = cfg
            .select_vhost(local_ip, port, sni.as_deref())
            .map(|vhost| {
                cfg.vhost_position(vhost).ok_or_else(|| {
                    "TLS handshake selected a virtual host outside the compiled configuration"
                        .to_string()
                })
            })
            .transpose()?;
        let ssl = handshake_vhost
            .and_then(|index| cfg.vhosts.get(index))
            .map(|vhost| &vhost.ssl)
            .unwrap_or(&cfg.ssl);
        let certificate_present = client_certificate.is_some();
        if !vapache_verified::tls_client_identity_admit(
            matches!(
                ssl.verify_client,
                Some(crate::config::ClientVerify::Require)
            ),
            certificate_present,
        ) {
            return Err(
                "required TLS client identity was absent after the completed handshake".into(),
            );
        }
        let client_certificate_sha256 = client_certificate.map(|certificate| {
            let digest = ::ring::digest::digest(&::ring::digest::SHA256, certificate);
            let mut identity = [0u8; 32];
            identity.copy_from_slice(digest.as_ref());
            identity
        });
        Ok(Self {
            sni,
            local_ip,
            port,
            handshake_vhost,
            client_certificate_sha256,
        })
    }

    pub(crate) fn capture(
        cfg: &Config,
        local_ip: Option<IpAddr>,
        port: u16,
        connection: &rustls::ServerConnection,
    ) -> Result<Self, String> {
        Self::from_parts(
            cfg,
            local_ip,
            port,
            connection.server_name(),
            connection
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|certificate| certificate.as_ref()),
        )
    }

    /// Return an HTTP status when an authority cannot safely use this TLS
    /// connection.  400 preserves Apache's SNI-without-Host behavior; 421 is
    /// the RFC-defined signal that a coalesced connection selected an
    /// incompatible vhost.
    pub(crate) fn request_status(&self, cfg: &Config, authority: Option<&str>) -> Option<u16> {
        if !vapache_verified::tls_sni_authority_admit(self.sni.is_some(), authority.is_some()) {
            return Some(400);
        }
        let request_vhost = cfg
            .select_vhost(self.local_ip, self.port, authority)
            .and_then(|vhost| cfg.vhost_position(vhost));
        let handshake_ssl = self
            .handshake_vhost
            .and_then(|index| cfg.vhosts.get(index))
            .map(|vhost| &vhost.ssl)
            .unwrap_or(&cfg.ssl);
        let request_ssl = request_vhost
            .and_then(|index| cfg.vhosts.get(index))
            .map(|vhost| &vhost.ssl)
            .unwrap_or(&cfg.ssl);
        (!vapache_verified::tls_vhost_transition_admit(tls_vhost_policy_equal(
            handshake_ssl,
            request_ssl,
        )))
        .then_some(421)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        cfg: &Config,
        local_ip: Option<IpAddr>,
        port: u16,
        sni: Option<&str>,
    ) -> Self {
        Self::from_parts(cfg, local_ip, port, sni, None).expect("test TLS connection identity")
    }
}

/// Rustls selects protocol versions before SNI-based certificate resolution,
/// so every virtual host sharing a listener must agree on the effective
/// `SSLProtocol` policy. Applying only the default vhost's policy would
/// silently weaken one host or make another unavailable.
fn ensure_uniform_protocol_policy(policies: &[&SslConfig], port: u16) -> Result<(), String> {
    let Some(first) = policies.first() else {
        return Ok(());
    };
    let expected = protocol_policy(first.protocols.as_deref())?;
    for ssl in policies.iter().skip(1) {
        if protocol_policy(ssl.protocols.as_deref())? != expected {
            return Err(format!(
                "TLS port {port} has virtual hosts with different SSLProtocol policies; use separate Listen directives so protocol versions cannot be applied across vhosts"
            ));
        }
    }
    Ok(())
}

fn ensure_uniform_cipher_preference(policies: &[&SslConfig], port: u16) -> Result<(), String> {
    let Some(first) = policies.first() else {
        return Ok(());
    };
    let expected = first.honor_cipher_order.unwrap_or(false);
    if policies
        .iter()
        .skip(1)
        .any(|ssl| ssl.honor_cipher_order.unwrap_or(false) != expected)
    {
        return Err(format!(
            "TLS port {port} has virtual hosts with different SSLHonorCipherOrder policies; use separate Listen directives"
        ));
    }
    Ok(())
}

fn ensure_uniform_resumption_policy(policies: &[&SslConfig], port: u16) -> Result<(), String> {
    let Some(first) = policies.first() else {
        return Ok(());
    };
    let expected = (
        first.session_cache.unwrap_or(true),
        first
            .session_cache_timeout
            .unwrap_or(DEFAULT_SESSION_CACHE_TIMEOUT),
        first.session_tickets.unwrap_or(true),
    );
    for ssl in policies.iter().skip(1) {
        if (
            ssl.session_cache.unwrap_or(true),
            ssl.session_cache_timeout
                .unwrap_or(DEFAULT_SESSION_CACHE_TIMEOUT),
            ssl.session_tickets.unwrap_or(true),
        ) != expected
        {
            return Err(format!(
                "TLS port {port} has virtual hosts with different session-resumption policies; use separate Listen directives"
            ));
        }
    }
    Ok(())
}

/// ALPN is selected before the HTTP Host header is available. Every TLS
/// virtual host on one listener must therefore offer the same application
/// protocols, or an HTTP/1.1-only vhost could still be exposed to h2.
fn ensure_uniform_application_protocols(
    policies: &[&[HttpProtocol]],
    port: u16,
) -> Result<(), String> {
    let Some(first) = policies.first() else {
        return Ok(());
    };
    for protocols in policies.iter().skip(1) {
        if protocols != first {
            return Err(format!(
                "TLS port {port} has virtual hosts with different Protocols policies; use separate Listen directives so ALPN cannot expose a disabled protocol"
            ));
        }
    }
    Ok(())
}

/// Build the TLS configuration for a listening port, if any virtual host on
/// that port has `SSLEngine on` (or a global SSLEngine is configured).
/// `local_ip` filters address-bound vhosts when the listener itself is bound
/// to a specific destination address. `None` returns the safe wildcard
/// fallback; use `validate_listener_configs` when every exact destination
/// generation must be checked.
pub fn server_config(
    cfg: &Config,
    port: u16,
    local_ip: Option<IpAddr>,
) -> Result<Option<Arc<ServerConfig>>, String> {
    let local_ip = local_ip.or(Some(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)));
    Ok(prepare_server_config(cfg, port, local_ip)?.config())
}

/// Prepare every destination-specific TLS generation needed by one listener.
/// `listener_ip == None` denotes a wildcard bind. The fallback is built with
/// an unspecified destination so address-specific vhosts cannot leak into its
/// resolver; accepted sockets select an exact generation before handshaking.
pub(crate) fn prepare_listener_configs(
    cfg: &Config,
    port: u16,
    listener_ip: Option<IpAddr>,
) -> Result<PreparedListenerConfigs, String> {
    if let Some(listener_ip) = listener_ip {
        return Ok(PreparedListenerConfigs {
            default: prepare_server_config(cfg, port, Some(listener_ip))?,
            exact: HashMap::new(),
        });
    }

    let default =
        prepare_server_config(cfg, port, Some(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)))?;
    let mut exact = HashMap::new();
    for address in cfg.vhost_specific_addresses(port) {
        exact.insert(address, prepare_server_config(cfg, port, Some(address))?);
    }
    Ok(PreparedListenerConfigs { default, exact })
}

/// Syntax-test entry point that validates every certificate/policy generation
/// a wildcard listener may choose without exposing the prepared key material.
pub fn validate_listener_configs(
    cfg: &Config,
    port: u16,
    listener_ip: Option<IpAddr>,
) -> Result<(), String> {
    prepare_listener_configs(cfg, port, listener_ip).map(|_| ())
}

/// Fully validate and construct a TLS generation without starting any
/// background worker.  Activation is deliberately a separate, infallible
/// step so graceful reload has a real prepare/commit boundary.
pub(crate) fn prepare_server_config(
    cfg: &Config,
    port: u16,
    local_ip: Option<IpAddr>,
) -> Result<PreparedServerConfig, String> {
    let provider = Arc::new(ring::default_provider());
    let mut applicable_vhosts: Vec<&VHost> = cfg
        .vhosts
        .iter()
        .filter(|v| vhost_applies(v, port, local_ip))
        .collect();
    if let Some(ip) = local_ip {
        let exact_available = applicable_vhosts
            .iter()
            .any(|v| Config::vhost_address_is_specific(v, ip, port));
        applicable_vhosts
            .retain(|v| !exact_available || Config::vhost_address_is_specific(v, ip, port));
    }
    let global_only = cfg.ssl.engine && applicable_vhosts.is_empty();
    if !global_only && !applicable_vhosts.iter().any(|v| v.ssl.engine) {
        return Ok(PreparedServerConfig {
            config: None,
            refreshes: Vec::new(),
        });
    }
    if !global_only && applicable_vhosts.iter().any(|v| !v.ssl.engine) {
        return Err(format!(
            "TLS port {port} has virtual hosts with different SSLEngine policies; use separate Listen directives so an SSL-disabled host cannot inherit another host's TLS configuration"
        ));
    }
    let mut vhosts = applicable_vhosts;
    let policies: Vec<&SslConfig> = vhosts.iter().map(|v| &v.ssl).collect();
    ensure_uniform_client_policy(&policies, port)?;
    ensure_uniform_protocol_policy(&policies, port)?;
    ensure_uniform_cipher_preference(&policies, port)?;
    ensure_uniform_resumption_policy(&policies, port)?;
    let application_protocols: Vec<&[HttpProtocol]> =
        vhosts.iter().map(|v| v.protocols.as_slice()).collect();
    ensure_uniform_application_protocols(&application_protocols, port)?;

    // Apache's first matching virtual host is the default server.
    let default_ssl = if global_only {
        &cfg.ssl
    } else {
        &vhosts[0].ssl
    };
    let default_protocols = if global_only {
        cfg.protocols.as_slice()
    } else {
        vhosts[0].protocols.as_slice()
    };
    // Keep privileged stapling state directly below the root-owned ServerRoot,
    // not below a legacy logs directory that older releases handed to the
    // service account.
    let ocsp_cache_dir = cfg.server_root.join(".vapache-ocsp-cache");
    let default_server_name = (!global_only)
        .then(|| vhosts[0].server_name.as_deref())
        .flatten();
    let (default_cert, default_refresh) = load_key_with_ocsp_accounted(
        default_ssl,
        &provider,
        Some(&ocsp_cache_dir),
        true,
        Some(&cfg.resource_budget),
    )
    .map_err(|error| certbot_first_issuance_error(error, default_ssl, default_server_name))?;
    let default_key: SharedKey = Arc::new(RwLock::new(default_cert));
    let mut refreshes = Vec::new();
    if let Some(mut refresh) = default_refresh {
        refresh.key = Arc::downgrade(&default_key);
        refreshes.push(refresh);
    }
    let mut resolver = SniResolver {
        default: default_key.clone(),
        names: HashMap::new(),
        wildcards: Vec::new(),
    };
    if global_only {
        // No SNI names are known; the global certificate is the only key.
    } else {
        // The default vhost may be repeated; insert names for every TLS vhost.
        for (order, v) in vhosts.drain(..).enumerate() {
            let key = if std::ptr::eq(&v.ssl, default_ssl) {
                default_key.clone()
            } else {
                let (cert, refresh) = load_key_with_ocsp_accounted(
                    &v.ssl,
                    &provider,
                    Some(&ocsp_cache_dir),
                    true,
                    Some(&cfg.resource_budget),
                )
                .map_err(|error| {
                    certbot_first_issuance_error(error, &v.ssl, v.server_name.as_deref())
                })?;
                let shared = Arc::new(RwLock::new(cert));
                if let Some(mut refresh) = refresh {
                    refresh.key = Arc::downgrade(&shared);
                    refreshes.push(refresh);
                }
                shared
            };
            if let Some(n) = &v.server_name {
                // Apache treats ServerName literally even when it contains a
                // wildcard metacharacter. Only ServerAlias is pattern-aware.
                resolver.add_name(n, order, key.clone(), false);
            }
            for alias in &v.aliases {
                resolver.add_name(alias, order, key.clone(), true);
            }
        }
    }

    let versions = protocol_versions(default_ssl.protocols.as_deref())?;
    let revocation_check = default_ssl
        .ca_revocation_check
        .unwrap_or(ClientRevocationCheck::None);
    if client_policy_mode(default_ssl) == 0
        && (revocation_check != ClientRevocationCheck::None
            || default_ssl.ca_revocation_file.is_some())
    {
        return Err(
            "client-certificate revocation policy requires SSLVerifyClient optional or require"
                .into(),
        );
    }
    let verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> = match default_ssl
        .verify_client
        .unwrap_or(crate::config::ClientVerify::None)
    {
        crate::config::ClientVerify::None => Arc::new(rustls::server::NoClientAuth),
        mode => {
            let ca = default_ssl
                .ca_file
                .as_ref()
                .ok_or_else(|| "SSLVerifyClient requires SSLCACertificateFile".to_string())?;
            let mut roots = RootCertStore::empty();
            for cert in read_certs(ca)? {
                roots
                    .add(cert)
                    .map_err(|e| format!("invalid client CA certificate: {e}"))?;
            }
            let mut builder = WebPkiClientVerifier::builder(Arc::new(roots));
            match revocation_check {
                ClientRevocationCheck::None => {
                    if default_ssl.ca_revocation_file.is_some() {
                        return Err("SSLCARevocationFile requires SSLCARevocationCheck leaf or chain; refusing to load an unused security policy".into());
                    }
                }
                check => {
                    let crl = default_ssl.ca_revocation_file.as_ref().ok_or_else(|| {
                        "SSLCARevocationCheck requires SSLCARevocationFile".to_string()
                    })?;
                    builder = builder
                        .with_crls(read_crls(crl)?)
                        .enforce_revocation_expiration();
                    if check == ClientRevocationCheck::Leaf {
                        builder = builder.only_check_end_entity_revocation();
                    }
                }
            }
            let builder = if mode == crate::config::ClientVerify::Optional {
                builder.allow_unauthenticated()
            } else {
                builder
            };
            builder
                .build()
                .map_err(|e| format!("invalid client certificate verifier: {e}"))?
        }
    };
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| format!("invalid TLS protocol configuration: {e}"))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(resolver));
    // Keep replayable 0-RTT and pre-client-Finished application data outside
    // the supported protocol, even if a future Rustls release changes a
    // builder default. Request admission assumes every byte follows a fully
    // authenticated handshake and an immutable mTLS identity.
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    config.enable_secret_extraction = false;
    if default_ssl.session_cache == Some(false) {
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    } else {
        config.session_storage = Arc::new(ExpiringSessionCache::new(
            256,
            default_ssl
                .session_cache_timeout
                .unwrap_or(DEFAULT_SESSION_CACHE_TIMEOUT),
        ));
    }
    if default_ssl.session_tickets == Some(false) {
        // Rustls already disables stateless TLS 1.2 tickets. This also turns
        // off its stateful TLS 1.3 NewSessionTicket messages, conservatively
        // honoring Apache's broader SSLSessionTickets Off policy.
        config.send_tls13_tickets = 0;
    }
    config.ignore_client_order = default_ssl.honor_cipher_order.unwrap_or(false);
    config.alpn_protocols = default_protocols
        .iter()
        .map(|protocol| protocol.alpn().to_vec())
        .collect();
    Ok(PreparedServerConfig {
        config: Some(Arc::new(config)),
        refreshes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::server::StoresServerSessions as _;
    use rustls::{ClientConfig, ClientConnection, HandshakeKind, ServerConnection};
    use std::os::fd::IntoRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn protocol_selection_is_safe() {
        assert_eq!(protocol_versions(None).unwrap().len(), 2);
        assert_eq!(protocol_versions(Some("TLSv1.2")).unwrap().len(), 1);
        assert_eq!(protocol_versions(Some("-TLSv1.3")).unwrap().len(), 1);
        assert_eq!(protocol_versions(Some("+TLSv1.2")).unwrap().len(), 2);
        assert!(protocol_versions(Some("-TLSv1.2 -TLSv1.3")).is_err());
        assert!(
            protocol_versions(Some("all -SSLv3 -TLSv1 -TLSv1.1"))
                .unwrap()
                .len()
                == 2
        );
        assert!(protocol_versions(Some("bogus")).is_err());
    }

    #[test]
    fn privileged_broker_protocol_rejects_unknown_file_ids() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let helper = std::thread::spawn(move || privileged_broker_loop(&mut server, &[], u32::MAX));
        client.write_all(&0u32.to_ne_bytes()).unwrap();
        let mut header = [0u8; 9];
        client.read_exact(&mut header).unwrap();
        assert_eq!(header[0], 1);
        let len = u64::from_ne_bytes(header[1..].try_into().unwrap());
        assert!(len <= MAX_BROKER_ERROR_BYTES);
        let mut error = vec![0; len as usize];
        client.read_exact(&mut error).unwrap();
        assert!(String::from_utf8(error).unwrap().contains("unrecognized"));
        client.write_all(&BROKER_SHUTDOWN.to_ne_bytes()).unwrap();
        helper.join().unwrap();
    }

    #[test]
    fn privileged_broker_process_restrictions_are_tight() {
        // SAFETY: this child-only probe owns both pipe descriptors, checks
        // every syscall result used by the parent, and exits without running
        // post-fork destructors.
        unsafe {
            let mut pipe = [-1; 2];
            assert_eq!(libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC), 0);
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                libc::close(pipe[0]);
                let mut core: libc::rlimit = std::mem::zeroed();
                let mut files: libc::rlimit = std::mem::zeroed();
                let ok = restrict_privileged_broker_process().is_ok()
                    && libc::getrlimit(libc::RLIMIT_CORE, &mut core) == 0
                    && libc::getrlimit(libc::RLIMIT_NOFILE, &mut files) == 0
                    && core.rlim_cur == 0
                    && core.rlim_max == 0
                    && files.rlim_cur == 4
                    && files.rlim_max == 4
                    && libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0;
                let value = [u8::from(ok)];
                libc::write(pipe[1], value.as_ptr().cast(), value.len());
                libc::_exit(i32::from(!ok));
            }
            libc::close(pipe[1]);
            let mut value = [0u8; 1];
            assert_eq!(libc::read(pipe[0], value.as_mut_ptr().cast(), 1), 1);
            libc::close(pipe[0]);
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
            assert_eq!(value, [1]);
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn privileged_broker_seccomp_kills_unlisted_syscalls() {
        // SAFETY: the child installs the filter and intentionally executes one
        // forbidden syscall; the parent observes only its wait status.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || install_broker_seccomp().is_err()
                {
                    libc::_exit(1);
                }
                libc::syscall(libc::SYS_getpid);
                libc::_exit(0);
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(libc::WIFSIGNALED(status));
            assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
        }
    }

    #[test]
    fn root_broker_lifecycle_rotates_only_authorized_immutable_files() {
        // SAFETY: the root-only child receives one owned socket descriptor;
        // all pathname bytes are NUL-checked before chown and the child is
        // synchronously reaped before fixture removal.
        unsafe {
            if libc::geteuid() != 0 {
                return;
            }
            let dir = tempdir("root-broker-lifecycle");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let key = dir.join("key.pem");
            std::fs::write(&key, b"first-secret").unwrap();
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
            let (mut client, server) = UnixStream::pair().unwrap();
            let parent_pid = libc::getpid();
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                drop(client);
                privileged_broker_child(server.into_raw_fd(), parent_pid, vec![(key, 64)], 65_534);
            }
            drop(server);
            assert_eq!(
                privileged_broker_read(&mut client, 0, 64).unwrap(),
                b"first-secret"
            );

            let replacement = dir.join("replacement.pem");
            std::fs::write(&replacement, b"rotated-secret").unwrap();
            std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::rename(&replacement, &key).unwrap();
            assert_eq!(
                privileged_broker_read(&mut client, 0, 64).unwrap(),
                b"rotated-secret"
            );

            let key_c = std::ffi::CString::new(key.as_os_str().as_bytes()).unwrap();
            assert_eq!(libc::chown(key_c.as_ptr(), 65_534, 65_534), 0);
            assert!(privileged_broker_read(&mut client, 0, 64).is_err());
            client.write_all(&BROKER_SHUTDOWN.to_ne_bytes()).unwrap();
            drop(client);
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn oversized_broker_response_is_drained_before_the_next_request() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let helper = std::thread::spawn(move || {
            for (expected_id, data) in [(7u32, b"too large".as_slice()), (8, b"ok".as_slice())] {
                let mut request = [0u8; 4];
                server.read_exact(&mut request).unwrap();
                assert_eq!(u32::from_ne_bytes(request), expected_id);
                let mut header = [0u8; 9];
                header[1..].copy_from_slice(&(data.len() as u64).to_ne_bytes());
                server.write_all(&header).unwrap();
                server.write_all(data).unwrap();
            }
        });
        assert!(privileged_broker_read(&mut client, 7, 2).is_err());
        assert_eq!(privileged_broker_read(&mut client, 8, 2).unwrap(), b"ok");
        helper.join().unwrap();
    }

    #[test]
    fn privileged_broker_rechecks_service_owned_parents_on_each_read() {
        let dir = tempdir("broker-parent-recheck");
        let key = dir.join("key.pem");
        std::fs::write(&key, b"secret").unwrap();
        let service_uid = std::fs::metadata(&dir).unwrap().uid();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let helper = std::thread::spawn(move || {
            privileged_broker_loop(&mut server, &[(key, 16)], service_uid)
        });
        client.write_all(&0u32.to_ne_bytes()).unwrap();
        let mut header = [0u8; 9];
        client.read_exact(&mut header).unwrap();
        assert_eq!(header[0], 1);
        let len = u64::from_ne_bytes(header[1..].try_into().unwrap());
        let mut error = vec![0; len as usize];
        client.read_exact(&mut error).unwrap();
        assert!(String::from_utf8(error)
            .unwrap()
            .contains("unsafe TLS path"));
        client.write_all(&BROKER_SHUTDOWN.to_ne_bytes()).unwrap();
        helper.join().unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_certificate_is_an_error() {
        let provider = ring::default_provider();
        assert!(load_key(&SslConfig::default(), &provider, None).is_err());
        let ssl = SslConfig {
            engine: true,
            cert_file: Some("/does/not/exist.pem".into()),
            ..SslConfig::default()
        };
        assert!(load_key(&ssl, &provider, None).is_err());
    }

    #[test]
    fn missing_certbot_lineage_has_first_issuance_command() {
        assert!(missing_certbot_live_file(Path::new(
            "/etc/letsencrypt/live/new.example/fullchain.pem"
        )));
        assert!(!missing_certbot_live_file(Path::new("/does/not/exist.pem")));
        let ssl = SslConfig {
            engine: true,
            cert_file: Some("/etc/letsencrypt/live/new.example/fullchain.pem".into()),
            key_file: Some("/etc/letsencrypt/live/new.example/privkey.pem".into()),
            ..SslConfig::default()
        };
        let error = certbot_first_issuance_error(
            "cannot open certificate /etc/letsencrypt/live/new.example/fullchain.pem".into(),
            &ssl,
            Some("new.example:443"),
        );
        assert!(error.contains("sudo certbot certonly --standalone -d new.example"));
        assert!(error.contains("sudo vapachectl configtest"));
    }

    #[test]
    fn missing_named_certbot_lineage_preserves_cert_name() {
        let ssl = SslConfig {
            engine: true,
            cert_file: Some("/etc/letsencrypt/live/site-lineage/fullchain.pem".into()),
            ..SslConfig::default()
        };
        let error = certbot_first_issuance_error(
            "cannot open certificate /etc/letsencrypt/live/site-lineage/fullchain.pem".into(),
            &ssl,
            Some("www.example.test"),
        );
        assert!(error.contains(
            "sudo certbot certonly --standalone --cert-name site-lineage -d www.example.test"
        ));
    }

    #[test]
    fn ordinary_missing_certificate_does_not_suggest_certbot() {
        let ssl = SslConfig {
            engine: true,
            cert_file: Some("/does/not/exist.pem".into()),
            ..SslConfig::default()
        };
        assert_eq!(
            certbot_first_issuance_error(
                "cannot open certificate".into(),
                &ssl,
                Some("example.test")
            ),
            "cannot open certificate"
        );
    }

    #[test]
    fn unrelated_tls_error_does_not_blame_a_missing_certbot_sibling() {
        let ssl = SslConfig {
            engine: true,
            cert_file: Some("/etc/letsencrypt/live/example.test/fullchain.pem".into()),
            key_file: Some("/etc/letsencrypt/live/example.test/privkey.pem".into()),
            ..SslConfig::default()
        };
        assert_eq!(
            certbot_first_issuance_error(
                "cannot parse certificate /some/other/certificate.pem".into(),
                &ssl,
                Some("example.test")
            ),
            "cannot parse certificate /some/other/certificate.pem"
        );
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn injected_certificate_and_key_reads_fail_closed() {
        let _fault_guard = crate::fault::test_guard();
        let dir = tempdir("read-failpoints");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, b"not reached").unwrap();
        std::fs::write(&key, b"not reached").unwrap();

        crate::fault::configure("tls.cert.read", 0, std::io::ErrorKind::PermissionDenied);
        assert!(read_certs(&cert)
            .unwrap_err()
            .contains("injected failure at tls.cert.read"));

        crate::fault::configure("tls.key.read", 0, std::io::ErrorKind::PermissionDenied);
        assert!(read_key(&key)
            .unwrap_err()
            .contains("injected failure at tls.key.read"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn vhosts_cannot_share_a_listener_with_different_client_auth_policy() {
        let none = SslConfig::default();
        let require = SslConfig {
            verify_client: Some(crate::config::ClientVerify::Require),
            ca_file: Some("/etc/client-ca.pem".into()),
            ..SslConfig::default()
        };
        assert!(ensure_uniform_client_policy(&[&none, &none], 443).is_ok());
        assert!(ensure_uniform_client_policy(&[&none, &require], 443).is_err());
        let require2 = SslConfig {
            verify_client: Some(crate::config::ClientVerify::Require),
            ca_file: Some("/etc/client-ca.pem".into()),
            ..SslConfig::default()
        };
        assert!(ensure_uniform_client_policy(&[&require, &require2], 443).is_ok());
        let require3 = SslConfig {
            verify_client: Some(crate::config::ClientVerify::Require),
            ca_file: Some("/etc/other-ca.pem".into()),
            ..SslConfig::default()
        };
        assert!(ensure_uniform_client_policy(&[&require, &require3], 443).is_err());
        let revoked_leaf = SslConfig {
            verify_client: Some(crate::config::ClientVerify::Require),
            ca_file: Some("/etc/client-ca.pem".into()),
            ca_revocation_file: Some("/etc/client.crl".into()),
            ca_revocation_check: Some(ClientRevocationCheck::Leaf),
            ..SslConfig::default()
        };
        let revoked_leaf_same = revoked_leaf.clone();
        assert!(ensure_uniform_client_policy(&[&revoked_leaf, &revoked_leaf_same], 443).is_ok());
        assert!(ensure_uniform_client_policy(&[&require, &revoked_leaf], 443).is_err());
        let revoked_chain = SslConfig {
            ca_revocation_check: Some(ClientRevocationCheck::Chain),
            ..revoked_leaf.clone()
        };
        assert!(ensure_uniform_client_policy(&[&revoked_leaf, &revoked_chain], 443).is_err());
        let other_crl = SslConfig {
            ca_revocation_file: Some("/etc/other.crl".into()),
            ..revoked_leaf.clone()
        };
        assert!(ensure_uniform_client_policy(&[&revoked_leaf, &other_crl], 443).is_err());
    }

    #[test]
    fn vhosts_cannot_share_a_listener_with_different_protocol_policy() {
        let both = SslConfig::default();
        let tls12 = SslConfig {
            protocols: Some("TLSv1.2".into()),
            ..SslConfig::default()
        };
        let equivalent = SslConfig {
            protocols: Some("all -SSLv3 -TLSv1 -TLSv1.1".into()),
            ..SslConfig::default()
        };
        let invalid = SslConfig {
            protocols: Some("bogus".into()),
            ..SslConfig::default()
        };

        assert!(ensure_uniform_protocol_policy(&[&both, &equivalent], 443).is_ok());
        assert!(ensure_uniform_protocol_policy(&[&both, &tls12], 443).is_err());
        assert!(ensure_uniform_protocol_policy(&[&both, &invalid], 443).is_err());
        // Two malformed policies are not equal merely because both fail to
        // parse. Startup rejects them, and the request-time transition guard
        // independently remains closed for directly constructed configs.
        assert!(!tls_vhost_policy_equal(&invalid, &invalid));
    }

    #[test]
    fn session_cache_is_bounded_consumable_and_redacted() {
        let cache = ExpiringSessionCache::new(2, Duration::from_secs(60));
        assert!(cache.can_cache());
        assert!(cache.put(b"client-a".to_vec(), b"secret-a".to_vec()));
        assert!(cache.put(b"client-b".to_vec(), b"secret-b".to_vec()));
        assert!(cache.put(b"client-c".to_vec(), b"secret-c".to_vec()));
        assert!(cache.entries.lock().unwrap().len() <= 2);
        assert_eq!(cache.get(b"client-c"), Some(b"secret-c".to_vec()));
        assert_eq!(cache.take(b"client-c"), Some(b"secret-c".to_vec()));
        assert_eq!(cache.take(b"client-c"), None);

        let debug = format!("{cache:?}");
        assert!(!debug.contains("client"));
        assert!(!debug.contains("secret"));

        let disabled = ExpiringSessionCache::new(2, Duration::ZERO);
        assert!(!disabled.can_cache());
        assert!(!disabled.put(b"client".to_vec(), b"secret".to_vec()));
    }

    #[test]
    fn vhosts_cannot_share_a_listener_with_different_resumption_policy() {
        let first = SslConfig {
            session_cache: Some(true),
            session_cache_timeout: Some(Duration::from_secs(300)),
            session_tickets: Some(false),
            ..SslConfig::default()
        };
        let same = first.clone();
        let explicit_on = SslConfig {
            session_cache: Some(true),
            session_cache_timeout: Some(Duration::from_secs(300)),
            session_tickets: Some(true),
            ..SslConfig::default()
        };
        let implicit_on = SslConfig {
            session_cache_timeout: Some(Duration::from_secs(300)),
            ..SslConfig::default()
        };
        let different = SslConfig {
            session_cache_timeout: Some(Duration::from_secs(600)),
            ..first.clone()
        };
        assert!(ensure_uniform_resumption_policy(&[&first, &same], 443).is_ok());
        assert!(ensure_uniform_resumption_policy(&[&explicit_on, &implicit_on], 443).is_ok());
        assert!(ensure_uniform_resumption_policy(&[&first, &different], 443).is_err());
    }

    #[test]
    fn vhosts_cannot_share_a_listener_with_different_cipher_preference() {
        let client_order = SslConfig {
            honor_cipher_order: Some(false),
            ..SslConfig::default()
        };
        let implicit_client_order = SslConfig::default();
        let server_order = SslConfig {
            honor_cipher_order: Some(true),
            ..SslConfig::default()
        };
        assert!(
            ensure_uniform_cipher_preference(&[&client_order, &implicit_client_order], 443).is_ok()
        );
        assert!(ensure_uniform_cipher_preference(&[&client_order, &server_order], 443).is_err());
    }

    #[test]
    fn sni_names_are_normalized() {
        assert_eq!(normalize_name("Example.COM:443"), "example.com");
        assert_eq!(normalize_name("[::1]:443"), "::1");
        assert_eq!(normalize_name("host.example."), "host.example");
    }

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vapache-tls-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_cert(dir: &Path) -> (PathBuf, PathBuf) {
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
                "subjectAltName=DNS:localhost,DNS:*.example.test,IP:127.0.0.1",
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
        (cert, key)
    }

    fn run_openssl(args: &[&str]) {
        let status = std::process::Command::new("openssl")
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("openssl");
        assert!(status.success(), "openssl failed: {args:?}");
    }

    fn make_mtls_certificates(dir: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
        let ca = dir.join("ca.pem");
        let ca_key = dir.join("ca.key");
        let server = dir.join("server.pem");
        let server_key = dir.join("server.key");
        let server_csr = dir.join("server.csr");
        let server_ext = dir.join("server.ext");
        let client = dir.join("client.pem");
        let client_key = dir.join("client.key");
        let client_csr = dir.join("client.csr");
        let client_ext = dir.join("client.ext");

        run_openssl(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=vapache-test-ca",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            ca_key.to_str().unwrap(),
            "-out",
            ca.to_str().unwrap(),
        ]);
        run_openssl(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            server_key.to_str().unwrap(),
            "-out",
            server_csr.to_str().unwrap(),
        ]);
        std::fs::write(
            &server_ext,
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n",
        )
        .unwrap();
        run_openssl(&[
            "x509",
            "-req",
            "-days",
            "1",
            "-in",
            server_csr.to_str().unwrap(),
            "-CA",
            ca.to_str().unwrap(),
            "-CAkey",
            ca_key.to_str().unwrap(),
            "-CAcreateserial",
            "-extfile",
            server_ext.to_str().unwrap(),
            "-out",
            server.to_str().unwrap(),
        ]);
        run_openssl(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=vapache-test-client",
            "-keyout",
            client_key.to_str().unwrap(),
            "-out",
            client_csr.to_str().unwrap(),
        ]);
        std::fs::write(
            &client_ext,
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n",
        )
        .unwrap();
        run_openssl(&[
            "x509",
            "-req",
            "-days",
            "1",
            "-in",
            client_csr.to_str().unwrap(),
            "-CA",
            ca.to_str().unwrap(),
            "-CAkey",
            ca_key.to_str().unwrap(),
            "-CAcreateserial",
            "-extfile",
            client_ext.to_str().unwrap(),
            "-out",
            client.to_str().unwrap(),
        ]);
        (ca, server, server_key, client, client_key)
    }

    fn make_crl(dir: &Path, ca: &Path, ca_key: &Path, revoked: &Path) -> PathBuf {
        let database = dir.join("index.txt");
        let serial = dir.join("crl-serial");
        let number = dir.join("crlnumber");
        let new_certs = dir.join("newcerts");
        let config = dir.join("crl-openssl.cnf");
        let crl = dir.join("client.crl.pem");
        std::fs::create_dir_all(&new_certs).unwrap();
        std::fs::write(&database, "").unwrap();
        std::fs::write(&serial, "1000\n").unwrap();
        std::fs::write(&number, "1000\n").unwrap();
        std::fs::write(
            &config,
            format!(
                "[ ca ]\n\
                 default_ca = local\n\
                 [ local ]\n\
                 database = {}\n\
                 new_certs_dir = {}\n\
                 certificate = {}\n\
                 private_key = {}\n\
                 serial = {}\n\
                 crlnumber = {}\n\
                 default_md = sha256\n\
                 default_days = 1\n\
                 default_crl_days = 1\n\
                 policy = policy_any\n\
                 [ policy_any ]\n\
                 commonName = optional\n",
                database.display(),
                new_certs.display(),
                ca.display(),
                ca_key.display(),
                serial.display(),
                number.display()
            ),
        )
        .unwrap();
        run_openssl(&[
            "ca",
            "-batch",
            "-config",
            config.to_str().unwrap(),
            "-revoke",
            revoked.to_str().unwrap(),
        ]);
        run_openssl(&[
            "ca",
            "-batch",
            "-config",
            config.to_str().unwrap(),
            "-gencrl",
            "-out",
            crl.to_str().unwrap(),
        ]);
        crl
    }

    fn drive_handshake_result(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) -> Result<(), String> {
        for _ in 0..32 {
            let mut progressed = false;
            if client.wants_write() {
                let mut message = Vec::new();
                progressed |= client.write_tls(&mut message).map_err(|e| e.to_string())? != 0;
                if !message.is_empty() {
                    server
                        .read_tls(&mut message.as_slice())
                        .map_err(|e| e.to_string())?;
                    server.process_new_packets().map_err(|e| e.to_string())?;
                }
            }
            if server.wants_write() {
                let mut message = Vec::new();
                progressed |= server.write_tls(&mut message).map_err(|e| e.to_string())? != 0;
                if !message.is_empty() {
                    client
                        .read_tls(&mut message.as_slice())
                        .map_err(|e| e.to_string())?;
                    client.process_new_packets().map_err(|e| e.to_string())?;
                }
            }
            if !client.is_handshaking() && !server.is_handshaking() && !server.wants_write() {
                return Ok(());
            }
            if !progressed {
                return Err("TLS handshake made no progress".into());
            }
        }
        Err("TLS handshake did not complete".into())
    }

    fn drive_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
        drive_handshake_result(client, server).unwrap();
    }

    #[derive(Debug)]
    struct FixedTime(rustls::pki_types::UnixTime);

    impl rustls::time_provider::TimeProvider for FixedTime {
        fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
            Some(self.0)
        }
    }

    fn test_client_config(
        server_ca: &Path,
        client_identity: Option<(&Path, &Path)>,
    ) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        for cert in read_certs(server_ca).unwrap() {
            roots.add(cert).unwrap();
        }
        let builder = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots);
        match client_identity {
            Some((cert, key)) => builder
                .with_client_auth_cert(read_certs(cert).unwrap(), read_key(key).unwrap())
                .unwrap(),
            None => builder.with_no_client_auth(),
        }
    }

    fn handshake_with_name(
        client_config: Arc<ClientConfig>,
        server_config: Arc<ServerConfig>,
        name: &str,
    ) -> Result<(), String> {
        let mut client = ClientConnection::new(
            client_config,
            ServerName::try_from(name).unwrap().to_owned(),
        )
        .unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();
        drive_handshake_result(&mut client, &mut server)
    }

    fn test_config(dir: &Path, text: &str) -> Config {
        let path = dir.join("httpd.conf");
        std::fs::write(&path, text).unwrap();
        Config::load(&path, dir, &Default::default(), &Default::default(), false).unwrap()
    }

    #[test]
    fn broker_allowlist_is_exact_deduplicated_and_bounded() {
        let dir = tempdir("broker-allowlist");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let crl = dir.join("client.crl");
        let cfg = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\nSSLEngine On\nSSLCertificateFile {}\nSSLCertificateKeyFile {}\nSSLCertificateChainFile {}\nSSLCARevocationFile {}\nSSLCARevocationCheck leaf\n",
                cert.display(),
                key.display(),
                cert.display(),
                crl.display()
            ),
        );
        let specs = tls_file_specs(&cfg);
        assert_eq!(specs.len(), 3);
        assert_eq!(
            specs.iter().find(|(path, _)| path == &cert).unwrap().1,
            MAX_TLS_CERTIFICATE_BYTES
        );
        assert_eq!(
            specs.iter().find(|(path, _)| path == &key).unwrap().1,
            MAX_TLS_PRIVATE_KEY_BYTES
        );
        assert_eq!(
            specs.iter().find(|(path, _)| path == &crl).unwrap().1,
            MAX_TLS_CRL_BYTES
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn certificate_and_key_parsing_errors_are_closed() {
        let dir = tempdir("parse");
        let empty = dir.join("empty.pem");
        std::fs::write(&empty, "").unwrap();
        assert!(read_certs(&empty)
            .unwrap_err()
            .contains("no PEM certificates"));
        assert!(read_key(&empty).unwrap_err().contains("no PEM private key"));
        assert!(read_crls(&empty).unwrap_err().contains("no PEM CRLs"));

        let garbage = dir.join("garbage.pem");
        std::fs::write(&garbage, "not a pem file\n").unwrap();
        assert!(read_certs(&garbage).is_err());
        assert!(read_key(&garbage).is_err());
        assert!(read_crls(&garbage).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_key_uses_cached_ocsp_and_zero_timeout_defaults() {
        let dir = tempdir("ocsp");
        let (cert, key) = make_cert(&dir);
        let mut chain = read_certs(&cert).unwrap();
        chain.extend(read_certs(&cert).unwrap());
        let force_url = Some("http://127.0.0.1:1/");
        let cache_dir = dir.join("cache");
        let cache_path = crate::ocsp::cache_path(&cache_dir, &chain, force_url);
        let response = crate::ocsp::test_valid_response(&chain, &key);
        assert!(crate::ocsp::valid_response(&chain, &response));
        let mut tampered = response.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(!crate::ocsp::valid_response(&chain, &tampered));
        crate::ocsp::save_cached(&cache_path, &chain, &response);
        let ssl = SslConfig {
            engine: true,
            cert_file: Some(cert.clone()),
            key_file: Some(key),
            chain_file: Some(cert),
            stapling: true,
            stapling_force_url: force_url.map(str::to_string),
            stapling_responder_timeout: Duration::ZERO,
            stapling_standard_cache_timeout: Duration::ZERO,
            ..SslConfig::default()
        };
        let provider = ring::default_provider();
        let (certified, refresh) = load_key(&ssl, &provider, Some(&cache_dir)).unwrap();
        assert!(certified.ocsp.is_some());
        let mut refresh = refresh.expect("refresh handle");
        let expires = refresh
            .staple_expires
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("cached response deadline");
        let now = Instant::now();
        let interval_deadline = now + Duration::from_secs(3600);
        let deadline = ocsp_refresh_deadline(now, interval_deadline, Some(expires));
        assert!(deadline <= expires);
        assert!(deadline <= interval_deadline);
        let near_expiry = now + Duration::from_secs(20);
        let near_deadline = ocsp_refresh_deadline(now, interval_deadline, Some(near_expiry));
        assert!(near_deadline > now);
        assert!(near_deadline < near_expiry);

        let shared = Arc::new(RwLock::new(certified));
        refresh.key = Arc::downgrade(&shared);
        *refresh
            .staple_expires
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(Instant::now());
        assert!(clear_expired_ocsp(&refresh, Instant::now()));
        assert!(shared
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .ocsp
            .is_none());
        assert!(refresh
            .staple_expires
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_none());

        // Non-zero responder timeout with no cached response exercises the
        // warning path and returns a refresh handle with no initial staple.
        let no_cache = dir.join("no-cache");
        let ssl = SslConfig {
            engine: true,
            cert_file: Some(dir.join("cert.pem")),
            key_file: Some(dir.join("key.pem")),
            stapling: true,
            stapling_force_url: force_url.map(str::to_string),
            stapling_responder_timeout: Duration::from_millis(1),
            stapling_standard_cache_timeout: Duration::from_millis(1),
            ..SslConfig::default()
        };
        let (certified, refresh) = load_key(&ssl, &provider, Some(&no_cache)).unwrap();
        assert!(certified.ocsp.is_none());
        assert!(refresh.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ocsp_refresh_loop_applies_a_response_and_spawn_is_bounded() {
        let dir = tempdir("ocsp-loop");
        let (cert, key) = make_cert(&dir);
        let mut chain = read_certs(&cert).unwrap();
        chain.extend(read_certs(&cert).unwrap());
        let response = crate::ocsp::test_valid_response(&chain, &key);
        let ssl = SslConfig {
            engine: true,
            cert_file: Some(cert.clone()),
            key_file: Some(key),
            chain_file: Some(cert),
            stapling: true,
            stapling_responder_timeout: Duration::from_millis(1),
            stapling_standard_cache_timeout: Duration::from_millis(1),
            ..SslConfig::default()
        };
        let provider = ring::default_provider();
        let (certified, refresh) = load_key(&ssl, &provider, Some(&dir)).unwrap();
        let mut refresh = refresh.expect("refresh handle");
        let shared = Arc::new(RwLock::new(certified));
        refresh.key = Arc::downgrade(&shared);
        refresh.interval = Duration::ZERO;
        let mut iterations = 0;
        ocsp_refresh_loop(
            refresh,
            |_| Some(response.clone()),
            |_| {
                iterations += 1;
                iterations == 1
            },
        );
        assert_eq!(iterations, 2);

        // The production spawn wrapper is covered; the thread sleeps on the
        // default interval and is reclaimed when the test process exits.
        let (cert, key) = make_cert(&dir);
        let ssl = SslConfig {
            engine: true,
            cert_file: Some(cert),
            key_file: Some(key),
            stapling: true,
            stapling_standard_cache_timeout: Duration::from_secs(3600),
            ..SslConfig::default()
        };
        let (_certified, refresh) = load_key(&ssl, &provider, Some(&dir)).unwrap();
        if let Some(mut refresh) = refresh {
            let shared = Arc::new(RwLock::new(_certified));
            refresh.key = Arc::downgrade(&shared);
            let thread = spawn_ocsp_refresh(refresh);
            drop(shared);
            thread.join().unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sni_selection_and_client_policy_modes_are_explicit() {
        let dir = tempdir("sni");
        let (cert, key) = make_cert(&dir);
        let provider = ring::default_provider();
        let ssl = SslConfig {
            engine: true,
            cert_file: Some(cert),
            key_file: Some(key),
            ..SslConfig::default()
        };
        let (first, _) = load_key(&ssl, &provider, None).unwrap();
        let (second, _) = load_key(&ssl, &provider, None).unwrap();
        let first = Arc::new(RwLock::new(first));
        let second = Arc::new(RwLock::new(second));
        let resolver = SniResolver {
            default: first.clone(),
            names: HashMap::from([("exact.test".to_string(), (1, second.clone()))]),
            wildcards: vec![(1, "*.example.test".to_string(), second.clone())],
        };
        let default_key = current_key(&first);
        let second_key = current_key(&second);
        assert!(Arc::ptr_eq(&resolver.select_key(None), &default_key));
        assert!(Arc::ptr_eq(
            &resolver.select_key(Some("exact.test")),
            &second_key
        ));
        assert!(Arc::ptr_eq(
            &resolver.select_key(Some("single.example.test")),
            &second_key
        ));
        assert!(Arc::ptr_eq(
            &resolver.select_key(Some("multi.label.example.test")),
            &second_key
        ));
        assert!(Arc::ptr_eq(
            &resolver.select_key(Some("unknown.test")),
            &default_key
        ));

        let mut duplicates = SniResolver {
            default: first.clone(),
            names: HashMap::new(),
            wildcards: Vec::new(),
        };
        duplicates.add_name("duplicate.test", 0, first.clone(), false);
        duplicates.add_name("DUPLICATE.TEST.", 1, second.clone(), false);
        duplicates.add_name("*.test", 0, first.clone(), true);
        duplicates.add_name("*", 1, second.clone(), true);
        assert!(Arc::ptr_eq(
            &duplicates.select_key(Some("duplicate.test")),
            &default_key
        ));
        // First configured vhost wins across exact and wildcard aliases, just
        // as it does in the HTTP vhost index.
        assert!(Arc::ptr_eq(
            &duplicates.select_key(Some("later.test")),
            &default_key
        ));
        assert!(Arc::ptr_eq(
            &duplicates.select_key(Some("anything.invalid")),
            &second_key
        ));

        let mut patterns = SniResolver {
            default: first.clone(),
            names: HashMap::new(),
            wildcards: Vec::new(),
        };
        patterns.add_name("api-?.example", 1, second.clone(), true);
        patterns.add_name("literal-?.example", 1, second.clone(), false);
        assert!(Arc::ptr_eq(
            &patterns.select_key(Some("api-a.example")),
            &default_key
        ));
        assert!(Arc::ptr_eq(
            &patterns.select_key(Some("literal-a.example")),
            &default_key
        ));
        assert!(Arc::ptr_eq(
            &patterns.select_key(Some("literal-?.example")),
            &second_key
        ));

        assert_eq!(client_policy_mode(&SslConfig::default()), 0);
        assert_eq!(
            client_policy_mode(&SslConfig {
                verify_client: Some(crate::config::ClientVerify::None),
                ..SslConfig::default()
            }),
            0
        );
        assert_eq!(
            client_policy_mode(&SslConfig {
                verify_client: Some(crate::config::ClientVerify::Optional),
                ..SslConfig::default()
            }),
            1
        );
        assert_eq!(
            client_policy_mode(&SslConfig {
                verify_client: Some(crate::config::ClientVerify::Require),
                ..SslConfig::default()
            }),
            2
        );
        assert!(ensure_uniform_client_policy(&[], 443).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tls_connection_identity_binds_sni_host_and_verified_client() {
        let dir = tempdir("connection-identity");
        let cfg = test_config(
            &dir,
            "Listen 127.0.0.1:443\n\
             <VirtualHost *:443>\n\
               ServerName a.test\n\
               SSLEngine On\n\
               SSLCertificateFile /tls/a.pem\n\
               SSLCertificateKeyFile /tls/a.key\n\
             </VirtualHost>\n\
             <VirtualHost *:443>\n\
               ServerName b.test\n\
               SSLEngine On\n\
               SSLCertificateFile /tls/b.pem\n\
               SSLCertificateKeyFile /tls/b.key\n\
             </VirtualHost>\n\
             <VirtualHost *:443>\n\
               ServerName alias.test\n\
               SSLEngine On\n\
               SSLCertificateFile /tls/a.pem\n\
               SSLCertificateKeyFile /tls/a.key\n\
             </VirtualHost>\n",
        );
        let ip = Some("127.0.0.1".parse().unwrap());
        let identity = TlsConnectionIdentity::from_parts(
            &cfg,
            ip,
            443,
            Some("A.TEST."),
            Some(b"verified-client-leaf"),
        )
        .unwrap();
        assert_eq!(identity.sni.as_deref(), Some("a.test"));
        assert!(identity.client_certificate_sha256.is_some());
        assert_eq!(identity.request_status(&cfg, Some("a.test")), None);
        assert_eq!(identity.request_status(&cfg, Some("alias.test")), None);
        assert_eq!(identity.request_status(&cfg, Some("b.test")), Some(421));
        assert_eq!(identity.request_status(&cfg, None), Some(400));

        let no_sni = TlsConnectionIdentity::from_parts(&cfg, ip, 443, None, None).unwrap();
        assert_eq!(no_sni.request_status(&cfg, Some("a.test")), None);
        assert_eq!(no_sni.request_status(&cfg, Some("b.test")), Some(421));

        let required = test_config(
            &dir,
            "Listen 127.0.0.1:443\n\
             SSLEngine On\n\
             SSLCertificateFile /tls/server.pem\n\
             SSLCertificateKeyFile /tls/server.key\n\
             SSLVerifyClient require\n\
             SSLCACertificateFile /tls/client-ca.pem\n",
        );
        assert!(TlsConnectionIdentity::from_parts(&required, ip, 443, None, None).is_err());
        assert!(TlsConnectionIdentity::from_parts(
            &required,
            ip,
            443,
            None,
            Some(b"verified-client-leaf")
        )
        .is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn completed_and_resumed_mtls_handshakes_preserve_connection_identity() {
        let dir = tempdir("mtls-resumption-identity");
        let (ca, server_cert, server_key, client_cert, client_key) = make_mtls_certificates(&dir);
        let expected_leaf = read_certs(&client_cert).unwrap().remove(0);
        for (policy, version) in [
            ("TLSv1.2", &rustls::version::TLS12),
            ("TLSv1.3", &rustls::version::TLS13),
        ] {
            let cfg = test_config(
                &dir,
                &format!(
                    "Listen 127.0.0.1:443\n\
                     SSLEngine on\n\
                     SSLProtocol {policy}\n\
                     SSLCertificateFile {}\n\
                     SSLCertificateKeyFile {}\n\
                     SSLVerifyClient require\n\
                     SSLCACertificateFile {}\n",
                    server_cert.display(),
                    server_key.display(),
                    ca.display()
                ),
            );
            let server_config = server_config(&cfg, 443, None).unwrap().unwrap();
            let mut roots = RootCertStore::empty();
            for cert in read_certs(&ca).unwrap() {
                roots.add(cert).unwrap();
            }
            let client_config = Arc::new(
                ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_client_auth_cert(
                        read_certs(&client_cert).unwrap(),
                        read_key(&client_key).unwrap(),
                    )
                    .unwrap(),
            );

            let mut first_client = ClientConnection::new(
                client_config.clone(),
                ServerName::try_from("localhost").unwrap().to_owned(),
            )
            .unwrap();
            let mut first_server = ServerConnection::new(server_config.clone()).unwrap();
            drive_handshake(&mut first_client, &mut first_server);
            assert_eq!(
                first_server.handshake_kind(),
                Some(HandshakeKind::Full),
                "{policy}"
            );
            let first_identity =
                TlsConnectionIdentity::capture(&cfg, None, 443, &first_server).unwrap();
            assert_eq!(first_identity.sni.as_deref(), Some("localhost"));
            assert!(first_identity.client_certificate_sha256.is_some());
            assert_eq!(
                first_server.peer_certificates().unwrap()[0].as_ref(),
                expected_leaf.as_ref()
            );

            let mut resumed_client = ClientConnection::new(
                client_config,
                ServerName::try_from("localhost").unwrap().to_owned(),
            )
            .unwrap();
            let mut resumed_server = ServerConnection::new(server_config).unwrap();
            drive_handshake(&mut resumed_client, &mut resumed_server);
            assert_eq!(
                resumed_server.handshake_kind(),
                Some(HandshakeKind::Resumed),
                "{policy}"
            );
            let resumed_identity =
                TlsConnectionIdentity::capture(&cfg, None, 443, &resumed_server).unwrap();
            assert_eq!(resumed_identity, first_identity, "{policy}");
            assert_eq!(
                resumed_server.peer_certificates().unwrap()[0].as_ref(),
                expected_leaf.as_ref()
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn negative_handshake_matrix_rejects_invalid_server_and_client_identity() {
        let dir = tempdir("negative-handshake-matrix");
        let first_dir = dir.join("first");
        let second_dir = dir.join("second");
        std::fs::create_dir_all(&first_dir).unwrap();
        std::fs::create_dir_all(&second_dir).unwrap();
        let (ca, server_cert, server_key, client_cert, client_key) =
            make_mtls_certificates(&first_dir);
        let (other_ca, _, _, other_client_cert, other_client_key) =
            make_mtls_certificates(&second_dir);

        let plain = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\n\
                 SSLEngine on\n\
                 SSLProtocol TLSv1.3\n\
                 SSLCertificateFile {}\n\
                 SSLCertificateKeyFile {}\n",
                server_cert.display(),
                server_key.display()
            ),
        );
        let plain_server = server_config(&plain, 443, None).unwrap().unwrap();
        assert!(handshake_with_name(
            Arc::new(test_client_config(&ca, None)),
            plain_server.clone(),
            "localhost"
        )
        .is_ok());

        // The certificate is otherwise trusted, so this isolates name
        // validation rather than merely testing an unknown issuer.
        assert!(handshake_with_name(
            Arc::new(test_client_config(&ca, None)),
            plain_server.clone(),
            "wrong.example"
        )
        .is_err());
        assert!(handshake_with_name(
            Arc::new(test_client_config(&other_ca, None)),
            plain_server.clone(),
            "localhost"
        )
        .is_err());

        // Exercise both sides of the X.509 validity interval with actual TLS
        // handshakes, using Rustls's injectable wall clock instead of flaky
        // sub-second certificates.
        let mut not_yet_valid = test_client_config(&ca, None);
        not_yet_valid.time_provider = Arc::new(FixedTime(
            rustls::pki_types::UnixTime::since_unix_epoch(Duration::ZERO),
        ));
        assert!(
            handshake_with_name(Arc::new(not_yet_valid), plain_server.clone(), "localhost")
                .is_err()
        );
        let mut expired = test_client_config(&ca, None);
        expired.time_provider = Arc::new(FixedTime(rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_secs(rustls::pki_types::UnixTime::now().as_secs() + 10 * 86_400),
        )));
        assert!(handshake_with_name(Arc::new(expired), plain_server, "localhost").is_err());

        let mtls_text = |client_ca: &Path, revocation: Option<&Path>| {
            format!(
                "Listen 127.0.0.1:443\n\
                 SSLEngine on\n\
                 SSLProtocol TLSv1.3\n\
                 SSLCertificateFile {}\n\
                 SSLCertificateKeyFile {}\n\
                 SSLVerifyClient require\n\
                 SSLCACertificateFile {}\n{}",
                server_cert.display(),
                server_key.display(),
                client_ca.display(),
                revocation.map_or_else(String::new, |crl| format!(
                    "SSLCARevocationFile {}\nSSLCARevocationCheck leaf\n",
                    crl.display()
                ))
            )
        };
        let mtls = test_config(&dir, &mtls_text(&ca, None));
        let mtls_server = server_config(&mtls, 443, None).unwrap().unwrap();
        let valid_client = Arc::new(test_client_config(&ca, Some((&client_cert, &client_key))));
        assert!(
            handshake_with_name(valid_client.clone(), mtls_server.clone(), "localhost").is_ok()
        );

        // A certificate with only serverAuth is not a client identity, even
        // when it chains to the configured client CA.
        assert!(handshake_with_name(
            Arc::new(test_client_config(&ca, Some((&server_cert, &server_key)))),
            mtls_server.clone(),
            "localhost"
        )
        .is_err());
        assert!(handshake_with_name(
            Arc::new(test_client_config(
                &ca,
                Some((&other_client_cert, &other_client_key))
            )),
            mtls_server,
            "localhost"
        )
        .is_err());

        // The client has a cached session from the successful CA-1
        // handshake. Rebuilding the listener with CA-2 must still reject that
        // identity rather than carrying authentication across the boundary.
        let changed_trust = test_config(&dir, &mtls_text(&other_ca, None));
        let changed_server = server_config(&changed_trust, 443, None).unwrap().unwrap();
        assert!(handshake_with_name(valid_client.clone(), changed_server, "localhost").is_err());

        let crl = make_crl(&first_dir, &ca, &first_dir.join("ca.key"), &client_cert);
        assert!(!read_crls(&crl).unwrap().is_empty());
        let revoked = test_config(&dir, &mtls_text(&ca, Some(&crl)));
        let revoked_server = server_config(&revoked, 443, None).unwrap().unwrap();
        assert!(handshake_with_name(valid_client, revoked_server, "localhost").is_err());

        let missing_crl_policy = test_config(
            &dir,
            &format!("{}SSLCARevocationCheck leaf\n", mtls_text(&ca, None)),
        );
        assert!(server_config(&missing_crl_policy, 443, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wildcard_listener_selects_tls_generation_by_destination_address() {
        let dir = tempdir("destination-identity");
        let first_dir = dir.join("first");
        let second_dir = dir.join("second");
        std::fs::create_dir(&first_dir).unwrap();
        std::fs::create_dir(&second_dir).unwrap();
        let (first_ca, first_cert, first_key, _, _) = make_mtls_certificates(&first_dir);
        let (second_ca, second_cert, second_key, _, _) = make_mtls_certificates(&second_dir);
        let cfg = test_config(
            &dir,
            &format!(
                "Listen 0.0.0.0:443\n\
                 <VirtualHost 127.0.0.1:443>\n\
                   ServerName localhost\n\
                   SSLEngine on\n\
                   SSLProtocol TLSv1.2\n\
                   SSLCertificateFile {}\n\
                   SSLCertificateKeyFile {}\n\
                 </VirtualHost>\n\
                 <VirtualHost 127.0.0.2:443>\n\
                   ServerName localhost\n\
                   SSLEngine on\n\
                   SSLProtocol TLSv1.2\n\
                   SSLCertificateFile {}\n\
                   SSLCertificateKeyFile {}\n\
                 </VirtualHost>\n",
                first_cert.display(),
                first_key.display(),
                second_cert.display(),
                second_key.display()
            ),
        );
        let prepared = prepare_listener_configs(&cfg, 443, None).unwrap();
        let (default, exact) = prepared.configs();
        assert!(default.is_none());
        let first_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let second_ip: IpAddr = "127.0.0.2".parse().unwrap();
        let first_server_config = exact.get(&first_ip).unwrap().clone().unwrap();
        let second_server_config = exact.get(&second_ip).unwrap().clone().unwrap();
        assert!(!Arc::ptr_eq(&first_server_config, &second_server_config));

        let mut roots = RootCertStore::empty();
        for cert in read_certs(&first_ca)
            .unwrap()
            .into_iter()
            .chain(read_certs(&second_ca).unwrap())
        {
            roots.add(cert).unwrap();
        }
        let client_config = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        for (ip, server_config, expected_cert) in [
            (first_ip, first_server_config, first_cert),
            (second_ip, second_server_config, second_cert),
        ] {
            let mut client = ClientConnection::new(
                client_config.clone(),
                ServerName::try_from("localhost").unwrap().to_owned(),
            )
            .unwrap();
            let mut server = ServerConnection::new(server_config).unwrap();
            drive_handshake(&mut client, &mut server);
            let expected = read_certs(&expected_cert).unwrap().remove(0);
            assert_eq!(
                client.peer_certificates().unwrap()[0].as_ref(),
                expected.as_ref(),
                "wrong certificate for destination {ip}"
            );
            let identity = TlsConnectionIdentity::capture(&cfg, Some(ip), 443, &server).unwrap();
            assert_eq!(identity.request_status(&cfg, Some("localhost")), None);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn server_config_covers_global_vhost_sni_and_optional_client_auth() {
        let dir = tempdir("server-config");
        let (cert, key) = make_cert(&dir);
        let cert_s = cert.display();
        let key_s = key.display();

        let none = test_config(&dir, "Listen 127.0.0.1:444\n");
        assert!(server_config(&none, 444, None).unwrap().is_none());

        let global = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\nSSLEngine on\nSSLCertificateFile \"{cert_s}\"\nSSLCertificateKeyFile \"{key_s}\"\n"
            ),
        );
        let global_tls = server_config(&global, 443, None).unwrap().unwrap();
        assert_eq!(
            global_tls.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(global_tls.max_early_data_size, 0);
        assert!(!global_tls.send_half_rtt_data);
        assert!(!global_tls.enable_secret_extraction);
        let default_cache = format!("{:?}", global_tls.session_storage);
        assert!(default_cache.contains("ExpiringSessionCache"));
        assert!(default_cache.contains("300s"));

        let resumption = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\nSSLEngine on\nSSLCertificateFile \"{cert_s}\"\nSSLCertificateKeyFile \"{key_s}\"\nSSLSessionCache shmcb:/run/apache2/ssl_scache(512000)\nSSLSessionCacheTimeout 300\nSSLSessionTickets Off\n"
            ),
        );
        let resumption_tls = server_config(&resumption, 443, None).unwrap().unwrap();
        assert!(resumption_tls.session_storage.can_cache());
        assert_eq!(resumption_tls.send_tls13_tickets, 0);

        let no_cache = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\nSSLEngine on\nSSLCertificateFile \"{cert_s}\"\nSSLCertificateKeyFile \"{key_s}\"\nSSLSessionCache none\n"
            ),
        );
        let no_cache_tls = server_config(&no_cache, 443, None).unwrap().unwrap();
        assert!(!no_cache_tls.session_storage.can_cache());

        let server_cipher_order = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\nSSLEngine on\nSSLCertificateFile \"{cert_s}\"\nSSLCertificateKeyFile \"{key_s}\"\nSSLHonorCipherOrder On\nSSLOptions +StrictRequire\n"
            ),
        );
        let server_cipher_order_tls = server_config(&server_cipher_order, 443, None)
            .unwrap()
            .unwrap();
        assert!(server_cipher_order_tls.ignore_client_order);

        let http1_only = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\nProtocols http/1.1\nSSLEngine on\nSSLCertificateFile \"{cert_s}\"\nSSLCertificateKeyFile \"{key_s}\"\n"
            ),
        );
        let http1_tls = server_config(&http1_only, 443, None).unwrap().unwrap();
        assert_eq!(http1_tls.alpn_protocols, vec![b"http/1.1".to_vec()]);

        let vhosts = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\n\
                 <VirtualHost *:443>\n\
                     ServerName a.test\n\
                     ServerAlias *.example.test .example.test _default_ *\n\
                     SSLEngine on\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                 </VirtualHost>\n\
                 <VirtualHost *:443>\n\
                     ServerName b.test\n\
                     SSLEngine on\n\
                     SSLUseStapling on\n\
                     SSLStaplingStandardCacheTimeout 3600\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                 </VirtualHost>\n"
            ),
        );
        assert!(server_config(&vhosts, 443, None).unwrap().is_some());

        let protocol_mismatch = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\n\
                 <VirtualHost *:443>\n\
                     Protocols http/1.1\n\
                     SSLEngine on\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                 </VirtualHost>\n\
                 <VirtualHost *:443>\n\
                     Protocols h2 http/1.1\n\
                     SSLEngine on\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                 </VirtualHost>\n"
            ),
        );
        assert!(server_config(&protocol_mismatch, 443, None)
            .unwrap_err()
            .contains("different Protocols policies"));

        let engine_mismatch = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\n\
                 <VirtualHost *:443>\n\
                     ServerName enabled.test\n\
                     SSLEngine on\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                 </VirtualHost>\n\
                 <VirtualHost *:443>\n\
                     ServerName disabled.test\n\
                     SSLEngine off\n\
                 </VirtualHost>\n"
            ),
        );
        assert!(server_config(&engine_mismatch, 443, None)
            .unwrap_err()
            .contains("different SSLEngine policies"));

        let address_bound = test_config(
            &dir,
            &format!(
                "Listen 0.0.0.0:443\n\
                 <VirtualHost 127.0.0.1:443>\n\
                     ServerName admin.test\n\
                     SSLEngine on\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                 </VirtualHost>\n\
                 <VirtualHost *:443>\n\
                     ServerName public.test\n\
                     SSLEngine on\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                 </VirtualHost>\n"
            ),
        );
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let other: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(vhost_applies(&address_bound.vhosts[0], 443, Some(loopback)));
        assert!(!vhost_applies(&address_bound.vhosts[0], 443, Some(other)));
        assert!(vhost_applies(&address_bound.vhosts[1], 443, Some(other)));
        assert!(server_config(&address_bound, 443, Some(loopback))
            .unwrap()
            .is_some());
        assert!(server_config(&address_bound, 443, Some(other))
            .unwrap()
            .is_some());

        let address_disabled = test_config(
            &dir,
            &format!(
                "Listen 0.0.0.0:443\n\
                 <VirtualHost 127.0.0.1:443>\n\
                     ServerName disabled.test\n\
                     SSLEngine off\n\
                 </VirtualHost>\n\
                 <VirtualHost *:443>\n\
                     ServerName public.test\n\
                     SSLEngine on\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                 </VirtualHost>\n"
            ),
        );
        assert!(server_config(&address_disabled, 443, Some(loopback))
            .unwrap()
            .is_none());
        assert!(server_config(&address_disabled, 443, Some(other))
            .unwrap()
            .is_some());
        assert!(server_config(&address_disabled, 443, None)
            .unwrap()
            .is_some());
        let prepared = prepare_listener_configs(&address_disabled, 443, None).unwrap();
        let (fallback, exact) = prepared.configs();
        assert!(fallback.is_some());
        assert!(exact.get(&loopback).is_some_and(Option::is_none));
        assert!(!exact.contains_key(&other));

        for mode in ["optional", "require"] {
            let cfg = test_config(
                &dir,
                &format!(
                    "Listen 127.0.0.1:443\n\
                     SSLEngine on\n\
                     SSLCertificateFile \"{cert_s}\"\n\
                     SSLCertificateKeyFile \"{key_s}\"\n\
                     SSLVerifyClient {mode}\n\
                     SSLCACertificateFile \"{cert_s}\"\n"
                ),
            );
            assert!(server_config(&cfg, 443, None).unwrap().is_some(), "{mode}");
        }

        let missing_ca = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\n\
                 SSLEngine on\n\
                 SSLCertificateFile \"{cert_s}\"\n\
                 SSLCertificateKeyFile \"{key_s}\"\n\
                 SSLVerifyClient require\n"
            ),
        );
        assert!(server_config(&missing_ca, 443, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
