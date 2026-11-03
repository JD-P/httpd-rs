//! TLS (mod_ssl-compatible subset) using Rustls.
//!
//! Certificates are loaded while the process is still privileged and then
//! shared immutably.  TLS is fail-closed: enabling `SSLEngine` without a
//! usable certificate/key pair is a startup error, and only TLS 1.2/1.3 are
//! offered even if an old configuration mentions SSLv3/TLSv1.0.

use crate::config::{vhost_port, Config, HttpProtocol, SslConfig, VHost};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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
const MAX_BROKER_ERROR_BYTES: u64 = 1024;
const BROKER_SHUTDOWN: u32 = u32::MAX;

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
    names: HashMap<String, SharedKey>,
    wildcards: Vec<(String, SharedKey)>,
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

fn wildcard_name_matches(name: &str, suffix: &str) -> bool {
    name.strip_suffix(&format!(".{suffix}"))
        .is_some_and(|prefix| !prefix.is_empty() && !prefix.contains('.'))
}

impl SniResolver {
    fn add_name(&mut self, raw: &str, key: SharedKey) {
        let name = normalize_name(raw);
        if name.is_empty() || name == "*" || name.starts_with('_') {
            return;
        }
        if let Some(suffix) = name.strip_prefix("*.") {
            if !suffix.is_empty() {
                self.wildcards.push((suffix.to_string(), key));
            }
        } else if let Some(suffix) = name.strip_prefix('.') {
            if !suffix.is_empty() {
                self.wildcards.push((suffix.to_string(), key));
            }
        } else {
            // Apache selects the first virtual host for a duplicate name.
            // Keeping the first certificate makes the TLS and HTTP routing
            // decisions agree instead of presenting a later vhost's key.
            self.names.entry(name).or_insert(key);
        }
    }

    fn select_key(&self, name: Option<&str>) -> Arc<CertifiedKey> {
        let Some(name) = name else {
            return current_key(&self.default);
        };
        let name = normalize_name(name);
        if let Some(key) = self.names.get(&name) {
            return current_key(key);
        }
        for (suffix, key) in &self.wildcards {
            if wildcard_name_matches(&name, suffix) {
                return current_key(key);
            }
        }
        current_key(&self.default)
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
        refresh = Some((chain.clone(), cache_path, interval, timeout));
        response
    } else {
        None
    };
    let mut certified = CertifiedKey::from_der(chain, key, provider)
        .map_err(|e| format!("invalid TLS certificate/key pair: {e}"))?;
    certified.ocsp = ocsp;
    let certified = Arc::new(certified);
    let refresh = refresh.map(|(chain, cache_path, interval, timeout)| OcspRefresh {
        chain,
        force_url: ssl.stapling_force_url.clone(),
        timeout,
        interval,
        cache_path,
        resource_budget: resource_budget.cloned(),
        key: Weak::new(),
    });
    Ok((certified, refresh))
}

fn apply_ocsp_response(refresh: &OcspRefresh, response: Vec<u8>) -> bool {
    if !crate::ocsp::valid_response(&refresh.chain, &response) {
        return true;
    }
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
    true
}

fn wait_for_refresh(refresh: &OcspRefresh) -> bool {
    let deadline = Instant::now() + refresh.interval;
    loop {
        if refresh.key.upgrade().is_none() {
            return false;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
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
        None => 0,
        Some(crate::config::ClientVerify::None) => 1,
        Some(crate::config::ClientVerify::Optional) => 2,
        Some(crate::config::ClientVerify::Require) => 3,
    }
}

fn client_policy_key(ssl: &SslConfig) -> (u8, Option<Vec<u8>>) {
    (
        client_policy_mode(ssl),
        ssl.ca_file
            .as_ref()
            .map(|path| path.as_os_str().as_bytes().to_vec()),
    )
}

fn client_policy_equal(a: &(u8, Option<Vec<u8>>), b: &(u8, Option<Vec<u8>>)) -> bool {
    let (a_mode, a_ca) = a;
    let (b_mode, b_ca) = b;
    vapache_verified::tls_client_policy_equal(
        *a_mode,
        a_ca.is_some(),
        a_ca.as_deref().unwrap_or(&[]),
        *b_mode,
        b_ca.is_some(),
        b_ca.as_deref().unwrap_or(&[]),
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
                "TLS port {port} has virtual hosts with different client-certificate policies;                  use separate Listen directives so SSLVerifyClient/SSLCACertificateFile cannot                  be applied across vhosts"
            ));
        }
    }
    Ok(())
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
        first.session_cache_timeout,
        first.session_tickets.unwrap_or(true),
    );
    for ssl in policies.iter().skip(1) {
        if (
            ssl.session_cache.unwrap_or(true),
            ssl.session_cache_timeout,
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
/// to a specific destination address.
pub fn server_config(
    cfg: &Config,
    port: u16,
    local_ip: Option<IpAddr>,
) -> Result<Option<Arc<ServerConfig>>, String> {
    Ok(prepare_server_config(cfg, port, local_ip)?.config())
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
    let (default_cert, default_refresh) = load_key_with_ocsp_accounted(
        default_ssl,
        &provider,
        Some(&ocsp_cache_dir),
        true,
        Some(&cfg.resource_budget),
    )?;
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
        for v in vhosts.drain(..) {
            let key = if std::ptr::eq(&v.ssl, default_ssl) {
                default_key.clone()
            } else {
                let (cert, refresh) = load_key_with_ocsp_accounted(
                    &v.ssl,
                    &provider,
                    Some(&ocsp_cache_dir),
                    true,
                    Some(&cfg.resource_budget),
                )?;
                let shared = Arc::new(RwLock::new(cert));
                if let Some(mut refresh) = refresh {
                    refresh.key = Arc::downgrade(&shared);
                    refreshes.push(refresh);
                }
                shared
            };
            let mut names = Vec::new();
            if let Some(n) = &v.server_name {
                names.push(n.clone());
            }
            names.extend(v.aliases.iter().cloned());
            for raw in names {
                resolver.add_name(&raw, key.clone());
            }
        }
    }

    let versions = protocol_versions(default_ssl.protocols.as_deref())?;
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
            let builder = WebPkiClientVerifier::builder(Arc::new(roots));
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
    if default_ssl.session_cache == Some(false) {
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    } else if let Some(timeout) = default_ssl.session_cache_timeout {
        config.session_storage = Arc::new(ExpiringSessionCache::new(256, timeout));
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
    use rustls::server::StoresServerSessions as _;
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
        let cfg = test_config(
            &dir,
            &format!(
                "Listen 127.0.0.1:443\nSSLEngine On\nSSLCertificateFile {}\nSSLCertificateKeyFile {}\nSSLCertificateChainFile {}\n",
                cert.display(),
                key.display(),
                cert.display()
            ),
        );
        let specs = tls_file_specs(&cfg);
        assert_eq!(specs.len(), 2);
        assert_eq!(
            specs.iter().find(|(path, _)| path == &cert).unwrap().1,
            MAX_TLS_CERTIFICATE_BYTES
        );
        assert_eq!(
            specs.iter().find(|(path, _)| path == &key).unwrap().1,
            MAX_TLS_PRIVATE_KEY_BYTES
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

        let garbage = dir.join("garbage.pem");
        std::fs::write(&garbage, "not a pem file\n").unwrap();
        assert!(read_certs(&garbage).is_err());
        assert!(read_key(&garbage).is_err());
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
        assert!(refresh.is_some());

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
            names: HashMap::from([("exact.test".to_string(), second.clone())]),
            wildcards: vec![("example.test".to_string(), second.clone())],
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
            &default_key
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
        duplicates.add_name("duplicate.test", first.clone());
        duplicates.add_name("DUPLICATE.TEST.", second.clone());
        assert!(Arc::ptr_eq(
            &duplicates.select_key(Some("duplicate.test")),
            &default_key
        ));

        assert_eq!(client_policy_mode(&SslConfig::default()), 0);
        assert_eq!(
            client_policy_mode(&SslConfig {
                verify_client: Some(crate::config::ClientVerify::None),
                ..SslConfig::default()
            }),
            1
        );
        assert_eq!(
            client_policy_mode(&SslConfig {
                verify_client: Some(crate::config::ClientVerify::Optional),
                ..SslConfig::default()
            }),
            2
        );
        assert_eq!(
            client_policy_mode(&SslConfig {
                verify_client: Some(crate::config::ClientVerify::Require),
                ..SslConfig::default()
            }),
            3
        );
        assert!(ensure_uniform_client_policy(&[], 443).is_ok());
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
            .unwrap_err()
            .contains("different SSLEngine policies"));

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
