//! Process-generation resource accounting for attacker-controlled dynamic I/O.
//!
//! Reservations are RAII values.  A failed parse, backend error, early return,
//! or short client connection therefore releases its bytes/slot without every
//! caller having to remember a matching decrement.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Every attacker-reachable concurrency slot is represented in this one
/// ledger. Byte reservations use the same `ResourceContext` below, but retain
/// their specialized adjustable leases because their charge changes while a
/// body is read or transformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum SlotKind {
    DynamicBackend,
    H2Stream,
    SlowInput,
    SlowOutput,
    ResponseBodyRead,
    Websocket,
    ExpensiveCpu,
    PendingConnection,
    H1Connection,
    RequestWorker,
    RequestBodyWorker,
    H2Connection,
    TlsHandshake,
    RewriteProgram,
    SpoolFile,
    SlowSpoolFile,
    FilesystemWork,
}

impl SlotKind {
    const COUNT: usize = 17;

    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
enum ByteKind {
    Spool,
    SlowSpool,
    RequestResident,
    ResponseResident,
    SlowResponseResident,
    PolicyExpansion,
    CacheResident,
}

/// Typed leases ultimately consume a smaller set of operating-system
/// resources.  These parent counters prevent individually-safe pools from
/// collectively exhausting the process file-descriptor, task, or resident
/// memory ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
enum PhysicalKind {
    FileDescriptor,
    Task,
    ResidentMemory,
}

impl PhysicalKind {
    const COUNT: usize = 3;

    const fn index(self) -> usize {
        self as usize
    }
}

impl ByteKind {
    const COUNT: usize = 7;

    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug)]
struct ScopeUsage {
    slots: [AtomicU64; SlotKind::COUNT],
    bytes: [AtomicU64; ByteKind::COUNT],
    request_rate_admitted: AtomicBool,
}

impl Default for ScopeUsage {
    fn default() -> Self {
        Self {
            slots: std::array::from_fn(|_| AtomicU64::new(0)),
            bytes: std::array::from_fn(|_| AtomicU64::new(0)),
            request_rate_admitted: AtomicBool::new(false),
        }
    }
}

#[derive(Debug, Default)]
struct RateWindow {
    started: Option<std::time::Instant>,
    total: u64,
    clients: HashMap<IpAddr, u64>,
}

#[derive(Debug, Default)]
struct RateLedger {
    tls: RateWindow,
    rewrite_program: RateWindow,
    request_parse: RateWindow,
    request: RateWindow,
    expensive: RateWindow,
    cache_write: RateWindow,
    log_bytes: RateWindow,
}

/// One writable filesystem's exact byte and directory-entry allowance.  The
/// device number is the kernel identity returned by `stat(2)`, so configured
/// cache, log and OCSP paths on different mounts cannot consume one another's
/// reserved recovery headroom.
#[derive(Debug)]
struct DiskLedger {
    device: u64,
    bytes: AtomicU64,
    files: AtomicU64,
    byte_limit: u64,
    file_limit: u64,
}

impl DiskLedger {
    fn new(device: u64, byte_limit: u64, file_limit: u64) -> Self {
        Self {
            device,
            bytes: AtomicU64::new(0),
            files: AtomicU64::new(0),
            byte_limit,
            file_limit,
        }
    }
}

#[derive(Debug, Default)]
struct DiskLedgers {
    devices: HashMap<u64, Arc<DiskLedger>>,
    /// Callers use a small, configuration-owned set of roots (temp, cache,
    /// log and OCSP). Caching those paths avoids a `statvfs(2)` on every
    /// request-body or response-cache spool admission.
    paths: HashMap<PathBuf, Arc<DiskLedger>>,
}

#[derive(Debug)]
pub struct ResourceBudget {
    slot_process: [AtomicU64; SlotKind::COUNT],
    slot_clients: Mutex<HashMap<IpAddr, [u64; SlotKind::COUNT]>>,
    byte_process: [AtomicU64; ByteKind::COUNT],
    byte_clients: Mutex<HashMap<IpAddr, [u64; ByteKind::COUNT]>>,
    physical_process: [AtomicU64; PhysicalKind::COUNT],
    physical_limits: [u64; PhysicalKind::COUNT],
    disk_bytes: AtomicU64,
    disk_files: AtomicU64,
    disk_byte_limit: u64,
    disk_file_limit: u64,
    disk_ledgers: Mutex<DiskLedgers>,
    transport_bytes: AtomicU64,
    transport_byte_limit: u64,
    rates: Mutex<RateLedger>,
    next_scope: AtomicU64,
}

/// Complete process-ledger state used by deterministic transition campaigns.
/// Comparing snapshots before and after an injected failure catches leaks in
/// typed pools as well as their aggregate descriptor/task/memory parents.
#[cfg(any(test, feature = "fault-injection"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionResourceSnapshot {
    slots: [u64; SlotKind::COUNT],
    bytes: [u64; ByteKind::COUNT],
    physical: [u64; PhysicalKind::COUNT],
    disk_bytes: u64,
    disk_files: u64,
    filesystem_bytes: u64,
    filesystem_files: u64,
    transport_bytes: u64,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        let physical_limits = detected_physical_limits();
        Self {
            slot_process: std::array::from_fn(|_| AtomicU64::new(0)),
            slot_clients: Mutex::new(HashMap::new()),
            byte_process: std::array::from_fn(|_| AtomicU64::new(0)),
            byte_clients: Mutex::new(HashMap::new()),
            physical_process: std::array::from_fn(|_| AtomicU64::new(0)),
            physical_limits,
            disk_bytes: AtomicU64::new(0),
            disk_files: AtomicU64::new(0),
            disk_byte_limit: DEFAULT_DISK_BYTE_BUDGET,
            disk_file_limit: DEFAULT_DISK_FILE_BUDGET,
            disk_ledgers: Mutex::new(DiskLedgers::default()),
            transport_bytes: AtomicU64::new(0),
            transport_byte_limit: DEFAULT_TRANSPORT_BUFFER_BUDGET,
            rates: Mutex::new(RateLedger::default()),
            next_scope: AtomicU64::new(1),
        }
    }
}

/// Process-wide ceilings for work whose callers do not carry a `Config`
/// reference (PCRE expression evaluation, password hashing and compression).
/// Keeping this separate from request-worker admission prevents HTTP/2 from
/// multiplying expensive work by its per-connection stream allowance.
pub const MAX_EXPENSIVE_OPS: u64 = 32;
pub const MAX_EXPENSIVE_OPS_PER_CLIENT: u64 = 8;
pub const MAX_DYNAMIC_REQUESTS_PER_CLIENT: u64 = 8;
pub const MAX_RESPONSE_BODY_READS: u64 = 32;
pub const MAX_RESPONSE_BODY_READS_PER_CLIENT: u64 = 8;
pub const MAX_H2_STREAMS: u64 = 256;
pub const MAX_H2_STREAMS_PER_CLIENT: u64 = 64;
/// Request-body-blocked HTTP/2 streams leave the general dispatch pool and
/// enter this smaller source-fair pool. A peer that withholds DATA can retain
/// only this reserve, rather than every stream needed by unrelated clients.
pub const MAX_SLOW_INPUTS: u64 = 128;
/// Allow one complete advertised 32-stream connection per source while
/// preventing a small set of addresses from owning the entire reserve.
pub const MAX_SLOW_INPUTS_PER_CLIENT: u64 = 32;
/// Flow-control-blocked outputs leave the general stream pool and enter this
/// smaller source-fair pool. A handful of slow peers can therefore retain
/// their responses without denying dispatch capacity to unrelated clients.
pub const MAX_SLOW_OUTPUTS: u64 = 128;
/// Preserve a complete advertised 32-stream connection for a legitimate slow
/// client while preventing one address from owning more than one quarter of
/// the process reserve.
pub const MAX_SLOW_OUTPUTS_PER_CLIENT: u64 = 32;
/// Once output becomes downstream-bound, require useful aggregate progress
/// from the original response start and impose a non-renewable lifetime.
/// Protocol adapters choose the interval (normally max(Timeout, 5s)) but do
/// not get to weaken these shared invariants.
pub const SLOW_OUTPUT_MIN_RATE: u64 = 1024;
pub const SLOW_OUTPUT_MAX_INTERVALS: u32 = 16;
pub const MAX_REQUEST_RESIDENT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_RESPONSE_RESIDENT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_REQUEST_RESIDENT_BYTES_PER_CLIENT: u64 = 32 * 1024 * 1024;
pub const MAX_REQUEST_RESIDENT_BYTES_PER_REQUEST: u64 = 8 * 1024 * 1024;
/// One network identity may retain at most one quarter of the response heap
/// while downstream clients consume it. This prevents a handful of slow
/// responses from turning the process-wide memory safety bound into a global
/// availability oracle.
pub const MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT: u64 = 32 * 1024 * 1024;
pub const MAX_RESPONSE_RESIDENT_BYTES_PER_REQUEST: u64 = 32 * 1024 * 1024;
pub const MAX_WEBSOCKET_TUNNELS: u64 = 64;
pub const MAX_WEBSOCKETS_PER_CLIENT: u64 = 8;
// These are runaway-work ceilings, not ordinary traffic shaping. Keep them
// above measured same-host static throughput so the security boundary does
// not impose a benchmark or CDN/NAT bottleneck.
pub const MAX_REQUESTS_PER_SECOND: u64 = 2_000_000;
pub const MAX_REQUESTS_PER_CLIENT_PER_SECOND: u64 = 500_000;
pub const MAX_REQUEST_HEADS_PER_SECOND: u64 = 2_000_000;
pub const MAX_REQUEST_HEADS_PER_CLIENT_PER_SECOND: u64 = 500_000;
pub const MAX_EXPENSIVE_OPS_PER_SECOND: u64 = 256;
pub const MAX_EXPENSIVE_OPS_PER_CLIENT_PER_SECOND: u64 = 64;
pub const MAX_CACHE_WRITE_UNITS_PER_SECOND: u64 = 64 * 1024 * 1024;
pub const MAX_CACHE_WRITE_UNITS_PER_CLIENT_PER_SECOND: u64 = 16 * 1024 * 1024;
pub const MAX_LOG_BYTES_PER_SECOND: u64 = 16 * 1024 * 1024;
pub const MAX_LOG_BYTES_PER_CLIENT_PER_SECOND: u64 = 2 * 1024 * 1024;
const CACHE_WRITE_MIN_CHARGE: u64 = 64 * 1024;
const DEFAULT_TASK_BUDGET: u64 = 1_024;
const DEFAULT_RESIDENT_BUDGET: u64 = 256 * 1024 * 1024;
const DEFAULT_DISK_BYTE_BUDGET: u64 = 4 * 1024 * 1024 * 1024;
const DEFAULT_DISK_FILE_BUDGET: u64 = 16 * 1024;
const DEFAULT_TRANSPORT_BUFFER_BUDGET: u64 = 256 * 1024 * 1024;
/// Conservative ownership charge for the kernel send/receive queues and the
/// protocol/TLS buffers associated with one accepted transport.
pub(crate) const TRANSPORT_BUFFER_CHARGE: u64 = 512 * 1024;
pub(crate) const SOCKET_BUFFER_BYTES: usize = 128 * 1024;

pub(crate) fn configure_transport_fd(fd: impl AsFd) -> io::Result<()> {
    rustix::net::sockopt::set_socket_send_buffer_size(&fd, SOCKET_BUFFER_BYTES)
        .map_err(io::Error::from)?;
    rustix::net::sockopt::set_socket_recv_buffer_size(&fd, SOCKET_BUFFER_BYTES)
        .map_err(io::Error::from)?;
    Ok(())
}

fn bounded_system_limit(path: &str, fallback: u64) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

fn process_open_file_limit() -> u64 {
    std::fs::read_to_string("/proc/self/limits")
        .ok()
        .and_then(|limits| {
            limits.lines().find_map(|line| {
                line.strip_prefix("Max open files")?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
        })
        .unwrap_or(1_024)
}

fn detected_physical_limits() -> [u64; PhysicalKind::COUNT] {
    let nofile = process_open_file_limit();
    // Retain at least one quarter for listeners, logs, libraries, reloads and
    // administrator access. Never raise a deliberately tiny kernel limit.
    let fd = nofile.saturating_mul(3).saturating_div(4).max(1);

    let pids = bounded_system_limit("/sys/fs/cgroup/pids.max", DEFAULT_TASK_BUDGET);
    let tasks = pids
        .saturating_mul(3)
        .saturating_div(4)
        .min(DEFAULT_TASK_BUDGET)
        .max(1);

    let cgroup_memory = bounded_system_limit("/sys/fs/cgroup/memory.max", u64::MAX);
    let memory = cgroup_memory
        .saturating_div(4)
        .min(DEFAULT_RESIDENT_BUDGET)
        .max(1);
    [fd, tasks, memory]
}

fn existing_filesystem_path(path: &Path) -> io::Result<PathBuf> {
    let absolute;
    let mut candidate = if path.is_absolute() {
        path
    } else {
        absolute = std::env::current_dir()?.join(path);
        &absolute
    };
    loop {
        match std::fs::metadata(candidate) {
            Ok(_) => return Ok(candidate.to_path_buf()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                candidate = candidate.parent().ok_or(error)?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn detected_disk_target(path: &Path) -> io::Result<(u64, u64, u64)> {
    let existing = existing_filesystem_path(path)?;
    // Bind identity and capacity to one opened object. A concurrent rename or
    // mount change cannot pair one filesystem's `st_dev` with another one's
    // free-space limits.
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(existing)?;
    let device = opened.metadata()?.dev();
    let stats = rustix::fs::fstatvfs(&opened).map_err(io::Error::from)?;
    let available_bytes = stats.f_bavail.saturating_mul(stats.f_frsize);
    let available_files = stats.f_favail;
    // Retain one quarter of the observed free filesystem for the operating
    // system, administrator recovery, and unrelated services. The hard caps
    // also keep a very large filesystem from turning configured log/spool
    // ceilings into an unexpectedly large aggregate allowance.
    Ok((
        device,
        available_bytes
            .saturating_mul(3)
            .saturating_div(4)
            .min(DEFAULT_DISK_BYTE_BUDGET)
            .max(1),
        available_files
            .saturating_mul(3)
            .saturating_div(4)
            .min(DEFAULT_DISK_FILE_BUDGET)
            .max(1),
    ))
}

const fn slot_physical_charge(kind: SlotKind) -> [u64; PhysicalKind::COUNT] {
    use SlotKind::*;
    match kind {
        // Pending, H1 and H2 connection leases are alternate ownership phases
        // of one accepted socket. A short overlap during transfer is covered by
        // the reserved descriptor/task headroom. Resident charges cover
        // protocol state and conservative stack/allocator overhead that is not
        // represented by an explicit byte lease.
        PendingConnection => [0, 1, 32 * 1024],
        H1Connection => [0, 1, 64 * 1024],
        RequestWorker => [0, 1, 512 * 1024],
        H2Connection => [0, 1, 256 * 1024],
        H2Stream | SlowInput | SlowOutput => [0, 1, 128 * 1024],
        ResponseBodyRead => [0, 1, 64 * 1024],
        // A dynamic request may own an upstream socket or the CGI stdin/stdout/
        // stderr pipes, plus bounded helper work.
        DynamicBackend => [0, 2, 256 * 1024],
        Websocket => [1, 0, 64 * 1024],
        RewriteProgram => [3, 1, 128 * 1024],
        SpoolFile | SlowSpoolFile | FilesystemWork => [0, 0, 0],
        TlsHandshake => [0, 0, 128 * 1024],
        RequestBodyWorker | ExpensiveCpu => [0, 0, 0],
    }
}

const fn byte_physical_kind(kind: ByteKind) -> Option<PhysicalKind> {
    match kind {
        ByteKind::RequestResident
        | ByteKind::ResponseResident
        | ByteKind::SlowResponseResident
        | ByteKind::PolicyExpansion
        | ByteKind::CacheResident => Some(PhysicalKind::ResidentMemory),
        ByteKind::Spool | ByteKind::SlowSpool => None,
    }
}
/// Per-request ceiling for configuration-policy work.  One unit represents
/// one byte/cell inspected by a matcher or one constant-cost policy
/// instruction.  The budget is shared by every clone and every internal
/// rewrite of the same request, so splitting work across sections or phases
/// cannot reset it.
pub const MAX_POLICY_WORK_UNITS: u64 = 16 * 1024 * 1024;
/// Aggregate bytes materialized by request-controlled configuration
/// expansion (`SetEnvIf`, dynamic `Require` operands, and related policy
/// values).  This is deliberately aligned with the expression evaluator's
/// existing four-MiB aggregate limit.
pub const MAX_POLICY_EXPANSION_BYTES: u64 = 4 * 1024 * 1024;
/// No single configuration expansion may monopolize the aggregate budget.
pub const MAX_POLICY_VALUE_BYTES: u64 = 1024 * 1024;
/// Process-wide reservation for request-controlled policy values retained by
/// live requests. The per-request limit alone allowed many concurrent
/// requests to multiply resident configuration-expansion memory.
pub const MAX_POLICY_RESIDENT_BYTES: u64 = 128 * 1024 * 1024;

/// Monotonic request-local accounting for attacker-influenced policy work.
/// `Request` clones share this object through `Headers`, including internal
/// rewrites and the HTTP/2 adapter.
#[derive(Debug)]
pub struct RequestPolicyBudget {
    work: AtomicU64,
    expansion_bytes: AtomicU64,
    expansion_lease: Mutex<Option<ByteLease>>,
    context: Mutex<Option<ResourceContext>>,
    failed: AtomicBool,
}

impl Default for RequestPolicyBudget {
    fn default() -> Self {
        Self {
            work: AtomicU64::new(0),
            expansion_bytes: AtomicU64::new(0),
            expansion_lease: Mutex::new(None),
            context: Mutex::new(None),
            failed: AtomicBool::new(false),
        }
    }
}

impl RequestPolicyBudget {
    pub(crate) fn bind_context(&self, context: ResourceContext) {
        let mut bound = self
            .context
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if bound.is_none() {
            *bound = Some(context);
        }
    }

    pub fn charge_work(&self, amount: u64) -> Result<(), &'static str> {
        if self.failed.load(Ordering::Acquire) {
            return Err("request policy work limit exceeded");
        }
        if !try_add(&self.work, amount, MAX_POLICY_WORK_UNITS) {
            self.failed.store(true, Ordering::Release);
            return Err("request policy work limit exceeded");
        }
        Ok(())
    }

    pub fn charge_expansion(&self, amount: u64) -> Result<(), &'static str> {
        if self.failed.load(Ordering::Acquire) {
            return Err("request policy expansion limit exceeded");
        }
        if amount > MAX_POLICY_VALUE_BYTES {
            self.failed.store(true, Ordering::Release);
            return Err("request policy expansion limit exceeded");
        }
        if !try_add(&self.expansion_bytes, amount, MAX_POLICY_EXPANSION_BYTES) {
            self.failed.store(true, Ordering::Release);
            return Err("request policy expansion limit exceeded");
        }
        let context = self
            .context
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
            .or_else(current_context);
        #[cfg(test)]
        let context = context.unwrap_or_else(|| current_or_test_context());
        #[cfg(not(test))]
        let Some(context) = context
        else {
            self.expansion_bytes.fetch_sub(amount, Ordering::AcqRel);
            self.failed.store(true, Ordering::Release);
            return Err("policy expansion has no resource context");
        };
        let mut lease = self
            .expansion_lease
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if lease.is_none() {
            *lease = Some(ByteLease::new(
                context,
                ByteKind::PolicyExpansion,
                MAX_POLICY_RESIDENT_BYTES,
                Some(MAX_POLICY_RESIDENT_BYTES / 4),
                Some(MAX_POLICY_EXPANSION_BYTES),
            ));
        }
        if lease
            .as_mut()
            .expect("policy expansion lease initialized")
            .reserve(amount, "hierarchical policy-expansion byte limit reached")
            .is_err()
        {
            self.expansion_bytes.fetch_sub(amount, Ordering::AcqRel);
            self.failed.store(true, Ordering::Release);
            return Err("process policy expansion limit exceeded");
        }
        Ok(())
    }

    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn charged_work(&self) -> u64 {
        self.work.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn charged_expansion(&self) -> u64 {
        self.expansion_bytes.load(Ordering::Acquire)
    }
}

/// Collapse IPv6 interface identifiers into their /64 allocation while
/// retaining exact IPv4 identities. IPv4-mapped IPv6 is canonicalized first.
pub fn client_quota_key(client: IpAddr) -> IpAddr {
    match crate::access::canonical_ip(client) {
        IpAddr::V4(ip) => IpAddr::V4(ip),
        IpAddr::V6(ip) => IpAddr::V6(std::net::Ipv6Addr::from(
            vapache_verified::client_quota_ipv6_key(u128::from(ip)),
        )),
    }
}

/// Validated resource identity for one request or pre-request connection
/// phase. Clones share the request-local ledger, so internal rewrites and
/// helper calls cannot reset request ceilings.
#[derive(Clone, Debug)]
pub struct ResourceContext {
    budget: Arc<ResourceBudget>,
    client: Option<IpAddr>,
    scope_id: u64,
    local: Arc<ScopeUsage>,
}

impl ResourceContext {
    pub fn for_client(budget: &Arc<ResourceBudget>, client: IpAddr) -> Self {
        let scope_id = budget.next_scope.fetch_add(1, Ordering::Relaxed);
        Self {
            budget: budget.clone(),
            client: Some(client_quota_key(client)),
            scope_id,
            local: Arc::new(ScopeUsage::default()),
        }
    }

    fn process_only(budget: &Arc<ResourceBudget>) -> Self {
        let scope_id = budget.next_scope.fetch_add(1, Ordering::Relaxed);
        Self {
            budget: budget.clone(),
            client: None,
            scope_id,
            local: Arc::new(ScopeUsage::default()),
        }
    }

    pub fn client(&self) -> Option<IpAddr> {
        self.client
    }

    pub fn scope_id(&self) -> u64 {
        self.scope_id
    }

    pub fn budget(&self) -> &Arc<ResourceBudget> {
        &self.budget
    }

    pub(crate) fn slot(
        &self,
        kind: SlotKind,
        process_limit: u64,
        client_limit: Option<u64>,
        request_limit: Option<u64>,
        message: &'static str,
    ) -> io::Result<SlotLease> {
        self.budget.try_slot(
            self,
            kind,
            process_limit,
            client_limit,
            request_limit,
            message,
        )
    }
}

#[derive(Debug)]
struct RequestScopeState {
    cancelled: AtomicBool,
}

/// Explicit lifetime and cancellation authority for one externally admitted
/// request.  Clones carried by internal rewrites share both the hierarchical
/// resource ledger and cancellation state.
#[derive(Clone, Debug)]
pub struct RequestScope {
    context: ResourceContext,
    state: Arc<RequestScopeState>,
}

impl RequestScope {
    pub fn new(context: ResourceContext) -> Self {
        Self {
            context,
            state: Arc::new(RequestScopeState {
                cancelled: AtomicBool::new(false),
            }),
        }
    }

    pub fn context(&self) -> &ResourceContext {
        &self.context
    }

    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    pub fn cancel(&self) {
        self.state.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn guard(&self) -> RequestScopeGuard {
        RequestScopeGuard {
            scope: self.clone(),
        }
    }
}

/// Cancels child work on every request exit, including parse/dispatch/write
/// errors. Resource leases remain ordinary RAII values owned by the request.
pub(crate) struct RequestScopeGuard {
    scope: RequestScope,
}

impl Drop for RequestScopeGuard {
    fn drop(&mut self) {
        self.scope.cancel();
    }
}

thread_local! {
    static CURRENT_CONTEXT: RefCell<Option<ResourceContext>> = const { RefCell::new(None) };
}

/// Thread-bound scope guard for synchronous protocol paths that need to make
/// several helper calls before they enter ordinary request dispatch.
pub(crate) struct ResourceContextGuard {
    previous: Option<ResourceContext>,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for ResourceContextGuard {
    fn drop(&mut self) {
        CURRENT_CONTEXT.with(|current| {
            current.replace(self.previous.take());
        });
    }
}

pub(crate) fn enter_resource_context(context: ResourceContext) -> ResourceContextGuard {
    let previous = CURRENT_CONTEXT.with(|current| current.replace(Some(context)));
    ResourceContextGuard {
        previous,
        _thread_bound: std::marker::PhantomData,
    }
}

pub fn with_resource_context<T>(context: ResourceContext, operation: impl FnOnce() -> T) -> T {
    let _guard = enter_resource_context(context);
    operation()
}

pub(crate) fn current_context() -> Option<ResourceContext> {
    CURRENT_CONTEXT.with(|current| current.borrow().clone())
}

#[cfg(test)]
fn test_context(client: IpAddr) -> ResourceContext {
    static BUDGET: std::sync::OnceLock<Arc<ResourceBudget>> = std::sync::OnceLock::new();
    ResourceContext::for_client(
        BUDGET.get_or_init(|| Arc::new(ResourceBudget::default())),
        client,
    )
}

#[cfg(test)]
pub(crate) fn current_or_test_context() -> ResourceContext {
    current_context().unwrap_or_else(|| test_context(IpAddr::from([127, 0, 0, 1])))
}

/// Compatibility wrapper for request dispatch call sites while they migrate
/// to carrying the complete context. Unlike the old implementation, the
/// thread-local value is the sealed hierarchical context, not merely an IP
/// hint that each resource pool may interpret differently.
pub fn with_expensive_client<T>(client: IpAddr, operation: impl FnOnce() -> T) -> T {
    if let Some(current) = current_context() {
        if current.client == Some(client_quota_key(client)) {
            return operation();
        }
        let context = ResourceContext::for_client(&current.budget, client);
        return with_resource_context(context, operation);
    }
    #[cfg(test)]
    {
        return with_resource_context(test_context(client), operation);
    }
    #[cfg(not(test))]
    operation()
}

pub(crate) fn current_expensive_client() -> Option<IpAddr> {
    current_context().and_then(|context| context.client)
}

fn try_add(counter: &AtomicU64, amount: u64, limit: u64) -> bool {
    try_add_counter(counter, amount, limit)
}

/// Small abstraction over the atomic operation used by the production
/// budget.  Keeping the admission loop generic lets the exact production
/// algorithm run under Loom's deterministic scheduler in tests.
trait BudgetCounter {
    fn load_value(&self, order: Ordering) -> u64;
    fn compare_exchange_value(
        &self,
        current: u64,
        next: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64>;
}

impl BudgetCounter for AtomicU64 {
    fn load_value(&self, order: Ordering) -> u64 {
        self.load(order)
    }

    fn compare_exchange_value(
        &self,
        current: u64,
        next: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.compare_exchange_weak(current, next, success, failure)
    }
}

#[cfg(test)]
impl BudgetCounter for loom::sync::atomic::AtomicU64 {
    fn load_value(&self, order: Ordering) -> u64 {
        self.load(order)
    }

    fn compare_exchange_value(
        &self,
        current: u64,
        next: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.compare_exchange_weak(current, next, success, failure)
    }
}

fn try_add_counter<C: BudgetCounter>(counter: &C, amount: u64, limit: u64) -> bool {
    let mut current = counter.load_value(Ordering::Acquire);
    loop {
        if !vapache_verified::hierarchical_resource_admit(current, amount, limit) {
            return false;
        }
        let Some(next) = current.checked_add(amount) else {
            return false;
        };
        match counter.compare_exchange_value(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

/// Exact ownership permit for one open descriptor.  Slot weights describe
/// scheduler and memory pressure; descriptors are charged at the point the
/// kernel object is actually acquired so ownership transfers cannot double
/// count (or silently omit) the same socket/file.
#[derive(Debug)]
pub(crate) struct DescriptorLease {
    budget: Arc<ResourceBudget>,
    amount: u64,
}

/// Exact ownership of attacker-influenced persistent/spooled filesystem
/// capacity. Bytes and directory entries charge both the process-generation
/// parent and the child ledger for the filesystem that owns the target.
#[derive(Debug)]
pub(crate) struct DiskLease {
    budget: Arc<ResourceBudget>,
    ledger: Arc<DiskLedger>,
    bytes: u64,
    files: u64,
}

impl DiskLease {
    pub(crate) fn reserve(&mut self, amount: u64) -> io::Result<()> {
        self.resize(self.bytes.saturating_add(amount), self.files)
    }

    pub(crate) fn release(&mut self, amount: u64) {
        let _ = self.resize(self.bytes.saturating_sub(amount), self.files);
    }

    pub(crate) fn resize(&mut self, bytes: u64, files: u64) -> io::Result<()> {
        let add_bytes = bytes.saturating_sub(self.bytes);
        let add_files = files.saturating_sub(self.files);
        if add_bytes > 0 {
            if !try_add(
                &self.budget.disk_bytes,
                add_bytes,
                self.budget.disk_byte_limit,
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "aggregate writable-disk byte limit reached",
                ));
            }
            if !try_add(&self.ledger.bytes, add_bytes, self.ledger.byte_limit) {
                self.budget
                    .disk_bytes
                    .fetch_sub(add_bytes, Ordering::AcqRel);
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    format!(
                        "writable-disk byte limit reached for filesystem {}",
                        self.ledger.device
                    ),
                ));
            }
        }
        if add_files > 0 {
            if !try_add(
                &self.budget.disk_files,
                add_files,
                self.budget.disk_file_limit,
            ) {
                if add_bytes > 0 {
                    self.ledger.bytes.fetch_sub(add_bytes, Ordering::AcqRel);
                    self.budget
                        .disk_bytes
                        .fetch_sub(add_bytes, Ordering::AcqRel);
                }
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "aggregate writable-disk inode limit reached",
                ));
            }
            if !try_add(&self.ledger.files, add_files, self.ledger.file_limit) {
                self.budget
                    .disk_files
                    .fetch_sub(add_files, Ordering::AcqRel);
                if add_bytes > 0 {
                    self.ledger.bytes.fetch_sub(add_bytes, Ordering::AcqRel);
                    self.budget
                        .disk_bytes
                        .fetch_sub(add_bytes, Ordering::AcqRel);
                }
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    format!(
                        "writable-disk inode limit reached for filesystem {}",
                        self.ledger.device
                    ),
                ));
            }
        }
        if bytes < self.bytes {
            self.ledger
                .bytes
                .fetch_sub(self.bytes - bytes, Ordering::AcqRel);
            self.budget
                .disk_bytes
                .fetch_sub(self.bytes - bytes, Ordering::AcqRel);
        }
        if files < self.files {
            self.ledger
                .files
                .fetch_sub(self.files - files, Ordering::AcqRel);
            self.budget
                .disk_files
                .fetch_sub(self.files - files, Ordering::AcqRel);
        }
        self.bytes = bytes;
        self.files = files;
        Ok(())
    }
}

impl Drop for DiskLease {
    fn drop(&mut self) {
        self.ledger.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        self.ledger.files.fetch_sub(self.files, Ordering::AcqRel);
        self.budget
            .disk_bytes
            .fetch_sub(self.bytes, Ordering::AcqRel);
        self.budget
            .disk_files
            .fetch_sub(self.files, Ordering::AcqRel);
    }
}

#[derive(Debug)]
pub(crate) struct TransportBufferLease {
    budget: Arc<ResourceBudget>,
    bytes: u64,
}

impl Drop for TransportBufferLease {
    fn drop(&mut self) {
        self.budget
            .transport_bytes
            .fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResourceTelemetry {
    pub disk_bytes: u64,
    pub disk_byte_limit: u64,
    pub disk_files: u64,
    pub disk_file_limit: u64,
    pub disk_filesystems: u64,
    pub disk_min_byte_headroom: u64,
    pub disk_min_file_headroom: u64,
    pub transport_bytes: u64,
    pub transport_byte_limit: u64,
}

impl Drop for DescriptorLease {
    fn drop(&mut self) {
        self.budget
            .release_physical_one(PhysicalKind::FileDescriptor, self.amount);
    }
}

#[derive(Debug)]
pub(crate) struct SlotLease {
    context: ResourceContext,
    kind: SlotKind,
    amount: u64,
    process_limit: u64,
    charged_client: bool,
    charged_request: bool,
    client_limit: Option<u64>,
    request_limit: Option<u64>,
    physical: [u64; PhysicalKind::COUNT],
    active: bool,
}

impl SlotLease {
    fn attribute_context(&mut self, context: ResourceContext) -> io::Result<()> {
        if !Arc::ptr_eq(&self.context.budget, &context.budget) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource context belongs to another process ledger",
            ));
        }
        if self.context.scope_id == context.scope_id {
            return Ok(());
        }
        let index = self.kind.index();
        let target_request = if let Some(limit) = self.request_limit {
            if !try_add(&context.local.slots[index], self.amount, limit) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "request-local slot limit reached",
                ));
            }
            true
        } else {
            false
        };
        let mut clients = self
            .context
            .budget
            .slot_clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let unchanged_client = self.charged_client
            && self.context.client.is_some()
            && self.context.client == context.client;
        let target_client = if unchanged_client {
            true
        } else if let (Some(client), Some(limit)) = (context.client, self.client_limit) {
            let usage = clients.entry(client).or_insert([0; SlotKind::COUNT]);
            if !vapache_verified::hierarchical_resource_admit(usage[index], self.amount, limit) {
                if usage.iter().all(|value| *value == 0) {
                    clients.remove(&client);
                }
                if target_request {
                    context.local.slots[index].fetch_sub(self.amount, Ordering::AcqRel);
                }
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "per-client slot limit reached",
                ));
            }
            usage[index] += self.amount;
            true
        } else {
            false
        };
        if self.charged_client && !unchanged_client {
            if let Some(old) = self.context.client {
                if let Some(usage) = clients.get_mut(&old) {
                    usage[index] = usage[index].saturating_sub(self.amount);
                    if usage.iter().all(|value| *value == 0) {
                        clients.remove(&old);
                    }
                }
            }
        }
        drop(clients);
        if self.charged_request {
            self.context.local.slots[index].fetch_sub(self.amount, Ordering::AcqRel);
        }
        self.context = context;
        self.charged_client = target_client;
        self.charged_request = target_request;
        Ok(())
    }
}

impl Drop for SlotLease {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let index = self.kind.index();
        self.context.budget.slot_process[index].fetch_sub(self.amount, Ordering::AcqRel);
        self.context.budget.release_physical(self.physical);
        if self.charged_client {
            if let Some(client) = self.context.client {
                let mut clients = self
                    .context
                    .budget
                    .slot_clients
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if let Some(usage) = clients.get_mut(&client) {
                    usage[index] = usage[index].saturating_sub(self.amount);
                    if usage.iter().all(|value| *value == 0) {
                        clients.remove(&client);
                    }
                }
            }
        }
        if self.charged_request {
            self.context.local.slots[index].fetch_sub(self.amount, Ordering::AcqRel);
        }
        self.active = false;
    }
}

#[derive(Debug)]
struct ByteLease {
    context: ResourceContext,
    kind: ByteKind,
    bytes: u64,
    process_limit: u64,
    client_limit: Option<u64>,
    request_limit: Option<u64>,
}

impl ByteLease {
    fn new(
        context: ResourceContext,
        kind: ByteKind,
        process_limit: u64,
        client_limit: Option<u64>,
        request_limit: Option<u64>,
    ) -> Self {
        Self {
            context,
            kind,
            bytes: 0,
            process_limit,
            client_limit,
            request_limit,
        }
    }

    fn reserve(&mut self, amount: u64, message: &'static str) -> io::Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let index = self.kind.index();
        let charged_request = if let Some(limit) = self.request_limit {
            if !try_add(&self.context.local.bytes[index], amount, limit) {
                return Err(io::Error::new(io::ErrorKind::OutOfMemory, message));
            }
            true
        } else {
            false
        };

        let mut clients = self
            .context
            .budget
            .byte_clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let charged_client =
            if let (Some(client), Some(limit)) = (self.context.client, self.client_limit) {
                let usage = clients.entry(client).or_insert([0; ByteKind::COUNT]);
                if !vapache_verified::hierarchical_resource_admit(usage[index], amount, limit) {
                    if usage.iter().all(|value| *value == 0) {
                        clients.remove(&client);
                    }
                    if charged_request {
                        self.context.local.bytes[index].fetch_sub(amount, Ordering::AcqRel);
                    }
                    return Err(io::Error::new(io::ErrorKind::OutOfMemory, message));
                }
                usage[index] += amount;
                true
            } else {
                false
            };

        if !try_add(
            &self.context.budget.byte_process[index],
            amount,
            self.process_limit,
        ) {
            if charged_client {
                if let Some(client) = self.context.client {
                    if let Some(usage) = clients.get_mut(&client) {
                        usage[index] = usage[index].saturating_sub(amount);
                        if usage.iter().all(|value| *value == 0) {
                            clients.remove(&client);
                        }
                    }
                }
            }
            drop(clients);
            if charged_request {
                self.context.local.bytes[index].fetch_sub(amount, Ordering::AcqRel);
            }
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, message));
        }
        if let Some(kind) = byte_physical_kind(self.kind) {
            if !self.context.budget.try_physical_one(kind, amount) {
                self.context.budget.byte_process[index].fetch_sub(amount, Ordering::AcqRel);
                if charged_client {
                    if let Some(client) = self.context.client {
                        if let Some(usage) = clients.get_mut(&client) {
                            usage[index] = usage[index].saturating_sub(amount);
                            if usage.iter().all(|value| *value == 0) {
                                clients.remove(&client);
                            }
                        }
                    }
                }
                drop(clients);
                if charged_request {
                    self.context.local.bytes[index].fetch_sub(amount, Ordering::AcqRel);
                }
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "aggregate resident-memory limit reached",
                ));
            }
        }
        drop(clients);
        self.bytes += amount;
        Ok(())
    }

    /// Move an existing charge between sibling logical pools without
    /// changing its physical-memory charge. The destination is admitted
    /// first; only then are the source counters released.
    fn transfer_kind(
        &mut self,
        kind: ByteKind,
        process_limit: u64,
        client_limit: Option<u64>,
        request_limit: Option<u64>,
        message: &'static str,
    ) -> io::Result<()> {
        if self.kind == kind {
            return Ok(());
        }
        debug_assert_eq!(byte_physical_kind(self.kind), byte_physical_kind(kind));
        let amount = self.bytes;
        if amount == 0 {
            self.kind = kind;
            self.process_limit = process_limit;
            self.client_limit = client_limit;
            self.request_limit = request_limit;
            return Ok(());
        }
        let old_index = self.kind.index();
        let new_index = kind.index();
        let charged_request = if let Some(limit) = request_limit {
            if !try_add(&self.context.local.bytes[new_index], amount, limit) {
                return Err(io::Error::new(io::ErrorKind::OutOfMemory, message));
            }
            true
        } else {
            false
        };

        let mut clients = self
            .context
            .budget
            .byte_clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let charged_client =
            if let (Some(client), Some(limit)) = (self.context.client, client_limit) {
                let usage = clients.entry(client).or_insert([0; ByteKind::COUNT]);
                if !vapache_verified::hierarchical_resource_admit(usage[new_index], amount, limit) {
                    if usage.iter().all(|value| *value == 0) {
                        clients.remove(&client);
                    }
                    if charged_request {
                        self.context.local.bytes[new_index].fetch_sub(amount, Ordering::AcqRel);
                    }
                    return Err(io::Error::new(io::ErrorKind::OutOfMemory, message));
                }
                usage[new_index] += amount;
                true
            } else {
                false
            };
        if !try_add(
            &self.context.budget.byte_process[new_index],
            amount,
            process_limit,
        ) {
            if charged_client {
                if let Some(client) = self.context.client {
                    if let Some(usage) = clients.get_mut(&client) {
                        usage[new_index] = usage[new_index].saturating_sub(amount);
                        if usage.iter().all(|value| *value == 0) {
                            clients.remove(&client);
                        }
                    }
                }
            }
            if charged_request {
                self.context.local.bytes[new_index].fetch_sub(amount, Ordering::AcqRel);
            }
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, message));
        }

        self.context.budget.byte_process[old_index].fetch_sub(amount, Ordering::AcqRel);
        if let (Some(client), Some(_)) = (self.context.client, self.client_limit) {
            if let Some(usage) = clients.get_mut(&client) {
                usage[old_index] = usage[old_index].saturating_sub(amount);
            }
        }
        drop(clients);
        if self.request_limit.is_some() {
            self.context.local.bytes[old_index].fetch_sub(amount, Ordering::AcqRel);
        }
        self.kind = kind;
        self.process_limit = process_limit;
        self.client_limit = client_limit;
        self.request_limit = request_limit;
        Ok(())
    }

    fn release(&mut self, amount: u64) {
        let amount = amount.min(self.bytes);
        if amount == 0 {
            return;
        }
        let index = self.kind.index();
        self.context.budget.byte_process[index].fetch_sub(amount, Ordering::AcqRel);
        if let Some(kind) = byte_physical_kind(self.kind) {
            self.context.budget.release_physical_one(kind, amount);
        }
        if let (Some(client), Some(_)) = (self.context.client, self.client_limit) {
            let mut clients = self
                .context
                .budget
                .byte_clients
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(usage) = clients.get_mut(&client) {
                usage[index] = usage[index].saturating_sub(amount);
                if usage.iter().all(|value| *value == 0) {
                    clients.remove(&client);
                }
            }
        }
        if self.request_limit.is_some() {
            self.context.local.bytes[index].fetch_sub(amount, Ordering::AcqRel);
        }
        self.bytes -= amount;
    }

    fn attribute_context(&mut self, context: ResourceContext) -> io::Result<()> {
        if !Arc::ptr_eq(&self.context.budget, &context.budget) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource context belongs to another process ledger",
            ));
        }
        if self.context.scope_id == context.scope_id {
            return Ok(());
        }
        if self.bytes == 0 {
            self.context = context;
            return Ok(());
        }
        let index = self.kind.index();
        if let Some(limit) = self.request_limit {
            if !try_add(&context.local.bytes[index], self.bytes, limit) {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "request-local byte limit reached",
                ));
            }
        }
        let mut clients = self
            .context
            .budget
            .byte_clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let unchanged_client = self.client_limit.is_some()
            && self.context.client.is_some()
            && self.context.client == context.client;
        if !unchanged_client {
            if let (Some(client), Some(limit)) = (context.client, self.client_limit) {
                let usage = clients.entry(client).or_insert([0; ByteKind::COUNT]);
                if !vapache_verified::hierarchical_resource_admit(usage[index], self.bytes, limit) {
                    if usage.iter().all(|value| *value == 0) {
                        clients.remove(&client);
                    }
                    if self.request_limit.is_some() {
                        context.local.bytes[index].fetch_sub(self.bytes, Ordering::AcqRel);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "per-client byte limit reached",
                    ));
                }
                usage[index] += self.bytes;
            }
            if let (Some(old), Some(_)) = (self.context.client, self.client_limit) {
                if let Some(usage) = clients.get_mut(&old) {
                    usage[index] = usage[index].saturating_sub(self.bytes);
                    if usage.iter().all(|value| *value == 0) {
                        clients.remove(&old);
                    }
                }
            }
        }
        drop(clients);
        if self.request_limit.is_some() {
            self.context.local.bytes[index].fetch_sub(self.bytes, Ordering::AcqRel);
        }
        self.context = context;
        Ok(())
    }
}

impl Drop for ByteLease {
    fn drop(&mut self) {
        self.release(self.bytes);
    }
}

impl ResourceBudget {
    fn disk_ledger_for_path(&self, path: &Path) -> io::Result<Arc<DiskLedger>> {
        {
            let ledgers = self
                .disk_ledgers
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(ledger) = ledgers.paths.get(path) {
                return Ok(ledger.clone());
            }
        }
        let (device, byte_limit, file_limit) = detected_disk_target(path)?;
        let mut ledgers = self
            .disk_ledgers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let ledger = ledgers
            .devices
            .entry(device)
            .or_insert_with(|| Arc::new(DiskLedger::new(device, byte_limit, file_limit)))
            .clone();
        ledgers.paths.insert(path.to_path_buf(), ledger.clone());
        Ok(ledger)
    }

    fn try_disk_on_ledger(
        self: &Arc<Self>,
        ledger: Arc<DiskLedger>,
        bytes: u64,
        files: u64,
    ) -> io::Result<DiskLease> {
        let mut lease = DiskLease {
            budget: self.clone(),
            ledger,
            bytes: 0,
            files: 0,
        };
        lease.resize(bytes, files)?;
        Ok(lease)
    }

    pub fn context(self: &Arc<Self>, client: IpAddr) -> ResourceContext {
        ResourceContext::for_client(self, client)
    }

    fn current_context_for(self: &Arc<Self>) -> io::Result<ResourceContext> {
        if let Some(context) =
            current_context().filter(|context| Arc::ptr_eq(&context.budget, self))
        {
            return Ok(context);
        }
        #[cfg(test)]
        {
            return Ok(ResourceContext::process_only(self));
        }
        #[cfg(not(test))]
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "request resource operation has no matching resource context",
        ))
    }

    fn try_physical_one(&self, kind: PhysicalKind, amount: u64) -> bool {
        try_add(
            &self.physical_process[kind.index()],
            amount,
            self.physical_limits[kind.index()],
        )
    }

    pub(crate) fn try_descriptor(self: &Arc<Self>) -> io::Result<DescriptorLease> {
        self.try_descriptors(1)
    }

    pub(crate) fn try_descriptors(self: &Arc<Self>, amount: u64) -> io::Result<DescriptorLease> {
        if !self.try_physical_one(PhysicalKind::FileDescriptor, amount) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "aggregate file-descriptor limit reached",
            ));
        }
        Ok(DescriptorLease {
            budget: self.clone(),
            amount,
        })
    }

    #[cfg(test)]
    fn try_disk(self: &Arc<Self>, bytes: u64, files: u64) -> io::Result<DiskLease> {
        self.try_disk_at(Path::new("."), bytes, files)
    }

    pub(crate) fn try_disk_at(
        self: &Arc<Self>,
        path: &Path,
        bytes: u64,
        files: u64,
    ) -> io::Result<DiskLease> {
        let ledger = self.disk_ledger_for_path(path)?;
        self.try_disk_on_ledger(ledger, bytes, files)
    }

    pub(crate) fn try_transport_buffers(self: &Arc<Self>) -> io::Result<TransportBufferLease> {
        if !try_add(
            &self.transport_bytes,
            TRANSPORT_BUFFER_CHARGE,
            self.transport_byte_limit,
        ) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "aggregate transport-buffer limit reached",
            ));
        }
        Ok(TransportBufferLease {
            budget: self.clone(),
            bytes: TRANSPORT_BUFFER_CHARGE,
        })
    }

    pub(crate) fn telemetry(&self) -> ResourceTelemetry {
        let ledgers = self
            .disk_ledgers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let disk_min_byte_headroom = ledgers
            .devices
            .values()
            .map(|ledger| {
                ledger
                    .byte_limit
                    .saturating_sub(ledger.bytes.load(Ordering::Acquire))
            })
            .min()
            .unwrap_or(self.disk_byte_limit);
        let disk_min_file_headroom = ledgers
            .devices
            .values()
            .map(|ledger| {
                ledger
                    .file_limit
                    .saturating_sub(ledger.files.load(Ordering::Acquire))
            })
            .min()
            .unwrap_or(self.disk_file_limit);
        ResourceTelemetry {
            disk_bytes: self.disk_bytes.load(Ordering::Acquire),
            disk_byte_limit: self.disk_byte_limit,
            disk_files: self.disk_files.load(Ordering::Acquire),
            disk_file_limit: self.disk_file_limit,
            disk_filesystems: ledgers.devices.len() as u64,
            disk_min_byte_headroom,
            disk_min_file_headroom,
            transport_bytes: self.transport_bytes.load(Ordering::Acquire),
            transport_byte_limit: self.transport_byte_limit,
        }
    }

    /// Hysteresis signals used by the listener loop.  Pausing before the hard
    /// ceiling leaves enough capacity for logs, reloads and accepted sockets
    /// already racing through admission; resumption at the lower watermark
    /// prevents poll/accept oscillation.
    pub(crate) fn listener_pressure_high(&self, pending_limit: u64, worker_limit: u64) -> bool {
        let fd_index = PhysicalKind::FileDescriptor.index();
        let descriptors = self.physical_process[fd_index].load(Ordering::Acquire);
        let descriptor_high = self.physical_limits[fd_index]
            .saturating_mul(9)
            .saturating_add(9)
            / 10;
        let pending = self.slot_usage(SlotKind::PendingConnection);
        let pending_high = pending_limit.saturating_mul(9).saturating_add(9) / 10;
        let workers = self.slot_usage(SlotKind::RequestWorker);
        // A full worker pool is not, by itself, a reason to stop accepting:
        // accepting one connection lets us return a bounded 503 instead of
        // leaving it parked indefinitely in the kernel backlog.  Pause only
        // once an admitted connection is already waiting behind that full
        // pool. This keeps the overload queue bounded while preserving prompt
        // failure for the first excess client.
        let worker_backlog = workers >= worker_limit.max(1) && pending > 0;
        descriptors >= descriptor_high.max(1) || pending >= pending_high.max(1) || worker_backlog
    }

    pub(crate) fn listener_pressure_below_low(
        &self,
        pending_limit: u64,
        worker_limit: u64,
    ) -> bool {
        let fd_index = PhysicalKind::FileDescriptor.index();
        let descriptors = self.physical_process[fd_index].load(Ordering::Acquire);
        let descriptor_low = self.physical_limits[fd_index].saturating_mul(3) / 4;
        let pending = self.slot_usage(SlotKind::PendingConnection);
        let pending_low = pending_limit.saturating_mul(3) / 4;
        let workers = self.slot_usage(SlotKind::RequestWorker);
        let worker_low = worker_limit.saturating_mul(3) / 4;
        let worker_backlog_cleared = pending == 0 || workers <= worker_low;
        descriptors <= descriptor_low && pending <= pending_low && worker_backlog_cleared
    }

    fn release_physical_one(&self, kind: PhysicalKind, amount: u64) {
        if amount > 0 {
            self.physical_process[kind.index()].fetch_sub(amount, Ordering::AcqRel);
        }
    }

    fn try_physical(&self, charge: [u64; PhysicalKind::COUNT]) -> bool {
        let mut admitted = 0usize;
        while admitted < PhysicalKind::COUNT {
            let amount = charge[admitted];
            if amount > 0
                && !try_add(
                    &self.physical_process[admitted],
                    amount,
                    self.physical_limits[admitted],
                )
            {
                for rollback in 0..admitted {
                    if charge[rollback] > 0 {
                        self.physical_process[rollback]
                            .fetch_sub(charge[rollback], Ordering::AcqRel);
                    }
                }
                return false;
            }
            admitted += 1;
        }
        true
    }

    fn release_physical(&self, charge: [u64; PhysicalKind::COUNT]) {
        for (index, amount) in charge.into_iter().enumerate() {
            if amount > 0 {
                self.physical_process[index].fetch_sub(amount, Ordering::AcqRel);
            }
        }
    }

    fn try_slot(
        self: &Arc<Self>,
        context: &ResourceContext,
        kind: SlotKind,
        process_limit: u64,
        client_limit: Option<u64>,
        request_limit: Option<u64>,
        message: &'static str,
    ) -> io::Result<SlotLease> {
        if !Arc::ptr_eq(self, &context.budget) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource context belongs to another process ledger",
            ));
        }
        let index = kind.index();
        let charged_request = if let Some(limit) = request_limit {
            if !try_add(&context.local.slots[index], 1, limit) {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, message));
            }
            true
        } else {
            false
        };

        let mut clients = self
            .slot_clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let charged_client = if let (Some(client), Some(limit)) = (context.client, client_limit) {
            let usage = clients.entry(client).or_insert([0; SlotKind::COUNT]);
            if !vapache_verified::hierarchical_resource_admit(usage[index], 1, limit) {
                if usage.iter().all(|value| *value == 0) {
                    clients.remove(&client);
                }
                if charged_request {
                    context.local.slots[index].fetch_sub(1, Ordering::AcqRel);
                }
                return Err(io::Error::new(io::ErrorKind::WouldBlock, message));
            }
            usage[index] += 1;
            true
        } else {
            false
        };

        // Request and client scopes are admitted before process scope. A
        // rejection can therefore never retain scarce global capacity while
        // it reports a lower-level quota failure.
        if !vapache_verified::hierarchical_acquisition_order_admit(
            !charged_request || request_limit.is_some(),
            !charged_client || client_limit.is_some(),
        ) || !try_add(&self.slot_process[index], 1, process_limit)
        {
            if charged_client {
                if let Some(client) = context.client {
                    if let Some(usage) = clients.get_mut(&client) {
                        usage[index] = usage[index].saturating_sub(1);
                        if usage.iter().all(|value| *value == 0) {
                            clients.remove(&client);
                        }
                    }
                }
            }
            drop(clients);
            if charged_request {
                context.local.slots[index].fetch_sub(1, Ordering::AcqRel);
            }
            return Err(io::Error::new(io::ErrorKind::WouldBlock, message));
        }
        let physical = slot_physical_charge(kind);
        if !self.try_physical(physical) {
            self.slot_process[index].fetch_sub(1, Ordering::AcqRel);
            if charged_client {
                if let Some(client) = context.client {
                    if let Some(usage) = clients.get_mut(&client) {
                        usage[index] = usage[index].saturating_sub(1);
                        if usage.iter().all(|value| *value == 0) {
                            clients.remove(&client);
                        }
                    }
                }
            }
            drop(clients);
            if charged_request {
                context.local.slots[index].fetch_sub(1, Ordering::AcqRel);
            }
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "aggregate physical resource limit reached",
            ));
        }
        drop(clients);
        Ok(SlotLease {
            context: context.clone(),
            kind,
            amount: 1,
            process_limit,
            charged_client,
            charged_request,
            client_limit,
            request_limit,
            physical,
            active: true,
        })
    }

    fn admit_rate_amount(
        window: &mut RateWindow,
        client: Option<IpAddr>,
        now: std::time::Instant,
        amount: u64,
        process_limit: u64,
        client_limit: u64,
    ) -> bool {
        if window.started.is_none_or(|start| {
            now.saturating_duration_since(start) >= std::time::Duration::from_secs(1)
        }) {
            window.started = Some(now);
            window.total = 0;
            window.clients.clear();
        }
        let client_used = client
            .and_then(|client| window.clients.get(&client).copied())
            .unwrap_or(0);
        if !vapache_verified::hierarchical_weighted_rate_admit(
            window.total,
            client_used,
            amount,
            process_limit,
            client_limit,
            client.is_some(),
        ) {
            return false;
        }
        window.total += amount;
        if let Some(client) = client {
            window.clients.insert(client, client_used + amount);
        }
        true
    }

    fn admit_rate(
        window: &mut RateWindow,
        client: Option<IpAddr>,
        now: std::time::Instant,
        process_limit: u64,
        client_limit: u64,
    ) -> bool {
        Self::admit_rate_amount(window, client, now, 1, process_limit, client_limit)
    }

    /// Charge one parsed request exactly once for its shared request scope.
    /// Internal rewrites and helper calls clone the same `ScopeUsage`, so they
    /// cannot multiply or reset the process/client rate gate.
    pub(crate) fn try_request_rate(&self, context: &ResourceContext) -> io::Result<()> {
        if !std::ptr::eq(self, Arc::as_ptr(&context.budget)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource context belongs to another process ledger",
            ));
        }
        if context
            .local
            .request_rate_admitted
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        let mut rates = self.rates.lock().unwrap_or_else(|error| error.into_inner());
        if !Self::admit_rate(
            &mut rates.request,
            context.client,
            std::time::Instant::now(),
            MAX_REQUESTS_PER_SECOND,
            MAX_REQUESTS_PER_CLIENT_PER_SECOND,
        ) {
            context
                .local
                .request_rate_admitted
                .store(false, Ordering::Release);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "request rate limit reached",
            ));
        }
        Ok(())
    }

    /// Bound work spent parsing HTTP/1 request heads, including malformed
    /// heads that never reach request admission. The transport peer is used
    /// because trusted forwarding headers are not available until parsing has
    /// completed.
    pub(crate) fn try_request_parse_rate(&self, client: IpAddr) -> io::Result<()> {
        let mut rates = self.rates.lock().unwrap_or_else(|error| error.into_inner());
        Self::admit_rate(
            &mut rates.request_parse,
            Some(client_quota_key(client)),
            std::time::Instant::now(),
            MAX_REQUEST_HEADS_PER_SECOND,
            MAX_REQUEST_HEADS_PER_CLIENT_PER_SECOND,
        )
        .then_some(())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "request-head parse rate limit reached",
            )
        })
    }

    pub(crate) fn try_cache_write(&self, context: &ResourceContext, bytes: u64) -> io::Result<()> {
        if !std::ptr::eq(self, Arc::as_ptr(&context.budget)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource context belongs to another process ledger",
            ));
        }
        let charge = bytes.max(CACHE_WRITE_MIN_CHARGE);
        let mut rates = self.rates.lock().unwrap_or_else(|error| error.into_inner());
        Self::admit_rate_amount(
            &mut rates.cache_write,
            context.client,
            std::time::Instant::now(),
            charge,
            MAX_CACHE_WRITE_UNITS_PER_SECOND,
            MAX_CACHE_WRITE_UNITS_PER_CLIENT_PER_SECOND,
        )
        .then_some(())
        .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "cache write rate limit reached"))
    }

    pub(crate) fn try_cache_resident(
        self: &Arc<Self>,
        context: &ResourceContext,
        limit: u64,
        bytes: u64,
    ) -> io::Result<CacheResidentLease> {
        if !Arc::ptr_eq(self, &context.budget) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource context belongs to another process ledger",
            ));
        }
        if limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "memory cache is disabled",
            ));
        }
        let mut lease = ByteLease::new(
            context.clone(),
            ByteKind::CacheResident,
            limit,
            Some(limit.saturating_add(3).saturating_div(4).max(1)),
            Some(limit),
        );
        lease.reserve(bytes, "hierarchical memory-cache limit reached")?;
        Ok(CacheResidentLease { bytes: lease })
    }

    pub(crate) fn try_log_bytes(&self, client: Option<IpAddr>, bytes: u64) -> bool {
        let mut rates = self.rates.lock().unwrap_or_else(|error| error.into_inner());
        Self::admit_rate_amount(
            &mut rates.log_bytes,
            client.map(client_quota_key),
            std::time::Instant::now(),
            bytes.max(1),
            MAX_LOG_BYTES_PER_SECOND,
            MAX_LOG_BYTES_PER_CLIENT_PER_SECOND,
        )
    }

    pub(crate) fn try_filesystem_work_in(
        self: &Arc<Self>,
        context: &ResourceContext,
    ) -> io::Result<SlotLease> {
        context.slot(
            SlotKind::FilesystemWork,
            64,
            Some(8),
            Some(1),
            "filesystem work limit reached",
        )
    }

    pub fn try_spool(self: &Arc<Self>, max_bytes: u64, max_files: u64) -> io::Result<SpoolLease> {
        let context = self.current_context_for()?;
        self.try_spool_inner(max_bytes, max_files, &context)
    }

    pub fn try_spool_for(
        self: &Arc<Self>,
        max_bytes: u64,
        max_files: u64,
        client: IpAddr,
    ) -> io::Result<SpoolLease> {
        let context = self.context(client);
        self.try_spool_inner(max_bytes, max_files, &context)
    }

    pub(crate) fn try_spool_in(
        self: &Arc<Self>,
        max_bytes: u64,
        max_files: u64,
        context: &ResourceContext,
    ) -> io::Result<SpoolLease> {
        self.try_spool_inner(max_bytes, max_files, context)
    }

    fn try_spool_inner(
        self: &Arc<Self>,
        max_bytes: u64,
        max_files: u64,
        context: &ResourceContext,
    ) -> io::Result<SpoolLease> {
        let descriptor = self.try_descriptor()?;
        let share_files = max_files.saturating_add(3) / 4;
        let file_slot = context.slot(
            SlotKind::SpoolFile,
            max_files,
            Some(share_files.max(1)),
            Some(share_files.max(1)),
            "spool-file limit reached",
        )?;
        let share_bytes = max_bytes.saturating_add(3) / 4;
        Ok(SpoolLease {
            bytes: ByteLease::new(
                context.clone(),
                ByteKind::Spool,
                max_bytes,
                Some(share_bytes.max(1)),
                Some(max_bytes.max(1)),
            ),
            file_slot: Some(file_slot),
            _descriptor: descriptor,
            disk: self.try_disk_at(&std::env::temp_dir(), 0, 1)?,
            slow: false,
        })
    }

    pub fn try_dynamic(self: &Arc<Self>, limit: u64) -> io::Result<DynamicLease> {
        let context = self.current_context_for()?;
        self.try_dynamic_in(&context, limit)
    }

    pub fn try_dynamic_for(
        self: &Arc<Self>,
        limit: u64,
        client: IpAddr,
    ) -> io::Result<DynamicLease> {
        let context = self.context(client);
        self.try_dynamic_in(&context, limit)
    }

    pub fn try_dynamic_in(
        self: &Arc<Self>,
        context: &ResourceContext,
        limit: u64,
    ) -> io::Result<DynamicLease> {
        self.try_dynamic_descriptors_in(context, limit, 4)
    }

    pub(crate) fn try_dynamic_descriptors_in(
        self: &Arc<Self>,
        context: &ResourceContext,
        limit: u64,
        descriptors: u64,
    ) -> io::Result<DynamicLease> {
        let slot = context.slot(
            SlotKind::DynamicBackend,
            limit,
            Some(limit.min(MAX_DYNAMIC_REQUESTS_PER_CLIENT)),
            Some(1),
            "dynamic backend concurrency limit reached",
        )?;
        let descriptor_lease = self.try_descriptors(descriptors)?;
        let transport_lease = self.try_transport_buffers()?;
        Ok(DynamicLease {
            _slot: Some(slot),
            _descriptors: descriptor_lease,
            _transport: transport_lease,
        })
    }

    /// Acquire the source-keyed quota before the process quota as one
    /// indivisible API operation. Keeping the individual helpers private
    /// prevents a future protocol caller from restoring P30's split-order
    /// failure mode.
    pub(crate) fn try_h2_stream_for(
        self: &Arc<Self>,
        client: IpAddr,
    ) -> io::Result<CombinedH2Lease> {
        let context = self.context(client);
        self.try_h2_stream_in(&context)
    }

    pub(crate) fn try_h2_stream_in(
        self: &Arc<Self>,
        context: &ResourceContext,
    ) -> io::Result<CombinedH2Lease> {
        Ok(CombinedH2Lease {
            _slot: context.slot(
                SlotKind::H2Stream,
                MAX_H2_STREAMS,
                Some(MAX_H2_STREAMS_PER_CLIENT),
                Some(1),
                "HTTP/2 stream limit reached",
            )?,
        })
    }

    pub(crate) fn try_slow_output_in(
        self: &Arc<Self>,
        context: &ResourceContext,
    ) -> io::Result<SlowOutputLease> {
        Ok(SlowOutputLease {
            _slot: context.slot(
                SlotKind::SlowOutput,
                MAX_SLOW_OUTPUTS,
                Some(MAX_SLOW_OUTPUTS_PER_CLIENT),
                Some(1),
                "slow-output limit reached",
            )?,
        })
    }

    pub(crate) fn try_slow_input_in(
        self: &Arc<Self>,
        context: &ResourceContext,
    ) -> io::Result<SlowInputLease> {
        Ok(SlowInputLease {
            _slot: context.slot(
                SlotKind::SlowInput,
                MAX_SLOW_INPUTS,
                Some(MAX_SLOW_INPUTS_PER_CLIENT),
                Some(1),
                "slow-input limit reached",
            )?,
        })
    }

    pub fn try_request_bytes(self: &Arc<Self>) -> io::Result<ResidentLease> {
        let context = self.current_context_for()?;
        Ok(ResidentLease::new(
            context,
            ResidentKind::Request,
            MAX_REQUEST_RESIDENT_BYTES,
            MAX_REQUEST_RESIDENT_BYTES_PER_CLIENT,
            MAX_REQUEST_RESIDENT_BYTES_PER_REQUEST,
        ))
    }

    pub fn try_request_bytes_for(self: &Arc<Self>, client: IpAddr) -> ResidentLease {
        ResidentLease::new(
            self.context(client),
            ResidentKind::Request,
            MAX_REQUEST_RESIDENT_BYTES,
            MAX_REQUEST_RESIDENT_BYTES_PER_CLIENT,
            MAX_REQUEST_RESIDENT_BYTES_PER_REQUEST,
        )
    }

    pub(crate) fn try_request_bytes_in(
        self: &Arc<Self>,
        context: &ResourceContext,
    ) -> io::Result<ResidentLease> {
        if !Arc::ptr_eq(self, &context.budget) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource context belongs to another process ledger",
            ));
        }
        Ok(ResidentLease::new(
            context.clone(),
            ResidentKind::Request,
            MAX_REQUEST_RESIDENT_BYTES,
            MAX_REQUEST_RESIDENT_BYTES_PER_CLIENT,
            MAX_REQUEST_RESIDENT_BYTES_PER_REQUEST,
        ))
    }

    pub fn try_response_bytes(self: &Arc<Self>) -> io::Result<ResidentLease> {
        let context = self.current_context_for()?;
        Ok(ResidentLease::new(
            context,
            ResidentKind::Response,
            MAX_RESPONSE_RESIDENT_BYTES,
            MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT,
            MAX_RESPONSE_RESIDENT_BYTES_PER_REQUEST,
        ))
    }

    pub fn try_response_bytes_for(self: &Arc<Self>, client: IpAddr) -> ResidentLease {
        ResidentLease::new(
            self.context(client),
            ResidentKind::Response,
            MAX_RESPONSE_RESIDENT_BYTES,
            MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT,
            MAX_RESPONSE_RESIDENT_BYTES_PER_REQUEST,
        )
    }

    pub(crate) fn try_response_bytes_in(
        self: &Arc<Self>,
        context: &ResourceContext,
    ) -> io::Result<ResidentLease> {
        if !Arc::ptr_eq(self, &context.budget) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource context belongs to another process ledger",
            ));
        }
        Ok(ResidentLease::new(
            context.clone(),
            ResidentKind::Response,
            MAX_RESPONSE_RESIDENT_BYTES,
            MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT,
            MAX_RESPONSE_RESIDENT_BYTES_PER_REQUEST,
        ))
    }

    /// Reserve one short blocking read of a response-body descriptor.
    ///
    /// This permit deliberately excludes request dispatch and downstream
    /// socket waits. Holding it across either boundary lets a client exhaust
    /// the read capacity without causing any read work (P30-A/A').
    pub fn try_response_body_read(self: &Arc<Self>) -> io::Result<ResponseBodyReadLease> {
        let context = self.current_context_for()?;
        self.try_response_body_read_in(&context)
    }

    pub fn try_response_body_read_for(
        self: &Arc<Self>,
        client: IpAddr,
    ) -> io::Result<ResponseBodyReadLease> {
        let context = self.context(client);
        self.try_response_body_read_in(&context)
    }

    pub fn try_response_body_read_in(
        self: &Arc<Self>,
        context: &ResourceContext,
    ) -> io::Result<ResponseBodyReadLease> {
        debug_assert!(vapache_verified::response_body_read_lease_admit(
            vapache_verified::ResponseWorkPhase::DescriptorRead,
        ));
        Ok(ResponseBodyReadLease {
            _slot: context.slot(
                SlotKind::ResponseBodyRead,
                MAX_RESPONSE_BODY_READS,
                Some(MAX_RESPONSE_BODY_READS_PER_CLIENT),
                Some(1),
                "response-body read limit reached",
            )?,
        })
    }

    pub fn try_websocket_for(self: &Arc<Self>, client: IpAddr) -> io::Result<WebsocketLease> {
        let context = self.context(client);
        Ok(WebsocketLease {
            _slot: context.slot(
                SlotKind::Websocket,
                MAX_WEBSOCKET_TUNNELS,
                Some(MAX_WEBSOCKETS_PER_CLIENT),
                Some(1),
                "WebSocket tunnel limit reached",
            )?,
        })
    }

    pub(crate) fn try_tls_handshake(
        self: &Arc<Self>,
        context: &ResourceContext,
        concurrency_limit: u64,
        process_rate_limit: u64,
        client_rate_limit: u64,
    ) -> io::Result<SlotLease> {
        let slot = context.slot(
            SlotKind::TlsHandshake,
            concurrency_limit,
            Some(concurrency_limit),
            Some(1),
            "TLS handshake concurrency limit reached",
        )?;
        let mut rates = self.rates.lock().unwrap_or_else(|error| error.into_inner());
        if !Self::admit_rate(
            &mut rates.tls,
            context.client,
            std::time::Instant::now(),
            process_rate_limit,
            client_rate_limit,
        ) {
            drop(slot);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TLS handshake rate limit reached",
            ));
        }
        Ok(slot)
    }

    pub(crate) fn try_rewrite_program(
        self: &Arc<Self>,
        context: &ResourceContext,
        concurrency_limit: u64,
        client_concurrency_limit: u64,
        process_rate_limit: u64,
        client_rate_limit: u64,
    ) -> io::Result<SlotLease> {
        let slot = context.slot(
            SlotKind::RewriteProgram,
            concurrency_limit,
            Some(client_concurrency_limit),
            Some(1),
            "rewrite program concurrency limit reached",
        )?;
        let mut rates = self.rates.lock().unwrap_or_else(|error| error.into_inner());
        if !Self::admit_rate(
            &mut rates.rewrite_program,
            context.client,
            std::time::Instant::now(),
            process_rate_limit,
            client_rate_limit,
        ) {
            drop(slot);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "rewrite program rate limit reached",
            ));
        }
        Ok(slot)
    }

    pub(crate) fn slot_usage(&self, kind: SlotKind) -> u64 {
        self.slot_process[kind.index()].load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn test_rate_admit(
        &self,
        rewrite_program: bool,
        client: Option<IpAddr>,
        now: std::time::Instant,
        process_limit: u64,
        client_limit: u64,
    ) -> bool {
        let mut rates = self.rates.lock().unwrap_or_else(|error| error.into_inner());
        let window = if rewrite_program {
            &mut rates.rewrite_program
        } else {
            &mut rates.tls
        };
        Self::admit_rate(
            window,
            client.map(client_quota_key),
            now,
            process_limit,
            client_limit,
        )
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn usage(&self) -> (u64, u64, u64) {
        (
            self.byte_process[ByteKind::Spool.index()]
                .load(Ordering::Acquire)
                .saturating_add(
                    self.byte_process[ByteKind::SlowSpool.index()].load(Ordering::Acquire),
                ),
            self.slot_usage(SlotKind::SpoolFile)
                .saturating_add(self.slot_usage(SlotKind::SlowSpoolFile)),
            self.slot_usage(SlotKind::DynamicBackend),
        )
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn extended_usage(&self) -> (u64, u64, u64, u64) {
        (
            self.slot_usage(SlotKind::H2Stream),
            self.byte_process[ByteKind::RequestResident.index()].load(Ordering::Acquire),
            self.byte_process[ByteKind::ResponseResident.index()]
                .load(Ordering::Acquire)
                .saturating_add(
                    self.byte_process[ByteKind::SlowResponseResident.index()]
                        .load(Ordering::Acquire),
                ),
            self.slot_usage(SlotKind::ResponseBodyRead),
        )
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn h2_output_usage(&self) -> (u64, u64) {
        (
            self.slot_usage(SlotKind::H2Stream),
            self.slot_usage(SlotKind::SlowOutput),
        )
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn h2_input_usage(&self) -> (u64, u64) {
        (
            self.slot_usage(SlotKind::H2Stream),
            self.slot_usage(SlotKind::SlowInput),
        )
    }

    #[cfg(test)]
    pub(crate) fn slow_output_resource_usage(&self) -> (u64, u64, u64, u64) {
        (
            self.slot_usage(SlotKind::SlowOutput),
            self.byte_process[ByteKind::SlowResponseResident.index()].load(Ordering::Acquire),
            self.slot_usage(SlotKind::SlowSpoolFile),
            self.byte_process[ByteKind::SlowSpool.index()].load(Ordering::Acquire),
        )
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn websocket_usage(&self) -> u64 {
        self.slot_usage(SlotKind::Websocket)
    }

    #[cfg(any(test, feature = "fault-injection"))]
    pub fn transition_snapshot(&self) -> TransitionResourceSnapshot {
        let ledgers = self
            .disk_ledgers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        TransitionResourceSnapshot {
            slots: std::array::from_fn(|index| self.slot_process[index].load(Ordering::Acquire)),
            bytes: std::array::from_fn(|index| self.byte_process[index].load(Ordering::Acquire)),
            physical: std::array::from_fn(|index| {
                self.physical_process[index].load(Ordering::Acquire)
            }),
            disk_bytes: self.disk_bytes.load(Ordering::Acquire),
            disk_files: self.disk_files.load(Ordering::Acquire),
            filesystem_bytes: ledgers
                .devices
                .values()
                .map(|ledger| ledger.bytes.load(Ordering::Acquire))
                .sum(),
            filesystem_files: ledgers
                .devices
                .values()
                .map(|ledger| ledger.files.load(Ordering::Acquire))
                .sum(),
            transport_bytes: self.transport_bytes.load(Ordering::Acquire),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ResidentKind {
    Request,
    Response,
}

#[derive(Debug)]
pub struct ResidentLease {
    kind: ResidentKind,
    bytes: ByteLease,
}

#[derive(Debug)]
pub(crate) struct CacheResidentLease {
    bytes: ByteLease,
}

impl CacheResidentLease {
    #[cfg(test)]
    fn bytes(&self) -> u64 {
        self.bytes.bytes
    }
}

impl ResidentLease {
    fn new(
        context: ResourceContext,
        kind: ResidentKind,
        process_limit: u64,
        client_limit: u64,
        request_limit: u64,
    ) -> Self {
        let byte_kind = match kind {
            ResidentKind::Request => ByteKind::RequestResident,
            ResidentKind::Response => ByteKind::ResponseResident,
        };
        Self {
            kind,
            bytes: ByteLease::new(
                context,
                byte_kind,
                process_limit,
                Some(client_limit),
                Some(request_limit),
            ),
        }
    }

    pub fn reserve(&mut self, amount: u64) -> io::Result<()> {
        self.bytes
            .reserve(amount, "hierarchical resident-byte limit reached")
    }

    /// Attribute an already-reserved transient response allocation to the
    /// client that will retain it during the downstream write.
    pub fn attribute_response_client(&mut self, client: IpAddr) -> io::Result<()> {
        if !matches!(self.kind, ResidentKind::Response) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "request memory cannot be attributed as a response",
            ));
        }
        let context = self.bytes.context.budget.context(client);
        self.bytes.attribute_context(context)
    }

    pub(crate) fn attribute_context(&mut self, context: ResourceContext) -> io::Result<()> {
        self.bytes.attribute_context(context)
    }

    /// Release transient working-set bytes that are no longer retained by the
    /// response representation.
    pub fn release(&mut self, amount: u64) {
        self.bytes.release(amount);
    }

    pub fn bytes(&self) -> u64 {
        self.bytes.bytes
    }

    pub(crate) fn enter_slow_output(&mut self) -> io::Result<()> {
        if !matches!(self.kind, ResidentKind::Response) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "request memory cannot enter the slow-output pool",
            ));
        }
        self.bytes.transfer_kind(
            ByteKind::SlowResponseResident,
            MAX_RESPONSE_RESIDENT_BYTES,
            Some(MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT),
            Some(MAX_RESPONSE_RESIDENT_BYTES_PER_REQUEST),
            "slow-output resident-byte limit reached",
        )
    }
}

#[derive(Debug)]
pub struct CombinedH2Lease {
    _slot: SlotLease,
}

#[derive(Debug)]
pub(crate) struct SlowInputLease {
    _slot: SlotLease,
}

#[derive(Debug)]
pub(crate) struct SlowOutputLease {
    _slot: SlotLease,
}

#[derive(Debug)]
pub struct ResponseBodyReadLease {
    _slot: SlotLease,
}

#[derive(Debug)]
pub struct WebsocketLease {
    _slot: SlotLease,
}

#[derive(Debug)]
pub struct ExpensiveLease {
    _slot: SlotLease,
}

pub fn try_expensive() -> Option<ExpensiveLease> {
    #[cfg(test)]
    let context = current_or_test_context();
    #[cfg(not(test))]
    let context = current_context()?;
    try_expensive_in(&context)
}

pub(crate) fn try_expensive_in(context: &ResourceContext) -> Option<ExpensiveLease> {
    let slot = context
        .slot(
            SlotKind::ExpensiveCpu,
            MAX_EXPENSIVE_OPS,
            Some(MAX_EXPENSIVE_OPS_PER_CLIENT),
            Some(MAX_EXPENSIVE_OPS_PER_CLIENT),
            "expensive operation limit reached",
        )
        .ok()?;
    let mut rates = context
        .budget
        .rates
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if !ResourceBudget::admit_rate(
        &mut rates.expensive,
        context.client,
        std::time::Instant::now(),
        MAX_EXPENSIVE_OPS_PER_SECOND,
        MAX_EXPENSIVE_OPS_PER_CLIENT_PER_SECOND,
    ) {
        drop(rates);
        drop(slot);
        return None;
    }
    drop(rates);
    Some(ExpensiveLease { _slot: slot })
}

#[derive(Debug)]
pub struct SpoolLease {
    bytes: ByteLease,
    file_slot: Option<SlotLease>,
    _descriptor: DescriptorLease,
    disk: DiskLease,
    slow: bool,
}

impl SpoolLease {
    pub fn reserve(&mut self, amount: u64) -> io::Result<()> {
        self.disk.reserve(amount)?;
        if let Err(error) = self
            .bytes
            .reserve(amount, "hierarchical spool-byte limit reached")
        {
            let _ = self
                .disk
                .resize(self.disk.bytes.saturating_sub(amount), self.disk.files);
            return Err(io::Error::new(io::ErrorKind::StorageFull, error));
        }
        Ok(())
    }

    pub fn attribute_client(&mut self, client: IpAddr) -> io::Result<()> {
        let context = self.bytes.context.budget.context(client);
        self.file_slot
            .as_mut()
            .expect("spool lease lost its file slot")
            .attribute_context(context.clone())?;
        if let Err(error) = self.bytes.attribute_context(context) {
            // A failed byte attribution must not leave the file slot owned by
            // a different scope. Move it back before reporting failure.
            let old = self.bytes.context.clone();
            let _ = self
                .file_slot
                .as_mut()
                .expect("spool lease lost its file slot")
                .attribute_context(old);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn enter_slow(&mut self) -> io::Result<()> {
        if self.slow {
            return Ok(());
        }
        let general = self
            .file_slot
            .as_ref()
            .expect("spool lease lost its file slot");
        let slow_files = (general.process_limit.saturating_add(3) / 4).max(1);
        let slow_slot = general.context.slot(
            SlotKind::SlowSpoolFile,
            slow_files,
            Some(slow_files),
            Some(slow_files),
            "slow-output spool-file limit reached",
        )?;
        let slow_bytes = (self.bytes.process_limit.saturating_add(3) / 4).max(1);
        if let Err(error) = self.bytes.transfer_kind(
            ByteKind::SlowSpool,
            slow_bytes,
            Some(slow_bytes),
            Some(slow_bytes),
            "slow-output spool-byte limit reached",
        ) {
            drop(slow_slot);
            return Err(io::Error::new(io::ErrorKind::StorageFull, error));
        }
        drop(self.file_slot.replace(slow_slot));
        self.slow = true;
        Ok(())
    }
}

#[derive(Debug)]
pub struct DynamicLease {
    _slot: Option<SlotLease>,
    _descriptors: DescriptorLease,
    _transport: TransportBufferLease,
}

impl DynamicLease {
    /// A downstream-bound dynamic response is protected by the slow-output
    /// pool. Release only its general backend concurrency slot while retaining
    /// the descriptor lease until the reader itself is finished.
    pub(crate) fn release_general_slot(&mut self) {
        drop(self._slot.take());
    }
}

#[derive(Debug)]
enum GeneralOutputLease {
    H1(SlotLease),
    H2 { _lease: CombinedH2Lease },
}

/// Protocol-neutral ownership transfer for downstream-bound responses.  The
/// slow lease is acquired before the protocol's general lease is released,
/// so cancellation or admission failure cannot create an unaccounted output.
#[derive(Debug)]
pub(crate) struct SlowOutputAdmission {
    context: ResourceContext,
    general: Option<GeneralOutputLease>,
    slow_input: Option<SlowInputLease>,
    slow: Option<SlowOutputLease>,
    input_phase: Option<vapache_verified::H2InputPhase>,
    phase: vapache_verified::SlowOutputPhase,
}

impl SlowOutputAdmission {
    pub(crate) fn tracked_h1(context: ResourceContext, general: SlotLease) -> Self {
        Self {
            context,
            general: Some(GeneralOutputLease::H1(general)),
            slow_input: None,
            slow: None,
            input_phase: None,
            phase: vapache_verified::SlowOutputPhase::General,
        }
    }

    pub(crate) fn tracked_h2(context: ResourceContext, general: CombinedH2Lease) -> Self {
        Self {
            context,
            general: Some(GeneralOutputLease::H2 { _lease: general }),
            slow_input: None,
            slow: None,
            input_phase: Some(vapache_verified::H2InputPhase::GeneralBeforeBody),
            phase: vapache_verified::SlowOutputPhase::General,
        }
    }

    pub(crate) fn detached(context: ResourceContext) -> Self {
        Self {
            context,
            general: None,
            slow_input: None,
            slow: None,
            input_phase: None,
            phase: vapache_verified::SlowOutputPhase::General,
        }
    }

    pub(crate) fn is_slow(&self) -> bool {
        self.phase == vapache_verified::SlowOutputPhase::Slow
    }

    pub(crate) fn client(&self) -> IpAddr {
        self.context
            .client()
            .expect("slow output admission requires a client identity")
    }

    pub(crate) fn is_slow_input(&self) -> bool {
        self.input_phase == Some(vapache_verified::H2InputPhase::SlowInput)
    }

    /// Transfer an HTTP/2 stream that is about to wait for request DATA from
    /// general dispatch capacity into the source-fair slow-input reserve. The
    /// slow lease is acquired first, so rejection leaves the general lease
    /// intact for the bounded error response.
    pub(crate) fn enter_slow_input(&mut self) -> io::Result<()> {
        if self.is_slow_input() {
            return Ok(());
        }
        let phase = self
            .input_phase
            .ok_or_else(|| io::Error::other("slow input requires HTTP/2 ownership"))?;
        let next =
            vapache_verified::h2_input_phase_step(phase, vapache_verified::H2InputEvent::BodyWait)
                .ok_or_else(|| io::Error::other("HTTP/2 input ownership cannot enter body wait"))?;
        if !matches!(self.general, Some(GeneralOutputLease::H2 { .. })) {
            return Err(io::Error::other("HTTP/2 input lost general ownership"));
        }
        let slow = self
            .context
            .budget()
            .try_slow_input_in(&self.context)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "slow-input capacity exhausted")
            })?;
        self.input_phase = Some(next);
        self.slow_input = Some(slow);
        drop(self.general.take());
        Ok(())
    }

    /// A completed/abandoned upload must reacquire normal stream ownership
    /// before policy/backend execution or response output resumes. Acquire the
    /// general lease first; on overload the slow-input lease remains owned
    /// until the stream is reset and this value is dropped.
    pub(crate) fn leave_slow_input(&mut self) -> io::Result<()> {
        if !self.is_slow_input() {
            return Ok(());
        }
        let next = vapache_verified::h2_input_phase_step(
            vapache_verified::H2InputPhase::SlowInput,
            vapache_verified::H2InputEvent::BodyComplete,
        )
        .expect("verified slow-input completion transition");
        let general = self
            .context
            .budget()
            .try_h2_stream_in(&self.context)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "HTTP/2 stream capacity exhausted after request body",
                )
            })?;
        self.general = Some(GeneralOutputLease::H2 { _lease: general });
        self.input_phase = Some(next);
        drop(self.slow_input.take());
        Ok(())
    }

    pub(crate) fn enter_slow(&mut self) -> io::Result<()> {
        self.enter_slow_with(|| Ok(()))
    }

    /// Acquire slow-output ownership, run every coupled resource transfer,
    /// and only then surrender general protocol capacity. If any transfer
    /// fails, the temporary slow lease is rolled back and the general lease
    /// remains owned by this admission value.
    pub(crate) fn enter_slow_with(
        &mut self,
        transfer: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.is_slow() {
            return Ok(());
        }
        if self.is_slow_input() {
            return Err(io::Error::other(
                "output cannot start while HTTP/2 request input is pending",
            ));
        }
        let next = vapache_verified::slow_output_phase_step(
            self.phase,
            vapache_verified::SlowOutputEvent::DownstreamStall,
        )
        .ok_or_else(|| io::Error::other("output ownership is closed"))?;
        let slow = self
            .context
            .budget()
            .try_slow_output_in(&self.context)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "slow-output capacity exhausted")
            })?;
        transfer()?;
        self.phase = next;
        self.slow = Some(slow);
        drop(self.general.take());
        Ok(())
    }

    fn finish(&mut self) {
        if let Some(phase) = self.input_phase {
            if let Some(next) =
                vapache_verified::h2_input_phase_step(phase, vapache_verified::H2InputEvent::Finish)
            {
                self.input_phase = Some(next);
            }
        }
        if let Some(next) = vapache_verified::slow_output_phase_step(
            self.phase,
            vapache_verified::SlowOutputEvent::Finish,
        ) {
            self.phase = next;
        }
        drop(self.general.take());
        drop(self.slow_input.take());
        drop(self.slow.take());
    }

    /// A fast HTTP/1 response may return its established-connection lease to
    /// the keep-alive loop. A classified slow connection is deliberately not
    /// promoted: its response completes under the slow pool and then closes.
    pub(crate) fn finish_h1(mut self) -> Option<SlotLease> {
        let reusable = if self.is_slow() {
            None
        } else {
            match self.general.take() {
                Some(GeneralOutputLease::H1(lease)) => Some(lease),
                _ => None,
            }
        };
        self.finish();
        reusable
    }

    pub(crate) fn finish_response(&mut self) {
        self.finish();
    }
}

impl Drop for SlowOutputAdmission {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Anchored progress state shared by HTTP/1 socket output and HTTP/2 flow
/// control. Neither successful partial writes nor capacity grants alter the
/// response start or its absolute deadline.
pub(crate) struct SlowOutputProgress {
    pub(crate) started: Instant,
    pub(crate) delivered: u64,
    blocked: Duration,
    pub(crate) interval: Duration,
    pub(crate) checkpoint: Instant,
    pub(crate) absolute_deadline: Instant,
}

impl SlowOutputProgress {
    pub(crate) fn new(interval: Duration) -> Self {
        let started = Instant::now();
        let checkpoint = started.checked_add(interval).unwrap_or(started);
        let absolute_deadline = started
            .checked_add(interval.saturating_mul(SLOW_OUTPUT_MAX_INTERVALS))
            .unwrap_or(checkpoint);
        Self {
            started,
            delivered: 0,
            blocked: Duration::ZERO,
            interval,
            checkpoint,
            absolute_deadline,
        }
    }

    pub(crate) fn record(&mut self, bytes: usize) {
        self.delivered = self.delivered.saturating_add(bytes as u64);
    }

    pub(crate) fn record_blocked(&mut self, blocked: Duration) {
        self.blocked = self.blocked.saturating_add(blocked);
    }

    pub(crate) fn remaining_classification_grace(&self, grace: Duration) -> Duration {
        grace.saturating_sub(self.blocked)
    }

    pub(crate) fn validate(&mut self, now: Instant) -> io::Result<()> {
        if now >= self.absolute_deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "response lifetime exceeded",
            ));
        }
        if now < self.checkpoint {
            return Ok(());
        }
        let elapsed_ms =
            u64::try_from(now.duration_since(self.started).as_millis()).unwrap_or(u64::MAX);
        let grace_ms = u64::try_from(self.interval.as_millis()).unwrap_or(u64::MAX);
        if !vapache_verified::minimum_progress_rate_admit(
            self.delivered,
            elapsed_ms,
            SLOW_OUTPUT_MIN_RATE,
            grace_ms,
        ) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "response minimum rate not met",
            ));
        }
        while self.checkpoint <= now {
            self.checkpoint = self
                .checkpoint
                .checked_add(self.interval)
                .unwrap_or(self.absolute_deadline);
            if self.checkpoint >= self.absolute_deadline {
                self.checkpoint = self.absolute_deadline;
                break;
            }
        }
        Ok(())
    }

    pub(crate) fn next_deadline(&self) -> Instant {
        self.checkpoint.min(self.absolute_deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    #[test]
    fn request_scope_cancellation_is_shared_by_internal_clones() {
        let budget = Arc::new(ResourceBudget::default());
        let scope = RequestScope::new(budget.context(IpAddr::from([192, 0, 2, 9])));
        let child = scope.clone();
        assert!(!child.is_cancelled());
        {
            let _guard = scope.guard();
        }
        assert!(scope.is_cancelled());
        assert!(child.is_cancelled());
    }

    #[test]
    fn bound_policy_budget_does_not_depend_on_thread_local_context() {
        let budget = Arc::new(ResourceBudget::default());
        let policy = RequestPolicyBudget::default();
        policy.bind_context(budget.context(IpAddr::from([192, 0, 2, 10])));
        policy.charge_expansion(64).unwrap();
        assert_eq!(policy.charged_expansion(), 64);
    }

    #[test]
    fn exact_descriptor_permits_drive_listener_hysteresis_and_recover() {
        let budget = Arc::new(ResourceBudget {
            physical_limits: [4, DEFAULT_TASK_BUDGET, DEFAULT_RESIDENT_BUDGET],
            ..ResourceBudget::default()
        });
        let first = budget.try_descriptor().unwrap();
        let second = budget.try_descriptor().unwrap();
        let third = budget.try_descriptor().unwrap();
        assert!(!budget.listener_pressure_high(64, 64));
        let fourth = budget.try_descriptor().unwrap();
        assert!(budget.listener_pressure_high(64, 64));
        assert!(!budget.listener_pressure_below_low(64, 64));
        assert!(budget.try_descriptor().is_err());
        drop(fourth);
        assert!(budget.listener_pressure_below_low(64, 64));
        drop((first, second, third));
        assert_eq!(
            budget.physical_process[PhysicalKind::FileDescriptor.index()].load(Ordering::Acquire),
            0
        );
    }

    #[test]
    fn disk_and_transport_parents_are_shared_exact_and_recoverable() {
        let budget = Arc::new(ResourceBudget {
            disk_byte_limit: 8,
            disk_file_limit: 2,
            transport_byte_limit: TRANSPORT_BUFFER_CHARGE,
            ..ResourceBudget::default()
        });
        let mut first = budget.try_disk(5, 1).unwrap();
        let second = budget.try_disk(3, 1).unwrap();
        assert!(budget.try_disk(1, 0).is_err());
        assert!(budget.try_disk(0, 1).is_err());
        first.resize(4, 1).unwrap();
        let third = budget.try_disk(1, 0).unwrap();
        assert_eq!(budget.telemetry().disk_bytes, 8);

        let transport = budget.try_transport_buffers().unwrap();
        assert!(budget.try_transport_buffers().is_err());
        assert_eq!(budget.telemetry().transport_bytes, TRANSPORT_BUFFER_CHARGE);
        drop((first, second, third, transport));
        let telemetry = budget.telemetry();
        assert_eq!(telemetry.disk_bytes, 0);
        assert_eq!(telemetry.disk_files, 0);
        assert_eq!(telemetry.transport_bytes, 0);
    }

    #[test]
    fn disk_children_isolate_filesystems_beneath_the_shared_parent() {
        let budget = Arc::new(ResourceBudget {
            disk_byte_limit: 100,
            disk_file_limit: 10,
            ..ResourceBudget::default()
        });
        let first = Arc::new(DiskLedger::new(11, 5, 1));
        let second = Arc::new(DiskLedger::new(22, 7, 2));
        let no_inodes = Arc::new(DiskLedger::new(33, 10, 0));
        {
            let mut ledgers = budget
                .disk_ledgers
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            ledgers.devices.insert(first.device, first.clone());
            ledgers.devices.insert(second.device, second.clone());
            ledgers.devices.insert(no_inodes.device, no_inodes.clone());
        }

        let first_lease = budget.try_disk_on_ledger(first.clone(), 5, 1).unwrap();
        assert!(budget.try_disk_on_ledger(first.clone(), 1, 0).is_err());
        let second_lease = budget.try_disk_on_ledger(second.clone(), 7, 2).unwrap();
        assert_eq!(first.bytes.load(Ordering::Acquire), 5);
        assert_eq!(second.bytes.load(Ordering::Acquire), 7);
        assert!(budget.try_disk_on_ledger(no_inodes.clone(), 3, 1).is_err());
        assert_eq!(no_inodes.bytes.load(Ordering::Acquire), 0);
        assert_eq!(no_inodes.files.load(Ordering::Acquire), 0);
        let telemetry = budget.telemetry();
        assert_eq!(telemetry.disk_bytes, 12);
        assert_eq!(telemetry.disk_filesystems, 3);
        assert_eq!(telemetry.disk_min_byte_headroom, 0);
        assert_eq!(telemetry.disk_min_file_headroom, 0);

        drop(first_lease);
        assert_eq!(first.bytes.load(Ordering::Acquire), 0);
        assert_eq!(second.bytes.load(Ordering::Acquire), 7);
        drop(second_lease);
        assert_eq!(budget.telemetry().disk_bytes, 0);
        assert_eq!(budget.telemetry().disk_files, 0);

        let inode_capped = Arc::new(ResourceBudget {
            disk_byte_limit: 10,
            disk_file_limit: 0,
            ..ResourceBudget::default()
        });
        let ample_child = Arc::new(DiskLedger::new(44, 10, 10));
        assert!(inode_capped
            .try_disk_on_ledger(ample_child.clone(), 3, 1)
            .is_err());
        assert_eq!(ample_child.bytes.load(Ordering::Acquire), 0);
        assert_eq!(inode_capped.disk_bytes.load(Ordering::Acquire), 0);
        assert_eq!(inode_capped.disk_files.load(Ordering::Acquire), 0);
    }

    #[test]
    fn disk_paths_reuse_their_kernel_device_ledger() {
        let budget = ResourceBudget::default();
        let first = budget.disk_ledger_for_path(Path::new(".")).unwrap();
        let second = budget
            .disk_ledger_for_path(&std::env::current_dir().unwrap().join("missing/child"))
            .unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.device, std::fs::metadata(".").unwrap().dev());
        if let Ok(other_metadata) = std::fs::metadata("/dev/shm") {
            if other_metadata.dev() != first.device {
                let other = budget.disk_ledger_for_path(Path::new("/dev/shm")).unwrap();
                assert!(!Arc::ptr_eq(&first, &other));
                assert_eq!(other.device, other_metadata.dev());
                assert_eq!(budget.telemetry().disk_filesystems, 2);
            }
        }
    }

    #[test]
    fn filesystem_phase_is_source_fair_and_releases() {
        let budget = Arc::new(ResourceBudget::default());
        let client = IpAddr::from([192, 0, 2, 60]);
        let leases: Vec<_> = (0..8)
            .map(|_| {
                let context = budget.context(client);
                budget.try_filesystem_work_in(&context).unwrap()
            })
            .collect();
        let denied = budget.context(client);
        assert!(budget.try_filesystem_work_in(&denied).is_err());
        let other = budget.context(IpAddr::from([198, 51, 100, 60]));
        let other_lease = budget.try_filesystem_work_in(&other).unwrap();
        drop((leases, other_lease));
        assert_eq!(budget.slot_usage(SlotKind::FilesystemWork), 0);
    }

    #[test]
    fn request_policy_budget_is_monotonic_and_poisoned_on_exhaustion() {
        let budget = RequestPolicyBudget::default();
        budget.charge_work(MAX_POLICY_WORK_UNITS - 1).unwrap();
        assert_eq!(budget.charged_work(), MAX_POLICY_WORK_UNITS - 1);
        assert!(budget.charge_work(2).is_err());
        assert!(budget.failed());
        assert_eq!(budget.charged_work(), MAX_POLICY_WORK_UNITS - 1);
        assert!(budget.charge_work(1).is_err());
        assert_eq!(budget.charged_work(), MAX_POLICY_WORK_UNITS - 1);

        let expansion = RequestPolicyBudget::default();
        expansion.charge_expansion(MAX_POLICY_VALUE_BYTES).unwrap();
        assert_eq!(expansion.charged_expansion(), MAX_POLICY_VALUE_BYTES);
        assert!(expansion
            .charge_expansion(MAX_POLICY_VALUE_BYTES + 1)
            .is_err());
        assert!(expansion.failed());
        assert!(expansion.charge_expansion(1).is_err());
        assert_eq!(expansion.charged_expansion(), MAX_POLICY_VALUE_BYTES);
    }

    #[test]
    fn aggregate_spool_and_dynamic_limits_release_on_drop() {
        let budget = Arc::new(ResourceBudget::default());
        let mut first = budget.try_spool(8, 1).unwrap();
        first.reserve(0).unwrap();
        first.reserve(8).unwrap();
        assert!(first.reserve(1).is_err());
        assert!(budget.try_spool(8, 1).is_err());
        assert_eq!(budget.usage(), (8, 1, 0));
        drop(first);

        let second = budget.try_spool(8, 1).unwrap();
        let dynamic = budget.try_dynamic(1).unwrap();
        assert!(budget.try_dynamic(1).is_err());
        assert_eq!(budget.usage(), (0, 1, 1));
        drop((second, dynamic));
        assert_eq!(budget.usage(), (0, 0, 0));
    }

    #[test]
    fn per_client_dynamic_limit_is_enforced_and_recovers() {
        let budget = Arc::new(ResourceBudget::default());
        let first = IpAddr::from([192, 0, 2, 1]);
        let second = IpAddr::from([198, 51, 100, 1]);
        let leases: Vec<_> = (0..MAX_DYNAMIC_REQUESTS_PER_CLIENT)
            .map(|_| budget.try_dynamic_for(64, first).unwrap())
            .collect();
        assert!(budget.try_dynamic_for(64, first).is_err());
        let other = budget.try_dynamic_for(64, second).unwrap();
        drop((leases, other));
        assert!(budget.try_dynamic_for(64, first).is_ok());
    }

    #[test]
    fn protocol_neutral_slow_output_handoff_is_irreversible() {
        let budget = Arc::new(ResourceBudget::default());
        let context = budget.context(IpAddr::from([192, 0, 2, 44]));
        let general = context
            .slot(SlotKind::H1Connection, 1, Some(1), Some(1), "full")
            .unwrap();
        let mut output = SlowOutputAdmission::tracked_h1(context.clone(), general);
        assert_eq!(budget.slot_usage(SlotKind::H1Connection), 1);
        assert!(output
            .enter_slow_with(|| Err(io::Error::other("coupled transfer rejected")))
            .is_err());
        assert_eq!(budget.slot_usage(SlotKind::H1Connection), 1);
        assert_eq!(budget.slot_usage(SlotKind::SlowOutput), 0);
        assert!(!output.is_slow());
        output.enter_slow().unwrap();
        output.enter_slow().unwrap();
        assert_eq!(budget.slot_usage(SlotKind::H1Connection), 0);
        assert_eq!(budget.slot_usage(SlotKind::SlowOutput), 1);
        assert!(output.finish_h1().is_none());
        assert_eq!(budget.slot_usage(SlotKind::SlowOutput), 0);

        let general = context
            .slot(SlotKind::H1Connection, 1, Some(1), Some(1), "full")
            .unwrap();
        let output = SlowOutputAdmission::tracked_h1(context, general);
        let reclaimed = output
            .finish_h1()
            .expect("fast HTTP/1 output did not return its general lease");
        assert_eq!(budget.slot_usage(SlotKind::H1Connection), 1);
        drop(reclaimed);
        assert_eq!(budget.slot_usage(SlotKind::H1Connection), 0);
    }

    #[test]
    fn h2_slow_input_handoff_is_atomic_in_both_directions() {
        let budget = Arc::new(ResourceBudget::default());
        let context = budget.context(IpAddr::from([192, 0, 2, 44]));
        let general = budget.try_h2_stream_in(&context).unwrap();
        let mut output = SlowOutputAdmission::tracked_h2(context, general);

        assert_eq!(budget.h2_input_usage(), (1, 0));
        output.enter_slow_input().unwrap();
        output.enter_slow_input().unwrap();
        assert_eq!(budget.h2_input_usage(), (0, 1));

        let general: Vec<_> = (0..MAX_H2_STREAMS)
            .map(|index| {
                budget
                    .try_h2_stream_for(IpAddr::from([
                        198,
                        51,
                        (index / MAX_H2_STREAMS_PER_CLIENT) as u8,
                        (index % MAX_H2_STREAMS_PER_CLIENT) as u8,
                    ]))
                    .unwrap()
            })
            .collect();
        assert!(output.leave_slow_input().is_err());
        assert_eq!(budget.h2_input_usage(), (MAX_H2_STREAMS, 1));

        drop(general);
        output.leave_slow_input().unwrap();
        output.leave_slow_input().unwrap();
        assert_eq!(budget.h2_input_usage(), (1, 0));
        output.finish_response();
        assert_eq!(budget.h2_input_usage(), (0, 0));
    }

    #[test]
    fn one_request_context_cannot_multiply_dynamic_backend_slots() {
        let budget = Arc::new(ResourceBudget::default());
        let context = budget.context(IpAddr::from([192, 0, 2, 2]));
        let lease = budget.try_dynamic_in(&context, 64).unwrap();
        assert!(budget.try_dynamic_in(&context, 64).is_err());
        assert_eq!(budget.slot_usage(SlotKind::DynamicBackend), 1);
        drop(lease);
        assert!(budget.try_dynamic_in(&context, 64).is_ok());
    }

    #[test]
    fn failed_process_admission_rolls_back_request_and_client_scopes() {
        let budget = Arc::new(ResourceBudget::default());
        let first = budget.context(IpAddr::from([192, 0, 2, 3]));
        let second = budget.context(IpAddr::from([192, 0, 2, 3]));
        let occupied = first
            .slot(SlotKind::DynamicBackend, 1, Some(2), Some(1), "full")
            .unwrap();
        assert!(second
            .slot(SlotKind::DynamicBackend, 1, Some(2), Some(1), "full")
            .is_err());
        drop(occupied);
        assert!(second
            .slot(SlotKind::DynamicBackend, 1, Some(2), Some(1), "full")
            .is_ok());
    }

    #[test]
    fn resident_bytes_transfer_to_the_validated_request_identity() {
        let budget = Arc::new(ResourceBudget::default());
        let mut request = budget.try_request_bytes().unwrap();
        request.reserve(1024).unwrap();
        let context = budget.context(IpAddr::from([192, 0, 2, 4]));
        request.attribute_context(context.clone()).unwrap();
        assert_eq!(request.bytes.context.scope_id(), context.scope_id());
        assert_eq!(budget.extended_usage().1, 1024);
        drop(request);
        assert_eq!(budget.extended_usage().1, 0);
    }

    #[test]
    fn context_transfer_does_not_double_charge_an_unchanged_client() {
        let budget = Arc::new(ResourceBudget::default());
        let client = IpAddr::from([192, 0, 2, 5]);
        let first = budget.context(client);
        let second = budget.context(client);

        let mut bytes = ByteLease::new(
            first.clone(),
            ByteKind::RequestResident,
            8,
            Some(8),
            Some(8),
        );
        bytes.reserve(8, "full").unwrap();
        bytes.attribute_context(second.clone()).unwrap();
        assert_eq!(bytes.context.scope_id(), second.scope_id());

        let mut slot = first
            .slot(SlotKind::DynamicBackend, 1, Some(1), Some(1), "full")
            .unwrap();
        slot.attribute_context(second).unwrap();
        assert_eq!(slot.context.client(), Some(client));
        drop((bytes, slot));
        assert!(budget.slot_clients.lock().unwrap().is_empty());
        assert!(budget.byte_clients.lock().unwrap().is_empty());
    }

    #[test]
    fn zero_byte_context_transfer_does_not_retain_a_client_entry() {
        let budget = Arc::new(ResourceBudget::default());
        let mut bytes = ByteLease::new(
            ResourceContext::process_only(&budget),
            ByteKind::RequestResident,
            8,
            Some(8),
            Some(8),
        );
        bytes
            .attribute_context(budget.context(IpAddr::from([192, 0, 2, 6])))
            .unwrap();
        assert!(budget.byte_clients.lock().unwrap().is_empty());
    }

    #[test]
    fn process_wide_stream_memory_and_blocking_leases_release() {
        let budget = Arc::new(ResourceBudget::default());
        let stream = budget
            .try_h2_stream_for(IpAddr::from([192, 0, 2, 1]))
            .unwrap();
        let mut request = budget.try_request_bytes().unwrap();
        let mut response = budget.try_response_bytes().unwrap();
        let blocking = budget.try_response_body_read().unwrap();
        request.reserve(7).unwrap();
        response.reserve(11).unwrap();
        assert_eq!(budget.extended_usage(), (1, 7, 11, 1));
        drop((stream, request, response, blocking));
        assert_eq!(budget.extended_usage(), (0, 0, 0, 0));
    }

    #[test]
    fn response_body_read_limit_is_exact_and_releases() {
        let budget = Arc::new(ResourceBudget::default());
        let leases: Vec<_> = (0..MAX_RESPONSE_BODY_READS)
            .map(|_| budget.try_response_body_read().unwrap())
            .collect();
        assert!(budget.try_response_body_read().is_err());
        assert_eq!(budget.extended_usage().3, MAX_RESPONSE_BODY_READS);
        drop(leases);
        assert_eq!(budget.extended_usage().3, 0);
    }

    #[test]
    fn retained_response_memory_has_an_exact_per_client_share() {
        let budget = Arc::new(ResourceBudget::default());
        let first = IpAddr::from([192, 0, 2, 10]);
        let second = IpAddr::from([198, 51, 100, 10]);
        let mut retained = budget.try_response_bytes_for(first);
        retained
            .reserve(MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT)
            .unwrap();
        assert!(budget.try_response_bytes_for(first).reserve(1).is_err());
        let mut other = budget.try_response_bytes_for(second);
        other.reserve(1).unwrap();
        assert_eq!(budget.extended_usage().2, retained.bytes() + 1);
        retained.release(7);
        let mut recovered = budget.try_response_bytes_for(first);
        recovered.reserve(7).unwrap();
        drop((retained, recovered, other));
        assert_eq!(budget.extended_usage().2, 0);
    }

    #[test]
    fn per_client_spool_share_covers_files_bytes_and_late_attribution() {
        let budget = Arc::new(ResourceBudget::default());
        let first = IpAddr::from([192, 0, 2, 20]);
        let second = IpAddr::from([198, 51, 100, 20]);
        let mut one = budget.try_spool_for(100, 8, first).unwrap();
        one.reserve(25).unwrap();
        assert!(one.reserve(1).is_err());
        let two = budget.try_spool_for(100, 8, first).unwrap();
        assert!(budget.try_spool_for(100, 8, first).is_err());
        let mut other = budget.try_spool_for(100, 8, second).unwrap();
        other.reserve(25).unwrap();

        let process_context = ResourceContext::process_only(&budget);
        let mut unattributed = budget.try_spool_in(100, 8, &process_context).unwrap();
        unattributed.reserve(1).unwrap();
        assert!(unattributed.attribute_client(first).is_err());
        drop((one, two, other, unattributed));
        assert_eq!(budget.usage(), (0, 0, 0));
    }

    #[test]
    fn response_body_reads_have_an_exact_per_client_share() {
        let budget = Arc::new(ResourceBudget::default());
        let first = IpAddr::from([192, 0, 2, 30]);
        let second = IpAddr::from([198, 51, 100, 30]);
        let leases: Vec<_> = (0..MAX_RESPONSE_BODY_READS_PER_CLIENT)
            .map(|_| budget.try_response_body_read_for(first).unwrap())
            .collect();
        assert!(budget.try_response_body_read_for(first).is_err());
        let other = budget.try_response_body_read_for(second).unwrap();
        drop((leases, other));
        assert_eq!(budget.extended_usage().3, 0);
    }

    #[test]
    fn h2_client_rejection_does_not_consume_a_process_slot() {
        let budget = Arc::new(ResourceBudget::default());
        let client = IpAddr::from([192, 0, 2, 40]);
        let clients: Vec<_> = (0..MAX_H2_STREAMS_PER_CLIENT)
            .map(|_| budget.try_h2_stream_for(client).unwrap())
            .collect();
        assert!(budget.try_h2_stream_for(client).is_err());
        assert_eq!(budget.extended_usage().0, MAX_H2_STREAMS_PER_CLIENT);
        drop(clients);
        assert!(budget.try_h2_stream_for(client).is_ok());
    }

    #[test]
    fn process_wide_h2_stream_limit_is_enforced_and_recovers() {
        let budget = Arc::new(ResourceBudget::default());
        let leases: Vec<_> = (0..MAX_H2_STREAMS)
            .map(|index| {
                budget
                    .try_h2_stream_for(IpAddr::from([
                        192,
                        0,
                        2 + (index / MAX_H2_STREAMS_PER_CLIENT) as u8,
                        1,
                    ]))
                    .unwrap()
            })
            .collect();
        assert!(budget
            .try_h2_stream_for(IpAddr::from([198, 51, 100, 1]))
            .is_err());
        drop(leases);
        assert!(budget
            .try_h2_stream_for(IpAddr::from([198, 51, 100, 1]))
            .is_ok());
    }

    #[test]
    fn slow_h2_outputs_have_source_and_process_fairness() {
        let budget = Arc::new(ResourceBudget::default());
        let first_leases: Vec<_> = (0..MAX_SLOW_OUTPUTS_PER_CLIENT)
            .map(|_| {
                let context = budget.context(IpAddr::from([192, 0, 2, 1]));
                budget.try_slow_output_in(&context).unwrap()
            })
            .collect();
        let first_overflow = budget.context(IpAddr::from([192, 0, 2, 1]));
        assert!(budget.try_slow_output_in(&first_overflow).is_err());

        let mut all = first_leases;
        for source in 2..=4 {
            all.extend((0..MAX_SLOW_OUTPUTS_PER_CLIENT).map(|_| {
                let context = budget.context(IpAddr::from([192, 0, 2, source]));
                budget.try_slow_output_in(&context).unwrap()
            }));
        }
        assert_eq!(all.len() as u64, MAX_SLOW_OUTPUTS);
        assert!(budget
            .try_slow_output_in(&budget.context(IpAddr::from([198, 51, 100, 1])))
            .is_err());
        assert_eq!(budget.h2_output_usage(), (0, MAX_SLOW_OUTPUTS));
        drop(all);
        assert_eq!(budget.h2_output_usage(), (0, 0));
    }

    #[test]
    fn slow_h2_inputs_have_source_and_process_fairness() {
        let budget = Arc::new(ResourceBudget::default());
        let first_leases: Vec<_> = (0..MAX_SLOW_INPUTS_PER_CLIENT)
            .map(|_| {
                let context = budget.context(IpAddr::from([192, 0, 2, 1]));
                budget.try_slow_input_in(&context).unwrap()
            })
            .collect();
        let first_overflow = budget.context(IpAddr::from([192, 0, 2, 1]));
        assert!(budget.try_slow_input_in(&first_overflow).is_err());

        let mut all = first_leases;
        for source in 2..=4 {
            all.extend((0..MAX_SLOW_INPUTS_PER_CLIENT).map(|_| {
                let context = budget.context(IpAddr::from([192, 0, 2, source]));
                budget.try_slow_input_in(&context).unwrap()
            }));
        }
        assert_eq!(all.len() as u64, MAX_SLOW_INPUTS);
        assert!(budget
            .try_slow_input_in(&budget.context(IpAddr::from([198, 51, 100, 1])))
            .is_err());
        assert_eq!(budget.h2_input_usage(), (0, MAX_SLOW_INPUTS));
        drop(all);
        assert_eq!(budget.h2_input_usage(), (0, 0));
    }

    #[test]
    fn per_client_h2_stream_limit_is_enforced_and_recovers() {
        let budget = Arc::new(ResourceBudget::default());
        let client = IpAddr::from([192, 0, 2, 77]);
        let leases: Vec<_> = (0..MAX_H2_STREAMS_PER_CLIENT)
            .map(|_| budget.try_h2_stream_for(client).unwrap())
            .collect();
        assert!(budget.try_h2_stream_for(client).is_err());
        assert!(budget
            .try_h2_stream_for(IpAddr::from([192, 0, 2, 78]))
            .is_ok());
        drop(leases);
        assert!(budget.try_h2_stream_for(client).is_ok());
    }

    #[test]
    fn ipv6_quota_identity_is_a_prefix_not_an_interface_address() {
        let first: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let rotated: IpAddr = "2001:db8:1:2:ffff::beef".parse().unwrap();
        let other_prefix: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(client_quota_key(first), client_quota_key(rotated));
        assert_ne!(client_quota_key(first), client_quota_key(other_prefix));
        assert_eq!(
            client_quota_key("::ffff:192.0.2.9".parse().unwrap()),
            IpAddr::from([192, 0, 2, 9])
        );

        let budget = Arc::new(ResourceBudget::default());
        let leases: Vec<_> = (0..MAX_H2_STREAMS_PER_CLIENT)
            .map(|_| budget.try_h2_stream_for(first).unwrap())
            .collect();
        assert!(budget.try_h2_stream_for(rotated).is_err());
        assert!(budget.try_h2_stream_for(other_prefix).is_ok());
        drop(leases);
    }

    #[test]
    fn process_wide_websocket_limit_is_enforced_and_recovers() {
        let budget = Arc::new(ResourceBudget::default());
        let leases: Vec<_> = (0..MAX_WEBSOCKET_TUNNELS)
            .map(|index| {
                budget
                    .try_websocket_for(IpAddr::from([127, 0, (index / 255) as u8, index as u8]))
                    .unwrap()
            })
            .collect();
        assert_eq!(budget.websocket_usage(), MAX_WEBSOCKET_TUNNELS);
        assert!(budget
            .try_websocket_for(IpAddr::from([192, 0, 2, 1]))
            .is_err());
        drop(leases);
        assert_eq!(budget.websocket_usage(), 0);
        assert!(budget
            .try_websocket_for(IpAddr::from([192, 0, 2, 1]))
            .is_ok());
    }

    #[test]
    fn per_client_websocket_limit_is_enforced_and_recovers() {
        let budget = Arc::new(ResourceBudget::default());
        let client = IpAddr::from([192, 0, 2, 42]);
        let leases: Vec<_> = (0..MAX_WEBSOCKETS_PER_CLIENT)
            .map(|_| budget.try_websocket_for(client).unwrap())
            .collect();
        assert!(budget.try_websocket_for(client).is_err());
        assert!(budget
            .try_websocket_for(IpAddr::from([192, 0, 2, 43]))
            .is_ok());
        drop(leases);
        assert!(budget.try_websocket_for(client).is_ok());
    }

    #[test]
    fn resident_lease_rejects_overflow_and_global_expensive_work_releases() {
        let budget = Arc::new(ResourceBudget::default());
        let mut resident = ResidentLease::new(
            budget.context(IpAddr::from([192, 0, 2, 1])),
            ResidentKind::Request,
            8,
            8,
            8,
        );
        resident.reserve(8).unwrap();
        assert!(resident.reserve(1).is_err());
        let lease = try_expensive().expect("expensive slot");
        drop(lease);
        assert!(try_expensive().is_some());
    }

    #[test]
    fn expensive_work_is_fair_per_client_and_recovers() {
        let first = IpAddr::from([192, 0, 2, 10]);
        let second = IpAddr::from([192, 0, 2, 11]);
        with_expensive_client(first, || {
            let leases: Vec<_> = (0..MAX_EXPENSIVE_OPS_PER_CLIENT)
                .map(|_| try_expensive().expect("per-client expensive slot"))
                .collect();
            assert!(try_expensive().is_none());
            assert!(with_expensive_client(second, try_expensive).is_some());
            drop(leases);
            assert!(try_expensive().is_some());
        });
    }

    #[test]
    fn physical_parent_composes_typed_fd_and_task_leases() {
        let mut raw = ResourceBudget::default();
        raw.physical_limits[PhysicalKind::FileDescriptor.index()] = 4;
        raw.physical_limits[PhysicalKind::Task.index()] = 8;
        let budget = Arc::new(raw);
        let context = budget.context(IpAddr::from([192, 0, 2, 90]));
        let dynamic = budget.try_dynamic_in(&context, 8).unwrap();
        assert!(budget.try_spool_in(1024, 8, &context).is_err());
        drop(dynamic);
        assert!(budget.try_spool_in(1024, 8, &context).is_ok());

        let mut task_limited = ResourceBudget::default();
        task_limited.physical_limits[PhysicalKind::Task.index()] = 1;
        let task_limited = Arc::new(task_limited);
        let context = task_limited.context(IpAddr::from([192, 0, 2, 91]));
        let pending = context
            .slot(SlotKind::PendingConnection, 8, Some(8), Some(1), "full")
            .unwrap();
        assert!(task_limited.try_h2_stream_in(&context).is_err());
        drop(pending);
        assert!(task_limited.try_h2_stream_in(&context).is_ok());
    }

    #[test]
    fn physical_memory_parent_composes_typed_resident_categories() {
        let mut raw = ResourceBudget::default();
        raw.physical_limits[PhysicalKind::ResidentMemory.index()] = 10;
        let budget = Arc::new(raw);
        let context = budget.context(IpAddr::from([192, 0, 2, 92]));
        let mut request = ResidentLease::new(context.clone(), ResidentKind::Request, 100, 100, 100);
        let mut response =
            ResidentLease::new(context.clone(), ResidentKind::Response, 100, 100, 100);
        request.reserve(6).unwrap();
        assert!(budget.try_cache_resident(&context, 100, 5).is_err());
        let cache = budget.try_cache_resident(&context, 100, 4).unwrap();
        assert_eq!(cache.bytes(), 4);
        assert!(response.reserve(1).is_err());
        drop(cache);
        response.reserve(4).unwrap();
    }

    #[test]
    fn request_rate_is_once_per_scope_and_weighted_rates_are_exact() {
        let budget = Arc::new(ResourceBudget::default());
        let context = budget.context(IpAddr::from([192, 0, 2, 93]));
        budget.try_request_rate(&context).unwrap();
        budget.try_request_rate(&context).unwrap();
        let rates = budget.rates.lock().unwrap();
        assert_eq!(rates.request.total, 1);
        drop(rates);

        let mut window = RateWindow::default();
        let now = std::time::Instant::now();
        let client = Some(IpAddr::from([192, 0, 2, 94]));
        assert!(ResourceBudget::admit_rate_amount(
            &mut window,
            client,
            now,
            7,
            10,
            8,
        ));
        assert!(!ResourceBudget::admit_rate_amount(
            &mut window,
            client,
            now,
            2,
            10,
            8,
        ));
        assert!(ResourceBudget::admit_rate_amount(
            &mut window,
            None,
            now,
            3,
            10,
            8,
        ));
        assert!(!ResourceBudget::admit_rate_amount(
            &mut window,
            None,
            now,
            1,
            10,
            8,
        ));
    }

    #[test]
    fn concurrent_dynamic_admission_never_exceeds_the_limit() {
        const THREADS: usize = 32;
        const LIMIT: usize = 4;
        let budget = Arc::new(ResourceBudget::default());
        let start = Arc::new(std::sync::Barrier::new(THREADS));
        let attempted = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..THREADS {
            let budget = budget.clone();
            let start = start.clone();
            let attempted = attempted.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                let lease = budget.try_dynamic(LIMIT as u64).ok();
                attempted.fetch_add(1, AtomicOrdering::AcqRel);
                while attempted.load(AtomicOrdering::Acquire) != THREADS {
                    std::thread::yield_now();
                }
                lease.is_some()
            }));
        }
        let admitted = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, LIMIT);
        assert_eq!(budget.usage(), (0, 0, 0));
    }

    #[test]
    fn loom_explores_atomic_admission_and_release_interleavings() {
        loom::model(|| {
            use loom::sync::atomic::AtomicU64 as LoomAtomicU64;
            use loom::sync::Arc as LoomArc;

            let counter = LoomArc::new(LoomAtomicU64::new(0));
            let mut workers = Vec::new();
            for _ in 0..2 {
                let counter = counter.clone();
                workers.push(loom::thread::spawn(move || {
                    if try_add_counter(&*counter, 1, 1) {
                        assert!(counter.load(Ordering::Acquire) <= 1);
                        loom::thread::yield_now();
                        counter.fetch_sub(1, Ordering::AcqRel);
                    }
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
            assert_eq!(counter.load(Ordering::Acquire), 0);
        });
    }
}
