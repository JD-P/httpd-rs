//! Process-generation resource accounting for attacker-controlled dynamic I/O.
//!
//! Reservations are RAII values.  A failed parse, backend error, early return,
//! or short client connection therefore releases its bytes/slot without every
//! caller having to remember a matching decrement.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Debug, Default)]
pub struct ResourceBudget {
    spool_bytes: AtomicU64,
    spool_files: AtomicU64,
    spool_clients: Mutex<HashMap<IpAddr, (u64, u64)>>,
    dynamic_requests: AtomicU64,
    dynamic_clients: Mutex<HashMap<IpAddr, u64>>,
    h2_streams: AtomicU64,
    h2_clients: Mutex<HashMap<IpAddr, u64>>,
    request_bytes: AtomicU64,
    response_bytes: AtomicU64,
    response_clients: Mutex<HashMap<IpAddr, u64>>,
    response_body_reads: AtomicU64,
    response_body_read_clients: Mutex<HashMap<IpAddr, u64>>,
    websocket_tunnels: AtomicU64,
    websocket_clients: Mutex<HashMap<IpAddr, u64>>,
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
pub const MAX_REQUEST_RESIDENT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_RESPONSE_RESIDENT_BYTES: u64 = 128 * 1024 * 1024;
/// One network identity may retain at most one quarter of the response heap
/// while downstream clients consume it. This prevents a handful of slow
/// responses from turning the process-wide memory safety bound into a global
/// availability oracle.
pub const MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT: u64 = 32 * 1024 * 1024;
pub const MAX_WEBSOCKET_TUNNELS: u64 = 64;
pub const MAX_WEBSOCKETS_PER_CLIENT: u64 = 8;
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
    failed: AtomicBool,
}

static POLICY_RESIDENT_BYTES: AtomicU64 = AtomicU64::new(0);

impl Default for RequestPolicyBudget {
    fn default() -> Self {
        Self {
            work: AtomicU64::new(0),
            expansion_bytes: AtomicU64::new(0),
            failed: AtomicBool::new(false),
        }
    }
}

impl RequestPolicyBudget {
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
        if !try_add(&POLICY_RESIDENT_BYTES, amount, MAX_POLICY_RESIDENT_BYTES) {
            self.failed.store(true, Ordering::Release);
            return Err("process policy expansion limit exceeded");
        }
        if !try_add(&self.expansion_bytes, amount, MAX_POLICY_EXPANSION_BYTES) {
            POLICY_RESIDENT_BYTES.fetch_sub(amount, Ordering::AcqRel);
            self.failed.store(true, Ordering::Release);
            return Err("request policy expansion limit exceeded");
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

impl Drop for RequestPolicyBudget {
    fn drop(&mut self) {
        let reserved = self.expansion_bytes.load(Ordering::Acquire);
        if reserved != 0 {
            POLICY_RESIDENT_BYTES.fetch_sub(reserved, Ordering::AcqRel);
        }
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

static EXPENSIVE_OPS: AtomicU64 = AtomicU64::new(0);
static EXPENSIVE_CLIENTS: OnceLock<Mutex<HashMap<IpAddr, u64>>> = OnceLock::new();

thread_local! {
    static EXPENSIVE_CLIENT: RefCell<Option<IpAddr>> = const { RefCell::new(None) };
}

pub fn with_expensive_client<T>(client: IpAddr, operation: impl FnOnce() -> T) -> T {
    let client = client_quota_key(client);
    EXPENSIVE_CLIENT.with(|current| {
        let previous = current.replace(Some(client));
        struct Restore<'a> {
            slot: &'a RefCell<Option<IpAddr>>,
            previous: Option<IpAddr>,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.slot.replace(self.previous);
            }
        }
        let _restore = Restore {
            slot: current,
            previous,
        };
        operation()
    })
}

pub(crate) fn current_expensive_client() -> Option<IpAddr> {
    EXPENSIVE_CLIENT.with(|current| *current.borrow())
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
        if !vapache_verified::resource_budget_admit(current, amount, limit) {
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

impl ResourceBudget {
    pub fn try_spool(self: &Arc<Self>, max_bytes: u64, max_files: u64) -> io::Result<SpoolLease> {
        // Dynamic handlers run inside `with_expensive_client`. Attribute
        // their temporary proxy/FastCGI/CGI spools at creation time so one
        // request cannot consume the global pool before the completed
        // response is attributed by the transport.
        self.try_spool_inner(max_bytes, max_files, current_expensive_client())
    }

    pub fn try_spool_for(
        self: &Arc<Self>,
        max_bytes: u64,
        max_files: u64,
        client: IpAddr,
    ) -> io::Result<SpoolLease> {
        self.try_spool_inner(max_bytes, max_files, Some(client_quota_key(client)))
    }

    fn try_spool_inner(
        self: &Arc<Self>,
        max_bytes: u64,
        max_files: u64,
        client: Option<IpAddr>,
    ) -> io::Result<SpoolLease> {
        if !try_add(&self.spool_files, 1, max_files) {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "aggregate spool-file limit reached",
            ));
        }
        if let Some(client) = client {
            let mut clients = self
                .spool_clients
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let usage = clients.entry(client).or_default();
            let client_files = max_files.saturating_add(3) / 4;
            if !vapache_verified::resource_budget_admit(usage.1, 1, client_files.max(1)) {
                if usage.0 == 0 && usage.1 == 0 {
                    clients.remove(&client);
                }
                self.spool_files.fetch_sub(1, Ordering::AcqRel);
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "per-client spool-file limit reached",
                ));
            }
            usage.1 += 1;
        }
        Ok(SpoolLease {
            budget: self.clone(),
            bytes: 0,
            max_bytes,
            max_files,
            client,
            active: true,
        })
    }

    pub fn try_dynamic(self: &Arc<Self>, limit: u64) -> io::Result<DynamicLease> {
        self.try_dynamic_inner(limit, None)
    }

    pub fn try_dynamic_for(
        self: &Arc<Self>,
        limit: u64,
        client: IpAddr,
    ) -> io::Result<DynamicLease> {
        self.try_dynamic_inner(limit, Some(client_quota_key(client)))
    }

    fn try_dynamic_inner(
        self: &Arc<Self>,
        limit: u64,
        client: Option<IpAddr>,
    ) -> io::Result<DynamicLease> {
        if !try_add(&self.dynamic_requests, 1, limit) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "dynamic backend concurrency limit reached",
            ));
        }
        if let Some(client) = client {
            let mut clients = self
                .dynamic_clients
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let count = clients.entry(client).or_insert(0);
            if *count >= limit.min(MAX_DYNAMIC_REQUESTS_PER_CLIENT) {
                drop(clients);
                self.dynamic_requests.fetch_sub(1, Ordering::AcqRel);
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "per-client dynamic backend limit reached",
                ));
            }
            *count += 1;
        }
        Ok(DynamicLease {
            budget: self.clone(),
            client,
            active: true,
        })
    }

    fn try_h2_stream(self: &Arc<Self>) -> io::Result<H2StreamLease> {
        if !try_add(&self.h2_streams, 1, MAX_H2_STREAMS) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "process-wide HTTP/2 stream limit reached",
            ));
        }
        Ok(H2StreamLease {
            budget: self.clone(),
            active: true,
        })
    }

    fn try_h2_client_for(self: &Arc<Self>, client: IpAddr) -> io::Result<H2ClientLease> {
        let client = client_quota_key(client);
        let mut clients = self
            .h2_clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let count = clients.entry(client).or_default();
        if !vapache_verified::resource_budget_admit(*count, 1, MAX_H2_STREAMS_PER_CLIENT) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "per-client HTTP/2 stream limit reached",
            ));
        }
        *count += 1;
        drop(clients);
        Ok(H2ClientLease {
            budget: self.clone(),
            client,
            active: true,
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
        let client = self.try_h2_client_for(client)?;
        debug_assert!(vapache_verified::h2_process_slot_admit(client.active));
        let stream = self.try_h2_stream()?;
        Ok(CombinedH2Lease {
            _stream: stream,
            _client: client,
        })
    }

    pub fn try_request_bytes(self: &Arc<Self>) -> ResidentLease {
        ResidentLease::new(
            self.clone(),
            ResidentKind::Request,
            MAX_REQUEST_RESIDENT_BYTES,
        )
    }

    pub fn try_response_bytes(self: &Arc<Self>) -> ResidentLease {
        let mut lease = ResidentLease::new(
            self.clone(),
            ResidentKind::Response,
            MAX_RESPONSE_RESIDENT_BYTES,
        );
        // Cover transient allocation as well as the retained response. The
        // dispatch wrapper supplies the effective (RemoteIP-aware) identity
        // while response generators build their result.
        lease.client = current_expensive_client();
        lease
    }

    pub fn try_response_bytes_for(self: &Arc<Self>, client: IpAddr) -> ResidentLease {
        let mut lease = self.try_response_bytes();
        lease.client = Some(client_quota_key(client));
        lease
    }

    /// Reserve one short blocking read of a response-body descriptor.
    ///
    /// This permit deliberately excludes request dispatch and downstream
    /// socket waits. Holding it across either boundary lets a client exhaust
    /// the read capacity without causing any read work (P30-A/A').
    pub fn try_response_body_read(self: &Arc<Self>) -> io::Result<ResponseBodyReadLease> {
        self.try_response_body_read_inner(None)
    }

    pub fn try_response_body_read_for(
        self: &Arc<Self>,
        client: IpAddr,
    ) -> io::Result<ResponseBodyReadLease> {
        self.try_response_body_read_inner(Some(client_quota_key(client)))
    }

    fn try_response_body_read_inner(
        self: &Arc<Self>,
        client: Option<IpAddr>,
    ) -> io::Result<ResponseBodyReadLease> {
        debug_assert!(vapache_verified::response_body_read_lease_admit(
            vapache_verified::ResponseWorkPhase::DescriptorRead,
        ));
        if !try_add(&self.response_body_reads, 1, MAX_RESPONSE_BODY_READS) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "process-wide response-body read limit reached",
            ));
        }
        if let Some(client) = client {
            let mut clients = self
                .response_body_read_clients
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let count = clients.entry(client).or_default();
            if !vapache_verified::resource_budget_admit(
                *count,
                1,
                MAX_RESPONSE_BODY_READS_PER_CLIENT,
            ) {
                if *count == 0 {
                    clients.remove(&client);
                }
                self.response_body_reads.fetch_sub(1, Ordering::AcqRel);
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "per-client response-body read limit reached",
                ));
            }
            *count += 1;
        }
        Ok(ResponseBodyReadLease {
            budget: self.clone(),
            client,
            active: true,
        })
    }

    pub fn try_websocket_for(self: &Arc<Self>, client: IpAddr) -> io::Result<WebsocketLease> {
        let client = client_quota_key(client);
        if !try_add(&self.websocket_tunnels, 1, MAX_WEBSOCKET_TUNNELS) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "process-wide WebSocket tunnel limit reached",
            ));
        }
        let mut clients = self
            .websocket_clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let count = clients.entry(client).or_default();
        if !vapache_verified::resource_budget_admit(*count, 1, MAX_WEBSOCKETS_PER_CLIENT) {
            self.websocket_tunnels.fetch_sub(1, Ordering::AcqRel);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "per-client WebSocket tunnel limit reached",
            ));
        }
        *count += 1;
        drop(clients);
        Ok(WebsocketLease {
            budget: self.clone(),
            client,
            active: true,
        })
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn usage(&self) -> (u64, u64, u64) {
        (
            self.spool_bytes.load(Ordering::Acquire),
            self.spool_files.load(Ordering::Acquire),
            self.dynamic_requests.load(Ordering::Acquire),
        )
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn extended_usage(&self) -> (u64, u64, u64, u64) {
        (
            self.h2_streams.load(Ordering::Acquire),
            self.request_bytes.load(Ordering::Acquire),
            self.response_bytes.load(Ordering::Acquire),
            self.response_body_reads.load(Ordering::Acquire),
        )
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn websocket_usage(&self) -> u64 {
        self.websocket_tunnels.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug)]
enum ResidentKind {
    Request,
    Response,
}

#[derive(Debug)]
pub struct ResidentLease {
    budget: Arc<ResourceBudget>,
    kind: ResidentKind,
    bytes: u64,
    limit: u64,
    client: Option<IpAddr>,
}

impl ResidentLease {
    fn new(budget: Arc<ResourceBudget>, kind: ResidentKind, limit: u64) -> Self {
        Self {
            budget,
            kind,
            bytes: 0,
            limit,
            client: None,
        }
    }

    fn counter(&self) -> &AtomicU64 {
        match self.kind {
            ResidentKind::Request => &self.budget.request_bytes,
            ResidentKind::Response => &self.budget.response_bytes,
        }
    }

    pub fn reserve(&mut self, amount: u64) -> io::Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let mut client_counts = if matches!(self.kind, ResidentKind::Response) {
            self.client.map(|client| {
                let counts = self
                    .budget
                    .response_clients
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                (client, counts)
            })
        } else {
            None
        };
        if let Some((client, counts)) = client_counts.as_mut() {
            let current = counts.get(client).copied().unwrap_or(0);
            if !vapache_verified::resource_budget_admit(
                current,
                amount,
                MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT,
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "per-client response resident-byte limit reached",
                ));
            }
        }
        if !try_add(self.counter(), amount, self.limit) {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "process-wide resident-byte limit reached",
            ));
        }
        if let Some((client, counts)) = client_counts.as_mut() {
            *counts.entry(*client).or_default() += amount;
        }
        self.bytes = self.bytes.saturating_add(amount);
        Ok(())
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
        let client = client_quota_key(client);
        if self.client == Some(client) {
            return Ok(());
        }
        if self.client.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "response memory already belongs to another client",
            ));
        }
        let mut counts = self
            .budget
            .response_clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let current = counts.get(&client).copied().unwrap_or(0);
        if !vapache_verified::resource_budget_admit(
            current,
            self.bytes,
            MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT,
        ) {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "per-client response resident-byte limit reached",
            ));
        }
        if self.bytes != 0 {
            *counts.entry(client).or_default() += self.bytes;
        }
        self.client = Some(client);
        Ok(())
    }

    /// Release transient working-set bytes that are no longer retained by the
    /// response representation.
    pub fn release(&mut self, amount: u64) {
        let amount = amount.min(self.bytes);
        if amount == 0 {
            return;
        }
        self.counter().fetch_sub(amount, Ordering::AcqRel);
        if let Some(client) = self.client {
            let mut counts = self
                .budget
                .response_clients
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(current) = counts.get_mut(&client) {
                *current = current.saturating_sub(amount);
                if *current == 0 {
                    counts.remove(&client);
                }
            }
        }
        self.bytes -= amount;
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for ResidentLease {
    fn drop(&mut self) {
        self.release(self.bytes);
    }
}

#[derive(Debug)]
pub struct H2StreamLease {
    budget: Arc<ResourceBudget>,
    active: bool,
}

impl Drop for H2StreamLease {
    fn drop(&mut self) {
        if self.active {
            self.budget.h2_streams.fetch_sub(1, Ordering::AcqRel);
            self.active = false;
        }
    }
}

#[derive(Debug)]
pub struct H2ClientLease {
    budget: Arc<ResourceBudget>,
    client: IpAddr,
    active: bool,
}

impl Drop for H2ClientLease {
    fn drop(&mut self) {
        if self.active {
            let mut clients = self
                .budget
                .h2_clients
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(count) = clients.get_mut(&self.client) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    clients.remove(&self.client);
                }
            }
            self.active = false;
        }
    }
}

#[derive(Debug)]
pub struct CombinedH2Lease {
    _stream: H2StreamLease,
    _client: H2ClientLease,
}

#[derive(Debug)]
pub struct ResponseBodyReadLease {
    budget: Arc<ResourceBudget>,
    client: Option<IpAddr>,
    active: bool,
}

#[derive(Debug)]
pub struct WebsocketLease {
    budget: Arc<ResourceBudget>,
    client: IpAddr,
    active: bool,
}

impl Drop for WebsocketLease {
    fn drop(&mut self) {
        if self.active {
            let mut clients = self
                .budget
                .websocket_clients
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(count) = clients.get_mut(&self.client) {
                *count -= 1;
                if *count == 0 {
                    clients.remove(&self.client);
                }
            }
            drop(clients);
            self.budget.websocket_tunnels.fetch_sub(1, Ordering::AcqRel);
            self.active = false;
        }
    }
}

impl Drop for ResponseBodyReadLease {
    fn drop(&mut self) {
        if self.active {
            self.budget
                .response_body_reads
                .fetch_sub(1, Ordering::AcqRel);
            if let Some(client) = self.client {
                let mut clients = self
                    .budget
                    .response_body_read_clients
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if let Some(count) = clients.get_mut(&client) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        clients.remove(&client);
                    }
                }
            }
            self.active = false;
        }
    }
}

#[derive(Debug)]
pub struct ExpensiveLease {
    client: Option<IpAddr>,
    active: bool,
}

pub fn try_expensive() -> Option<ExpensiveLease> {
    if !try_add(&EXPENSIVE_OPS, 1, MAX_EXPENSIVE_OPS) {
        return None;
    }
    let client = EXPENSIVE_CLIENT.with(|current| *current.borrow());
    if let Some(client) = client {
        let mut clients = EXPENSIVE_CLIENTS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let count = clients.entry(client).or_insert(0);
        if *count >= MAX_EXPENSIVE_OPS_PER_CLIENT {
            if *count == 0 {
                clients.remove(&client);
            }
            drop(clients);
            EXPENSIVE_OPS.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        *count += 1;
    }
    Some(ExpensiveLease {
        client,
        active: true,
    })
}

impl Drop for ExpensiveLease {
    fn drop(&mut self) {
        if self.active {
            if let Some(client) = self.client {
                let mut clients = EXPENSIVE_CLIENTS
                    .get_or_init(|| Mutex::new(HashMap::new()))
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if let Some(count) = clients.get_mut(&client) {
                    *count -= 1;
                    if *count == 0 {
                        clients.remove(&client);
                    }
                }
            }
            EXPENSIVE_OPS.fetch_sub(1, Ordering::AcqRel);
            self.active = false;
        }
    }
}

#[derive(Debug)]
pub struct SpoolLease {
    budget: Arc<ResourceBudget>,
    bytes: u64,
    max_bytes: u64,
    max_files: u64,
    client: Option<IpAddr>,
    active: bool,
}

impl SpoolLease {
    pub fn reserve(&mut self, amount: u64) -> io::Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let mut clients = self.client.map(|client| {
            let counts = self
                .budget
                .spool_clients
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            (client, counts)
        });
        if let Some((client, counts)) = clients.as_mut() {
            let current = counts.get(client).copied().unwrap_or_default().0;
            let client_bytes = self.max_bytes.saturating_add(3) / 4;
            if !vapache_verified::resource_budget_admit(current, amount, client_bytes.max(1)) {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "per-client spool-byte limit reached",
                ));
            }
        }
        if !try_add(&self.budget.spool_bytes, amount, self.max_bytes) {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "aggregate spool-byte limit reached",
            ));
        }
        if let Some((client, counts)) = clients.as_mut() {
            counts.entry(*client).or_default().0 += amount;
        }
        self.bytes += amount;
        Ok(())
    }

    pub fn attribute_client(&mut self, client: IpAddr) -> io::Result<()> {
        let client = client_quota_key(client);
        if self.client == Some(client) {
            return Ok(());
        }
        if self.client.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spool already belongs to another client",
            ));
        }
        let mut clients = self
            .budget
            .spool_clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let usage = clients.get(&client).copied().unwrap_or_default();
        let client_bytes = self.max_bytes.saturating_add(3) / 4;
        let client_files = self.max_files.saturating_add(3) / 4;
        if !vapache_verified::resource_budget_admit(usage.0, self.bytes, client_bytes.max(1))
            || !vapache_verified::resource_budget_admit(usage.1, 1, client_files.max(1))
        {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "per-client spool limit reached",
            ));
        }
        let entry = clients.entry(client).or_default();
        entry.0 += self.bytes;
        entry.1 += 1;
        self.client = Some(client);
        Ok(())
    }
}

impl Drop for SpoolLease {
    fn drop(&mut self) {
        if self.active {
            self.budget
                .spool_bytes
                .fetch_sub(self.bytes, Ordering::AcqRel);
            self.budget.spool_files.fetch_sub(1, Ordering::AcqRel);
            if let Some(client) = self.client {
                let mut clients = self
                    .budget
                    .spool_clients
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if let Some(usage) = clients.get_mut(&client) {
                    usage.0 = usage.0.saturating_sub(self.bytes);
                    usage.1 = usage.1.saturating_sub(1);
                    if usage.0 == 0 && usage.1 == 0 {
                        clients.remove(&client);
                    }
                }
            }
            self.active = false;
        }
    }
}

#[derive(Debug)]
pub struct DynamicLease {
    budget: Arc<ResourceBudget>,
    client: Option<IpAddr>,
    active: bool,
}

impl Drop for DynamicLease {
    fn drop(&mut self) {
        if self.active {
            if let Some(client) = self.client {
                let mut clients = self
                    .budget
                    .dynamic_clients
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if let Some(count) = clients.get_mut(&client) {
                    *count -= 1;
                    if *count == 0 {
                        clients.remove(&client);
                    }
                }
            }
            self.budget.dynamic_requests.fetch_sub(1, Ordering::AcqRel);
            self.active = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

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
    fn process_wide_stream_memory_and_blocking_leases_release() {
        let budget = Arc::new(ResourceBudget::default());
        let stream = budget
            .try_h2_stream_for(IpAddr::from([192, 0, 2, 1]))
            .unwrap();
        let mut request = budget.try_request_bytes();
        let mut response = budget.try_response_bytes();
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
        let mut retained = with_expensive_client(first, || {
            let mut lease = budget.try_response_bytes();
            lease
                .reserve(MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT)
                .unwrap();
            lease
        });
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
        let mut one = with_expensive_client(first, || budget.try_spool(100, 8).unwrap());
        one.reserve(25).unwrap();
        assert!(one.reserve(1).is_err());
        let two = budget.try_spool_for(100, 8, first).unwrap();
        assert!(budget.try_spool_for(100, 8, first).is_err());
        let mut other = budget.try_spool_for(100, 8, second).unwrap();
        other.reserve(25).unwrap();

        let mut unattributed = budget.try_spool(100, 8).unwrap();
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
            .map(|_| budget.try_h2_client_for(client).unwrap())
            .collect();
        assert!(budget.try_h2_stream_for(client).is_err());
        assert_eq!(budget.extended_usage().0, 0);
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
        let mut resident = ResidentLease::new(budget, ResidentKind::Request, 8);
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
