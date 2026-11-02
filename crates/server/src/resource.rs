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
use std::sync::{Arc, Mutex};

/// Every attacker-reachable concurrency slot is represented in this one
/// ledger. Byte reservations use the same `ResourceContext` below, but retain
/// their specialized adjustable leases because their charge changes while a
/// body is read or transformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum SlotKind {
    DynamicBackend,
    H2Stream,
    ResponseBodyRead,
    Websocket,
    ExpensiveCpu,
    PendingConnection,
    RequestWorker,
    RequestBodyWorker,
    H2Connection,
    TlsHandshake,
    RewriteProgram,
    SpoolFile,
}

impl SlotKind {
    const COUNT: usize = 12;

    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
enum ByteKind {
    Spool,
    RequestResident,
    ResponseResident,
    PolicyExpansion,
}

impl ByteKind {
    const COUNT: usize = 4;

    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug)]
struct ScopeUsage {
    slots: [AtomicU64; SlotKind::COUNT],
    bytes: [AtomicU64; ByteKind::COUNT],
}

impl Default for ScopeUsage {
    fn default() -> Self {
        Self {
            slots: std::array::from_fn(|_| AtomicU64::new(0)),
            bytes: std::array::from_fn(|_| AtomicU64::new(0)),
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
}

#[derive(Debug)]
pub struct ResourceBudget {
    slot_process: [AtomicU64; SlotKind::COUNT],
    slot_clients: Mutex<HashMap<IpAddr, [u64; SlotKind::COUNT]>>,
    byte_process: [AtomicU64; ByteKind::COUNT],
    byte_clients: Mutex<HashMap<IpAddr, [u64; ByteKind::COUNT]>>,
    rates: Mutex<RateLedger>,
    next_scope: AtomicU64,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            slot_process: std::array::from_fn(|_| AtomicU64::new(0)),
            slot_clients: Mutex::new(HashMap::new()),
            byte_process: std::array::from_fn(|_| AtomicU64::new(0)),
            byte_clients: Mutex::new(HashMap::new()),
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
    failed: AtomicBool,
}

impl Default for RequestPolicyBudget {
    fn default() -> Self {
        Self {
            work: AtomicU64::new(0),
            expansion_bytes: AtomicU64::new(0),
            expansion_lease: Mutex::new(None),
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
        if !try_add(&self.expansion_bytes, amount, MAX_POLICY_EXPANSION_BYTES) {
            self.failed.store(true, Ordering::Release);
            return Err("request policy expansion limit exceeded");
        }
        #[cfg(test)]
        let context = current_or_test_context();
        #[cfg(not(test))]
        let Some(context) = current_context() else {
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

#[derive(Debug)]
pub(crate) struct SlotLease {
    context: ResourceContext,
    kind: SlotKind,
    amount: u64,
    charged_client: bool,
    charged_request: bool,
    client_limit: Option<u64>,
    request_limit: Option<u64>,
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
        drop(clients);
        self.bytes += amount;
        Ok(())
    }

    fn release(&mut self, amount: u64) {
        let amount = amount.min(self.bytes);
        if amount == 0 {
            return;
        }
        let index = self.kind.index();
        self.context.budget.byte_process[index].fetch_sub(amount, Ordering::AcqRel);
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
    pub fn context(self: &Arc<Self>, client: IpAddr) -> ResourceContext {
        ResourceContext::for_client(self, client)
    }

    fn context_or_process(self: &Arc<Self>) -> ResourceContext {
        current_context()
            .filter(|context| Arc::ptr_eq(&context.budget, self))
            .unwrap_or_else(|| ResourceContext::process_only(self))
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
        drop(clients);
        Ok(SlotLease {
            context: context.clone(),
            kind,
            amount: 1,
            charged_client,
            charged_request,
            client_limit,
            request_limit,
            active: true,
        })
    }

    fn admit_rate(
        window: &mut RateWindow,
        client: Option<IpAddr>,
        now: std::time::Instant,
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
        if !vapache_verified::hierarchical_rate_admit(
            window.total,
            client_used,
            process_limit,
            client_limit,
            client.is_some(),
        ) {
            return false;
        }
        window.total += 1;
        if let Some(client) = client {
            window.clients.insert(client, client_used + 1);
        }
        true
    }

    pub fn try_spool(self: &Arc<Self>, max_bytes: u64, max_files: u64) -> io::Result<SpoolLease> {
        let context = current_context()
            .filter(|context| Arc::ptr_eq(context.budget(), self))
            .or_else(|| current_expensive_client().map(|client| self.context(client)))
            .unwrap_or_else(|| ResourceContext::process_only(self));
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
            _file_slot: file_slot,
        })
    }

    pub fn try_dynamic(self: &Arc<Self>, limit: u64) -> io::Result<DynamicLease> {
        let context = self.context_or_process();
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
        Ok(DynamicLease {
            _slot: context.slot(
                SlotKind::DynamicBackend,
                limit,
                Some(limit.min(MAX_DYNAMIC_REQUESTS_PER_CLIENT)),
                Some(1),
                "dynamic backend concurrency limit reached",
            )?,
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

    pub fn try_request_bytes(self: &Arc<Self>) -> ResidentLease {
        let context = self.context_or_process();
        ResidentLease::new(
            context,
            ResidentKind::Request,
            MAX_REQUEST_RESIDENT_BYTES,
            MAX_REQUEST_RESIDENT_BYTES_PER_CLIENT,
            MAX_REQUEST_RESIDENT_BYTES_PER_REQUEST,
        )
    }

    pub fn try_response_bytes(self: &Arc<Self>) -> ResidentLease {
        let context = current_context()
            .filter(|context| Arc::ptr_eq(context.budget(), self))
            .or_else(|| current_expensive_client().map(|client| self.context(client)))
            .unwrap_or_else(|| ResourceContext::process_only(self));
        ResidentLease::new(
            context,
            ResidentKind::Response,
            MAX_RESPONSE_RESIDENT_BYTES,
            MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT,
            MAX_RESPONSE_RESIDENT_BYTES_PER_REQUEST,
        )
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

    /// Reserve one short blocking read of a response-body descriptor.
    ///
    /// This permit deliberately excludes request dispatch and downstream
    /// socket waits. Holding it across either boundary lets a client exhaust
    /// the read capacity without causing any read work (P30-A/A').
    pub fn try_response_body_read(self: &Arc<Self>) -> io::Result<ResponseBodyReadLease> {
        let context = self.context_or_process();
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
            self.byte_process[ByteKind::Spool.index()].load(Ordering::Acquire),
            self.slot_usage(SlotKind::SpoolFile),
            self.slot_usage(SlotKind::DynamicBackend),
        )
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn extended_usage(&self) -> (u64, u64, u64, u64) {
        (
            self.slot_usage(SlotKind::H2Stream),
            self.byte_process[ByteKind::RequestResident.index()].load(Ordering::Acquire),
            self.byte_process[ByteKind::ResponseResident.index()].load(Ordering::Acquire),
            self.slot_usage(SlotKind::ResponseBodyRead),
        )
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn websocket_usage(&self) -> u64 {
        self.slot_usage(SlotKind::Websocket)
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
}

#[derive(Debug)]
pub struct CombinedH2Lease {
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
    Some(ExpensiveLease {
        _slot: context
            .slot(
                SlotKind::ExpensiveCpu,
                MAX_EXPENSIVE_OPS,
                Some(MAX_EXPENSIVE_OPS_PER_CLIENT),
                Some(MAX_EXPENSIVE_OPS_PER_CLIENT),
                "expensive operation limit reached",
            )
            .ok()?,
    })
}

#[derive(Debug)]
pub struct SpoolLease {
    bytes: ByteLease,
    _file_slot: SlotLease,
}

impl SpoolLease {
    pub fn reserve(&mut self, amount: u64) -> io::Result<()> {
        self.bytes
            .reserve(amount, "hierarchical spool-byte limit reached")
            .map_err(|error| io::Error::new(io::ErrorKind::StorageFull, error))
    }

    pub fn attribute_client(&mut self, client: IpAddr) -> io::Result<()> {
        let context = self.bytes.context.budget.context(client);
        self._file_slot.attribute_context(context.clone())?;
        if let Err(error) = self.bytes.attribute_context(context) {
            // A failed byte attribution must not leave the file slot owned by
            // a different scope. Move it back before reporting failure.
            let old = self.bytes.context.clone();
            let _ = self._file_slot.attribute_context(old);
            return Err(error);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DynamicLease {
    _slot: SlotLease,
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
        let mut request = budget.try_request_bytes();
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
