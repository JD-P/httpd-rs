//! HTTP/2 over TLS (RFC 9113) using the `h2` state machine.
//!
//! HTTP/2 has no request line, chunked framing, or Connection headers.  We
//! translate each stream into the same internal `Request` used by the strict
//! HTTP/1 parser and reuse the central dispatcher, so access control, path
//! canonicalisation, file serving and CGI policy are identical on both
//! protocols.

use crate::config::Config;
use crate::http::{
    Body, BodyAccumulator, Request, Response, SpooledBody, Version, REQUEST_BODY_SPOOL_PREFIX,
};
use crate::log::{AccessEntry, Logger};
use crate::resource::{ResidentLease, ResourceBudget};
use crate::util::{http_date_now, trim_ascii};
use bytes::Bytes;
use http::{HeaderName, HeaderValue, StatusCode};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;

#[cfg(not(test))]
const H2_RESET_RECLAIM: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(test)]
const H2_RESET_RECLAIM: std::time::Duration = std::time::Duration::from_millis(1);
#[cfg(not(test))]
const H2_IDLE_FLOOR: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(test)]
const H2_IDLE_FLOOR: std::time::Duration = std::time::Duration::from_millis(20);
#[cfg(not(test))]
const H2_STREAM_FLOOR: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(test)]
const H2_STREAM_FLOOR: std::time::Duration = std::time::Duration::from_millis(20);
#[cfg(not(test))]
const H2_SLOW_CLASSIFY_GRACE: Duration = Duration::from_millis(100);
#[cfg(test)]
const H2_SLOW_CLASSIFY_GRACE: Duration = Duration::from_millis(2);

#[derive(Clone, Copy)]
enum H2TaskEvent {
    Ended { stream_id: u64, reset: bool },
}

#[derive(Clone, Copy)]
struct H2StreamRecord {
    id: u64,
    phase: httpd_rs_verified::H2StreamPhase,
}

/// One adapter-side lifecycle ledger owns stream identity, phase and aggregate
/// capacity. Transitions are computed completely before mutation, so a failed
/// phase or budget transition cannot update only half of the accounting state.
struct H2ConnectionLedger {
    budget: httpd_rs_verified::H2Budget,
    streams: Vec<H2StreamRecord>,
}

impl H2ConnectionLedger {
    fn new(max_active: u64, max_pending_resets: u64) -> Self {
        Self {
            budget: httpd_rs_verified::h2_budget_new(max_active, max_pending_resets),
            streams: Vec::new(),
        }
    }

    fn active(&self) -> u64 {
        self.budget.active
    }

    fn pending_resets(&self) -> u64 {
        self.budget.pending_resets
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn is_consistent(&self) -> bool {
        let active = self
            .streams
            .iter()
            .filter(|stream| stream.phase == httpd_rs_verified::H2StreamPhase::Active)
            .count() as u64;
        let pending = self
            .streams
            .iter()
            .filter(|stream| stream.phase == httpd_rs_verified::H2StreamPhase::AwaitingReset)
            .count() as u64;
        let unique = self.streams.iter().enumerate().all(|(index, stream)| {
            self.streams[index + 1..]
                .iter()
                .all(|other| stream.id != other.id)
        });
        unique
            && active == self.active()
            && pending == self.pending_resets()
            && self.active() <= self.budget.max_active
            && self.pending_resets() <= self.budget.max_pending_resets
            && active.saturating_add(pending) == self.streams.len() as u64
    }

    fn begin(&mut self, stream_id: u64) -> bool {
        if self.streams.iter().any(|stream| stream.id == stream_id) {
            return false;
        }
        let Some(phase) = httpd_rs_verified::h2_stream_phase_step(
            httpd_rs_verified::H2StreamPhase::Idle,
            httpd_rs_verified::H2StreamEvent::Begin,
        ) else {
            return false;
        };
        let Some(budget) =
            httpd_rs_verified::h2_budget_step(self.budget, httpd_rs_verified::H2BudgetEvent::Begin)
        else {
            return false;
        };
        self.budget = budget;
        self.streams.push(H2StreamRecord {
            id: stream_id,
            phase,
        });
        true
    }

    fn end(&mut self, stream_id: u64, reset: bool) -> bool {
        let Some(index) = self
            .streams
            .iter()
            .position(|stream| stream.id == stream_id)
        else {
            return false;
        };
        let event = if reset {
            httpd_rs_verified::H2StreamEvent::Reset
        } else {
            httpd_rs_verified::H2StreamEvent::Finish
        };
        let Some(phase) = httpd_rs_verified::h2_stream_phase_step(self.streams[index].phase, event)
        else {
            return false;
        };
        let Some(finished) = httpd_rs_verified::h2_budget_step(
            self.budget,
            httpd_rs_verified::H2BudgetEvent::Finish,
        ) else {
            return false;
        };
        let budget = if reset {
            let Some(reset_budget) = httpd_rs_verified::h2_budget_step(
                finished,
                httpd_rs_verified::H2BudgetEvent::Reset,
            ) else {
                return false;
            };
            reset_budget
        } else {
            finished
        };
        self.budget = budget;
        self.streams[index].phase = phase;
        if !reset {
            self.streams.swap_remove(index);
        }
        true
    }

    fn reclaim(&mut self, stream_id: u64) -> bool {
        let Some(index) = self
            .streams
            .iter()
            .position(|stream| stream.id == stream_id)
        else {
            return false;
        };
        let Some(phase) = httpd_rs_verified::h2_stream_phase_step(
            self.streams[index].phase,
            httpd_rs_verified::H2StreamEvent::Reclaim,
        ) else {
            return false;
        };
        let Some(budget) = httpd_rs_verified::h2_budget_step(
            self.budget,
            httpd_rs_verified::H2BudgetEvent::Reclaim,
        ) else {
            return false;
        };
        debug_assert_eq!(phase, httpd_rs_verified::H2StreamPhase::Closed);
        self.budget = budget;
        self.streams.swap_remove(index);
        true
    }

    fn close(&mut self) -> bool {
        if self.streams.iter().any(|stream| {
            httpd_rs_verified::h2_stream_phase_step(
                stream.phase,
                httpd_rs_verified::H2StreamEvent::ConnectionClose,
            ) != Some(httpd_rs_verified::H2StreamPhase::Closed)
        }) {
            return false;
        }
        let Some(budget) = httpd_rs_verified::h2_budget_step(
            self.budget,
            httpd_rs_verified::H2BudgetEvent::ConnectionClose,
        ) else {
            return false;
        };
        self.budget = budget;
        self.streams.clear();
        self.active() == 0 && self.pending_resets() == 0
    }
}

/// Releases an active slot even if the stream task panics or is cancelled.
/// The normal path overwrites `reset` with the observed result; unwinding
/// conservatively reports a reset so the connection fails closed rather than
/// leaking capacity.
struct H2TaskEventGuard {
    tx: mpsc::Sender<H2TaskEvent>,
    stream_id: u64,
    reset: bool,
}

/// Cancellation authority exists from stream admission, before the decoded
/// request is assembled. Dropping the connection-owned task therefore
/// cancels backend/body work even if the task exits during header projection
/// or while a blocking dispatcher owns a clone of the request.
struct H2RequestCancelGuard {
    scope: crate::resource::RequestScope,
}

impl Drop for H2RequestCancelGuard {
    fn drop(&mut self) {
        self.scope.cancel();
    }
}

impl Drop for H2TaskEventGuard {
    fn drop(&mut self) {
        // Capacity equals the maximum admitted stream count and each guard
        // emits once. The connection loop prioritizes these events before
        // accepting another stream, so a live connection cannot overflow the
        // terminal queue; teardown may only observe a closed receiver.
        let _ = self.tx.try_send(H2TaskEvent::Ended {
            stream_id: self.stream_id,
            reset: self.reset,
        });
    }
}

enum H2ReadFailure {
    /// The peer sent RST_STREAM.  Do not attempt a response; report the
    /// observed reset to the connection-level budget.
    Reset,
    BackendClosed,
    Response(Response),
}

struct H2RequestBody {
    bytes: Vec<u8>,
    spool: Option<Arc<SpooledBody>>,
    len: u64,
}

fn request_target(method: &str, uri: &http::Uri, https: bool) -> Option<Vec<u8>> {
    // Accessors synthesize `/` for an absolute URI whose stored
    // `path_and_query` is absent.  Inspect the raw URI parts so a missing
    // HTTP/2 :path cannot silently become a request for the server root.
    let parts = uri.clone().into_parts();
    let path = parts.path_and_query.as_ref();
    let serialized = uri.to_string();
    let scheme_matches = parts.scheme.as_ref().is_some_and(|scheme| {
        scheme
            .as_str()
            .eq_ignore_ascii_case(if https { "https" } else { "http" })
    });
    let authority_valid = parts.authority.as_ref().is_some_and(|authority| {
        crate::util::parse_http_authority(
            authority.as_str().as_bytes(),
            if https { 443 } else { 80 },
        )
        .is_some()
    });
    let admitted = httpd_rs_verified::h2_request_target_admit(
        method.eq_ignore_ascii_case("CONNECT"),
        parts.scheme.is_some(),
        scheme_matches,
        parts.authority.is_some(),
        authority_valid,
        path.is_some(),
        path.is_some_and(|value| !value.as_str().is_empty()),
        serialized.as_bytes().contains(&b'#'),
    );
    admitted.then(|| path.expect("admitted path").as_str().as_bytes().to_vec())
}

/// Reuse bounded file/stream chunks across responses. The pool retains at
/// most 4 MiB and receives a buffer only after h2 releases the last `Bytes`
/// slice and its live response-resident lease.
const POOL_MIN_CAPACITY: usize = 64 * 1024;
// Match the verified per-stream send-buffer ceiling so a large cached file
// needs at most four blocking reads per MiB instead of sixteen. Capacity is
// still acquired before allocation/read, and the pool's total retained-byte
// ceiling remains unchanged.
const POOL_MAX_CAPACITY: usize = 256 * 1024;
const POOL_MAX_TOTAL: usize = 4 * 1024 * 1024;
const POOL_MAX_ENTRIES: usize = 64;

#[derive(Default)]
struct BodyPool {
    free: Vec<Vec<u8>>,
    bytes: usize,
}

fn body_pool() -> &'static Mutex<BodyPool> {
    static POOL: OnceLock<Mutex<BodyPool>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(BodyPool::default()))
}

fn take_body_buffer(len: usize) -> Vec<u8> {
    let mut pool = body_pool().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(index) = pool.free.iter().position(|buf| {
        buf.capacity() >= len && buf.capacity() <= len.saturating_mul(2).max(len + 4096)
    }) {
        let buf = pool.free.swap_remove(index);
        pool.bytes = pool.bytes.saturating_sub(buf.capacity());
        return buf;
    }
    Vec::with_capacity(len)
}

struct PooledBuffer {
    buf: Option<Vec<u8>>,
    _resident: Arc<Mutex<ResidentLease>>,
    _transport: Arc<QueuedH2TransportState>,
}

struct AccountedResponseBytes {
    data: Vec<u8>,
    _resident: Arc<Mutex<ResidentLease>>,
    _transport: Arc<QueuedH2TransportState>,
}

struct QueuedResponseHeadOwnership {
    resident: Arc<Mutex<ResidentLease>>,
    transport: Arc<QueuedH2TransportState>,
}

struct AccountedResponseHeaderValue {
    data: Vec<u8>,
    _resident: Arc<Mutex<ResidentLease>>,
    _transport: Arc<QueuedH2TransportState>,
}

#[derive(Default)]
struct QueuedH2TransportState {
    admission: Mutex<Option<crate::resource::QueuedH2TransportLease>>,
}

impl QueuedH2TransportState {
    fn install(&self, admission: Option<crate::resource::QueuedH2TransportLease>) {
        let Some(admission) = admission else {
            return;
        };
        let mut current = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            current.replace(admission).is_none(),
            "HTTP/2 transport admission installed twice"
        );
    }
}

struct QueuedH2TransportMarker {
    _transport: Arc<QueuedH2TransportState>,
}

impl AsRef<[u8]> for AccountedResponseBytes {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsRef<[u8]> for AccountedResponseHeaderValue {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsRef<[u8]> for QueuedH2TransportMarker {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] {
        self.buf.as_deref().unwrap_or(&[])
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        let Some(buf) = self.buf.take() else {
            return;
        };
        let capacity = buf.capacity();
        if capacity < POOL_MIN_CAPACITY || capacity > POOL_MAX_CAPACITY {
            return;
        }
        let mut pool = body_pool().lock().unwrap_or_else(|e| e.into_inner());
        if pool.free.len() < POOL_MAX_ENTRIES
            && pool.bytes.saturating_add(capacity) <= POOL_MAX_TOTAL
        {
            pool.bytes += capacity;
            pool.free.push(buf);
        }
    }
}

fn response_chunk_lease(
    budget: &Arc<ResourceBudget>,
    client: std::net::IpAddr,
    len: usize,
) -> io::Result<ResidentLease> {
    let mut resident = budget.try_response_bytes_for(client);
    resident.reserve(len as u64)?;
    Ok(resident)
}

fn response_header_value(
    value: Vec<u8>,
    ownership: &mut Option<QueuedResponseHeadOwnership>,
) -> Result<HeaderValue, http::header::InvalidHeaderValue> {
    match ownership.take() {
        Some(QueuedResponseHeadOwnership {
            resident,
            transport,
        }) => {
            let mut value =
                HeaderValue::from_maybe_shared(Bytes::from_owner(AccountedResponseHeaderValue {
                    data: value,
                    _resident: resident,
                    _transport: transport,
                }))?;
            // The HPACK encoder stores indexable HeaderValue objects in its
            // dynamic table. This field is an ownership carrier, so allowing
            // it to be indexed would retain the completed response's leases
            // until table eviction or connection close.
            value.set_sensitive(true);
            Ok(value)
        }
        None => HeaderValue::from_bytes(&value),
    }
}

fn retain_queued_h2_transport(
    output: &mut crate::resource::SlowOutputAdmission,
    transport: &Arc<QueuedH2TransportState>,
) -> io::Result<()> {
    transport.install(output.retain_queued_h2_transport()?);
    Ok(())
}

fn queued_h2_transport_marker(transport: &Arc<QueuedH2TransportState>) -> Bytes {
    Bytes::from_owner(QueuedH2TransportMarker {
        _transport: transport.clone(),
    })
}

fn read_range(
    file: &std::fs::File,
    offset: u64,
    len: usize,
    resident: Arc<Mutex<ResidentLease>>,
    transport: Arc<QueuedH2TransportState>,
) -> io::Result<Bytes> {
    let mut buf = take_body_buffer(len);
    // Keep pooled buffers initialized between responses. The generic
    // `Read::read_to_end` fallback issues small repeated reads for this
    // positional wrapper; reading the admitted slice directly normally turns
    // a 256 KiB cached chunk into one `pread64` call.
    buf.resize(len, 0);
    let mut filled = 0usize;
    while filled < len {
        match file.read_at(&mut buf[filled..], offset.saturating_add(filled as u64)) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    buf.truncate(filled);
    Ok(Bytes::from_owner(PooledBuffer {
        buf: Some(buf),
        _resident: resident,
        _transport: transport,
    }))
}

fn bad(status: u16, message: &str) -> Response {
    let body = format!(
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head><title>{status} {}</title></head><body><h1>{}</h1><p>{}</p></body></html>\n",
        crate::http::reason_phrase(status),
        crate::http::reason_phrase(status),
        crate::util::html_escape(message.as_bytes())
    );
    Response::bytes(status, "text/html; charset=iso-8859-1", body.into_bytes())
}

fn head_error_response(decision: httpd_rs_verified::H2HeadDecision) -> Option<Response> {
    match decision {
        httpd_rs_verified::H2HeadDecision::Accept => None,
        httpd_rs_verified::H2HeadDecision::InvalidMethod => Some(bad(400, "invalid HTTP/2 method")),
        httpd_rs_verified::H2HeadDecision::TargetTooLong => {
            Some(bad(414, "request target too long"))
        }
        httpd_rs_verified::H2HeadDecision::TooManyHeaders => {
            Some(bad(431, "too many request headers"))
        }
        httpd_rs_verified::H2HeadDecision::HeaderFieldTooLarge => {
            Some(bad(431, "request header field too large"))
        }
    }
}

fn canonicalize_content_length(headers: &mut crate::http::Headers) -> Result<Option<u64>, ()> {
    let mut declared = None;
    for value in headers.get_all("content-length") {
        // Match the strict HTTP/1 boundary: one decimal field, with only
        // HTTP OWS around it. `Headers::push_merged` exposes duplicates as a
        // comma list, so this also rejects identical repeated values rather
        // than passing a non-canonical CONTENT_LENGTH to CGI/FastCGI.
        if declared.is_some() || value.contains(&b',') {
            return Err(());
        }
        let value = trim_ascii(value);
        let Some(length) = httpd_rs_verified::parse_decimal_u64(value) else {
            return Err(());
        };
        declared = Some(length);
    }
    if let Some(length) = declared {
        headers.insert("content-length", length.to_string().into_bytes());
    }
    Ok(declared)
}

fn forbidden_h2_header(name: &str, value: &[u8]) -> bool {
    !crate::verified::h2_header_field_admit(name.as_bytes(), value)
}

struct H2HeadProjection {
    request: Request,
    declared: Option<u64>,
}

fn project_h2_target(
    method: &str,
    uri: &http::Uri,
    https: bool,
    field_size_limit: usize,
) -> Result<Vec<u8>, Response> {
    if uri.authority().is_some_and(|authority| {
        !httpd_rs_verified::h2_field_size_admit(
            b"host".len() as u64,
            authority.as_str().len() as u64,
            field_size_limit as u64,
        )
    }) {
        return Err(bad(431, "request header field too large"));
    }
    request_target(method, uri, https).ok_or_else(|| bad(400, "invalid HTTP/2 request target"))
}

/// Project the decoded HTTP/2 pseudo-header/header view into the same
/// canonical `Request` consumed by HTTP/1 dispatch. This function owns the
/// complete adapter boundary and is also used by the whole-request
/// differential fuzzer; keeping one implementation prevents the oracle from
/// silently drifting away from production.
fn project_h2_head(
    method: String,
    target: Vec<u8>,
    authority: Option<&str>,
    fields: &http::HeaderMap,
    request_line_limit: usize,
    field_count_limit: usize,
    field_size_limit: usize,
) -> Result<H2HeadProjection, Response> {
    let (raw_path, query) = match target.iter().position(|byte| *byte == b'?') {
        Some(index) => (target[..index].to_vec(), target[index + 1..].to_vec()),
        None => (target.clone(), Vec::new()),
    };

    let mut headers = crate::http::Headers::default();
    let mut header_budget =
        httpd_rs_verified::h2_header_init(httpd_rs_verified::h2_settings().max_header_list as u64);
    let mut header_count = 0u64;
    let mut largest_field = 0u64;
    for (name, value) in fields.iter() {
        let field_len = name.as_str().len().saturating_add(value.as_bytes().len()) as u64;
        let Some(next) = httpd_rs_verified::h2_header_add(header_budget, field_len) else {
            return Err(bad(431, "request header list too large"));
        };
        header_budget = next;
        header_count = header_count.saturating_add(1);
        largest_field = largest_field.max(field_len);
        if forbidden_h2_header(name.as_str(), value.as_bytes()) {
            return Err(bad(400, "connection-specific HTTP/2 header"));
        }

        // :authority is authoritative. A legacy Host field still consumes
        // the configured head budgets but cannot select a second identity.
        if name.as_str() == "host" {
            continue;
        }
        headers.push_merged(name.as_str(), value.as_bytes());
    }
    if let Some(authority) = authority {
        let value = authority.as_bytes();
        let field_len = b"host".len().saturating_add(value.len()) as u64;
        let Some(next) = httpd_rs_verified::h2_header_add(header_budget, field_len) else {
            return Err(bad(431, "request header list too large"));
        };
        header_budget = next;
        header_count = header_count.saturating_add(1);
        largest_field = largest_field.max(field_len);
        headers.push("host", value.to_vec());
    }
    let _ = header_budget;

    if let Some(response) = head_error_response(httpd_rs_verified::h2_head_admit(
        method.as_bytes(),
        target.len() as u64,
        request_line_limit as u64,
        header_count,
        field_count_limit as u64,
        largest_field,
        field_size_limit as u64,
    )) {
        return Err(response);
    }
    let declared = canonicalize_content_length(&mut headers)
        .map_err(|()| bad(400, "invalid Content-Length"))?;

    Ok(H2HeadProjection {
        request: Request {
            method,
            target,
            raw_path,
            query,
            version: Version::Http2,
            headers,
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            // DATA framing remains owned by h2. The caller installs the
            // shared logical body marker after observing END_STREAM/CL.
            framing: crate::verified::BodyFraming::None,
        },
        declared,
    })
}

async fn read_body(
    mut recv: h2::RecvStream,
    limit: u64,
    timeout: std::time::Duration,
    min_rate: u64,
    resource_budget: Arc<crate::resource::ResourceBudget>,
    max_spool_bytes: u64,
    max_spool_files: u64,
    resource_context: crate::resource::ResourceContext,
    request_scope: &crate::resource::RequestScope,
    resident: &mut crate::resource::ResidentLease,
    allow_trailers: bool,
) -> Result<H2RequestBody, H2ReadFailure> {
    // HTTP/2 can run many request bodies concurrently on one connection.  A
    // small per-stream prefix keeps ordinary forms cheap while the process-
    // wide spool budget bounds larger concurrent bodies.
    let mut body = BodyAccumulator::new_in(
        REQUEST_BODY_SPOOL_PREFIX,
        resource_budget,
        max_spool_bytes,
        max_spool_files,
        Some(resource_context),
    );
    let mut budget = httpd_rs_verified::h2_body_init(limit);
    let mut framing = httpd_rs_verified::ChunkFramingState {
        chunks: 0,
        bytes: 0,
    };
    let started = Instant::now();
    loop {
        // One deadline covers the complete body.  Restarting the timeout for
        // every DATA frame lets a slow peer keep a request alive forever.
        let remaining = timeout.saturating_sub(started.elapsed());
        if crate::fault::hit("transition.h2.body.data-await").is_err() {
            return Err(H2ReadFailure::Response(bad(
                503,
                "request-body transition aborted",
            )));
        }
        let next = match tokio::time::timeout(remaining, recv.data()).await {
            Ok(next) => next,
            Err(_) => return Err(H2ReadFailure::Response(bad(408, "request body timeout"))),
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            // `handle_stream` polls `SendResponse::poll_reset` first with a
            // biased select, and h2 rejects other malformed DATA frames in its
            // connection driver.  Keep these defensive RecvStream mappings.
            // coverage:ignore-start - upstream h2 state-machine invariant
            Err(e) if e.is_reset() => return Err(H2ReadFailure::Reset),
            Err(_) => {
                return Err(H2ReadFailure::Response(bad(
                    400,
                    "malformed HTTP/2 request body",
                )))
            } // coverage:ignore-stop
        };
        // DATA payload limits do not bound frame-processing work: a peer can
        // encode a small body as tens of thousands of one-byte frames. Charge
        // the nine-byte HTTP/2 frame header and one work unit per delivered
        // DATA frame, using the same verified budget shape as HTTP/1 chunks.
        let Some(next_framing) =
            httpd_rs_verified::chunk_framing_budget_step(framing, 5, true, 65_536, 1024 * 1024)
        else {
            return Err(H2ReadFailure::Response(bad(
                400,
                "HTTP/2 DATA frame budget exceeded",
            )));
        };
        framing = next_framing;
        let Some(next_budget) = httpd_rs_verified::h2_body_append(budget, chunk.len() as u64)
        else {
            return Err(H2ReadFailure::Response(bad(413, "request body too large")));
        };
        budget = next_budget;
        if let Err(error) = crate::http::push_body_without_blocking_runtime(
            &mut body,
            resident,
            &chunk,
            Some(request_scope),
        ) {
            let response = if matches!(
                error.kind(),
                io::ErrorKind::StorageFull | io::ErrorKind::OutOfMemory
            ) {
                bad(503, "request-body capacity exhausted")
            } else {
                bad(500, "cannot spool request body")
            };
            return Err(H2ReadFailure::Response(response));
        }
        if !crate::http::minimum_read_rate_ok(started, body.len(), min_rate) {
            return Err(H2ReadFailure::Response(bad(
                408,
                "request body minimum rate not met",
            )));
        }
        // Return consumed receive-window capacity to h2.  Without this, any
        // body larger than the initial connection window stalls permanently.
        if recv.flow_control().release_capacity(chunk.len()).is_err() {
            return Err(H2ReadFailure::Reset); // coverage:ignore-line - opaque h2 reset race
        }
        debug_assert_eq!(body.len(), budget.len);
    }
    read_trailers(&mut recv, started, timeout, allow_trailers).await?;
    let len = body.len();
    let (bytes, spool) = body.finish();
    Ok(H2RequestBody { bytes, spool, len })
}

async fn stream_body(
    mut recv: h2::RecvStream,
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    declared: u64,
    limit: u64,
    timeout: std::time::Duration,
    min_rate: u64,
    allow_trailers: bool,
) -> Result<(), H2ReadFailure> {
    let mut budget = httpd_rs_verified::h2_body_init(limit);
    let mut framing = httpd_rs_verified::ChunkFramingState {
        chunks: 0,
        bytes: 0,
    };
    let started = Instant::now();
    loop {
        let remaining = timeout.saturating_sub(started.elapsed());
        if crate::fault::hit("transition.h2.body.data-await").is_err() {
            return Err(H2ReadFailure::Response(bad(
                503,
                "request-body transition aborted",
            )));
        }
        let next = match tokio::time::timeout(remaining, recv.data()).await {
            Ok(next) => next,
            Err(_) => return Err(H2ReadFailure::Response(bad(408, "request body timeout"))),
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) if error.is_reset() => return Err(H2ReadFailure::Reset),
            Err(_) => {
                return Err(H2ReadFailure::Response(bad(
                    400,
                    "malformed HTTP/2 request body",
                )))
            }
        };
        let Some(next_framing) =
            httpd_rs_verified::chunk_framing_budget_step(framing, 5, true, 65_536, 1024 * 1024)
        else {
            return Err(H2ReadFailure::Response(bad(
                400,
                "HTTP/2 DATA frame budget exceeded",
            )));
        };
        framing = next_framing;
        let Some(next_budget) = httpd_rs_verified::h2_body_append(budget, chunk.len() as u64)
        else {
            return Err(H2ReadFailure::Response(bad(413, "request body too large")));
        };
        if next_budget.len > declared {
            return Err(H2ReadFailure::Response(bad(400, "Content-Length mismatch")));
        }
        budget = next_budget;
        let chunk_len = chunk.len();
        let remaining = timeout.saturating_sub(started.elapsed());
        if crate::fault::hit("transition.h2.body.backend-await").is_err() {
            return Err(H2ReadFailure::Response(bad(
                503,
                "backend body transition aborted",
            )));
        }
        match tokio::time::timeout(remaining, sender.send(chunk.to_vec())).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(H2ReadFailure::BackendClosed),
            Err(_) => return Err(H2ReadFailure::Response(bad(408, "request body timeout"))),
        }
        if !crate::http::minimum_read_rate_ok(started, budget.len, min_rate) {
            return Err(H2ReadFailure::Response(bad(
                408,
                "request body minimum rate not met",
            )));
        }
        if recv.flow_control().release_capacity(chunk_len).is_err() {
            return Err(H2ReadFailure::Reset);
        }
    }
    read_trailers(&mut recv, started, timeout, allow_trailers).await?;
    if budget.len != declared {
        return Err(H2ReadFailure::Response(bad(400, "Content-Length mismatch")));
    }
    Ok(())
}

const H2_MAX_REQUEST_TRAILERS: usize = 64;
const H2_MAX_REQUEST_TRAILER_BYTES: usize = 64 * 1024;

/// Consume the terminal trailer block instead of dropping it unseen. The h2
/// codec owns HPACK and END_STREAM validation, while this adapter owns the
/// same capability, routing-field and size policy as HTTP/1 chunked bodies.
async fn read_trailers(
    recv: &mut h2::RecvStream,
    started: Instant,
    timeout: Duration,
    allow_trailers: bool,
) -> Result<(), H2ReadFailure> {
    let remaining = timeout.saturating_sub(started.elapsed());
    if crate::fault::hit("transition.h2.body.trailers-await").is_err() {
        return Err(H2ReadFailure::Response(bad(
            503,
            "request-trailer transition aborted",
        )));
    }
    let trailers = match tokio::time::timeout(remaining, recv.trailers()).await {
        Err(_) => return Err(H2ReadFailure::Response(bad(408, "request body timeout"))),
        Ok(Err(error)) if error.is_reset() => return Err(H2ReadFailure::Reset),
        Ok(Err(_)) => {
            return Err(H2ReadFailure::Response(bad(
                400,
                "malformed HTTP/2 request trailers",
            )))
        }
        Ok(Ok(trailers)) => trailers,
    };
    let Some(trailers) = trailers else {
        return Ok(());
    };
    if !httpd_rs_verified::capability_admit(allow_trailers, !trailers.is_empty()) {
        return Err(H2ReadFailure::Response(bad(
            400,
            "request trailers are disabled",
        )));
    }
    let mut count = 0usize;
    let mut bytes = 0usize;
    for (name, value) in trailers.iter() {
        count = count.saturating_add(1);
        bytes = bytes
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(2);
        if count > H2_MAX_REQUEST_TRAILERS || bytes > H2_MAX_REQUEST_TRAILER_BYTES {
            return Err(H2ReadFailure::Response(bad(
                400,
                "request trailers are too large",
            )));
        }
        let mut line = Vec::with_capacity(name.as_str().len() + value.as_bytes().len() + 1);
        line.extend_from_slice(name.as_str().as_bytes());
        line.push(b':');
        line.extend_from_slice(value.as_bytes());
        if !crate::http::valid_trailer_field(&line) {
            return Err(H2ReadFailure::Response(bad(400, "invalid request trailer")));
        }
    }
    Ok(())
}

// The h2 crate owns these capacity terminal states.  The bounded sender is
// integration-tested for normal, stalled and reset streams; individual error
// variants cannot be constructed through its public API.
// coverage:ignore-start - opaque upstream h2 error variants
fn send_io_error(e: h2::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}
// coverage:ignore-stop

async fn poll_send_capacity(send: &mut h2::SendStream<Bytes>) -> io::Result<usize> {
    loop {
        match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(n)) if n > 0 => return Ok(n),
            Some(Ok(_)) => continue, // coverage:ignore-line - h2 never assigns zero
            Some(Err(e)) => return Err(send_io_error(e)), // coverage:ignore-line - opaque h2 error
            None => {
                // coverage:ignore-start - opaque upstream h2 closure state
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "HTTP/2 send stream closed",
                ));
                // coverage:ignore-stop
            }
        }
    }
}

async fn send_capacity(
    send: &mut h2::SendStream<Bytes>,
    remaining: usize,
    output: &mut crate::resource::SlowOutputAdmission,
    progress: &mut crate::resource::SlowOutputProgress,
    ownership: &mut crate::http::ResponseOwnership,
) -> io::Result<usize> {
    crate::fault::hit("transition.h2.output.capacity-await")?;
    // A reader may legally return a short chunk without reaching EOF.  In
    // that case the stream still owns part of the capacity assigned for the
    // previous read. `poll_capacity` reports newly assigned capacity, not a
    // replay of that remainder, so waiting again can deadlock forever.
    let assigned = send.capacity().min(remaining);
    if assigned > 0 {
        return Ok(assigned);
    }
    send.reserve_capacity(remaining);
    if !output.is_slow() {
        let remaining_grace = progress.remaining_classification_grace(H2_SLOW_CLASSIFY_GRACE);
        let wait_started = Instant::now();
        match tokio::time::timeout(remaining_grace, poll_send_capacity(send)).await {
            Ok(result) => {
                progress.record_blocked(wait_started.elapsed());
                return result;
            }
            Err(_) => {
                progress.record_blocked(wait_started.elapsed());
                output.enter_slow_with(|| ownership.enter_slow())?;
            }
        }
    }
    loop {
        let now = Instant::now();
        progress.validate(now)?;
        let deadline = tokio::time::Instant::from_std(progress.next_deadline());
        match tokio::time::timeout_at(deadline, poll_send_capacity(send)).await {
            Ok(result) => {
                let capacity = result?;
                progress.validate(Instant::now())?;
                return Ok(capacity);
            }
            Err(_) => progress.validate(Instant::now())?,
        }
    }
}

/// Send DATA only after the h2 crate has assigned capacity.  Without this,
/// `send_data` queues an unbounded amount of response bytes when a client
/// advertises a zero/small flow-control window.  Each chunk is split to the
/// assigned capacity, so pending bytes are bounded by the window.
async fn send_data_bounded(
    send: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end: bool,
    output: &mut crate::resource::SlowOutputAdmission,
    progress: &mut crate::resource::SlowOutputProgress,
    ownership: &mut crate::http::ResponseOwnership,
) -> io::Result<()> {
    if data.is_empty() {
        return send.send_data(data, end).map_err(send_io_error);
    }
    let mut offset = 0usize;
    while offset < data.len() {
        let remaining = data.len() - offset;
        let capacity = send_capacity(send, remaining, output, progress, ownership).await?;
        let n = capacity.min(remaining);
        let last = end && offset + n == data.len();
        send.send_data(data.slice(offset..offset + n), last)
            .map_err(send_io_error)?;
        offset += n;
        progress.record(n);
    }
    Ok(())
}

async fn send_response_with_admission(
    mut respond: h2::server::SendResponse<Bytes>,
    cfg: &Config,
    mut resp: Response,
    head_only: bool,
    output: &mut crate::resource::SlowOutputAdmission,
) -> io::Result<u64> {
    crate::fault::hit("transition.h2.output.start")?;
    let client = output.client();
    if !crate::http::response_headers_valid(&resp) {
        // Do not silently discard just the malformed fields and forward the
        // backend-selected body.  HTTP/2 can still return a canonical local
        // policy error because no response head has been committed yet.
        resp = Response::policy_error();
    }
    if resp.ensure_file_descriptor(&cfg.resource_budget).is_err() {
        resp = Response::memory_overload();
    }
    if resp.attribute_spool_client(client).is_err() {
        resp = Response::memory_overload();
    }
    if resp
        .admit_resident_for(&cfg.resource_budget, client)
        .is_err()
    {
        resp = Response::memory_overload();
        resp.admit_resident_for(&cfg.resource_budget, client)?;
    }
    let status = StatusCode::from_u16(resp.status)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid response status"))?;
    let no_body = status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::RESET_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || head_only;
    let body_len = resp.body.known_len();
    let end = no_body || body_len == Some(0);
    let preserved_content_length =
        crate::http::preserved_response_content_length(&resp, head_only)?;
    let header_sanitizer = crate::http::ResponseHeaderSanitizer::from_response(&resp)?;
    let mut ownership = resp.take_retained_output_ownership();
    let resident = ownership.share_resident()?;
    let transport = Arc::new(QueuedH2TransportState::default());
    let mut queued_head_ownership = Some(QueuedResponseHeadOwnership {
        resident: resident.clone(),
        transport: transport.clone(),
    });

    let mut out = http::Response::builder().status(status);
    {
        let headers = out.headers_mut().expect("response builder");
        let mut have_date = false;
        let mut have_server = false;
        for (name, value) in resp.headers.drain(..) {
            let lname = name.to_ascii_lowercase();
            if lname == "content-length" {
                continue;
            }
            // Connection-specific fields are forbidden in HTTP/2. Apply the
            // same complete ownership rule as the HTTP/1 writer, including
            // fields nominated by a caller-supplied Connection field.
            if header_sanitizer.is_hop_by_hop(&lname) {
                continue;
            }
            if lname == "date" {
                have_date = true;
            } else if lname == "server" {
                have_server = true;
            }
            let name = HeaderName::from_bytes(lname.as_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid response header name")
            })?;
            let value = response_header_value(value, &mut queued_head_ownership).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid response header value")
            })?;
            headers.append(name, value);
        }
        if !have_date {
            headers.append(
                HeaderName::from_static("date"),
                response_header_value(http_date_now().into_bytes(), &mut queued_head_ownership)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad date"))?,
            );
        }
        if !have_server {
            headers.append(
                HeaderName::from_static("server"),
                response_header_value(
                    cfg.server_header().as_bytes().to_vec(),
                    &mut queued_head_ownership,
                )
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad server"))?,
            );
        }
        if let Some(length) = preserved_content_length {
            headers.append(
                HeaderName::from_static("content-length"),
                response_header_value(length.to_string().into_bytes(), &mut queued_head_ownership)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad length"))?,
            );
        } else if let Some(body_len) = body_len.filter(|_| {
            !status.is_informational()
                && status != StatusCode::NO_CONTENT
                && status != StatusCode::RESET_CONTENT
                && status != StatusCode::NOT_MODIFIED
        }) {
            // Body-bearing responses and HEAD responses without an explicit
            // representation length use the actual selected body length.
            headers.append(
                HeaderName::from_static("content-length"),
                response_header_value(
                    body_len.to_string().into_bytes(),
                    &mut queued_head_ownership,
                )
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad length"))?,
            );
        }
    }
    if queued_head_ownership.is_some() {
        return Err(io::Error::other(
            "HTTP/2 response head has no field to retain transport ownership",
        ));
    }
    let response = out
        .body(())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid response headers"))?;

    if end {
        retain_queued_h2_transport(output, &transport)?;
    }
    let mut send = respond
        .send_response(response, end)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    if end {
        ownership.finish();
        output.finish_response();
        return Ok(0);
    }
    let send_timeout = cfg.timeout.max(H2_STREAM_FLOOR);
    let mut progress = crate::resource::SlowOutputProgress::new(send_timeout);
    // The h2 crate retains queued `Bytes` after this function returns. Move
    // the body reservation into the byte owner so accounting lasts until the
    // transport releases the final queued slice, not merely until enqueue.
    let mut sent = 0u64;
    match resp.body {
        Body::Empty => {
            // `end` returned above because Body::Empty has length zero.
            // coverage:ignore-start - body-length invariant
            send_data_bounded(
                &mut send,
                queued_h2_transport_marker(&transport),
                true,
                output,
                &mut progress,
                &mut ownership,
            )
            .await?;
            // coverage:ignore-stop
        }
        Body::Bytes(data) => {
            sent = data.len() as u64;
            let capacity =
                send_capacity(&mut send, data.len(), output, &mut progress, &mut ownership)
                    .await?
                    .min(data.len());
            let data = Bytes::from_owner(AccountedResponseBytes {
                data,
                _resident: resident.clone(),
                _transport: transport.clone(),
            });
            let first = capacity.min(data.len());
            send.send_data(data.slice(..first), first == data.len())
                .map_err(send_io_error)?;
            progress.record(first);
            if first < data.len() {
                send_data_bounded(
                    &mut send,
                    data.slice(first..),
                    true,
                    output,
                    &mut progress,
                    &mut ownership,
                )
                .await?;
            }
        }
        Body::Stream { mut reader, len } => {
            let mut left = len;
            while left > 0 {
                let want = left.min(64 * 1024) as usize;
                // Wait for downstream capacity before reading from the
                // upstream. A zero-window client therefore owns neither a
                // response buffer nor a process-wide blocking-read lease.
                let capacity =
                    send_capacity(&mut send, want, output, &mut progress, &mut ownership)
                        .await?
                        .min(want);
                let resident = response_chunk_lease(&cfg.resource_budget, client, capacity)?;
                let resident = ownership.track_resident(resident)?;
                let blocking_read = cfg.resource_budget.try_response_body_read_for(client)?;
                let read_ownership = ownership.begin_read();
                let (next_reader, mut buf, resident, result, next_ownership) =
                    crate::fault::spawn_blocking(move || {
                        let _blocking_read = blocking_read;
                        let mut buf = take_body_buffer(capacity);
                        buf.resize(capacity, 0);
                        let result = crate::fault::hit("transition.h2.output.stream-read")
                            .and_then(|()| reader.read(&mut buf[..capacity]));
                        (
                            reader,
                            buf,
                            resident,
                            result,
                            read_ownership.complete_read(),
                        )
                    })
                    .await
                    .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
                reader = next_reader;
                ownership = next_ownership;
                let n = result.map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
                if n == 0 {
                    send.send_data(queued_h2_transport_marker(&transport), true)
                        .map_err(send_io_error)?;
                    retain_queued_h2_transport(output, &transport)?;
                    ownership.finish();
                    output.finish_response();
                    return Ok(sent);
                }
                if output.is_slow() {
                    progress.validate(Instant::now())?;
                }
                buf.truncate(n);
                left -= n as u64;
                sent += n as u64;
                let data = Bytes::from_owner(PooledBuffer {
                    buf: Some(buf),
                    _resident: resident,
                    _transport: transport.clone(),
                });
                send.send_data(data, left == 0).map_err(send_io_error)?;
                progress.record(n);
            }
        }
        Body::UnknownLengthStream {
            mut reader,
            max_len,
        } => {
            let mut remaining = max_len;
            loop {
                let want = if remaining == 0 {
                    1
                } else {
                    remaining.min(64 * 1024) as usize
                };
                let capacity =
                    send_capacity(&mut send, want, output, &mut progress, &mut ownership)
                        .await?
                        .min(want);
                if !httpd_rs_verified::compression_stream_read_admit(
                    capacity > 0,
                    capacity as u64,
                    64 * 1024,
                ) {
                    return Err(io::Error::other(
                        "encoded response read lacks downstream capacity",
                    ));
                }
                let resident = response_chunk_lease(&cfg.resource_budget, client, capacity)?;
                let resident = ownership.track_resident(resident)?;
                let blocking_read = cfg.resource_budget.try_response_body_read_for(client)?;
                let read_ownership = ownership.begin_read();
                let (next_reader, mut buf, resident, result, next_ownership) =
                    crate::fault::spawn_blocking(move || {
                        let _blocking_read = blocking_read;
                        let mut buf = take_body_buffer(capacity);
                        buf.resize(capacity, 0);
                        let result = crate::fault::hit("transition.h2.output.encoded-read")
                            .and_then(|()| reader.read(&mut buf[..capacity]));
                        (
                            reader,
                            buf,
                            resident,
                            result,
                            read_ownership.complete_read(),
                        )
                    })
                    .await
                    .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
                reader = next_reader;
                ownership = next_ownership;
                let n = result.map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
                if n == 0 {
                    send.send_data(queued_h2_transport_marker(&transport), true)
                        .map_err(send_io_error)?;
                    retain_queued_h2_transport(output, &transport)?;
                    ownership.finish();
                    output.finish_response();
                    return Ok(sent);
                }
                if n as u64 > remaining {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "encoded response exceeded its admitted maximum",
                    ));
                }
                if output.is_slow() {
                    progress.validate(Instant::now())?;
                }
                buf.truncate(n);
                remaining -= n as u64;
                sent += n as u64;
                let data = Bytes::from_owner(PooledBuffer {
                    buf: Some(buf),
                    _resident: resident,
                    _transport: transport.clone(),
                });
                send.send_data(data, false).map_err(send_io_error)?;
                progress.record(n);
            }
        }
        Body::File {
            mut file,
            offset,
            len,
        } => {
            // Reserve downstream capacity before materializing each bounded
            // file chunk. This keeps zero-window streams allocation-free and
            // attaches resident accounting to every chunk queued in h2.
            const OFFLOAD_MIN: u64 = 256 * 1024;
            const CHUNK: u64 = 256 * 1024;
            let offload = len >= OFFLOAD_MIN;
            let mut left = len;
            let mut pos = offset;
            while left > 0 {
                let want = left.min(CHUNK) as usize;
                let capacity =
                    send_capacity(&mut send, want, output, &mut progress, &mut ownership)
                        .await?
                        .min(want);
                let resident = response_chunk_lease(&cfg.resource_budget, client, capacity)?;
                let resident = ownership.track_resident(resident)?;
                let data = if offload {
                    let blocking_read = cfg.resource_budget.try_response_body_read_for(client)?;
                    let read_ownership = ownership.begin_read();
                    let chunk_transport = transport.clone();
                    let (next_file, data, next_ownership) =
                        crate::fault::spawn_blocking(move || {
                            let _blocking_read = blocking_read;
                            let data = crate::fault::hit("transition.h2.output.file-read")
                                .and_then(|()| {
                                    read_range(&file, pos, capacity, resident, chunk_transport)
                                });
                            (file, data, read_ownership.complete_read())
                        })
                        .await
                        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
                    file = next_file;
                    ownership = next_ownership;
                    data?
                } else {
                    crate::fault::hit("transition.h2.output.file-read")?;
                    read_range(&file, pos, capacity, resident, transport.clone())?
                };
                let filled = data.len();
                if filled == 0 {
                    send.send_data(queued_h2_transport_marker(&transport), true)
                        .map_err(send_io_error)?;
                    retain_queued_h2_transport(output, &transport)?;
                    ownership.finish();
                    output.finish_response();
                    return Ok(sent);
                }
                if output.is_slow() {
                    progress.validate(Instant::now())?;
                }
                left -= filled as u64;
                pos = pos.saturating_add(filled as u64);
                sent += filled as u64;
                send.send_data(data, left == 0).map_err(send_io_error)?;
                progress.record(filled);
            }
        }
    }
    retain_queued_h2_transport(output, &transport)?;
    ownership.finish();
    output.finish_response();
    Ok(sent)
}

async fn send_response(
    respond: h2::server::SendResponse<Bytes>,
    cfg: &Config,
    client: std::net::IpAddr,
    resp: Response,
    head_only: bool,
) -> io::Result<u64> {
    let mut output =
        crate::resource::SlowOutputAdmission::detached(cfg.resource_budget.context(client));
    send_response_with_admission(respond, cfg, resp, head_only, &mut output).await
}

struct H2StreamAdmission {
    quota_peer: SocketAddr,
    resource_context: crate::resource::ResourceContext,
    request_scope: crate::resource::RequestScope,
    quota_identity_valid: bool,
    stream_quota: crate::resource::CombinedH2Lease,
}

fn admit_stream_before_spawn(
    cfg: &Arc<Config>,
    peer: SocketAddr,
    request: &http::Request<h2::RecvStream>,
) -> io::Result<H2StreamAdmission> {
    let mut quota_headers = crate::http::Headers::default();
    let mut quota_identity_valid = true;
    if let Some(remoteip_header) = &cfg.remoteip_header {
        let remoteip_header = remoteip_header.to_ascii_lowercase();
        if remoteip_header == "host" {
            if let Some(authority) = request.uri().authority() {
                let value = authority.as_str().as_bytes();
                quota_identity_valid = httpd_rs_verified::h2_field_size_admit(
                    b"host".len() as u64,
                    value.len() as u64,
                    cfg.limit_request_field_size as u64,
                );
                if quota_identity_valid {
                    quota_headers.push("host", value.to_vec());
                }
            }
        } else {
            for (name, value) in request.headers() {
                if name.as_str() != remoteip_header {
                    continue;
                }
                let merged_len = quota_headers
                    .get(&remoteip_header)
                    .map(|existing| existing.len().saturating_add(2))
                    .unwrap_or(0)
                    .saturating_add(value.as_bytes().len());
                if !httpd_rs_verified::h2_field_size_admit(
                    name.as_str().len() as u64,
                    merged_len as u64,
                    cfg.limit_request_field_size as u64,
                ) {
                    quota_identity_valid = false;
                    break;
                }
                quota_headers.push_merged(name.as_str(), value.as_bytes());
            }
        }
        if !quota_identity_valid {
            quota_headers = crate::http::Headers::default();
        }
    }
    let quota_peer = cfg.client_addr_from_headers(peer, &quota_headers);
    let resource_context = cfg.resource_budget.context(quota_peer.ip());
    let request_scope = crate::resource::RequestScope::new(resource_context.clone());
    let stream_quota = cfg.resource_budget.try_h2_stream_in(&resource_context)?;
    if let Err(error) = cfg.resource_budget.try_request_rate(&resource_context) {
        drop(stream_quota);
        return Err(error);
    }
    Ok(H2StreamAdmission {
        quota_peer,
        resource_context,
        request_scope,
        quota_identity_valid,
        stream_quota,
    })
}

/// Await one blocking policy/backend phase while the response handle remains
/// reset-observable. A peer reset cancels the shared request scope before the
/// async owner drops its JoinHandle; synchronous backend code therefore sees
/// cancellation at its next bounded I/O checkpoint.
fn spawn_request_blocking<F, T>(
    scope: &crate::resource::RequestScope,
    work: F,
) -> io::Result<tokio::task::JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let async_work = scope.try_async_work()?;
    Ok(crate::fault::spawn_blocking(move || {
        let _async_work = async_work;
        work()
    }))
}

async fn blocking_task_or_reset<T>(
    respond: &mut h2::server::SendResponse<Bytes>,
    task: &mut tokio::task::JoinHandle<T>,
    scope: &crate::resource::RequestScope,
) -> Option<Result<T, tokio::task::JoinError>> {
    if crate::fault::hit("transition.h2.blocking-await").is_err() {
        scope.cancel();
        return None;
    }
    let reset = std::future::poll_fn(|cx| respond.poll_reset(cx));
    tokio::pin!(reset);
    tokio::select! {
        biased;
        _ = &mut reset => {
            scope.cancel();
            None
        }
        result = task => Some(result),
    }
}

async fn handle_stream(
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    peer: SocketAddr,
    local_ip: String,
    local_port: u16,
    tls_identity: crate::tls::TlsConnectionIdentity,
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    admission: H2StreamAdmission,
) -> bool {
    // The return value is true when the stream was reset (including a
    // timeout that drops the response future).  `serve` projects that event
    // into the verified connection budget.
    let started = Instant::now();
    let (parts, recv) = request.into_parts();
    let method = parts.method.as_str().to_string();
    let uri = parts.uri.clone();
    let H2StreamAdmission {
        quota_peer,
        resource_context,
        request_scope,
        quota_identity_valid,
        stream_quota,
    } = admission;
    let mut output_admission =
        crate::resource::SlowOutputAdmission::tracked_h2(resource_context.clone(), stream_quota);
    if crate::fault::hit("transition.h2.head").is_err() {
        return send_response_with_admission(
            respond,
            &cfg,
            Response::memory_overload(),
            false,
            &mut output_admission,
        )
        .await
        .is_err();
    }
    if !quota_identity_valid {
        return send_response_with_admission(
            respond,
            &cfg,
            bad(431, "request header field too large"),
            false,
            &mut output_admission,
        )
        .await
        .is_err();
    }
    // Bound the request-controlled authority before parsing it. The complete
    // head admission below still determines final error precedence for all
    // fields, but no field parser should receive more than the configured
    // HTTP/1-compatible per-field limit first.
    let target = match project_h2_target(&method, &uri, true, cfg.limit_request_field_size) {
        Ok(target) => target,
        Err(response) => {
            return send_response_with_admission(
                respond,
                &cfg,
                response,
                false,
                &mut output_admission,
            )
            .await
            .is_err();
        }
    };
    // The adapter creates a second owned representation of the decoded h2
    // request. Charge it before cloning and retain the lease through dispatch
    // and response sending.
    let mut request_resident = match cfg.resource_budget.try_request_bytes_in(&resource_context) {
        Ok(lease) => lease,
        Err(_) => {
            return send_response_with_admission(
                respond,
                &cfg,
                bad(503, "request memory capacity exhausted"),
                false,
                &mut output_admission,
            )
            .await
            .is_err();
        }
    };
    if request_resident
        .attribute_context(resource_context.clone())
        .is_err()
    {
        return send_response_with_admission(
            respond,
            &cfg,
            bad(503, "request memory capacity exhausted"),
            false,
            &mut output_admission,
        )
        .await
        .is_err();
    }
    let header_bytes = parts
        .headers
        .iter()
        .fold(target.len() as u64, |total, (name, value)| {
            total
                .saturating_add(name.as_str().len() as u64)
                .saturating_add(value.as_bytes().len() as u64)
                // Canonical duplicate lines add either ", " or "; ".
                .saturating_add(2)
        })
        .saturating_add(
            uri.authority()
                .map(|authority| 4u64.saturating_add(authority.as_str().len() as u64))
                .unwrap_or(0),
        );
    if request_resident.reserve(header_bytes).is_err() {
        return send_response_with_admission(
            respond,
            &cfg,
            bad(503, "request memory capacity exhausted"),
            false,
            &mut output_admission,
        )
        .await
        .is_err();
    }
    let mut request_resident = Some(request_resident);

    let H2HeadProjection {
        request: mut req,
        declared,
    } = match project_h2_head(
        method,
        target,
        uri.authority().map(|authority| authority.as_str()),
        &parts.headers,
        cfg.limit_request_line,
        cfg.limit_request_fields,
        cfg.limit_request_field_size,
    ) {
        Ok(projected) => projected,
        Err(response) => {
            return send_response_with_admission(
                respond,
                &cfg,
                response,
                false,
                &mut output_admission,
            )
            .await
            .is_err();
        }
    };
    req.headers.bind_request_scope(request_scope.clone());
    if let Some(status) =
        tls_identity.request_status(&cfg, req.header_str("host").filter(|host| !host.is_empty()))
    {
        return send_response_with_admission(
            respond,
            &cfg,
            bad(
                status,
                if status == 421 {
                    "misdirected TLS virtual host"
                } else {
                    "TLS SNI requires an HTTP authority"
                },
            ),
            req.is_head(),
            &mut output_admission,
        )
        .await
        .is_err();
    }
    let peer = cfg.client_addr(peer, &req);
    let _request_scope_guard = request_scope.guard();
    if peer != quota_peer {
        // Admission and dispatch must never disagree about the effective
        // source. Fail the stream closed if a future header-canonicalization
        // change escapes the pre-admission projection above.
        logger.error("HTTP/2 quota and dispatch client identities diverged");
        respond.send_reset(h2::Reason::PROTOCOL_ERROR);
        return true;
    }

    let has_body = declared.unwrap_or(0) > 0 || !recv.is_end_stream();
    if declared.is_some_and(|length| length > cfg.limit_request_body) {
        return send_response_with_admission(
            respond,
            &cfg,
            bad(413, "request body too large"),
            req.is_head(),
            &mut output_admission,
        )
        .await
        .is_err();
    }
    if has_body {
        // HTTP/2 owns the wire framing, but the shared policy/cache pipeline
        // still needs an explicit marker that DATA is pending. In particular,
        // a GET-with-body must not consume a cache entry before the body has
        // been validated and drained. `Chunked` is only the no-declared-size
        // sentinel here; the h2 adapter remains the sole DATA parser.
        req.framing = declared
            .map(crate::verified::BodyFraming::Length)
            .unwrap_or(crate::verified::BodyFraming::Chunked);
    }
    let mut phase = httpd_rs_verified::RequestPhase::Head;
    let mut early = None;
    let mut early_remote_user = None;
    let mut prepared_handler = None;
    let mut body_remote_user = None;
    let mut drain_after_body = None;
    let mut recv = Some(recv);
    if has_body && !cfg.body_handlers_possible() {
        let status = if matches!(req.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
            400
        } else {
            405
        };
        phase = httpd_rs_verified::request_phase_step(
            phase,
            httpd_rs_verified::RequestPhaseEvent::RouteNeedsDrain,
        )
        .expect("HTTP/2 static-only body-drain phase transition");
        drain_after_body = Some((
            bad(
                status,
                "request body is not accepted by a static-only configuration",
            ),
            None,
        ));
    }
    if has_body && drain_after_body.is_none() {
        // Route, rewrite and authorization complete before DATA is accepted.
        // This is the HTTP/2 projection of the same lazy-body transition used
        // by HTTP/1 (and, importantly, it happens before allocating a spool).
        let probe_cfg = cfg.clone();
        let probe_local_ip = local_ip.clone();
        let mut probe_req = req;
        let Ok(mut probed) = spawn_request_blocking(&request_scope, move || {
            let decision = crate::server::probe_request_body(
                &probe_cfg,
                &mut probe_req,
                peer,
                &probe_local_ip,
                local_port,
                true,
            );
            (probe_req, decision)
        }) else {
            request_scope.cancel();
            respond.send_reset(h2::Reason::REFUSED_STREAM);
            return true;
        };
        let Some(probed) = blocking_task_or_reset(&mut respond, &mut probed, &request_scope).await
        else {
            return true;
        };
        match probed {
            Ok((
                returned_req,
                crate::server::BodyRouteDecision::Read {
                    handler,
                    remote_user,
                },
            )) => {
                req = returned_req;
                phase = httpd_rs_verified::request_phase_step(
                    phase,
                    httpd_rs_verified::RequestPhaseEvent::RouteNeedsBody,
                )
                .expect("HTTP/2 body route phase transition");
                prepared_handler = Some(handler);
                body_remote_user = remote_user;
            }
            Ok((returned_req, crate::server::BodyRouteDecision::Drain(response, remote_user))) => {
                req = returned_req;
                phase = httpd_rs_verified::request_phase_step(
                    phase,
                    httpd_rs_verified::RequestPhaseEvent::RouteNeedsDrain,
                )
                .expect("HTTP/2 static body-drain phase transition");
                body_remote_user = remote_user.clone();
                drain_after_body = Some((response, remote_user));
            }
            Ok((
                returned_req,
                crate::server::BodyRouteDecision::Respond(response, remote_user),
            )) => {
                req = returned_req;
                phase = httpd_rs_verified::request_phase_step(
                    phase,
                    httpd_rs_verified::RequestPhaseEvent::EarlyResponse,
                )
                .expect("HTTP/2 early response phase transition");
                early = Some(response);
                early_remote_user = remote_user;
                // A policy denial is terminal without interpreting a body.
                // Dropping the receive half prevents an untrusted upload from
                // converting that rejection into a slow-input occupation.
                drop(recv.take());
            }
            Err(_) => {
                logger.error("HTTP/2 request probe task failed");
                return true;
            }
        }
    }
    if !has_body {
        // Bodyless dynamic requests use the same prepared-handler IR.  Route
        // and authorization run under stream admission, then the
        // potentially slow backend phase runs independently of that worker.
        let probe_cfg = cfg.clone();
        let probe_local_ip = local_ip.clone();
        let mut probe_req = req;
        let Ok(mut probed) = spawn_request_blocking(&request_scope, move || {
            let decision = crate::server::probe_prepared_handler(
                &probe_cfg,
                &mut probe_req,
                peer,
                &probe_local_ip,
                local_port,
                true,
            );
            (probe_req, decision)
        }) else {
            request_scope.cancel();
            respond.send_reset(h2::Reason::REFUSED_STREAM);
            return true;
        };
        let Some(probed) = blocking_task_or_reset(&mut respond, &mut probed, &request_scope).await
        else {
            return true;
        };
        match probed {
            Ok((
                returned_req,
                crate::server::PreparedRouteDecision::Prepared {
                    handler,
                    remote_user,
                },
            )) => {
                req = returned_req;
                phase = httpd_rs_verified::request_phase_step(
                    phase,
                    httpd_rs_verified::RequestPhaseEvent::RoutePrepared,
                )
                .expect("HTTP/2 prepared route phase transition");
                prepared_handler = Some(handler);
                body_remote_user = remote_user;
            }
            Ok((
                returned_req,
                crate::server::PreparedRouteDecision::Respond(response, remote_user),
            )) => {
                req = returned_req;
                phase = httpd_rs_verified::request_phase_step(
                    phase,
                    httpd_rs_verified::RequestPhaseEvent::RouteReady,
                )
                .expect("HTTP/2 bodyless route phase transition");
                phase = httpd_rs_verified::request_phase_step(
                    phase,
                    httpd_rs_verified::RequestPhaseEvent::DispatchComplete,
                )
                .expect("HTTP/2 bodyless dispatch phase transition");
                early = Some(response);
                early_remote_user = remote_user;
            }
            Err(_) => {
                logger.error("HTTP/2 request probe task failed");
                return true;
            }
        }
    }

    if has_body && early.is_none() {
        // Waiting for peer-controlled DATA must not retain the general H2
        // dispatch pool. Acquire the source-fair slow-input class first; a
        // rejected transfer keeps general ownership long enough to send this
        // bounded overload response.
        if output_admission.enter_slow_input().is_err() {
            phase = httpd_rs_verified::request_phase_step(
                phase,
                httpd_rs_verified::RequestPhaseEvent::BodyErrorResponse,
            )
            .expect("HTTP/2 slow-input admission failure transition");
            early = Some(bad(503, "slow request-body capacity exhausted"));
            early_remote_user = body_remote_user.take();
            drop(prepared_handler.take());
            drop(drain_after_body.take());
            drop(recv.take());
        }
    }

    let mut streamed = None;
    if has_body
        && early.is_none()
        && declared.is_some_and(|length| length > crate::http::MAX_REQUEST_BODY_IN_MEMORY)
        && prepared_handler.is_some()
    {
        let length = declared.expect("checked fixed HTTP/2 body length");
        let install = crate::fault::hit("transition.h2.streaming-body-install").and_then(|()| {
            crate::http::install_streaming_request_body(&mut req, length, &cfg.resource_budget)
        });
        match install {
            Ok(sender) => {
                req.headers.hold_resident(
                    request_resident
                        .take()
                        .expect("streaming HTTP/2 body retained its resident lease"),
                );
                phase = httpd_rs_verified::request_phase_step(
                    phase,
                    httpd_rs_verified::RequestPhaseEvent::BackendStarted,
                )
                .expect("HTTP/2 streaming backend phase transition");
                let mut rejected_req = req.clone();
                let dispatch_cfg = cfg.clone();
                let handler = prepared_handler
                    .take()
                    .expect("streaming route retained its prepared handler");
                let remote_user = body_remote_user.take();
                let backend_req = req.clone();
                let Ok(mut backend) = spawn_request_blocking(&request_scope, move || {
                    let mut req = backend_req;
                    let response = crate::server::execute_prepared_handler(
                        &dispatch_cfg,
                        &mut req,
                        peer,
                        local_port,
                        true,
                        handler,
                    );
                    (req, response)
                }) else {
                    request_scope.cancel();
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    return true;
                };
                let body_timeout = cfg
                    .request_body_timeout
                    .max(std::time::Duration::from_secs(1));
                let body_future = stream_body(
                    recv.take()
                        .expect("streaming route retained receive stream"),
                    sender,
                    length,
                    cfg.limit_request_body,
                    body_timeout,
                    cfg.request_body_min_rate,
                    cfg.capability_enabled(crate::config::Capability::RequestTrailers),
                );
                tokio::pin!(body_future);
                let mut reset_watch = std::future::poll_fn(|cx| respond.poll_reset(cx));
                let backend_result = tokio::select! {
                    biased;
                    _ = &mut reset_watch => {
                        if let Some(scope) = rejected_req.request_scope() {
                            scope.cancel();
                        }
                        drop(backend);
                        return true;
                    }
                    result = &mut backend => Some(result),
                    result = &mut body_future => {
                        match result {
                            Ok(()) | Err(H2ReadFailure::BackendClosed) => {
                                if output_admission.leave_slow_input().is_err() {
                                    request_scope.cancel();
                                    drop(backend);
                                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                                    return true;
                                }
                                let Some(result) = blocking_task_or_reset(
                                    &mut respond,
                                    &mut backend,
                                    &request_scope,
                                )
                                .await else {
                                    return true;
                                };
                                Some(result)
                            }
                            Err(H2ReadFailure::Reset) => {
                                if let Some(scope) = rejected_req.request_scope() {
                                    scope.cancel();
                                }
                                drop(backend);
                                return true;
                            }
                            Err(H2ReadFailure::Response(response)) => {
                                if let Some(scope) = rejected_req.request_scope() {
                                    scope.cancel();
                                }
                                drop(backend);
                                rejected_req.clear_streaming_body();
                                phase = httpd_rs_verified::request_phase_step(
                                    phase,
                                    httpd_rs_verified::RequestPhaseEvent::BodyErrorResponse,
                                )
                                .expect("HTTP/2 streaming body error phase transition");
                                req = rejected_req;
                                early = Some(response);
                                early_remote_user = remote_user.clone();
                                None
                            }
                        }
                    }
                };
                if let Some(result) = backend_result {
                    let Ok((req, response)) = result else {
                        logger.error("HTTP/2 backend task failed");
                        return true;
                    };
                    phase = httpd_rs_verified::request_phase_step(
                        phase,
                        httpd_rs_verified::RequestPhaseEvent::BackendComplete,
                    )
                    .expect("HTTP/2 streaming backend completion transition");
                    streamed = Some((req, response, remote_user));
                }
                if output_admission.is_slow_input()
                    && (streamed.is_some() || early.is_some())
                    && output_admission.leave_slow_input().is_err()
                {
                    request_scope.cancel();
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    return true;
                }
            }
            Err(_) => {
                phase = httpd_rs_verified::request_phase_step(
                    phase,
                    httpd_rs_verified::RequestPhaseEvent::BodyErrorResponse,
                )
                .expect("HTTP/2 streaming admission failure transition");
                early = Some(bad(503, "request-body capacity exhausted"));
                early_remote_user = body_remote_user.take();
                drop(recv.take());
            }
        }
        if output_admission.is_slow_input()
            && early.is_some()
            && output_admission.leave_slow_input().is_err()
        {
            request_scope.cancel();
            respond.send_reset(h2::Reason::REFUSED_STREAM);
            return true;
        }
    }

    if has_body && early.is_none() && streamed.is_none() {
        let max_body = cfg.limit_request_body.min(crate::http::MAX_BODY_BUFFERED);
        let body_timeout = cfg
            .request_body_timeout
            .max(std::time::Duration::from_secs(1));
        let body_result = {
            let body_future = read_body(
                recv.take().expect("body route retained its receive stream"),
                max_body,
                body_timeout,
                cfg.request_body_min_rate,
                cfg.resource_budget.clone(),
                cfg.max_spool_bytes,
                cfg.max_spool_files,
                req.resource_context()
                    .expect("HTTP/2 request scope was bound")
                    .clone(),
                &request_scope,
                request_resident
                    .as_mut()
                    .expect("buffered HTTP/2 body retained its resident lease"),
                cfg.capability_enabled(crate::config::Capability::RequestTrailers),
            );
            tokio::pin!(body_future);
            // `SendResponse::poll_reset` is the h2 API for a client RST_STREAM
            // before response headers. Race it against body consumption so a
            // reset while DATA is open releases stream capacity promptly.
            let mut reset_watch = std::future::poll_fn(|cx| respond.poll_reset(cx));
            tokio::select! {
                biased;
                _ = &mut reset_watch => return true,
                result = &mut body_future => result,
            }
        };
        match body_result {
            Ok(body) => {
                if output_admission.leave_slow_input().is_err() {
                    request_scope.cancel();
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    return true;
                }
                if declared.is_some_and(|declared| declared != body.len) {
                    // h2 enforces this before clean end-of-stream; retain the
                    // adapter check as a fail-closed dependency boundary.
                    // coverage:ignore-start - upstream h2 framing invariant
                    return send_response_with_admission(
                        respond,
                        &cfg,
                        bad(400, "Content-Length mismatch"),
                        false,
                        &mut output_admission,
                    )
                    .await
                    .is_err();
                    // coverage:ignore-stop
                }
                if let Some((response, remote_user)) = drain_after_body.take() {
                    req.body = body.bytes;
                    req.body_spool = body.spool;
                    req.discard_body();
                    phase = httpd_rs_verified::request_phase_step(
                        phase,
                        httpd_rs_verified::RequestPhaseEvent::BodyDiscarded,
                    )
                    .expect("HTTP/2 body discard phase transition");
                    early = Some(response);
                    early_remote_user = remote_user;
                } else {
                    req.body = body.bytes;
                    req.body_spool = body.spool;
                    phase = httpd_rs_verified::request_phase_step(
                        phase,
                        httpd_rs_verified::RequestPhaseEvent::BodyComplete,
                    )
                    .expect("HTTP/2 body completion phase transition");
                }
            }
            // The biased `poll_reset` arm above observes this state first.
            Err(H2ReadFailure::Reset) => return true, // coverage:ignore-line - reset-watch invariant
            Err(H2ReadFailure::BackendClosed) => {
                logger.error("buffered HTTP/2 body unexpectedly lost its backend");
                return true;
            }
            Err(H2ReadFailure::Response(response)) => {
                if output_admission.leave_slow_input().is_err() {
                    request_scope.cancel();
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    return true;
                }
                phase = httpd_rs_verified::request_phase_step(
                    phase,
                    httpd_rs_verified::RequestPhaseEvent::BodyErrorResponse,
                )
                .expect("HTTP/2 body error phase transition");
                early = Some(response);
                early_remote_user = body_remote_user.take();
            }
        }
    }
    if let Some(request_resident) = request_resident.take() {
        req.headers.hold_resident(request_resident);
    }

    let (req, resp, remote_user) = if let Some(streamed) = streamed {
        streamed
    } else {
        match early {
            Some(resp) => (req, resp, early_remote_user),
            None => {
                // Dispatch runs in Tokio's bounded blocking pool. It must not
                // consume the response-body read permits: those protect only the
                // short descriptor read itself, whereas dispatch duration and
                // concurrency are already bounded by H2 stream/client quotas.
                let dispatch_cfg = cfg.clone();
                let dispatch_local_ip = local_ip.clone();
                let runs_backend = prepared_handler.is_some();
                let Ok(mut dispatched) = spawn_request_blocking(&request_scope, move || {
                    let mut req = req;
                    let (resp, remote_user) = match prepared_handler {
                        Some(handler) => (
                            crate::server::execute_prepared_handler(
                                &dispatch_cfg,
                                &mut req,
                                peer,
                                local_port,
                                true,
                                handler,
                            ),
                            body_remote_user,
                        ),
                        None => crate::server::dispatch_with_scheme_and_identity(
                            &dispatch_cfg,
                            &req,
                            peer,
                            &dispatch_local_ip,
                            local_port,
                            true,
                        ),
                    };
                    (req, resp, remote_user)
                }) else {
                    request_scope.cancel();
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    return true;
                };
                let Some(dispatched) =
                    blocking_task_or_reset(&mut respond, &mut dispatched, &request_scope).await
                else {
                    return true;
                };
                let Ok((req, resp, remote_user)) = dispatched else {
                    logger.error("HTTP/2 request dispatcher task failed");
                    return true;
                };
                phase = httpd_rs_verified::request_phase_step(
                    phase,
                    if runs_backend {
                        httpd_rs_verified::RequestPhaseEvent::BackendComplete
                    } else {
                        httpd_rs_verified::RequestPhaseEvent::DispatchComplete
                    },
                )
                .expect("HTTP/2 backend/dispatch phase transition");
                (req, resp, remote_user)
            }
        }
    };
    let head_only = req.is_head();
    let status = resp.status;
    let bytes_in = req.target.len() as u64 + req.body_len();
    let body_sent =
        match send_response_with_admission(respond, &cfg, resp, head_only, &mut output_admission)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                let closed = httpd_rs_verified::request_phase_step(
                    phase,
                    httpd_rs_verified::RequestPhaseEvent::Cancel,
                )
                .expect("HTTP/2 cancellation phase transition");
                debug_assert_eq!(closed, httpd_rs_verified::RequestPhase::Closed);
                // Peer-close/send failures are already exercised directly by the
                // bounded response sender; this adapter arm only adds logging.
                logger.error(&format!("HTTP/2 stream failed: {e}")); // coverage:ignore-line - peer timing race
                return true; // coverage:ignore-line - peer timing race
            }
        };
    phase = httpd_rs_verified::request_phase_step(
        phase,
        httpd_rs_verified::RequestPhaseEvent::OutputComplete,
    )
    .expect("HTTP/2 output phase transition");
    debug_assert_eq!(phase, httpd_rs_verified::RequestPhase::Closed);
    crate::status::hit(body_sent);

    let host = req.header_str("host").unwrap_or("");
    let server_name = crate::server::server_name_for_public(&cfg, &req, &local_ip, local_port);
    let vhost_idx = cfg
        .select_vhost(
            local_ip.parse().ok(),
            local_port,
            if host.is_empty() { None } else { Some(host) },
        )
        .and_then(|v| cfg.vhosts.iter().position(|x| std::ptr::eq(x, v)));
    logger.access(&AccessEntry {
        remote_ip: &peer.ip().to_string(),
        remote_port: peer.port(),
        local_ip: &local_ip,
        local_port,
        server_name: &server_name,
        method: &req.method,
        uri: &req.target,
        remote_user: remote_user.as_deref(),
        protocol: req.version.as_str(),
        status,
        bytes_sent: body_sent,
        bytes_in,
        referer: req.header_str("referer").unwrap_or(""),
        user_agent: req.header_str("user-agent").unwrap_or(""),
        host,
        vhost_index: vhost_idx,
        started,
    });
    false
}

/// Feed arbitrary wire bytes through the patched h2 state machine.  This is
/// deliberately bounded: malformed inputs must terminate promptly rather
/// than parking a fuzz worker on an incomplete connection.
#[cfg(feature = "fuzzing")]
pub fn fuzz_h2_frames(data: &[u8]) {
    // Hit the fork's direct HPACK harness as well as the full framed state
    // machine below. The direct path runs stateless and maximum-bounded table
    // modes plus every integer prefix.
    h2::fuzz_bridge::fuzz_logic::fuzz_hpack(data);

    run_h2_fuzz_wire(data[..data.len().min(256 * 1024)].to_vec());
}

/// Exercise the exact adapter ledger independently of async scheduling. Every
/// byte sequence is a sequence of valid or rejected lifecycle operations;
/// rejected transitions must leave identity, phase, and capacity consistent.
#[cfg(feature = "fuzzing")]
fn fuzz_h2_lifecycle(data: &[u8]) {
    let mut lifecycle = H2ConnectionLedger::new(8, 8);
    for command in data.chunks(2).take(16 * 1024) {
        let operation = command.first().copied().unwrap_or(0) % 5;
        let stream_id = u64::from(command.get(1).copied().unwrap_or(0) % 16) * 2 + 1;
        match operation {
            0 => {
                let _ = lifecycle.begin(stream_id);
            }
            1 => {
                let _ = lifecycle.end(stream_id, false);
            }
            2 => {
                let _ = lifecycle.end(stream_id, true);
            }
            3 => {
                let _ = lifecycle.reclaim(stream_id);
            }
            _ => {
                assert!(lifecycle.close());
            }
        }
        assert!(lifecycle.is_consistent());
    }
    assert!(lifecycle.close());
    assert!(lifecycle.is_consistent());
}

/// Encode one logical request through the real h2 client, decode it through
/// the vendored server state machine, and consume the production head/body
/// projection. The whole-request differential campaign pairs the result with
/// the HTTP/1 parser before running both through policy and dispatch.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn differential_decode_request(
    cfg: &Config,
    method: &str,
    target: &str,
    fields: &[(String, Vec<u8>)],
    body: &[u8],
    peer: std::net::IpAddr,
) -> Result<Request, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let capacity = 64 * 1024;
        let (client_io, server_io) = tokio::io::duplex(capacity);
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server_driver = tokio::spawn(async move {
            let Ok(mut connection) = h2::server::handshake(server_io).await else {
                return;
            };
            let Some(Ok(first)) = connection.accept().await else {
                return;
            };
            if accepted_tx.send(first).is_err() {
                return;
            }
            while let Some(result) = connection.accept().await {
                match result {
                    Ok((_request, mut response)) => {
                        response.send_reset(h2::Reason::REFUSED_STREAM);
                    }
                    Err(_) => break,
                }
            }
        });
        let (mut client, client_connection) = h2::client::handshake(client_io)
            .await
            .map_err(|error| error.to_string())?;
        let client_driver = tokio::spawn(async move {
            let _ = client_connection.await;
        });

        let uri = format!("https://localhost{target}")
            .parse::<http::Uri>()
            .map_err(|error| error.to_string())?;
        let mut outbound = http::Request::builder().method(method).uri(uri);
        {
            let headers = outbound
                .headers_mut()
                .ok_or_else(|| "HTTP/2 request builder lost its headers".to_string())?;
            for (name, value) in fields {
                let name =
                    HeaderName::from_bytes(name.as_bytes()).map_err(|error| error.to_string())?;
                let value = HeaderValue::from_bytes(value).map_err(|error| error.to_string())?;
                headers.append(name, value);
            }
            if !body.is_empty() {
                headers.insert(
                    HeaderName::from_static("content-length"),
                    HeaderValue::from_str(&body.len().to_string())
                        .map_err(|error| error.to_string())?,
                );
            }
        }
        let outbound = outbound.body(()).map_err(|error| error.to_string())?;
        let (_response, mut send) = client
            .send_request(outbound, body.is_empty())
            .map_err(|error| error.to_string())?;
        if !body.is_empty() {
            send.send_data(Bytes::copy_from_slice(body), true)
                .map_err(|error| error.to_string())?;
        }

        let (request, mut respond) = tokio::time::timeout(Duration::from_secs(1), accepted_rx)
            .await
            .map_err(|_| "HTTP/2 differential request timed out".to_string())?
            .map_err(|_| "HTTP/2 differential connection closed".to_string())?;
        let (parts, recv) = request.into_parts();
        let target = project_h2_target(
            parts.method.as_str(),
            &parts.uri,
            true,
            cfg.limit_request_field_size,
        )
        .map_err(|response| format!("HTTP/2 target rejected with {}", response.status))?;
        let H2HeadProjection {
            request: mut projected,
            declared,
        } = project_h2_head(
            parts.method.as_str().to_string(),
            target,
            parts.uri.authority().map(|authority| authority.as_str()),
            &parts.headers,
            cfg.limit_request_line,
            cfg.limit_request_fields,
            cfg.limit_request_field_size,
        )
        .map_err(|response| format!("HTTP/2 head rejected with {}", response.status))?;

        let context = cfg.resource_budget.context(peer);
        let mut resident = cfg
            .resource_budget
            .try_request_bytes_in(&context)
            .map_err(|error| error.to_string())?;
        let head_bytes = projected
            .target
            .len()
            .saturating_add(
                projected
                    .headers
                    .iter()
                    .map(|(name, value)| name.len().saturating_add(value.len()).saturating_add(2))
                    .sum::<usize>(),
            )
            .saturating_mul(2);
        resident
            .reserve(head_bytes as u64)
            .map_err(|error| error.to_string())?;
        projected
            .headers
            .bind_request_scope(crate::resource::RequestScope::new(context.clone()));
        let request_scope = projected
            .request_scope()
            .expect("fuzz request scope was bound")
            .clone();

        let has_body = declared.unwrap_or(0) > 0 || !recv.is_end_stream();
        if has_body {
            projected.framing = declared
                .map(crate::verified::BodyFraming::Length)
                .unwrap_or(crate::verified::BodyFraming::Chunked);
            let decoded = read_body(
                recv,
                cfg.limit_request_body.min(crate::http::MAX_BODY_BUFFERED),
                Duration::from_secs(1),
                0,
                cfg.resource_budget.clone(),
                cfg.max_spool_bytes,
                cfg.max_spool_files,
                context,
                &request_scope,
                &mut resident,
                false,
            )
            .await
            .map_err(|failure| match failure {
                H2ReadFailure::Reset => "HTTP/2 body reset".to_string(),
                H2ReadFailure::BackendClosed => "HTTP/2 body backend closed".to_string(),
                H2ReadFailure::Response(response) => {
                    format!("HTTP/2 body rejected with {}", response.status)
                }
            })?;
            if declared.is_some_and(|length| length != decoded.len) {
                return Err("HTTP/2 Content-Length mismatch".to_string());
            }
            projected.body = decoded.bytes;
            projected.body_spool = decoded.spool;
        } else if declared != Some(0) && declared.is_some() {
            return Err("HTTP/2 empty body length mismatch".to_string());
        }
        projected.headers.hold_resident(resident);
        respond.send_reset(h2::Reason::NO_ERROR);
        drop(client);
        client_driver.abort();
        server_driver.abort();
        let _ = client_driver.await;
        let _ = server_driver.await;
        Ok(projected)
    })
}

#[cfg(feature = "fuzzing")]
fn run_h2_fuzz_wire(input: Vec<u8>) {
    use tokio::io::AsyncWriteExt;
    use tokio::time::{timeout, Duration};

    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    else {
        return;
    };
    runtime.block_on(async move {
        let capacity = input.len().clamp(1024, 256 * 1024);
        let (mut raw_client, server_io) = tokio::io::duplex(capacity);
        let writer = tokio::spawn(async move {
            let _ = raw_client.write_all(&input).await;
            let _ = raw_client.shutdown().await;
        });
        if let Ok(Ok(mut connection)) =
            timeout(Duration::from_millis(20), h2::server::handshake(server_io)).await
        {
            for _ in 0..16 {
                match timeout(Duration::from_millis(2), connection.accept()).await {
                    Ok(Some(Ok((_request, mut respond)))) => {
                        respond.send_reset(h2::Reason::REFUSED_STREAM);
                    }
                    Ok(Some(Err(_))) | Ok(None) | Err(_) => break,
                }
            }
        }
        let _ = writer.await;
    });
}

#[cfg(feature = "fuzzing")]
fn append_h2_fuzz_frame(wire: &mut Vec<u8>, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    const MAX_WIRE: usize = 256 * 1024;
    if payload.len() > 16 * 1024
        || wire.len().saturating_add(9).saturating_add(payload.len()) > MAX_WIRE
    {
        return;
    }
    let len = payload.len() as u32;
    wire.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags]);
    wire.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    wire.extend_from_slice(payload);
}

/// Convert compact commands into deep SETTINGS/window/reset/continuation
/// sequences. Unlike arbitrary wire fuzzing, every input reaches a complete
/// preface and initial SETTINGS exchange before mutating the connection state.
#[cfg(feature = "fuzzing")]
pub fn fuzz_h2_stateful(data: &[u8]) {
    h2::fuzz_bridge::fuzz_logic::fuzz_hpack(data);
    fuzz_h2_lifecycle(data);

    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    append_h2_fuzz_frame(&mut wire, 4, 0, 0, &[]);
    let mut next_stream = 1u32;
    let mut last_stream = 1u32;
    let mut continuation_stream = None;

    for command in data.chunks(8).take(4096) {
        let byte = |index: usize| command.get(index).copied().unwrap_or(0);
        let value = u32::from_be_bytes([byte(1), byte(2), byte(3), byte(4)]);
        match byte(0) % 12 {
            0 => {
                last_stream = next_stream;
                next_stream = next_stream.saturating_add(2).min(0x7fff_fffd);
                let mut block = vec![0x82, 0x87, 0x84, 0x01, 9];
                block.extend_from_slice(b"localhost");
                append_h2_fuzz_frame(&mut wire, 1, 0x5, last_stream, &block);
            }
            1 => {
                last_stream = next_stream;
                next_stream = next_stream.saturating_add(2).min(0x7fff_fffd);
                append_h2_fuzz_frame(&mut wire, 1, byte(5) & 1, last_stream, &[0x82]);
                continuation_stream = Some(last_stream);
            }
            2 => {
                let expected = continuation_stream.unwrap_or(last_stream);
                let stream = if byte(5) & 1 == 0 {
                    expected
                } else {
                    expected.saturating_add(2)
                };
                let end = byte(5) & 2 != 0;
                append_h2_fuzz_frame(&mut wire, 9, if end { 4 } else { 0 }, stream, &command[1..]);
                if end && stream == expected {
                    continuation_stream = None;
                }
            }
            3 => {
                let setting = if byte(5) & 1 == 0 { 4u16 } else { 1u16 };
                let mut payload = Vec::with_capacity(6);
                payload.extend_from_slice(&setting.to_be_bytes());
                payload.extend_from_slice(&value.to_be_bytes());
                append_h2_fuzz_frame(&mut wire, 4, byte(5) & 1, 0, &payload);
            }
            4 => {
                let increment = (value & 0x7fff_ffff).max(1);
                let stream = if byte(5) & 1 == 0 { 0 } else { last_stream };
                append_h2_fuzz_frame(&mut wire, 8, 0, stream, &increment.to_be_bytes());
            }
            5 => append_h2_fuzz_frame(&mut wire, 3, 0, last_stream, &value.to_be_bytes()),
            6 => append_h2_fuzz_frame(&mut wire, 6, byte(5) & 1, 0, command),
            7 => append_h2_fuzz_frame(&mut wire, 0xf0 | (byte(5) & 0x0f), 0, value, command),
            8 => append_h2_fuzz_frame(
                &mut wire,
                2,
                0,
                last_stream,
                &command[..5.min(command.len())],
            ),
            9 => {
                let mut payload = Vec::with_capacity(8);
                payload.extend_from_slice(&(last_stream & 0x7fff_ffff).to_be_bytes());
                payload.extend_from_slice(&value.to_be_bytes());
                append_h2_fuzz_frame(&mut wire, 7, 0, 0, &payload);
            }
            10 => append_h2_fuzz_frame(&mut wire, 0, byte(5) & 1, last_stream, &command[1..]),
            _ => {
                let promised = next_stream;
                let mut payload = Vec::from((promised & 0x7fff_ffff).to_be_bytes());
                payload.extend_from_slice(&[0x82, 0x87, 0x84]);
                append_h2_fuzz_frame(&mut wire, 5, 4, last_stream, &payload);
            }
        }
    }

    run_h2_fuzz_wire(wire);
}

/// Exercise the outbound HTTP/2 header encoder and queued-frame lifecycle.
/// Input selects flush, peer-reset, and connection-drop endings while header
/// values cover both indexable ASCII and worst-case valid obs-text.
#[cfg(feature = "fuzzing")]
pub fn fuzz_h2_output(data: &[u8]) {
    use tokio::time::{timeout, Duration};

    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    else {
        return;
    };
    let control = data.first().copied().unwrap_or(0);
    let mut value = data
        .get(1..)
        .unwrap_or_default()
        .iter()
        .take(128 * 1024)
        .map(|byte| match *byte {
            b'\t' | 0x20..=0x7e | 0x80..=0xff => *byte,
            _ => 0xdc,
        })
        .collect::<Vec<_>>();
    if value.is_empty() {
        value.push(0xdc);
    }
    // A tiny committed seed can deterministically exercise the maximum
    // admitted response-head value and the worst valid HPACK Huffman input.
    // This avoids waiting for libFuzzer's length schedule to grow a corpus
    // entry all the way to the protocol limit.
    if control & 0x40 != 0 {
        value.clear();
        value.resize(128 * 1024, 0xdc);
    }
    runtime.block_on(async move {
        let operation = async move {
            let (client_io, server_io) = tokio::io::duplex(512 * 1024);
            let (server_handshake, client_handshake) = tokio::join!(
                h2::server::handshake(server_io),
                h2::client::handshake(client_io)
            );
            let mut server_connection = server_handshake.ok()?;
            let (mut client, client_connection) = client_handshake.ok()?;
            let client_driver = tokio::spawn(async move { client_connection.await });
            let request = http::Request::builder()
                .uri("https://localhost/fuzz-output")
                .body(())
                .ok()?;
            let (response, mut request_stream) = client.send_request(request, true).ok()?;
            let (_, mut respond) = server_connection.accept().await?.ok()?;
            let mut outgoing = http::Response::builder().status(200).body(()).ok()?;
            let header = HeaderValue::from_bytes(&value).ok()?;
            outgoing
                .headers_mut()
                .append(HeaderName::from_static("x-fuzz-output"), header);
            let end = control & 1 == 0;
            let mut send = respond.send_response(outgoing, end).ok()?;
            if !end {
                send.send_data(
                    Bytes::copy_from_slice(&value[..value.len().min(1024)]),
                    true,
                )
                .ok()?;
            }

            match (control >> 1) % 3 {
                0 => {
                    let server_driver =
                        tokio::spawn(
                            async move { while server_connection.accept().await.is_some() {} },
                        );
                    if let Ok(Ok(response)) = timeout(Duration::from_millis(20), response).await {
                        let mut body = response.into_body();
                        while let Ok(Some(Ok(chunk))) =
                            timeout(Duration::from_millis(2), body.data()).await
                        {
                            let len = chunk.len();
                            let _ = body.flow_control().release_capacity(len);
                        }
                    }
                    server_driver.abort();
                    let _ = server_driver.await;
                }
                1 => {
                    request_stream.send_reset(h2::Reason::CANCEL);
                    let _ = timeout(Duration::from_millis(20), server_connection.accept()).await;
                }
                _ => drop(server_connection),
            }
            drop((request_stream, client));
            client_driver.abort();
            let _ = client_driver.await;
            Some(())
        };
        let _ = timeout(Duration::from_millis(50), operation).await;
    });
}

pub(crate) async fn serve<G, F>(
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    tls: TlsStream<TcpStream>,
    peer: SocketAddr,
    local_ip: String,
    local_port: u16,
    tls_identity: crate::tls::TlsConnectionIdentity,
    retired: tokio::sync::watch::Receiver<bool>,
    on_ready: F,
) -> io::Result<()>
where
    F: FnOnce() -> io::Result<G>,
{
    serve_io(
        cfg,
        logger,
        tls,
        peer,
        local_ip,
        local_port,
        tls_identity,
        retired,
        on_ready,
    )
    .await
}

async fn serve_io<T, G, F>(
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    io: T,
    peer: SocketAddr,
    local_ip: String,
    local_port: u16,
    tls_identity: crate::tls::TlsConnectionIdentity,
    mut retired: tokio::sync::watch::Receiver<bool>,
    on_ready: F,
) -> io::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
    F: FnOnce() -> io::Result<G>,
{
    let settings = httpd_rs_verified::h2_settings();
    let mut builder = h2::server::Builder::new();
    builder
        // Bound compressed/decoded header memory before HPACK allocates.
        .max_header_list_size(settings.max_header_list)
        // Keep HPACK stateless in both directions by default. The independent
        // send cap means a peer cannot re-enable response-side dynamic state
        // by advertising a larger table in its SETTINGS frame.
        .header_table_size(settings.header_table_size)
        .max_send_header_table_size(settings.max_send_header_table_size)
        .max_concurrent_streams(settings.max_concurrent_streams)
        // Bound stream/window and reset amplification.  The h2 crate owns
        // frame parsing; these limits control what the adapter will accept.
        .initial_window_size(settings.initial_window)
        .initial_connection_window_size(settings.initial_connection_window)
        .max_frame_size(settings.max_frame)
        .max_concurrent_reset_streams(settings.max_reset_streams as usize)
        .max_pending_accept_reset_streams(settings.max_reset_streams as usize)
        .reset_stream_duration(H2_RESET_RECLAIM)
        .max_send_buffer_size(settings.max_send_buffer as usize);
    let preface_timeout = cfg
        .request_header_timeout
        .max(std::time::Duration::from_secs(1));
    if !httpd_rs_verified::dependency_call_admit(
        true,
        settings.max_frame as u64,
        settings.max_frame as u64,
        settings.max_concurrent_streams as u64,
        settings.max_concurrent_streams as u64,
        settings.max_send_buffer as u64,
        settings.max_send_buffer as u64,
    ) {
        return Err(io::Error::other("HTTP/2 dependency boundary rejected"));
    }
    let handshake = tokio::time::timeout(preface_timeout, builder.handshake(io));
    tokio::pin!(handshake);
    let mut conn = loop {
        tokio::select! {
            biased;
            result = &mut handshake => {
                break result
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP/2 preface timed out"))?
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            }
            result = retired.changed() => {
                if result.is_err() || !httpd_rs_verified::configuration_generation_admit(
                    *retired.borrow(),
                ) {
                    return Ok(());
                }
            }
        }
    };
    // h2's server handshake consumes the 24-byte connection preface but does
    // not wait for the client's mandatory initial SETTINGS. Keep this socket
    // in lightweight admission until `accept` has processed SETTINGS and the
    // first request head. This is deliberately stronger than timing SETTINGS
    // alone: an idle post-SETTINGS peer cannot occupy an established slot.
    let mut ready_callback = Some(on_ready);
    let mut established_guard: Option<G> = None;
    let initial_request_deadline = tokio::time::sleep(preface_timeout);
    tokio::pin!(initial_request_deadline);

    // One ledger stores stream identity, phase, and aggregate capacity. The
    // h2 crate still owns frame parsing and its own reset counters; this loop
    // projects the adapter's task lifecycle and observed reset errors into
    // the verified transition system. Events are prioritized so a completed
    // task releases its slot before another request is accepted.
    let mut lifecycle = H2ConnectionLedger::new(
        settings.max_concurrent_streams as u64,
        settings.max_reset_streams as u64,
    );
    let (events_tx, mut events_rx) = mpsc::channel(settings.max_concurrent_streams as usize);
    let mut tasks = tokio::task::JoinSet::new();
    let mut reset_reclaims: BinaryHeap<Reverse<(Instant, u64)>> = BinaryHeap::new();
    let idle_timeout = cfg.timeout.max(cfg.keep_alive_timeout).max(H2_IDLE_FLOOR);
    let idle_timer = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_timer);
    let mut draining = false;
    let outcome: io::Result<()> = 'connection: loop {
        let reclaim_deadline = reset_reclaims.peek().map(|entry| entry.0 .0);
        let reclaim_timer = tokio::time::sleep_until(
            reclaim_deadline
                .map(tokio::time::Instant::from_std)
                .unwrap_or_else(|| tokio::time::Instant::now() + idle_timeout),
        );
        tokio::pin!(reclaim_timer);
        tokio::select! {
            biased;
            result = retired.changed(), if !draining => {
                if result.is_err() || !httpd_rs_verified::configuration_generation_admit(
                    *retired.borrow(),
                ) {
                    // Emit GOAWAY, refuse new streams in the h2 state machine,
                    // and keep polling until already-admitted tasks finish.
                    conn.graceful_shutdown();
                    draining = true;
                }
            }
            _ = &mut initial_request_deadline, if ready_callback.is_some() && !draining => {
                break 'connection Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP/2 initial SETTINGS/request head timed out",
                ));
            }
            Some(event) = events_rx.recv() => {
                match event {
                    H2TaskEvent::Ended { stream_id, reset } => {
                        // Identity, phase, and capacity move together or not
                        // at all. A failure can also mean reset capacity was
                        // exhausted, so fail closed instead of guessing.
                        if !lifecycle.end(stream_id, reset) {
                            // One RAII guard owns the sole Ended event.
                            // coverage:ignore-start - guard/budget invariant
                            logger.error("HTTP/2 invalid stream lifecycle transition; closing connection");
                            conn.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
                            break 'connection Ok(());
                            // coverage:ignore-stop
                        }
                        if lifecycle.active() == 0 {
                            idle_timer.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                        }
                        if reset {
                            reset_reclaims.push(Reverse((Instant::now() + H2_RESET_RECLAIM, stream_id)));
                        }
                    }
                }
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result {
                    logger.error(&format!("HTTP/2 stream task failed: {error}"));
                }
            }
            _ = &mut reclaim_timer, if reclaim_deadline.is_some() => {
                let now = Instant::now();
                while reset_reclaims
                    .peek()
                    .is_some_and(|entry| entry.0.0 <= now)
                {
                    let Reverse((_, stream_id)) = reset_reclaims
                        .pop()
                        .expect("peeked reset reclaim deadline");
                    // A stale timer cannot reclaim a second time.
                    let _ = lifecycle.reclaim(stream_id);
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)), if draining && lifecycle.active() == 0 => {
                // Give the state machine one scheduling turn to flush GOAWAY,
                // then release an otherwise idle retired transport.
                break 'connection Ok(());
            }
            _ = &mut idle_timer, if lifecycle.active() == 0 => {
                logger.error("HTTP/2 connection idle timeout");
                conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                break 'connection Ok(());
            }
            accepted = conn.accept() => {
                let Some(result) = accepted else {
                    break 'connection Ok(());
                };
                let (request, mut respond) = match result {
                    Ok(stream) => stream,
                    Err(error) => {
                        break 'connection Err(io::Error::new(io::ErrorKind::InvalidData, error));
                    }
                };
                if draining {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    continue;
                }
                let stream_id = respond.stream_id().as_u32() as u64;
                let admission = match cfg.admit_generation_work(|| {
                    admit_stream_before_spawn(&cfg, peer, &request)
                }) {
                    Some(Ok(admission)) => admission,
                    None | Some(Err(_)) => {
                        if !httpd_rs_verified::configuration_generation_admit(*retired.borrow()) {
                            conn.graceful_shutdown();
                            draining = true;
                        }
                        respond.send_reset(h2::Reason::REFUSED_STREAM);
                        continue;
                    }
                };
                if let Some(callback) = ready_callback.take() {
                    established_guard = match callback() {
                        Ok(guard) => Some(guard),
                        Err(error) => break 'connection Err(error),
                    };
                }
                if !lifecycle.begin(stream_id) {
                    // This is unreachable while h2's own stream/identity
                    // admission is at least as strict. Never spawn a task
                    // whose identity and capacity are not both recorded.
                    // coverage:ignore-start - upstream h2 admission invariant
                    logger.error("HTTP/2 lifecycle ledger rejected a stream");
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    continue;
                    // coverage:ignore-stop
                }
                let cfg = cfg.clone();
                let logger = logger.clone();
                let local_ip = local_ip.clone();
                let tls_identity = tls_identity.clone();
                let tx = events_tx.clone();
                let request_scope = admission.request_scope.clone();
                tasks.spawn(crate::fault::scope_future(async move {
                    let _cancel = H2RequestCancelGuard {
                        scope: request_scope,
                    };
                    let mut done = H2TaskEventGuard {
                        tx,
                        stream_id,
                        reset: true,
                    };
                    // Request-body, backend, and response-capacity operations
                    // each own a phase-specific deadline. A whole-stream
                    // timeout would truncate a transfer that keeps making
                    // progress merely because its total duration is long.
                    done.reset = handle_stream(
                        cfg,
                        logger,
                        peer,
                        local_ip,
                        local_port,
                        tls_identity,
                        request,
                        respond,
                        admission,
                    )
                    .await;
                }));
            }
        }
    };
    // `JoinSet` is the connection's ownership boundary. A connection error,
    // idle timeout, GOAWAY completion, callback failure, or generation drain
    // cannot detach request tasks. Aborting first drops each cancellation
    // guard; blocking backend clones observe the shared request scope and
    // retain their ordinary deadline as a final fail-safe.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    // Ended events produced while aborting are intentionally not replayed:
    // connection teardown is the terminal transition for every remaining
    // active or reset-pending stream and releases both counters.
    let ledger_closed = lifecycle.close();
    debug_assert!(ledger_closed);
    if !ledger_closed {
        // coverage:ignore-start - guarded by the verified lifecycle transitions
        logger.error("HTTP/2 lifecycle ledger rejected connection close");
        // coverage:ignore-stop
    }
    drop(established_guard);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::fs::{self, File};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    fn test_config_with_upstream(
        name: &str,
        upstream: &str,
        extra: &str,
    ) -> (Arc<Config>, Arc<Logger>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("httpd-rs-h2-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("www")).unwrap();
        fs::write(dir.join("www/file.txt"), b"hello h2").unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "ServerRoot \"{}\"\n\
                 Listen 127.0.0.1:0\n\
                 ServerName localhost\n\
                 DocumentRoot \"{}/www\"\n\
                 ErrorLog \"{}/error.log\"\n\
                 ProxyPass /__body_test {}\n\
                 {}\n",
                dir.display(),
                dir.display(),
                dir.display(),
                upstream,
                extra
            ),
        )
        .unwrap();
        let cfg = Config::load(&conf, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let cfg = Arc::new(cfg);
        let logger = Arc::new(Logger::new(&cfg).unwrap());
        (cfg, logger, dir)
    }

    fn test_config_with_extra(
        name: &str,
        extra: &str,
    ) -> (Arc<Config>, Arc<Logger>, std::path::PathBuf) {
        test_config_with_upstream(name, "http://127.0.0.1:9/", extra)
    }

    fn test_config(name: &str) -> (Arc<Config>, Arc<Logger>, std::path::PathBuf) {
        test_config_with_extra(name, "")
    }

    fn test_tls_identity(cfg: &Config) -> crate::tls::TlsConnectionIdentity {
        crate::tls::TlsConnectionIdentity::for_test(
            cfg,
            Some("127.0.0.1".parse().unwrap()),
            443,
            None,
        )
    }

    fn stalling_upstream() -> (
        u16,
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Receiver<()>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            use std::io::Read as _;

            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read_exact(&mut byte).is_err() {
                    return;
                }
                head.push(byte[0]);
            }
            let _ = accepted_tx.send(());
            // Never produce response headers. A reset/connection close must
            // cancel the request scope and close this backend transport.
            while matches!(stream.read(&mut byte), Ok(1)) {}
            let _ = closed_tx.send(());
        });
        (port, accepted_rx, closed_rx, thread)
    }

    struct InjectReadFailure<T> {
        inner: T,
        fail: tokio::sync::oneshot::Receiver<()>,
    }

    impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for InjectReadFailure<T> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            use std::future::Future as _;

            if std::pin::Pin::new(&mut self.fail).poll(cx).is_ready() {
                return std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "injected HTTP/2 transport failure",
                )));
            }
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for InjectReadFailure<T> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    async fn wait_for_request_resources_to_drain(cfg: &Config) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if cfg.resource_budget.extended_usage().0 == 0 && cfg.resource_budget.usage().2 == 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("HTTP/2 request resources did not drain after cancellation");
    }

    #[derive(Clone, Copy)]
    enum StreamBodyReceiver {
        Drain,
        Drop,
        Stall,
    }

    enum StreamBodyEnd {
        Data,
        Trailers(http::HeaderMap),
        Reset,
        Open,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum StreamBodyOutcome {
        Complete,
        Reset,
        BackendClosed,
        Response(u16),
    }

    async fn stream_body_case(
        chunks: &[&[u8]],
        end: StreamBodyEnd,
        receiver: StreamBodyReceiver,
        declared: u64,
        limit: u64,
        timeout: Duration,
        min_rate: u64,
        allow_trailers: bool,
        delay_before_first_chunk: Duration,
    ) -> StreamBodyOutcome {
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let server = tokio::spawn(crate::fault::scope_future(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, _) = connection.accept().await.unwrap().unwrap();
            let (sender, mut receiver_channel) = tokio::sync::mpsc::channel(1);
            let drain = match receiver {
                StreamBodyReceiver::Drain => Some(tokio::spawn(async move {
                    while receiver_channel.recv().await.is_some() {}
                })),
                StreamBodyReceiver::Drop => {
                    drop(receiver_channel);
                    None
                }
                StreamBodyReceiver::Stall => {
                    // Retain but deliberately do not poll the backend side.
                    let _receiver = receiver_channel;
                    let result = stream_body(
                        request.into_body(),
                        sender,
                        declared,
                        limit,
                        timeout,
                        min_rate,
                        allow_trailers,
                    )
                    .await;
                    return result;
                }
            };
            let body = stream_body(
                request.into_body(),
                sender,
                declared,
                limit,
                timeout,
                min_rate,
                allow_trailers,
            );
            tokio::pin!(body);
            let result = loop {
                tokio::select! {
                    result = &mut body => break result,
                    accepted = connection.accept() => {
                        if accepted.is_none() {
                            break Err(H2ReadFailure::Reset);
                        }
                    }
                }
            };
            if let Some(drain) = drain {
                drain.abort();
            }
            result
        }));
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/upload")
            .body(())
            .unwrap();
        let (_response, mut send) = client.send_request(request, false).unwrap();
        if !delay_before_first_chunk.is_zero() {
            tokio::time::sleep(delay_before_first_chunk).await;
        }
        for (index, chunk) in chunks.iter().enumerate() {
            send.reserve_capacity(chunk.len());
            let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
                .await
                .unwrap()
                .unwrap();
            assert!(capacity >= chunk.len());
            let last = matches!(end, StreamBodyEnd::Data) && index + 1 == chunks.len();
            send.send_data(Bytes::copy_from_slice(chunk), last).unwrap();
        }
        match end {
            StreamBodyEnd::Data if chunks.is_empty() => {
                send.send_data(Bytes::new(), true).unwrap();
            }
            StreamBodyEnd::Trailers(trailers) => send.send_trailers(trailers).unwrap(),
            StreamBodyEnd::Reset => send.send_reset(h2::Reason::CANCEL),
            StreamBodyEnd::Data | StreamBodyEnd::Open => {}
        }
        let result = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("stream-body case did not terminate")
            .unwrap();
        drop((send, client));
        driver.abort();
        let _ = driver.await;
        match result {
            Ok(()) => StreamBodyOutcome::Complete,
            Err(H2ReadFailure::Reset) => StreamBodyOutcome::Reset,
            Err(H2ReadFailure::BackendClosed) => StreamBodyOutcome::BackendClosed,
            Err(H2ReadFailure::Response(response)) => StreamBodyOutcome::Response(response.status),
        }
    }

    #[cfg(feature = "fault-injection")]
    #[tokio::test(flavor = "current_thread")]
    async fn request_body_transition_awaits_fail_closed() {
        let _fault_guard = crate::fault::test_guard();
        for (boundary, chunks, end, declared) in [
            (
                "transition.h2.body.data-await",
                Vec::<&[u8]>::new(),
                StreamBodyEnd::Open,
                0,
            ),
            (
                "transition.h2.body.backend-await",
                vec![b"body".as_slice()],
                StreamBodyEnd::Data,
                4,
            ),
            (
                "transition.h2.body.trailers-await",
                vec![b"body".as_slice()],
                StreamBodyEnd::Data,
                4,
            ),
        ] {
            crate::fault::clear();
            crate::fault::configure(boundary, 0, io::ErrorKind::ConnectionReset);
            assert_eq!(
                stream_body_case(
                    &chunks,
                    end,
                    StreamBodyReceiver::Drain,
                    declared,
                    1024,
                    Duration::from_secs(1),
                    0,
                    false,
                    Duration::ZERO,
                )
                .await,
                StreamBodyOutcome::Response(503),
                "{boundary}"
            );
            assert!(crate::fault::trace().iter().any(|name| name == boundary));
        }
    }

    async fn round_trip(
        cfg: Arc<Config>,
        logger: Arc<Logger>,
        request: http::Request<()>,
        body: &[u8],
    ) -> (u16, Vec<u8>, bool) {
        round_trip_with_sni(cfg, logger, request, body, None).await
    }

    async fn round_trip_with_sni(
        cfg: Arc<Config>,
        logger: Arc<Logger>,
        request: http::Request<()>,
        body: &[u8],
        sni: Option<&str>,
    ) -> (u16, Vec<u8>, bool) {
        round_trip_with_sni_and_trailers(cfg, logger, request, body, sni, None).await
    }

    async fn round_trip_with_trailers(
        cfg: Arc<Config>,
        logger: Arc<Logger>,
        request: http::Request<()>,
        body: &[u8],
        trailers: http::HeaderMap,
    ) -> (u16, Vec<u8>, bool) {
        round_trip_with_sni_and_trailers(cfg, logger, request, body, None, Some(trailers)).await
    }

    async fn round_trip_with_sni_and_trailers(
        cfg: Arc<Config>,
        logger: Arc<Logger>,
        request: http::Request<()>,
        body: &[u8],
        sni: Option<&str>,
        trailers: Option<http::HeaderMap>,
    ) -> (u16, Vec<u8>, bool) {
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let tls_identity = crate::tls::TlsConnectionIdentity::for_test(
            &cfg,
            Some("127.0.0.1".parse().unwrap()),
            443,
            sni,
        );
        let server = tokio::spawn(crate::fault::scope_future(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, respond) = connection.accept().await.unwrap().unwrap();
            let admission =
                admit_stream_before_spawn(&cfg, "127.0.0.1:12345".parse().unwrap(), &request)
                    .unwrap();
            let handler = handle_stream(
                cfg,
                logger,
                "127.0.0.1:12345".parse().unwrap(),
                "127.0.0.1".into(),
                443,
                tls_identity,
                request,
                respond,
                admission,
            );
            tokio::pin!(handler);
            let reset = loop {
                tokio::select! {
                    reset = &mut handler => break reset,
                    accepted = connection.accept() => {
                        if accepted.is_none() {
                            break true;
                        }
                    }
                }
            };
            loop {
                tokio::select! {
                    _ = &mut done_rx => break,
                    accepted = connection.accept() => {
                        if accepted.is_none() {
                            break;
                        }
                    }
                }
            }
            reset
        }));
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await.unwrap() });
        let request_label = format!("{} {}", request.method(), request.uri());
        let head_only = request.method() == http::Method::HEAD;
        let end = body.is_empty() && trailers.is_none();
        let (response, mut send) = client.send_request(request, end).unwrap();
        if !end {
            let mut offset = 0usize;
            while offset < body.len() {
                send.reserve_capacity(body.len() - offset);
                let Some(capacity) = std::future::poll_fn(|cx| send.poll_capacity(cx)).await else {
                    break;
                };
                let Ok(capacity) = capacity else {
                    break;
                };
                let take = capacity.min(body.len() - offset);
                let last = offset + take == body.len() && trailers.is_none();
                if send
                    .send_data(Bytes::copy_from_slice(&body[offset..offset + take]), last)
                    .is_err()
                {
                    break;
                }
                offset += take;
            }
            if let Some(trailers) = trailers {
                send.send_trailers(trailers).unwrap();
            }
        }
        let response = tokio::time::timeout(std::time::Duration::from_secs(2), response)
            .await
            .expect("HTTP/2 response timed out")
            .unwrap_or_else(|error| panic!("HTTP/2 response failed for {request_label}: {error}"));
        let status = response.status().as_u16();
        let mut recv = response.into_body();
        let mut response_body = Vec::new();
        if !head_only {
            while let Some(chunk) =
                tokio::time::timeout(std::time::Duration::from_secs(2), recv.data())
                    .await
                    .expect("HTTP/2 response body timed out")
            {
                response_body.extend_from_slice(&chunk.unwrap());
            }
        }
        let _ = done_tx.send(());
        drop(client);
        driver.abort();
        let _ = driver.await;
        let reset = tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("HTTP/2 server task timed out")
            .unwrap();
        (status, response_body, reset)
    }

    #[cfg(feature = "fault-injection")]
    async fn round_trip_expecting_reset(
        cfg: Arc<Config>,
        logger: Arc<Logger>,
        request: http::Request<()>,
        body: &[u8],
        finish_body: bool,
    ) -> h2::Reason {
        let (client_io, server_io) = tokio::io::duplex(4 * 1024 * 1024);
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let tls_identity = test_tls_identity(&cfg);
        let server = tokio::spawn(crate::fault::scope_future(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, respond) = connection.accept().await.unwrap().unwrap();
            let admission =
                admit_stream_before_spawn(&cfg, "127.0.0.1:12345".parse().unwrap(), &request)
                    .unwrap();
            let handler = handle_stream(
                cfg,
                logger,
                "127.0.0.1:12345".parse().unwrap(),
                "127.0.0.1".into(),
                443,
                tls_identity,
                request,
                respond,
                admission,
            );
            tokio::pin!(handler);
            let reset = loop {
                tokio::select! {
                    reset = &mut handler => break reset,
                    accepted = connection.accept() => {
                        if accepted.is_none() {
                            break true;
                        }
                    }
                }
            };
            loop {
                tokio::select! {
                    _ = &mut done_rx => break,
                    accepted = connection.accept() => {
                        if accepted.is_none() {
                            break;
                        }
                    }
                }
            }
            reset
        }));
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let (response, mut send) = client
            .send_request(request, body.is_empty() && finish_body)
            .unwrap();
        if !body.is_empty() {
            let mut offset = 0usize;
            while offset < body.len() {
                send.reserve_capacity(body.len() - offset);
                let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
                    .await
                    .expect("reset arrived before request DATA was admitted")
                    .expect("request DATA capacity failed");
                let take = capacity.min(body.len() - offset);
                let last = finish_body && offset + take == body.len();
                send.send_data(Bytes::copy_from_slice(&body[offset..offset + take]), last)
                    .unwrap();
                offset += take;
            }
        }
        let error = tokio::time::timeout(Duration::from_secs(2), response)
            .await
            .expect("faulted HTTP/2 request did not reset")
            .expect_err("faulted slow-input reacquisition returned a response");
        let reason = error.reason().expect("HTTP/2 reset omitted its reason");
        let _ = done_tx.send(());
        drop((send, client));
        driver.abort();
        let _ = driver.await;
        assert!(server.await.unwrap());
        reason
    }

    #[tokio::test(flavor = "current_thread")]
    async fn slow_input_saturation_returns_a_bounded_overload_response() {
        let (cfg, logger, dir) = test_config("slow-input-overload");
        let mut occupied = Vec::new();
        for source in 1..=4 {
            for _ in 0..crate::resource::MAX_SLOW_INPUTS_PER_CLIENT {
                let context = cfg
                    .resource_budget
                    .context(std::net::IpAddr::from([192, 0, 2, source]));
                occupied.push(cfg.resource_budget.try_slow_input_in(&context).unwrap());
            }
        }
        assert_eq!(
            cfg.resource_budget.h2_input_usage(),
            (0, crate::resource::MAX_SLOW_INPUTS)
        );
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/__body_test")
            .body(())
            .unwrap();
        assert_eq!(round_trip(cfg.clone(), logger, request, b"x").await.0, 503);
        drop(occupied);
        assert_eq!(cfg.resource_budget.h2_input_usage(), (0, 0));
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(feature = "fault-injection")]
    #[tokio::test(flavor = "current_thread")]
    async fn slow_input_reacquisition_faults_reset_every_body_path() {
        let _fault_guard = crate::fault::test_guard();

        let (cfg, logger, dir) = test_config("slow-input-buffered-reacquire");
        crate::fault::configure(
            "transition.h2.slow-input-reacquire",
            0,
            io::ErrorKind::WouldBlock,
        );
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/__body_test")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip_expecting_reset(cfg, logger, request, b"x", true).await,
            h2::Reason::REFUSED_STREAM
        );
        fs::remove_dir_all(dir).unwrap();

        let (cfg, logger, dir) = test_config("slow-input-error-reacquire");
        let mut limited = (*cfg).clone();
        limited.limit_request_body = 2;
        crate::fault::configure(
            "transition.h2.slow-input-reacquire",
            0,
            io::ErrorKind::WouldBlock,
        );
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/__body_test")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip_expecting_reset(Arc::new(limited), logger, request, b"too large", true,)
                .await,
            h2::Reason::REFUSED_STREAM
        );
        fs::remove_dir_all(dir).unwrap();

        let (cfg, logger, dir) = test_config("slow-input-stream-install-reacquire");
        crate::fault::configure(
            "transition.h2.streaming-body-install",
            0,
            io::ErrorKind::OutOfMemory,
        );
        crate::fault::configure(
            "transition.h2.slow-input-reacquire",
            0,
            io::ErrorKind::WouldBlock,
        );
        let length = crate::http::MAX_REQUEST_BODY_IN_MEMORY + 1;
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/__body_test")
            .header("content-length", length.to_string())
            .body(())
            .unwrap();
        assert_eq!(
            round_trip_expecting_reset(cfg, logger, request, &[], false).await,
            h2::Reason::REFUSED_STREAM
        );
        fs::remove_dir_all(dir).unwrap();

        let (port, accepted, closed, upstream) = stalling_upstream();
        let upstream_url = format!("http://127.0.0.1:{port}/");
        let (cfg, logger, dir) =
            test_config_with_upstream("slow-input-stream-complete-reacquire", &upstream_url, "");
        crate::fault::configure(
            "transition.h2.slow-input-reacquire",
            0,
            io::ErrorKind::WouldBlock,
        );
        let length = crate::http::MAX_REQUEST_BODY_IN_MEMORY + 1;
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/__body_test")
            .header("content-length", length.to_string())
            .body(())
            .unwrap();
        let body = vec![b'x'; length as usize];
        assert_eq!(
            round_trip_expecting_reset(cfg, logger, request, &body, true).await,
            h2::Reason::REFUSED_STREAM
        );
        accepted.await.unwrap();
        closed
            .recv_timeout(Duration::from_secs(2))
            .expect("reset did not close the streaming upstream");
        upstream.join().unwrap();
        fs::remove_dir_all(dir).unwrap();

        let (cfg, logger, dir) = test_config("slow-input-stream-read-reacquire");
        crate::fault::configure(
            "transition.h2.body.data-await",
            0,
            io::ErrorKind::ConnectionReset,
        );
        crate::fault::configure(
            "transition.h2.slow-input-reacquire",
            0,
            io::ErrorKind::WouldBlock,
        );
        let length = crate::http::MAX_REQUEST_BODY_IN_MEMORY + 1;
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/__body_test")
            .header("content-length", length.to_string())
            .body(())
            .unwrap();
        assert_eq!(
            round_trip_expecting_reset(cfg, logger, request, &[], false).await,
            h2::Reason::REFUSED_STREAM
        );
        fs::remove_dir_all(dir).unwrap();
    }

    async fn response_round_trip(
        cfg: Arc<Config>,
        response: Response,
        head_only: bool,
    ) -> (io::Result<u64>, u16, http::HeaderMap, Vec<u8>) {
        response_round_trip_with_window(cfg, response, head_only, None).await
    }

    async fn response_round_trip_with_window(
        cfg: Arc<Config>,
        response: Response,
        head_only: bool,
        initial_window: Option<u32>,
    ) -> (io::Result<u64>, u16, http::HeaderMap, Vec<u8>) {
        let (client_io, server_io) = tokio::io::duplex(32 * 1024 * 1024);
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(crate::fault::scope_future(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (_, respond) = connection.accept().await.unwrap().unwrap();
            let sender = send_response(
                respond,
                &cfg,
                std::net::IpAddr::from([127, 0, 0, 1]),
                response,
                head_only,
            );
            tokio::pin!(sender);
            let result = loop {
                tokio::select! {
                    result = &mut sender => break result,
                    accepted = connection.accept() => {
                        if accepted.is_none() {
                            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "client closed"));
                        }
                    }
                }
            };
            loop {
                tokio::select! {
                    _ = &mut done_rx => break,
                    accepted = connection.accept() => {
                        if accepted.is_none() {
                            break;
                        }
                    }
                }
            }
            result
        }));
        let mut builder = h2::client::Builder::new();
        if let Some(initial_window) = initial_window {
            builder.initial_window_size(initial_window);
        }
        let (mut client, connection) = builder.handshake::<_, Bytes>(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = http::Request::builder()
            .method(if head_only { "HEAD" } else { "GET" })
            .uri("https://localhost/body")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let mut body = Vec::new();
        if !head_only {
            let mut recv = response.into_body();
            while let Some(chunk) = recv.data().await {
                match chunk {
                    Ok(chunk) => {
                        let len = chunk.len();
                        body.extend_from_slice(&chunk);
                        recv.flow_control().release_capacity(len).unwrap();
                    }
                    Err(_) => break,
                }
            }
        }
        let _ = done_tx.send(());
        let result = server.await.unwrap();
        drop(client);
        driver.abort();
        let _ = driver.await;
        (result, status, headers, body)
    }

    async fn assert_stalled_response_transport_lifetime(
        cfg: Arc<Config>,
        response: Response,
        expected_body: &[u8],
        minimum_resident: u64,
    ) {
        let budget = cfg.resource_budget.clone();
        let client_ip = std::net::IpAddr::from([127, 0, 0, 1]);
        let context = budget.context(client_ip);
        let general = budget.try_h2_stream_in(&context).unwrap();
        let mut output = crate::resource::SlowOutputAdmission::tracked_h2(context, general);

        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let (server_handshake, client_handshake) = tokio::join!(
            h2::server::handshake(server_io),
            h2::client::handshake(client_io)
        );
        let mut connection = server_handshake.unwrap();
        let (mut client, client_connection) = client_handshake.unwrap();
        let client_driver = tokio::spawn(async move { client_connection.await });
        let request = http::Request::builder()
            .uri("https://localhost/stalled-output")
            .body(())
            .unwrap();
        let (mut received, _) = client.send_request(request, true).unwrap();
        let (_, respond) = connection.accept().await.unwrap().unwrap();

        send_response_with_admission(respond, &cfg, response, false, &mut output)
            .await
            .unwrap();
        let usage = budget.extended_usage();
        assert_eq!(usage.0, 1, "queued response released H2 admission");
        assert!(
            usage.2 >= minimum_resident,
            "queued response released resident accounting: {} < {minimum_resident}",
            usage.2
        );
        assert_eq!(budget.telemetry().queued_h2_outputs, 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut received)
                .await
                .is_err(),
            "response arrived while the server connection was not being polled"
        );

        let server_driver =
            tokio::spawn(async move { while connection.accept().await.is_some() {} });
        let response = tokio::time::timeout(Duration::from_secs(1), &mut received)
            .await
            .expect("queued response did not flush")
            .unwrap();
        let mut recv = response.into_body();
        let mut body = Vec::new();
        while let Some(chunk) = recv.data().await {
            let chunk = chunk.unwrap();
            let len = chunk.len();
            body.extend_from_slice(&chunk);
            recv.flow_control().release_capacity(len).unwrap();
        }
        assert_eq!(body, expected_body);
        tokio::time::timeout(Duration::from_secs(1), async {
            while budget.extended_usage().0 != 0
                || budget.extended_usage().2 != 0
                || budget.telemetry().queued_h2_outputs != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("queued response ownership did not release after flush");

        drop(client);
        client_driver.abort();
        server_driver.abort();
        let _ = client_driver.await;
        let _ = server_driver.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queued_header_only_response_retains_memory_and_stream_admission() {
        let (cfg, _logger, dir) = test_config("queued-header-ownership");
        let budget = cfg.resource_budget.clone();
        let client_ip = std::net::IpAddr::from([127, 0, 0, 1]);
        let context = budget.context(client_ip);
        let general = budget.try_h2_stream_in(&context).unwrap();
        let mut output = crate::resource::SlowOutputAdmission::tracked_h2(context.clone(), general);

        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let (server_handshake, client_handshake) = tokio::join!(
            h2::server::handshake(server_io),
            h2::client::handshake(client_io)
        );
        let mut connection = server_handshake.unwrap();
        let (mut client, client_connection) = client_handshake.unwrap();
        let client_driver = tokio::spawn(async move { client_connection.await });

        let request = http::Request::builder()
            .uri("https://localhost/header-only")
            .body(())
            .unwrap();
        let (mut received, _) = client.send_request(request, true).unwrap();
        let (_, respond) = connection.accept().await.unwrap().unwrap();

        let retained = vec![b'h'; 60 * 1024];
        let expected_resident = 256 + b"x-retained".len() as u64 + retained.len() as u64 + 4;
        let mut response = Response::new(204);
        response
            .headers
            .push((Cow::Borrowed("x-retained"), retained));
        assert_eq!(
            send_response_with_admission(respond, &cfg, response, false, &mut output)
                .await
                .unwrap(),
            0
        );

        // Do not poll the server connection after enqueue. The h2 state
        // machine therefore still owns the HeaderMap, and both the resident
        // bytes and general stream admission must follow that queued owner.
        let usage = budget.extended_usage();
        assert_eq!(usage.0, 1, "queued response head released H2 admission");
        assert_eq!(
            usage.2, expected_resident,
            "queued response head released resident accounting"
        );
        assert_eq!(budget.telemetry().queued_h2_outputs, 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut received)
                .await
                .is_err(),
            "response arrived while the server connection was not being polled"
        );

        let server_driver =
            tokio::spawn(async move { while connection.accept().await.is_some() {} });
        let received = tokio::time::timeout(Duration::from_secs(1), &mut received)
            .await
            .expect("queued response head did not flush")
            .unwrap();
        assert_eq!(received.status(), StatusCode::NO_CONTENT);
        tokio::time::timeout(Duration::from_secs(1), async {
            while budget.extended_usage().0 != 0
                || budget.extended_usage().2 != 0
                || budget.telemetry().queued_h2_outputs != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("queued response ownership did not release after flush");

        drop((received, client));
        client_driver.abort();
        server_driver.abort();
        let _ = client_driver.await;
        let _ = server_driver.await;
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn indexable_response_header_cannot_retain_transport_ownership_in_hpack() {
        let (cfg, _logger, dir) = test_config("indexable-header-ownership");
        let mut response = Response::new(204);
        response
            .headers
            .push((Cow::Borrowed("x-indexable"), b"small-value".to_vec()));
        assert_stalled_response_transport_lifetime(cfg, response, &[], 256).await;
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn every_body_shape_retains_head_memory_and_stream_admission_until_transport_release() {
        let (cfg, _logger, dir) = test_config("all-body-transport-ownership");
        let retained = vec![b'h'; 60 * 1024];
        let body = b"body-data".to_vec();

        let mut bytes = Response::bytes(200, "application/octet-stream", body.clone());
        bytes
            .headers
            .push((Cow::Borrowed("x-retained"), retained.clone()));
        assert_stalled_response_transport_lifetime(
            cfg.clone(),
            bytes,
            &body,
            retained.len() as u64,
        )
        .await;

        let path = dir.join("queued-body.bin");
        fs::write(&path, &body).unwrap();
        let mut file = Response::new(200);
        file.headers
            .push((Cow::Borrowed("x-retained"), retained.clone()));
        file.body = Body::File {
            file: File::open(&path).unwrap(),
            offset: 0,
            len: body.len() as u64,
        };
        assert_stalled_response_transport_lifetime(cfg.clone(), file, &body, retained.len() as u64)
            .await;

        let mut stream = Response::new(200);
        stream
            .headers
            .push((Cow::Borrowed("x-retained"), retained.clone()));
        stream.body = Body::Stream {
            reader: Box::new(std::io::Cursor::new(body.clone())),
            len: body.len() as u64,
        };
        assert_stalled_response_transport_lifetime(cfg, stream, &body, retained.len() as u64).await;

        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queued_response_ownership_releases_on_reset_and_connection_drop() {
        for reset in [true, false] {
            let (cfg, _logger, dir) = test_config(if reset {
                "queued-owner-reset"
            } else {
                "queued-owner-drop"
            });
            let budget = cfg.resource_budget.clone();
            let client_ip = std::net::IpAddr::from([127, 0, 0, 1]);
            let context = budget.context(client_ip);
            let general = budget.try_h2_stream_in(&context).unwrap();
            let mut output = crate::resource::SlowOutputAdmission::tracked_h2(context, general);
            let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
            let (server_handshake, client_handshake) = tokio::join!(
                h2::server::handshake(server_io),
                h2::client::handshake(client_io)
            );
            let mut connection = server_handshake.unwrap();
            let (mut client, client_connection) = client_handshake.unwrap();
            let client_driver = tokio::spawn(async move { client_connection.await });
            let request = http::Request::builder()
                .uri("https://localhost/release-owner")
                .body(())
                .unwrap();
            let (_received, mut request_stream) = client.send_request(request, true).unwrap();
            let (_, respond) = connection.accept().await.unwrap().unwrap();
            let mut response = Response::new(204);
            response
                .headers
                .push((Cow::Borrowed("x-owner"), b"release-me".to_vec()));
            send_response_with_admission(respond, &cfg, response, false, &mut output)
                .await
                .unwrap();
            assert_eq!(budget.telemetry().queued_h2_outputs, 1);

            let server_driver = if reset {
                request_stream.send_reset(h2::Reason::CANCEL);
                Some(tokio::spawn(async move {
                    while connection.accept().await.is_some() {}
                }))
            } else {
                drop(connection);
                None
            };
            tokio::time::timeout(Duration::from_secs(1), async {
                while budget.extended_usage().0 != 0
                    || budget.extended_usage().2 != 0
                    || budget.telemetry().queued_h2_outputs != 0
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("queued H2 ownership did not release on reset/drop");

            drop((request_stream, client));
            client_driver.abort();
            let _ = client_driver.await;
            if let Some(server_driver) = server_driver {
                server_driver.abort();
                let _ = server_driver.await;
            }
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_policy_denial_does_not_wait_for_request_data() {
        let (cfg, logger, dir) = test_config_with_extra(
            "lazy-policy",
            "<Location \"/\">\nRequire all denied\n</Location>",
        );
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, respond) = connection.accept().await.unwrap().unwrap();
            let admission =
                admit_stream_before_spawn(&cfg, "127.0.0.1:12345".parse().unwrap(), &request)
                    .unwrap();
            let tls_identity = test_tls_identity(&cfg);
            let handler = handle_stream(
                cfg,
                logger,
                "127.0.0.1:12345".parse().unwrap(),
                "127.0.0.1".into(),
                443,
                tls_identity,
                request,
                respond,
                admission,
            );
            tokio::pin!(handler);
            let reset = loop {
                tokio::select! {
                    reset = &mut handler => break reset,
                    accepted = connection.accept() => {
                        if accepted.is_none() {
                            return true;
                        }
                    }
                }
            };
            loop {
                tokio::select! {
                    _ = &mut done_rx => break,
                    accepted = connection.accept() => {
                        if accepted.is_none() {
                            break;
                        }
                    }
                }
            }
            reset
        });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/file.txt")
            .header("content-length", "1048576")
            .body(())
            .unwrap();
        let (response, send) = client.send_request(request, false).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(1), response)
            .await
            .expect("policy response waited for DATA")
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        drop(send);
        let _ = done_tx.send(());
        let reset = tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("server did not finish")
            .unwrap();
        assert!(!reset);
        drop(client);
        driver.abort();
        let _ = driver.await;
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_large_proxy_upload_streams_through_the_bounded_body_channel() {
        use std::io::{Read as _, Write as _};

        let body_len = crate::http::MAX_REQUEST_BODY_IN_MEMORY as usize + 64 * 1024;
        let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
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
                assert!(chunk[..read].iter().all(|byte| *byte == b'h'));
                received += read;
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")
                .unwrap();
        });

        let (cfg, logger, dir) = test_config_with_extra(
            "streaming-proxy-upload",
            &format!("ProxyPass /upload http://127.0.0.1:{upstream_port}/upload"),
        );
        let body = vec![b'h'; body_len];
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/upload")
            .header("content-length", body_len.to_string())
            .body(())
            .unwrap();
        let (status, response_body, reset) = round_trip(cfg, logger, request, &body).await;
        assert_eq!(status, 200);
        assert_eq!(response_body, b"ok\n");
        assert!(!reset);

        upstream_thread.join().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_get_with_body_bypasses_a_preexisting_cache_entry() {
        let name = "body-cache-bypass";
        let root = std::env::temp_dir().join(format!("httpd-rs-h2-{name}-{}", std::process::id()));
        let extra = format!(
            "CacheRoot \"{}\"\nCacheEnable disk /",
            root.join("cache").display()
        );
        let (cfg, logger, dir) = test_config_with_extra(name, &extra);
        let request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/file.txt")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip(cfg.clone(), logger.clone(), request, &[])
                .await
                .1,
            b"hello h2"
        );

        fs::write(dir.join("www/file.txt"), b"changed after cache").unwrap();
        let request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/file.txt")
            .header("content-length", "1")
            .body(())
            .unwrap();
        let (status, body, reset) = round_trip(cfg, logger, request, b"x").await;
        assert_eq!(status, 200);
        assert_eq!(body, b"changed after cache");
        assert!(!reset);
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_request_trailers_are_capability_gated_and_route_neutral() {
        let (cfg, logger, dir) = test_config("trailers-disabled");
        let request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/file.txt")
            .header("content-length", "1")
            .body(())
            .unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-checksum", http::HeaderValue::from_static("ok"));
        let (status, _, reset) =
            round_trip_with_trailers(cfg, logger, request, b"x", trailers).await;
        assert_eq!(status, 400);
        assert!(!reset);
        fs::remove_dir_all(dir).unwrap();

        let (cfg, logger, dir) =
            test_config_with_extra("trailers-enabled", "HttpdRsCapability RequestTrailers On");
        let request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/file.txt")
            .header("content-length", "1")
            .body(())
            .unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-checksum", http::HeaderValue::from_static("ok"));
        let (status, body, reset) =
            round_trip_with_trailers(cfg.clone(), logger.clone(), request, b"x", trailers).await;
        assert_eq!(status, 200);
        assert_eq!(body, b"hello h2");
        assert!(!reset);

        // Trailer fields are never allowed to alter framing or routing after
        // authorization and handler selection have already completed.
        let request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/file.txt")
            .header("content-length", "1")
            .body(())
            .unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("content-length", http::HeaderValue::from_static("0"));
        assert_eq!(
            round_trip_with_trailers(cfg.clone(), logger.clone(), request, b"x", trailers)
                .await
                .0,
            400
        );

        let request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/file.txt")
            .header("content-length", "1")
            .body(())
            .unwrap();
        let mut trailers = http::HeaderMap::new();
        for index in 0..=H2_MAX_REQUEST_TRAILERS {
            trailers.insert(
                http::HeaderName::from_bytes(format!("x-trailer-{index}").as_bytes()).unwrap(),
                http::HeaderValue::from_static("v"),
            );
        }
        assert_eq!(
            round_trip_with_trailers(cfg, logger, request, b"x", trailers)
                .await
                .0,
            400
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn streaming_request_body_covers_terminal_and_failure_states() {
        assert_eq!(
            stream_body_case(
                &[b"a", b"b"],
                StreamBodyEnd::Data,
                StreamBodyReceiver::Drain,
                2,
                2,
                Duration::from_secs(1),
                0,
                false,
                Duration::ZERO,
            )
            .await,
            StreamBodyOutcome::Complete
        );
        assert_eq!(
            stream_body_case(
                &[b"ab"],
                StreamBodyEnd::Data,
                StreamBodyReceiver::Drain,
                2,
                1,
                Duration::from_secs(1),
                0,
                false,
                Duration::ZERO,
            )
            .await,
            StreamBodyOutcome::Response(413)
        );
        assert_eq!(
            stream_body_case(
                &[b"ab"],
                StreamBodyEnd::Data,
                StreamBodyReceiver::Drain,
                1,
                2,
                Duration::from_secs(1),
                0,
                false,
                Duration::ZERO,
            )
            .await,
            StreamBodyOutcome::Response(400)
        );
        assert_eq!(
            stream_body_case(
                &[b"a"],
                StreamBodyEnd::Data,
                StreamBodyReceiver::Drain,
                2,
                2,
                Duration::from_secs(1),
                0,
                false,
                Duration::ZERO,
            )
            .await,
            StreamBodyOutcome::Response(400)
        );
        assert_eq!(
            stream_body_case(
                &[b"a"],
                StreamBodyEnd::Data,
                StreamBodyReceiver::Drop,
                1,
                1,
                Duration::from_secs(1),
                0,
                false,
                Duration::ZERO,
            )
            .await,
            StreamBodyOutcome::BackendClosed
        );
        assert_eq!(
            stream_body_case(
                &[b"a", b"b"],
                StreamBodyEnd::Data,
                StreamBodyReceiver::Stall,
                2,
                2,
                Duration::from_millis(20),
                0,
                false,
                Duration::ZERO,
            )
            .await,
            StreamBodyOutcome::Response(408)
        );
        assert_eq!(
            stream_body_case(
                &[],
                StreamBodyEnd::Open,
                StreamBodyReceiver::Drain,
                0,
                1,
                Duration::from_millis(20),
                0,
                false,
                Duration::ZERO,
            )
            .await,
            StreamBodyOutcome::Response(408)
        );
        assert_eq!(
            stream_body_case(
                &[],
                StreamBodyEnd::Reset,
                StreamBodyReceiver::Drain,
                0,
                1,
                Duration::from_secs(1),
                0,
                false,
                Duration::ZERO,
            )
            .await,
            StreamBodyOutcome::Reset
        );
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-checksum", http::HeaderValue::from_static("ok"));
        assert_eq!(
            stream_body_case(
                &[b"a"],
                StreamBodyEnd::Trailers(trailers),
                StreamBodyReceiver::Drain,
                1,
                1,
                Duration::from_secs(1),
                0,
                true,
                Duration::ZERO,
            )
            .await,
            StreamBodyOutcome::Complete
        );
        assert_eq!(
            stream_body_case(
                &[b"a"],
                StreamBodyEnd::Data,
                StreamBodyReceiver::Drain,
                1,
                1,
                Duration::from_secs(2),
                1024,
                false,
                Duration::from_millis(1_050),
            )
            .await,
            StreamBodyOutcome::Response(408)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_adapter_handles_files_heads_bounds_and_body_errors() {
        let (cfg, logger, dir) = test_config("adapter");
        let read_leases: Vec<_> = (0..crate::resource::MAX_RESPONSE_BODY_READS)
            .map(|_| cfg.resource_budget.try_response_body_read().unwrap())
            .collect();
        assert!(cfg.resource_budget.try_response_body_read().is_err());
        let request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/file.txt?x=1")
            .header("host", "ignored.example")
            .body(())
            .unwrap();
        let (status, body, reset) = round_trip(cfg.clone(), logger.clone(), request, &[]).await;
        assert_eq!(status, 200);
        assert_eq!(body, b"hello h2");
        assert!(!reset);
        assert_eq!(
            cfg.resource_budget.extended_usage().3,
            read_leases.len() as u64
        );
        drop(read_leases);

        let request = http::Request::builder()
            .method("HEAD")
            .uri("https://localhost/file.txt")
            .body(())
            .unwrap();
        let (status, body, _) = round_trip(cfg.clone(), logger.clone(), request, &[]).await;
        assert_eq!(status, 200);
        assert!(body.is_empty());

        let mut static_only = (*cfg).clone();
        static_only.body_handlers_possible = false;
        let request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/file.txt")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip(Arc::new(static_only.clone()), logger.clone(), request, b"x")
                .await
                .0,
            400
        );
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/file.txt")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip(Arc::new(static_only), logger.clone(), request, b"x")
                .await
                .0,
            405
        );

        let mut limited = (*cfg).clone();
        limited.limit_request_line = 2;
        let request = http::Request::builder()
            .uri("https://localhost/file.txt")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip(Arc::new(limited), logger.clone(), request, &[])
                .await
                .0,
            414
        );

        let mut limited = (*cfg).clone();
        limited.limit_request_fields = 0;
        let request = http::Request::builder()
            .uri("https://localhost/")
            .header("x-test", "yes")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip(Arc::new(limited), logger.clone(), request, &[])
                .await
                .0,
            431
        );

        // A traditional CONNECT request is valid at the h2 framing layer,
        // but httpd-rs does not implement tunnels and must reject the
        // authority-form target before normal request dispatch.
        let request = http::Request::builder()
            .method("CONNECT")
            .uri("localhost:443")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip(cfg.clone(), logger.clone(), request, &[])
                .await
                .0,
            400
        );

        let mut limited = (*cfg).clone();
        limited.limit_request_field_size = 1;
        let request = http::Request::builder()
            .uri("https://localhost/")
            .header("x", "long")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip(Arc::new(limited), logger.clone(), request, &[])
                .await
                .0,
            431
        );

        let mut limited = (*cfg).clone();
        limited.limit_request_body = 32;
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/file.txt")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip(Arc::new(limited), logger.clone(), request, b"small body")
                .await
                .0,
            405
        );

        let mut limited = (*cfg).clone();
        limited.limit_request_body = 512 * 1024;
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/file.txt")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip(
                Arc::new(limited),
                logger.clone(),
                request,
                &vec![b'x'; 300 * 1024],
            )
            .await
            .0,
            405
        );

        let mut spool_limited = (*cfg).clone();
        spool_limited.limit_request_body = 512 * 1024;
        spool_limited.max_spool_bytes = 1024;
        spool_limited.max_spool_files = 1;
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/__body_test")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip(
                Arc::new(spool_limited),
                logger.clone(),
                request,
                &vec![b'x'; 80 * 1024],
            )
            .await
            .0,
            503
        );

        let mut limited = (*cfg).clone();
        limited.limit_request_body = 2;
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/__body_test")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip(Arc::new(limited), logger.clone(), request, b"too large")
                .await
                .0,
            413
        );
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/__body_test")
            .header("content-length", "9")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip(
                Arc::new({
                    let mut limited = (*cfg).clone();
                    limited.limit_request_body = 2;
                    limited
                }),
                logger.clone(),
                request,
                b"too large",
            )
            .await
            .0,
            413
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_duplicate_fields_are_canonicalized_before_policy() {
        let name = "duplicate-policy";
        let dir = std::env::temp_dir().join(format!("httpd-rs-h2-{name}-{}", std::process::id()));
        let directory = dir.join("www");
        let extra = format!(
            "<Directory \"{}\">\nRequire expr \"%{{HTTP:X-Gate}} == 'allow, deny'\"\n</Directory>",
            directory.display()
        );
        let (cfg, logger, dir) = test_config_with_extra(name, &extra);
        let mut request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/file.txt")
            .body(())
            .unwrap();
        request
            .headers_mut()
            .append("x-gate", http::HeaderValue::from_static("allow"));
        request
            .headers_mut()
            .append("x-gate", http::HeaderValue::from_static("deny"));

        let (status, body, reset) = round_trip(cfg.clone(), logger.clone(), request, &[]).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        assert_eq!(body, b"hello h2");
        assert!(!reset);

        // LimitRequestFields counts wire field lines before canonicalization;
        // merging duplicates must not let them evade the raw-line limit.
        let mut limited = (*cfg).clone();
        limited.limit_request_fields = 2;
        let mut request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/file.txt")
            .body(())
            .unwrap();
        request
            .headers_mut()
            .append("x-gate", http::HeaderValue::from_static("allow"));
        request
            .headers_mut()
            .append("x-gate", http::HeaderValue::from_static("deny"));
        assert_eq!(
            round_trip(Arc::new(limited), logger, request, &[]).await.0,
            431
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_remoteip_identity_is_bounded_before_stream_admission() {
        let (cfg, logger, dir) = test_config_with_extra(
            "remoteip-admission",
            "RemoteIPHeader X-Forwarded-For\n\
             RemoteIPTrustedProxy 127.0.0.1\n\
             LimitRequestFieldSize 32",
        );
        let mut request = http::Request::builder()
            .method("GET")
            .uri("https://localhost/file.txt")
            .body(())
            .unwrap();
        // Each wire field fits independently, but the value used by
        // mod_remoteip semantics is the comma-merged field. Reject before
        // quota admission if that effective identity operand exceeds the
        // configured field bound.
        request.headers_mut().append(
            "x-forwarded-for",
            http::HeaderValue::from_static("198.51.100.1"),
        );
        request.headers_mut().append(
            "x-forwarded-for",
            http::HeaderValue::from_static("203.0.113.1"),
        );
        assert_eq!(round_trip(cfg, logger, request, &[]).await.0, 431);
        fs::remove_dir_all(dir).unwrap();

        let (cfg, logger, dir) = test_config_with_extra(
            "remoteip-host-admission",
            "RemoteIPHeader Host\nRemoteIPTrustedProxy 127.0.0.1",
        );
        let request = http::Request::builder()
            .method("GET")
            .uri("https://198.51.100.1/file.txt")
            // HTTP/2 canonicalization intentionally ignores this legacy
            // field in favor of :authority. Admission must do likewise.
            .header("host", "203.0.113.1")
            .body(())
            .unwrap();
        assert_eq!(round_trip(cfg, logger, request, &[]).await.0, 200);
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_coalescing_cannot_cross_a_tls_vhost_policy() {
        let (cfg, logger, dir) = test_config_with_extra(
            "tls-vhost-coalescing",
            "<VirtualHost *:443>\n\
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
             </VirtualHost>",
        );
        let request = http::Request::builder()
            .method("GET")
            .uri("https://b.test/file.txt")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip_with_sni(cfg.clone(), logger.clone(), request, &[], Some("a.test"))
                .await
                .0,
            421
        );
        let request = http::Request::builder()
            .method("GET")
            .uri("https://alias.test/file.txt")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip_with_sni(cfg, logger, request, &[], Some("a.test"))
                .await
                .0,
            200
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_connection_loop_handles_completion_reset_and_reclaim() {
        async fn run(reset: bool) {
            let (cfg, logger, dir) = test_config(if reset { "serve-reset" } else { "serve-ok" });
            let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
            let tls_identity = test_tls_identity(&cfg);
            let (_retire, retired) = tokio::sync::watch::channel(false);
            let server = tokio::spawn(serve_io(
                cfg,
                logger,
                server_io,
                "127.0.0.1:12345".parse().unwrap(),
                "127.0.0.1".into(),
                443,
                tls_identity,
                retired,
                || Ok(()),
            ));
            let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
            let driver = tokio::spawn(async move { connection.await });
            let request = http::Request::builder()
                .uri("https://localhost/file.txt")
                .body(())
                .unwrap();
            let (response, mut send) = client.send_request(request, !reset).unwrap();
            if reset {
                send.send_reset(h2::Reason::CANCEL);
                drop(response);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            } else {
                let response = response.await.unwrap();
                let mut body = response.into_body();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    let len = chunk.len();
                    body.flow_control().release_capacity(len).unwrap();
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            drop(send);
            drop(client);
            driver.abort();
            let _ = driver.await;
            tokio::time::timeout(std::time::Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            fs::remove_dir_all(dir).unwrap();
        }

        run(false).await;
        run(true).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_reset_cancels_backend_without_poisoning_other_streams() {
        let (port, accepted, closed, upstream) = stalling_upstream();
        let (cfg, logger, dir) = test_config_with_extra(
            "reset-backend-isolation",
            &format!("ProxyPass /slow http://127.0.0.1:{port}/"),
        );
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let tls_identity = test_tls_identity(&cfg);
        let (_retire, retired) = tokio::sync::watch::channel(false);
        let server_cfg = cfg.clone();
        let server = tokio::spawn(serve_io(
            server_cfg,
            logger,
            server_io,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1".into(),
            443,
            tls_identity,
            retired,
            || Ok(()),
        ));
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });

        let request = http::Request::builder()
            .uri("https://localhost/slow")
            .body(())
            .unwrap();
        let (slow_response, mut slow_send) = client.send_request(request, true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), accepted)
            .await
            .expect("proxy request did not reach the upstream")
            .unwrap();
        assert_eq!(cfg.resource_budget.usage().2, 1);
        slow_send.send_reset(h2::Reason::CANCEL);
        drop(slow_response);

        let request = http::Request::builder()
            .uri("https://localhost/file.txt")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let mut response = tokio::time::timeout(Duration::from_secs(1), response)
            .await
            .expect("unrelated HTTP/2 stream stalled behind a reset backend")
            .unwrap()
            .into_body();
        let mut body = Vec::new();
        while let Some(chunk) = response.data().await {
            let chunk = chunk.unwrap();
            response
                .flow_control()
                .release_capacity(chunk.len())
                .unwrap();
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, b"hello h2");
        wait_for_request_resources_to_drain(&cfg).await;
        closed
            .recv_timeout(Duration::from_secs(1))
            .expect("cancelled proxy transport remained open");

        drop((slow_send, client));
        driver.abort();
        let _ = driver.await;
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        upstream.join().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_connection_close_cancels_owned_backend_tasks() {
        let (port, accepted, closed, upstream) = stalling_upstream();
        let (cfg, logger, dir) = test_config_with_extra(
            "close-backend-ownership",
            &format!("ProxyPass /slow http://127.0.0.1:{port}/"),
        );
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let tls_identity = test_tls_identity(&cfg);
        let (_retire, retired) = tokio::sync::watch::channel(false);
        let server_cfg = cfg.clone();
        let server = tokio::spawn(serve_io(
            server_cfg,
            logger,
            server_io,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1".into(),
            443,
            tls_identity,
            retired,
            || Ok(()),
        ));
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = http::Request::builder()
            .uri("https://localhost/slow")
            .body(())
            .unwrap();
        let (_response, _send) = client.send_request(request, true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), accepted)
            .await
            .expect("proxy request did not reach the upstream")
            .unwrap();
        assert_eq!(cfg.resource_budget.usage().2, 1);

        drop(client);
        driver.abort();
        let _ = driver.await;
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("HTTP/2 connection owner retained a detached backend task")
            .unwrap()
            .unwrap();
        wait_for_request_resources_to_drain(&cfg).await;
        closed
            .recv_timeout(Duration::from_secs(1))
            .expect("connection-owned proxy transport remained open");
        upstream.join().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_transport_error_cancels_owned_backend_tasks() {
        let (port, accepted, closed, upstream) = stalling_upstream();
        let (cfg, logger, dir) = test_config_with_extra(
            "transport-error-backend-ownership",
            &format!("ProxyPass /slow http://127.0.0.1:{port}/"),
        );
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let (fail_tx, fail_rx) = tokio::sync::oneshot::channel();
        let server_io = InjectReadFailure {
            inner: server_io,
            fail: fail_rx,
        };
        let tls_identity = test_tls_identity(&cfg);
        let (_retire, retired) = tokio::sync::watch::channel(false);
        let server_cfg = cfg.clone();
        let server = tokio::spawn(serve_io(
            server_cfg,
            logger,
            server_io,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1".into(),
            443,
            tls_identity,
            retired,
            || Ok(()),
        ));
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = http::Request::builder()
            .uri("https://localhost/slow")
            .body(())
            .unwrap();
        let (_response, _send) = client.send_request(request, true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), accepted)
            .await
            .expect("proxy request did not reach the upstream")
            .unwrap();
        assert_eq!(cfg.resource_budget.usage().2, 1);

        fail_tx.send(()).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("HTTP/2 transport error retained a detached backend task")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        wait_for_request_resources_to_drain(&cfg).await;
        closed
            .recv_timeout(Duration::from_secs(1))
            .expect("transport-error proxy transport remained open");

        drop(client);
        driver.abort();
        let _ = driver.await;
        upstream.join().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retired_h2_generation_refuses_new_streams() {
        let (cfg, logger, dir) = test_config("retired-generation");
        let drain_len = 256 * 1024;
        fs::write(dir.join("www/drain.bin"), vec![b'd'; drain_len]).unwrap();
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let tls_identity = test_tls_identity(&cfg);
        let retired = cfg.generation_retirement();
        let server = tokio::spawn(serve_io(
            cfg.clone(),
            logger,
            server_io,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1".into(),
            443,
            tls_identity,
            retired,
            || Ok(()),
        ));
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });

        let request = http::Request::builder()
            .uri("https://localhost/drain.bin")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Retirement must refuse later streams without truncating a response
        // whose body was already admitted and is blocked on H2 flow control.
        cfg.retire_generation();
        let mut body = response.into_body();
        let mut received = 0usize;
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            received += chunk.len();
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        assert_eq!(received, drain_len);
        let stale = http::Request::builder()
            .uri("https://localhost/file.txt")
            .body(())
            .unwrap();
        let refused = match client.send_request(stale, true) {
            Err(_) => true,
            Ok((response, _)) => response.await.is_err(),
        };
        assert!(refused, "retired HTTP/2 generation accepted a new stream");

        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
        driver.abort();
        let _ = driver.await;
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_preface_and_initial_settings_must_arrive_before_header_deadline() {
        let (cfg, logger, dir) = test_config("preface-timeout");
        let mut short = (*cfg).clone();
        short.request_header_timeout = std::time::Duration::ZERO;
        let cfg = Arc::new(short);
        for preface in [None, Some(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..])] {
            let (mut client_io, server_io) = tokio::io::duplex(1024);
            let (_retire, retired) = tokio::sync::watch::channel(false);
            if let Some(preface) = preface {
                client_io.write_all(preface).await.unwrap();
            }
            let admitted = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let admitted_by_callback = admitted.clone();
            let tls_identity = test_tls_identity(&cfg);
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                serve_io(
                    cfg.clone(),
                    logger.clone(),
                    server_io,
                    "127.0.0.1:12345".parse().unwrap(),
                    "127.0.0.1".into(),
                    443,
                    tls_identity,
                    retired,
                    move || {
                        admitted_by_callback.store(true, std::sync::atomic::Ordering::Release);
                        Ok(())
                    },
                ),
            )
            .await
            .expect("incomplete HTTP/2 setup did not time out")
            .unwrap_err();
            assert_eq!(result.kind(), io::ErrorKind::TimedOut);
            assert!(!admitted.load(std::sync::atomic::Ordering::Acquire));
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retiring_generation_cancels_an_incomplete_h2_handshake() {
        let (cfg, logger, dir) = test_config("preface-retirement");
        let (_client_io, server_io) = tokio::io::duplex(1024);
        let (retire, retired) = tokio::sync::watch::channel(false);
        let admitted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_admitted = admitted.clone();
        let tls_identity = test_tls_identity(&cfg);
        let server = tokio::spawn(serve_io(
            cfg,
            logger,
            server_io,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1".into(),
            443,
            tls_identity,
            retired,
            move || {
                callback_admitted.store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            },
        ));
        tokio::task::yield_now().await;
        retire.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("retired incomplete H2 handshake did not terminate")
            .unwrap()
            .unwrap();
        assert!(!admitted.load(std::sync::atomic::Ordering::Acquire));
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_connection_idle_and_stream_timeouts_close_cleanly() {
        let (cfg, logger, dir) = test_config("serve-timeouts");
        let mut short = (*cfg).clone();
        short.timeout = std::time::Duration::ZERO;
        short.keep_alive_timeout = std::time::Duration::ZERO;
        let cfg = Arc::new(short);

        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let tls_identity = test_tls_identity(&cfg);
        let (_retire, retired) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(serve_io(
            cfg.clone(),
            logger.clone(),
            server_io,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1".into(),
            443,
            tls_identity,
            retired,
            || Ok(()),
        ));
        let (_client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .expect("idle connection did not close")
            .unwrap()
            .unwrap();
        driver.abort();
        let _ = driver.await;

        let large = vec![b'x'; 2 * 1024 * 1024];
        fs::write(dir.join("www/large.bin"), large).unwrap();
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let tls_identity = test_tls_identity(&cfg);
        let (_retire, retired) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(serve_io(
            cfg,
            logger,
            server_io,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1".into(),
            443,
            tls_identity,
            retired,
            || Ok(()),
        ));
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = http::Request::builder()
            .uri("https://localhost/large.bin")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // Retain the body without polling DATA.  The adapter task must time out
        // while flow control is stalled and report a reset to the loop.
        let _body = response.into_body();
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        drop(client);
        driver.abort();
        let _ = driver.await;
        tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .expect("timed-out stream connection did not close")
            .unwrap()
            .unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn progressing_h2_response_outlives_the_idle_and_send_intervals() {
        let (cfg, logger, dir) = test_config("progressing-response");
        let mut short = (*cfg).clone();
        short.timeout = std::time::Duration::ZERO;
        short.keep_alive_timeout = std::time::Duration::ZERO;
        let cfg = Arc::new(short);
        let expected = vec![b'p'; 64 * 1024];
        fs::write(dir.join("www/progress.bin"), &expected).unwrap();

        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let tls_identity = test_tls_identity(&cfg);
        let (_retire, retired) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(serve_io(
            cfg,
            logger,
            server_io,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1".into(),
            443,
            tls_identity,
            retired,
            || Ok(()),
        ));
        let mut builder = h2::client::Builder::new();
        builder.initial_window_size(4 * 1024);
        let (mut client, connection) = builder.handshake::<_, Bytes>(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = http::Request::builder()
            .uri("https://localhost/progress.bin")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let mut body = response.await.unwrap().into_body();
        let mut received = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            received.extend_from_slice(&chunk);
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        assert_eq!(received, expected);

        drop((body, client));
        driver.abort();
        let _ = driver.await;
        tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .expect("progressing response server did not close")
            .unwrap()
            .unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn slow_output_handoff_preserves_capacity_for_an_unrelated_client() {
        let budget = Arc::new(crate::resource::ResourceBudget::default());
        let mut outputs = Vec::new();
        for source in 1..=8 {
            for _ in 0..32 {
                let context = budget.context(std::net::IpAddr::from([192, 0, 2, source]));
                let general = budget.try_h2_stream_in(&context).unwrap();
                outputs.push(crate::resource::SlowOutputAdmission::tracked_h2(
                    context, general,
                ));
            }
        }
        assert_eq!(budget.h2_output_usage(), (256, 0));

        let mut retained = Vec::new();
        for mut output in outputs {
            if output.enter_slow().is_ok() {
                output.enter_slow().unwrap();
                retained.push(output);
            }
            // Rejected slow outputs are dropped here, exactly as an errored
            // response task is unwound by the stream handler.
        }
        assert_eq!(budget.h2_output_usage(), (0, 128));

        let victim = budget.context(std::net::IpAddr::from([198, 51, 100, 7]));
        let victim_stream = budget
            .try_h2_stream_in(&victim)
            .expect("slow outputs consumed unrelated dispatch capacity");
        assert_eq!(budget.h2_output_usage(), (1, 128));
        drop(victim_stream);
        drop(retained);
        assert_eq!(budget.h2_output_usage(), (0, 0));
    }

    #[test]
    fn slow_input_handoff_preserves_capacity_for_an_unrelated_client() {
        let budget = Arc::new(crate::resource::ResourceBudget::default());
        let mut inputs = Vec::new();
        for source in 1..=8 {
            for _ in 0..32 {
                let context = budget.context(std::net::IpAddr::from([192, 0, 2, source]));
                let general = budget.try_h2_stream_in(&context).unwrap();
                inputs.push(crate::resource::SlowOutputAdmission::tracked_h2(
                    context, general,
                ));
            }
        }
        assert_eq!(budget.h2_input_usage(), (256, 0));

        let mut retained = Vec::new();
        for mut input in inputs {
            if input.enter_slow_input().is_ok() {
                input.enter_slow_input().unwrap();
                retained.push(input);
            }
            // Rejected waiters retain their general lease only until this
            // bounded error path unwinds and drops the admission value.
        }
        assert_eq!(budget.h2_input_usage(), (0, 128));

        let victim = budget.context(std::net::IpAddr::from([198, 51, 100, 7]));
        let victim_stream = budget
            .try_h2_stream_in(&victim)
            .expect("slow request bodies consumed unrelated dispatch capacity");
        assert_eq!(budget.h2_input_usage(), (1, 128));
        drop(victim_stream);
        drop(retained);
        assert_eq!(budget.h2_input_usage(), (0, 0));
    }

    #[test]
    fn slow_output_progress_is_anchored_and_has_an_absolute_ceiling() {
        let mut progress = crate::resource::SlowOutputProgress::new(Duration::from_secs(1));
        progress.record(1024);
        assert!(progress
            .validate(progress.started + Duration::from_secs(1))
            .is_ok());
        assert!(progress
            .validate(progress.started + Duration::from_secs(2))
            .is_err());

        let mut trickle = crate::resource::SlowOutputProgress::new(Duration::from_millis(20));
        trickle.record(1);
        assert!(
            trickle.validate(trickle.absolute_deadline).is_err(),
            "partial progress renewed the absolute deadline"
        );

        // Exercise the defensive Instant overflow path deterministically.
        // The constructor cannot create this shape because the absolute
        // deadline is derived from the same smaller interval.
        let mut rollover = crate::resource::SlowOutputProgress::new(Duration::from_secs(1));
        rollover.interval = Duration::MAX;
        rollover.checkpoint = rollover.started;
        rollover.absolute_deadline = rollover.started + Duration::from_secs(1);
        assert!(rollover.validate(rollover.started).is_ok());
        assert_eq!(rollover.checkpoint, rollover.absolute_deadline);
    }

    #[test]
    fn response_body_buffer_pool_reuses_only_bounded_chunks() {
        let budget = Arc::new(crate::resource::ResourceBudget::default());
        let client = std::net::IpAddr::from([127, 0, 0, 1]);
        let resident = Arc::new(Mutex::new(
            response_chunk_lease(&budget, client, POOL_MAX_CAPACITY).unwrap(),
        ));
        let mut buffer = Vec::with_capacity(POOL_MAX_CAPACITY);
        buffer.extend_from_slice(b"old data");
        drop(PooledBuffer {
            buf: Some(buffer),
            _resident: resident,
            _transport: Arc::new(QueuedH2TransportState::default()),
        });
        let reused = take_body_buffer(POOL_MAX_CAPACITY);
        // Reusing the initialized length avoids zero-filling a full file
        // chunk on every response. Readers must overwrite and truncate the
        // admitted slice before it can become response data.
        assert_eq!(&reused[..], b"old data");
        assert!(reused.capacity() >= POOL_MAX_CAPACITY);

        // Empty and out-of-range owners exercise the no-op drop paths; they
        // must not change accounting or retain attacker-sized allocations.
        let resident = Arc::new(Mutex::new(
            response_chunk_lease(&budget, client, 1).unwrap(),
        ));
        drop(PooledBuffer {
            buf: None,
            _resident: resident.clone(),
            _transport: Arc::new(QueuedH2TransportState::default()),
        });
        drop(PooledBuffer {
            buf: Some(Vec::with_capacity(1)),
            _resident: resident,
            _transport: Arc::new(QueuedH2TransportState::default()),
        });
        assert_eq!(budget.extended_usage().2, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admitted_slow_stream_body_checks_deadlines_after_each_read() {
        let (cfg, _logger, dir) = test_config("progressing-stream-response");
        let mut short = (*cfg).clone();
        short.timeout = Duration::ZERO;
        let cfg = Arc::new(short);
        // Keep the body small enough that this invariant-path test cannot
        // approach the deliberately tiny test-only absolute deadline under a
        // loaded CI scheduler.
        let expected = vec![b's'; 8 * 1024];
        let mut response = Response::new(200);
        response.body = Body::Stream {
            reader: Box::new(std::io::Cursor::new(expected.clone())),
            len: expected.len() as u64,
        };

        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let server_cfg = cfg.clone();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (_, respond) = connection.accept().await.unwrap().unwrap();
            let client = std::net::IpAddr::from([127, 0, 0, 1]);
            let mut output = crate::resource::SlowOutputAdmission::detached(
                server_cfg.resource_budget.context(client),
            );
            output.enter_slow().unwrap();
            let sender =
                send_response_with_admission(respond, &server_cfg, response, false, &mut output);
            tokio::pin!(sender);
            let result = loop {
                tokio::select! {
                    result = &mut sender => break result,
                    accepted = connection.accept() => {
                        if accepted.is_none() {
                            break Err(io::Error::new(io::ErrorKind::BrokenPipe, "client closed"));
                        }
                    }
                }
            };
            loop {
                tokio::select! {
                    _ = &mut done_rx => break,
                    accepted = connection.accept() => {
                        if accepted.is_none() { break; }
                    }
                }
            }
            result
        });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = http::Request::builder()
            .uri("https://localhost/stream")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let mut body = response.await.unwrap().into_body();
        let mut received = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            received.extend_from_slice(&chunk);
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        assert_eq!(received, expected);
        let _ = done_tx.send(());
        assert_eq!(server.await.unwrap().unwrap(), expected.len() as u64);

        drop((body, client));
        driver.abort();
        let _ = driver.await;
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_body_timeout_returns_408() {
        let (cfg, logger, dir) = test_config("body-timeout");
        let mut short_timeout = (*cfg).clone();
        short_timeout.request_body_timeout = std::time::Duration::ZERO;
        let cfg = Arc::new(short_timeout);
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, respond) = connection.accept().await.unwrap().unwrap();
            let admission =
                admit_stream_before_spawn(&cfg, "127.0.0.1:12345".parse().unwrap(), &request)
                    .unwrap();
            let tls_identity = test_tls_identity(&cfg);
            let handler = handle_stream(
                cfg,
                logger,
                "127.0.0.1:12345".parse().unwrap(),
                "127.0.0.1".into(),
                443,
                tls_identity,
                request,
                respond,
                admission,
            );
            tokio::pin!(handler);
            let reset = loop {
                tokio::select! {
                    reset = &mut handler => break reset,
                    accepted = connection.accept() => {
                        if accepted.is_none() { break true; }
                    }
                }
            };
            loop {
                tokio::select! {
                    _ = &mut done_rx => break,
                    accepted = connection.accept() => {
                        if accepted.is_none() { break; }
                    }
                }
            }
            reset
        });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/__body_test")
            .body(())
            .unwrap();
        let (response, send) = client.send_request(request, false).unwrap();
        let response = tokio::time::timeout(std::time::Duration::from_secs(2), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        let _ = done_tx.send(());
        drop(send);
        drop(client);
        driver.abort();
        let _ = driver.await;
        assert!(!server.await.unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn response_sender_covers_stream_and_every_file_strategy() {
        let (cfg, _logger, dir) = test_config("response-bodies");
        let split = vec![b'b'; 128 * 1024];
        let (result, status, _, body) = response_round_trip_with_window(
            cfg.clone(),
            Response::bytes(200, "application/octet-stream", split.clone()),
            false,
            Some(1024),
        )
        .await;
        assert_eq!(result.unwrap(), split.len() as u64);
        assert_eq!(status, 200);
        assert_eq!(body, split);

        let mut stream = Response::new(200);
        stream.body = Body::Stream {
            reader: Box::new(&b"stream body"[..]),
            len: 11,
        };
        let (result, status, _, body) = response_round_trip(cfg.clone(), stream, false).await;
        assert_eq!(result.unwrap(), 11);
        assert_eq!(status, 200);
        assert_eq!(body, b"stream body");

        let mut unknown = Response::new(200);
        unknown.body = Body::UnknownLengthStream {
            reader: Box::new(&b"encoded body"[..]),
            max_len: 64,
        };
        let (result, status, headers, body) =
            response_round_trip(cfg.clone(), unknown, false).await;
        assert_eq!(result.unwrap(), 12);
        assert_eq!(status, 200);
        assert_eq!(body, b"encoded body");
        assert!(
            !headers.contains_key("content-length"),
            "unknown-length H2 response acquired a false Content-Length"
        );

        let mut reset = Response::bytes(205, "text/plain", b"must not escape".to_vec());
        reset
            .headers
            .push((Cow::Borrowed("Content-Length"), b"15".to_vec()));
        reset
            .headers
            .push((Cow::Borrowed("Connection"), b"keep-alive, X-Hop".to_vec()));
        reset
            .headers
            .push((Cow::Borrowed("X-Hop"), b"secret".to_vec()));
        reset
            .headers
            .push((Cow::Borrowed("TE"), b"trailers".to_vec()));
        reset
            .headers
            .push((Cow::Borrowed("Trailer"), b"X-Later".to_vec()));
        reset.headers.push((
            Cow::Borrowed("Date"),
            b"Tue, 15 Nov 1994 08:12:31 GMT".to_vec(),
        ));
        reset
            .headers
            .push((Cow::Borrowed("Server"), b"explicit-server".to_vec()));
        let (result, status, headers, body) = response_round_trip(cfg.clone(), reset, false).await;
        assert_eq!(result.unwrap(), 0);
        assert_eq!(status, 205);
        assert!(body.is_empty());
        assert_eq!(headers.get("content-length").unwrap(), "0");
        assert_eq!(headers.get_all("date").iter().count(), 1);
        assert_eq!(
            headers.get("date").unwrap(),
            "Tue, 15 Nov 1994 08:12:31 GMT"
        );
        assert_eq!(headers.get_all("server").iter().count(), 1);
        assert_eq!(headers.get("server").unwrap(), "explicit-server");
        for removed in ["connection", "keep-alive", "x-hop", "te", "trailer"] {
            assert!(!headers.contains_key(removed), "{removed}: {headers:?}");
        }

        let mut short_stream = Response::new(200);
        short_stream.body = Body::Stream {
            reader: Box::new(&b""[..]),
            len: 1,
        };
        let (result, _, _, _) = response_round_trip(cfg.clone(), short_stream, false).await;
        assert_eq!(result.unwrap(), 0);

        let mut invalid_headers = Response::bytes(200, "text/plain", b"headers".to_vec());
        invalid_headers
            .headers
            .push((Cow::Borrowed("bad header"), b"ignored".to_vec()));
        invalid_headers
            .headers
            .push((Cow::Borrowed("x-bad-value"), b"bad\nvalue".to_vec()));
        let (result, status, _, body) =
            response_round_trip(cfg.clone(), invalid_headers, false).await;
        assert_eq!(status, 500);
        assert_eq!(result.unwrap(), body.len() as u64);
        assert!(body.starts_with(b"Response policy exceeds"));

        let mut excessive_headers = Response::new(200);
        for index in 0..crate::http::MAX_RESPONSE_HEADERS {
            excessive_headers
                .headers
                .push((Cow::Owned(format!("X-{index}")), b"value".to_vec()));
        }
        let (result, status, _, body) =
            response_round_trip(cfg.clone(), excessive_headers, false).await;
        assert_eq!(status, 500);
        assert_eq!(result.unwrap(), body.len() as u64);
        assert!(body.starts_with(b"Response policy exceeds"));

        let medium_path = dir.join("medium.bin");
        let medium = vec![b'm'; 300 * 1024 + 1];
        fs::write(&medium_path, &medium).unwrap();
        let mut mapped = Response::new(200);
        mapped.body = Body::File {
            file: File::open(&medium_path).unwrap(),
            offset: 0,
            len: 300 * 1024,
        };
        let (result, _, _, body) = response_round_trip(cfg.clone(), mapped, false).await;
        assert_eq!(result.unwrap(), 300 * 1024);
        assert_eq!(body.len(), 300 * 1024);

        let mut ranged = Response::new(206);
        ranged.body = Body::File {
            file: File::open(&medium_path).unwrap(),
            offset: 1,
            len: 300 * 1024,
        };
        let (result, status, _, body) = response_round_trip(cfg.clone(), ranged, false).await;
        assert_eq!(result.unwrap(), 300 * 1024);
        assert_eq!(status, 206);
        assert_eq!(body, medium[1..].to_vec());

        let large_path = dir.join("large.bin");
        let large = vec![b'l'; 8 * 1024 * 1024 + 1];
        fs::write(&large_path, &large).unwrap();
        let mut batched = Response::new(200);
        batched.body = Body::File {
            file: File::open(&large_path).unwrap(),
            offset: 0,
            len: large.len() as u64,
        };
        let (result, _, _, body) = response_round_trip(cfg.clone(), batched, false).await;
        assert_eq!(result.unwrap(), large.len() as u64);
        assert_eq!(body.len(), large.len());

        // A declared large body backed by an empty file exercises the clean
        // EOF/end-stream path without allocating a response-sized buffer.
        let empty_path = dir.join("empty.bin");
        fs::write(&empty_path, b"").unwrap();
        let mut empty_large = Response::new(200);
        empty_large.body = Body::File {
            file: File::open(&empty_path).unwrap(),
            offset: 0,
            len: 8 * 1024 * 1024 + 1,
        };
        let (result, _, _, _) = response_round_trip(cfg.clone(), empty_large, false).await;
        assert_eq!(result.unwrap(), 0);

        let mut read_error = Response::new(200);
        read_error.body = Body::File {
            file: File::open(&dir).unwrap(),
            offset: 0,
            len: 8 * 1024 * 1024 + 1,
        };
        assert!(response_round_trip(cfg, read_error, false).await.0.is_err());

        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(feature = "fault-injection")]
    #[tokio::test(flavor = "current_thread")]
    async fn inherited_h2_read_failure_releases_all_response_ownership() {
        let _fault_guard = crate::fault::test_guard();
        let (cfg, _logger, dir) = test_config("transition-h2-output");
        let before = cfg.resource_budget.transition_snapshot();
        let client = std::net::IpAddr::from([127, 0, 0, 1]);
        let context = cfg.resource_budget.context(client);
        let mut response = Response::new(200);
        response.body = Body::Stream {
            reader: Box::new(std::io::Cursor::new(vec![b'x'; 16 * 1024])),
            len: 16 * 1024,
        };
        response
            .admit_resident_for(&cfg.resource_budget, client)
            .unwrap();
        response.hold_dynamic(
            cfg.resource_budget
                .try_dynamic_descriptors_in(&context, 1, 1)
                .unwrap(),
        );
        crate::fault::clear();
        crate::fault::configure(
            "transition.h2.output.stream-read",
            0,
            io::ErrorKind::ConnectionReset,
        );

        let (result, status, _, body) = response_round_trip(cfg.clone(), response, false).await;
        assert!(result.is_err());
        assert_eq!(status, 200, "headers must commit before the body read");
        assert!(body.is_empty());
        assert_eq!(cfg.resource_budget.transition_snapshot(), before);
        assert_eq!(
            crate::fault::trace(),
            [
                "transition.h2.output.start",
                "transition.h2.output.capacity-await",
                "transition.h2.output.stream-read"
            ]
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn zero_window_stream_waits_before_reading_body() {
        use std::sync::atomic::{AtomicU64, Ordering};

        struct CountingReader(Arc<AtomicU64>);

        impl Read for CountingReader {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.0.fetch_add(1, Ordering::AcqRel);
                out.fill(b'x');
                Ok(out.len())
            }
        }

        let (cfg, _logger, dir) = test_config("zero-window-stream");
        let reads = Arc::new(AtomicU64::new(0));
        let mut body = Response::new(200);
        body.body = Body::Stream {
            reader: Box::new(CountingReader(reads.clone())),
            len: 300 * 1024,
        };
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let server_cfg = cfg.clone();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (_, respond) = connection.accept().await.unwrap().unwrap();
            let sender = send_response(
                respond,
                &server_cfg,
                std::net::IpAddr::from([127, 0, 0, 1]),
                body,
                false,
            );
            tokio::pin!(sender);
            loop {
                tokio::select! {
                    result = &mut sender => break result,
                    accepted = connection.accept() => {
                        if accepted.is_none() {
                            break Err(io::Error::new(io::ErrorKind::BrokenPipe, "client closed"));
                        }
                    }
                }
            }
        });
        let mut builder = h2::client::Builder::new();
        builder.initial_window_size(0);
        let (mut client, connection) = builder.handshake::<_, Bytes>(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = http::Request::builder()
            .uri("https://localhost/body")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(reads.load(Ordering::Acquire), 0);
        let usage = cfg.resource_budget.extended_usage();
        assert_eq!(
            usage.2, 256,
            "only the bounded serialized-header reservation may be held"
        );
        assert_eq!(usage.3, 0, "zero-window stream pinned a blocking read");

        drop(response);
        drop(client);
        driver.abort();
        server.abort();
        let _ = driver.await;
        let _ = server.await;
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn zero_window_file_is_not_read_before_capacity() {
        let (cfg, _logger, dir) = test_config("zero-window-file");
        let mut body = Response::new(200);
        // A pre-capacity read of this advertised mid-sized body reaches EOF
        // immediately. The secure ordering leaves the sender pending on the
        // zero flow-control window without touching the descriptor.
        body.body = Body::File {
            file: File::open("/dev/null").unwrap(),
            offset: 0,
            len: 300 * 1024,
        };
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let server_cfg = cfg.clone();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (_, respond) = connection.accept().await.unwrap().unwrap();
            let sender = send_response(
                respond,
                &server_cfg,
                std::net::IpAddr::from([127, 0, 0, 1]),
                body,
                false,
            );
            tokio::pin!(sender);
            loop {
                tokio::select! {
                    result = &mut sender => break result,
                    accepted = connection.accept() => {
                        if accepted.is_none() {
                            break Err(io::Error::new(io::ErrorKind::BrokenPipe, "client closed"));
                        }
                    }
                }
            }
        });
        let mut builder = h2::client::Builder::new();
        builder.initial_window_size(0);
        let (mut client, connection) = builder.handshake::<_, Bytes>(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = http::Request::builder()
            .uri("https://localhost/body")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(!server.is_finished(), "file was read before send capacity");
        let usage = cfg.resource_budget.extended_usage();
        assert_eq!((usage.2, usage.3), (256, 0));

        drop(response);
        drop(client);
        driver.abort();
        server.abort();
        let _ = driver.await;
        let _ = server.await;
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn response_decisions_and_content_lengths_are_total() {
        use httpd_rs_verified::H2HeadDecision::{
            Accept, HeaderFieldTooLarge, InvalidMethod, TargetTooLong, TooManyHeaders,
        };
        assert!(head_error_response(Accept).is_none());
        for (decision, status) in [
            (InvalidMethod, 400),
            (TargetTooLong, 414),
            (TooManyHeaders, 431),
            (HeaderFieldTooLarge, 431),
        ] {
            assert_eq!(head_error_response(decision).unwrap().status, status);
        }

        let mut headers = crate::http::Headers::default();
        assert_eq!(canonicalize_content_length(&mut headers), Ok(None));
        headers.push_merged("content-length", b"7");
        assert_eq!(canonicalize_content_length(&mut headers), Ok(Some(7)));
        assert_eq!(headers.get("content-length"), Some(b"7".as_slice()));

        let mut duplicate = crate::http::Headers::default();
        duplicate.push_merged("content-length", b"7");
        duplicate.push_merged("content-length", b"7");
        assert_eq!(canonicalize_content_length(&mut duplicate), Err(()));

        let mut ascii_ows = crate::http::Headers::default();
        ascii_ows.push("content-length", b"\t7 ".to_vec());
        assert_eq!(canonicalize_content_length(&mut ascii_ows), Ok(Some(7)));
        assert_eq!(ascii_ows.get("content-length"), Some(b"7".as_slice()));

        let mut unicode_ows = crate::http::Headers::default();
        unicode_ows.push("content-length", b"\xc2\xa07".to_vec());
        assert_eq!(canonicalize_content_length(&mut unicode_ows), Err(()));

        let mut conflicting = crate::http::Headers::default();
        conflicting.push_merged("content-length", b"7");
        conflicting.push_merged("content-length", b"8");
        assert_eq!(canonicalize_content_length(&mut conflicting), Err(()));

        let mut malformed = crate::http::Headers::default();
        malformed.push("content-length", b"not-a-number".to_vec());
        assert_eq!(canonicalize_content_length(&mut malformed), Err(()));
    }

    #[test]
    fn request_targets_require_complete_pseudo_header_identity() {
        let good: http::Uri = "https://example.test/path?q=1".parse().unwrap();
        assert_eq!(
            request_target("GET", &good, true).as_deref(),
            Some(b"/path?q=1".as_slice())
        );
        assert!(request_target("GET", &good, false).is_none());

        // h2/http normalize an absent :path to `/` before the application
        // adapter sees it.  The exploitable no-:path/no-:authority shape is
        // still rejected because the authority identity is absent.
        let missing_target_identity: http::Uri = "/".parse().unwrap();
        assert!(request_target("GET", &missing_target_identity, true).is_none());
        let missing_authority: http::Uri = "/path".parse().unwrap();
        assert!(request_target("GET", &missing_authority, true).is_none());
        assert!(request_target("CONNECT", &good, true).is_none());
        assert!(!httpd_rs_verified::h2_request_target_admit(
            false, true, true, true, false, true, true, false,
        ));
        let bad_port: http::Uri = "https://example.test:99999/path".parse().unwrap();
        assert!(request_target("GET", &bad_port, true).is_none());
        for name in [
            "connection",
            "proxy-connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(forbidden_h2_header(name, b"anything"), "{name}");
        }
        assert!(forbidden_h2_header("te", b"gzip"));
        assert!(!forbidden_h2_header("te", b"trailers"));
        assert!(!forbidden_h2_header("x-test", b"value"));
        assert!(forbidden_h2_header("bad name", b"value"));
        assert!(forbidden_h2_header("x-test", b"bad\x01value"));
    }

    async fn raw_malformed_request_is_rejected(mut hpack: Vec<u8>) {
        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            matches!(
                tokio::time::timeout(Duration::from_millis(200), connection.accept()).await,
                Ok(Some(Ok(_)))
            )
        });

        let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        // Empty client SETTINGS.
        wire.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        let len = hpack.len();
        wire.extend_from_slice(&[
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
            1,   // HEADERS
            0x5, // END_STREAM | END_HEADERS
            0,
            0,
            0,
            1,
        ]);
        wire.append(&mut hpack);
        client_io.write_all(&wire).await.unwrap();

        let accepted = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("malformed h2 request timed out")
            .unwrap();
        assert!(!accepted, "malformed request reached the application");
    }

    fn append_raw_h2_frame(
        wire: &mut Vec<u8>,
        kind: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) {
        let len = payload.len() as u32;
        wire.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags]);
        wire.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        wire.extend_from_slice(payload);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_stream_empty_data_flood_reaches_the_hard_frame_cap() {
        use tokio::io::AsyncReadExt as _;

        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            while let Some(accepted) = connection.accept().await {
                match accepted {
                    Ok((request, mut respond)) => {
                        // Put the peer-open stream into the same locally-reset
                        // lifecycle state used by rejected request bodies.
                        drop(request);
                        respond.send_reset(h2::Reason::CANCEL);
                    }
                    Err(_) => break,
                }
            }
        });

        let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        append_raw_h2_frame(&mut wire, 4, 0, 0, &[]); // SETTINGS
                                                      // Indexed GET, HTTPS and `/`, plus literal :authority=localhost.
        let mut headers = vec![0x82, 0x87, 0x84, 0x01, 0x09];
        headers.extend_from_slice(b"localhost");
        append_raw_h2_frame(&mut wire, 1, 0x04, 1, &headers);
        // Vendored h2's MAX_RECV_EMPTY_DATA_FRAMES is 100; send the first
        // frame beyond the cap.
        for _ in 0..=100 {
            append_raw_h2_frame(&mut wire, 0, 0, 1, &[]);
        }
        client_io.write_all(&wire).await.unwrap();

        let mut received = Vec::new();
        let goaway = tokio::time::timeout(Duration::from_secs(2), async {
            let mut chunk = [0u8; 4096];
            loop {
                let read = client_io.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0, "terminal DATA flood closed without GOAWAY");
                received.extend_from_slice(&chunk[..read]);
                let mut offset = 0usize;
                while received.len().saturating_sub(offset) >= 9 {
                    let len = ((received[offset] as usize) << 16)
                        | ((received[offset + 1] as usize) << 8)
                        | received[offset + 2] as usize;
                    if received.len().saturating_sub(offset) < 9 + len {
                        break;
                    }
                    let kind = received[offset + 3];
                    let payload = &received[offset + 9..offset + 9 + len];
                    if kind == 7 && payload.len() >= 8 {
                        return u32::from_be_bytes(payload[4..8].try_into().unwrap());
                    }
                    offset += 9 + len;
                }
            }
        })
        .await
        .expect("terminal DATA flood did not produce GOAWAY");
        assert_eq!(goaway, h2::Reason::ENHANCE_YOUR_CALM.into());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn h2_parser_rejects_missing_path_and_fragments_before_uri_normalization() {
        let mut base = vec![
            0x82, // :method GET
            0x87, // :scheme https
            0x41, // literal :authority
            0x0c, // value length
        ];
        base.extend_from_slice(b"example.test");

        raw_malformed_request_is_rejected(base.clone()).await;

        // Literal, never-indexed :path with a fragment. The http URI parser
        // used to truncate `#admin` and dispatch `/path`.
        base.extend_from_slice(&[0x04, 0x0b]);
        base.extend_from_slice(b"/path#admin");
        raw_malformed_request_is_rejected(base).await;
    }

    #[test]
    fn h2_admission_bounds_are_checked_without_overflow() {
        assert!(httpd_rs_verified::h2_body_admit(0, 10, 10));
        assert!(!httpd_rs_verified::h2_body_admit(10, 1, 10));
        assert!(!httpd_rs_verified::h2_body_admit(u64::MAX, 1, 10));
        assert!(httpd_rs_verified::h2_target_admit(10, 10));
        assert!(!httpd_rs_verified::h2_target_admit(11, 10));
        assert!(httpd_rs_verified::h2_header_admit(3, 10, 3, 10));
        assert!(!httpd_rs_verified::h2_header_admit(4, 10, 3, 10));
        assert!(httpd_rs_verified::h2_header_total_admit(10, 10));
        assert!(!httpd_rs_verified::h2_header_total_admit(11, 10));
        let hs = httpd_rs_verified::h2_header_init(10);
        let hs = httpd_rs_verified::h2_header_add(hs, 7).unwrap();
        assert!(httpd_rs_verified::h2_header_add(hs, 4).is_none());
        assert_eq!(httpd_rs_verified::h2_header_add(hs, 3).unwrap().total, 10);
    }

    #[test]
    fn h2_head_admission_reports_the_first_failed_bound() {
        use httpd_rs_verified::H2HeadDecision::{
            Accept, HeaderFieldTooLarge, InvalidMethod, TargetTooLong, TooManyHeaders,
        };
        assert!(httpd_rs_verified::h2_method_ok(b"GET"));
        assert!(!httpd_rs_verified::h2_method_ok(b""));
        assert!(!httpd_rs_verified::h2_method_ok(b"GET SPACE"));
        let too_long = [b'A'; 65];
        assert!(!httpd_rs_verified::h2_method_ok(&too_long));
        assert!(httpd_rs_verified::h2_field_size_admit(4, 6, 10));
        assert!(!httpd_rs_verified::h2_field_size_admit(4, 7, 10));
        assert!(!httpd_rs_verified::h2_field_size_admit(11, 0, 10));
        assert_eq!(
            httpd_rs_verified::h2_head_admit(b"GET", 10, 10, 3, 3, 10, 10),
            Accept
        );
        assert_eq!(
            httpd_rs_verified::h2_head_admit(b"BAD\x00METHOD", 1, 10, 1, 3, 1, 10),
            InvalidMethod
        );
        assert_eq!(
            httpd_rs_verified::h2_head_admit(b"GET", 11, 10, 1, 3, 1, 10),
            TargetTooLong
        );
        assert_eq!(
            httpd_rs_verified::h2_head_admit(b"GET", 10, 10, 4, 3, 1, 10),
            TooManyHeaders
        );
        assert_eq!(
            httpd_rs_verified::h2_head_admit(b"GET", 10, 10, 3, 3, 11, 10),
            HeaderFieldTooLarge
        );
    }

    #[test]
    fn h2_body_state_never_accepts_more_than_the_limit() {
        let state = httpd_rs_verified::h2_body_init(10);
        let state = httpd_rs_verified::h2_body_append(state, 7).unwrap();
        assert_eq!(state.len, 7);
        assert!(httpd_rs_verified::h2_body_append(state, 4).is_none());
        let state = httpd_rs_verified::h2_body_append(state, 3).unwrap();
        assert_eq!(state.len, 10);
        assert!(httpd_rs_verified::h2_body_append(state, 1).is_none());
    }

    #[test]
    fn h2_flow_model_bounds_windows_and_send_buffer() {
        let flow = httpd_rs_verified::h2_flow_new(1024, 256, 512);
        let flow = httpd_rs_verified::h2_flow_charge(flow, 200).unwrap();
        assert_eq!(flow.conn_window, 824);
        assert_eq!(flow.stream_window, 56);
        assert!(httpd_rs_verified::h2_flow_charge(flow, 57).is_none());
        let flow = httpd_rs_verified::h2_flow_enqueue(flow, 512).unwrap();
        assert!(httpd_rs_verified::h2_flow_enqueue(flow, 1).is_none());
        let flow = httpd_rs_verified::h2_flow_dequeue(flow, 512).unwrap();
        let flow = httpd_rs_verified::h2_flow_credit(flow, u64::MAX);
        assert_eq!(flow.conn_window, 1024);
        assert_eq!(flow.stream_window, 256);
    }

    #[test]
    fn h2_budget_transitions_preserve_limits() {
        use httpd_rs_verified::{H2StreamEvent, H2StreamPhase};

        let active =
            httpd_rs_verified::h2_stream_phase_step(H2StreamPhase::Idle, H2StreamEvent::Begin)
                .unwrap();
        assert_eq!(
            httpd_rs_verified::h2_stream_phase_step(active, H2StreamEvent::Finish),
            Some(H2StreamPhase::Closed)
        );
        let awaiting =
            httpd_rs_verified::h2_stream_phase_step(active, H2StreamEvent::Reset).unwrap();
        assert_eq!(awaiting, H2StreamPhase::AwaitingReset);
        assert_eq!(
            httpd_rs_verified::h2_stream_phase_step(awaiting, H2StreamEvent::Reclaim),
            Some(H2StreamPhase::Closed)
        );
        assert_eq!(
            httpd_rs_verified::h2_stream_phase_step(active, H2StreamEvent::ConnectionClose),
            Some(H2StreamPhase::Closed)
        );
        assert!(httpd_rs_verified::h2_stream_phase_step(
            H2StreamPhase::Closed,
            H2StreamEvent::Begin
        )
        .is_none());

        let budget = httpd_rs_verified::h2_budget_new(2, 1);
        let budget = httpd_rs_verified::h2_budget_begin(budget).unwrap();
        let budget = httpd_rs_verified::h2_budget_begin(budget).unwrap();
        assert!(httpd_rs_verified::h2_budget_begin(budget).is_none());
        let budget = httpd_rs_verified::h2_budget_reset(budget).unwrap();
        assert!(httpd_rs_verified::h2_budget_reset(budget).is_none());
        let budget = httpd_rs_verified::h2_budget_reclaim(budget).unwrap();
        assert!(httpd_rs_verified::h2_budget_reclaim(budget).is_none());
        let budget = httpd_rs_verified::h2_budget_finish(budget).unwrap();
        let budget = httpd_rs_verified::h2_budget_finish(budget).unwrap();
        assert!(httpd_rs_verified::h2_budget_finish(budget).is_none());

        let budget =
            httpd_rs_verified::h2_budget_step(budget, httpd_rs_verified::H2BudgetEvent::Begin)
                .unwrap();
        assert_eq!(budget.active, 1);
        let budget =
            httpd_rs_verified::h2_budget_step(budget, httpd_rs_verified::H2BudgetEvent::Finish)
                .unwrap();
        assert_eq!(budget.active, 0);

        let budget = httpd_rs_verified::h2_budget_step(
            httpd_rs_verified::h2_budget_new(2, 2),
            httpd_rs_verified::H2BudgetEvent::Begin,
        )
        .unwrap();
        let budget =
            httpd_rs_verified::h2_budget_step(budget, httpd_rs_verified::H2BudgetEvent::Reset)
                .unwrap();
        let budget = httpd_rs_verified::h2_budget_step(
            budget,
            httpd_rs_verified::H2BudgetEvent::ConnectionClose,
        )
        .unwrap();
        assert_eq!(budget.active, 0);
        assert_eq!(budget.pending_resets, 0);

        let (tx, mut rx) = mpsc::channel(1);
        {
            let _guard = H2TaskEventGuard {
                tx,
                stream_id: 1,
                reset: true,
            };
        }
        assert!(matches!(
            rx.try_recv(),
            Ok(H2TaskEvent::Ended {
                stream_id: 1,
                reset: true
            })
        ));
    }

    #[test]
    fn h2_control_events_assign_cost_and_refill_once() {
        use httpd_rs_verified::H2ControlEvent::{Ping, Priority, Settings, WindowUpdate};

        let settings = httpd_rs_verified::h2_control_event_step(256, 0, Settings, 256, 2);
        assert_eq!(settings.cost, 16);
        assert_eq!(settings.available, 240);
        assert!(settings.admitted);

        let ping = httpd_rs_verified::h2_control_event_step(0, 1, Ping, 256, 2);
        assert_eq!(ping.refill_seconds, 1);
        assert_eq!(ping.cost, 1);
        assert_eq!(ping.available, 1);
        assert!(ping.admitted);
        let priority =
            httpd_rs_verified::h2_control_event_step(ping.available, 0, Priority, 256, 2);
        assert_eq!(priority.available, 0);
        assert!(priority.admitted);
        assert!(!httpd_rs_verified::h2_control_event_step(0, 0, Ping, 256, 2).admitted);

        let tiny = httpd_rs_verified::h2_control_event_step(
            1,
            0,
            WindowUpdate { increment: 1023 },
            256,
            2,
        );
        assert_eq!(tiny.cost, 1);
        assert_eq!(tiny.available, 0);
        let useful = httpd_rs_verified::h2_control_event_step(
            0,
            u64::MAX,
            WindowUpdate { increment: 1024 },
            256,
            2,
        );
        assert_eq!(useful.cost, 1);
        assert_eq!(useful.available, 255);
        assert!(useful.admitted);
    }

    #[test]
    fn h2_stream_admission_rejects_active_or_pending_ids() {
        let active = [1u64, 3];
        let pending = [2u64, 5];
        assert!(httpd_rs_verified::h2_stream_admit(&active, &pending, 4));
        assert!(!httpd_rs_verified::h2_stream_admit(&active, &pending, 1));
        assert!(!httpd_rs_verified::h2_stream_admit(&active, &pending, 3));
        assert!(!httpd_rs_verified::h2_stream_admit(&active, &pending, 2));
        assert!(!httpd_rs_verified::h2_stream_admit(&active, &pending, 5));
    }

    #[test]
    fn h2_stream_cleanup_is_idempotent() {
        let mut lifecycle = H2ConnectionLedger::new(2, 1);
        assert!(lifecycle.begin(1));
        assert!(lifecycle.is_consistent());
        assert!(!lifecycle.begin(1));
        assert_eq!(lifecycle.active(), 1);
        assert!(lifecycle.end(1, true));
        assert!(lifecycle.is_consistent());
        assert!(!lifecycle.end(1, true));
        assert_eq!(lifecycle.active(), 0);
        assert_eq!(lifecycle.pending_resets(), 1);
        assert!(lifecycle.reclaim(1));
        assert!(lifecycle.is_consistent());
        assert!(!lifecycle.reclaim(1));
        assert_eq!(lifecycle.pending_resets(), 0);
        assert!(lifecycle.begin(1));
        assert!(lifecycle.end(1, false));
        assert_eq!(lifecycle.active(), 0);
        assert!(lifecycle.begin(3));
        assert!(lifecycle.close());
        assert!(lifecycle.is_consistent());
        assert_eq!(lifecycle.active(), 0);
        assert_eq!(lifecycle.pending_resets(), 0);
        assert!(lifecycle.streams.is_empty());
    }

    #[test]
    fn h2_settings_exchange_is_an_explicit_state_machine() {
        use httpd_rs_verified::{
            H2LocalSettingsPhase as Local, H2SettingsSync, H2SettingsSyncEvent as Event,
        };

        let state = H2SettingsSync {
            local: Local::WaitingAck,
            remote_pending: false,
            remote_initial_seen: false,
        };
        assert!(httpd_rs_verified::h2_settings_sync_step(state, Event::QueueLocal).is_none());
        let state = httpd_rs_verified::h2_settings_sync_step(state, Event::ReceiveAck).unwrap();
        assert_eq!(state.local, Local::Synced);
        let state = httpd_rs_verified::h2_settings_sync_step(state, Event::QueueLocal).unwrap();
        assert_eq!(state.local, Local::ToSend);
        let state = httpd_rs_verified::h2_settings_sync_step(state, Event::LocalSent).unwrap();
        assert_eq!(state.local, Local::WaitingAck);
        let state = httpd_rs_verified::h2_settings_sync_step(state, Event::ReceiveRemote).unwrap();
        assert!(state.remote_pending);
        assert!(httpd_rs_verified::h2_settings_sync_step(state, Event::ReceiveRemote).is_none());
        let state = httpd_rs_verified::h2_settings_sync_step(state, Event::ApplyRemote).unwrap();
        assert!(!state.remote_pending);
        assert!(state.remote_initial_seen);
    }

    #[test]
    fn h2_closed_stream_frames_use_one_classifier() {
        use httpd_rs_verified::{
            H2PeerFrame as Frame, H2PeerFrameDecision as Decision, H2PeerStreamPhase as Phase,
        };

        assert_eq!(
            httpd_rs_verified::h2_peer_frame_decision(Phase::ClosedRemoteReset, Frame::Headers),
            Decision::StreamClosed
        );
        assert_eq!(
            httpd_rs_verified::h2_peer_frame_decision(Phase::ClosedEndStream, Frame::Data),
            Decision::ConnectionStreamClosed
        );
        assert_eq!(
            httpd_rs_verified::h2_peer_frame_decision(Phase::ClosedLocalReset, Frame::Headers),
            Decision::Ignore
        );
        assert_eq!(
            httpd_rs_verified::h2_peer_frame_decision(
                Phase::ClosedLocalReset,
                Frame::MalformedHeaders,
            ),
            Decision::StreamProtocolError
        );
        assert_eq!(
            httpd_rs_verified::h2_peer_frame_decision(Phase::Idle, Frame::Data),
            Decision::ConnectionProtocolError
        );
    }

    #[test]
    fn batch_length_makes_progress_and_is_bounded() {
        assert_eq!(httpd_rs_verified::h2_batch_len(0, 1024), 0);
        assert_eq!(httpd_rs_verified::h2_batch_len(512, 1024), 512);
        assert_eq!(httpd_rs_verified::h2_batch_len(2048, 1024), 1024);
        assert!(httpd_rs_verified::h2_batch_len(1, 1) > 0);
    }

    #[test]
    fn positional_read_range_does_not_depend_on_the_file_offset() {
        let dir = std::env::temp_dir().join(format!("httpd-rs-h2-range-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("body.bin");
        fs::write(&path, b"0123456789").unwrap();
        let file = File::open(&path).unwrap();
        let budget = Arc::new(ResourceBudget::default());

        let client = std::net::IpAddr::from([127, 0, 0, 1]);
        let transport = Arc::new(QueuedH2TransportState::default());
        let middle = read_range(
            &file,
            3,
            5,
            Arc::new(Mutex::new(
                response_chunk_lease(&budget, client, 5).unwrap(),
            )),
            transport.clone(),
        )
        .unwrap();
        assert_eq!(&middle[..], b"34567");
        let whole = read_range(
            &file,
            0,
            10,
            Arc::new(Mutex::new(
                response_chunk_lease(&budget, client, 10).unwrap(),
            )),
            transport.clone(),
        )
        .unwrap();
        assert_eq!(&whole[..], b"0123456789");
        let short = read_range(
            &file,
            8,
            5,
            Arc::new(Mutex::new(
                response_chunk_lease(&budget, client, 5).unwrap(),
            )),
            transport,
        )
        .unwrap();
        assert_eq!(&short[..], b"89");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn queued_byte_slices_retain_their_resident_accounting() {
        let budget = Arc::new(ResourceBudget::default());
        let client = std::net::IpAddr::from([192, 0, 2, 50]);
        let mut resident = budget.try_response_bytes_for(client);
        resident.reserve(16).unwrap();
        let resident = Arc::new(Mutex::new(resident));
        let bytes = Bytes::from_owner(AccountedResponseBytes {
            data: vec![b'x'; 16],
            _resident: Arc::clone(&resident),
            _transport: Arc::new(QueuedH2TransportState::default()),
        });
        drop(resident);
        let tail = bytes.slice(8..);
        drop(bytes);
        assert_eq!(budget.extended_usage().2, 16);
        drop(tail);
        assert_eq!(budget.extended_usage().2, 0);
    }

    #[test]
    fn zero_length_eos_marker_retains_transport_admission() {
        let budget = Arc::new(ResourceBudget::default());
        let context = budget.context(std::net::IpAddr::from([192, 0, 2, 51]));
        let general = budget.try_h2_stream_in(&context).unwrap();
        let mut output = crate::resource::SlowOutputAdmission::tracked_h2(context, general);
        let transport = Arc::new(QueuedH2TransportState::default());
        retain_queued_h2_transport(&mut output, &transport).unwrap();
        output.finish_response();

        let marker = queued_h2_transport_marker(&transport);
        let queued = marker.clone();
        drop(transport);
        drop(marker);
        assert_eq!(budget.extended_usage().0, 1);
        assert_eq!(budget.telemetry().queued_h2_outputs, 1);

        drop(queued);
        assert_eq!(budget.extended_usage().0, 0);
        assert_eq!(budget.telemetry().queued_h2_outputs, 0);
    }
}
