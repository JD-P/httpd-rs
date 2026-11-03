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
    Reclaimed { stream_id: u64 },
}

/// Adapter-side stream identity ledger.  This is the runtime projection of
/// the verified idempotent purge set: a stream may be ended and scheduled for
/// reset cleanup at most once, even if the same early-RST/completion path is
/// observed more than once.
#[derive(Default)]
struct H2StreamIds {
    active: Vec<u64>,
    pending_resets: Vec<u64>,
}

impl H2StreamIds {
    fn begin(&mut self, stream_id: u64) -> bool {
        if !vapache_verified::h2_stream_admit(&self.active, &self.pending_resets, stream_id) {
            false
        } else {
            self.active.push(stream_id);
            true
        }
    }

    fn end(&mut self, stream_id: u64) -> bool {
        if let Some(i) = self.active.iter().position(|id| *id == stream_id) {
            self.active.swap_remove(i);
            true
        } else {
            false
        }
    }

    fn schedule_purge(&mut self, stream_id: u64) -> bool {
        if vapache_verified::h2_purge_contains_exec(&self.pending_resets, stream_id) {
            false
        } else {
            self.pending_resets.push(stream_id);
            true
        }
    }

    fn reclaim(&mut self, stream_id: u64) -> bool {
        if let Some(i) = self.pending_resets.iter().position(|id| *id == stream_id) {
            self.pending_resets.swap_remove(i);
            true
        } else {
            false
        }
    }
}

/// Releases an active slot even if the stream task panics or is cancelled.
/// The normal path overwrites `reset` with the observed result; unwinding
/// conservatively reports a reset so the connection fails closed rather than
/// leaking capacity.
struct H2TaskEventGuard {
    tx: mpsc::UnboundedSender<H2TaskEvent>,
    stream_id: u64,
    reset: bool,
}

impl Drop for H2TaskEventGuard {
    fn drop(&mut self) {
        let _ = self.tx.send(H2TaskEvent::Ended {
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
    let admitted = vapache_verified::h2_request_target_admit(
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

/// Positional reader for a response body.  `read_at` avoids changing the
/// descriptor offset (and the extra `lseek` syscall) when several streams or
/// range requests share a file.  `Read::take` + `read_to_end` fill a
/// `Vec::with_capacity` through the standard library's uninitialised spare
/// capacity, so a large body does not first zero a same-sized buffer.
struct FileAt<'a> {
    file: &'a std::fs::File,
    pos: u64,
}

impl Read for FileAt<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read_at(buf, self.pos)?;
        self.pos = self.pos.saturating_add(n as u64);
        Ok(n)
    }
}

/// Reuse bounded file/stream chunks across responses. The pool retains at
/// most 4 MiB and receives a buffer only after h2 releases the last `Bytes`
/// slice and its live response-resident lease.
const POOL_MIN_CAPACITY: usize = 64 * 1024;
const POOL_MAX_CAPACITY: usize = 64 * 1024;
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
        let mut buf = pool.free.swap_remove(index);
        pool.bytes = pool.bytes.saturating_sub(buf.capacity());
        buf.clear();
        return buf;
    }
    Vec::with_capacity(len)
}

struct PooledBuffer {
    buf: Option<Vec<u8>>,
    _resident: Arc<Mutex<ResidentLease>>,
}

struct AccountedResponseBytes {
    data: Vec<u8>,
    _resident: Arc<Mutex<ResidentLease>>,
}

impl AsRef<[u8]> for AccountedResponseBytes {
    fn as_ref(&self) -> &[u8] {
        &self.data
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

fn read_range(
    file: &std::fs::File,
    offset: u64,
    len: usize,
    resident: Arc<Mutex<ResidentLease>>,
) -> io::Result<Bytes> {
    let mut buf = take_body_buffer(len);
    let reader = FileAt { file, pos: offset };
    reader.take(len as u64).read_to_end(&mut buf)?;
    Ok(Bytes::from_owner(PooledBuffer {
        buf: Some(buf),
        _resident: resident,
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

fn head_error_response(decision: vapache_verified::H2HeadDecision) -> Option<Response> {
    match decision {
        vapache_verified::H2HeadDecision::Accept => None,
        vapache_verified::H2HeadDecision::InvalidMethod => Some(bad(400, "invalid HTTP/2 method")),
        vapache_verified::H2HeadDecision::TargetTooLong => {
            Some(bad(414, "request target too long"))
        }
        vapache_verified::H2HeadDecision::TooManyHeaders => {
            Some(bad(431, "too many request headers"))
        }
        vapache_verified::H2HeadDecision::HeaderFieldTooLarge => {
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
        let Some(length) = vapache_verified::parse_decimal_u64(value) else {
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

async fn read_body(
    mut recv: h2::RecvStream,
    limit: u64,
    timeout: std::time::Duration,
    min_rate: u64,
    resource_budget: Arc<crate::resource::ResourceBudget>,
    max_spool_bytes: u64,
    max_spool_files: u64,
    resource_context: crate::resource::ResourceContext,
    resident: &mut crate::resource::ResidentLease,
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
    let mut budget = vapache_verified::h2_body_init(limit);
    let mut framing = vapache_verified::ChunkFramingState {
        chunks: 0,
        bytes: 0,
    };
    let started = Instant::now();
    loop {
        // One deadline covers the complete body.  Restarting the timeout for
        // every DATA frame lets a slow peer keep a request alive forever.
        let remaining = timeout.saturating_sub(started.elapsed());
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
            vapache_verified::chunk_framing_budget_step(framing, 5, true, 65_536, 1024 * 1024)
        else {
            return Err(H2ReadFailure::Response(bad(
                400,
                "HTTP/2 DATA frame budget exceeded",
            )));
        };
        framing = next_framing;
        let Some(next_budget) = vapache_verified::h2_body_append(budget, chunk.len() as u64) else {
            return Err(H2ReadFailure::Response(bad(413, "request body too large")));
        };
        budget = next_budget;
        if let Err(error) = body.push_with_resident(&chunk, resident) {
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
) -> Result<(), H2ReadFailure> {
    let mut budget = vapache_verified::h2_body_init(limit);
    let mut framing = vapache_verified::ChunkFramingState {
        chunks: 0,
        bytes: 0,
    };
    let started = Instant::now();
    loop {
        let remaining = timeout.saturating_sub(started.elapsed());
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
            vapache_verified::chunk_framing_budget_step(framing, 5, true, 65_536, 1024 * 1024)
        else {
            return Err(H2ReadFailure::Response(bad(
                400,
                "HTTP/2 DATA frame budget exceeded",
            )));
        };
        framing = next_framing;
        let Some(next_budget) = vapache_verified::h2_body_append(budget, chunk.len() as u64) else {
            return Err(H2ReadFailure::Response(bad(413, "request body too large")));
        };
        if next_budget.len > declared {
            return Err(H2ReadFailure::Response(bad(400, "Content-Length mismatch")));
        }
        budget = next_budget;
        let chunk_len = chunk.len();
        let remaining = timeout.saturating_sub(started.elapsed());
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
    if budget.len != declared {
        return Err(H2ReadFailure::Response(bad(400, "Content-Length mismatch")));
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
    let client = output.client();
    if !crate::http::response_headers_admitted(&resp) {
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
    let body_len = resp.body_len();
    let preserved_content_length =
        crate::http::preserved_response_content_length(&resp, head_only)?;
    let header_sanitizer = crate::http::ResponseHeaderSanitizer::from_response(&resp)?;

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
            let Ok(name) = HeaderName::from_bytes(lname.as_bytes()) else {
                continue;
            };
            let Ok(value) = HeaderValue::from_bytes(&value) else {
                continue;
            };
            headers.append(name, value);
        }
        if !have_date {
            headers.append(
                HeaderName::from_static("date"),
                HeaderValue::from_str(&http_date_now())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad date"))?,
            );
        }
        if !have_server {
            headers.append(
                HeaderName::from_static("server"),
                HeaderValue::from_bytes(cfg.server_header().as_bytes())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad server"))?,
            );
        }
        if let Some(length) = preserved_content_length {
            headers.append(
                HeaderName::from_static("content-length"),
                HeaderValue::from_str(&length.to_string())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad length"))?,
            );
        } else if !status.is_informational()
            && status != StatusCode::NO_CONTENT
            && status != StatusCode::RESET_CONTENT
            && status != StatusCode::NOT_MODIFIED
        {
            // Body-bearing responses and HEAD responses without an explicit
            // representation length use the actual selected body length.
            headers.append(
                HeaderName::from_static("content-length"),
                HeaderValue::from_str(&body_len.to_string())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad length"))?,
            );
        }
    }
    let response = out
        .body(())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid response headers"))?;

    let end = no_body || body_len == 0;
    let mut ownership = resp.take_retained_output_ownership();
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
                Bytes::new(),
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
            let resident = ownership.share_resident()?;
            let data = Bytes::from_owner(AccountedResponseBytes {
                data,
                _resident: resident,
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
                    tokio::task::spawn_blocking(move || {
                        let _blocking_read = blocking_read;
                        let mut buf = take_body_buffer(capacity);
                        buf.resize(capacity, 0);
                        let result = reader.read(&mut buf[..capacity]);
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
                    send.send_data(Bytes::new(), true).map_err(send_io_error)?;
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
                });
                send.send_data(data, left == 0).map_err(send_io_error)?;
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
            const CHUNK: u64 = 64 * 1024;
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
                    let (next_file, data, next_ownership) =
                        tokio::task::spawn_blocking(move || {
                            let _blocking_read = blocking_read;
                            let data = read_range(&file, pos, capacity, resident);
                            (file, data, read_ownership.complete_read())
                        })
                        .await
                        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
                    file = next_file;
                    ownership = next_ownership;
                    data?
                } else {
                    read_range(&file, pos, capacity, resident)?
                };
                let filled = data.len();
                if filled == 0 {
                    send.send_data(Bytes::new(), true).map_err(send_io_error)?;
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
                quota_identity_valid = vapache_verified::h2_field_size_admit(
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
                if !vapache_verified::h2_field_size_admit(
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
    let stream_quota = cfg.resource_budget.try_h2_stream_in(&resource_context)?;
    if let Err(error) = cfg.resource_budget.try_request_rate(&resource_context) {
        drop(stream_quota);
        return Err(error);
    }
    Ok(H2StreamAdmission {
        quota_peer,
        resource_context,
        quota_identity_valid,
        stream_quota,
    })
}

async fn handle_stream(
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    peer: SocketAddr,
    local_ip: String,
    local_port: u16,
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
        quota_identity_valid,
        stream_quota,
    } = admission;
    let mut output_admission =
        crate::resource::SlowOutputAdmission::tracked_h2(resource_context.clone(), stream_quota);
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
    if uri.authority().is_some_and(|authority| {
        !vapache_verified::h2_field_size_admit(
            b"host".len() as u64,
            authority.as_str().len() as u64,
            cfg.limit_request_field_size as u64,
        )
    }) {
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
    let Some(target) = request_target(&method, &uri, true) else {
        return send_response_with_admission(
            respond,
            &cfg,
            bad(400, "invalid HTTP/2 request target"),
            false,
            &mut output_admission,
        )
        .await
        .is_err();
    };
    let (raw_path, query) = match target.iter().position(|b| *b == b'?') {
        Some(i) => (target[..i].to_vec(), target[i + 1..].to_vec()),
        None => (target.clone(), Vec::new()),
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

    let mut headers = crate::http::Headers::default();
    let mut header_budget =
        vapache_verified::h2_header_init(vapache_verified::h2_settings().max_header_list as u64);
    let mut header_count = 0u64;
    let mut largest_field = 0u64;
    for (name, value) in parts.headers.iter() {
        let field_len = name.as_str().len().saturating_add(value.as_bytes().len()) as u64;
        let Some(next) = vapache_verified::h2_header_add(header_budget, field_len) else {
            let _ = send_response_with_admission(
                respond,
                &cfg,
                bad(431, "request header list too large"),
                false,
                &mut output_admission,
            )
            .await;
            return true;
        };
        header_budget = next;
        header_count = header_count.saturating_add(1);
        largest_field = largest_field.max(field_len);

        // RFC 9113 forbids connection-specific fields.  The h2 codec rejects
        // them today, but keep the downgrade boundary explicit in the
        // adapter so a dependency behavior change cannot reintroduce the
        // Transfer-Encoding smuggling primitive (CVE-2026-58150).
        if forbidden_h2_header(name.as_str(), value.as_bytes()) {
            let _ = send_response_with_admission(
                respond,
                &cfg,
                bad(400, "connection-specific HTTP/2 header"),
                false,
                &mut output_admission,
            )
            .await;
            return true;
        }

        // :authority is authoritative in HTTP/2.  Ignore any legacy Host
        // header so a conflicting pair cannot select a different vhost than
        // the one used for TLS SNI/absolute redirects. It still counts toward
        // all request-head limits above.
        if name.as_str() == "host" {
            continue;
        }
        headers.push_merged(name.as_str(), value.as_bytes());
    }
    // HTTP/2 carries the authority in :authority (exposed through the URI),
    // not in a Host header.  Apache exposes it as Host to modules/CGI.
    if let Some(authority) = uri.authority() {
        let value = authority.as_str().as_bytes();
        let field_len = b"host".len().saturating_add(value.len()) as u64;
        let Some(_next) = vapache_verified::h2_header_add(header_budget, field_len) else {
            let _ = send_response_with_admission(
                respond,
                &cfg,
                bad(431, "request header list too large"),
                false,
                &mut output_admission,
            )
            .await;
            return true;
        };
        header_count = header_count.saturating_add(1);
        largest_field = largest_field.max(field_len);
        headers.push("host", value.to_vec());
    }

    // Apply the same request bounds as the HTTP/1 parser.  HTTP/2's HPACK
    // decoder has its own table limits, but that does not replace Apache's
    // LimitRequestLine/Fields/FieldSize policy.  The whole head is admitted by
    // one verified decision function so rejection precedence cannot drift
    // between the h2 and HTTP/1 paths.
    let head_error = head_error_response(vapache_verified::h2_head_admit(
        method.as_bytes(),
        target.len() as u64,
        cfg.limit_request_line as u64,
        header_count,
        cfg.limit_request_fields as u64,
        largest_field,
        cfg.limit_request_field_size as u64,
    ));
    if let Some(resp) = head_error {
        return send_response_with_admission(respond, &cfg, resp, false, &mut output_admission)
            .await
            .is_err();
    }
    let declared = match canonicalize_content_length(&mut headers) {
        Ok(declared) => declared,
        Err(()) => {
            // h2 validates Content-Length syntax and duplicates before
            // yielding an accepted request.
            // coverage:ignore-start - upstream h2 framing invariant
            return send_response_with_admission(
                respond,
                &cfg,
                bad(400, "invalid Content-Length"),
                false,
                &mut output_admission,
            )
            .await
            .is_err();
            // coverage:ignore-stop
        }
    };
    headers.bind_request_scope(crate::resource::RequestScope::new(resource_context));
    let mut req = Request {
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
        // HTTP/2 framing is handled by the h2 crate before a `Request` exists.
        framing: crate::verified::BodyFraming::None,
    };
    let peer = cfg.client_addr(peer, &req);
    let _request_scope_guard = req.request_scope().map(|scope| scope.guard());
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
    if has_body && !cfg.body_handlers_possible() {
        let status = if matches!(req.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
            400
        } else {
            405
        };
        return send_response_with_admission(
            respond,
            &cfg,
            bad(
                status,
                "request body is not accepted by a static-only configuration",
            ),
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
    let mut phase = vapache_verified::RequestPhase::Head;
    let mut early = None;
    let mut early_remote_user = None;
    let mut prepared_handler = None;
    let mut body_remote_user = None;
    let mut drain_after_body = None;
    let mut recv = Some(recv);
    if has_body {
        // Route, rewrite and authorization complete before DATA is accepted.
        // This is the HTTP/2 projection of the same lazy-body transition used
        // by HTTP/1 (and, importantly, it happens before allocating a spool).
        let probe_cfg = cfg.clone();
        let probe_local_ip = local_ip.clone();
        let mut probe_req = req;
        let probed = tokio::task::spawn_blocking(move || {
            let decision = crate::server::probe_request_body(
                &probe_cfg,
                &mut probe_req,
                peer,
                &probe_local_ip,
                local_port,
                true,
            );
            (probe_req, decision)
        })
        .await;
        match probed {
            Ok((
                returned_req,
                crate::server::BodyRouteDecision::Read {
                    handler,
                    remote_user,
                },
            )) => {
                req = returned_req;
                phase = vapache_verified::request_phase_step(
                    phase,
                    vapache_verified::RequestPhaseEvent::RouteNeedsBody,
                )
                .expect("HTTP/2 body route phase transition");
                prepared_handler = Some(handler);
                body_remote_user = remote_user;
            }
            Ok((returned_req, crate::server::BodyRouteDecision::Drain(response, remote_user))) => {
                req = returned_req;
                phase = vapache_verified::request_phase_step(
                    phase,
                    vapache_verified::RequestPhaseEvent::RouteNeedsDrain,
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
                phase = vapache_verified::request_phase_step(
                    phase,
                    vapache_verified::RequestPhaseEvent::EarlyResponse,
                )
                .expect("HTTP/2 early response phase transition");
                early = Some(response);
                early_remote_user = remote_user;
                // Dropping the receive half discards already queued DATA and
                // stops returning stream-level credit for further upload.
                drop(recv.take());
            }
            Err(_) => {
                logger.error("HTTP/2 request probe task failed");
                return true;
            }
        }
    } else {
        // Bodyless dynamic requests use the same prepared-handler IR.  Route
        // and authorization run under stream admission, then the
        // potentially slow backend phase runs independently of that worker.
        let probe_cfg = cfg.clone();
        let probe_local_ip = local_ip.clone();
        let mut probe_req = req;
        let probed = tokio::task::spawn_blocking(move || {
            let decision = crate::server::probe_prepared_handler(
                &probe_cfg,
                &mut probe_req,
                peer,
                &probe_local_ip,
                local_port,
                true,
            );
            (probe_req, decision)
        })
        .await;
        match probed {
            Ok((
                returned_req,
                crate::server::PreparedRouteDecision::Prepared {
                    handler,
                    remote_user,
                },
            )) => {
                req = returned_req;
                phase = vapache_verified::request_phase_step(
                    phase,
                    vapache_verified::RequestPhaseEvent::RoutePrepared,
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
                phase = vapache_verified::request_phase_step(
                    phase,
                    vapache_verified::RequestPhaseEvent::RouteReady,
                )
                .expect("HTTP/2 bodyless route phase transition");
                phase = vapache_verified::request_phase_step(
                    phase,
                    vapache_verified::RequestPhaseEvent::DispatchComplete,
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

    let mut streamed = None;
    if has_body
        && early.is_none()
        && declared.is_some_and(|length| length > crate::http::MAX_REQUEST_BODY_IN_MEMORY)
        && prepared_handler.is_some()
    {
        let length = declared.expect("checked fixed HTTP/2 body length");
        match crate::http::install_streaming_request_body(&mut req, length, &cfg.resource_budget) {
            Ok(sender) => {
                req.headers.hold_resident(
                    request_resident
                        .take()
                        .expect("streaming HTTP/2 body retained its resident lease"),
                );
                phase = vapache_verified::request_phase_step(
                    phase,
                    vapache_verified::RequestPhaseEvent::BackendStarted,
                )
                .expect("HTTP/2 streaming backend phase transition");
                let mut rejected_req = req.clone();
                let dispatch_cfg = cfg.clone();
                let handler = prepared_handler
                    .take()
                    .expect("streaming route retained its prepared handler");
                let remote_user = body_remote_user.take();
                let backend_req = req.clone();
                let mut backend = tokio::task::spawn_blocking(move || {
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
                });
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
                            Ok(()) | Err(H2ReadFailure::BackendClosed) => Some(backend.await),
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
                                phase = vapache_verified::request_phase_step(
                                    phase,
                                    vapache_verified::RequestPhaseEvent::BodyErrorResponse,
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
                    phase = vapache_verified::request_phase_step(
                        phase,
                        vapache_verified::RequestPhaseEvent::BackendComplete,
                    )
                    .expect("HTTP/2 streaming backend completion transition");
                    streamed = Some((req, response, remote_user));
                }
            }
            Err(_) => {
                phase = vapache_verified::request_phase_step(
                    phase,
                    vapache_verified::RequestPhaseEvent::BodyErrorResponse,
                )
                .expect("HTTP/2 streaming admission failure transition");
                early = Some(bad(503, "request-body capacity exhausted"));
                early_remote_user = body_remote_user.take();
                drop(recv.take());
            }
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
                request_resident
                    .as_mut()
                    .expect("buffered HTTP/2 body retained its resident lease"),
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
                    phase = vapache_verified::request_phase_step(
                        phase,
                        vapache_verified::RequestPhaseEvent::BodyDiscarded,
                    )
                    .expect("HTTP/2 body discard phase transition");
                    early = Some(response);
                    early_remote_user = remote_user;
                } else {
                    req.body = body.bytes;
                    req.body_spool = body.spool;
                    phase = vapache_verified::request_phase_step(
                        phase,
                        vapache_verified::RequestPhaseEvent::BodyComplete,
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
                phase = vapache_verified::request_phase_step(
                    phase,
                    vapache_verified::RequestPhaseEvent::BodyErrorResponse,
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
                let dispatched = tokio::task::spawn_blocking(move || {
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
                })
                .await;
                let Ok((req, resp, remote_user)) = dispatched else {
                    logger.error("HTTP/2 request dispatcher task failed");
                    return true;
                };
                phase = vapache_verified::request_phase_step(
                    phase,
                    if runs_backend {
                        vapache_verified::RequestPhaseEvent::BackendComplete
                    } else {
                        vapache_verified::RequestPhaseEvent::DispatchComplete
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
                let closed = vapache_verified::request_phase_step(
                    phase,
                    vapache_verified::RequestPhaseEvent::Cancel,
                )
                .expect("HTTP/2 cancellation phase transition");
                debug_assert_eq!(closed, vapache_verified::RequestPhase::Closed);
                // Peer-close/send failures are already exercised directly by the
                // bounded response sender; this adapter arm only adds logging.
                logger.error(&format!("HTTP/2 stream failed: {e}")); // coverage:ignore-line - peer timing race
                return true; // coverage:ignore-line - peer timing race
            }
        };
    phase = vapache_verified::request_phase_step(
        phase,
        vapache_verified::RequestPhaseEvent::OutputComplete,
    )
    .expect("HTTP/2 output phase transition");
    debug_assert_eq!(phase, vapache_verified::RequestPhase::Closed);
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

/// Compose the two H2Budget transitions for a task completion.  A normal
/// completion releases the active slot; a reset releases it and consumes one
/// pending-reset slot.  `None` means the connection should fail closed.
fn h2_task_end(
    budget: vapache_verified::H2Budget,
    reset: bool,
) -> Option<vapache_verified::H2Budget> {
    let finished =
        vapache_verified::h2_budget_step(budget, vapache_verified::H2BudgetEvent::Finish)?;
    if reset {
        vapache_verified::h2_budget_step(finished, vapache_verified::H2BudgetEvent::Reset)
    } else {
        Some(finished)
    }
}

/// Feed arbitrary wire bytes through the patched h2 state machine.  This is
/// deliberately bounded: malformed inputs must terminate promptly rather
/// than parking a fuzz worker on an incomplete connection.
#[cfg(feature = "fuzzing")]
pub fn fuzz_h2_frames(data: &[u8]) {
    use tokio::io::AsyncWriteExt;
    use tokio::time::{timeout, Duration};

    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    else {
        return;
    };
    let input = data[..data.len().min(256 * 1024)].to_vec();
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

pub async fn serve<G, F>(
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    tls: TlsStream<TcpStream>,
    peer: SocketAddr,
    local_ip: String,
    local_port: u16,
    on_ready: F,
) -> io::Result<()>
where
    F: FnOnce() -> io::Result<G>,
{
    serve_io(cfg, logger, tls, peer, local_ip, local_port, on_ready).await
}

async fn serve_io<T, G, F>(
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    io: T,
    peer: SocketAddr,
    local_ip: String,
    local_port: u16,
    on_ready: F,
) -> io::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
    F: FnOnce() -> io::Result<G>,
{
    let settings = vapache_verified::h2_settings();
    let mut builder = h2::server::Builder::new();
    builder
        // Bound compressed/decoded header memory before HPACK allocates.
        .max_header_list_size(settings.max_header_list)
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
    let mut conn = tokio::time::timeout(preface_timeout, builder.handshake(io))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP/2 preface timed out"))?
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // h2's server handshake consumes the 24-byte connection preface but does
    // not wait for the client's mandatory initial SETTINGS. Keep this socket
    // in lightweight admission until `accept` has processed SETTINGS and the
    // first request head. This is deliberately stronger than timing SETTINGS
    // alone: an idle post-SETTINGS peer cannot occupy an established slot.
    let mut ready_callback = Some(on_ready);
    let mut established_guard: Option<G> = None;
    let initial_request_deadline = tokio::time::sleep(preface_timeout);
    tokio::pin!(initial_request_deadline);

    // The same verified budget is used for every accepted stream.  The h2
    // crate still owns frame parsing and its own reset counters; this loop
    // projects the adapter's task lifecycle and observed reset errors into
    // the H2Budget state machine.  Events are prioritized so a completed
    // task releases its slot before another request is accepted.
    let mut budget = vapache_verified::h2_budget_new(
        settings.max_concurrent_streams as u64,
        settings.max_reset_streams as u64,
    );
    let mut stream_ids = H2StreamIds::default();
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let mut reset_reclaims: BinaryHeap<Reverse<(Instant, u64)>> = BinaryHeap::new();
    let idle_timeout = cfg.timeout.max(cfg.keep_alive_timeout).max(H2_IDLE_FLOOR);
    loop {
        let reclaim_deadline = reset_reclaims.peek().map(|entry| entry.0 .0);
        let reclaim_timer = tokio::time::sleep_until(
            reclaim_deadline
                .map(tokio::time::Instant::from_std)
                .unwrap_or_else(|| tokio::time::Instant::now() + idle_timeout),
        );
        tokio::pin!(reclaim_timer);
        tokio::select! {
            biased;
            _ = &mut initial_request_deadline, if ready_callback.is_some() => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP/2 initial SETTINGS/request head timed out",
                ));
            }
            Some(event) = events_rx.recv() => {
                match event {
                    H2TaskEvent::Ended { stream_id, reset } => {
                        // Idempotent cleanup: a duplicate early-reset or close
                        // notification for the same stream is ignored instead
                        // of decrementing the budget twice.
                        if !stream_ids.end(stream_id) {
                            // One RAII guard owns the sole Ended event.
                            logger.error("HTTP/2 duplicate stream completion ignored"); // coverage:ignore-line - guard uniqueness invariant
                            continue; // coverage:ignore-line - guard uniqueness invariant
                        }
                        let Some(next) = h2_task_end(budget, reset) else {
                            // Either the accounting state was lost, or the
                            // reset budget is exhausted.  Do not let queued
                            // reset wakeups grow without bound.
                            // h2's stricter stream/reset settings and the
                            // verified budget transition make this unreachable.
                            // coverage:ignore-start - verified budget invariant
                            logger.error("HTTP/2 stream/reset budget exhausted; closing connection");
                            conn.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
                            break;
                            // coverage:ignore-stop
                        };
                        budget = next;
                        if reset && stream_ids.schedule_purge(stream_id) {
                            reset_reclaims.push(Reverse((Instant::now() + H2_RESET_RECLAIM, stream_id)));
                        }
                    }
                    H2TaskEvent::Reclaimed { stream_id } => {
                        if !stream_ids.reclaim(stream_id) {
                            // Reclaim is scheduled once by `schedule_purge`.
                            continue; // coverage:ignore-line - purge-set invariant
                        }
                        if let Some(next) = vapache_verified::h2_budget_step(
                            budget,
                            vapache_verified::H2BudgetEvent::Reclaim,
                        ) {
                            budget = next;
                        }
                    }
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
                    if !stream_ids.reclaim(stream_id) {
                        continue;
                    }
                    if let Some(next) = vapache_verified::h2_budget_step(
                        budget,
                        vapache_verified::H2BudgetEvent::Reclaim,
                    ) {
                        budget = next;
                    }
                }
            }
            _ = tokio::time::sleep(idle_timeout), if budget.active == 0 => {
                logger.error("HTTP/2 connection idle timeout");
                conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                break;
            }
            accepted = conn.accept() => {
                let Some(result) = accepted else {
                    break;
                };
                let (request, mut respond) =
                    result.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                if let Some(callback) = ready_callback.take() {
                    established_guard = Some(callback()?);
                }
                let stream_id = respond.stream_id().as_u32() as u64;
                let admission = match admit_stream_before_spawn(&cfg, peer, &request) {
                    Ok(admission) => admission,
                    Err(_) => {
                        respond.send_reset(h2::Reason::REFUSED_STREAM);
                        continue;
                    }
                };
                let Some(next) = vapache_verified::h2_budget_step(
                    budget,
                    vapache_verified::H2BudgetEvent::Begin,
                ) else {
                    // This should be unreachable while h2's own max-stream
                    // setting is at least as strict; refuse rather than
                    // spawning an untracked task if it ever is not.
                    // The h2 builder rejects at the same (or lower) active
                    // stream limit before accept can yield this request.
                    // coverage:ignore-start - upstream h2 admission invariant
                    logger.error("HTTP/2 active-stream budget rejected a stream");
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    continue;
                    // coverage:ignore-stop
                };
                budget = next;
                if !stream_ids.begin(stream_id) {
                    // h2 guarantees connection-unique monotonically assigned
                    // stream identifiers for accepted requests.
                    // coverage:ignore-start - upstream h2 identity invariant
                    logger.error("HTTP/2 duplicate stream identifier; closing connection");
                    conn.abrupt_shutdown(h2::Reason::PROTOCOL_ERROR);
                    break;
                    // coverage:ignore-stop
                }
                let cfg = cfg.clone();
                let logger = logger.clone();
                let local_ip = local_ip.clone();
                let tx = events_tx.clone();
                tokio::spawn(async move {
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
                        cfg, logger, peer, local_ip, local_port, request, respond, admission,
                    )
                    .await;
                });
            }
        }
    }
    drop(established_guard);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::fs::{self, File};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    fn test_config_with_extra(
        name: &str,
        extra: &str,
    ) -> (Arc<Config>, Arc<Logger>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("vapache-h2-{name}-{}", std::process::id()));
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
                 ProxyPass /__body_test http://127.0.0.1:9/\n\
                 {}\n",
                dir.display(),
                dir.display(),
                dir.display(),
                extra
            ),
        )
        .unwrap();
        let cfg = Config::load(&conf, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let cfg = Arc::new(cfg);
        let logger = Arc::new(Logger::new(&cfg).unwrap());
        (cfg, logger, dir)
    }

    fn test_config(name: &str) -> (Arc<Config>, Arc<Logger>, std::path::PathBuf) {
        test_config_with_extra(name, "")
    }

    async fn round_trip(
        cfg: Arc<Config>,
        logger: Arc<Logger>,
        request: http::Request<()>,
        body: &[u8],
    ) -> (u16, Vec<u8>, bool) {
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
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
        });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move { connection.await.unwrap() });
        let request_label = format!("{} {}", request.method(), request.uri());
        let head_only = request.method() == http::Method::HEAD;
        let end = body.is_empty();
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
                let last = offset + take == body.len();
                if send
                    .send_data(Bytes::copy_from_slice(&body[offset..offset + take]), last)
                    .is_err()
                {
                    break;
                }
                offset += take;
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

    async fn response_round_trip(
        cfg: Arc<Config>,
        response: Response,
        head_only: bool,
    ) -> (io::Result<u64>, u16, http::HeaderMap, Vec<u8>) {
        let (client_io, server_io) = tokio::io::duplex(32 * 1024 * 1024);
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
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
        });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
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
            let handler = handle_stream(
                cfg,
                logger,
                "127.0.0.1:12345".parse().unwrap(),
                "127.0.0.1".into(),
                443,
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
        let root = std::env::temp_dir().join(format!("vapache-h2-{name}-{}", std::process::id()));
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
        // but vapached does not implement tunnels and must reject the
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
        let dir = std::env::temp_dir().join(format!("vapache-h2-{name}-{}", std::process::id()));
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
    async fn h2_connection_loop_handles_completion_reset_and_reclaim() {
        async fn run(reset: bool) {
            let (cfg, logger, dir) = test_config(if reset { "serve-reset" } else { "serve-ok" });
            let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
            let server = tokio::spawn(serve_io(
                cfg,
                logger,
                server_io,
                "127.0.0.1:12345".parse().unwrap(),
                "127.0.0.1".into(),
                443,
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
    async fn h2_preface_and_initial_settings_must_arrive_before_header_deadline() {
        let (cfg, logger, dir) = test_config("preface-timeout");
        let mut short = (*cfg).clone();
        short.request_header_timeout = std::time::Duration::ZERO;
        let cfg = Arc::new(short);
        for preface in [None, Some(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..])] {
            let (mut client_io, server_io) = tokio::io::duplex(1024);
            if let Some(preface) = preface {
                client_io.write_all(preface).await.unwrap();
            }
            let admitted = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let admitted_by_callback = admitted.clone();
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                serve_io(
                    cfg.clone(),
                    logger.clone(),
                    server_io,
                    "127.0.0.1:12345".parse().unwrap(),
                    "127.0.0.1".into(),
                    443,
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
    async fn h2_connection_idle_and_stream_timeouts_close_cleanly() {
        let (cfg, logger, dir) = test_config("serve-timeouts");
        let mut short = (*cfg).clone();
        short.timeout = std::time::Duration::ZERO;
        short.keep_alive_timeout = std::time::Duration::ZERO;
        let cfg = Arc::new(short);

        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let server = tokio::spawn(serve_io(
            cfg.clone(),
            logger.clone(),
            server_io,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1".into(),
            443,
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
        let server = tokio::spawn(serve_io(
            cfg,
            logger,
            server_io,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1".into(),
            443,
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
        let server = tokio::spawn(serve_io(
            cfg,
            logger,
            server_io,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1".into(),
            443,
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
            let handler = handle_stream(
                cfg,
                logger,
                "127.0.0.1:12345".parse().unwrap(),
                "127.0.0.1".into(),
                443,
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
        let mut stream = Response::new(200);
        stream.body = Body::Stream {
            reader: Box::new(&b"stream body"[..]),
            len: 11,
        };
        let (result, status, _, body) = response_round_trip(cfg.clone(), stream, false).await;
        assert_eq!(result.unwrap(), 11);
        assert_eq!(status, 200);
        assert_eq!(body, b"stream body");

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
        assert_eq!(
            response_round_trip(cfg.clone(), invalid_headers, false)
                .await
                .0
                .unwrap(),
            7
        );

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
        use vapache_verified::H2HeadDecision::{
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
        assert!(!vapache_verified::h2_request_target_admit(
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
        assert!(vapache_verified::h2_body_admit(0, 10, 10));
        assert!(!vapache_verified::h2_body_admit(10, 1, 10));
        assert!(!vapache_verified::h2_body_admit(u64::MAX, 1, 10));
        assert!(vapache_verified::h2_target_admit(10, 10));
        assert!(!vapache_verified::h2_target_admit(11, 10));
        assert!(vapache_verified::h2_header_admit(3, 10, 3, 10));
        assert!(!vapache_verified::h2_header_admit(4, 10, 3, 10));
        assert!(vapache_verified::h2_header_total_admit(10, 10));
        assert!(!vapache_verified::h2_header_total_admit(11, 10));
        let hs = vapache_verified::h2_header_init(10);
        let hs = vapache_verified::h2_header_add(hs, 7).unwrap();
        assert!(vapache_verified::h2_header_add(hs, 4).is_none());
        assert_eq!(vapache_verified::h2_header_add(hs, 3).unwrap().total, 10);
    }

    #[test]
    fn h2_head_admission_reports_the_first_failed_bound() {
        use vapache_verified::H2HeadDecision::{
            Accept, HeaderFieldTooLarge, InvalidMethod, TargetTooLong, TooManyHeaders,
        };
        assert!(vapache_verified::h2_method_ok(b"GET"));
        assert!(!vapache_verified::h2_method_ok(b""));
        assert!(!vapache_verified::h2_method_ok(b"GET SPACE"));
        let too_long = [b'A'; 65];
        assert!(!vapache_verified::h2_method_ok(&too_long));
        assert!(vapache_verified::h2_field_size_admit(4, 6, 10));
        assert!(!vapache_verified::h2_field_size_admit(4, 7, 10));
        assert!(!vapache_verified::h2_field_size_admit(11, 0, 10));
        assert_eq!(
            vapache_verified::h2_head_admit(b"GET", 10, 10, 3, 3, 10, 10),
            Accept
        );
        assert_eq!(
            vapache_verified::h2_head_admit(b"BAD\x00METHOD", 1, 10, 1, 3, 1, 10),
            InvalidMethod
        );
        assert_eq!(
            vapache_verified::h2_head_admit(b"GET", 11, 10, 1, 3, 1, 10),
            TargetTooLong
        );
        assert_eq!(
            vapache_verified::h2_head_admit(b"GET", 10, 10, 4, 3, 1, 10),
            TooManyHeaders
        );
        assert_eq!(
            vapache_verified::h2_head_admit(b"GET", 10, 10, 3, 3, 11, 10),
            HeaderFieldTooLarge
        );
    }

    #[test]
    fn h2_body_state_never_accepts_more_than_the_limit() {
        let state = vapache_verified::h2_body_init(10);
        let state = vapache_verified::h2_body_append(state, 7).unwrap();
        assert_eq!(state.len, 7);
        assert!(vapache_verified::h2_body_append(state, 4).is_none());
        let state = vapache_verified::h2_body_append(state, 3).unwrap();
        assert_eq!(state.len, 10);
        assert!(vapache_verified::h2_body_append(state, 1).is_none());
    }

    #[test]
    fn h2_flow_model_bounds_windows_and_send_buffer() {
        let flow = vapache_verified::h2_flow_new(1024, 256, 512);
        let flow = vapache_verified::h2_flow_charge(flow, 200).unwrap();
        assert_eq!(flow.conn_window, 824);
        assert_eq!(flow.stream_window, 56);
        assert!(vapache_verified::h2_flow_charge(flow, 57).is_none());
        let flow = vapache_verified::h2_flow_enqueue(flow, 512).unwrap();
        assert!(vapache_verified::h2_flow_enqueue(flow, 1).is_none());
        let flow = vapache_verified::h2_flow_dequeue(flow, 512).unwrap();
        let flow = vapache_verified::h2_flow_credit(flow, u64::MAX);
        assert_eq!(flow.conn_window, 1024);
        assert_eq!(flow.stream_window, 256);
    }

    #[test]
    fn h2_budget_transitions_preserve_limits() {
        let budget = vapache_verified::h2_budget_new(2, 1);
        let budget = vapache_verified::h2_budget_begin(budget).unwrap();
        let budget = vapache_verified::h2_budget_begin(budget).unwrap();
        assert!(vapache_verified::h2_budget_begin(budget).is_none());
        let budget = vapache_verified::h2_budget_reset(budget).unwrap();
        assert!(vapache_verified::h2_budget_reset(budget).is_none());
        let budget = vapache_verified::h2_budget_reclaim(budget).unwrap();
        assert!(vapache_verified::h2_budget_reclaim(budget).is_none());
        let budget = vapache_verified::h2_budget_finish(budget).unwrap();
        let budget = vapache_verified::h2_budget_finish(budget).unwrap();
        assert!(vapache_verified::h2_budget_finish(budget).is_none());

        let budget =
            vapache_verified::h2_budget_step(budget, vapache_verified::H2BudgetEvent::Begin)
                .unwrap();
        assert_eq!(budget.active, 1);
        let budget =
            vapache_verified::h2_budget_step(budget, vapache_verified::H2BudgetEvent::Finish)
                .unwrap();
        assert_eq!(budget.active, 0);

        let budget = vapache_verified::h2_budget_step(
            vapache_verified::h2_budget_new(1, 1),
            vapache_verified::H2BudgetEvent::Begin,
        )
        .unwrap();
        let budget = h2_task_end(budget, true).unwrap();
        assert_eq!(budget.active, 0);
        assert_eq!(budget.pending_resets, 1);
        let budget =
            vapache_verified::h2_budget_step(budget, vapache_verified::H2BudgetEvent::Reclaim)
                .unwrap();
        assert_eq!(budget.pending_resets, 0);
        let budget =
            vapache_verified::h2_budget_step(budget, vapache_verified::H2BudgetEvent::Begin)
                .unwrap();
        assert!(h2_task_end(budget, false).is_some());

        let (tx, mut rx) = mpsc::unbounded_channel();
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
        use vapache_verified::H2ControlEvent::{Ping, Priority, Settings, WindowUpdate};

        let settings = vapache_verified::h2_control_event_step(256, 0, Settings, 256, 2);
        assert_eq!(settings.cost, 16);
        assert_eq!(settings.available, 240);
        assert!(settings.admitted);

        let ping = vapache_verified::h2_control_event_step(0, 1, Ping, 256, 2);
        assert_eq!(ping.refill_seconds, 1);
        assert_eq!(ping.cost, 1);
        assert_eq!(ping.available, 1);
        assert!(ping.admitted);
        let priority = vapache_verified::h2_control_event_step(ping.available, 0, Priority, 256, 2);
        assert_eq!(priority.available, 0);
        assert!(priority.admitted);
        assert!(!vapache_verified::h2_control_event_step(0, 0, Ping, 256, 2).admitted);

        let tiny =
            vapache_verified::h2_control_event_step(1, 0, WindowUpdate { increment: 1023 }, 256, 2);
        assert_eq!(tiny.cost, 1);
        assert_eq!(tiny.available, 0);
        let useful = vapache_verified::h2_control_event_step(
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
        assert!(vapache_verified::h2_stream_admit(&active, &pending, 4));
        assert!(!vapache_verified::h2_stream_admit(&active, &pending, 1));
        assert!(!vapache_verified::h2_stream_admit(&active, &pending, 3));
        assert!(!vapache_verified::h2_stream_admit(&active, &pending, 2));
        assert!(!vapache_verified::h2_stream_admit(&active, &pending, 5));
    }

    #[test]
    fn h2_stream_cleanup_is_idempotent() {
        let mut ids = H2StreamIds::default();
        assert!(ids.begin(1));
        assert!(!ids.begin(1));
        assert!(ids.end(1));
        assert!(!ids.end(1));
        assert!(ids.schedule_purge(1));
        assert!(!ids.schedule_purge(1));
        assert!(ids.reclaim(1));
        assert!(!ids.reclaim(1));
        assert!(ids.begin(1));
    }

    #[test]
    fn batch_length_makes_progress_and_is_bounded() {
        assert_eq!(vapache_verified::h2_batch_len(0, 1024), 0);
        assert_eq!(vapache_verified::h2_batch_len(512, 1024), 512);
        assert_eq!(vapache_verified::h2_batch_len(2048, 1024), 1024);
        assert!(vapache_verified::h2_batch_len(1, 1) > 0);
    }

    #[test]
    fn positional_read_range_does_not_depend_on_the_file_offset() {
        let dir = std::env::temp_dir().join(format!("vapache-h2-range-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("body.bin");
        fs::write(&path, b"0123456789").unwrap();
        let file = File::open(&path).unwrap();
        let budget = Arc::new(ResourceBudget::default());

        let client = std::net::IpAddr::from([127, 0, 0, 1]);
        let middle = read_range(
            &file,
            3,
            5,
            Arc::new(Mutex::new(
                response_chunk_lease(&budget, client, 5).unwrap(),
            )),
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
        });
        drop(resident);
        let tail = bytes.slice(8..);
        drop(bytes);
        assert_eq!(budget.extended_usage().2, 16);
        drop(tail);
        assert_eq!(budget.extended_usage().2, 0);
    }
}
