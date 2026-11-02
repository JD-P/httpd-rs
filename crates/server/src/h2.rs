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
use crate::util::http_date_now;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, StatusCode};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
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
    _resident: ResidentLease,
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

fn response_chunk_lease(budget: &Arc<ResourceBudget>, len: usize) -> io::Result<ResidentLease> {
    let mut resident = budget.try_response_bytes();
    resident.reserve(len as u64)?;
    Ok(resident)
}

fn read_range(
    file: &std::fs::File,
    offset: u64,
    len: usize,
    resident: ResidentLease,
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

fn declared_content_length(headers: &crate::http::Headers) -> Result<Option<u64>, ()> {
    let mut declared = None;
    for value in headers.get_all("content-length") {
        // A repeated Content-Length is canonicalized into a comma list with
        // the other H2 fields. RFC 9110 permits that representation only when
        // every value is valid and identical.
        for item in value.split(|byte| *byte == b',') {
            let Some(n) = std::str::from_utf8(item)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
            else {
                return Err(());
            };
            if declared.is_some_and(|previous| previous != n) {
                return Err(());
            }
            declared = Some(n);
        }
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
    resource_budget: Arc<crate::resource::ResourceBudget>,
    max_spool_bytes: u64,
    max_spool_files: u64,
    resident: &mut crate::resource::ResidentLease,
) -> Result<H2RequestBody, H2ReadFailure> {
    // HTTP/2 can run many request bodies concurrently on one connection.  A
    // small per-stream prefix keeps ordinary forms cheap while the process-
    // wide spool budget bounds larger concurrent bodies.
    let mut body = BodyAccumulator::new(
        REQUEST_BODY_SPOOL_PREFIX,
        resource_budget,
        max_spool_bytes,
        max_spool_files,
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

// The h2 crate owns these capacity terminal states.  The bounded sender is
// integration-tested for normal, stalled and reset streams; individual error
// variants cannot be constructed through its public API.
// coverage:ignore-start - opaque upstream h2 error variants
fn send_io_error(e: h2::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}
// coverage:ignore-stop

async fn send_capacity(
    send: &mut h2::SendStream<Bytes>,
    remaining: usize,
    deadline: Instant,
) -> io::Result<usize> {
    send.reserve_capacity(remaining);
    loop {
        let now = Instant::now();
        if now >= deadline {
            // coverage:ignore-start - opaque upstream h2 capacity timing
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP/2 send window timeout",
            ));
            // coverage:ignore-stop
        }
        let wait = deadline.saturating_duration_since(now);
        match tokio::time::timeout(wait, std::future::poll_fn(|cx| send.poll_capacity(cx))).await {
            Ok(Some(Ok(n))) if n > 0 => return Ok(n),
            Ok(Some(Ok(_))) => continue, // coverage:ignore-line - h2 never assigns zero
            Ok(Some(Err(e))) => return Err(send_io_error(e)), // coverage:ignore-line - opaque h2 error
            Ok(None) => {
                // coverage:ignore-start - opaque upstream h2 closure state
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "HTTP/2 send stream closed",
                ));
                // coverage:ignore-stop
            }
            Err(_) => {
                // coverage:ignore-start - Tokio deadline terminal state
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP/2 send window timeout",
                ));
                // coverage:ignore-stop
            }
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
    timeout: std::time::Duration,
) -> io::Result<()> {
    if data.is_empty() {
        return send.send_data(data, end).map_err(send_io_error);
    }
    let deadline = Instant::now() + timeout;
    let mut offset = 0usize;
    while offset < data.len() {
        let remaining = data.len() - offset;
        let capacity = send_capacity(send, remaining, deadline).await?;
        let n = capacity.min(remaining);
        let last = end && offset + n == data.len();
        send.send_data(data.slice(offset..offset + n), last)
            .map_err(send_io_error)?;
        offset += n;
    }
    Ok(())
}

async fn send_response(
    mut respond: h2::server::SendResponse<Bytes>,
    cfg: &Config,
    mut resp: Response,
    head_only: bool,
) -> io::Result<u64> {
    if !crate::http::response_headers_admitted(&resp) {
        resp = Response::policy_error();
    }
    if resp.admit_resident(&cfg.resource_budget).is_err() {
        resp = Response::memory_overload();
        resp.admit_resident(&cfg.resource_budget)?;
    }
    let status = StatusCode::from_u16(resp.status)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid response status"))?;
    let no_body = status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || head_only;
    let body_len = resp.body_len();

    let mut out = http::Response::builder().status(status);
    {
        let headers = out.headers_mut().expect("response builder");
        let mut have_date = false;
        let mut have_server = false;
        let mut declared_len = None;
        for (name, value) in resp.headers.drain(..) {
            let lname = name.to_ascii_lowercase();
            match lname.as_str() {
                "date" => have_date = true,
                "server" => have_server = true,
                "content-length" => {
                    declared_len = std::str::from_utf8(&value)
                        .ok()
                        .and_then(|v| v.trim().parse::<u64>().ok());
                    continue;
                }
                // Connection-specific header fields are forbidden in HTTP/2.
                "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding"
                | "upgrade" => continue,
                "te" if !value.eq_ignore_ascii_case(b"trailers") => continue,
                _ => {}
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
        if !no_body || status == StatusCode::OK {
            // HEAD has no body but must advertise the selected
            // representation's length, which the file layer already supplied.
            let cl = if head_only {
                declared_len.unwrap_or(body_len)
            } else {
                body_len
            };
            headers.append(
                HeaderName::from_static("content-length"),
                HeaderValue::from_str(&cl.to_string())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad length"))?,
            );
        }
    }
    let response = out
        .body(())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid response headers"))?;

    let end = no_body || body_len == 0;
    let mut send = respond
        .send_response(response, end)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    if end {
        return Ok(0);
    }
    let send_timeout = cfg.timeout.max(std::time::Duration::from_secs(5));

    let mut sent = 0u64;
    match resp.body {
        Body::Empty => {
            // `end` returned above because Body::Empty has length zero.
            // coverage:ignore-start - body-length invariant
            send_data_bounded(&mut send, Bytes::new(), true, send_timeout).await?;
            // coverage:ignore-stop
        }
        Body::Bytes(data) => {
            sent = data.len() as u64;
            send_data_bounded(&mut send, Bytes::from(data), true, send_timeout).await?;
        }
        Body::Stream { mut reader, len } => {
            let mut left = len;
            while left > 0 {
                let want = left.min(64 * 1024) as usize;
                // Wait for downstream capacity before reading from the
                // upstream. A zero-window client therefore owns neither a
                // response buffer nor a process-wide blocking-read lease.
                let capacity = send_capacity(&mut send, want, Instant::now() + send_timeout)
                    .await?
                    .min(want);
                let resident = response_chunk_lease(&cfg.resource_budget, capacity)?;
                let blocking_read = cfg.resource_budget.try_blocking_read()?;
                let (next_reader, mut buf, resident, result) =
                    tokio::task::spawn_blocking(move || {
                        let _blocking_read = blocking_read;
                        let mut buf = take_body_buffer(capacity);
                        buf.resize(capacity, 0);
                        let result = reader.read(&mut buf[..capacity]);
                        (reader, buf, resident, result)
                    })
                    .await
                    .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
                reader = next_reader;
                let n = result.map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
                if n == 0 {
                    send.send_data(Bytes::new(), true).map_err(send_io_error)?;
                    return Ok(sent);
                }
                buf.truncate(n);
                left -= n as u64;
                sent += n as u64;
                let data = Bytes::from_owner(PooledBuffer {
                    buf: Some(buf),
                    _resident: resident,
                });
                send.send_data(data, left == 0).map_err(send_io_error)?;
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
                let capacity = send_capacity(&mut send, want, Instant::now() + send_timeout)
                    .await?
                    .min(want);
                let resident = response_chunk_lease(&cfg.resource_budget, capacity)?;
                let data = if offload {
                    let blocking_read = cfg.resource_budget.try_blocking_read()?;
                    let (next_file, data) = tokio::task::spawn_blocking(move || {
                        let _blocking_read = blocking_read;
                        let data = read_range(&file, pos, capacity, resident);
                        (file, data)
                    })
                    .await
                    .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
                    file = next_file;
                    data?
                } else {
                    read_range(&file, pos, capacity, resident)?
                };
                let filled = data.len();
                if filled == 0 {
                    send.send_data(Bytes::new(), true).map_err(send_io_error)?;
                    return Ok(sent);
                }
                left -= filled as u64;
                pos = pos.saturating_add(filled as u64);
                sent += filled as u64;
                send.send_data(data, left == 0).map_err(send_io_error)?;
            }
        }
    }
    Ok(sent)
}

async fn handle_stream(
    cfg: Arc<Config>,
    logger: Arc<Logger>,
    peer: SocketAddr,
    local_ip: String,
    local_port: u16,
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) -> bool {
    // The return value is true when the stream was reset (including a
    // timeout that drops the response future).  `serve` projects that event
    // into the verified connection budget.
    let started = Instant::now();
    let (parts, recv) = request.into_parts();
    let method = parts.method.as_str().to_string();
    let uri = parts.uri.clone();
    let Some(target) = request_target(&method, &uri, true) else {
        return send_response(
            respond,
            &cfg,
            bad(400, "invalid HTTP/2 request target"),
            false,
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
    let mut request_resident = cfg.resource_budget.try_request_bytes();
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
        return send_response(
            respond,
            &cfg,
            bad(503, "request memory capacity exhausted"),
            false,
        )
        .await
        .is_err();
    }

    let mut headers = crate::http::Headers::default();
    let mut header_budget =
        vapache_verified::h2_header_init(vapache_verified::h2_settings().max_header_list as u64);
    let mut header_count = 0u64;
    let mut largest_field = 0u64;
    for (name, value) in parts.headers.iter() {
        let field_len = name.as_str().len().saturating_add(value.as_bytes().len()) as u64;
        let Some(next) = vapache_verified::h2_header_add(header_budget, field_len) else {
            let _ = send_response(
                respond,
                &cfg,
                bad(431, "request header list too large"),
                false,
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
            let _ = send_response(
                respond,
                &cfg,
                bad(400, "connection-specific HTTP/2 header"),
                false,
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
            let _ = send_response(
                respond,
                &cfg,
                bad(431, "request header list too large"),
                false,
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
        return send_response(respond, &cfg, resp, false).await.is_err();
    }
    let quota_peer = cfg.client_addr_from_headers(peer, &headers);
    let _client_stream = match cfg.resource_budget.try_h2_client_for(quota_peer.ip()) {
        Ok(lease) => lease,
        Err(_) => {
            return send_response(
                respond,
                &cfg,
                bad(503, "per-client HTTP/2 stream limit reached"),
                false,
            )
            .await
            .is_err();
        }
    };

    let declared = match declared_content_length(&headers) {
        Ok(declared) => declared,
        Err(()) => {
            // h2 validates Content-Length syntax and duplicates before
            // yielding an accepted request.
            // coverage:ignore-start - upstream h2 framing invariant
            return send_response(respond, &cfg, bad(400, "invalid Content-Length"), false)
                .await
                .is_err();
            // coverage:ignore-stop
        }
    };
    let has_body = declared.unwrap_or(0) > 0 || !recv.is_end_stream();
    if has_body && !cfg.body_handlers_possible() {
        let mut response = if matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
            bad(
                400,
                "request body is not accepted by a static-only configuration",
            )
        } else {
            bad(405, "method not allowed for a static resource")
        };
        if response.status == 405 {
            response
                .headers
                .push(("Allow".into(), b"GET, HEAD, OPTIONS".to_vec()));
        }
        return send_response(respond, &cfg, response, false).await.is_err();
    }
    let max_body = cfg.limit_request_body.min(crate::http::MAX_BODY_BUFFERED);
    let body_timeout = cfg
        .request_body_timeout
        .max(std::time::Duration::from_secs(1));
    let body_result = {
        let body_future = read_body(
            recv,
            max_body,
            body_timeout,
            cfg.resource_budget.clone(),
            cfg.max_spool_bytes,
            cfg.max_spool_files,
            &mut request_resident,
        );
        tokio::pin!(body_future);
        // `SendResponse::poll_reset` is the h2 API for a client RST_STREAM
        // before response headers.  Race it against body consumption so a
        // reset that arrives while the body is still open is projected into
        // the connection budget even if no DATA error is surfaced.
        let mut reset_watch = std::future::poll_fn(|cx| respond.poll_reset(cx));
        tokio::select! {
            biased;
            _ = &mut reset_watch => return true,
            result = &mut body_future => result,
        }
    };
    let (body, early) = match body_result {
        Ok(body) => (body, None),
        // The biased `poll_reset` arm above observes this state first.
        Err(H2ReadFailure::Reset) => return true, // coverage:ignore-line - reset-watch invariant
        Err(H2ReadFailure::Response(resp)) => (
            H2RequestBody {
                bytes: Vec::new(),
                spool: None,
                len: 0,
            },
            Some(resp),
        ),
    };
    if let Some(declared) = declared {
        if declared != body.len && early.is_none() {
            // h2 enforces the declared DATA length before clean end-of-stream.
            // coverage:ignore-start - upstream h2 framing invariant
            return send_response(respond, &cfg, bad(400, "Content-Length mismatch"), false)
                .await
                .is_err();
            // coverage:ignore-stop
        }
    }

    headers.hold_resident(request_resident);
    let req = Request {
        method,
        target,
        raw_path,
        query,
        version: Version::Http2,
        headers,
        body: body.bytes,
        body_spool: body.spool,
        keep_alive: true,
        expect_continue: false,
        // HTTP/2 framing is handled by the h2 crate before a `Request` exists.
        framing: crate::verified::BodyFraming::None,
    };
    let peer = cfg.client_addr(peer, &req);
    let (req, resp, remote_user) = match early {
        Some(resp) => (req, resp, None),
        None => match cfg.resource_budget.try_blocking_read() {
            Err(_) => (req, bad(503, "request execution capacity exhausted"), None),
            Ok(dispatch_lease) => {
                // Request dispatch performs blocking filesystem and policy
                // work.  Keep it off the shared async admission/H2 runtime,
                // and bound the blocking pool with the same process-wide
                // lease used by the other blocking I/O paths.
                let dispatch_cfg = cfg.clone();
                let dispatch_local_ip = local_ip.clone();
                let dispatched = tokio::task::spawn_blocking(move || {
                    let _dispatch_lease = dispatch_lease;
                    let result = crate::server::dispatch_with_scheme_and_identity(
                        &dispatch_cfg,
                        &req,
                        peer,
                        &dispatch_local_ip,
                        local_port,
                        true,
                    );
                    (req, result)
                })
                .await;
                let Ok((req, (resp, remote_user))) = dispatched else {
                    logger.error("HTTP/2 request dispatcher task failed");
                    return true;
                };
                (req, resp, remote_user)
            }
        },
    };
    let head_only = req.is_head();
    let status = resp.status;
    let bytes_in = req.target.len() as u64 + req.body_len();
    let body_sent = match send_response(respond, &cfg, resp, head_only).await {
        Ok(n) => n,
        Err(e) => {
            // Peer-close/send failures are already exercised directly by the
            // bounded response sender; this adapter arm only adds logging.
            logger.error(&format!("HTTP/2 stream failed: {e}")); // coverage:ignore-line - peer timing race
            return true; // coverage:ignore-line - peer timing race
        }
    };
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
            _ = tokio::time::sleep(idle_timeout) => {
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
                let process_stream = match cfg.resource_budget.try_h2_stream() {
                    Ok(lease) => lease,
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
                let stream_timeout = cfg.timeout.max(H2_STREAM_FLOOR);
                let tx = events_tx.clone();
                tokio::spawn(async move {
                    let _process_stream = process_stream;
                    let mut done = H2TaskEventGuard {
                        tx,
                        stream_id,
                        reset: true,
                    };
                    done.reset = match tokio::time::timeout(
                        stream_timeout,
                        handle_stream(cfg, logger, peer, local_ip, local_port, request, respond),
                    )
                    .await
                    {
                        Ok(reset) => reset,
                        // Dropping the response future resets the h2 stream.
                        // All adapter awaits have stricter local deadlines;
                        // this remains a final containment guard for scheduler stalls.
                        Err(_) => true, // coverage:ignore-line - outer timeout fallback
                    };
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
                 {}\n",
                dir.display(),
                dir.display(),
                dir.display(),
                extra
            ),
        )
        .unwrap();
        let mut cfg = Config::load(&conf, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        // Most adapter tests exercise body framing independently of route
        // selection. Mark their fixture as body-capable; static-only early
        // rejection has dedicated HTTP/1 and configuration coverage.
        cfg.body_handlers_possible = true;
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
            let handler = handle_stream(
                cfg,
                logger,
                "127.0.0.1:12345".parse().unwrap(),
                "127.0.0.1".into(),
                443,
                request,
                respond,
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
    ) -> (io::Result<u64>, u16, Vec<u8>) {
        let (client_io, server_io) = tokio::io::duplex(32 * 1024 * 1024);
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (_, respond) = connection.accept().await.unwrap().unwrap();
            let sender = send_response(respond, &cfg, response, head_only);
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
        (result, status, body)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_adapter_handles_files_heads_bounds_and_body_errors() {
        let (cfg, logger, dir) = test_config("adapter");
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
            .uri("https://localhost/file.txt")
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
            .uri("https://localhost/file.txt")
            .body(())
            .unwrap();
        assert_eq!(
            round_trip(Arc::new(limited), logger, request, b"too large")
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
            let handler = handle_stream(
                cfg,
                logger,
                "127.0.0.1:12345".parse().unwrap(),
                "127.0.0.1".into(),
                443,
                request,
                respond,
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
            .uri("https://localhost/file.txt")
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
        let (result, status, body) = response_round_trip(cfg.clone(), stream, false).await;
        assert_eq!(result.unwrap(), 11);
        assert_eq!(status, 200);
        assert_eq!(body, b"stream body");

        let mut short_stream = Response::new(200);
        short_stream.body = Body::Stream {
            reader: Box::new(&b""[..]),
            len: 1,
        };
        let (result, _, _) = response_round_trip(cfg.clone(), short_stream, false).await;
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
        let (result, status, body) =
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
        let (result, _, body) = response_round_trip(cfg.clone(), mapped, false).await;
        assert_eq!(result.unwrap(), 300 * 1024);
        assert_eq!(body.len(), 300 * 1024);

        let mut ranged = Response::new(206);
        ranged.body = Body::File {
            file: File::open(&medium_path).unwrap(),
            offset: 1,
            len: 300 * 1024,
        };
        let (result, status, body) = response_round_trip(cfg.clone(), ranged, false).await;
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
        let (result, _, body) = response_round_trip(cfg.clone(), batched, false).await;
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
        let (result, _, _) = response_round_trip(cfg.clone(), empty_large, false).await;
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
            let sender = send_response(respond, &server_cfg, body, false);
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
            let sender = send_response(respond, &server_cfg, body, false);
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
        assert_eq!(declared_content_length(&headers), Ok(None));
        headers.push_merged("content-length", b"7");
        headers.push_merged("content-length", b"7");
        assert_eq!(declared_content_length(&headers), Ok(Some(7)));
        headers.push_merged("content-length", b"8");
        assert_eq!(declared_content_length(&headers), Err(()));
        let mut malformed = crate::http::Headers::default();
        malformed.push("content-length", b"not-a-number".to_vec());
        assert_eq!(declared_content_length(&malformed), Err(()));
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

        let middle = read_range(&file, 3, 5, response_chunk_lease(&budget, 5).unwrap()).unwrap();
        assert_eq!(&middle[..], b"34567");
        let whole = read_range(&file, 0, 10, response_chunk_lease(&budget, 10).unwrap()).unwrap();
        assert_eq!(&whole[..], b"0123456789");
        let short = read_range(&file, 8, 5, response_chunk_lease(&budget, 5).unwrap()).unwrap();
        assert_eq!(&short[..], b"89");

        fs::remove_dir_all(&dir).unwrap();
    }
}
