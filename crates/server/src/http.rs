//! HTTP/1.1 parsing and response serialization.
//!
//! The parser is intentionally strict and linear: no request smuggling via
//! conflicting `Content-Length`/`Transfer-Encoding`, no obs-fold, no
//! whitespace before the colon, bounded header counts and sizes, and an
//! allow-list token check for methods and header names.  These are the
//! parsing rules that httpd's own security advisories keep returning to.

use crate::resource::{ResidentLease, ResourceBudget, SpoolLease};
use crate::util::with_http_date_now;
use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use vapache_verified::{parse_request_head, HeadError, HttpVersion, ParsedHead};

pub use vapache_verified::BodyFraming;

pub const DEFAULT_LIMIT_REQUEST_LINE: usize = 8190;
pub const DEFAULT_LIMIT_REQUEST_FIELDS: usize = 100;
pub const DEFAULT_LIMIT_REQUEST_FIELD_SIZE: usize = 8190;
pub const MAX_HEAD_TOTAL: usize = 131_072;
pub const MAX_BODY_BUFFERED: u64 = 32 * 1024 * 1024;
/// Request bodies above this size are spooled to an unlinked temporary file
/// instead of occupying heap memory for the whole request.
pub const MAX_REQUEST_BODY_IN_MEMORY: u64 = 1024 * 1024;
/// A request already known to require spooling must still provide a
/// meaningful amount of data before it consumes a global file slot. This
/// prevents a large declaration plus one byte from exhausting spool files.
pub(crate) const REQUEST_BODY_SPOOL_PREFIX: u64 = 64 * 1024;
/// Bound request trailers the same way the proxy reader does.
const MAX_REQUEST_TRAILERS: usize = 64;
const MAX_REQUEST_TRAILER_BYTES: usize = 64 * 1024;
/// Bound work that is proportional to HTTP/1 chunk framing rather than to
/// decoded body bytes.  A decoded-size limit alone still permits hundreds of
/// millions of one-byte chunks (the root cause class behind Envoy
/// CVE-2020-8659).  This limit is shared with the proxy response decoder.
const MAX_CHUNKS_PER_MESSAGE: u64 = 65_536;
const MAX_CHUNK_FRAMING_BYTES: u64 = 1024 * 1024;

#[derive(Default)]
pub(crate) struct ChunkFramingBudget {
    chunks: u64,
    bytes: u64,
}

impl ChunkFramingBudget {
    /// Charge a complete chunk-size line and its CRLF.  Data chunks also have
    /// a CRLF after their payload; trailers have their own independent bound.
    pub(crate) fn charge(&mut self, line_len: usize, data_chunk: bool) -> io::Result<()> {
        let line_len = u64::try_from(line_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk framing too large"))?;
        let Some(next) = crate::verified::chunk_framing_budget_step(
            crate::verified::ChunkFramingState {
                chunks: self.chunks,
                bytes: self.bytes,
            },
            line_len,
            data_chunk,
            MAX_CHUNKS_PER_MESSAGE,
            MAX_CHUNK_FRAMING_BYTES,
        ) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk framing budget exceeded",
            ));
        };
        self.chunks = next.chunks;
        self.bytes = next.bytes;
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Version {
    Http10,
    Http11,
    Http2,
}

impl Version {
    pub fn as_str(self) -> &'static str {
        match self {
            Version::Http10 => "HTTP/1.0",
            Version::Http11 => "HTTP/1.1",
            Version::Http2 => "HTTP/2.0",
        }
    }
}

impl From<HttpVersion> for Version {
    fn from(v: HttpVersion) -> Self {
        match v {
            HttpVersion::Http10 => Version::Http10,
            HttpVersion::Http11 => Version::Http11,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Headers {
    entries: Vec<(String, Vec<u8>)>,
    // Clones of a request's headers share the same reservation.  This keeps
    // the charge alive through dispatch without adding a lease field to every
    // synthetic Request initializer in tests and modules.
    resident_lease: Option<std::sync::Arc<ResidentLease>>,
    // Every clone of a request must consume the same policy budget.  Keeping
    // it beside the already-shared header reservation avoids a reset when an
    // internal rewrite or adapter clones `Request`.
    policy_budget: std::sync::Arc<crate::resource::RequestPolicyBudget>,
    // The validated source identity and request-local resource ledger travel
    // with every clone/internal rewrite of this request.
    request_scope: Option<crate::resource::RequestScope>,
    // A body probe executes the ordinary mapping/rewrite/authorization flow
    // but stops before an authorized content handler performs side effects.
    // It lives in the request rather than thread-local state so internal
    // rewrites and cloned requests cannot accidentally escape the probe.
    body_probe: bool,
}

impl Headers {
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }

    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.entries
            .iter()
            .filter(move |(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.entries.iter().any(|(n, _)| n == name)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.entries.iter().map(|(n, v)| (n.as_str(), v.as_slice()))
    }

    pub fn insert(&mut self, name: &str, value: impl Into<Vec<u8>>) {
        let lname = name.to_ascii_lowercase();
        self.entries.retain(|(n, _)| *n != lname);
        self.entries.push((lname, value.into()));
    }

    pub fn remove(&mut self, name: &str) {
        let lname = name.to_ascii_lowercase();
        self.entries.retain(|(n, _)| *n != lname);
    }

    pub fn push(&mut self, name: &str, value: impl Into<Vec<u8>>) {
        self.entries.push((name.to_ascii_lowercase(), value.into()));
    }

    /// Append a field line to the canonical request-header view.  HTTP/2's
    /// decoder preserves repeated field lines, while HTTP/1 collapses them
    /// before constructing `Request`; keeping that difference here lets an
    /// authorization consumer see a different value than CGI/proxy sinks.
    pub(crate) fn push_merged(&mut self, name: &str, value: &[u8]) {
        let lname = name.to_ascii_lowercase();
        if let Some((_, current)) = self.entries.iter_mut().find(|(n, _)| *n == lname) {
            current.extend_from_slice(header_merge_separator(lname.as_bytes()));
            current.extend_from_slice(value);
        } else {
            self.entries.push((lname, value.to_vec()));
        }
    }

    pub(crate) fn hold_resident(&mut self, lease: ResidentLease) {
        self.resident_lease = Some(std::sync::Arc::new(lease));
    }

    pub(crate) fn policy_budget(&self) -> &crate::resource::RequestPolicyBudget {
        &self.policy_budget
    }

    pub(crate) fn bind_request_scope(&mut self, scope: crate::resource::RequestScope) {
        self.policy_budget.bind_context(scope.context().clone());
        self.request_scope = Some(scope);
    }

    pub(crate) fn resource_context(&self) -> Option<&crate::resource::ResourceContext> {
        self.request_scope
            .as_ref()
            .map(crate::resource::RequestScope::context)
    }

    pub(crate) fn request_scope(&self) -> Option<&crate::resource::RequestScope> {
        self.request_scope.as_ref()
    }

    pub(crate) fn set_body_probe(&mut self, enabled: bool) {
        self.body_probe = enabled;
    }

    pub(crate) fn is_body_probe(&self) -> bool {
        self.body_probe
    }
}

fn header_merge_separator(name: &[u8]) -> &'static [u8] {
    // RFC 9113 permits a peer to split Cookie for HPACK efficiency and
    // requires recipients to join those lines with "; ".  Other combinable
    // request fields use the normal comma-list representation.
    if name.eq_ignore_ascii_case(b"cookie") {
        b"; "
    } else {
        b", "
    }
}

#[derive(Debug)]
pub struct SpooledBody {
    file: std::sync::Mutex<File>,
    pub len: u64,
    _lease: Option<SpoolLease>,
}

impl SpooledBody {
    pub(crate) fn from_parts(file: File, len: u64, lease: SpoolLease) -> Self {
        Self {
            file: std::sync::Mutex::new(file),
            len,
            _lease: Some(lease),
        }
    }

    pub fn reader(&self) -> io::Result<File> {
        let file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        let mut clone = file.try_clone()?;
        clone.seek(SeekFrom::Start(0))?;
        Ok(clone)
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(data: &[u8]) -> Self {
        let mut file = spool_file().expect("spool file");
        file.write_all(data).expect("spool write");
        file.seek(SeekFrom::Start(0)).expect("spool seek");
        Self {
            file: std::sync::Mutex::new(file),
            len: data.len() as u64,
            _lease: None,
        }
    }
}

/// Incremental request-body sink shared by HTTP/1 chunked framing and HTTP/2.
/// It retains only a small prefix in memory, obtains a spool-file slot only
/// when real body bytes cross that threshold, and charges the aggregate spool
/// budget for bytes actually written rather than for an untrusted declaration.
pub(crate) struct BodyAccumulator {
    body: Vec<u8>,
    file: Option<File>,
    lease: Option<SpoolLease>,
    len: u64,
    memory_limit: u64,
    resource_budget: std::sync::Arc<ResourceBudget>,
    max_spool_bytes: u64,
    max_spool_files: u64,
    resource_context: Option<crate::resource::ResourceContext>,
}

impl BodyAccumulator {
    pub(crate) fn new(
        memory_limit: u64,
        resource_budget: std::sync::Arc<ResourceBudget>,
        max_spool_bytes: u64,
        max_spool_files: u64,
    ) -> Self {
        Self::new_for(
            memory_limit,
            resource_budget,
            max_spool_bytes,
            max_spool_files,
            None,
        )
    }

    pub(crate) fn new_for(
        memory_limit: u64,
        resource_budget: std::sync::Arc<ResourceBudget>,
        max_spool_bytes: u64,
        max_spool_files: u64,
        client: Option<std::net::IpAddr>,
    ) -> Self {
        let context = client.map(|client| resource_budget.context(client));
        Self::new_in(
            memory_limit,
            resource_budget,
            max_spool_bytes,
            max_spool_files,
            context,
        )
    }

    pub(crate) fn new_in(
        memory_limit: u64,
        resource_budget: std::sync::Arc<ResourceBudget>,
        max_spool_bytes: u64,
        max_spool_files: u64,
        resource_context: Option<crate::resource::ResourceContext>,
    ) -> Self {
        Self {
            body: Vec::new(),
            file: None,
            lease: None,
            len: 0,
            memory_limit,
            resource_budget,
            max_spool_bytes,
            max_spool_files,
            resource_context,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.push_inner(bytes, None)
    }

    /// Reserve resident memory before extending the in-memory prefix.  Bytes
    /// written to the bounded spool file do not consume resident capacity.
    pub(crate) fn push_with_resident(
        &mut self,
        bytes: &[u8],
        resident: &mut ResidentLease,
    ) -> io::Result<()> {
        self.push_inner(bytes, Some(resident))
    }

    fn push_inner(&mut self, bytes: &[u8], resident: Option<&mut ResidentLease>) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let add = bytes.len() as u64;
        let next = self
            .len
            .checked_add(add)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "request body overflow"))?;
        if self.file.is_none()
            && vapache_verified::request_body_memory_admit(self.len, add, self.memory_limit)
        {
            if let Some(resident) = resident {
                resident.reserve(add)?;
            }
            self.body.extend_from_slice(bytes);
            self.len = next;
            return Ok(());
        }
        if self.file.is_none() {
            let mut lease = match self.resource_context.as_ref() {
                Some(context) => self.resource_budget.try_spool_in(
                    self.max_spool_bytes,
                    self.max_spool_files,
                    context,
                )?,
                None => self
                    .resource_budget
                    .try_spool(self.max_spool_bytes, self.max_spool_files)?,
            };
            // Once the in-memory prefix moves to disk it becomes part of the
            // spool budget too.  Reserve before writing so failure is atomic.
            lease.reserve(next)?;
            let mut file = spool_file()?;
            file.write_all(&self.body)?;
            file.write_all(bytes)?;
            self.body.clear();
            self.file = Some(file);
            self.lease = Some(lease);
        } else {
            self.lease
                .as_mut()
                .expect("spooled body owns its resource lease")
                .reserve(add)?;
            self.file
                .as_mut()
                .expect("spooled body owns its file")
                .write_all(bytes)?;
        }
        self.len = next;
        Ok(())
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn finish(mut self) -> (Vec<u8>, Option<std::sync::Arc<SpooledBody>>) {
        match (self.file.take(), self.lease.take()) {
            (Some(file), Some(lease)) => (
                Vec::new(),
                Some(std::sync::Arc::new(SpooledBody::from_parts(
                    file, self.len, lease,
                ))),
            ),
            (None, None) => (std::mem::take(&mut self.body), None),
            _ => unreachable!("spool file and lease are created together"),
        }
    }
}

struct ResidentBodyWriter<'a> {
    body: &'a mut BodyAccumulator,
    resident: &'a mut ResidentLease,
}

impl Write for ResidentBodyWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.body.push_with_resident(bytes, self.resident)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for BodyAccumulator {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.push(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = &mut self.file {
            file.flush()
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub target: Vec<u8>,
    /// Raw path bytes (still percent-encoded), without the query string.
    pub raw_path: Vec<u8>,
    pub query: Vec<u8>,
    pub version: Version,
    pub headers: Headers,
    pub body: Vec<u8>,
    /// Bodies above the in-memory threshold are spooled here.  The file is
    /// unlinked immediately and shared by clones of the request.
    pub body_spool: Option<std::sync::Arc<SpooledBody>>,
    pub keep_alive: bool,
    pub expect_continue: bool,
    /// Body framing proved by the verified request-head parser.
    pub framing: BodyFraming,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers.get(name)
    }

    pub fn header_str(&self, name: &str) -> Option<&str> {
        self.header(name).and_then(|v| std::str::from_utf8(v).ok())
    }

    pub fn is_head(&self) -> bool {
        self.method == "HEAD"
    }

    pub fn body_len(&self) -> u64 {
        self.body_spool
            .as_ref()
            .map(|b| b.len)
            .unwrap_or(self.body.len() as u64)
    }

    pub fn body_reader(&self) -> Option<io::Result<File>> {
        self.body_spool.as_ref().map(|b| b.reader())
    }

    pub(crate) fn charge_policy_work(&self, amount: u64) -> Result<(), &'static str> {
        self.headers.policy_budget().charge_work(amount)
    }

    pub(crate) fn charge_policy_expansion(&self, amount: u64) -> Result<(), &'static str> {
        self.headers.policy_budget().charge_expansion(amount)
    }

    pub(crate) fn policy_budget_failed(&self) -> bool {
        self.headers.policy_budget().failed()
    }

    pub(crate) fn policy_budget(&self) -> &crate::resource::RequestPolicyBudget {
        self.headers.policy_budget()
    }

    pub(crate) fn resource_context(&self) -> Option<&crate::resource::ResourceContext> {
        self.headers.resource_context()
    }

    pub(crate) fn request_scope(&self) -> Option<&crate::resource::RequestScope> {
        self.headers.request_scope()
    }

    pub(crate) fn body_probe(&self) -> bool {
        self.headers.is_body_probe()
    }

    pub(crate) fn set_body_probe(&mut self, enabled: bool) {
        self.headers.set_body_probe(enabled);
    }
}

#[derive(Debug)]
pub enum ParseError {
    BadRequest(&'static str),
    UriTooLong,
    HeadersTooLarge,
    TooManyHeaders,
    VersionNotSupported,
    PayloadTooLarge,
    MethodNotAllowed,
    LengthRequired,
    NotImplemented(&'static str),
}

impl ParseError {
    pub fn status(&self) -> u16 {
        match self {
            ParseError::BadRequest(_) => 400,
            ParseError::UriTooLong => 414,
            ParseError::HeadersTooLarge | ParseError::TooManyHeaders => 431,
            ParseError::VersionNotSupported => 505,
            ParseError::PayloadTooLarge => 413,
            ParseError::MethodNotAllowed => 405,
            ParseError::LengthRequired => 411,
            ParseError::NotImplemented(_) => 501,
        }
    }

    pub fn message(&self) -> String {
        match self {
            ParseError::BadRequest(m) => format!("Bad request: {m}"),
            ParseError::UriTooLong => "Request-URI Too Long".into(),
            ParseError::HeadersTooLarge => "Request Header Fields Too Large".into(),
            ParseError::TooManyHeaders => "Too Many Request Header Fields".into(),
            ParseError::VersionNotSupported => "HTTP Version Not Supported".into(),
            ParseError::PayloadTooLarge => "Request Entity Too Large".into(),
            ParseError::MethodNotAllowed => "Method Not Allowed".into(),
            ParseError::LengthRequired => "Length Required".into(),
            ParseError::NotImplemented(m) => format!("Not implemented: {m}"),
        }
    }
}

#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    Parse(ParseError),
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        ReadError::Io(e)
    }
}

impl From<ParseError> for ReadError {
    fn from(e: ParseError) -> Self {
        ReadError::Parse(e)
    }
}

pub struct Limits {
    pub request_line: usize,
    pub fields: usize,
    pub field_size: usize,
    pub body: u64,
    pub header_timeout: Duration,
    pub body_timeout: Duration,
    pub header_min_rate: u64,
    pub body_min_rate: u64,
    pub resource_budget: std::sync::Arc<ResourceBudget>,
    pub max_spool_bytes: u64,
    pub max_spool_files: u64,
    /// Transport identity used to validate absolute-form request targets.
    pub https: bool,
    pub allow_absolute_request_target: bool,
    pub allow_request_trailers: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            request_line: DEFAULT_LIMIT_REQUEST_LINE,
            fields: DEFAULT_LIMIT_REQUEST_FIELDS,
            field_size: DEFAULT_LIMIT_REQUEST_FIELD_SIZE,
            body: MAX_BODY_BUFFERED,
            header_timeout: Duration::from_secs(20),
            body_timeout: Duration::from_secs(30),
            header_min_rate: 0,
            body_min_rate: 0,
            resource_budget: std::sync::Arc::new(ResourceBudget::default()),
            max_spool_bytes: 1024 * 1024 * 1024,
            max_spool_files: 128,
            https: false,
            allow_absolute_request_target: false,
            allow_request_trailers: false,
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    // Strict CRLF CRLF.  Bare-LF tolerance is intentionally not provided:
    // split-parser differentials are a recurring smuggling vector.
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn absolute_target_authority(target: &[u8]) -> Option<(bool, &[u8])> {
    let (tls, start) = if target.starts_with(b"http://") {
        (false, 7)
    } else if target.starts_with(b"https://") {
        (true, 8)
    } else {
        return None;
    };
    let end = target[start..]
        .iter()
        .position(|byte| *byte == b'/')
        .map(|offset| start + offset)
        .unwrap_or(target.len());
    Some((tls, &target[start..end]))
}

fn validate_request_authority(req: &mut Request, limits: &Limits) -> Result<(), ParseError> {
    let transport_default = if limits.https { 443 } else { 80 };
    let parsed_host = match req.header("host") {
        Some(host) => Some(
            crate::util::parse_http_authority(host, transport_default)
                .ok_or(ParseError::BadRequest("invalid Host header"))?,
        ),
        None => None,
    };
    let Some((target_tls, authority)) = absolute_target_authority(&req.target) else {
        return Ok(());
    };
    if !vapache_verified::capability_admit(limits.allow_absolute_request_target, true) {
        return Err(ParseError::BadRequest(
            "absolute-form request target is disabled",
        ));
    }
    let target_default = if target_tls { 443 } else { 80 };
    let (target_host, target_port) =
        crate::util::parse_http_authority(authority, target_default)
            .ok_or(ParseError::BadRequest("invalid absolute URI authority"))?;
    if target_tls != limits.https {
        return Err(ParseError::BadRequest(
            "absolute URI scheme does not match the connection",
        ));
    }
    if let Some((host, port)) = parsed_host {
        if !vapache_verified::authority_endpoint_equal(
            target_host.as_bytes(),
            target_port,
            target_tls,
            host.as_bytes(),
            port,
            limits.https,
        ) {
            return Err(ParseError::BadRequest(
                "absolute URI authority does not match Host",
            ));
        }
    } else {
        // HTTP/1.0 did not require Host.  Once absolute-form is explicitly
        // enabled, expose its authoritative identity to vhost/cache/policy
        // consumers instead of silently falling back to the default vhost.
        req.headers.push("host", authority.to_vec());
    }
    Ok(())
}

pub(crate) fn minimum_read_rate_ok(started: Instant, bytes: u64, min_rate: u64) -> bool {
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    vapache_verified::minimum_progress_rate_admit(bytes, elapsed_ms, min_rate, 1_000)
}

/// Read one complete request from a keep-alive connection.
///
/// `buf` is a per-connection buffer; any bytes belonging to the next pipelined
/// request remain in it.  Returns `Ok(None)` on a clean EOF between requests.
pub fn read_request<R: Read + Write>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    limits: &Limits,
    on_headers: impl FnOnce(&mut R),
) -> Result<Option<Request>, ReadError> {
    read_request_with_reservation(
        stream,
        buf,
        limits,
        |stream, _request| {
            on_headers(stream);
            Ok(None)
        },
        None,
    )
}

/// Continue parsing a head already read and charged by asynchronous
/// connection admission.  The reservation is transferred into the returned
/// request, so the raw head, parser copies and body all remain covered by one
/// process-wide resident-byte lease without double-charging the prefix.
pub(crate) struct ParsedRequestHead {
    request: Request,
    resident: ResidentLease,
}

impl ParsedRequestHead {
    pub(crate) fn request(&self) -> &Request {
        &self.request
    }

    pub(crate) fn request_mut(&mut self) -> &mut Request {
        &mut self.request
    }

    pub(crate) fn into_parts(self) -> (Request, ResidentLease) {
        (self.request, self.resident)
    }

    pub(crate) fn finish_without_body(mut self) -> Request {
        self.request.headers.hold_resident(self.resident);
        self.request
    }
}

/// Parse and authorize one complete request head without consuming any body
/// bytes or emitting `100 Continue`. The returned object owns the request's
/// resident reservation until a later body or no-body phase takes ownership.
pub(crate) fn read_request_head_with_reservation<R: Read + Write>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    limits: &Limits,
    on_headers: impl FnOnce(
        &mut R,
        &Request,
    ) -> Result<Option<crate::resource::ResourceContext>, ReadError>,
    reservation: Option<ResidentLease>,
) -> Result<Option<ParsedRequestHead>, ReadError> {
    let prefix_precharged = reservation.is_some();
    let mut request_resident = match reservation {
        Some(reservation) => reservation,
        None => limits.resource_budget.try_request_bytes()?,
    };
    // Pipelined bytes left by the previous request remain resident while this
    // request is dispatched, so they enter the new request's reservation.
    if !prefix_precharged {
        request_resident.reserve(buf.len() as u64)?;
    }
    let header_started = Instant::now();
    let head_end = loop {
        if let Some(end) = find_head_end(buf) {
            break end;
        }
        if buf.len() > MAX_HEAD_TOTAL {
            return Err(ReadError::Parse(ParseError::HeadersTooLarge));
        }
        let elapsed = header_started.elapsed();
        // `header_timeout` is the configured range maximum.  Never derive an
        // absolute connection lifetime from attacker-controlled byte counts.
        // MinRate is enforced independently inside that hard ceiling.
        let allowed = limits.header_timeout;
        if elapsed > allowed {
            return Err(ReadError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "request header timeout",
            )));
        }
        let mut chunk = [0u8; 8192];
        let read = crate::fault::hit("http.head.read").and_then(|()| stream.read(&mut chunk));
        match read {
            Ok(0) => {
                if buf.is_empty() {
                    return Ok(None);
                }
                return Err(ReadError::Parse(ParseError::BadRequest(
                    "unexpected EOF in request headers",
                )));
            }
            Ok(n) => {
                request_resident.reserve(n as u64)?;
                buf.extend_from_slice(&chunk[..n]);
                if !minimum_read_rate_ok(header_started, buf.len() as u64, limits.header_min_rate) {
                    return Err(ReadError::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "request header minimum rate not met",
                    )));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ReadError::Io(e)),
        }
        if buf.len() > MAX_HEAD_TOTAL {
            return Err(ReadError::Parse(ParseError::HeadersTooLarge));
        }
    };

    // Charge before the verified parser creates owned copies of the target
    // and headers.  The factor of two conservatively covers both the retained
    // connection bytes and the owned representation during parsing.
    if !prefix_precharged {
        request_resident.reserve(head_end as u64)?;
    }

    // Parse directly from the connection buffer; the verified parser returns
    // owned request fields and does not retain a borrow of the head.
    let mut req = parse_head(&buf[..head_end], limits)?;
    validate_request_authority(&mut req, limits)?;
    buf.drain(..head_end);

    // Admission that depends on parsed framing (for example the process-wide
    // slow-body reserve) must happen after the complete head is validated but
    // before a 100 response or any body byte is consumed.
    let resource_context = on_headers(stream, &req)?;
    if let Some(context) = resource_context {
        request_resident.attribute_context(context.clone())?;
        req.headers
            .bind_request_scope(crate::resource::RequestScope::new(context));
    }

    if let BodyFraming::Length(length) = req.framing {
        if length > limits.body {
            return Err(ReadError::Parse(ParseError::PayloadTooLarge));
        }
    }

    Ok(Some(ParsedRequestHead {
        request: req,
        resident: request_resident,
    }))
}

pub(crate) fn read_request_body<R: Read + Write>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    limits: &Limits,
    head: ParsedRequestHead,
) -> Result<Request, ReadError> {
    let (mut req, mut request_resident) = head.into_parts();
    let framing = req.framing;
    let spool_context = req.resource_context().cloned();

    if req.expect_continue && framing != BodyFraming::None {
        // The client is waiting for this before sending the body.
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        stream.flush()?;
    }

    match framing {
        BodyFraming::None => {}
        BodyFraming::Length(n) => {
            // This is an absolute deadline.  Deriving it from an untrusted
            // Content-Length let a huge declaration extend a worker lease for
            // hours even when the peer sent no body bytes.
            let body_deadline = Instant::now() + limits.body_timeout;
            let body_started = Instant::now();
            if n > MAX_REQUEST_BODY_IN_MEMORY {
                // A known-large body spills after a small actual-byte prefix.
                // A declaration plus a token byte therefore holds neither a
                // spool slot nor a declared-length byte reservation.
                let mut body = BodyAccumulator::new_in(
                    REQUEST_BODY_SPOOL_PREFIX,
                    limits.resource_budget.clone(),
                    limits.max_spool_bytes,
                    limits.max_spool_files,
                    spool_context.clone(),
                );
                let take = (n as usize).min(buf.len());
                body.push_with_resident(&buf[..take], &mut request_resident)?;
                buf.drain(..take);
                let mut remaining = n - take as u64;
                let mut chunk = vec![0u8; 64 * 1024];
                while remaining > 0 {
                    if Instant::now() > body_deadline {
                        return Err(ReadError::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "request body timeout",
                        )));
                    }
                    let want = remaining.min(chunk.len() as u64) as usize;
                    crate::fault::hit("http.body.read")?;
                    let got = stream.read(&mut chunk[..want])?;
                    if got == 0 {
                        return Err(ReadError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF in request body",
                        )));
                    }
                    body.push_with_resident(&chunk[..got], &mut request_resident)?;
                    remaining -= got as u64;
                    if !minimum_read_rate_ok(
                        body_started,
                        n.saturating_sub(remaining),
                        limits.body_min_rate,
                    ) {
                        return Err(ReadError::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "request body minimum rate not met",
                        )));
                    }
                }
                let (bytes, spool) = body.finish();
                req.body = bytes;
                req.body_spool = spool;
            } else {
                read_exact_into(
                    stream,
                    buf,
                    &mut req.body,
                    n,
                    body_deadline,
                    limits.body_min_rate,
                    &mut request_resident,
                )?;
            }
        }
        BodyFraming::Chunked => {
            let mut body = BodyAccumulator::new_in(
                REQUEST_BODY_SPOOL_PREFIX,
                limits.resource_budget.clone(),
                limits.max_spool_bytes,
                limits.max_spool_files,
                spool_context,
            );
            let chunk_deadline = Instant::now() + limits.body_timeout;
            let mut writer = ResidentBodyWriter {
                body: &mut body,
                resident: &mut request_resident,
            };
            let len = read_chunked_to_writer_budgeted(
                stream,
                buf,
                &mut writer,
                limits.body,
                chunk_deadline,
                None,
                limits.allow_request_trailers,
                limits.body_min_rate,
            )
            .map_err(|error| {
                if error.kind() == io::ErrorKind::PermissionDenied {
                    ReadError::Parse(ParseError::BadRequest("request trailers are disabled"))
                } else {
                    ReadError::Io(error)
                }
            })?;
            debug_assert_eq!(len, body.len());
            let (bytes, spool) = body.finish();
            req.body = bytes;
            req.body_spool = spool;
        }
    }
    req.headers.hold_resident(request_resident);
    Ok(req)
}

fn push_body_without_blocking_runtime(
    body: &mut BodyAccumulator,
    resident: &mut ResidentLease,
    bytes: &[u8],
) -> io::Result<()> {
    if matches!(
        tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()),
        Ok(tokio::runtime::RuntimeFlavor::MultiThread)
    ) {
        tokio::task::block_in_place(|| body.push_with_resident(bytes, resident))
    } else {
        body.push_with_resident(bytes, resident)
    }
}

async fn async_read_with_deadline<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<usize> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "request body timeout"))?;
    tokio::time::timeout(remaining, tokio::io::AsyncReadExt::read(stream, bytes))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request body timeout"))?
}

async fn async_read_line_until<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    max: usize,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    loop {
        if let Some(position) = buf.windows(2).position(|window| window == b"\r\n") {
            if position > max {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            let line = buf[..position].to_vec();
            buf.drain(..position + 2);
            return Ok(line);
        }
        if buf.len() > max.saturating_add(2) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        let mut chunk = [0u8; 8 * 1024];
        crate::fault::hit("http.chunk.line")?;
        let read = async_read_with_deadline(stream, &mut chunk, deadline).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF in chunked body",
            ));
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

/// Consume a body after the route and authorization probe has selected a
/// handler that actually needs it. Socket waits are asynchronous; bounded
/// spool-file writes temporarily leave the runtime worker through
/// `block_in_place` and remain protected by the body/spool leases.
pub(crate) async fn read_request_body_async<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    limits: &Limits,
    head: ParsedRequestHead,
) -> Result<Request, ReadError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut req, mut request_resident) = head.into_parts();
    let framing = req.framing;
    let context = req.resource_context().cloned();
    let scope = req.request_scope().cloned();
    let deadline = Instant::now()
        .checked_add(limits.body_timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "request body timeout"))?;
    let started = Instant::now();

    if req.expect_continue && framing != BodyFraming::None {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "request body timeout"))?;
        tokio::time::timeout(remaining, async {
            tokio::io::AsyncWriteExt::write_all(stream, b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            tokio::io::AsyncWriteExt::flush(stream).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request body timeout"))??;
    }

    let memory_limit = match framing {
        BodyFraming::Length(length) if length <= MAX_REQUEST_BODY_IN_MEMORY => {
            MAX_REQUEST_BODY_IN_MEMORY
        }
        BodyFraming::None => MAX_REQUEST_BODY_IN_MEMORY,
        BodyFraming::Length(_) | BodyFraming::Chunked => REQUEST_BODY_SPOOL_PREFIX,
    };
    let mut body = BodyAccumulator::new_in(
        memory_limit,
        limits.resource_budget.clone(),
        limits.max_spool_bytes,
        limits.max_spool_files,
        context,
    );

    match framing {
        BodyFraming::None => {}
        BodyFraming::Length(length) => {
            let take = usize::try_from(length.min(buf.len() as u64)).unwrap_or(buf.len());
            push_body_without_blocking_runtime(&mut body, &mut request_resident, &buf[..take])?;
            buf.drain(..take);
            let mut remaining = length.saturating_sub(take as u64);
            let mut chunk = vec![0u8; 64 * 1024];
            while remaining > 0 {
                if scope.as_ref().is_some_and(|scope| scope.is_cancelled()) {
                    return Err(ReadError::Io(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "request scope cancelled",
                    )));
                }
                let want = remaining.min(chunk.len() as u64) as usize;
                crate::fault::hit("http.body.read")?;
                let read = async_read_with_deadline(stream, &mut chunk[..want], deadline).await?;
                if read == 0 {
                    return Err(ReadError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF in request body",
                    )));
                }
                push_body_without_blocking_runtime(
                    &mut body,
                    &mut request_resident,
                    &chunk[..read],
                )?;
                remaining -= read as u64;
                if !minimum_read_rate_ok(
                    started,
                    length.saturating_sub(remaining),
                    limits.body_min_rate,
                ) {
                    return Err(ReadError::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "request body minimum rate not met",
                    )));
                }
            }
        }
        BodyFraming::Chunked => {
            let mut total = 0u64;
            let mut framing_budget = ChunkFramingBudget::default();
            loop {
                if scope.as_ref().is_some_and(|scope| scope.is_cancelled()) {
                    return Err(ReadError::Io(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "request scope cancelled",
                    )));
                }
                let line = async_read_line_until(stream, buf, 1024, deadline).await?;
                let size = parse_chunk_size_line(&line)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
                framing_budget.charge(line.len(), size != 0)?;
                if size == 0 {
                    let mut trailer_count = 0usize;
                    let mut trailer_bytes = 0usize;
                    loop {
                        let trailer = async_read_line_until(stream, buf, 8190, deadline).await?;
                        if trailer.is_empty() {
                            break;
                        }
                        if !vapache_verified::capability_admit(limits.allow_request_trailers, true)
                        {
                            return Err(ReadError::Parse(ParseError::BadRequest(
                                "request trailers are disabled",
                            )));
                        }
                        if !valid_trailer_field(&trailer) {
                            return Err(ReadError::Parse(ParseError::BadRequest(
                                "invalid request trailer",
                            )));
                        }
                        trailer_count += 1;
                        trailer_bytes = trailer_bytes.saturating_add(trailer.len() + 2);
                        if trailer_count > MAX_REQUEST_TRAILERS
                            || trailer_bytes > MAX_REQUEST_TRAILER_BYTES
                        {
                            return Err(ReadError::Parse(ParseError::BadRequest(
                                "request trailers are too large",
                            )));
                        }
                    }
                    break;
                }
                if total.saturating_add(size) > limits.body {
                    return Err(ReadError::Parse(ParseError::PayloadTooLarge));
                }
                let mut remaining = size;
                while remaining > 0 {
                    if !buf.is_empty() {
                        let take =
                            usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
                        push_body_without_blocking_runtime(
                            &mut body,
                            &mut request_resident,
                            &buf[..take],
                        )?;
                        buf.drain(..take);
                        remaining -= take as u64;
                        total += take as u64;
                    } else {
                        let mut chunk = [0u8; 8 * 1024];
                        let want = usize::try_from(remaining.min(chunk.len() as u64))
                            .unwrap_or(chunk.len());
                        crate::fault::hit("http.chunk.read")?;
                        let read =
                            async_read_with_deadline(stream, &mut chunk[..want], deadline).await?;
                        if read == 0 {
                            return Err(ReadError::Io(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF in chunked body",
                            )));
                        }
                        push_body_without_blocking_runtime(
                            &mut body,
                            &mut request_resident,
                            &chunk[..read],
                        )?;
                        remaining -= read as u64;
                        total += read as u64;
                    }
                    if !minimum_read_rate_ok(started, total, limits.body_min_rate) {
                        return Err(ReadError::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "request body minimum rate not met",
                        )));
                    }
                }
                while buf.len() < 2 {
                    let mut crlf = [0u8; 2];
                    let read = async_read_with_deadline(stream, &mut crlf, deadline).await?;
                    if read == 0 {
                        return Err(ReadError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF after chunk data",
                        )));
                    }
                    buf.extend_from_slice(&crlf[..read]);
                }
                if &buf[..2] != b"\r\n" {
                    return Err(ReadError::Parse(ParseError::BadRequest("bad chunk CRLF")));
                }
                buf.drain(..2);
            }
        }
    }

    let (bytes, spool) = body.finish();
    req.body = bytes;
    req.body_spool = spool;
    req.headers.hold_resident(request_resident);
    Ok(req)
}

pub(crate) fn read_request_with_reservation<R: Read + Write>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    limits: &Limits,
    on_headers: impl FnOnce(
        &mut R,
        &Request,
    ) -> Result<Option<crate::resource::ResourceContext>, ReadError>,
    reservation: Option<ResidentLease>,
) -> Result<Option<Request>, ReadError> {
    let Some(head) =
        read_request_head_with_reservation(stream, buf, limits, on_headers, reservation)?
    else {
        return Ok(None);
    };
    read_request_body(stream, buf, limits, head).map(Some)
}

const SPOOL_ATTEMPTS: u64 = 16;

fn spool_path(dir: &Path, counter: u64) -> PathBuf {
    dir.join(format!(
        "vapache-request-{}-{}.body",
        std::process::id(),
        counter
    ))
}

/// Create an unlinked, private spool file.  `O_EXCL` matters: a predictable
/// name in a shared temporary directory must never follow a pre-created
/// symlink (which could truncate or expose a file the server can reach).  A
/// colliding name is skipped rather than followed, and a bounded number of
/// collisions fails closed.
fn spool_file_named(dir: &Path, counter: &std::sync::atomic::AtomicU64) -> io::Result<File> {
    use std::sync::atomic::Ordering;
    for _ in 0..SPOOL_ATTEMPTS {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        let path = spool_path(dir, n);
        match OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                let _ = std::fs::remove_file(&path);
                return Ok(file);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cannot create a private request spool file",
    ))
}

pub(crate) fn spool_file() -> io::Result<File> {
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    spool_file_named(&std::env::temp_dir(), &COUNTER)
}

fn read_exact_into<R: Read>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    out: &mut Vec<u8>,
    n: u64,
    deadline: Instant,
    min_rate: u64,
    resident: &mut ResidentLease,
) -> io::Result<()> {
    let started = Instant::now();
    let n = n as usize;
    let take = n.min(buf.len());
    resident.reserve(take as u64)?;
    out.extend_from_slice(&buf[..take]);
    buf.drain(..take);
    let mut remaining = n - take;
    let mut chunk = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let elapsed = deadline.saturating_duration_since(Instant::now());
        if elapsed.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request body timeout",
            ));
        }
        let want = remaining.min(chunk.len());
        crate::fault::hit("http.body.read")?;
        let got = stream.read(&mut chunk[..want])?;
        if got == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF in request body",
            ));
        }
        // Charge the owned body only after bytes arrive. A Content-Length is
        // framing metadata, not evidence that the peer has supplied memory
        // worth reserving process-wide.
        resident.reserve(got as u64)?;
        out.extend_from_slice(&chunk[..got]);
        remaining -= got;
        if !minimum_read_rate_ok(started, (n - remaining) as u64, min_rate) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request body minimum rate not met",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn read_chunked_to_file<R: Read>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    file: &mut File,
    max: u64,
    deadline: Instant,
) -> io::Result<u64> {
    read_chunked_to_file_budgeted(stream, buf, file, max, deadline, None, true)
}

#[cfg(test)]
fn read_chunked_to_file_budgeted<R: Read>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    file: &mut File,
    max: u64,
    deadline: Instant,
    lease: Option<&mut SpoolLease>,
    allow_trailers: bool,
) -> io::Result<u64> {
    read_chunked_to_writer_budgeted(stream, buf, file, max, deadline, lease, allow_trailers, 0)
}

/// Parse one RFC 9112 chunk-size line, including the complete chunk-extension
/// grammar.  Ignoring everything after the first semicolon makes invalid
/// extensions look valid to this server while a front proxy may reject or
/// delimit them differently—the primitive behind CVE-2026-24880.
pub(crate) fn parse_chunk_size_line(line: &[u8]) -> Option<u64> {
    let mut index = 0usize;
    while index < line.len() && line[index].is_ascii_hexdigit() {
        index += 1;
    }
    let size = crate::verified::parse_chunk_size_hex(&line[..index])?;
    crate::verified::chunk_extension_admit(&line[index..]).then_some(size)
}

pub(crate) fn valid_trailer_field(line: &[u8]) -> bool {
    crate::verified::http_trailer_field_admit(line)
}

fn read_chunked_to_writer_budgeted<R: Read, W: Write>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    writer: &mut W,
    max: u64,
    deadline: Instant,
    mut lease: Option<&mut SpoolLease>,
    allow_trailers: bool,
    min_rate: u64,
) -> io::Result<u64> {
    let started = Instant::now();
    let mut total = 0u64;
    let mut framing_budget = ChunkFramingBudget::default();
    loop {
        if Instant::now() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request body timeout",
            ));
        }
        let line = read_line_until(stream, buf, 1024, Some(deadline))?;
        let size = parse_chunk_size_line(&line)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
        framing_budget.charge(line.len(), size != 0)?;
        if size == 0 {
            // Trailer fields are part of the request body deadline.  Without
            // an explicit check a client can send a zero-size chunk and then
            // keep one worker busy with trailer lines indefinitely.
            let mut trailer_count = 0usize;
            let mut trailer_bytes = 0usize;
            loop {
                if Instant::now() > deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "request body timeout",
                    ));
                }
                let t = read_line_until(stream, buf, 8190, Some(deadline))?;
                if t.is_empty() {
                    return Ok(total);
                }
                if !vapache_verified::capability_admit(allow_trailers, true) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "request trailers are disabled",
                    ));
                }
                if !valid_trailer_field(&t) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid request trailer",
                    ));
                }
                trailer_count += 1;
                trailer_bytes = trailer_bytes.saturating_add(t.len() + 2);
                if trailer_count > MAX_REQUEST_TRAILERS || trailer_bytes > MAX_REQUEST_TRAILER_BYTES
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request trailers too large",
                    ));
                }
            }
        }
        if total.saturating_add(size) > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked body too large",
            ));
        }
        let size_usize = usize::try_from(size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk too large"))?;
        let mut remaining = size_usize;
        while remaining > 0 {
            if Instant::now() > deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "request body timeout",
                ));
            }
            if !buf.is_empty() {
                let take = remaining.min(buf.len());
                if let Some(lease) = lease.as_deref_mut() {
                    lease.reserve(take as u64)?;
                }
                writer.write_all(&buf[..take])?;
                buf.drain(..take);
                remaining -= take;
                total += take as u64;
                if !minimum_read_rate_ok(started, total, min_rate) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "request body minimum rate not met",
                    ));
                }
            } else {
                let mut chunk = [0u8; 8192];
                let want = remaining.min(chunk.len());
                crate::fault::hit("http.chunk.read")?;
                let got = stream.read(&mut chunk[..want])?;
                if got == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF in chunked body",
                    ));
                }
                if let Some(lease) = lease.as_deref_mut() {
                    lease.reserve(got as u64)?;
                }
                writer.write_all(&chunk[..got])?;
                remaining -= got;
                total += got as u64;
                if !minimum_read_rate_ok(started, total, min_rate) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "request body minimum rate not met",
                    ));
                }
            }
        }
        let mut crlf = [0u8; 2];
        let buffered = buf.len().min(2);
        crlf[..buffered].copy_from_slice(&buf[..buffered]);
        buf.drain(..buffered);
        if buffered < 2 {
            stream.read_exact(&mut crlf[buffered..])?;
        }
        if crlf != *b"\r\n" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad chunk crlf"));
        }
    }
}

#[cfg(test)]
fn read_line<R: Read>(stream: &mut R, buf: &mut Vec<u8>, max: usize) -> io::Result<Vec<u8>> {
    read_line_until(stream, buf, max, None)
}

fn read_line_until<R: Read>(
    stream: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
    deadline: Option<Instant>,
) -> io::Result<Vec<u8>> {
    loop {
        if deadline.is_some_and(|deadline| Instant::now() > deadline) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request body timeout",
            ));
        }
        if let Some(p) = buf.windows(2).position(|w| w == b"\r\n") {
            if p > max {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            let line = buf[..p].to_vec();
            buf.drain(..p + 2);
            return Ok(line);
        }
        if buf.len() > max + 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        let mut chunk = [0u8; 8192];
        crate::fault::hit("http.chunk.line")?;
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF in chunked body",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn parse_head(head: &[u8], limits: &Limits) -> Result<Request, ParseError> {
    let parsed = parse_request_head(head, limits.request_line, limits.fields, limits.field_size)
        .map_err(head_error)?;
    let ParsedHead {
        method,
        target,
        raw_path,
        query,
        version,
        headers,
        framing,
        keep_alive,
        expect_continue,
    } = parsed;

    let method =
        String::from_utf8(method).map_err(|_| ParseError::BadRequest("non-ASCII method"))?;
    // The verified parser validates framing against the original field lines
    // first. Now compress duplicates for the policy/module view, matching
    // Apache's HTTP/1 table semantics without weakening CL/TE validation.
    let mut merged: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        if let Some(i) = vapache_verified::header_merge_index(&merged, &name) {
            merged[i].1.extend_from_slice(header_merge_separator(&name));
            merged[i].1.extend_from_slice(&value);
        } else {
            merged.push((name, value));
        }
    }
    let mut entries = Vec::with_capacity(merged.len());
    for (name, value) in merged {
        let name =
            String::from_utf8(name).map_err(|_| ParseError::BadRequest("non-ASCII header name"))?;
        entries.push((name, value));
    }

    Ok(Request {
        method,
        target,
        raw_path,
        query,
        version: version.into(),
        headers: Headers {
            entries,
            resident_lease: None,
            policy_budget: std::sync::Arc::new(crate::resource::RequestPolicyBudget::default()),
            request_scope: None,
            body_probe: false,
        },
        body: Vec::new(),
        body_spool: None,
        keep_alive,
        expect_continue,
        framing,
    })
}

/// Validate the first request head while its socket is still owned by the
/// asynchronous admission stage.  This keeps malformed heads and slow
/// pre-request clients out of the blocking worker pool.  The worker parses the
/// retained bytes again when it consumes the request; this preflight copy is
/// deliberately short-lived and bounded by `MAX_HEAD_TOTAL`.
pub(crate) fn preflight_request_head(head: &[u8], limits: &Limits) -> Result<Request, ParseError> {
    let mut request = parse_head(head, limits)?;
    validate_request_authority(&mut request, limits)?;
    Ok(request)
}

/// Map a rejection from the verified request-head parser to the wire-level
/// `ParseError` that the HTTP/1.1 layer has always used.
fn head_error(e: HeadError) -> ParseError {
    match e {
        HeadError::NulByte => ParseError::BadRequest("NUL in request"),
        HeadError::TooManyEmptyLines => ParseError::BadRequest("too many empty lines"),
        HeadError::UnterminatedRequestLine => ParseError::BadRequest("unterminated request line"),
        HeadError::RequestLineTooLong => ParseError::UriTooLong,
        HeadError::MissingMethod => ParseError::BadRequest("missing method"),
        HeadError::MissingTarget => ParseError::BadRequest("missing request target"),
        HeadError::MissingVersion => ParseError::BadRequest("missing HTTP version"),
        HeadError::WhitespaceInRequestLine => ParseError::BadRequest("whitespace in request line"),
        HeadError::InvalidMethod => ParseError::BadRequest("invalid method"),
        HeadError::InvalidTargetByte => ParseError::BadRequest("invalid byte in request target"),
        HeadError::InvalidVersion => ParseError::BadRequest("invalid HTTP version"),
        HeadError::VersionNotSupported => ParseError::VersionNotSupported,
        HeadError::UnterminatedHeaders => ParseError::BadRequest("unterminated headers"),
        HeadError::UnterminatedHeader => ParseError::BadRequest("unterminated header"),
        HeadError::HeaderLineTooLong => ParseError::HeadersTooLarge,
        HeadError::ObsoleteFolding => ParseError::BadRequest("obsolete line folding"),
        HeadError::MissingColon => ParseError::BadRequest("header without colon"),
        HeadError::InvalidHeaderName => ParseError::BadRequest("invalid header name"),
        HeadError::InvalidHeaderValue => ParseError::BadRequest("invalid header value"),
        HeadError::TooManyHeaders => ParseError::TooManyHeaders,
        HeadError::DuplicateHost => ParseError::BadRequest("duplicate Host header"),
        HeadError::MissingHost => ParseError::BadRequest("missing Host header"),
        HeadError::InvalidHost => ParseError::BadRequest("invalid Host header"),
        HeadError::InvalidAuthority => ParseError::BadRequest("invalid absolute URI authority"),
        HeadError::NotOriginForm => ParseError::BadRequest("request target is not origin-form"),
        HeadError::FragmentInTarget => ParseError::BadRequest("fragment in request target"),
        HeadError::BothTransferEncodingAndContentLength => {
            ParseError::BadRequest("both Transfer-Encoding and Content-Length")
        }
        HeadError::TransferEncodingInHttp10 => {
            ParseError::BadRequest("Transfer-Encoding in HTTP/1.0 request")
        }
        HeadError::UnsupportedTransferCoding => {
            ParseError::NotImplemented("unsupported transfer coding")
        }
        HeadError::InvalidContentLength => ParseError::BadRequest("invalid Content-Length"),
        HeadError::ConflictingContentLength => {
            ParseError::BadRequest("conflicting Content-Length values")
        }
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

pub enum Body {
    Empty,
    Bytes(Vec<u8>),
    File {
        file: File,
        offset: u64,
        len: u64,
    },
    Stream {
        reader: Box<dyn Read + Send>,
        len: u64,
    },
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(Cow<'static, str>, Vec<u8>)>,
    pub body: Body,
    spool_lease: Option<SpoolLease>,
    resident_lease: Option<ResidentLease>,
    flow: ResponseFlow,
    descriptor_leases: Vec<crate::resource::DescriptorLease>,
    dynamic_lease: Option<crate::resource::DynamicLease>,
}

enum ResponseFlow {
    Normal,
    BodyRequired(Option<BodyContinuation>),
}

pub(crate) type BodyContinuation =
    Box<dyn FnOnce(&crate::config::Config, &mut Request) -> Response + Send>;

struct ResponseOwnership {
    _descriptor_leases: Vec<crate::resource::DescriptorLease>,
    _dynamic_lease: Option<crate::resource::DynamicLease>,
}

pub const MAX_RESPONSE_HEADERS: usize = 256;
pub const MAX_RESPONSE_HEADER_BYTES: usize = 128 * 1024;

pub(crate) fn response_headers_admitted(resp: &Response) -> bool {
    let count = resp.headers.len().saturating_add(3);
    let bytes = resp.headers.iter().fold(0usize, |total, (name, value)| {
        total
            .saturating_add(name.len())
            .saturating_add(value.len())
            .saturating_add(4)
    });
    vapache_verified::response_header_budget_admit(
        count as u64,
        bytes.saturating_add(256) as u64,
        MAX_RESPONSE_HEADERS as u64,
        MAX_RESPONSE_HEADER_BYTES as u64,
    )
}

impl Response {
    pub fn new(status: u16) -> Self {
        Response {
            status,
            headers: Vec::new(),
            body: Body::Empty,
            spool_lease: None,
            resident_lease: None,
            flow: ResponseFlow::Normal,
            descriptor_leases: Vec::new(),
            dynamic_lease: None,
        }
    }

    pub(crate) fn body_required(continuation: BodyContinuation) -> Self {
        let mut response = Self::new(204);
        response.flow = ResponseFlow::BodyRequired(Some(continuation));
        response
    }

    pub(crate) fn requires_body(&self) -> bool {
        matches!(self.flow, ResponseFlow::BodyRequired(_))
    }

    pub(crate) fn take_body_continuation(&mut self) -> Option<BodyContinuation> {
        match &mut self.flow {
            ResponseFlow::BodyRequired(continuation) => continuation.take(),
            ResponseFlow::Normal => None,
        }
    }

    pub(crate) fn hold_descriptor(&mut self, lease: crate::resource::DescriptorLease) {
        self.descriptor_leases.push(lease);
    }

    pub(crate) fn hold_dynamic(&mut self, lease: crate::resource::DynamicLease) {
        self.dynamic_lease = Some(lease);
    }

    fn take_output_ownership(&mut self) -> ResponseOwnership {
        ResponseOwnership {
            _descriptor_leases: std::mem::take(&mut self.descriptor_leases),
            _dynamic_lease: self.dynamic_lease.take(),
        }
    }

    /// Attach exact ownership accounting to a response that keeps an open
    /// file descriptor until its body has been sent. Calling this more than
    /// once is idempotent, which lets every protocol adapter enforce the
    /// invariant at its final response boundary.
    pub(crate) fn ensure_file_descriptor(
        &mut self,
        budget: &std::sync::Arc<ResourceBudget>,
    ) -> io::Result<()> {
        if matches!(self.body, Body::File { .. }) && self.descriptor_leases.is_empty() {
            self.hold_descriptor(budget.try_descriptor()?);
        }
        Ok(())
    }

    pub fn bytes(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        let mut r = Response::new(status);
        r.headers.push((
            Cow::Borrowed("Content-Type"),
            content_type.as_bytes().to_vec(),
        ));
        r.body = Body::Bytes(body);
        r
    }

    pub(crate) fn policy_error() -> Self {
        Response::bytes(
            500,
            "text/plain; charset=UTF-8",
            b"Response policy exceeds configured resource limits\n".to_vec(),
        )
    }

    pub(crate) fn memory_overload() -> Self {
        Response::bytes(
            503,
            "text/plain; charset=UTF-8",
            b"Response memory capacity is temporarily exhausted\n".to_vec(),
        )
    }

    pub fn header(mut self, name: &str, value: impl Into<Vec<u8>>) -> Self {
        self.headers
            .push((Cow::Owned(name.to_string()), value.into()));
        self
    }

    pub fn body_len(&self) -> u64 {
        match &self.body {
            Body::Empty => 0,
            Body::Bytes(b) => b.len() as u64,
            Body::File { len, .. } => *len,
            Body::Stream { len, .. } => *len,
        }
    }

    pub(crate) fn hold_spool(&mut self, lease: SpoolLease) {
        self.spool_lease = Some(lease);
    }

    pub(crate) fn attribute_spool_client(&mut self, client: std::net::IpAddr) -> io::Result<()> {
        if let Some(lease) = &mut self.spool_lease {
            lease.attribute_client(client)?;
        }
        Ok(())
    }

    /// Charge retained byte bodies until the response has actually been sent
    /// or discarded. File and streaming bodies already have bounded backing
    /// storage and do not consume this resident-byte budget.
    pub(crate) fn admit_resident(
        &mut self,
        budget: &std::sync::Arc<ResourceBudget>,
    ) -> io::Result<()> {
        self.admit_resident_inner(budget, None)
    }

    pub(crate) fn admit_resident_for(
        &mut self,
        budget: &std::sync::Arc<ResourceBudget>,
        client: std::net::IpAddr,
    ) -> io::Result<()> {
        self.admit_resident_inner(budget, Some(client))
    }

    fn admit_resident_inner(
        &mut self,
        budget: &std::sync::Arc<ResourceBudget>,
        client: Option<std::net::IpAddr>,
    ) -> io::Result<()> {
        let header_bytes = self.headers.iter().fold(256u64, |total, (name, value)| {
            total
                .saturating_add(name.len() as u64)
                .saturating_add(value.len() as u64)
                .saturating_add(4)
        });
        let body_bytes = match &self.body {
            Body::Bytes(bytes) => bytes.len() as u64,
            Body::Empty | Body::File { .. } | Body::Stream { .. } => 0,
        };
        let amount = header_bytes.saturating_add(body_bytes);
        if let Some(lease) = &mut self.resident_lease {
            if let Some(client) = client {
                lease.attribute_response_client(client)?;
            }
            lease.reserve(header_bytes)?;
        } else {
            let mut lease = match client {
                Some(client) => budget.try_response_bytes_for(client),
                None => budget.try_response_bytes()?,
            };
            lease.reserve(amount)?;
            self.resident_lease = Some(lease);
        }
        Ok(())
    }

    pub(crate) fn hold_resident(&mut self, lease: ResidentLease) {
        self.resident_lease = Some(lease);
    }

    pub(crate) fn take_resident(&mut self) -> Option<ResidentLease> {
        self.resident_lease.take()
    }
}

#[inline]
fn push_decimal(out: &mut Vec<u8>, mut n: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&buf[i..]);
}

pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

/// A response destination.  Raw file descriptors are used only for plain TCP
/// sockets; TLS and other wrappers must copy file bodies through `Write` so
/// that bytes are encrypted.
pub trait ResponseWrite: Write {
    fn raw_fd(&self) -> Option<RawFd> {
        None
    }

    /// Return the plain socket descriptor that can safely be written with
    /// `send(2)`/`poll(2)`. This is separate from `raw_fd`: test and adapter
    /// implementations may expose a descriptor to exercise sendfile fallback
    /// without being a real socket.
    fn deadline_fd(&self) -> Option<BorrowedFd<'_>> {
        None
    }

    /// Put a plain socket in non-blocking mode while `sendfile(2)` runs.
    /// Implementations that do not expose a plain socket leave this
    /// unsupported and use the bounded copy path.
    fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "non-blocking response writes are unsupported",
        ))
    }

    /// Configure transport-specific readiness notifications so downstream
    /// receive progress becomes observable before the stall deadline. This is
    /// best effort; the explicit deadline remains the safety boundary.
    fn configure_progress_wakeups(&self) {}

    /// Inform encrypted/adapted writers of the current stall deadline. It is
    /// renewed whenever bytes are written; plain sockets are bounded directly
    /// with non-blocking I/O below.
    fn set_write_deadline(&mut self, _deadline: Option<Instant>) {}
}

impl ResponseWrite for TcpStream {
    fn raw_fd(&self) -> Option<RawFd> {
        Some(self.as_raw_fd())
    }

    fn deadline_fd(&self) -> Option<BorrowedFd<'_>> {
        Some(self.as_fd())
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        TcpStream::set_nonblocking(self, nonblocking)
    }

    fn configure_progress_wakeups(&self) {
        let _ = configure_response_progress_wakeups(self.as_fd());
    }
}

pub struct ResponseOptions<'a> {
    pub server_header: &'a str,
    pub keep_alive: bool,
    pub head_only: bool,
    pub protocol: Version,
    pub request_keep_alive: bool,
    /// Maximum interval in which a response write may make no byte progress.
    pub write_timeout: Duration,
}

fn write_timeout_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "response write deadline exceeded")
}

fn poll_writable(fd: BorrowedFd<'_>, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(write_timeout_error)?;
        let timeout =
            rustix::event::Timespec::try_from(remaining).unwrap_or(rustix::event::Timespec {
                tv_sec: i64::MAX,
                tv_nsec: 0,
            });
        let mut pollfd = rustix::event::PollFd::from_borrowed_fd(fd, rustix::event::PollFlags::OUT);
        let rc = match rustix::event::poll(std::slice::from_mut(&mut pollfd), Some(&timeout))
            .map_err(io::Error::from)
        {
            Ok(rc) => rc,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if rc == 0 {
            return Err(write_timeout_error());
        }
        let revents = pollfd.revents();
        if revents.contains(rustix::event::PollFlags::NVAL) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid response socket",
            ));
        }
        if revents.intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::HUP) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "response socket closed",
            ));
        }
        if revents.contains(rustix::event::PollFlags::OUT) {
            return Ok(());
        }
    }
}

fn stall_deadline(timeout: Duration) -> io::Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(write_timeout_error)
}

/// Keep the kernel's unsent queue small enough that a downstream receive-
/// window update becomes visible to `poll(POLLOUT)` and the next nonblocking
/// send. Without this, Linux may retain megabytes of already-queued data: a
/// slow client can read repeatedly while the server observes no successful
/// write and expires the progress deadline (P30-B).
#[cfg(target_os = "linux")]
const RESPONSE_NOTSENT_LOWAT: libc::c_uint = 64 * 1024;

#[cfg(target_os = "linux")]
pub(crate) fn configure_response_progress_wakeups(fd: BorrowedFd<'_>) -> io::Result<()> {
    let value = RESPONSE_NOTSENT_LOWAT;
    // SAFETY: `fd` is borrowed for this call and `value` points to a live
    // c_uint of the exact size passed to setsockopt. Non-TCP descriptors
    // return ENOPROTOOPT and retain the ordinary deadline behavior.
    let result = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_NOTSENT_LOWAT,
            (&value as *const libc::c_uint).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn configure_response_progress_wakeups(_fd: BorrowedFd<'_>) -> io::Result<()> {
    Ok(())
}

fn write_socket_all(fd: BorrowedFd<'_>, mut bytes: &[u8], timeout: Duration) -> io::Result<()> {
    let mut deadline = stall_deadline(timeout)?;
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(write_timeout_error());
        }
        match rustix::net::send(
            fd,
            bytes,
            rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
        )
        .map_err(io::Error::from)
        {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "response socket wrote zero bytes",
                ));
            }
            Ok(written) => {
                bytes = &bytes[written..];
                deadline = stall_deadline(timeout)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => poll_writable(fd, deadline)?,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_all_until<W: ResponseWrite>(
    stream: &mut W,
    mut bytes: &[u8],
    timeout: Duration,
) -> io::Result<()> {
    if let Some(fd) = stream.deadline_fd() {
        return write_socket_all(fd, bytes, timeout);
    }
    let mut deadline = stall_deadline(timeout)?;
    stream.set_write_deadline(Some(deadline));
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(write_timeout_error());
        }
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write response",
                ));
            }
            Ok(written) => {
                bytes = &bytes[written..];
                deadline = stall_deadline(timeout)?;
                stream.set_write_deadline(Some(deadline));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn sendfile_until(
    socket: BorrowedFd<'_>,
    file: BorrowedFd<'_>,
    offset: &mut u64,
    remaining: &mut u64,
    timeout: Duration,
) -> io::Result<()> {
    let mut deadline = stall_deadline(timeout)?;
    while *remaining > 0 {
        if Instant::now() >= deadline {
            return Err(write_timeout_error());
        }
        let chunk = (*remaining).min(i32::MAX as u64) as usize;
        match rustix::fs::sendfile(socket, file, Some(offset), chunk).map_err(io::Error::from) {
            Ok(0) => break,
            Ok(written) => {
                *remaining -= written as u64;
                deadline = stall_deadline(timeout)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                poll_writable(socket, deadline)?
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn serialize_response_head(
    resp: &mut Response,
    opts: &ResponseOptions,
) -> io::Result<(Vec<u8>, bool, u64)> {
    if !response_headers_admitted(resp) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response headers exceed configured count/byte limits",
        ));
    }
    let body_len = resp.body_len();
    let status = resp.status;
    let mut have_date = false;
    let mut have_server = false;
    for (n, _) in &resp.headers {
        if n.eq_ignore_ascii_case("date") {
            have_date = true;
        } else if n.eq_ignore_ascii_case("server") {
            have_server = true;
        }
    }
    let no_body_status = status == 204 || status == 304 || (100..200).contains(&status);
    // For a HEAD response there is no body to frame, and a 204/304/1xx status
    // has no body by definition.  Preserve an explicitly supplied
    // Content-Length there (HEAD mirrors the GET representation); for every
    // body-bearing response the writer computes it from the bytes it will send.
    let preserve_content_length = (opts.head_only || no_body_status)
        && resp
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("content-length"));

    let mut head = Vec::with_capacity(512);
    head.extend_from_slice(b"HTTP/1.1 ");
    push_decimal(&mut head, status as u64);
    head.push(b' ');
    head.extend_from_slice(reason_phrase(status).as_bytes());
    head.extend_from_slice(b"\r\n");
    if !have_date {
        head.extend_from_slice(b"Date: ");
        with_http_date_now(|date| head.extend_from_slice(date.as_bytes()));
        head.extend_from_slice(b"\r\n");
    }
    if !have_server {
        head.extend_from_slice(b"Server: ");
        head.extend_from_slice(opts.server_header.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    for (name, value) in &resp.headers {
        // The writer owns the message framing.  A caller-supplied
        // Content-Length/Transfer-Encoding that disagreed with the bytes sent
        // would desynchronize a keep-alive connection (request/response
        // smuggling for the next request on the socket).
        if name.eq_ignore_ascii_case("content-length") {
            if !preserve_content_length {
                continue;
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        // Never let an upstream/CGI/filename-derived header split the response.
        if crate::verified::sanitize_header_value(value).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CR/LF/NUL in response header",
            ));
        }
        if !crate::verified::valid_token(name.as_bytes()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid response header name",
            ));
        }
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value);
        head.extend_from_slice(b"\r\n");
    }
    if !preserve_content_length && !no_body_status {
        head.extend_from_slice(b"Content-Length: ");
        push_decimal(&mut head, body_len);
        head.extend_from_slice(b"\r\n");
    }
    let close = !opts.keep_alive || !opts.request_keep_alive;
    if close {
        head.extend_from_slice(b"Connection: close\r\n");
    } else if opts.protocol == Version::Http10 {
        head.extend_from_slice(b"Connection: keep-alive\r\n");
    }
    head.extend_from_slice(b"\r\n");

    Ok((head, no_body_status, body_len))
}

/// Serialize a response and send its body.  Returns the number of body bytes
/// actually sent (used for `%O` accounting).
pub fn write_response<W: ResponseWrite>(
    stream: &mut W,
    resp: &mut Response,
    opts: &ResponseOptions,
) -> io::Result<u64> {
    let (mut head, no_body_status, body_len) = serialize_response_head(resp, opts)?;
    // Coalesce the response head with small bodies into one write.  For static
    // files this avoids a separate header packet/syscall; larger files still
    // use sendfile.  The limits keep CGI/error bodies from being double-buffered
    // without bound.
    const INLINE_BYTES_LIMIT: u64 = 64 * 1024;
    const INLINE_FILE_LIMIT: u64 = 16 * 1024;
    let inline_body = !opts.head_only
        && !no_body_status
        && match &resp.body {
            Body::Bytes(_) => body_len <= INLINE_BYTES_LIMIT,
            Body::File { len, .. } => *len > 0 && *len <= INLINE_FILE_LIMIT,
            Body::Empty | Body::Stream { .. } => false,
        };

    if inline_body {
        let mut sent = 0u64;
        if let Body::Bytes(b) = &mut resp.body {
            head.extend_from_slice(b);
            sent = b.len() as u64;
        }
        if let Body::File { file, offset, len } = &mut resp.body {
            file.seek(SeekFrom::Start(*offset))?;
            let start = head.len();
            head.resize(start + *len as usize, 0);
            file.read_exact(&mut head[start..])?;
            sent = *len;
        }
        write_all_until(stream, &head, opts.write_timeout)?;
        stream.set_write_deadline(Some(stall_deadline(opts.write_timeout)?));
        stream.flush()?;
        return Ok(sent);
    }

    write_all_until(stream, &head, opts.write_timeout)?;
    let mut sent = 0u64;
    if opts.head_only || no_body_status {
        return Ok(0);
    }
    match &mut resp.body {
        Body::Empty => {}
        Body::Bytes(b) => {
            write_all_until(stream, b, opts.write_timeout)?;
            sent = b.len() as u64;
        }
        Body::Stream { reader, len } => {
            let mut tmp = vec![0u8; 64 * 1024];
            let mut remaining = *len;
            while remaining > 0 {
                let want = remaining.min(tmp.len() as u64) as usize;
                let got = reader.read(&mut tmp[..want])?;
                if got == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short streamed response body",
                    ));
                }
                write_all_until(stream, &tmp[..got], opts.write_timeout)?;
                sent += got as u64;
                remaining -= got as u64;
            }
        }
        Body::File { file, offset, len } => {
            if *len == 0 {
                return Ok(0);
            }
            // `sendfile` uses the explicit offset below, so the plain-TCP path
            // does not need an lseek first.  The TLS fallback seeks its own
            // cloned handle.
            let mut off = *offset;
            let mut remaining = *len;
            if let Some(fd) = stream.deadline_fd() {
                // A blocking sendfile can outlive SO_SNDTIMEO by several
                // multiples. Temporarily make the destination non-blocking,
                // then poll it against a deadline renewed on byte progress.
                if stream.set_nonblocking(true).is_ok() {
                    let before_sendfile = remaining;
                    let result = sendfile_until(
                        fd,
                        file.as_fd(),
                        &mut off,
                        &mut remaining,
                        opts.write_timeout,
                    );
                    // sendfile can make progress before reporting an error.
                    // Preserve that progress for access-log byte accounting
                    // and let the fallback resume at the updated offset.
                    sent += before_sendfile - remaining;
                    let restore = stream.set_nonblocking(false);
                    match result {
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                            let _ = restore;
                            return Err(error);
                        }
                        // Filesystems that do not support sendfile continue
                        // through the bounded userspace copy path.
                        Err(_) => {}
                    }
                    restore?;
                }
            }
            // TLS and other non-socket destinations: copy through `Write`.
            if remaining > 0 {
                let mut f = file.try_clone()?;
                f.seek(SeekFrom::Start(off))?;
                let mut tmp = vec![0u8; 64 * 1024];
                while remaining > 0 {
                    let want = remaining.min(tmp.len() as u64) as usize;
                    let got = f.read(&mut tmp[..want])?;
                    if got == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "short file response body",
                        ));
                    }
                    write_all_until(stream, &tmp[..got], opts.write_timeout)?;
                    sent += got as u64;
                    remaining -= got as u64;
                }
            }
        }
    }
    stream.set_write_deadline(Some(stall_deadline(opts.write_timeout)?));
    stream.flush()?;
    Ok(sent)
}

/// Maximum body bytes one writable wake may transfer before yielding. This is
/// deliberately smaller than Linux's maximum sendfile count: an always-ready
/// large download must not monopolize a Tokio worker or starve timeout/cancel
/// processing for other connections.
pub(crate) const ASYNC_OUTPUT_QUANTUM: usize = 256 * 1024;

async fn async_write_progress<W>(
    stream: &mut W,
    mut bytes: &[u8],
    timeout: Duration,
    scope: Option<&crate::resource::RequestScope>,
) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    while !bytes.is_empty() {
        if scope.is_some_and(crate::resource::RequestScope::is_cancelled) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "request scope cancelled",
            ));
        }
        let quantum = bytes.len().min(ASYNC_OUTPUT_QUANTUM);
        let written = tokio::time::timeout(
            timeout,
            tokio::io::AsyncWriteExt::write(stream, &bytes[..quantum]),
        )
        .await
        .map_err(|_| write_timeout_error())??;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "response socket wrote zero bytes",
            ));
        }
        bytes = &bytes[written..];
        tokio::task::yield_now().await;
    }
    Ok(())
}

async fn async_read_stream_chunk(
    reader: Box<dyn Read + Send>,
    want: usize,
    context: Option<crate::resource::ResourceContext>,
    ownership: ResponseOwnership,
) -> io::Result<(Box<dyn Read + Send>, Vec<u8>, usize, ResponseOwnership)> {
    let lease = match context.as_ref() {
        Some(context) => Some(context.budget().try_response_body_read_in(context)?),
        None => None,
    };
    tokio::task::spawn_blocking(move || {
        let _lease = lease;
        let mut reader = reader;
        let mut bytes = vec![0u8; want];
        let read = reader.read(&mut bytes)?;
        bytes.truncate(read);
        Ok((reader, bytes, read, ownership))
    })
    .await
    .map_err(|error| io::Error::other(format!("response body reader failed: {error}")))?
}

async fn async_read_file_chunk(
    file: File,
    offset: u64,
    want: usize,
    context: Option<crate::resource::ResourceContext>,
    ownership: ResponseOwnership,
) -> io::Result<(File, Vec<u8>, usize, ResponseOwnership)> {
    let lease = match context.as_ref() {
        Some(context) => Some(context.budget().try_response_body_read_in(context)?),
        None => None,
    };
    tokio::task::spawn_blocking(move || {
        let _lease = lease;
        let mut bytes = vec![0u8; want];
        let read = file.read_at(&mut bytes, offset)?;
        bytes.truncate(read);
        Ok((file, bytes, read, ownership))
    })
    .await
    .map_err(|error| io::Error::other(format!("response file reader failed: {error}")))?
}

/// Event-driven HTTP/1 output. Response generation may use blocking workers,
/// but downstream writability, file reads and streaming-body reads do not hold
/// a request-worker lease. The `Response` retains all descriptor/spool/backend
/// guards until this future completes or is cancelled.
pub(crate) async fn write_response_async<W>(
    stream: &mut W,
    resp: &mut Response,
    opts: &ResponseOptions<'_>,
    scope: Option<&crate::resource::RequestScope>,
) -> io::Result<u64>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let (head, no_body_status, _) = serialize_response_head(resp, opts)?;
    async_write_progress(stream, &head, opts.write_timeout, scope).await?;
    if opts.head_only || no_body_status {
        tokio::time::timeout(opts.write_timeout, tokio::io::AsyncWriteExt::flush(stream))
            .await
            .map_err(|_| write_timeout_error())??;
        return Ok(0);
    }

    let body = std::mem::replace(&mut resp.body, Body::Empty);
    // Ownership follows the file/upstream reader into each blocking read. If
    // the async output future is cancelled while `spawn_blocking` is running,
    // the exact descriptor/backend permits therefore remain held until the
    // kernel object itself leaves that task.
    let mut ownership = resp.take_output_ownership();
    let mut sent = 0u64;
    match body {
        Body::Empty => {}
        Body::Bytes(bytes) => {
            async_write_progress(stream, &bytes, opts.write_timeout, scope).await?;
            sent = bytes.len() as u64;
        }
        Body::File {
            file,
            mut offset,
            mut len,
        } => {
            let mut file = file;
            let context = scope.map(|scope| scope.context().clone());
            while len > 0 {
                if scope.is_some_and(crate::resource::RequestScope::is_cancelled) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "request scope cancelled",
                    ));
                }
                let want = len.min(64 * 1024) as usize;
                let (next_file, chunk, read, next_ownership) =
                    async_read_file_chunk(file, offset, want, context.clone(), ownership).await?;
                file = next_file;
                ownership = next_ownership;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short file response body",
                    ));
                }
                async_write_progress(stream, &chunk, opts.write_timeout, scope).await?;
                sent += read as u64;
                len -= read as u64;
                offset = offset.saturating_add(read as u64);
            }
        }
        Body::Stream {
            mut reader,
            mut len,
        } => {
            let context = scope.map(|scope| scope.context().clone());
            while len > 0 {
                if scope.is_some_and(crate::resource::RequestScope::is_cancelled) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "request scope cancelled",
                    ));
                }
                let want = len.min(64 * 1024) as usize;
                let (next_reader, bytes, read, next_ownership) =
                    async_read_stream_chunk(reader, want, context.clone(), ownership).await?;
                reader = next_reader;
                ownership = next_ownership;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short streamed response body",
                    ));
                }
                async_write_progress(stream, &bytes, opts.write_timeout, scope).await?;
                sent += read as u64;
                len -= read as u64;
            }
        }
    }
    tokio::time::timeout(opts.write_timeout, tokio::io::AsyncWriteExt::flush(stream))
        .await
        .map_err(|_| write_timeout_error())??;
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    #[test]
    fn parse_basic() {
        let raw = b"GET /index.html?x=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let req = parse_head(raw, &limits()).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.raw_path, b"/index.html");
        assert_eq!(req.query, b"x=1");
        assert_eq!(req.version, Version::Http11);
        assert!(req.keep_alive);
    }

    #[test]
    fn request_clones_share_one_policy_budget() {
        let req = parse_head(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", &limits()).unwrap();
        let clone = req.clone();
        req.charge_policy_work(crate::resource::MAX_POLICY_WORK_UNITS - 1)
            .unwrap();
        assert!(clone.charge_policy_work(2).is_err());
        assert!(req.policy_budget_failed());
        assert!(clone.policy_budget_failed());
    }

    #[test]
    fn framing_is_decided_by_verified_parser() {
        let raw = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n";
        let req = parse_head(raw, &limits()).unwrap();
        assert_eq!(req.framing, BodyFraming::Length(5));

        let raw = b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
        let req = parse_head(raw, &limits()).unwrap();
        assert_eq!(req.framing, BodyFraming::Chunked);

        let raw = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
        let req = parse_head(raw, &limits()).unwrap();
        assert_eq!(req.framing, BodyFraming::None);

        let raw = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n";
        let req = parse_head(raw, &limits()).unwrap();
        assert_eq!(req.framing, BodyFraming::Length(5));

        for raw in [
            &b"POST /x HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: nope\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: ,chunked\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked,\r\n\r\n",
        ] {
            assert!(parse_head(raw, &limits()).is_err());
        }
    }

    #[test]
    fn header_names_are_canonicalized_and_values_trimmed() {
        let raw = b"GET / HTTP/1.1\r\nHost: Example.COM\r\nX-Mixed-Case:  value  \r\n\r\n";
        let req = parse_head(raw, &limits()).unwrap();
        assert_eq!(req.header("host"), Some(&b"Example.COM"[..]));
        assert_eq!(req.header("x-mixed-case"), Some(&b"value"[..]));
    }

    #[test]
    fn duplicate_http1_fields_are_merged_before_policy_consumers() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: benign\r\nuser-agent: scanner\r\nX-Forwarded-For: 198.51.100.1\r\nX-Forwarded-For: 127.0.0.1\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n";
        let req = parse_head(raw, &limits()).unwrap();
        assert_eq!(req.header("user-agent"), Some(&b"benign, scanner"[..]));
        assert_eq!(
            req.header("x-forwarded-for"),
            Some(&b"198.51.100.1, 127.0.0.1"[..])
        );
        assert_eq!(req.header("cookie"), Some(&b"a=1; b=2"[..]));
        assert_eq!(req.headers.get_all("user-agent").count(), 1);
    }

    #[test]
    fn h2_style_duplicate_fields_share_the_http1_canonical_view() {
        let mut headers = Headers::default();
        headers.push_merged("authorization", b"Basic first");
        headers.push_merged("Authorization", b"Basic second");
        headers.push_merged("cookie", b"a=1");
        headers.push_merged("cookie", b"b=2");

        assert_eq!(
            headers.get("authorization"),
            Some(&b"Basic first, Basic second"[..])
        );
        assert_eq!(headers.get_all("authorization").count(), 1);
        assert_eq!(headers.get("cookie"), Some(&b"a=1; b=2"[..]));
    }

    #[test]
    fn emitted_header_values_reject_non_http_controls() {
        assert_eq!(
            crate::verified::sanitize_header_value(b"safe\tvalue"),
            Some(b"safe\tvalue".to_vec())
        );
        for control in [0x00, 0x0b, 0x0c, 0x1f, 0x7f, b'\r', b'\n'] {
            assert!(
                crate::verified::sanitize_header_value(&[b'a', control, b'b']).is_none(),
                "control {control:#x} was accepted"
            );
        }
    }

    #[test]
    fn absolute_form_and_asterisk_targets() {
        let req = parse_head(
            b"GET http://example.com/a?b HTTP/1.1\r\nHost: example.com\r\n\r\n",
            &limits(),
        )
        .unwrap();
        assert_eq!(req.raw_path, b"/a");
        assert_eq!(req.query, b"b");

        let req = parse_head(b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n", &limits()).unwrap();
        assert_eq!(req.raw_path, b"*");
        assert!(req.query.is_empty());
    }

    #[test]
    fn rejects_smuggling_vectors() {
        let cases: &[&[u8]] = &[
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost : x\r\n\r\n",
            b"GET / HTTP/1.1\r\n Host: x\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\nX: a\r\n folded\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\nBad\x01Name: v\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\nX: a\x00b\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            b"GET / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n",
        ];
        for c in cases {
            assert!(parse_head(c, &limits()).is_err());
        }
    }

    #[test]
    fn rejects_bad_targets() {
        for t in [
            &b"GET http:/x HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            b"GET /a b HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET /a#frag HTTP/1.1\r\nHost: x\r\n\r\n",
        ] {
            assert!(parse_head(t, &limits()).is_err());
        }
    }

    #[test]
    fn http10_keepalive_opt_in() {
        let req = parse_head(b"GET / HTTP/1.0\r\n\r\n", &limits()).unwrap();
        assert!(!req.keep_alive);
        let req = parse_head(
            b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
            &limits(),
        )
        .unwrap();
        assert!(req.keep_alive);
        let req = parse_head(
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            &limits(),
        )
        .unwrap();
        assert!(!req.keep_alive);
        // `close` is sticky regardless of token order.
        for header in [
            "close, keep-alive",
            "keep-alive, close",
            "keep-alive, close, keep-alive",
        ] {
            let raw = format!("GET / HTTP/1.1\r\nHost: x\r\nConnection: {header}\r\n\r\n");
            let req = parse_head(raw.as_bytes(), &limits()).unwrap();
            assert!(!req.keep_alive, "{header}");
        }
        let req = parse_head(
            b"GET / HTTP/1.0\r\nConnection: keep-alive, close\r\n\r\n",
            &limits(),
        )
        .unwrap();
        assert!(!req.keep_alive);
    }

    #[test]
    fn large_request_bodies_are_spooled() {
        let body = vec![b'x'; 2 * 1024 * 1024];
        let mut wire = format!(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        wire.extend_from_slice(&body);
        let mut cursor = std::io::Cursor::new(wire);
        let mut buf = Vec::new();
        let req = read_request(&mut cursor, &mut buf, &limits(), |_| {})
            .unwrap()
            .unwrap();
        assert!(req.body.is_empty());
        assert_eq!(req.body_len(), body.len() as u64);
        let mut reader = req.body_reader().unwrap().unwrap();
        let mut read = Vec::new();
        reader.read_to_end(&mut read).unwrap();
        assert_eq!(read, body);
    }

    #[test]
    fn in_memory_content_length_charges_only_received_body_bytes() {
        use std::sync::atomic::{AtomicU64, Ordering};

        struct HeaderOnly {
            head: Vec<u8>,
            sent: bool,
            budget: std::sync::Arc<ResourceBudget>,
            observed: std::sync::Arc<AtomicU64>,
        }

        impl Read for HeaderOnly {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if !self.sent {
                    self.sent = true;
                    out[..self.head.len()].copy_from_slice(&self.head);
                    return Ok(self.head.len());
                }
                self.observed
                    .store(self.budget.extended_usage().1, Ordering::Release);
                Ok(0)
            }
        }

        impl Write for HeaderOnly {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let head = format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BODY_IN_MEMORY
        )
        .into_bytes();
        let budget = std::sync::Arc::new(ResourceBudget::default());
        let observed = std::sync::Arc::new(AtomicU64::new(u64::MAX));
        let mut limits = limits();
        limits.resource_budget = budget.clone();
        let mut stream = HeaderOnly {
            head: head.clone(),
            sent: false,
            budget: budget.clone(),
            observed: observed.clone(),
        };

        assert!(matches!(
            read_request(&mut stream, &mut Vec::new(), &limits, |_| {}),
            Err(ReadError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
        assert_eq!(
            observed.load(Ordering::Acquire),
            2 * head.len() as u64,
            "the declaration itself must not reserve resident body bytes"
        );
        assert_eq!(budget.extended_usage().1, 0);
    }

    #[test]
    fn aggregate_request_spool_limits_fail_closed_and_release() {
        let mut limits = limits();
        limits.max_spool_bytes = 1024;
        limits.max_spool_files = 1;
        let mut cursor = std::io::Cursor::new(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2000000\r\n\r\n".to_vec(),
        );
        assert!(read_request(&mut cursor, &mut Vec::new(), &limits, |_| {}).is_err());
        assert_eq!(limits.resource_budget.usage(), (0, 0, 0));

        limits.max_spool_bytes = 1024 * 1024;
        let chunked = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let first = read_request(
            &mut std::io::Cursor::new(chunked.to_vec()),
            &mut Vec::new(),
            &limits,
            |_| {},
        )
        .unwrap()
        .unwrap();
        assert!(first.body_spool.is_none());
        assert_eq!(limits.resource_budget.usage(), (0, 0, 0));
        assert!(read_request(
            &mut std::io::Cursor::new(chunked.to_vec()),
            &mut Vec::new(),
            &limits,
            |_| {},
        )
        .unwrap()
        .is_some());
        drop(first);
        assert_eq!(limits.resource_budget.usage(), (0, 0, 0));
        assert!(read_request(
            &mut std::io::Cursor::new(chunked.to_vec()),
            &mut Vec::new(),
            &limits,
            |_| {},
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn body_accumulator_accounts_actual_bytes_and_releases_its_lease() {
        let budget = std::sync::Arc::new(ResourceBudget::default());
        let mut body = BodyAccumulator::new(4, budget.clone(), 8, 1);
        body.push(b"abcd").unwrap();
        assert_eq!(budget.usage(), (0, 0, 0));
        body.push(b"e").unwrap();
        assert_eq!(budget.usage(), (5, 1, 0));
        assert!(body.push(b"four").is_err());
        assert_eq!(budget.usage(), (5, 1, 0));
        let (_, spool) = body.finish();
        assert_eq!(spool.as_ref().unwrap().len, 5);
        drop(spool);
        assert_eq!(budget.usage(), (0, 0, 0));

        let mut declared_large = BodyAccumulator::new(
            REQUEST_BODY_SPOOL_PREFIX,
            budget.clone(),
            2 * REQUEST_BODY_SPOOL_PREFIX,
            1,
        );
        declared_large.push(b"token body bytes").unwrap();
        assert_eq!(budget.usage(), (0, 0, 0));
        let mut real_upload = BodyAccumulator::new(
            REQUEST_BODY_SPOOL_PREFIX,
            budget.clone(),
            2 * REQUEST_BODY_SPOOL_PREFIX,
            1,
        );
        real_upload
            .push(&vec![b'x'; REQUEST_BODY_SPOOL_PREFIX as usize + 1])
            .unwrap();
        assert_eq!(budget.usage(), (REQUEST_BODY_SPOOL_PREFIX + 1, 1, 0));
        drop(real_upload);
        assert_eq!(budget.usage(), (0, 0, 0));
    }

    #[test]
    fn request_trailers_are_bounded() {
        let mut wire =
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
        for i in 0..(MAX_REQUEST_TRAILERS + 1) {
            wire.extend_from_slice(format!("X-Trailer-{i}: x\r\n").as_bytes());
        }
        wire.extend_from_slice(b"\r\n");
        let mut cursor = std::io::Cursor::new(wire);
        let mut buf = Vec::new();
        assert!(read_request(&mut cursor, &mut buf, &limits(), |_| {}).is_err());
    }

    #[test]
    fn chunk_extensions_and_trailers_are_strictly_parsed() {
        for (line, expected) in [
            (b"a".as_slice(), Some(10)),
            (b"A;name=value".as_slice(), Some(10)),
            (
                b"a ; name = \"quoted\\\" value\" ; next".as_slice(),
                Some(10),
            ),
            (b"0;done".as_slice(), Some(0)),
        ] {
            assert_eq!(parse_chunk_size_line(line), expected, "{line:?}");
        }
        for invalid in [
            b" 1".as_slice(),
            b"1 ".as_slice(),
            b"1x".as_slice(),
            b"10000000000000000".as_slice(),
            b"1;".as_slice(),
            b"1;;x".as_slice(),
            b"1;name=".as_slice(),
            b"1;name=bad=value".as_slice(),
            b"1;name=\"unterminated".as_slice(),
            b"1;name=\"bad\rvalue\"".as_slice(),
            b"1;na(me=value".as_slice(),
        ] {
            assert_eq!(parse_chunk_size_line(invalid), None, "{invalid:?}");
        }
        assert!(valid_trailer_field(b"X-Checksum: yes"));
        assert!(!valid_trailer_field(b" folded"));
        assert!(!valid_trailer_field(b"Content-Length: 1"));
        assert!(!valid_trailer_field(b"Bad Name: value"));

        let mut enabled = limits();
        enabled.allow_request_trailers = true;
        for invalid in [
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1;\r\nx\r\n0\r\n\r\n"
                .as_slice(),
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 1\r\n\r\n"
                .as_slice(),
        ] {
            assert!(read_request(
                &mut std::io::Cursor::new(invalid.to_vec()),
                &mut Vec::new(),
                &enabled,
                |_| {},
            )
            .is_err());
        }

        // Exercise a chunk delimiter split with exactly one byte already in
        // the connection buffer. The reader must preserve that byte while it
        // fetches the LF, rather than consuming two new bytes and desyncing.
        let mut buffered = b"4\r\nbody\r".to_vec();
        let mut rest = std::io::Cursor::new(b"\n0\r\n\r\n".to_vec());
        let mut body = Vec::new();
        assert_eq!(
            read_chunked_to_writer_budgeted(
                &mut rest,
                &mut buffered,
                &mut body,
                16,
                Instant::now() + Duration::from_secs(1),
                None,
                false,
                0,
            )
            .unwrap(),
            4
        );
        assert_eq!(body, b"body");
    }

    #[test]
    fn chunk_framing_work_is_bounded_independently_of_body_bytes() {
        let mut count_budget = ChunkFramingBudget::default();
        for _ in 0..MAX_CHUNKS_PER_MESSAGE {
            count_budget.charge(1, true).unwrap();
        }
        assert_eq!(
            count_budget.charge(1, true).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut byte_budget = ChunkFramingBudget::default();
        assert_eq!(
            byte_budget
                .charge(MAX_CHUNK_FRAMING_BYTES as usize, false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn minimum_read_rate_has_a_grace_period_and_overflow_safe_boundary() {
        assert!(vapache_verified::minimum_progress_rate_admit(
            0,
            999,
            u64::MAX,
            1_000
        ));
        assert!(!vapache_verified::minimum_progress_rate_admit(
            1, 2_000, 100, 1_000
        ));
        assert!(vapache_verified::minimum_progress_rate_admit(
            200, 2_000, 100, 1_000
        ));
        assert!(vapache_verified::minimum_progress_rate_admit(
            u64::MAX,
            u64::MAX,
            1,
            1_000,
        ));
        assert!(!vapache_verified::minimum_progress_rate_admit(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            1_000,
        ));
        assert!(vapache_verified::minimum_progress_rate_admit(
            0,
            u64::MAX,
            0,
            1_000,
        ));
    }

    #[test]
    fn absolute_targets_and_request_trailers_require_capabilities() {
        let absolute = b"GET http://example.test/a HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec();
        let mut default_limits = limits();
        assert!(matches!(
            read_request(
                &mut std::io::Cursor::new(absolute.clone()),
                &mut Vec::new(),
                &default_limits,
                |_| {},
            ),
            Err(ReadError::Parse(ParseError::BadRequest(
                "absolute-form request target is disabled"
            )))
        ));
        default_limits.allow_absolute_request_target = true;
        assert!(read_request(
            &mut std::io::Cursor::new(absolute),
            &mut Vec::new(),
            &default_limits,
            |_| {},
        )
        .unwrap()
        .is_some());

        for rejected in [
            b"GET http://example.test/a HTTP/1.1\r\nHost: other.test\r\n\r\n".as_slice(),
            b"GET http://example.test:81/a HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
            b"GET https://example.test/a HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
            b"GET http://user@example.test/a HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        ] {
            assert!(read_request(
                &mut std::io::Cursor::new(rejected.to_vec()),
                &mut Vec::new(),
                &default_limits,
                |_| {},
            )
            .is_err());
        }
        let h10 = b"GET http://example.test/a HTTP/1.0\r\n\r\n".to_vec();
        let req = read_request(
            &mut std::io::Cursor::new(h10),
            &mut Vec::new(),
            &default_limits,
            |_| {},
        )
        .unwrap()
        .unwrap();
        assert_eq!(req.header("host"), Some(b"example.test".as_slice()));

        let malformed_host = b"GET / HTTP/1.1\r\nHost: example.test#other\r\n\r\n".to_vec();
        assert!(read_request(
            &mut std::io::Cursor::new(malformed_host),
            &mut Vec::new(),
            &limits(),
            |_| {},
        )
        .is_err());

        let trailers = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\nX-Checksum: yes\r\n\r\n";
        let mut default_limits = limits();
        assert!(matches!(
            read_request(
                &mut std::io::Cursor::new(trailers.to_vec()),
                &mut Vec::new(),
                &default_limits,
                |_| {},
            ),
            Err(ReadError::Parse(ParseError::BadRequest(
                "request trailers are disabled"
            )))
        ));
        default_limits.allow_request_trailers = true;
        assert!(read_request(
            &mut std::io::Cursor::new(trailers.to_vec()),
            &mut Vec::new(),
            &default_limits,
            |_| {},
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn head_limits() {
        let long = format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "a".repeat(9000));
        assert!(matches!(
            parse_head(long.as_bytes(), &limits()),
            Err(ParseError::UriTooLong)
        ));
    }

    #[test]
    fn parse_error_and_reason_phrase_tables_are_complete() {
        let errors = [
            ParseError::BadRequest("x"),
            ParseError::UriTooLong,
            ParseError::HeadersTooLarge,
            ParseError::TooManyHeaders,
            ParseError::VersionNotSupported,
            ParseError::PayloadTooLarge,
            ParseError::LengthRequired,
            ParseError::NotImplemented("x"),
        ];
        for error in errors {
            assert!(error.status() >= 400);
            assert!(!error.message().is_empty());
        }
        for status in [
            100u16, 201, 202, 204, 303, 307, 308, 408, 409, 411, 413, 415, 417, 429, 431, 503, 504,
        ] {
            assert_ne!(reason_phrase(status), "Unknown", "status {status}");
        }
    }

    #[test]
    fn head_error_maps_every_parser_rejection() {
        use vapache_verified::HeadError::*;
        let errors = [
            NulByte,
            TooManyEmptyLines,
            UnterminatedRequestLine,
            RequestLineTooLong,
            MissingMethod,
            MissingTarget,
            MissingVersion,
            WhitespaceInRequestLine,
            InvalidMethod,
            InvalidTargetByte,
            InvalidVersion,
            VersionNotSupported,
            UnterminatedHeaders,
            UnterminatedHeader,
            HeaderLineTooLong,
            ObsoleteFolding,
            MissingColon,
            InvalidHeaderName,
            InvalidHeaderValue,
            TooManyHeaders,
            DuplicateHost,
            MissingHost,
            InvalidHost,
            InvalidAuthority,
            NotOriginForm,
            FragmentInTarget,
            BothTransferEncodingAndContentLength,
            TransferEncodingInHttp10,
            UnsupportedTransferCoding,
            InvalidContentLength,
            ConflictingContentLength,
        ];
        for error in errors {
            let mapped = head_error(error);
            assert!(mapped.status() >= 400);
            assert!(!mapped.message().is_empty());
        }
    }

    fn header_and_empty_body_helpers() {
        let response = Response::new(204).header("X-Test", "yes");
        assert_eq!(response.status, 204);
        assert_eq!(response.body_len(), 0);
        assert_eq!(response.headers[0].0, "X-Test");
        let stream = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::Stream {
                reader: Box::new(std::io::Cursor::new(Vec::<u8>::new())),
                len: 7,
            },
            ..Response::new(200)
        };
        assert_eq!(stream.body_len(), 7);
    }

    #[test]
    fn response_builders_and_body_lengths() {
        header_and_empty_body_helpers();
    }

    #[test]
    fn response_header_limits_fail_before_any_wire_bytes_are_written() {
        let mut response = Response::new(200);
        for index in 0..MAX_RESPONSE_HEADERS {
            response
                .headers
                .push((Cow::Owned(format!("X-{index}")), b"v".to_vec()));
        }
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let error = write_response(&mut writer, &mut response, &response_options()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(writer.data.is_empty());

        let mut response =
            Response::new(200).header("X-Large", vec![b'x'; MAX_RESPONSE_HEADER_BYTES]);
        let error = write_response(&mut writer, &mut response, &response_options()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(writer.data.is_empty());
    }

    #[test]
    fn resident_response_admission_includes_serialized_headers() {
        let budget = std::sync::Arc::new(ResourceBudget::default());
        let mut response = Response::bytes(200, "text/plain", vec![b'x'; 100]);
        response.admit_resident(&budget).unwrap();
        assert!(budget.extended_usage().2 >= 100 + 256 + "Content-Type".len() as u64);
        drop(response);
        assert_eq!(budget.extended_usage().2, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lazy_async_body_emits_continue_only_after_the_head_phase() {
        let budget = std::sync::Arc::new(ResourceBudget::default());
        let mut limits = Limits::default();
        limits.resource_budget = budget.clone();
        let context = budget.context("127.0.0.1".parse().unwrap());
        let mut parser = std::io::Cursor::new(Vec::<u8>::new());
        let mut buffered = b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n".to_vec();
        let head = read_request_head_with_reservation(
            &mut parser,
            &mut buffered,
            &limits,
            |_, _| Ok(Some(context)),
            None,
        )
        .unwrap()
        .unwrap();
        assert!(parser.into_inner().is_empty(), "head phase emitted 100");

        let (mut server, mut client) = tokio::io::duplex(1024);
        tokio::io::AsyncWriteExt::write_all(&mut client, b"body")
            .await
            .unwrap();
        let request = read_request_body_async(&mut server, &mut buffered, &limits, head)
            .await
            .unwrap();
        assert_eq!(request.body, b"body");
        let expected = b"HTTP/1.1 100 Continue\r\n\r\n";
        let mut actual = vec![0; expected.len()];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut actual)
            .await
            .unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_chunk_body_preserves_pipelined_bytes() {
        let budget = std::sync::Arc::new(ResourceBudget::default());
        let mut limits = Limits::default();
        limits.resource_budget = budget.clone();
        let context = budget.context("127.0.0.1".parse().unwrap());
        let mut parser = std::io::Cursor::new(Vec::<u8>::new());
        let mut buffered =
            b"POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec();
        let head = read_request_head_with_reservation(
            &mut parser,
            &mut buffered,
            &limits,
            |_, _| Ok(Some(context)),
            None,
        )
        .unwrap()
        .unwrap();
        let (mut server, mut client) = tokio::io::duplex(1024);
        tokio::io::AsyncWriteExt::write_all(&mut client, b"4\r\nbody\r\n0\r\n\r\nGET /next")
            .await
            .unwrap();
        let request = read_request_body_async(&mut server, &mut buffered, &limits, head)
            .await
            .unwrap();
        assert_eq!(request.body, b"body");
        assert_eq!(buffered, b"GET /next");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_output_pump_transfers_large_bodies_in_bounded_quanta() {
        let (mut server, mut client) = tokio::io::duplex(8 * 1024);
        let body = vec![b'x'; ASYNC_OUTPUT_QUANTUM * 3 + 17];
        let expected = body.len();
        let writer = tokio::spawn(async move {
            let mut response = Response::bytes(200, "application/octet-stream", body);
            write_response_async(&mut server, &mut response, &response_options(), None)
                .await
                .unwrap()
        });
        let mut wire = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client, &mut wire)
            .await
            .unwrap();
        let sent = writer.await.unwrap();
        assert_eq!(sent, expected as u64);
        let split = wire
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        assert_eq!(&wire[split..], vec![b'x'; expected]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_output_keeps_backend_ownership_with_blocking_read() {
        struct BlockingReader {
            started: std::sync::mpsc::SyncSender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }

        impl Read for BlockingReader {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                let _ = self.started.try_send(());
                self.release
                    .recv()
                    .map_err(|_| io::Error::other("test release channel closed"))?;
                bytes[0] = b'x';
                Ok(1)
            }
        }

        let budget = std::sync::Arc::new(ResourceBudget::default());
        let context = budget.context("127.0.0.1".parse().unwrap());
        let dynamic = budget.try_dynamic_descriptors_in(&context, 8, 1).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let reader = BlockingReader {
            started: started_tx,
            release: release_rx,
        };
        let (mut server, _client) = tokio::io::duplex(8 * 1024);
        let output = tokio::spawn(async move {
            let mut response = Response::new(200);
            response.body = Body::Stream {
                reader: Box::new(reader),
                len: 1,
            };
            response.hold_dynamic(dynamic);
            write_response_async(&mut server, &mut response, &response_options(), None).await
        });
        tokio::task::spawn_blocking(move || started_rx.recv_timeout(Duration::from_secs(2)))
            .await
            .unwrap()
            .unwrap();

        output.abort();
        assert!(output.await.unwrap_err().is_cancelled());
        assert_eq!(
            budget.slot_usage(crate::resource::SlotKind::DynamicBackend),
            1,
            "cancelling output released the backend while its reader still owned it"
        );
        release_tx.send(()).unwrap();
        for _ in 0..100 {
            if budget.slot_usage(crate::resource::SlotKind::DynamicBackend) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            budget.slot_usage(crate::resource::SlotKind::DynamicBackend),
            0
        );
    }

    struct TestWriter {
        data: Vec<u8>,
        fd: Option<RawFd>,
    }

    impl Write for TestWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.data.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ResponseWrite for TestWriter {
        fn raw_fd(&self) -> Option<RawFd> {
            self.fd
        }
    }

    struct SocketWriter(std::os::unix::net::UnixStream);

    impl Write for SocketWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl ResponseWrite for SocketWriter {
        fn raw_fd(&self) -> Option<RawFd> {
            Some(self.0.as_raw_fd())
        }

        fn deadline_fd(&self) -> Option<BorrowedFd<'_>> {
            Some(self.0.as_fd())
        }

        fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
            self.0.set_nonblocking(nonblocking)
        }
    }

    fn response_options() -> ResponseOptions<'static> {
        ResponseOptions {
            server_header: "test",
            keep_alive: true,
            head_only: false,
            protocol: Version::Http11,
            request_keep_alive: true,
            write_timeout: Duration::from_secs(5),
        }
    }

    fn temp_file(data: &[u8]) -> File {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vapache-http-test-{}-{}.body",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, data).unwrap();
        let file = File::open(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        file
    }

    #[test]
    fn response_writer_covers_inline_stream_file_and_error_paths() {
        // Inline bytes.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::bytes(200, "text/plain", b"hello".to_vec());
        let sent = write_response(&mut writer, &mut response, &response_options()).unwrap();
        assert_eq!(sent, 5);
        assert!(writer.data.windows(5).any(|w| w == b"hello"));

        // Inline small file.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(b"file-body"),
                offset: 0,
                len: 9,
            },
            ..Response::new(200)
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            9
        );
        assert!(writer.data.windows(9).any(|w| w == b"file-body"));

        // Empty body, HEAD and no-body statuses.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::new(200);
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            0
        );
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::bytes(200, "text/plain", b"abc".to_vec());
        let mut opts = response_options();
        opts.head_only = true;
        assert_eq!(
            write_response(&mut writer, &mut response, &opts).unwrap(),
            0
        );
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::bytes(204, "text/plain", b"abc".to_vec());
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            0
        );

        // Large bytes use the non-inline path.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::bytes(200, "text/plain", vec![b'b'; 70 * 1024]);
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            70 * 1024
        );

        // Stream body success and premature EOF.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::Stream {
                reader: Box::new(std::io::Cursor::new(vec![b's'; 10])),
                len: 10,
            },
            ..Response::new(200)
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            10
        );
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::Stream {
                reader: Box::new(std::io::Cursor::new(Vec::<u8>::new())),
                len: 10,
            },
            ..Response::new(200)
        };
        assert!(write_response(&mut writer, &mut response, &response_options()).is_err());

        // Non-socket file copy fallback.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(&vec![b'f'; 32 * 1024]),
                offset: 0,
                len: 32 * 1024,
            },
            ..Response::new(200)
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            32 * 1024
        );

        // sendfile failure falls back to the copy path.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: Some(-1),
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(&vec![b'g'; 32 * 1024]),
                offset: 0,
                len: 32 * 1024,
            },
            ..Response::new(200)
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            32 * 1024
        );

        // Short file: sendfile ends at EOF and the fallback sees no bytes.
        // The response must fail closed rather than advertise more body bytes
        // than were sent on a reusable connection.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: Some(-1),
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(b"short"),
                offset: 0,
                len: 32 * 1024,
            },
            ..Response::new(200)
        };
        assert!(write_response(&mut writer, &mut response, &response_options()).is_err());

        // Zero-length file body after the head.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(b""),
                offset: 0,
                len: 0,
            },
            ..Response::new(200)
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            0
        );

        // Header serialization failures.
        for bad in [
            ("X-Test", b"bad\r\nvalue".to_vec()),
            ("bad name", b"value".to_vec()),
        ] {
            let mut writer = TestWriter {
                data: Vec::new(),
                fd: None,
            };
            let mut response = Response::new(200);
            response
                .headers
                .push((Cow::Owned(bad.0.to_string()), bad.1));
            assert!(write_response(&mut writer, &mut response, &response_options()).is_err());
        }

        // Connection-header variants.
        for (opts, expected) in [
            (
                ResponseOptions {
                    keep_alive: false,
                    ..response_options()
                },
                "Connection: close\r\n",
            ),
            (
                ResponseOptions {
                    protocol: Version::Http10,
                    ..response_options()
                },
                "Connection: keep-alive\r\n",
            ),
        ] {
            let mut writer = TestWriter {
                data: Vec::new(),
                fd: None,
            };
            let mut response = Response::new(200);
            write_response(&mut writer, &mut response, &opts).unwrap();
            assert!(writer
                .data
                .windows(expected.len())
                .any(|w| w == expected.as_bytes()));
        }

        // sendfile success through a real socket.
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut writer = SocketWriter(a);
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(&vec![b'h'; 32 * 1024]),
                offset: 0,
                len: 32 * 1024,
            },
            ..Response::new(200)
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            32 * 1024
        );
        drop(writer);
        assert!(b.take(32 * 1024).bytes().count() > 0);

        // TcpStream implements raw_fd for the sendfile path.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let stream = std::net::TcpStream::connect(addr).unwrap();
        assert!(stream.raw_fd().is_some());
        drop(stream);
        handle.join().unwrap();
    }

    struct SlowReader {
        delay: Duration,
        data: Vec<u8>,
        pos: usize,
    }

    impl Read for SlowReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            std::thread::sleep(self.delay);
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn chunked_and_line_readers_cover_limits_timeouts_and_eof() {
        use std::io::Cursor;

        let mut file = spool_file().unwrap();
        let mut buf = Vec::new();
        let mut stream = Cursor::new(b"1\r\na\r\n0\r\n\r\n".to_vec());
        let now = Instant::now();
        assert_eq!(
            read_chunked_to_file(
                &mut stream,
                &mut buf,
                &mut file,
                10,
                now + Duration::from_secs(5)
            )
            .unwrap(),
            1
        );

        let mut file = spool_file().unwrap();
        let mut buf = b"1\r\na\r\n0\r\n\r\n".to_vec();
        let mut empty = Cursor::new(Vec::<u8>::new());
        assert_eq!(
            read_chunked_to_file(
                &mut empty,
                &mut buf,
                &mut file,
                10,
                now + Duration::from_secs(5)
            )
            .unwrap(),
            1
        );

        let mut file = spool_file().unwrap();
        let mut buf = Vec::new();
        let mut too_big = Cursor::new(b"2\r\nxx\r\n0\r\n\r\n".to_vec());
        assert!(read_chunked_to_file(
            &mut too_big,
            &mut buf,
            &mut file,
            1,
            now + Duration::from_secs(5)
        )
        .is_err());

        let mut file = spool_file().unwrap();
        let mut buf = Vec::new();
        let mut eof = Cursor::new(b"5\r\n".to_vec());
        assert!(read_chunked_to_file(
            &mut eof,
            &mut buf,
            &mut file,
            10,
            now + Duration::from_secs(5)
        )
        .is_err());

        let mut file = spool_file().unwrap();
        let mut buf = Vec::new();
        let mut bad_crlf = Cursor::new(b"1\r\naXX".to_vec());
        assert!(read_chunked_to_file(
            &mut bad_crlf,
            &mut buf,
            &mut file,
            10,
            now + Duration::from_secs(5)
        )
        .is_err());

        let mut file = spool_file().unwrap();
        let mut buf = b"0\r\n".to_vec();
        let mut slow = SlowReader {
            delay: Duration::from_millis(10),
            data: b"X-Test: x\r\n\r\n".to_vec(),
            pos: 0,
        };
        assert!(read_chunked_to_file(
            &mut slow,
            &mut buf,
            &mut file,
            10,
            Instant::now() + Duration::from_millis(1)
        )
        .is_err());

        let mut file = spool_file().unwrap();
        let mut buf = b"5\r\n".to_vec();
        let mut slow = SlowReader {
            delay: Duration::from_millis(10),
            data: b"abc".to_vec(),
            pos: 0,
        };
        assert!(read_chunked_to_file(
            &mut slow,
            &mut buf,
            &mut file,
            10,
            Instant::now() + Duration::from_millis(1)
        )
        .is_err());

        let mut line = Cursor::new(b"abc\r\n".to_vec());
        let mut buf = Vec::new();
        assert!(read_line(&mut line, &mut buf, 1).is_err());
        let mut long = Cursor::new(vec![b'a'; 8]);
        let mut buf = Vec::new();
        assert!(read_line(&mut long, &mut buf, 2).is_err());
        let mut eof = Cursor::new(Vec::<u8>::new());
        let mut buf = Vec::new();
        assert!(read_line(&mut eof, &mut buf, 10).is_err());
    }

    #[test]
    fn read_request_covers_header_and_body_error_branches() {
        use std::io::Cursor;

        // Clean EOF between requests.
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut buf = Vec::new();
        assert!(read_request(&mut empty, &mut buf, &limits(), |_| {})
            .unwrap()
            .is_none());

        // Partial header EOF.
        let mut partial = Cursor::new(b"GET / HTTP/1.1\r\nHost: x".to_vec());
        let mut buf = Vec::new();
        assert!(read_request(&mut partial, &mut buf, &limits(), |_| {}).is_err());

        // Header total limit before and after a read.
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut buf = vec![b'a'; MAX_HEAD_TOTAL + 1];
        assert!(matches!(
            read_request(&mut empty, &mut buf, &limits(), |_| {}),
            Err(ReadError::Parse(ParseError::HeadersTooLarge))
        ));
        let mut data = Cursor::new(vec![b'a'; 8192]);
        let mut buf = vec![b'a'; MAX_HEAD_TOTAL];
        assert!(matches!(
            read_request(&mut data, &mut buf, &limits(), |_| {}),
            Err(ReadError::Parse(ParseError::HeadersTooLarge))
        ));

        // Header timeout and rate-based allowance.
        let mut timeout_limits = limits();
        timeout_limits.header_timeout = Duration::ZERO;
        timeout_limits.header_min_rate = 1;
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut buf = Vec::new();
        assert!(matches!(
            read_request(&mut empty, &mut buf, &timeout_limits, |_| {}),
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::TimedOut
        ));

        // Content-Length over the configured limit.
        let wire = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\n\r\n".to_vec();
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        let mut small = limits();
        small.body = 5;
        assert!(matches!(
            read_request(&mut cursor, &mut buf, &small, |_| {}),
            Err(ReadError::Parse(ParseError::PayloadTooLarge))
        ));

        // Spooled body timeout and EOF.
        let wire = format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BODY_IN_MEMORY + 1
        )
        .into_bytes();
        let mut cursor = Cursor::new(wire.clone());
        let mut buf = Vec::new();
        let mut zero_timeout = limits();
        zero_timeout.body_timeout = Duration::ZERO;
        assert!(matches!(
            read_request(&mut cursor, &mut buf, &zero_timeout, |_| {}),
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::TimedOut
        ));
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        assert!(matches!(
            read_request(&mut cursor, &mut buf, &limits(), |_| {}),
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof
        ));

        // In-memory body timeout and EOF.
        let wire = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n".to_vec();
        let mut cursor = Cursor::new(wire.clone());
        let mut buf = Vec::new();
        let mut zero_timeout = limits();
        zero_timeout.body_timeout = Duration::ZERO;
        assert!(matches!(
            read_request(&mut cursor, &mut buf, &zero_timeout, |_| {}),
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::TimedOut
        ));
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        assert!(matches!(
            read_request(&mut cursor, &mut buf, &limits(), |_| {}),
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof
        ));

        // Chunked body deadline and success.
        let wire = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        let mut cursor = Cursor::new(wire.clone());
        let mut buf = Vec::new();
        let mut zero_timeout = limits();
        zero_timeout.body_timeout = Duration::ZERO;
        assert!(matches!(
            read_request(&mut cursor, &mut buf, &zero_timeout, |_| {}),
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::TimedOut
        ));
        let mut wire = wire;
        wire.extend_from_slice(b"4\r\nbody\r\n0\r\n\r\n");
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        let req = read_request(&mut cursor, &mut buf, &limits(), |_| {})
            .unwrap()
            .unwrap();
        assert_eq!(req.body_len(), 4);
    }

    #[test]
    fn body_rate_limits_are_applied_to_fixed_and_chunked_bodies() {
        use std::io::Cursor;

        let mut rate_limited = limits();
        rate_limited.body_min_rate = 1;

        let wire = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody".to_vec();
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        let req = read_request(&mut cursor, &mut buf, &rate_limited, |_| {})
            .unwrap()
            .unwrap();
        assert_eq!(req.body, b"body");

        let wire =
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n"
                .to_vec();
        let mut cursor = Cursor::new(wire);
        let mut buf = Vec::new();
        let req = read_request(&mut cursor, &mut buf, &rate_limited, |_| {})
            .unwrap()
            .unwrap();
        assert_eq!(req.body_len(), 4);
        assert_eq!(req.body, b"body");
        assert!(req.body_spool.is_none());
        assert_eq!(rate_limited.resource_budget.usage(), (0, 0, 0));
    }

    struct ShortReads {
        data: Vec<u8>,
        pos: usize,
        max: usize,
    }

    impl Read for ShortReads {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.max).min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn test_readers_report_eof_after_their_input() {
        let mut slow = SlowReader {
            delay: Duration::ZERO,
            data: Vec::new(),
            pos: 0,
        };
        assert_eq!(slow.read(&mut [0; 1]).unwrap(), 0);
        let mut short = ShortReads {
            data: Vec::new(),
            pos: 0,
            max: 1,
        };
        assert_eq!(short.read(&mut [0; 1]).unwrap(), 0);
    }

    #[test]
    fn chunk_terminator_can_span_two_reads() {
        let mut file = spool_file().unwrap();
        let mut buf = Vec::new();
        let mut stream = ShortReads {
            data: b"1\r\na\r\n0\r\n\r\n".to_vec(),
            pos: 0,
            max: 4,
        };
        let total = read_chunked_to_file(
            &mut stream,
            &mut buf,
            &mut file,
            10,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(total, 1);
    }

    struct PlainWriter {
        data: Vec<u8>,
    }

    impl Write for PlainWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.data.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ResponseWrite for PlainWriter {}

    #[test]
    fn response_write_default_destination_has_no_sendfile_fd() {
        let writer = PlainWriter { data: Vec::new() };
        assert_eq!(writer.raw_fd(), None);

        // The default implementation also selects the encrypted/copy path for
        // file bodies rather than sendfile.
        let mut writer = writer;
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(&vec![b'p'; 32 * 1024]),
                offset: 0,
                len: 32 * 1024,
            },
            ..Response::new(200)
        };
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            32 * 1024
        );
    }

    #[test]
    fn short_file_body_fails_closed_on_a_socket_destination() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut writer = SocketWriter(a);
        let mut response = Response {
            status: 200,
            headers: Vec::new(),
            body: Body::File {
                file: temp_file(b"short"),
                offset: 0,
                len: 32 * 1024,
            },
            ..Response::new(200)
        };
        assert!(write_response(&mut writer, &mut response, &response_options()).is_err());
        drop(writer);
        drop(b);
    }

    #[test]
    fn stalled_socket_file_write_obeys_stall_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut response = Response {
                status: 200,
                headers: Vec::new(),
                body: Body::File {
                    file: temp_file(&vec![b's'; 32 * 1024 * 1024]),
                    offset: 0,
                    len: 32 * 1024 * 1024,
                },
                ..Response::new(200)
            };
            let mut opts = response_options();
            opts.write_timeout = Duration::from_millis(200);
            let started = Instant::now();
            let result = write_response(&mut server, &mut response, &opts);
            let _ = tx.send((started.elapsed(), result));
        });

        // Keep the peer open without reading. The writer must release itself;
        // closing this socket is cleanup, not the event that unblocks it.
        let outcome = rx.recv_timeout(Duration::from_secs(2));
        drop(client);
        handle.join().unwrap();
        let (elapsed, result) = outcome.expect("stalled writer exceeded its deadline");
        assert!(elapsed < Duration::from_secs(2), "elapsed: {elapsed:?}");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tcp_response_writer_caps_unsent_bytes_for_progress_wakeups() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server.configure_progress_wakeups();
        let mut response = Response::bytes(200, "text/plain", b"ok".to_vec());
        write_response(&mut server, &mut response, &response_options()).unwrap();

        let mut value: libc::c_uint = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: the socket and output pointers remain valid for the call and
        // `length` describes the exact c_uint output buffer.
        let result = unsafe {
            libc::getsockopt(
                server.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_NOTSENT_LOWAT,
                (&mut value as *mut libc::c_uint).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(value, RESPONSE_NOTSENT_LOWAT);
        drop(client);
    }

    struct ProgressWriter {
        bytes: usize,
        delay: Duration,
    }

    impl Write for ProgressWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            std::thread::sleep(self.delay);
            if buf.is_empty() {
                return Ok(0);
            }
            self.bytes += 1;
            Ok(1)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ResponseWrite for ProgressWriter {}

    #[test]
    fn progressing_write_may_outlive_one_timeout_interval() {
        let mut writer = ProgressWriter {
            bytes: 0,
            delay: Duration::from_millis(3),
        };
        let mut response = Response::bytes(200, "text/plain", vec![b'x'; 64]);
        let mut opts = response_options();
        opts.write_timeout = Duration::from_millis(20);
        let started = Instant::now();
        let sent = write_response(&mut writer, &mut response, &opts).unwrap();
        assert_eq!(sent, 64);
        assert!(started.elapsed() > opts.write_timeout);
        assert!(writer.bytes > sent as usize); // response head plus body
    }

    #[test]
    fn response_writer_owns_framing_headers() {
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::bytes(200, "text/plain", b"abc".to_vec());
        response
            .headers
            .push((Cow::Borrowed("Content-Length"), b"999".to_vec()));
        response
            .headers
            .push((Cow::Borrowed("Transfer-Encoding"), b"chunked".to_vec()));
        assert_eq!(
            write_response(&mut writer, &mut response, &response_options()).unwrap(),
            3
        );
        let head = String::from_utf8_lossy(&writer.data[..writer.data.len() - 3]);
        assert!(head.contains("Content-Length: 3\r\n"), "{head}");
        assert!(!head.contains("999"), "{head}");
        assert!(!head.contains("Transfer-Encoding"), "{head}");

        // HEAD has no body to frame; the selected representation length is
        // preserved instead of being replaced with zero.
        let mut writer = TestWriter {
            data: Vec::new(),
            fd: None,
        };
        let mut response = Response::bytes(200, "text/plain", b"abc".to_vec());
        response
            .headers
            .push((Cow::Borrowed("Content-Length"), b"12".to_vec()));
        let mut opts = response_options();
        opts.head_only = true;
        assert_eq!(
            write_response(&mut writer, &mut response, &opts).unwrap(),
            0
        );
        let head = String::from_utf8_lossy(&writer.data);
        assert!(head.contains("Content-Length: 12\r\n"), "{head}");
        assert!(!head.contains("Content-Length: 3\r\n"), "{head}");
    }

    #[test]
    fn spool_files_are_private_and_do_not_follow_existing_names() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::sync::atomic::AtomicU64;

        let dir = std::env::temp_dir().join(format!("vapache-spool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        symlink(&victim, spool_path(&dir, 0)).unwrap();

        let counter = AtomicU64::new(0);
        let file = spool_file_named(&dir, &counter).unwrap();
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert!(spool_path(&dir, 0)
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spool_name_collisions_fail_closed() {
        use std::sync::atomic::AtomicU64;

        let dir = std::env::temp_dir().join(format!("vapache-spool-full-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for n in 0..SPOOL_ATTEMPTS {
            std::fs::write(spool_path(&dir, n), b"occupied").unwrap();
        }
        let counter = AtomicU64::new(0);
        assert!(spool_file_named(&dir, &counter).is_err());
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Relaxed),
            SPOOL_ATTEMPTS
        );

        // A missing/unusable directory is a hard error, not an unbounded retry.
        assert!(spool_file_named(&dir.join("missing"), &AtomicU64::new(0)).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
