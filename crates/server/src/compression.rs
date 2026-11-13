//! Apache-compatible gzip/brotli response filtering.
//!
//! The implementation supports the common `mod_deflate`/`mod_brotli` subset:
//! `SetOutputFilter`, `AddOutputFilterByType`, `AddOutputFilter`,
//! `DeflateCompressionLevel`, `BrotliCompressionQuality` and the ETag-alter
//! settings.  Compression is deliberately skipped for ranges, already encoded
//! bodies, `no-transform` responses and bodies larger than the in-memory cap;
//! `Vary: Accept-Encoding` is still emitted for negotiable representations.

use crate::config::{AlterEtag, CompressionKind, CompressionRule, Scope, UnsupportedFilterRule};
use crate::http::{Body, Request, Response};
use brotli::enc::cluster::HistogramPair;
use brotli::enc::command::Command;
use brotli::enc::entropy_encode::HuffmanTree;
use brotli::enc::histogram::{ContextType, HistogramCommand, HistogramDistance, HistogramLiteral};
use brotli::enc::{
    floatX, s16, v8, CombiningAllocator, StandardAlloc, StaticCommand, ZopfliNode, PDF,
};
use brotli::{Allocator, SliceWrapper, SliceWrapperMut};
use std::borrow::Cow;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::marker::PhantomData;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const MAX_COMPRESS_BODY: u64 = 8 * 1024 * 1024;
const DEFAULT_DEFLATE_LEVEL: u32 = 6;
const DEFAULT_BROTLI_QUALITY: u32 = 5;
const ENCODER_INPUT_BUFFER: usize = 64 * 1024;

#[derive(Debug)]
struct AllocationMeter {
    current: AtomicU64,
    peak: AtomicU64,
    limit: u64,
    exceeded: AtomicBool,
}

impl AllocationMeter {
    fn new(limit: u64) -> Self {
        Self {
            current: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            limit,
            exceeded: AtomicBool::new(false),
        }
    }

    fn allocate(&self, bytes: u64) {
        let current = self
            .current
            .fetch_add(bytes, Ordering::AcqRel)
            .saturating_add(bytes);
        self.peak.fetch_max(current, Ordering::AcqRel);
        if current > self.limit {
            self.exceeded.store(true, Ordering::Release);
        }
    }

    fn release(&self, bytes: u64) {
        self.current.fetch_sub(bytes, Ordering::AcqRel);
    }

    fn validate(&self) -> io::Result<()> {
        if self.exceeded.load(Ordering::Acquire) {
            Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "Brotli workspace exceeded its admitted bound",
            ))
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    fn peak(&self) -> u64 {
        self.peak.load(Ordering::Acquire)
    }
}

type StandardMemory<T> = <StandardAlloc as Allocator<T>>::AllocatedMemory;

struct MeteredMemory<T>
where
    T: Clone + Default,
    StandardAlloc: Allocator<T>,
{
    inner: StandardMemory<T>,
    bytes: u64,
    meter: Option<Arc<AllocationMeter>>,
}

impl<T> Default for MeteredMemory<T>
where
    T: Clone + Default,
    StandardAlloc: Allocator<T>,
{
    fn default() -> Self {
        Self {
            inner: StandardMemory::<T>::default(),
            bytes: 0,
            meter: None,
        }
    }
}

impl<T> SliceWrapper<T> for MeteredMemory<T>
where
    T: Clone + Default,
    StandardAlloc: Allocator<T>,
{
    fn slice(&self) -> &[T] {
        self.inner.slice()
    }
}

impl<T> SliceWrapperMut<T> for MeteredMemory<T>
where
    T: Clone + Default,
    StandardAlloc: Allocator<T>,
{
    fn slice_mut(&mut self) -> &mut [T] {
        self.inner.slice_mut()
    }
}

impl<T> Drop for MeteredMemory<T>
where
    T: Clone + Default,
    StandardAlloc: Allocator<T>,
{
    fn drop(&mut self) {
        if let Some(meter) = &self.meter {
            meter.release(self.bytes);
        }
    }
}

struct MeteredAllocator<T> {
    standard: StandardAlloc,
    meter: Arc<AllocationMeter>,
    marker: PhantomData<fn() -> T>,
}

impl<T> MeteredAllocator<T> {
    fn new(meter: Arc<AllocationMeter>) -> Self {
        Self {
            standard: StandardAlloc::default(),
            meter,
            marker: PhantomData,
        }
    }
}

impl<T> Allocator<T> for MeteredAllocator<T>
where
    T: Clone + Default,
    StandardAlloc: Allocator<T>,
{
    type AllocatedMemory = MeteredMemory<T>;

    fn alloc_cell(&mut self, len: usize) -> Self::AllocatedMemory {
        let bytes = u64::try_from(len)
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<T>()).unwrap_or(u64::MAX));
        self.meter.allocate(bytes);
        MeteredMemory {
            inner: self.standard.alloc_cell(len),
            bytes,
            meter: Some(Arc::clone(&self.meter)),
        }
    }

    fn free_cell(&mut self, data: Self::AllocatedMemory) {
        drop(data);
    }
}

type BrotliMeteredAllocator = CombiningAllocator<
    MeteredAllocator<u8>,
    MeteredAllocator<u16>,
    MeteredAllocator<i32>,
    MeteredAllocator<u32>,
    MeteredAllocator<u64>,
    MeteredAllocator<Command>,
    MeteredAllocator<floatX>,
    MeteredAllocator<v8>,
    MeteredAllocator<s16>,
    MeteredAllocator<PDF>,
    MeteredAllocator<StaticCommand>,
    MeteredAllocator<HistogramLiteral>,
    MeteredAllocator<HistogramCommand>,
    MeteredAllocator<HistogramDistance>,
    MeteredAllocator<HistogramPair>,
    MeteredAllocator<ContextType>,
    MeteredAllocator<HuffmanTree>,
    MeteredAllocator<ZopfliNode>,
>;

fn brotli_allocator(meter: &Arc<AllocationMeter>) -> BrotliMeteredAllocator {
    CombiningAllocator::new(
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
        MeteredAllocator::new(Arc::clone(meter)),
    )
}

fn header<'a>(resp: &'a Response, name: &str) -> Option<&'a [u8]> {
    resp.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

fn header_str(resp: &Response, name: &str) -> Option<String> {
    header(resp, name).map(|v| String::from_utf8_lossy(v).into_owned())
}

fn cache_control_allows_transform(resp: &Response) -> bool {
    crate::http::response_cache_control(resp)
        .map(|directives| {
            !directives
                .iter()
                .any(|directive| directive.name == "no-transform")
        })
        // A malformed backend policy is not permission to transform the
        // representation.  Forward it unchanged and let the output boundary
        // apply its ordinary header validation.
        .unwrap_or(false)
}

fn remove_header(resp: &mut Response, name: &str) {
    resp.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
}

fn set_header(resp: &mut Response, name: &'static str, value: Vec<u8>) {
    remove_header(resp, name);
    resp.headers.push((Cow::Borrowed(name), value));
}

fn add_vary_value(resp: &mut Response, value: &str) {
    for (name, existing) in &mut resp.headers {
        if name.eq_ignore_ascii_case("vary") {
            let text = String::from_utf8_lossy(existing);
            if text.trim() == "*"
                || text
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case(value))
            {
                return;
            }
            let mut text = text.into_owned();
            if !text.is_empty() {
                text.push_str(", ");
            }
            text.push_str(value);
            *existing = text.into_bytes();
            return;
        }
    }
    resp.headers
        .push((Cow::Borrowed("Vary"), value.as_bytes().to_vec()));
}

fn add_vary_accept_encoding(resp: &mut Response) {
    for (name, value) in &resp.headers {
        if name.eq_ignore_ascii_case("vary") {
            let text = String::from_utf8_lossy(value);
            if text.trim() == "*"
                || text
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("accept-encoding"))
            {
                return;
            }
        }
    }
    for (name, value) in &mut resp.headers {
        if name.eq_ignore_ascii_case("vary") {
            let mut text = String::from_utf8_lossy(value).into_owned();
            if !text.is_empty() {
                text.push_str(", ");
            }
            text.push_str("Accept-Encoding");
            *value = text.into_bytes();
            return;
        }
    }
    resp.headers
        .push((Cow::Borrowed("Vary"), b"Accept-Encoding".to_vec()));
}

fn media_type(resp: &Response) -> Option<String> {
    header_str(resp, "content-type").map(|s| {
        s.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    })
}

fn configured_kinds(scope: &Scope, media: Option<&str>, path: &[u8]) -> Vec<CompressionKind> {
    let mut kinds: Vec<CompressionKind> = Vec::new();
    let ext = path
        .rsplit(|b| *b == b'/')
        .next()
        .and_then(|name| {
            name.iter()
                .rposition(|b| *b == b'.')
                .map(|p| &name[p + 1..])
        })
        .map(|e| String::from_utf8_lossy(e).to_ascii_lowercase())
        .unwrap_or_default();

    for rule in &scope.compression_policy.compression_rules {
        match rule {
            CompressionRule::Set(list) => kinds = list.clone(),
            CompressionRule::ByType(kind, types) => {
                let Some(media) = media else { continue };
                if types.iter().any(|t| {
                    let t = t.trim();
                    t == "*" || t.eq_ignore_ascii_case(media)
                }) {
                    kinds.push(*kind);
                }
            }
            CompressionRule::ByExt(kind, exts) => {
                if exts.iter().any(|e| {
                    let e = e.trim().trim_start_matches('.');
                    !e.is_empty() && e.eq_ignore_ascii_case(&ext)
                }) {
                    kinds.push(*kind);
                }
            }
        }
    }
    // Stable de-duplication, preserving configured preference.
    let mut out = Vec::new();
    for k in kinds {
        if !out.contains(&k) {
            out.push(k);
        }
    }
    out
}

pub(crate) fn unsupported_filters(scope: &Scope, media: Option<&str>, path: &[u8]) -> Vec<String> {
    let ext = path
        .rsplit(|byte| *byte == b'/')
        .next()
        .and_then(|name| {
            name.iter()
                .rposition(|byte| *byte == b'.')
                .map(|position| &name[position + 1..])
        })
        .map(|value| String::from_utf8_lossy(value).to_ascii_lowercase())
        .unwrap_or_default();
    let mut filters = Vec::new();
    for rule in &scope.compression_policy.unsupported_filter_rules {
        let (name, applies) = match rule {
            UnsupportedFilterRule::ByType(name, types) => (
                name,
                media.is_some_and(|media| {
                    types.iter().any(|configured| {
                        let configured = configured.trim();
                        configured == "*" || configured.eq_ignore_ascii_case(media)
                    })
                }),
            ),
            UnsupportedFilterRule::ByExt(name, extensions) => (
                name,
                extensions.iter().any(|configured| {
                    let configured = configured.trim().trim_start_matches('.');
                    !configured.is_empty() && configured.eq_ignore_ascii_case(&ext)
                }),
            ),
        };
        if applies
            && !filters
                .iter()
                .any(|filter: &String| filter.eq_ignore_ascii_case(name))
        {
            filters.push(name.clone());
        }
    }
    filters
}

fn accepts_encoding(req: &Request, kind: CompressionKind) -> bool {
    let Some(value) = req.header("accept-encoding") else {
        return false;
    };
    let Some(items) = crate::http_fields::parse_weighted_list(value) else {
        return false;
    };
    let wanted = kind.encoding().as_bytes();
    let mut wildcard = crate::http_fields::QValue::ZERO;
    let mut explicit = None;
    for item in items {
        if item.value == b"*" {
            wildcard = wildcard.max(item.quality);
        } else if item.value.eq_ignore_ascii_case(wanted)
            || (wanted == b"gzip" && item.value.eq_ignore_ascii_case(b"x-gzip"))
        {
            explicit = Some(item.quality);
        }
    }
    explicit.unwrap_or(wildcard).milli() > 0
}

fn alter_etag(resp: &mut Response, kind: CompressionKind, scope: &Scope) {
    let setting = match kind {
        CompressionKind::Gzip => scope.compression_policy.deflate_alter_etag,
        CompressionKind::Brotli => scope.compression_policy.brotli_alter_etag,
    }
    .unwrap_or(AlterEtag::AddSuffix);
    match setting {
        AlterEtag::NoChange => {}
        AlterEtag::Remove => remove_header(resp, "etag"),
        AlterEtag::AddSuffix => {
            let suffix = format!("-{}", kind.encoding());
            for (name, value) in &mut resp.headers {
                if !name.eq_ignore_ascii_case("etag") {
                    continue;
                }
                let mut text = String::from_utf8_lossy(value).into_owned();
                if text.ends_with(&suffix) || text.ends_with(&format!("{suffix}\"")) {
                    return;
                }
                if let Some(pos) = text.rfind('"') {
                    text.insert_str(pos, &suffix);
                } else {
                    text.push_str(&suffix);
                }
                *value = text.into_bytes();
                return;
            }
        }
    }
}

/// Return the entity-tag for the representation selected by the static-file
/// output filter. Preconditions run before the body is materialized, so they
/// cannot wait for `finalize_inner`; nevertheless a gzip tag must never match
/// an identity or Brotli representation (and vice versa).
///
/// `response` contains the static representation headers after `Header`
/// policy has run. This keeps an operator-supplied `Content-Encoding`,
/// `Cache-Control: no-transform`, or ETag mutation in the same decision path
/// as the real output filter.
pub(crate) fn conditional_static_etag(
    scope: &Scope,
    req: &Request,
    response: &Response,
    path: &[u8],
    body_len: u64,
) -> Option<String> {
    let current = header_str(response, "etag")?;
    let media = media_type(response);
    let kinds = configured_kinds(scope, media.as_deref(), path);
    if kinds.is_empty()
        || req.is_head()
        || body_len == 0
        || body_len > MAX_COMPRESS_BODY
        || req.header("range").is_some()
        || req.header("if-range").is_some()
        || header(response, "content-encoding").is_some()
        || !cache_control_allows_transform(response)
    {
        return Some(current);
    }
    let Some(kind) = [CompressionKind::Brotli, CompressionKind::Gzip]
        .into_iter()
        .find(|kind| kinds.contains(kind) && accepts_encoding(req, *kind))
    else {
        return Some(current);
    };
    let mut selected = Response::new(200);
    selected
        .headers
        .push((Cow::Borrowed("ETag"), current.into_bytes()));
    alter_etag(&mut selected, kind, scope);
    header_str(&selected, "etag")
}

struct ExactReader<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> Read for ExactReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || output.is_empty() {
            return Ok(0);
        }
        let want = output
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut output[..want])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short compression source",
            ));
        }
        self.remaining -= read as u64;
        Ok(read)
    }
}

fn take_body_reader(body: Body) -> Result<(Box<dyn Read + Send>, u64), Body> {
    match body {
        Body::Empty => Ok((Box::new(Cursor::new(Vec::new())), 0)),
        Body::Bytes(bytes) => match u64::try_from(bytes.len()) {
            Ok(len) if httpd_rs_verified::compression_body_admit(len, MAX_COMPRESS_BODY) => {
                Ok((Box::new(Cursor::new(bytes)), len))
            }
            _ => Err(Body::Bytes(bytes)),
        },
        Body::Stream { reader, len } => Err(Body::Stream { reader, len }),
        Body::UnknownLengthStream { reader, max_len } => {
            Err(Body::UnknownLengthStream { reader, max_len })
        }
        Body::File {
            mut file,
            offset,
            len,
        } => {
            if !httpd_rs_verified::compression_body_admit(len, MAX_COMPRESS_BODY) {
                return Err(Body::File { file, offset, len });
            }
            if file.seek(SeekFrom::Start(offset)).is_err() {
                return Err(Body::File { file, offset, len });
            }
            Ok((
                Box::new(ExactReader {
                    inner: file,
                    remaining: len,
                }),
                len,
            ))
        }
    }
}

fn max_encoded_len(kind: CompressionKind, input_len: u64) -> u64 {
    match kind {
        CompressionKind::Gzip => input_len.saturating_mul(2).saturating_add(64 * 1024),
        CompressionKind::Brotli => usize::try_from(input_len)
            .ok()
            .map(brotli::enc::BrotliEncoderMaxCompressedSize)
            .and_then(|len| u64::try_from(len).ok())
            .unwrap_or_else(|| input_len.saturating_mul(2).saturating_add(64 * 1024)),
    }
}

struct AdmittedEncoder {
    inner: Box<dyn Read + Send>,
    meter: Option<Arc<AllocationMeter>>,
    _lease: crate::resource::CompressionLease,
}

impl Read for AdmittedEncoder {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if let Some(meter) = &self.meter {
            meter.validate()?;
        }
        let read = self.inner.read(output)?;
        if let Some(meter) = &self.meter {
            meter.validate()?;
        }
        Ok(read)
    }
}

fn encoded_body(
    kind: CompressionKind,
    quality: u32,
    input: Box<dyn Read + Send>,
    input_len: u64,
    lease: crate::resource::CompressionLease,
    workspace_bound: u64,
) -> Body {
    let (inner, meter): (Box<dyn Read + Send>, Option<Arc<AllocationMeter>>) = match kind {
        CompressionKind::Gzip => (
            Box::new(flate2::read::GzEncoder::new(
                input,
                flate2::Compression::new(quality.min(9)),
            )),
            None,
        ),
        CompressionKind::Brotli => {
            let meter = Arc::new(AllocationMeter::new(workspace_bound));
            let mut buffer_allocator = MeteredAllocator::<u8>::new(Arc::clone(&meter));
            let buffer = buffer_allocator.alloc_cell(ENCODER_INPUT_BUFFER);
            let encoder = brotli::enc::reader::CompressorReaderCustomAlloc::new(
                input,
                buffer,
                brotli_allocator(&meter),
                quality,
                22,
            );
            (Box::new(encoder), Some(meter))
        }
    };
    Body::UnknownLengthStream {
        reader: Box::new(AdmittedEncoder {
            inner,
            meter,
            _lease: lease,
        }),
        max_len: max_encoded_len(kind, input_len),
    }
}

/// Apply the configured output filter to a response.
///
/// `path` is the request path used for extension-based `AddOutputFilter`
/// rules.  The function is idempotent: responses already carrying a
/// `Content-Encoding` are left alone.
pub fn finalize(scope: &Scope, req: &Request, resp: &mut Response, path: &[u8]) {
    finalize_inner(scope, req, resp, path, None);
}

/// Production entry point.  Reserve the worst-case transient footprint before
/// materializing a file body or allocating the encoded representation.
pub fn finalize_budgeted(
    scope: &Scope,
    req: &Request,
    resp: &mut Response,
    path: &[u8],
    budget: &Arc<crate::resource::ResourceBudget>,
) {
    finalize_inner(scope, req, resp, path, Some(budget));
}

/// Apply response metadata that shares the output-filter phase but does not
/// depend on compression. Callers that intentionally bypass body filtering
/// (for example `OPTIONS`) still need rewrite-generated `Vary`/cookies and
/// `mod_expires` policy.
pub(crate) fn finalize_metadata(scope: &Scope, resp: &mut Response) {
    for value in &scope.header_policy.vary {
        add_vary_value(resp, value);
    }
    for cookie in &scope.header_policy.cookies {
        if !resp.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("set-cookie") && value.as_slice() == cookie.as_bytes()
        }) {
            resp.headers
                .push((Cow::Borrowed("Set-Cookie"), cookie.as_bytes().to_vec()));
        }
    }
    crate::expires::apply(scope, resp);
}

fn finalize_inner(
    scope: &Scope,
    req: &Request,
    resp: &mut Response,
    path: &[u8],
    _budget: Option<&Arc<crate::resource::ResourceBudget>>,
) {
    finalize_metadata(scope, resp);
    if resp.status == 204 || resp.status == 205 || (100..200).contains(&resp.status) {
        return;
    }
    let media = media_type(resp);
    let kinds = configured_kinds(scope, media.as_deref(), path);
    if kinds.is_empty() {
        return;
    }
    add_vary_accept_encoding(resp);

    // Compression changes the representation, so byte ranges and conditional
    // range validators continue to use the identity representation.
    if req.header("range").is_some() || req.header("if-range").is_some() {
        return;
    }
    if header(resp, "content-encoding").is_some() {
        return;
    }
    if !cache_control_allows_transform(resp) {
        return;
    }
    let kind = [CompressionKind::Brotli, CompressionKind::Gzip]
        .into_iter()
        .find(|k| kinds.contains(k) && accepts_encoding(req, *k));
    let Some(kind) = kind else {
        return;
    };

    if resp.status == 304 {
        alter_etag(resp, kind, scope);
        set_header(
            resp,
            "Content-Encoding",
            kind.encoding().as_bytes().to_vec(),
        );
        return;
    }
    // HEAD has no body to compress; keep the identity headers/length rather
    // than advertising an encoded representation whose length we cannot know.
    if req.is_head() {
        return;
    }

    #[cfg(test)]
    let fallback_context;
    let resource_context = match req.resource_context() {
        Some(context) => context,
        #[cfg(test)]
        None => {
            fallback_context = crate::resource::current_or_test_context();
            &fallback_context
        }
        #[cfg(not(test))]
        None => return,
    };
    let quality = match kind {
        CompressionKind::Gzip => scope
            .compression_policy
            .deflate_level
            .unwrap_or(DEFAULT_DEFLATE_LEVEL),
        CompressionKind::Brotli => scope
            .compression_policy
            .brotli_quality
            .unwrap_or(DEFAULT_BROTLI_QUALITY),
    };
    let verified_kind = match kind {
        CompressionKind::Gzip => httpd_rs_verified::DynamicCompressionKind::Gzip,
        CompressionKind::Brotli => httpd_rs_verified::DynamicCompressionKind::Brotli,
    };
    let Some(input_len) = resp.body.known_len() else {
        return;
    };
    let Some(profile) =
        httpd_rs_verified::dynamic_compression_budget(verified_kind, quality, input_len)
    else {
        // Qualities 10/11 perform a long, non-interruptible Zopfli search in
        // the dependency. They are intentionally unavailable for request-time
        // encoding; operators can precompress immutable assets instead.
        return;
    };
    let Some(compression_lease) = crate::resource::try_compression_in(
        resource_context,
        profile.work_units,
        profile.transient_bytes,
    ) else {
        // Compression is optional. Preserve the identity representation under
        // CPU or memory pressure instead of queueing transformation work.
        return;
    };
    let body = std::mem::replace(&mut resp.body, Body::Empty);
    let (input, _) = match take_body_reader(body) {
        Ok(value) => value,
        Err(body) => {
            resp.body = body;
            return;
        }
    };
    resp.body = encoded_body(
        kind,
        quality,
        input,
        input_len,
        compression_lease,
        profile.workspace_bytes,
    );
    set_header(
        resp,
        "Content-Encoding",
        kind.encoding().as_bytes().to_vec(),
    );
    remove_header(resp, "Content-Length");
    set_header(resp, "Accept-Ranges", b"none".to_vec());
    alter_etag(resp, kind, scope);
}

/// Drive the real Brotli output path as a resource-lifecycle state machine.
///
/// The input controls quality, downstream consumption/cancellation, budget
/// pressure, body shape/size and output-filter bypasses.  Successful streams
/// must round-trip, rejected qualities and pressure must preserve identity,
/// the metered allocator must stay inside the verified workspace profile, and
/// every exit must release the hierarchical compression lease.
#[cfg(feature = "fuzzing")]
pub fn fuzz_brotli_resource(data: &[u8]) {
    const MAX_FUZZ_BODY: usize = 256 * 1024;
    if data.len() < 7 {
        return;
    }

    let quality = u32::from(data[0] % 12);
    let consume = data[1] % 4;
    let pressure = data[2] % 3;
    let pattern = data[3] % 4;
    let size_class = data[4] % 5;
    let gate = data[5] % 7;
    let entropy = &data[7..];
    let requested_len = match size_class {
        0 => entropy.len().min(MAX_FUZZ_BODY),
        1 => 0,
        2 => 1,
        3 => 4 * 1024,
        _ => MAX_FUZZ_BODY,
    };
    let fallback = data[6];
    let mut source = Vec::with_capacity(requested_len);
    for index in 0..requested_len {
        let byte = match pattern {
            0 => entropy
                .get(index % entropy.len().max(1))
                .copied()
                .unwrap_or(fallback),
            1 => fallback,
            2 => fallback.wrapping_add(index as u8),
            _ => {
                if index & 1 == 0 {
                    fallback
                } else {
                    !fallback
                }
            }
        };
        source.push(byte);
    }

    let budget = Arc::new(crate::resource::ResourceBudget::default());
    let client = std::net::IpAddr::from([192, 0, 2, 41]);
    let mut headers = crate::http::Headers::default();
    headers.insert("accept-encoding", b"br".to_vec());
    headers.bind_request_scope(crate::resource::RequestScope::new(budget.context(client)));
    let mut request = Request {
        method: "GET".into(),
        target: b"/fuzz.txt".to_vec(),
        raw_path: b"/fuzz.txt".to_vec(),
        query: Vec::new(),
        version: crate::http::Version::Http11,
        headers,
        body: Vec::new(),
        body_spool: None,
        keep_alive: true,
        expect_continue: false,
        framing: crate::verified::BodyFraming::None,
    };

    let context = request
        .resource_context()
        .expect("fuzz request lost its resource context");
    let pressure_lease = match pressure {
        1 => crate::resource::try_compression_in(
            context,
            crate::resource::MAX_COMPRESSION_WORK_UNITS_PER_CLIENT,
            1,
        ),
        2 => crate::resource::try_compression_in(
            context,
            1,
            crate::resource::MAX_COMPRESSION_TRANSIENT_BYTES_PER_CLIENT,
        ),
        _ => None,
    };
    if pressure != 0 {
        assert!(
            pressure_lease.is_some(),
            "failed to establish fuzz pressure"
        );
    }

    let mut scope = Scope::default();
    scope
        .compression_policy
        .compression_rules
        .push(CompressionRule::Set(vec![CompressionKind::Brotli]));
    scope.compression_policy.brotli_quality = Some(quality);
    let mut response = Response::new(200);
    response
        .headers
        .push((Cow::Borrowed("Content-Type"), b"text/plain".to_vec()));
    response.body = Body::Bytes(source.clone());

    match gate {
        1 => request.headers.insert("range", b"bytes=0-1".to_vec()),
        2 => response.headers.push((
            Cow::Borrowed("Cache-Control"),
            b"public, no-transform".to_vec(),
        )),
        3 => response
            .headers
            .push((Cow::Borrowed("Content-Encoding"), b"gzip".to_vec())),
        4 => request.method = "HEAD".into(),
        5 => response.status = 204,
        6 => {
            response.body = Body::Stream {
                reader: Box::new(Cursor::new(Vec::new())),
                len: MAX_COMPRESS_BODY + 1,
            };
        }
        _ => {}
    }

    let admitted_profile = httpd_rs_verified::dynamic_compression_budget(
        httpd_rs_verified::DynamicCompressionKind::Brotli,
        quality,
        if gate == 6 {
            MAX_COMPRESS_BODY + 1
        } else {
            source.len() as u64
        },
    );
    finalize_budgeted(&scope, &request, &mut response, b"/fuzz.txt", &budget);

    let selected = header(&response, "content-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case(b"br"));
    let should_select = gate == 0 && pressure == 0 && admitted_profile.is_some();
    assert_eq!(
        selected, should_select,
        "Brotli admission disagreed with the verified resource profile"
    );

    if selected {
        assert!(
            !budget.transition_usage_is_zero(),
            "encoded body did not retain its compression lease"
        );
        let Body::UnknownLengthStream {
            mut reader,
            max_len,
        } = std::mem::replace(&mut response.body, Body::Empty)
        else {
            panic!("admitted Brotli response was not streamed");
        };
        assert_eq!(
            max_len,
            max_encoded_len(CompressionKind::Brotli, source.len() as u64)
        );

        let mut encoded = Vec::new();
        match consume {
            0 => {}
            1 => {
                let mut prefix = vec![0u8; usize::from(data[6]).max(1)];
                reader
                    .read(&mut prefix)
                    .expect("metered Brotli prefix read");
            }
            2 => {
                reader
                    .read_to_end(&mut encoded)
                    .expect("metered Brotli full read");
            }
            _ => {
                let chunk_len = 64 + usize::from(data[6]) * 32;
                let mut chunk = vec![0u8; chunk_len];
                loop {
                    let read = reader.read(&mut chunk).expect("metered Brotli chunk read");
                    if read == 0 {
                        break;
                    }
                    encoded.extend_from_slice(&chunk[..read]);
                    assert!(encoded.len() as u64 <= max_len);
                }
            }
        }
        drop(reader);

        if consume >= 2 {
            let mut decoded = Vec::new();
            brotli::Decompressor::new(Cursor::new(encoded), 4096)
                .read_to_end(&mut decoded)
                .expect("Brotli fuzz output did not decode");
            assert_eq!(decoded, source, "Brotli round trip changed the body");
        }
    }

    drop(response);
    drop(pressure_lease);
    drop(request);
    assert!(
        budget.transition_usage_is_zero(),
        "Brotli completion/cancellation retained a resource lease"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CompressionKind, CompressionRule, Scope, UnsupportedFilterRule};
    use crate::http::{Body, Headers, Request, Response, Version};
    use crate::resource::{RequestScope, ResourceBudget};
    use std::net::{IpAddr, Ipv4Addr};

    fn request(accept: &str) -> Request {
        let mut headers = Headers::default();
        headers.insert("accept-encoding", accept.as_bytes().to_vec());
        Request {
            method: "GET".into(),
            target: b"/index.html".to_vec(),
            raw_path: b"/index.html".to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers,
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn response(body: &[u8], content_type: &str) -> Response {
        let mut r = Response::new(200);
        r.headers.push((
            Cow::Borrowed("Content-Type"),
            content_type.as_bytes().to_vec(),
        ));
        r.headers.push((Cow::Borrowed("ETag"), b"\"abc\"".to_vec()));
        r.body = Body::Bytes(body.to_vec());
        r
    }

    fn request_in_budget(accept: &str, budget: &Arc<ResourceBudget>, client: IpAddr) -> Request {
        let mut request = request(accept);
        request
            .headers
            .bind_request_scope(RequestScope::new(budget.context(client)));
        request
    }

    fn take_body_bytes(response: &mut Response) -> io::Result<Vec<u8>> {
        match std::mem::replace(&mut response.body, Body::Empty) {
            Body::Empty => Ok(Vec::new()),
            Body::Bytes(bytes) => Ok(bytes),
            Body::UnknownLengthStream { mut reader, .. } | Body::Stream { mut reader, len: _ } => {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes)?;
                Ok(bytes)
            }
            Body::File { .. } => Err(io::Error::other("unexpected file body")),
        }
    }

    #[test]
    fn gzip_and_brotli_are_negotiated_and_vary_is_added() {
        let mut scope = Scope::default();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::ByType(
                CompressionKind::Gzip,
                vec!["text/html".into()],
            ));
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::ByType(
                CompressionKind::Brotli,
                vec!["text/html".into()],
            ));

        let mut r = response(b"hello hello hello", "text/html; charset=utf-8");
        finalize(&scope, &request("gzip, br"), &mut r, b"/index.html");
        assert_eq!(header_str(&r, "content-encoding").as_deref(), Some("br"));
        assert_eq!(header_str(&r, "vary").as_deref(), Some("Accept-Encoding"));
        assert!(header(&r, "content-length").is_none());
        assert!(header_str(&r, "etag").unwrap().ends_with("-br\""));
        let encoded = take_body_bytes(&mut r).unwrap();
        let mut decoded = Vec::new();
        brotli::Decompressor::new(Cursor::new(encoded), 4096)
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, b"hello hello hello");

        let mut r = response(b"hello hello hello", "text/html");
        finalize(&scope, &request("gzip"), &mut r, b"/index.html");
        assert_eq!(header_str(&r, "content-encoding").as_deref(), Some("gzip"));
        assert!(header_str(&r, "etag").unwrap().ends_with("-gzip\""));
        let encoded = take_body_bytes(&mut r).unwrap();
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(Cursor::new(encoded))
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, b"hello hello hello");
    }

    #[test]
    fn q_zero_and_unlisted_types_are_not_compressed() {
        let mut scope = Scope::default();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::ByType(
                CompressionKind::Gzip,
                vec!["text/html".into()],
            ));
        let mut r = response(b"hello", "application/octet-stream");
        finalize(&scope, &request("gzip"), &mut r, b"/x.bin");
        assert!(header(&r, "content-encoding").is_none());

        let mut r = response(b"hello", "text/html");
        finalize(&scope, &request("gzip;q=0"), &mut r, b"/x.html");
        assert!(header(&r, "content-encoding").is_none());
        assert_eq!(header_str(&r, "vary").as_deref(), Some("Accept-Encoding"));

        for status in [101, 204, 205] {
            let mut r = response(b"must not compress", "text/html");
            r.status = status;
            finalize(&scope, &request("gzip"), &mut r, b"/x.html");
            assert!(header(&r, "content-encoding").is_none());
        }
    }

    #[test]
    fn unsupported_filters_apply_only_to_their_configured_extension_or_type() {
        let mut scope = Scope::default();
        scope
            .compression_policy
            .unsupported_filter_rules
            .push(UnsupportedFilterRule::ByExt(
                "INCLUDES".into(),
                vec![".shtml".into()],
            ));
        scope
            .compression_policy
            .unsupported_filter_rules
            .push(UnsupportedFilterRule::ByType(
                "CUSTOM".into(),
                vec!["application/x-custom".into()],
            ));

        assert!(unsupported_filters(&scope, Some("text/html"), b"index.html").is_empty());
        assert_eq!(
            unsupported_filters(&scope, Some("text/html"), b"include.shtml"),
            vec!["INCLUDES"]
        );
        assert_eq!(
            unsupported_filters(&scope, Some("application/x-custom"), b"index.html"),
            vec!["CUSTOM"]
        );
    }

    #[test]
    fn ranges_and_no_transform_bypass_compression() {
        let mut scope = Scope::default();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::Set(vec![CompressionKind::Gzip]));
        let mut req = request("gzip");
        req.headers.insert("range", b"bytes=0-3".to_vec());
        let mut r = response(b"hello", "text/html");
        finalize(&scope, &req, &mut r, b"/x.html");
        assert!(header(&r, "content-encoding").is_none());

        let mut r = response(b"hello", "text/html");
        r.headers
            .push((Cow::Borrowed("Cache-Control"), b"no-transform".to_vec()));
        finalize(&scope, &request("gzip"), &mut r, b"/x.html");
        assert!(header(&r, "content-encoding").is_none());

        let mut split = response(b"hello", "text/html");
        split.headers.extend([
            (Cow::Borrowed("Cache-Control"), b"public".to_vec()),
            (Cow::Borrowed("Cache-Control"), b"no-transform".to_vec()),
        ]);
        finalize(&scope, &request("gzip"), &mut split, b"/x.html");
        assert!(header(&split, "content-encoding").is_none());

        let mut malformed = response(b"hello", "text/html");
        malformed.headers.push((
            Cow::Borrowed("Cache-Control"),
            b"public, extension=\"unterminated".to_vec(),
        ));
        finalize(&scope, &request("gzip"), &mut malformed, b"/x.html");
        assert!(header(&malformed, "content-encoding").is_none());
    }

    #[test]
    fn conditional_etag_honors_no_transform() {
        let mut scope = Scope::default();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::Set(vec![CompressionKind::Gzip]));
        let mut r = response(b"hello", "text/html");
        r.headers.push((
            Cow::Borrowed("Cache-Control"),
            b"public, No-Transform".to_vec(),
        ));
        assert_eq!(
            conditional_static_etag(&scope, &request("gzip"), &r, b"/x.html", 5).as_deref(),
            Some("\"abc\"")
        );

        let mut split = response(b"hello", "text/html");
        split.headers.extend([
            (Cow::Borrowed("Cache-Control"), b"public".to_vec()),
            (Cow::Borrowed("Cache-Control"), b"No-Transform".to_vec()),
        ]);
        assert_eq!(
            conditional_static_etag(&scope, &request("gzip"), &split, b"/x.html", 5).as_deref(),
            Some("\"abc\"")
        );
    }

    #[test]
    fn compression_pressure_preserves_identity_representation() {
        let mut scope = Scope::default();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::Set(vec![CompressionKind::Gzip]));
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);

        let expensive_budget = Arc::new(ResourceBudget::default());
        let expensive_request = request_in_budget("gzip", &expensive_budget, client);
        let context = expensive_request.resource_context().unwrap();
        let _expensive = crate::resource::try_compression_in(
            context,
            crate::resource::MAX_COMPRESSION_WORK_UNITS_PER_CLIENT,
            1,
        )
        .unwrap();
        let mut under_cpu_pressure = response(b"identity", "text/plain");
        finalize_budgeted(
            &scope,
            &expensive_request,
            &mut under_cpu_pressure,
            b"/x.txt",
            &expensive_budget,
        );
        assert_eq!(under_cpu_pressure.body_len(), 8);
        assert!(header(&under_cpu_pressure, "content-encoding").is_none());

        let resident_budget = Arc::new(ResourceBudget::default());
        let resident_request = request_in_budget("gzip", &resident_budget, client);
        let _occupied = crate::resource::try_compression_in(
            resident_request.resource_context().unwrap(),
            1,
            crate::resource::MAX_COMPRESSION_TRANSIENT_BYTES_PER_CLIENT,
        )
        .unwrap();
        let mut under_memory_pressure = response(b"identity", "text/plain");
        finalize_budgeted(
            &scope,
            &resident_request,
            &mut under_memory_pressure,
            b"/x.txt",
            &resident_budget,
        );
        assert_eq!(under_memory_pressure.body_len(), 8);
        assert!(header(&under_memory_pressure, "content-encoding").is_none());
    }

    #[test]
    fn extension_rules_and_set_filter_work() {
        let mut scope = Scope::default();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::ByExt(
                CompressionKind::Gzip,
                vec![".css".into()],
            ));
        let mut r = response(b"body{}", "text/css");
        finalize(&scope, &request("gzip"), &mut r, b"/style.css");
        assert_eq!(header_str(&r, "content-encoding").as_deref(), Some("gzip"));

        scope.compression_policy.compression_rules.clear();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::Set(vec![CompressionKind::Gzip]));
        let mut r = response(b"body", "application/octet-stream");
        finalize(&scope, &request("gzip"), &mut r, b"/x.bin");
        assert_eq!(header_str(&r, "content-encoding").as_deref(), Some("gzip"));
    }

    #[test]
    fn verified_compression_profile_is_the_runtime_budget_source() {
        use httpd_rs_verified::{dynamic_compression_budget, DynamicCompressionKind as Kind};

        let largest = dynamic_compression_budget(Kind::Brotli, 9, MAX_COMPRESS_BODY).unwrap();
        assert_eq!(largest.workspace_bytes, 64 * 1024 * 1024);
        assert_eq!(largest.work_units, 512);
        assert_eq!(
            largest.transient_bytes,
            MAX_COMPRESS_BODY + 64 * 1024 * 1024 + 128 * 1024
        );
        assert!(dynamic_compression_budget(Kind::Brotli, 10, 1).is_none());
        assert!(dynamic_compression_budget(Kind::Brotli, 11, MAX_COMPRESS_BODY).is_none());
        assert!(dynamic_compression_budget(Kind::Gzip, 10, 1).is_none());
        assert!(dynamic_compression_budget(Kind::Gzip, 6, 0).is_none());
        assert!(dynamic_compression_budget(Kind::Gzip, 6, MAX_COMPRESS_BODY + 1).is_none());
    }

    #[test]
    fn dynamic_brotli_is_metered_cancellable_and_excludes_zopfli_qualities() {
        let mut scope = Scope::default();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::Set(vec![CompressionKind::Brotli]));
        let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));

        // Configuration rejects this too, but the execution boundary remains
        // fail-closed if a synthetic Scope bypasses the parser.
        scope.compression_policy.brotli_quality = Some(10);
        let mut rejected = response(&vec![b'x'; 1024], "text/plain");
        finalize(&scope, &request("br"), &mut rejected, b"/x.txt");
        assert!(header(&rejected, "content-encoding").is_none());
        assert!(matches!(rejected.body, Body::Bytes(_)));

        let budget = Arc::new(ResourceBudget::default());
        let request = request_in_budget("br", &budget, client);
        scope.compression_policy.brotli_quality = Some(9);
        let mut encoded = response(&vec![b'a'; 1024 * 1024], "text/plain");
        finalize_budgeted(&scope, &request, &mut encoded, b"/x.txt", &budget);
        assert_eq!(
            header_str(&encoded, "content-encoding").as_deref(),
            Some("br")
        );
        assert!(!budget.transition_usage_is_zero());

        let Body::UnknownLengthStream { mut reader, .. } =
            std::mem::replace(&mut encoded.body, Body::Empty)
        else {
            panic!("Brotli response was not deferred into the output path");
        };
        let mut first_chunk = [0u8; 4096];
        assert!(reader.read(&mut first_chunk).unwrap() > 0);
        drop(reader);
        drop(encoded);
        assert!(budget.transition_usage_is_zero());
    }

    #[test]
    fn metered_brotli_allocator_tracks_and_releases_real_workspace() {
        let meter = Arc::new(AllocationMeter::new(1024));
        let mut allocator = MeteredAllocator::<u64>::new(Arc::clone(&meter));
        let memory = allocator.alloc_cell(16);
        assert_eq!(meter.peak(), 128);
        meter.validate().unwrap();
        allocator.free_cell(memory);
        assert_eq!(meter.current.load(Ordering::Acquire), 0);
    }

    #[test]
    fn supported_brotli_profiles_stay_inside_admitted_workspace_bounds() {
        fn patterned_bytes(len: usize) -> Vec<u8> {
            let mut state = 0x6a09_e667_f3bc_c909u64;
            (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect()
        }

        let supported_profiles = (0..=9)
            .map(|quality| (quality, 256 * 1024))
            .chain([(5, 8 * 1024 * 1024), (9, 1024 * 1024)]);
        for (quality, input_len) in supported_profiles {
            let bound = httpd_rs_verified::dynamic_compression_budget(
                httpd_rs_verified::DynamicCompressionKind::Brotli,
                quality,
                input_len as u64,
            )
            .unwrap()
            .workspace_bytes;
            let meter = Arc::new(AllocationMeter::new(bound));
            let mut buffer_allocator = MeteredAllocator::<u8>::new(Arc::clone(&meter));
            let buffer = buffer_allocator.alloc_cell(ENCODER_INPUT_BUFFER);
            let mut encoder = brotli::enc::reader::CompressorReaderCustomAlloc::new(
                Cursor::new(patterned_bytes(input_len)),
                buffer,
                brotli_allocator(&meter),
                quality,
                22,
            );
            let mut output = Vec::new();
            encoder.read_to_end(&mut output).unwrap();
            assert!(!output.is_empty());
            meter.validate().unwrap();
            assert!(
                meter.peak() <= bound,
                "quality {quality} used {} bytes beyond its {bound}-byte workspace admission",
                meter.peak()
            );
            drop(encoder);
            assert_eq!(
                meter.current.load(Ordering::Acquire),
                0,
                "quality {quality} retained allocator-owned memory"
            );
        }
    }

    #[test]
    fn vary_quality_and_etag_helpers_cover_all_settings() {
        let mut fresh = Response::new(200);
        add_vary_value(&mut fresh, "Origin");
        assert_eq!(header_str(&fresh, "vary").as_deref(), Some("Origin"));

        let mut r = Response::new(200);
        r.headers.push((Cow::Borrowed("Vary"), Vec::new()));
        add_vary_value(&mut r, "Origin");
        add_vary_value(&mut r, "Accept-Language");
        add_vary_value(&mut r, "origin");
        assert_eq!(
            header_str(&r, "vary").as_deref(),
            Some("Origin, Accept-Language")
        );
        r.headers[0].1 = b"*".to_vec();
        add_vary_value(&mut r, "Anything");
        assert_eq!(header_str(&r, "vary").as_deref(), Some("*"));

        add_vary_accept_encoding(&mut r);
        assert_eq!(header_str(&r, "vary").as_deref(), Some("*"));
        r.headers[0].1 = b"Origin".to_vec();
        add_vary_accept_encoding(&mut r);
        assert_eq!(
            header_str(&r, "vary").as_deref(),
            Some("Origin, Accept-Encoding")
        );
        add_vary_accept_encoding(&mut r);

        let no_encoding = request("");
        let mut no_encoding = no_encoding;
        no_encoding.headers.remove("accept-encoding");
        assert!(!accepts_encoding(&no_encoding, CompressionKind::Gzip));
        assert!(!accepts_encoding(
            &request("*;q=.4"),
            CompressionKind::Brotli
        ));
        assert!(accepts_encoding(
            &request("*;q=0.4"),
            CompressionKind::Brotli
        ));
        assert!(!accepts_encoding(
            &request("gzip;q=2"),
            CompressionKind::Gzip
        ));
        assert!(!accepts_encoding(
            &request("gzip;quality=1;broken"),
            CompressionKind::Gzip
        ));
        assert!(accepts_encoding(&request("x-gzip"), CompressionKind::Gzip));
        assert!(accepts_encoding(
            &request("gzip; level=9; q=1"),
            CompressionKind::Gzip
        ));

        let mut scope = Scope::default();
        let mut r = response(b"x", "text/plain");
        scope.compression_policy.deflate_alter_etag = Some(AlterEtag::NoChange);
        alter_etag(&mut r, CompressionKind::Gzip, &scope);
        assert_eq!(header_str(&r, "etag").as_deref(), Some("\"abc\""));
        scope.compression_policy.deflate_alter_etag = Some(AlterEtag::Remove);
        alter_etag(&mut r, CompressionKind::Gzip, &scope);
        assert!(header(&r, "etag").is_none());

        let mut r = Response::new(200);
        r.headers.push((Cow::Borrowed("ETag"), b"plain".to_vec()));
        scope.compression_policy.deflate_alter_etag = Some(AlterEtag::AddSuffix);
        alter_etag(&mut r, CompressionKind::Gzip, &scope);
        alter_etag(&mut r, CompressionKind::Gzip, &scope);
        assert_eq!(header_str(&r, "etag").as_deref(), Some("plain-gzip"));
    }

    #[test]
    fn body_reader_and_finalize_bypass_edges() {
        assert!(matches!(take_body_reader(Body::Empty), Ok((_, 0))));
        assert!(matches!(
            take_body_reader(Body::Stream {
                reader: Box::new(std::io::Cursor::new(b"stream".to_vec())),
                len: 6,
            }),
            Err(Body::Stream { len: 6, .. })
        ));

        let path = std::env::temp_dir().join(format!("httpd-rs-compress-{}", std::process::id()));
        std::fs::write(&path, b"short").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        assert!(matches!(
            take_body_reader(Body::File {
                file,
                offset: 0,
                len: MAX_COMPRESS_BODY + 1,
            }),
            Err(Body::File { .. })
        ));
        let file = std::fs::File::open(&path).unwrap();
        let Ok((mut short, len)) = take_body_reader(Body::File {
            file,
            offset: 0,
            len: 20,
        }) else {
            panic!("bounded file body was rejected")
        };
        assert_eq!(len, 20);
        assert!(io::copy(&mut short, &mut io::sink()).is_err());
        let file = std::fs::File::open(&path).unwrap();
        let Ok((mut exact, len)) = take_body_reader(Body::File {
            file,
            offset: 0,
            len: 5,
        }) else {
            panic!("exact file body was rejected")
        };
        assert_eq!(len, 5);
        let mut exact_bytes = Vec::new();
        exact.read_to_end(&mut exact_bytes).unwrap();
        assert_eq!(exact_bytes, b"short");
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let file = std::fs::File::from(std::os::fd::OwnedFd::from(stream));
        assert!(matches!(
            take_body_reader(Body::File {
                file,
                offset: 1,
                len: 1,
            }),
            Err(Body::File { .. })
        ));
        std::fs::remove_file(path).unwrap();

        let mut scope = Scope::default();
        scope
            .compression_policy
            .compression_rules
            .push(CompressionRule::Set(vec![CompressionKind::Gzip]));
        scope.header_policy.vary.push("Origin".into());
        scope.header_policy.cookies.push("a=b".into());
        scope.header_policy.cookies.push("a=b".into());

        let mut r = response(b"body", "text/plain");
        r.headers
            .push((Cow::Borrowed("Content-Encoding"), b"identity".to_vec()));
        finalize(&scope, &request("gzip"), &mut r, b"/x");
        assert_eq!(
            header_str(&r, "content-encoding").as_deref(),
            Some("identity")
        );

        let mut head = request("gzip");
        head.method = "HEAD".into();
        let mut r = response(b"body", "text/plain");
        finalize(&scope, &head, &mut r, b"/x");
        assert!(header(&r, "content-encoding").is_none());

        let mut r = response(b"", "text/plain");
        finalize(&scope, &request("gzip"), &mut r, b"/x");
        assert!(header(&r, "content-encoding").is_none());

        let mut r = Response::new(304);
        r.headers
            .push((Cow::Borrowed("ETag"), b"\"cached\"".to_vec()));
        finalize(&scope, &request("gzip"), &mut r, b"/x");
        assert_eq!(header_str(&r, "content-encoding").as_deref(), Some("gzip"));

        let mut r = response(b"ignored", "text/plain");
        r.body = Body::Stream {
            reader: Box::new(std::io::Cursor::new(b"stream".to_vec())),
            len: 6,
        };
        finalize(&scope, &request("gzip"), &mut r, b"/x");
        assert!(matches!(r.body, Body::Stream { .. }));

        let oversized = vec![b'x'; MAX_COMPRESS_BODY as usize + 1];
        let mut r = response(&oversized, "text/plain");
        finalize(&scope, &request("gzip"), &mut r, b"/x");
        assert!(header(&r, "content-encoding").is_none());
        assert_eq!(r.body_len(), oversized.len() as u64);
    }
}
