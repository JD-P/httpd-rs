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
use std::borrow::Cow;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

const MAX_COMPRESS_BODY: u64 = 8 * 1024 * 1024;
const DEFAULT_DEFLATE_LEVEL: u32 = 6;
const DEFAULT_BROTLI_QUALITY: u32 = 5;

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

fn read_body(body: Body) -> Result<Vec<u8>, Body> {
    match body {
        Body::Empty => Ok(Vec::new()),
        Body::Bytes(bytes) => {
            if !vapache_verified::compression_body_admit(bytes.len() as u64, MAX_COMPRESS_BODY) {
                return Err(Body::Bytes(bytes));
            }
            Ok(bytes)
        }
        Body::Stream { reader, len } => Err(Body::Stream { reader, len }),
        Body::File {
            mut file,
            offset,
            len,
        } => {
            if !vapache_verified::compression_body_admit(len, MAX_COMPRESS_BODY) {
                return Err(Body::File { file, offset, len });
            }
            if file.seek(SeekFrom::Start(offset)).is_err() {
                return Err(Body::File { file, offset, len });
            }
            let mut bytes = vec![0u8; len as usize];
            if file.read_exact(&mut bytes).is_err() {
                return Err(Body::File { file, offset, len });
            }
            Ok(bytes)
        }
    }
}

fn gzip(data: &[u8], level: u32) -> Vec<u8> {
    let mut encoder =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(level.min(9)));
    encoder
        .write_all(data)
        .expect("writing compressed bytes to Vec is infallible");
    encoder
        .finish()
        .expect("finishing compressed bytes in Vec is infallible")
}

fn brotli(data: &[u8], quality: u32) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut encoder = brotli::CompressorWriter::new(&mut out, 4096, quality.min(11), 22);
        encoder
            .write_all(data)
            .expect("writing compressed bytes to Vec is infallible");
        encoder
            .flush()
            .expect("flushing compressed bytes to Vec is infallible");
        encoder.into_inner();
    }
    out
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
    budget: Option<&Arc<crate::resource::ResourceBudget>>,
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
    let Some(_expensive) = crate::resource::try_expensive_in(resource_context) else {
        // Compression is optional. Under CPU pressure preserve and send the
        // identity representation instead of queueing more expensive work.
        return;
    };
    let mut compression_lease = budget.map(|budget| {
        let mut lease = budget.try_response_bytes_in(resource_context)?;
        let peak = resp.body_len().saturating_mul(2).saturating_add(64 * 1024);
        lease.reserve(peak).map(|()| lease)
    });
    if compression_lease.as_ref().is_some_and(Result::is_err) {
        // Compression is optional; preserve the identity representation when
        // admitting its transient working set would exceed the process cap.
        return;
    }
    let body = std::mem::replace(&mut resp.body, Body::Empty);
    let raw = match read_body(body) {
        Ok(v) => v,
        Err(body) => {
            resp.body = body;
            return;
        }
    };
    if raw.is_empty() {
        resp.body = Body::Bytes(raw);
        return;
    }
    let encoded = match kind {
        CompressionKind::Gzip => gzip(
            &raw,
            scope
                .compression_policy
                .deflate_level
                .unwrap_or(DEFAULT_DEFLATE_LEVEL),
        ),
        CompressionKind::Brotli => brotli(
            &raw,
            scope
                .compression_policy
                .brotli_quality
                .unwrap_or(DEFAULT_BROTLI_QUALITY),
        ),
    };
    // Compression admission covers the identity and encoded buffers at their
    // simultaneous peak. Retire the identity allocation before converting
    // that peak lease into the retained encoded-response lease below.
    drop(raw);
    let len = encoded.len();
    resp.body = Body::Bytes(encoded);
    set_header(
        resp,
        "Content-Encoding",
        kind.encoding().as_bytes().to_vec(),
    );
    set_header(resp, "Content-Length", len.to_string().into_bytes());
    set_header(resp, "Accept-Ranges", b"none".to_vec());
    alter_etag(resp, kind, scope);
    if let Some(Ok(mut lease)) = compression_lease.take() {
        // The 2x reservation covers the simultaneous identity and encoded
        // working set only. Retain accounting for the encoded representation,
        // not the transient peak, while a downstream client consumes it.
        lease.release(lease.bytes().saturating_sub(len as u64));
        resp.hold_resident(lease);
    }
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
        assert_eq!(
            header_str(&r, "content-length").unwrap(),
            r.body_len().to_string()
        );
        assert!(header_str(&r, "etag").unwrap().ends_with("-br\""));

        let mut r = response(b"hello hello hello", "text/html");
        finalize(&scope, &request("gzip"), &mut r, b"/index.html");
        assert_eq!(header_str(&r, "content-encoding").as_deref(), Some("gzip"));
        assert!(header_str(&r, "etag").unwrap().ends_with("-gzip\""));
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
        let _expensive = (0..crate::resource::MAX_EXPENSIVE_OPS_PER_CLIENT)
            .map(|_| crate::resource::try_expensive_in(context).unwrap())
            .collect::<Vec<_>>();
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
        let mut occupied = resident_budget.try_response_bytes_for(client);
        occupied
            .reserve(crate::resource::MAX_RESPONSE_RESIDENT_BYTES_PER_CLIENT)
            .unwrap();
        let resident_request = request_in_budget("gzip", &resident_budget, client);
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
        assert!(matches!(read_body(Body::Empty), Ok(bytes) if bytes.is_empty()));
        assert!(matches!(
            read_body(Body::Stream {
                reader: Box::new(std::io::Cursor::new(b"stream".to_vec())),
                len: 6,
            }),
            Err(Body::Stream { len: 6, .. })
        ));

        let path = std::env::temp_dir().join(format!("vapache-compress-{}", std::process::id()));
        std::fs::write(&path, b"short").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        assert!(matches!(
            read_body(Body::File {
                file,
                offset: 0,
                len: MAX_COMPRESS_BODY + 1,
            }),
            Err(Body::File { .. })
        ));
        let file = std::fs::File::open(&path).unwrap();
        assert!(matches!(
            read_body(Body::File {
                file,
                offset: 0,
                len: 20,
            }),
            Err(Body::File { .. })
        ));
        let file = std::fs::File::open(&path).unwrap();
        assert!(matches!(
            read_body(Body::File {
                file,
                offset: 0,
                len: 5,
            }),
            Ok(bytes) if bytes == b"short"
        ));
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let file = std::fs::File::from(std::os::fd::OwnedFd::from(stream));
        assert!(matches!(
            read_body(Body::File {
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
