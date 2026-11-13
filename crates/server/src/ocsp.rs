//! OCSP stapling support for the Rustls certificate resolver.
//!
//! `SSLUseStapling On` fetches an OCSP response for the leaf certificate from
//! the responder advertised in its Authority Information Access extension and
//! attaches it to the `CertifiedKey`.  This intentionally implements the
//! common HTTP responder case synchronously at startup; failures are soft
//! (the certificate is still served) unless the caller decides otherwise.

use rustls::pki_types::{CertificateDer, UnixTime};
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const MAX_OCSP_HTTP_LINE: usize = 16 * 1024;
const MAX_OCSP_HTTP_HEAD: usize = 64 * 1024;
const MAX_OCSP_RESPONSE: u64 = 2 * 1024 * 1024;
const OCSP_CLOCK_SKEW_SECS: i64 = 300;
const MAX_OCSP_AGE_WITHOUT_NEXT_UPDATE_SECS: i64 = 24 * 60 * 60;
const OCSP_SIGNING_EKU: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];

pub fn prepare_cache_dir(path: &std::path::Path) -> std::io::Result<()> {
    let dir = crate::files::ensure_admin_dir(path, 0o750)?;
    crate::files::make_admin_dir_root_owned(&dir, 0o750)
}

#[derive(Clone, Copy)]
struct Tlv {
    tag: u8,
    start: usize,
    content_start: usize,
    content_end: usize,
    end: usize,
}

fn parse_tlv(data: &[u8], pos: usize) -> Option<Tlv> {
    if pos + 2 > data.len() {
        return None;
    }
    let tag = data[pos];
    // Every structure consumed here uses the single-octet DER tag form.
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = data[pos + 1];
    let (len, content_start) = if first & 0x80 == 0 {
        (first as usize, pos + 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > std::mem::size_of::<usize>() || pos + 2 + n > data.len() {
            return None;
        }
        if data[pos + 2] == 0 {
            return None;
        }
        let mut len = 0usize;
        for &b in &data[pos + 2..pos + 2 + n] {
            len = len.checked_mul(256)?.checked_add(b as usize)?;
        }
        if len < 128 {
            return None;
        }
        (len, pos + 2 + n)
    };
    let content_end = content_start.checked_add(len)?;
    if content_end > data.len() {
        return None;
    }
    Some(Tlv {
        tag,
        start: pos,
        content_start,
        content_end,
        end: content_end,
    })
}

fn raw<'a>(data: &'a [u8], t: Tlv) -> &'a [u8] {
    &data[t.start..t.end]
}

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else {
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 8);
    out.push(tag);
    der_len(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

struct CertInfo {
    serial: Vec<u8>,
    subject_name: Vec<u8>,
    issuer_key: Vec<u8>,
    ocsp_url: Option<String>,
}

fn valid_algorithm_identifier(data: &[u8], algorithm: Tlv) -> bool {
    if algorithm.tag != 0x30 {
        return false;
    }
    let Some(oid) = parse_tlv(data, algorithm.content_start) else {
        return false;
    };
    if oid.tag != 0x06 || oid.content_start == oid.content_end {
        return false;
    }
    if oid.end == algorithm.content_end {
        return true;
    }
    parse_tlv(data, oid.end).is_some_and(|parameters| parameters.end == algorithm.content_end)
}

fn valid_bit_string_content(
    data: &[u8],
    content_start: usize,
    content_end: usize,
    require_payload: bool,
) -> bool {
    if content_start >= content_end {
        return false;
    }
    let unused = data[content_start];
    let payload = &data[content_start + 1..content_end];
    if unused > 7 || (require_payload && payload.is_empty()) {
        return false;
    }
    unused == 0
        || payload
            .last()
            .is_some_and(|last| last & ((1u8 << unused) - 1) == 0)
}

fn valid_bit_string(data: &[u8], value: Tlv, require_payload: bool) -> bool {
    value.tag == 0x03
        && valid_bit_string_content(
            data,
            value.content_start,
            value.content_end,
            require_payload,
        )
}

fn valid_validity(data: &[u8], validity: Tlv) -> bool {
    if validity.tag != 0x30 {
        return false;
    }
    let Some(not_before) = parse_tlv(data, validity.content_start) else {
        return false;
    };
    let Some(not_after) = parse_tlv(data, not_before.end) else {
        return false;
    };
    matches!(not_before.tag, 0x17 | 0x18)
        && matches!(not_after.tag, 0x17 | 0x18)
        && not_before.content_start != not_before.content_end
        && not_after.content_start != not_after.content_end
        && not_after.end == validity.content_end
}

fn parse_spki(data: &[u8], spki: Tlv) -> Option<Vec<u8>> {
    let algorithm = parse_tlv(data, spki.content_start)?;
    if !valid_algorithm_identifier(data, algorithm) {
        return None;
    }
    let key = parse_tlv(data, algorithm.end)?;
    if key.end != spki.content_end || !valid_bit_string(data, key, true) {
        return None;
    }
    Some(data[key.content_start + 1..key.content_end].to_vec())
}

fn parse_aia_value(data: &[u8], value: Tlv) -> Option<Option<String>> {
    let seq = parse_tlv(data, value.content_start)?;
    if seq.tag != 0x30 || seq.end != value.content_end {
        return None;
    }
    let mut p = seq.content_start;
    let mut ocsp_url = None;
    while p < seq.content_end {
        let ad = parse_tlv(data, p)?;
        p = ad.end;
        if ad.tag != 0x30 {
            return None;
        }
        let oid = parse_tlv(data, ad.content_start)?;
        let gn = parse_tlv(data, oid.end)?;
        if oid.tag != 0x06 || oid.content_start == oid.content_end || gn.end != ad.content_end {
            return None;
        }
        // 1.3.6.1.5.5.7.48.1 (id-ad-ocsp)
        if raw(data, oid) == [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01] {
            if gn.tag != 0x86 || ocsp_url.is_some() {
                return None;
            }
            ocsp_url = Some(
                std::str::from_utf8(&data[gn.content_start..gn.content_end])
                    .ok()?
                    .to_string(),
            );
        }
    }
    Some(ocsp_url)
}

fn parse_extensions(data: &[u8], wrapper: Tlv) -> Option<Option<String>> {
    // [3] EXPLICIT Extensions
    let extensions = parse_tlv(data, wrapper.content_start)?;
    if extensions.tag != 0x30 || extensions.end != wrapper.content_end {
        return None;
    }
    let aia_oid = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
    let mut p = extensions.content_start;
    let mut seen_oids = HashSet::new();
    let mut ocsp_url = None;
    while p < extensions.content_end {
        let ext = parse_tlv(data, p)?;
        p = ext.end;
        if ext.tag != 0x30 {
            return None;
        }
        let oid = parse_tlv(data, ext.content_start)?;
        if oid.tag != 0x06
            || oid.content_start == oid.content_end
            || !seen_oids.insert(&data[oid.content_start..oid.content_end])
        {
            return None;
        }
        let mut q = oid.end;
        let mut value = parse_tlv(data, q)?;
        if value.tag == 0x01 {
            if value.content_end != value.content_start + 1
                || !matches!(data[value.content_start], 0x00 | 0xff)
            {
                return None;
            }
            q = value.end;
            value = parse_tlv(data, q)?;
        }
        if value.tag != 0x04 || value.end != ext.content_end {
            return None;
        }
        if data[oid.content_start..oid.content_end] == aia_oid {
            if ocsp_url.is_some() {
                return None;
            }
            ocsp_url = parse_aia_value(data, value)?;
        }
    }
    Some(ocsp_url)
}

fn parse_cert(der_bytes: &[u8]) -> Option<CertInfo> {
    let outer = parse_tlv(der_bytes, 0)?;
    if outer.tag != 0x30 || outer.end != der_bytes.len() {
        return None;
    }
    let tbs = parse_tlv(der_bytes, outer.content_start)?;
    if tbs.tag != 0x30 {
        return None;
    }
    let signature_algorithm = parse_tlv(der_bytes, tbs.end)?;
    let signature = parse_tlv(der_bytes, signature_algorithm.end)?;
    if !valid_algorithm_identifier(der_bytes, signature_algorithm)
        || !valid_bit_string(der_bytes, signature, true)
        || signature.end != outer.content_end
    {
        return None;
    }

    // TBSCertificate := [0] Version OPTIONAL, serial, signature, issuer,
    // validity, subject, subjectPublicKeyInfo, [1], [2], [3] Extensions.
    // Every mandatory field is consumed at its exact position; optional fields
    // are unique and ordered.
    let mut p = tbs.content_start;
    let first = parse_tlv(der_bytes, p)?;
    let mut version_number = 0u8;
    if first.tag == 0xa0 {
        let version = parse_tlv(der_bytes, first.content_start)?;
        if version.tag != 0x02
            || version.end != first.content_end
            || version.content_end != version.content_start + 1
            || der_bytes[version.content_start] > 2
        {
            return None;
        }
        version_number = der_bytes[version.content_start];
        p = first.end;
    }
    let serial = parse_tlv(der_bytes, p)?;
    if serial.tag != 0x02 || serial.content_start == serial.content_end {
        return None;
    }
    p = serial.end;
    let tbs_signature = parse_tlv(der_bytes, p)?;
    if !valid_algorithm_identifier(der_bytes, tbs_signature) {
        return None;
    }
    p = tbs_signature.end;
    let issuer = parse_tlv(der_bytes, p)?;
    if issuer.tag != 0x30 {
        return None;
    }
    p = issuer.end;
    let validity = parse_tlv(der_bytes, p)?;
    if !valid_validity(der_bytes, validity) {
        return None;
    }
    p = validity.end;
    let subject = parse_tlv(der_bytes, p)?;
    if subject.tag != 0x30 {
        return None;
    }
    p = subject.end;
    let spki = parse_tlv(der_bytes, p)?;
    if spki.tag != 0x30 {
        return None;
    }
    let issuer_key = parse_spki(der_bytes, spki)?;
    p = spki.end;
    if raw(der_bytes, tbs_signature) != raw(der_bytes, signature_algorithm) {
        return None;
    }

    let mut ocsp_url = None;
    let mut last_optional = 0u8;
    while p < tbs.content_end {
        let t = parse_tlv(der_bytes, p)?;
        p = t.end;
        let order = match t.tag {
            0x81 => 1,
            0x82 => 2,
            0xa3 => 3,
            _ => return None,
        };
        if order <= last_optional {
            return None;
        }
        last_optional = order;
        match t.tag {
            0x81 | 0x82 => {
                if version_number == 0
                    || !valid_bit_string_content(der_bytes, t.content_start, t.content_end, false)
                {
                    return None;
                }
            }
            0xa3 => {
                if version_number != 2 {
                    return None;
                }
                ocsp_url = parse_extensions(der_bytes, t)?;
            }
            _ => unreachable!("optional certificate tag was classified above"),
        }
    }
    Some(CertInfo {
        serial: raw(der_bytes, serial).to_vec(),
        subject_name: raw(der_bytes, subject).to_vec(),
        issuer_key,
        ocsp_url,
    })
}

fn build_request(leaf: &CertInfo, issuer: &CertInfo) -> Option<Vec<u8>> {
    let mut name_hasher = Sha1::new();
    name_hasher.update(&issuer.subject_name);
    let name_hash = name_hasher.finalize();
    let mut key_hasher = Sha1::new();
    key_hasher.update(&issuer.issuer_key);
    let key_hash = key_hasher.finalize();
    let sha1_oid = [0x2b, 0x0e, 0x03, 0x02, 0x1a];
    let alg = der(0x30, &[der(0x06, &sha1_oid), der(0x05, &[])].concat());
    let cert_id = der(
        0x30,
        &[
            alg,
            der(0x04, &name_hash),
            der(0x04, &key_hash),
            leaf.serial.clone(),
        ]
        .concat(),
    );
    let request = der(0x30, &cert_id);
    let request_list = der(0x30, &request);
    let tbs_request = der(0x30, &request_list);
    Some(der(0x30, &tbs_request))
}

fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    if url.is_empty() || url.trim() != url {
        return None;
    }
    let rest = url.strip_prefix("http://")?;
    let split = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..split];
    let path = if split == rest.len() {
        "/"
    } else {
        &rest[split..]
    };
    // The URL is copied into an HTTP request line and Host field. Reuse the
    // verified authority parser and admit only visible ASCII origin-form path
    // bytes, so a certificate AIA value cannot inject a second field/request.
    let (host, port) = crate::util::parse_http_authority(authority.as_bytes(), 80)?;
    if path.is_empty()
        || !path.starts_with('/')
        || path
            .bytes()
            .any(|byte| !(0x21..=0x7e).contains(&byte) || byte == b'#')
    {
        return None;
    }
    Some((host, port, path.to_string()))
}

pub(crate) fn supported_responder_url(url: &str) -> bool {
    parse_http_url(url).is_some()
}

fn read_http_line(reader: &mut impl BufRead) -> Option<String> {
    // Do not use `read_until`: an OCSP peer can otherwise force allocation of
    // an unbounded line before the post-read size check runs.
    let mut line = Vec::with_capacity(MAX_OCSP_HTTP_LINE.min(1024));
    loop {
        let available = reader.fill_buf().ok()?;
        if available.is_empty() {
            return None;
        }
        if let Some(end) = available.iter().position(|byte| *byte == b'\n') {
            let take = end + 1;
            if line.len().saturating_add(take) > MAX_OCSP_HTTP_LINE {
                return None;
            }
            line.extend_from_slice(&available[..take]);
            reader.consume(take);
            break;
        }
        if line.len().saturating_add(available.len()) > MAX_OCSP_HTTP_LINE {
            return None;
        }
        let take = available.len();
        line.extend_from_slice(available);
        reader.consume(take);
    }
    if !line.ends_with(b"\r\n") {
        return None;
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line).ok()
}

fn valid_http_field_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn fetch_response(
    backend_identities: &crate::proxy::BackendIdentityRegistry,
    url: &str,
    request: &[u8],
    timeout: Duration,
) -> Option<Vec<u8>> {
    let (host, port, path) = parse_http_url(url)?;
    let deadline = Instant::now() + timeout;
    let mut stream = None;
    let addresses =
        crate::proxy::resolve_backend_addrs(backend_identities, &host, port, timeout).ok()?;
    for candidate in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if let Ok(s) = TcpStream::connect_timeout(&candidate, remaining) {
            let actual = s.peer_addr().ok()?;
            if httpd_rs_verified::backend_connected_endpoint_admit(actual == candidate, true) {
                stream = Some(s);
                break;
            }
        }
    }
    let stream = stream?;
    let quantum = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(1));
    if quantum.is_zero() {
        return None;
    }
    stream.set_read_timeout(Some(quantum)).ok()?;
    stream.set_write_timeout(Some(quantum)).ok()?;
    let mut stream = OcspDeadlineStream { stream, deadline };
    let host_field = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_field}\r\nContent-Type: application/ocsp-request\r\nAccept: application/ocsp-response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        request.len()
    );
    stream.write_all(head.as_bytes()).ok()?;
    stream.write_all(request).ok()?;
    let mut reader = BufReader::new(stream);
    let status = read_http_line(&mut reader)?;
    let mut status_parts = status.splitn(3, ' ');
    let version = status_parts.next();
    let code = status_parts.next();
    let reason = status_parts.next()?;
    if !matches!(version, Some("HTTP/1.0" | "HTTP/1.1"))
        || code != Some("200")
        || reason
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
    {
        return None;
    }
    let mut content_length = None;
    let mut head_bytes = status.len() + 2;
    loop {
        let line = read_http_line(&mut reader)?;
        head_bytes = head_bytes.saturating_add(line.len() + 2);
        if head_bytes > MAX_OCSP_HTTP_HEAD {
            return None;
        }
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        if !valid_http_field_name(name)
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return None;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return None;
            }
            let parsed = crate::util::parse_u64(value.trim().as_bytes())?;
            content_length = Some(usize::try_from(parsed).ok()?);
        }
    }
    let mut body = Vec::new();
    if let Some(n) = content_length {
        if n > 2 * 1024 * 1024 {
            return None;
        }
        body.resize(n, 0);
        reader.read_exact(&mut body).ok()?;
    } else {
        reader
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut body)
            .ok()?;
        if body.len() > 2 * 1024 * 1024 {
            return None; // coverage:ignore-line -- socket regression is transport-timing dependent
        }
    }
    Some(body)
}

struct OcspDeadlineStream {
    stream: TcpStream,
    deadline: Instant,
}

impl Read for OcspDeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "OCSP exchange deadline exceeded",
                ));
            }
            match self.stream.read(buf) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
}

impl Write for OcspDeadlineStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "OCSP exchange deadline exceeded",
                ));
            }
            match self.stream.write(buf) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "OCSP exchange deadline exceeded",
                ));
            }
            match self.stream.flush() {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
}

fn successful_response(data: &[u8]) -> bool {
    let Some(outer) = parse_tlv(data, 0) else {
        return false;
    };
    if outer.tag != 0x30 {
        return false;
    }
    let Some(status) = parse_tlv(data, outer.content_start) else {
        return false;
    };
    if status.tag != 0x0a
        || status.content_end - status.content_start != 1
        || data[status.content_start] != 0
    {
        return false;
    }
    // A successful status without ResponseBytes is not a staple. Require an
    // id-pkix-ocsp-basic payload with the complete BasicOCSPResponse signed
    // shape so a five-byte `successful` status injected on the plaintext AIA
    // transport cannot replace a working staple with malformed bytes. TLS
    // clients still perform the cryptographic certificate/status validation.
    let Some(wrapper) = parse_tlv(data, status.end) else {
        return false;
    };
    if outer.end != data.len() || wrapper.tag != 0xa0 || wrapper.end != outer.content_end {
        return false;
    }
    let Some(response_bytes) = parse_tlv(data, wrapper.content_start) else {
        return false;
    };
    if response_bytes.tag != 0x30 || response_bytes.end != wrapper.content_end {
        return false;
    }
    let Some(kind) = parse_tlv(data, response_bytes.content_start) else {
        return false;
    };
    const BASIC_OCSP_OID: &[u8] = &[
        0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
    ];
    if raw(data, kind) != BASIC_OCSP_OID {
        return false;
    }
    let Some(encoded) = parse_tlv(data, kind.end) else {
        return false;
    };
    if encoded.tag != 0x04 || encoded.end != response_bytes.content_end {
        return false;
    }
    let basic_bytes = &data[encoded.content_start..encoded.content_end];
    let Some(basic) = parse_tlv(basic_bytes, 0) else {
        return false;
    };
    if basic.tag != 0x30 || basic.end != basic_bytes.len() {
        return false;
    }
    let Some(tbs) = parse_tlv(basic_bytes, basic.content_start) else {
        return false;
    };
    let Some(algorithm) = parse_tlv(basic_bytes, tbs.end) else {
        return false;
    };
    let Some(signature) = parse_tlv(basic_bytes, algorithm.end) else {
        return false;
    };
    tbs.tag == 0x30
        && algorithm.tag == 0x30
        && signature.tag == 0x03
        && signature.content_end > signature.content_start + 1
        && basic_bytes[signature.content_start] == 0
}

struct BasicResponse<'a> {
    bytes: &'a [u8],
    tbs: Tlv,
    algorithm: Tlv,
    signature: Tlv,
    certificates: Vec<CertificateDer<'a>>,
}

fn basic_response(data: &[u8]) -> Option<BasicResponse<'_>> {
    if !successful_response(data) {
        return None;
    }
    let outer = parse_tlv(data, 0)?;
    let status = parse_tlv(data, outer.content_start)?;
    let wrapper = parse_tlv(data, status.end)?;
    let response_bytes = parse_tlv(data, wrapper.content_start)?;
    let kind = parse_tlv(data, response_bytes.content_start)?;
    let encoded = parse_tlv(data, kind.end)?;
    let bytes = &data[encoded.content_start..encoded.content_end];
    let basic = parse_tlv(bytes, 0)?;
    let tbs = parse_tlv(bytes, basic.content_start)?;
    let algorithm = parse_tlv(bytes, tbs.end)?;
    let signature = parse_tlv(bytes, algorithm.end)?;
    let mut certificates = Vec::new();
    if signature.end < basic.content_end {
        let wrapper = parse_tlv(bytes, signature.end)?;
        if wrapper.tag != 0xa0 || wrapper.end != basic.content_end {
            return None;
        }
        let sequence = parse_tlv(bytes, wrapper.content_start)?;
        if sequence.tag != 0x30 || sequence.end != wrapper.content_end {
            return None;
        }
        let mut p = sequence.content_start;
        while p < sequence.content_end {
            let certificate = parse_tlv(bytes, p)?;
            if certificate.tag != 0x30 {
                return None;
            }
            certificates.push(CertificateDer::from(raw(bytes, certificate)));
            p = certificate.end;
        }
    } else if signature.end != basic.content_end {
        return None;
    }
    Some(BasicResponse {
        bytes,
        tbs,
        algorithm,
        signature,
        certificates,
    })
}

fn parse_decimal(bytes: &[u8]) -> Option<i64> {
    bytes.iter().try_fold(0i64, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value.checked_mul(10)?.checked_add((byte - b'0') as i64))?
    })
}

fn leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn generalized_time(bytes: &[u8]) -> Option<i64> {
    if bytes.len() != 15 || bytes[14] != b'Z' {
        return None;
    }
    let year = parse_decimal(&bytes[0..4])?;
    let month = parse_decimal(&bytes[4..6])?;
    let day = parse_decimal(&bytes[6..8])?;
    let hour = parse_decimal(&bytes[8..10])?;
    let minute = parse_decimal(&bytes[10..12])?;
    let second = parse_decimal(&bytes[12..14])?;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year(year) => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=days_in_month).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    days.checked_mul(86_400)?
        .checked_add(hour * 3600 + minute * 60 + second)
}

fn algorithm_is_sha1(data: &[u8], algorithm: Tlv) -> bool {
    if algorithm.tag != 0x30 {
        return false;
    }
    let Some(oid) = parse_tlv(data, algorithm.content_start) else {
        return false;
    };
    if oid.tag != 0x06
        || &data[oid.content_start..oid.content_end] != [0x2b, 0x0e, 0x03, 0x02, 0x1a]
    {
        return false;
    }
    if oid.end == algorithm.content_end {
        return true;
    }
    let Some(null) = parse_tlv(data, oid.end) else {
        return false;
    };
    null.tag == 0x05 && null.content_start == null.content_end && null.end == algorithm.content_end
}

fn cert_id_matches(data: &[u8], cert_id: Tlv, leaf: &CertInfo, issuer: &CertInfo) -> Option<bool> {
    if cert_id.tag != 0x30 {
        return None;
    }
    let algorithm = parse_tlv(data, cert_id.content_start)?;
    let issuer_name_hash = parse_tlv(data, algorithm.end)?;
    let issuer_key_hash = parse_tlv(data, issuer_name_hash.end)?;
    let serial = parse_tlv(data, issuer_key_hash.end)?;
    if serial.end != cert_id.content_end
        || issuer_name_hash.tag != 0x04
        || issuer_key_hash.tag != 0x04
        || serial.tag != 0x02
        || !algorithm_is_sha1(data, algorithm)
    {
        return None;
    }
    let expected_name = Sha1::digest(&issuer.subject_name);
    let expected_key = Sha1::digest(&issuer.issuer_key);
    Some(
        &data[issuer_name_hash.content_start..issuer_name_hash.content_end]
            == expected_name.as_slice()
            && &data[issuer_key_hash.content_start..issuer_key_hash.content_end]
                == expected_key.as_slice()
            && raw(data, serial) == leaf.serial,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SingleResponseValidity {
    OtherCertificate,
    Invalid,
    GoodUntil(i64),
}

fn valid_single_response(
    data: &[u8],
    single: Tlv,
    leaf: &CertInfo,
    issuer: &CertInfo,
    now: i64,
) -> Option<SingleResponseValidity> {
    if single.tag != 0x30 {
        return None;
    }
    let cert_id = parse_tlv(data, single.content_start)?;
    let matches = cert_id_matches(data, cert_id, leaf, issuer)?;
    if !matches {
        return Some(SingleResponseValidity::OtherCertificate);
    }
    let status = parse_tlv(data, cert_id.end)?;
    if status.tag != 0x80 || status.content_start != status.content_end {
        return Some(SingleResponseValidity::Invalid);
    }
    let this_update = parse_tlv(data, status.end)?;
    if this_update.tag != 0x18 {
        return None;
    }
    let this_update_time =
        generalized_time(&data[this_update.content_start..this_update.content_end])?;
    if this_update_time > now + OCSP_CLOCK_SKEW_SECS {
        return Some(SingleResponseValidity::Invalid);
    }
    let mut p = this_update.end;
    let mut next_update_time = None;
    if p < single.content_end {
        let optional = parse_tlv(data, p)?;
        if optional.tag == 0xa0 {
            let next_update = parse_tlv(data, optional.content_start)?;
            if next_update.tag != 0x18 || next_update.end != optional.content_end {
                return None;
            }
            next_update_time = Some(generalized_time(
                &data[next_update.content_start..next_update.content_end],
            )?);
            p = optional.end;
        }
    }
    if p < single.content_end {
        let extensions = parse_tlv(data, p)?;
        if extensions.tag != 0xa1 || extensions.end != single.content_end {
            return None;
        }
        p = extensions.end;
    }
    if p != single.content_end {
        return None;
    }
    let valid_until = match next_update_time {
        Some(next) => next.checked_add(OCSP_CLOCK_SKEW_SECS)?,
        None => this_update_time.checked_add(MAX_OCSP_AGE_WITHOUT_NEXT_UPDATE_SECS)?,
    };
    Some(if valid_until > now {
        SingleResponseValidity::GoodUntil(valid_until)
    } else {
        SingleResponseValidity::Invalid
    })
}

fn responder_matches(data: &[u8], responder: Tlv, signer: &CertInfo) -> bool {
    match responder.tag {
        0xa1 => parse_tlv(data, responder.content_start).is_some_and(|name| {
            name.end == responder.content_end && raw(data, name) == signer.subject_name
        }),
        0xa2 => parse_tlv(data, responder.content_start).is_some_and(|key_hash| {
            key_hash.tag == 0x04
                && key_hash.end == responder.content_end
                && &data[key_hash.content_start..key_hash.content_end]
                    == Sha1::digest(&signer.issuer_key).as_slice()
        }),
        // Accept the IMPLICIT form emitted by older responders as well.
        0x82 => {
            &data[responder.content_start..responder.content_end]
                == Sha1::digest(&signer.issuer_key).as_slice()
        }
        _ => false,
    }
}

fn signature_valid(
    basic: &BasicResponse<'_>,
    responder: Tlv,
    chain: &[CertificateDer<'static>],
) -> bool {
    let signature = &basic.bytes[basic.signature.content_start + 1..basic.signature.content_end];
    let algorithm_der = &basic.bytes[basic.algorithm.content_start..basic.algorithm.content_end];
    let algorithms: Vec<_> = webpki::ALL_VERIFICATION_ALGS
        .iter()
        .copied()
        .filter(|algorithm| algorithm.signature_alg_id().as_ref() == algorithm_der)
        .collect();
    if algorithms.is_empty() {
        return false;
    }
    let issuer = &chain[1];
    let mut candidates = Vec::with_capacity(1 + basic.certificates.len());
    candidates.push(CertificateDer::from(issuer.as_ref()));
    candidates.extend(basic.certificates.iter().cloned());
    for candidate in &candidates {
        let Some(info) = parse_cert(candidate.as_ref()) else {
            continue;
        };
        if !responder_matches(basic.bytes, responder, &info) {
            continue;
        }
        let Ok(signer) = webpki::EndEntityCert::try_from(candidate) else {
            continue;
        };
        let authorized = if candidate.as_ref() == issuer.as_ref() {
            true
        } else {
            let Ok(anchor) = webpki::anchor_from_trusted_cert(issuer) else {
                continue;
            };
            let intermediates: Vec<_> = basic
                .certificates
                .iter()
                .filter(|certificate| certificate.as_ref() != candidate.as_ref())
                .cloned()
                .collect();
            signer
                .verify_for_usage(
                    webpki::ALL_VERIFICATION_ALGS,
                    &[anchor],
                    &intermediates,
                    UnixTime::now(),
                    webpki::KeyUsage::required(OCSP_SIGNING_EKU),
                    None,
                    None,
                )
                .is_ok()
        };
        if authorized
            && algorithms.iter().any(|algorithm| {
                signer
                    .verify_signature(*algorithm, raw(basic.bytes, basic.tbs), signature)
                    .is_ok()
            })
        {
            return true;
        }
    }
    false
}

fn valid_response_until(
    chain: &[CertificateDer<'static>],
    response: &[u8],
    now: i64,
) -> Option<i64> {
    if chain.len() < 2 {
        return None;
    }
    let Some(leaf) = parse_cert(chain[0].as_ref()) else {
        return None;
    };
    let Some(issuer) = parse_cert(chain[1].as_ref()) else {
        return None;
    };
    let Some(basic) = basic_response(response) else {
        return None;
    };
    if basic.signature.content_start >= basic.signature.content_end
        || basic.bytes[basic.signature.content_start] != 0
    {
        return None;
    }
    let mut p = basic.tbs.content_start;
    let Some(mut responder) = parse_tlv(basic.bytes, p) else {
        return None;
    };
    if responder.tag == 0xa0 {
        let Some(version) = parse_tlv(basic.bytes, responder.content_start) else {
            return None;
        };
        if version.tag != 0x02
            || version.end != responder.content_end
            || &basic.bytes[version.content_start..version.content_end] != [0]
        {
            return None;
        }
        p = responder.end;
        let Some(next) = parse_tlv(basic.bytes, p) else {
            return None;
        };
        responder = next;
    }
    if !matches!(responder.tag, 0xa1 | 0xa2 | 0x82) {
        return None;
    }
    let Some(produced_at) = parse_tlv(basic.bytes, responder.end) else {
        return None;
    };
    if produced_at.tag != 0x18 {
        return None;
    }
    let Some(produced) =
        generalized_time(&basic.bytes[produced_at.content_start..produced_at.content_end])
    else {
        return None;
    };
    if produced > now + OCSP_CLOCK_SKEW_SECS {
        return None;
    }
    let Some(responses) = parse_tlv(basic.bytes, produced_at.end) else {
        return None;
    };
    if responses.tag != 0x30 {
        return None;
    }
    let mut matched = None;
    let mut q = responses.content_start;
    while q < responses.content_end {
        let Some(single) = parse_tlv(basic.bytes, q) else {
            return None;
        };
        q = single.end;
        match valid_single_response(basic.bytes, single, &leaf, &issuer, now) {
            Some(SingleResponseValidity::OtherCertificate) => {}
            Some(SingleResponseValidity::GoodUntil(until)) if matched.is_none() => {
                matched = Some(until)
            }
            Some(SingleResponseValidity::GoodUntil(_) | SingleResponseValidity::Invalid) | None => {
                return None
            }
        }
    }
    if produced_at.end > responses.start
        || responses.end > basic.tbs.content_end
        || (responses.end < basic.tbs.content_end
            && parse_tlv(basic.bytes, responses.end).is_none_or(|extensions| {
                extensions.tag != 0xa1 || extensions.end != basic.tbs.content_end
            }))
    {
        return None;
    }
    signature_valid(&basic, responder, chain).then_some(matched?)
}

pub(crate) fn valid_response(chain: &[CertificateDer<'static>], response: &[u8]) -> bool {
    valid_response_until(chain, response, UnixTime::now().as_secs() as i64).is_some()
}

pub(crate) fn valid_response_ttl(
    chain: &[CertificateDer<'static>],
    response: &[u8],
) -> Option<Duration> {
    let now = UnixTime::now().as_secs() as i64;
    let valid_until = valid_response_until(chain, response, now)?;
    let seconds = valid_until.checked_sub(now)?;
    (seconds > 0).then(|| Duration::from_secs(seconds as u64))
}

#[cfg(test)]
pub(crate) fn test_successful_response() -> Vec<u8> {
    let basic = der(
        0x30,
        &[der(0x30, &[]), der(0x30, &[]), der(0x03, &[0, 1])].concat(),
    );
    let response_bytes = der(
        0x30,
        &[
            vec![
                0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
            ],
            der(0x04, &basic),
        ]
        .concat(),
    );
    der(
        0x30,
        &[der(0x0a, &[0]), der(0xa0, &response_bytes)].concat(),
    )
}

#[cfg(test)]
fn test_generalized_time(unix: i64) -> Vec<u8> {
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}Z",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
    .into_bytes()
}

/// Build a real issuer-signed response for TLS/cache integration tests. The
/// test certificate generator uses an RSA key, matching this AlgorithmIdentifier.
#[cfg(test)]
pub(crate) fn test_valid_response(
    chain: &[CertificateDer<'static>],
    issuer_key: &std::path::Path,
) -> Vec<u8> {
    let leaf = parse_cert(chain[0].as_ref()).expect("test leaf certificate");
    let issuer = parse_cert(chain[1].as_ref()).expect("test issuer certificate");
    let sha1_algorithm = der(
        0x30,
        &[der(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]), der(0x05, &[])].concat(),
    );
    let cert_id = der(
        0x30,
        &[
            sha1_algorithm,
            der(0x04, Sha1::digest(&issuer.subject_name).as_slice()),
            der(0x04, Sha1::digest(&issuer.issuer_key).as_slice()),
            leaf.serial,
        ]
        .concat(),
    );
    let now = UnixTime::now().as_secs() as i64;
    let single = der(
        0x30,
        &[
            cert_id,
            der(0x80, &[]),
            der(0x18, &test_generalized_time(now - 60)),
            der(0xa0, &der(0x18, &test_generalized_time(now + 3600))),
        ]
        .concat(),
    );
    let tbs = der(
        0x30,
        &[
            der(0xa1, &issuer.subject_name),
            der(0x18, &test_generalized_time(now)),
            der(0x30, &single),
        ]
        .concat(),
    );
    let mut child = std::process::Command::new("openssl")
        .args(["dgst", "-sha256", "-sign"])
        .arg(issuer_key)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("openssl signing process");
    child
        .stdin
        .take()
        .expect("openssl stdin")
        .write_all(&tbs)
        .expect("signing input");
    let output = child.wait_with_output().expect("openssl signature output");
    assert!(output.status.success());
    let signature_algorithm = der(
        0x30,
        &[
            der(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
            ),
            der(0x05, &[]),
        ]
        .concat(),
    );
    let mut signature = vec![0];
    signature.extend_from_slice(&output.stdout);
    let basic = der(
        0x30,
        &[tbs, signature_algorithm, der(0x03, &signature)].concat(),
    );
    let response_bytes = der(
        0x30,
        &[
            vec![
                0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
            ],
            der(0x04, &basic),
        ]
        .concat(),
    );
    der(
        0x30,
        &[der(0x0a, &[0]), der(0xa0, &response_bytes)].concat(),
    )
}

/// Bound the handwritten DER and HTTP-URL parsers with arbitrary certificate
/// and responder material.  No network access occurs in this entry point.
#[cfg(feature = "fuzzing")]
pub fn fuzz_ocsp_parsers(data: &[u8]) {
    let _ = parse_cert(data);
    let _ = successful_response(data);
    let _ = basic_response(data);
    let _ = generalized_time(data);
    if let Some(tlv) = parse_tlv(data, 0) {
        let _ = algorithm_is_sha1(data, tlv);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_http_url(text);
    }
}

fn cache() -> &'static Mutex<HashMap<Vec<u8>, Vec<u8>>> {
    static CACHE: OnceLock<Mutex<HashMap<Vec<u8>, Vec<u8>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn disk_leases() -> &'static Mutex<HashMap<std::path::PathBuf, crate::resource::DiskLease>> {
    static DISK: OnceLock<Mutex<HashMap<std::path::PathBuf, crate::resource::DiskLease>>> =
        OnceLock::new();
    DISK.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn account_cached(
    path: &std::path::Path,
    bytes: u64,
    budget: &std::sync::Arc<crate::resource::ResourceBudget>,
) -> bool {
    let mut leases = disk_leases()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if leases.contains_key(path) {
        return true;
    }
    let target = path.parent().unwrap_or(path);
    let Ok(lease) = budget.try_disk_at(target, bytes, 1) else {
        return false;
    };
    leases.insert(path.to_path_buf(), lease);
    true
}

fn response_key(chain: &[CertificateDer<'static>], force_url: Option<&str>) -> Vec<u8> {
    let mut key = chain
        .first()
        .map(|c| c.as_ref().to_vec())
        .unwrap_or_default();
    key.push(0);
    if let Some(url) = force_url {
        key.extend_from_slice(url.as_bytes());
    }
    key
}

pub fn cache_path(
    dir: &std::path::Path,
    chain: &[CertificateDer<'static>],
    force_url: Option<&str>,
) -> std::path::PathBuf {
    let key = response_key(chain, force_url);
    let mut hasher = Sha1::new();
    hasher.update(&key);
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    dir.join(format!("{digest}.ocsp"))
}

pub fn load_cached(path: &std::path::Path, chain: &[CertificateDer<'static>]) -> Option<Vec<u8>> {
    let mut file =
        crate::files::open_admin_path(path, libc::O_RDONLY | libc::O_NONBLOCK, 0).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_OCSP_RESPONSE {
        return None;
    }
    let mut data = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(MAX_OCSP_RESPONSE + 1)
        .read_to_end(&mut data)
        .ok()?;
    if data.len() as u64 > MAX_OCSP_RESPONSE {
        return None;
    }
    if valid_response(chain, &data) {
        Some(data)
    } else {
        None
    }
}

pub fn save_cached(path: &std::path::Path, chain: &[CertificateDer<'static>], response: &[u8]) {
    save_cached_inner(path, chain, response, None);
}

pub(crate) fn save_cached_accounted(
    path: &std::path::Path,
    chain: &[CertificateDer<'static>],
    response: &[u8],
    budget: &std::sync::Arc<crate::resource::ResourceBudget>,
) {
    save_cached_inner(path, chain, response, Some(budget));
}

fn save_cached_inner(
    path: &std::path::Path,
    chain: &[CertificateDer<'static>],
    response: &[u8],
    budget: Option<&std::sync::Arc<crate::resource::ResourceBudget>>,
) {
    if response.len() as u64 > MAX_OCSP_RESPONSE || !valid_response(chain, response) {
        return;
    }
    let Some(parent) = path.parent() else {
        return;
    };
    if crate::files::ensure_admin_dir(parent, 0o770).is_err() {
        return;
    }
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    // During replacement the old staple and a temporary file coexist. Hold
    // the peak reservation until rename has committed, then retain the final
    // file's charge for the lifetime of this process generation.
    let mut disk = match budget {
        Some(budget) => {
            match budget.try_disk_at(parent, (response.len() as u64).saturating_mul(2), 2) {
                Ok(lease) => Some(lease),
                Err(_) => return,
            }
        }
        None => None,
    };
    for _ in 0..16 {
        let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(".{name}.{}.{nonce}.tmp", std::process::id()));
        let Ok(mut file) = crate::files::open_admin_path(
            &tmp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
            0o600,
        ) else {
            continue;
        };
        let identity = file
            .metadata()
            .ok()
            .map(|metadata| (metadata.dev(), metadata.ino()));
        if file.write_all(response).is_ok()
            && file.sync_data().is_ok()
            && identity.is_some()
            && crate::files::open_admin_path(&tmp, libc::O_RDONLY | libc::O_NONBLOCK, 0)
                .ok()
                .and_then(|candidate| candidate.metadata().ok())
                .is_some_and(|metadata| {
                    metadata.is_file() && Some((metadata.dev(), metadata.ino())) == identity
                })
            && std::fs::rename(&tmp, path).is_ok()
        {
            if let Some(mut lease) = disk.take() {
                if lease.resize(response.len() as u64, 1).is_err() {
                    let _ = std::fs::remove_file(path);
                    return;
                }
                disk_leases()
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .insert(path.to_path_buf(), lease);
            }
            return;
        }
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Fetch a fresh response, bypassing the in-memory cache.  Used by the
/// periodic refresher so a valid startup staple is replaced with current
/// revocation information.
pub(crate) fn fetch_fresh(
    backend_identities: &crate::proxy::BackendIdentityRegistry,
    chain: &[CertificateDer<'static>],
    force_url: Option<&str>,
    timeout: Duration,
) -> Option<Vec<u8>> {
    if chain.len() < 2 {
        return None;
    }
    let leaf = parse_cert(chain[0].as_ref())?;
    let issuer = parse_cert(chain[1].as_ref())?;
    let url = force_url.map(str::to_string).or(leaf.ocsp_url.clone())?;
    let request = build_request(&leaf, &issuer)?;
    let response = fetch_response(backend_identities, &url, &request, timeout)?;
    if valid_response(chain, &response) {
        Some(response)
    } else {
        None
    }
}

/// Fetch and return a DER-encoded OCSPResponse to staple for `chain[0]`.
/// `chain[1]` must be the issuer certificate.  `force_url` overrides the AIA
/// URL when `SSLStaplingForceURL` is configured.
pub(crate) fn staple_response(
    backend_identities: &crate::proxy::BackendIdentityRegistry,
    chain: &[CertificateDer<'static>],
    force_url: Option<&str>,
    timeout: Duration,
) -> Option<Vec<u8>> {
    if chain.len() < 2 {
        return None;
    }
    let leaf = parse_cert(chain[0].as_ref())?;
    let issuer = parse_cert(chain[1].as_ref())?;
    let url = force_url.map(str::to_string).or(leaf.ocsp_url.clone())?;
    let request = build_request(&leaf, &issuer)?;
    let mut key = chain[0].as_ref().to_vec();
    key.extend_from_slice(url.as_bytes());
    if let Some(cached) = cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned()
    {
        if valid_response(chain, &cached) {
            return Some(cached);
        }
        cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key);
    }
    let response = fetch_response(backend_identities, &url, &request, timeout)?;
    if !valid_response(chain, &response) {
        return None;
    }
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, response.clone());
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_cert(url: Option<&str>) -> Vec<u8> {
        let algorithm = der(0x30, &der(0x06, &[0x2a]));
        let mut fields = vec![
            der(0x02, &[1]),
            algorithm.clone(),
            der(0x30, &[]),
            der(
                0x30,
                &[der(0x18, b"20200101000000Z"), der(0x18, b"20300101000000Z")].concat(),
            ),
            der(0x30, &[0x05, 0x00]),
            der(
                0x30,
                &[algorithm.clone(), der(0x03, &[0, 1, 2, 3])].concat(),
            ),
        ];
        if let Some(url) = url {
            fields.insert(0, der(0xa0, &der(0x02, &[2])));
            let access = der(
                0x30,
                &[
                    der(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]),
                    der(0x86, url.as_bytes()),
                ]
                .concat(),
            );
            let aia_value = der(0x04, &der(0x30, &access));
            let extension = der(
                0x30,
                &[
                    der(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]),
                    aia_value,
                ]
                .concat(),
            );
            fields.push(der(0xa3, &der(0x30, &extension)));
        }
        der(
            0x30,
            &[
                der(0x30, &fields.concat()),
                algorithm,
                der(0x03, &[0, 1, 2, 3]),
            ]
            .concat(),
        )
    }

    fn serve(response: Vec<u8>) -> Option<Vec<u8>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Drain the complete request before replying. Closing a socket
            // with unread request bytes can emit a TCP RST and make the
            // response-body assertion timing-dependent under a full suite.
            let mut request = Vec::new();
            let mut chunk = [0u8; 512];
            while !request.ends_with(b"\r\n\r\nrequest") {
                let n = stream.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
            }
            let _ = stream.write_all(&response);
        });
        let result = fetch_response(
            &crate::proxy::BackendIdentityRegistry::new(0),
            &format!("http://{addr}/ocsp"),
            b"request",
            Duration::from_secs(2),
        );
        handle.join().unwrap();
        result
    }

    #[test]
    fn cached_responses_must_be_cryptographically_valid() {
        let dir = std::env::temp_dir().join(format!("httpd-rs-ocsp-cache-{}", std::process::id()));
        let path = dir.join("response.ocsp");
        let chain = [
            CertificateDer::from(minimal_cert(None)),
            CertificateDer::from(minimal_cert(None)),
        ];
        let structural_only = test_successful_response();
        save_cached(&path, &chain, &structural_only);
        assert!(load_cached(&path, &chain).is_none());
        let bad = [0x30, 0x03, 0x0a, 0x01, 0x01];
        save_cached(&path, &chain, &bad);
        assert!(load_cached(&path, &chain).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_rejects_links_fifos_and_oversized_files() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!(
            "httpd-rs-ocsp-cache-objects-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"unchanged").unwrap();
        let path = dir.join("response.ocsp");
        let chain = [
            CertificateDer::from(minimal_cert(None)),
            CertificateDer::from(minimal_cert(None)),
        ];
        symlink(&victim, &path).unwrap();
        assert!(load_cached(&path, &chain).is_none());
        save_cached(&path, &chain, &test_successful_response());
        assert_eq!(std::fs::read(&victim).unwrap(), b"unchanged");
        assert!(load_cached(&path, &chain).is_none());

        let fifo = dir.join("fifo.ocsp");
        crate::files::make_test_fifo(&fifo).unwrap();
        assert!(load_cached(&fifo, &chain).is_none());

        let oversized = dir.join("oversized.ocsp");
        std::fs::write(&oversized, vec![0u8; MAX_OCSP_RESPONSE as usize + 1]).unwrap();
        assert!(load_cached(&oversized, &chain).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ocsp_http_lines_are_bounded() {
        let mut short = &b"HTTP/1.1 200 OK\r\n"[..];
        assert_eq!(
            read_http_line(&mut short).as_deref(),
            Some("HTTP/1.1 200 OK")
        );
        let mut long = vec![b'A'; MAX_OCSP_HTTP_LINE + 1];
        long.push(b'\n');
        let mut long = &long[..];
        assert!(read_http_line(&mut long).is_none());
    }

    #[test]
    fn der_length_round_trip() {
        let mut out = Vec::new();
        der_len(300, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x2c]);
        let encoded = der(0x04, b"abc");
        let t = parse_tlv(&encoded, 0).unwrap();
        assert_eq!(t.tag, 0x04);
        assert_eq!(&encoded[t.content_start..t.content_end], b"abc");
    }

    #[test]
    fn der_certificate_and_url_parsers_cover_malformed_edges() {
        assert!(parse_tlv(&[], 0).is_none());
        assert!(parse_tlv(&[0x04, 0x80], 0).is_none());
        assert!(parse_tlv(&[0x04, 0x89], 0).is_none());
        assert!(parse_tlv(&[0x04, 0x82, 0x01], 0).is_none());
        assert!(parse_tlv(&[0x04, 3, 1], 0).is_none());

        assert!(leap_year(2000));
        assert!(!leap_year(1900));
        assert!(generalized_time(b"20000229000000Z").is_some());
        assert!(generalized_time(b"19000229000000Z").is_none());
        assert!(generalized_time(b"20001301000000Z").is_none());
        assert!(generalized_time(b"20000101240000Z").is_none());

        let empty_spki = der(0x30, &[]);
        assert!(parse_spki(&empty_spki, parse_tlv(&empty_spki, 0).unwrap()).is_none());
        for content in [&[][..], &[8, 1][..]] {
            let spki = der(0x30, &der(0x03, content));
            assert!(parse_spki(&spki, parse_tlv(&spki, 0).unwrap()).is_none());
        }

        let not_a_sequence = der(0x04, &der(0x04, b"x"));
        assert!(parse_aia_value(&not_a_sequence, parse_tlv(&not_a_sequence, 0).unwrap()).is_none());
        let skipped_ad = der(0x04, &der(0x30, &der(0x04, b"x")));
        assert!(parse_aia_value(&skipped_ad, parse_tlv(&skipped_ad, 0).unwrap()).is_none());
        let missing_general_name = der(0x04, &der(0x30, &der(0x30, &der(0x06, &[0x2b]))));
        assert!(parse_aia_value(
            &missing_general_name,
            parse_tlv(&missing_general_name, 0).unwrap()
        )
        .is_none());
        let bad_wrapper = der(0xa3, &der(0x04, b"x"));
        assert!(parse_extensions(&bad_wrapper, parse_tlv(&bad_wrapper, 0).unwrap()).is_none());
        let skipped_extension = der(0xa3, &der(0x30, &der(0x04, b"x")));
        assert!(parse_extensions(
            &skipped_extension,
            parse_tlv(&skipped_extension, 0).unwrap()
        )
        .is_none());

        let cert = minimal_cert(Some("http://ocsp.example.test/check"));
        let info = parse_cert(&cert).unwrap();
        assert_eq!(
            info.ocsp_url.as_deref(),
            Some("http://ocsp.example.test/check")
        );
        assert!(!build_request(&info, &info).unwrap().is_empty());
        assert!(parse_cert(&der(0x04, b"bad")).is_none());
        assert!(parse_cert(&der(0x30, &der(0x04, b"bad"))).is_none());

        assert_eq!(
            parse_http_url("http://example.test:8080/path"),
            Some(("example.test".into(), 8080, "/path".into()))
        );
        assert_eq!(
            parse_http_url("http://example.test"),
            Some(("example.test".into(), 80, "/".into()))
        );
        assert!(parse_http_url("https://example.test/").is_none());
        assert!(parse_http_url("http:///path").is_none());
        assert!(parse_http_url("http://host:bad/").is_none());
        assert!(parse_http_url("http://user@host/").is_none());
        assert!(parse_http_url(" http://host/").is_none());
        assert!(parse_http_url("http://host/ ").is_none());
        assert!(parse_http_url("http://host/path\r\nX-Injected: yes").is_none());
        assert!(parse_http_url("http://host/path#fragment").is_none());
        assert_eq!(
            parse_http_url("http://[::1]:8080/status"),
            Some(("::1".into(), 8080, "/status".into()))
        );

        assert!(!successful_response(&[]));
        assert!(!successful_response(&der(0x04, b"bad")));
        assert!(!successful_response(&der(0x30, &[])));
        assert!(fetch_fresh(
            &crate::proxy::BackendIdentityRegistry::new(0),
            &[],
            None,
            Duration::ZERO,
        )
        .is_none());
        assert!(staple_response(
            &crate::proxy::BackendIdentityRegistry::new(0),
            &[],
            None,
            Duration::ZERO,
        )
        .is_none());
        let chain = [
            CertificateDer::from(cert),
            CertificateDer::from(minimal_cert(None)),
        ];
        assert!(response_key(&chain, Some("http://forced/")).ends_with(b"http://forced/"));
        assert!(cache_path(std::path::Path::new("/tmp"), &chain, None)
            .extension()
            .is_some_and(|ext| ext == "ocsp"));
    }

    #[test]
    fn single_response_requires_good_status_and_freshness() {
        let certificate = minimal_cert(None);
        let leaf = parse_cert(&certificate).unwrap();
        let issuer = parse_cert(&certificate).unwrap();
        let cert_id = der(
            0x30,
            &[
                der(
                    0x30,
                    &[der(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]), der(0x05, &[])].concat(),
                ),
                der(0x04, Sha1::digest(&issuer.subject_name).as_slice()),
                der(0x04, Sha1::digest(&issuer.issuer_key).as_slice()),
                leaf.serial.clone(),
            ]
            .concat(),
        );
        let now = UnixTime::now().as_secs() as i64;
        let single = |status: u8, this_update: i64, next_update: Option<i64>| {
            let mut fields = vec![
                cert_id.clone(),
                der(status, &[]),
                der(0x18, &test_generalized_time(this_update)),
            ];
            if let Some(next_update) = next_update {
                fields.push(der(0xa0, &der(0x18, &test_generalized_time(next_update))));
            }
            der(0x30, &fields.concat())
        };
        let current = single(0x80, now - 60, Some(now + 3600));
        assert_eq!(
            valid_single_response(
                &current,
                parse_tlv(&current, 0).unwrap(),
                &leaf,
                &issuer,
                now
            ),
            Some(SingleResponseValidity::GoodUntil(
                now + 3600 + OCSP_CLOCK_SKEW_SECS
            ))
        );
        let stale = single(0x80, now - 2 * 86_400, None);
        assert_eq!(
            valid_single_response(&stale, parse_tlv(&stale, 0).unwrap(), &leaf, &issuer, now),
            Some(SingleResponseValidity::Invalid)
        );
        let unknown = single(0x82, now - 60, Some(now + 3600));
        assert_eq!(
            valid_single_response(
                &unknown,
                parse_tlv(&unknown, 0).unwrap(),
                &leaf,
                &issuer,
                now
            ),
            Some(SingleResponseValidity::Invalid)
        );
    }

    #[test]
    fn ocsp_http_fetch_handles_length_eof_status_and_header_limits() {
        assert_eq!(
            serve(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec()),
            Some(b"hello".to_vec())
        );
        assert_eq!(
            serve(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody".to_vec()),
            Some(b"body".to_vec())
        );
        assert!(serve(b"HTTP/1.1 500 Error\r\n\r\n".to_vec()).is_none());
        assert!(serve(b"HTTP/1.1 200 OK\n\nbody".to_vec()).is_none());
        assert!(serve(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".to_vec()
        )
        .is_none());
        assert!(
            serve(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec())
                .is_none()
        );
        assert!(serve(b"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n".to_vec()).is_none());
        assert!(serve(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nno".to_vec()).is_none());
        assert!(serve(b"HTTP/1.1 200 OK\r\nContent-Length: 2097153\r\n\r\n".to_vec()).is_none());
        let mut oversized_body = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        oversized_body.resize(oversized_body.len() + 2 * 1024 * 1024 + 1, b'x');
        assert!(serve(oversized_body).is_none());

        let mut oversized_head = b"HTTP/1.1 200 OK\r\n".to_vec();
        for _ in 0..8 {
            oversized_head.extend_from_slice(b"X-Fill: ");
            oversized_head.extend(std::iter::repeat_n(b'x', 9000));
            oversized_head.extend_from_slice(b"\r\n");
        }
        oversized_head.extend_from_slice(b"\r\n");
        assert!(serve(oversized_head).is_none());

        let mut eof = &b""[..];
        assert!(read_http_line(&mut eof).is_none());
        assert!(fetch_response(
            &crate::proxy::BackendIdentityRegistry::new(0),
            "not-a-url",
            b"x",
            Duration::ZERO,
        )
        .is_none());
    }

    #[test]
    fn fresh_and_stapled_responses_reject_unauthenticated_payloads() {
        fn responder(body: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let handle = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request);
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            });
            (format!("http://{addr}/ocsp"), handle)
        }

        let cert = minimal_cert(None);
        let chain = [
            CertificateDer::from(cert.clone()),
            CertificateDer::from(cert),
        ];
        let (bad_url, bad_thread) = responder(der(0x30, &der(0x0a, &[1])));
        assert!(fetch_fresh(
            &crate::proxy::BackendIdentityRegistry::new(0),
            &chain,
            Some(&bad_url),
            Duration::from_secs(2),
        )
        .is_none());
        bad_thread.join().unwrap();

        let (bad_staple_url, bad_staple_thread) = responder(der(0x30, &der(0x0a, &[1])));
        assert!(staple_response(
            &crate::proxy::BackendIdentityRegistry::new(0),
            &chain,
            Some(&bad_staple_url),
            Duration::from_secs(2),
        )
        .is_none());
        bad_staple_thread.join().unwrap();

        let structural_only = test_successful_response();
        let (fresh_url, fresh_thread) = responder(structural_only.clone());
        assert!(fetch_fresh(
            &crate::proxy::BackendIdentityRegistry::new(0),
            &chain,
            Some(&fresh_url),
            Duration::from_secs(2),
        )
        .is_none());
        fresh_thread.join().unwrap();
        let (staple_url, staple_thread) = responder(structural_only);
        assert!(staple_response(
            &crate::proxy::BackendIdentityRegistry::new(0),
            &chain,
            Some(&staple_url),
            Duration::from_secs(2),
        )
        .is_none());
        staple_thread.join().unwrap();
    }
}
