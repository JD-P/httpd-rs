//! Small, dependency-free helpers shared by the server.
//!
//! Everything here is pure and heavily unit-tested; it is deliberately kept
//! free of I/O so that it can be moved into the verified crate as proofs are
//! written.

use std::cell::RefCell;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum pathname/URI-like value produced by a regex-backed configuration
/// directive. This prevents repeated references to one capture from
/// multiplying a bounded request target into an unbounded allocation.
pub const MAX_CAPTURE_EXPANSION_BYTES: usize = 64 * 1024;
const MAX_CAPTURE_GROUPS: usize = 128;

pub fn expand_regex_captures(
    template: &str,
    captures: &regex::bytes::Captures<'_>,
) -> Option<String> {
    if template.len() > MAX_CAPTURE_EXPANSION_BYTES || captures.len() > MAX_CAPTURE_GROUPS {
        return None;
    }
    let mut expanded = template.to_string();
    for index in (0..captures.len()).rev() {
        let marker = format!("${index}");
        let value = captures
            .get(index)
            .map(|matched| String::from_utf8_lossy(matched.as_bytes()))
            .unwrap_or_default();
        let occurrences = expanded.match_indices(&marker).count();
        if occurrences == 0 {
            continue;
        }
        let next = vapache_verified::capture_expansion_len(
            expanded.len() as u64,
            occurrences as u64,
            marker.len() as u64,
            value.len() as u64,
            MAX_CAPTURE_EXPANSION_BYTES as u64,
        )?;
        let _next = usize::try_from(next).ok()?;
        expanded = expanded.replace(&marker, value.as_ref());
    }
    Some(expanded)
}

/// Format a Unix timestamp as an IMF-fixdate (RFC 9110 §5.6.7), e.g.
/// `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn http_date(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let weekday = weekday_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    if !(0..=9999).contains(&year) {
        // RFC 9110 only defines four-digit years; keep the formatting
        // machinery for the out-of-range edge rather than silently wrapping.
        return format!(
            "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
            WEEKDAYS[weekday],
            day,
            MONTHS[month as usize - 1],
            year,
            hh,
            mm,
            ss
        );
    }
    // IMF-fixdate is fixed-width (29 bytes).  Building it directly avoids the
    // formatting machinery on every response.
    let mut buf = [0u8; 29];
    buf[..3].copy_from_slice(WEEKDAYS[weekday].as_bytes());
    buf[3] = b',';
    buf[4] = b' ';
    buf[5] = b'0' + (day / 10) as u8;
    buf[6] = b'0' + (day % 10) as u8;
    buf[7] = b' ';
    buf[8..11].copy_from_slice(MONTHS[month as usize - 1].as_bytes());
    buf[11] = b' ';
    let y = year as u32;
    buf[12] = b'0' + (y / 1000) as u8;
    buf[13] = b'0' + ((y / 100) % 10) as u8;
    buf[14] = b'0' + ((y / 10) % 10) as u8;
    buf[15] = b'0' + (y % 10) as u8;
    buf[16] = b' ';
    buf[17] = b'0' + (hh / 10) as u8;
    buf[18] = b'0' + (hh % 10) as u8;
    buf[19] = b':';
    buf[20] = b'0' + (mm / 10) as u8;
    buf[21] = b'0' + (mm % 10) as u8;
    buf[22] = b':';
    buf[23] = b'0' + (ss / 10) as u8;
    buf[24] = b'0' + (ss % 10) as u8;
    buf[25] = b' ';
    buf[26..].copy_from_slice(b"GMT");
    // Every byte written above is ASCII.
    String::from_utf8(buf.to_vec()).unwrap()
}

pub fn http_date_now() -> String {
    http_date(unix_now())
}

thread_local! {
    /// The `Date` header only changes once per second.  Formatting it for
    /// every response is a measurable cost at keep-alive request rates, so
    /// each connection thread keeps the current second's value and reuses it.
    static HTTP_DATE_CACHE: RefCell<(i64, String)> = const { RefCell::new((i64::MIN, String::new())) };
}

/// Call `f` with the current IMF-fixdate, reusing a per-thread cached string
/// when the wall-clock second has not changed.
pub fn with_http_date_now<F: FnOnce(&str)>(f: F) {
    let now = unix_now();
    HTTP_DATE_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.0 != now {
            cache.0 = now;
            cache.1 = http_date(now);
        }
        f(&cache.1);
    });
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

pub fn system_time_secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// Return the descendant suffix of a component-aware route prefix.
/// Prefixes ending in `/` already include their boundary, so `/app/` and `/`
/// both match child paths without requiring a second slash.
pub fn route_prefix_suffix<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    let exact = path == prefix;
    let rest = path.strip_prefix(prefix);
    let admitted = vapache_verified::proxy_prefix_match_admit(
        exact,
        rest.is_some(),
        prefix.ends_with('/'),
        rest.is_some_and(|value| value.starts_with('/')),
    );
    if !admitted {
        return None;
    }
    Some(rest.unwrap_or("").trim_start_matches('/'))
}

const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Days since 1970-01-01 -> (year, month, day). Howard Hinnant's algorithm.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// Days since epoch -> weekday index (0 = Thursday, matching WEEKDAYS).
fn weekday_from_days(z: i64) -> usize {
    z.rem_euclid(7) as usize
}

/// Inverse of `civil_from_days`.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse the three HTTP date formats accepted by RFC 9110. Returns Unix seconds.
pub fn parse_http_date(s: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(s).ok()?.trim();
    // IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT
    if let Some((_, rest)) = s.split_once(", ") {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() == 5 && parts[4] == "GMT" {
            let day: u32 = parts[0].parse().ok()?;
            let month = month_num(parts[1])?;
            let year: i64 = parts[2].parse().ok()?;
            let (hh, mm, ss) = parse_hms(parts[3])?;
            return Some(
                days_from_civil(year, month, day) * 86_400 + (hh * 3600 + mm * 60 + ss) as i64,
            );
        }
        // RFC 850: Sunday, 06-Nov-94 08:49:37 GMT
        if parts.len() == 3 && parts[2] == "GMT" {
            let dmy: Vec<&str> = parts[0].split('-').collect();
            if dmy.len() == 3 {
                let day: u32 = dmy[0].parse().ok()?;
                let month = month_num(dmy[1])?;
                let mut year: i64 = dmy[2].parse().ok()?;
                year += if year < 70 { 2000 } else { 1900 };
                let (hh, mm, ss) = parse_hms(parts[1])?;
                return Some(
                    days_from_civil(year, month, day) * 86_400 + (hh * 3600 + mm * 60 + ss) as i64,
                );
            }
        }
    }
    // asctime: Sun Nov  6 08:49:37 1994
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() == 5 {
        let month = month_num(parts[1])?;
        let day: u32 = parts[2].parse().ok()?;
        let (hh, mm, ss) = parse_hms(parts[3])?;
        let year: i64 = parts[4].parse().ok()?;
        return Some(
            days_from_civil(year, month, day) * 86_400 + (hh * 3600 + mm * 60 + ss) as i64,
        );
    }
    None
}

fn parse_hms(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.split(':');
    let h = it.next()?.parse().ok()?;
    let m = it.next()?.parse().ok()?;
    let sec = it.next()?.parse().ok()?;
    if it.next().is_some() || h > 23 || m > 59 || sec > 60 {
        return None;
    }
    Some((h, m, sec))
}

fn month_num(s: &str) -> Option<u32> {
    MONTHS.iter().position(|m| *m == s).map(|i| i as u32 + 1)
}

/// Case-insensitive ASCII comparison.
pub fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

pub fn trim_ascii(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t'))
        .unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t'))
        .map(|i| i + 1)
        .unwrap_or(start);
    &s[start..end]
}

/// Split a comma-separated header value into trimmed, non-empty elements.
pub fn comma_list(v: &[u8]) -> Vec<Vec<u8>> {
    v.split(|b| *b == b',')
        .map(trim_ascii)
        .filter(|x| !x.is_empty())
        .map(|x| x.to_vec())
        .collect()
}

#[inline]
fn is_safe_path_byte(b: u8) -> bool {
    b >= 0x20 && b != 0x7f && b != b'\\'
}

/// Independent runtime checker for the canonical-path invariant.
///
/// The normalizer itself is the Verus-verified `normalize_uri_path`; this
/// checker is retained as a cheap defense-in-depth assertion (and is unit
/// tested against the verified implementation) before filesystem access.
pub fn is_canonical_path(s: &[u8]) -> bool {
    if s.is_empty() || s[0] != b'/' {
        return false;
    }
    if s.iter().any(|b| !is_safe_path_byte(*b)) {
        return false;
    }
    if s.len() > 1 && s[s.len() - 1] == b'/' {
        return false;
    }
    let mut segs = s[1..].split(|b| *b == b'/');
    if s.len() == 1 {
        return true;
    }
    for seg in segs.by_ref() {
        if seg.is_empty() || seg == b"." || seg == b".." {
            return false;
        }
    }
    true
}

/// Map a URL path to a relative filesystem path (without leading slash),
/// refusing anything that is not canonical.  Returned as bytes so arbitrary
/// (non-UTF-8) file names work exactly as they do in Apache.
pub fn path_to_rel(url_path: &[u8]) -> Option<Vec<u8>> {
    if !is_canonical_path(url_path) {
        return None;
    }
    if url_path == b"/" {
        return Some(Vec::new());
    }
    Some(url_path[1..].to_vec())
}

/// URL-encode a path for use in a redirect or directory listing, leaving `/`
/// and RFC 3986 pchar characters alone.
pub fn url_encode_path(path: &[u8]) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path {
        if b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_'
                    | b'.'
                    | b'~'
                    | b'/'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            )
        {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xf) as usize] as char);
        }
    }
    out
}

/// URL-encode raw query octets for an externally visible redirect. Existing
/// percent escapes and RFC 3986 query delimiters remain intact; bytes that
/// cannot appear literally in a URI are represented reversibly as `%XX`.
pub fn url_encode_query(query: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(query.len());
    for &b in query {
        if b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_'
                    | b'.'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'/'
                    | b'?'
                    | b'%'
            )
        {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0xf) as usize]);
        }
    }
    out
}

/// Encode an autoindex entry as a relative hyperlink.  The leading `./`
/// is mandatory: it prevents a hostile filename such as `javascript:...`,
/// `data:...` or `//attacker.example/...` from becoming an absolute/scheme
/// URL in the generated HTML.  The encoder still handles quotes, controls
/// and other attribute-breaking bytes.
pub fn safe_relative_href(name: &[u8]) -> String {
    format!("./{}", url_encode_path(name))
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// HTML-escape file names for autoindex output.
pub fn html_escape(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s {
        match b {
            b'&' => out.push_str("&amp;"),
            b'<' => out.push_str("&lt;"),
            b'>' => out.push_str("&gt;"),
            b'"' => out.push_str("&quot;"),
            b'\'' => out.push_str("&#39;"),
            _ if b.is_ascii_graphic() || b == b' ' => out.push(b as char),
            _ => out.push('\u{fffd}'),
        }
    }
    out
}

/// Parse a hexadecimal `u64`, rejecting signs and overflow.
pub fn parse_hex_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &b in s {
        let d = match b {
            b'0'..=b'9' => (b - b'0') as u64,
            b'a'..=b'f' => (b - b'a' + 10) as u64,
            b'A'..=b'F' => (b - b'A' + 10) as u64,
            _ => return None,
        };
        v = v.checked_mul(16)?.checked_add(d)?;
    }
    Some(v)
}

/// Parse a decimal `u64`, rejecting signs and overflow.
pub fn parse_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(v)
}

/// Parse an HTTP authority into one unambiguous routing identity.
///
/// The verified parser owns bracket/colon splitting, IPv6 syntax, registered
/// names and checked ports. This wrapper only renders its typed host result;
/// no downstream string parser gets a second interpretation of the authority.
pub fn parse_http_authority(value: &[u8], default_port: u16) -> Option<(String, u16)> {
    let parsed = crate::verified::parse_http_authority_endpoint(value, default_port)?;
    let host = match parsed.host {
        crate::verified::HttpAuthorityHost::RegName(bytes) => String::from_utf8(bytes).ok()?,
        crate::verified::HttpAuthorityHost::Ipv6(address) => {
            std::net::Ipv6Addr::from(address).to_string()
        }
    };
    Some((host, parsed.port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verified::normalize_uri_path;

    #[test]
    fn date_roundtrip() {
        let cases = [0, 784_111_777, 1_700_000_000, 2_147_483_647, 951_782_400];
        for t in cases {
            let s = http_date(t);
            assert_eq!(parse_http_date(s.as_bytes()), Some(t), "{s}");
        }
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    #[test]
    fn old_date_formats() {
        assert_eq!(
            parse_http_date(b"Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(
            parse_http_date(b"Sun Nov  6 08:49:37 1994"),
            Some(784_111_777)
        );
        assert_eq!(parse_http_date(b"garbage"), None);
    }

    #[test]
    fn authority_parser_has_one_host_and_port_identity() {
        assert_eq!(
            parse_http_authority(b"Example.TEST", 80),
            Some(("example.test".into(), 80))
        );
        assert_eq!(
            parse_http_authority(b"example.test:8443", 443),
            Some(("example.test".into(), 8443))
        );
        assert_eq!(
            parse_http_authority(b"[0:0::1]:443", 80),
            Some(("::1".into(), 443))
        );
        assert_eq!(
            parse_http_authority(b"[::ffff:192.0.2.128]", 80),
            Some(("::ffff:192.0.2.128".into(), 80))
        );
        assert_eq!(
            parse_http_authority(b"[2001:db8:0:1:1:1:1:1]", 443),
            Some(("2001:db8:0:1:1:1:1:1".into(), 443))
        );
        for literal in [
            "::",
            "1::",
            "::1",
            "1:2:3:4:5:6:7:8",
            "::192.0.2.1",
            "1:2:3:4:5:6:192.0.2.1",
        ] {
            let authority = format!("[{literal}]");
            let expected = literal.parse::<std::net::Ipv6Addr>().unwrap().to_string();
            assert_eq!(
                parse_http_authority(authority.as_bytes(), 80),
                Some((expected, 80))
            );
        }
        assert_eq!(
            parse_http_authority(b"under_score.test", 80),
            Some(("under_score.test".into(), 80))
        );
        assert_eq!(
            parse_http_authority(b"percent%2Dname.test:0", 80),
            Some(("percent%2dname.test".into(), 0))
        );
        for invalid in [
            b"".as_slice(),
            b"example.test:".as_slice(),
            b"example.test:99999".as_slice(),
            b"user@example.test".as_slice(),
            b"example.test/path".as_slice(),
            b"example.test?query".as_slice(),
            b"example.test#fragment".as_slice(),
            b"2001:db8::1".as_slice(),
            b"[not-ipv6]".as_slice(),
            b"[1:2:3:4:5:6:7]".as_slice(),
            b"[1:2:3:4:5:6:7:8:9]".as_slice(),
            b"[1::2::3]".as_slice(),
            b"[::ffff:192.0.2.999]".as_slice(),
            b"[::ffff:192.0.2]".as_slice(),
            b"[::ffff:192.168.001.1]".as_slice(),
            b"bad%escape".as_slice(),
            b"bad%2".as_slice(),
            b"bad%2g".as_slice(),
            b"white space".as_slice(),
            b"control\x7f.test".as_slice(),
        ] {
            assert_eq!(parse_http_authority(invalid, 80), None, "{invalid:?}");
        }
    }

    #[test]
    fn normalize_basics() {
        assert_eq!(normalize_uri_path(b"/").unwrap(), b"/");
        assert_eq!(normalize_uri_path(b"/a/b").unwrap(), b"/a/b");
        assert_eq!(normalize_uri_path(b"//a///b/").unwrap(), b"/a/b");
        assert_eq!(normalize_uri_path(b"/a/./b").unwrap(), b"/a/b");
        assert_eq!(normalize_uri_path(b"/a/../b").unwrap(), b"/b");
        assert_eq!(normalize_uri_path(b"/../../etc/passwd"), None);
        assert_eq!(normalize_uri_path(b"/a/%2e%2e/b").unwrap(), b"/a/%2e%2e/b");
        assert_eq!(normalize_uri_path(b"a/b"), None);
        assert_eq!(normalize_uri_path(b"/a\\b"), None);
        assert_eq!(normalize_uri_path(b"/a\x00b"), None);
        assert_eq!(normalize_uri_path(b"/a\x7fb"), None);
        // Dot-prefixed names are ordinary segments; only exact `.`/`..` are
        // special.  Empty segments are collapsed, and a trailing `..` may
        // climb back to the root but never above it.
        assert_eq!(normalize_uri_path(b"/a/...").unwrap(), b"/a/...");
        assert_eq!(normalize_uri_path(b"/a/..b").unwrap(), b"/a/..b");
        assert_eq!(normalize_uri_path(b"/a/.b").unwrap(), b"/a/.b");
        assert_eq!(normalize_uri_path(b"/a//../b").unwrap(), b"/b");
        assert_eq!(normalize_uri_path(b"/a/../").unwrap(), b"/");
        assert_eq!(normalize_uri_path(b"/.").unwrap(), b"/");
        assert_eq!(normalize_uri_path(b"/.."), None);
        assert_eq!(normalize_uri_path(b"/a/../../b"), None);
    }

    #[test]
    fn canonical_checker_matches_normalizer() {
        let inputs: &[&[u8]] = &[
            b"/", b"/a", b"/a/b", b"//a", b"/a/../b", b"/a/./b", b"/../", b"/a//", b"/a\\b",
            b"/a%20b", b"/a?b", b"/a#b", b"/.", b"/..", b"///",
        ];
        for input in inputs {
            if let Some(out) = normalize_uri_path(input) {
                assert!(is_canonical_path(&out), "{:?} -> {:?}", input, out);
                assert!(path_to_rel(&out).is_some());
            }
        }
    }

    #[test]
    fn canonical_rejects_traversal() {
        assert!(!is_canonical_path(b"/../etc"));
        assert!(!is_canonical_path(b"/a/../b"));
        assert!(!is_canonical_path(b"/a/./b"));
        assert!(!is_canonical_path(b"/a//b"));
        assert!(!is_canonical_path(b"//etc"));
        assert!(!is_canonical_path(b"/a/"));
        assert!(is_canonical_path(b"/a/b"));
    }

    #[test]
    fn url_encoding() {
        assert_eq!(url_encode_path(b"/a b"), "/a%20b");
        assert_eq!(url_encode_path(b"/caf\xc3\xa9"), "/caf%C3%A9");
        assert_eq!(url_encode_path(b"/a?b"), "/a%3Fb");
        assert_eq!(
            url_encode_query(b"raw=\xff&escaped=%FE/path?x#fragment"),
            b"raw=%FF&escaped=%FE/path?x%23fragment"
        );
    }

    #[test]
    fn autoindex_hrefs_are_always_relative() {
        for name in [
            b"javascript:alert(1)".as_slice(),
            b"data:text/html,boom",
            b"vbscript:msgbox(1)",
            b"//attacker.example/x",
            b"\"/onmouseover=alert(1)",
        ] {
            let href = safe_relative_href(name);
            assert!(href.starts_with("./"), "{href}");
            assert!(!href.starts_with("//"), "{href}");
            assert!(!href.contains("://"), "{href}");
            assert!(!href.contains('"'), "{href}");
        }
    }

    #[test]
    fn helper_error_and_boundary_cases() {
        let far_future = days_from_civil(10_000, 1, 1) * 86_400;
        assert!(http_date(far_future).contains("10000"));
        assert_eq!(system_time_secs(UNIX_EPOCH - Duration::from_secs(2)), -2);
        with_http_date_now(|first| assert_eq!(first.len(), 29));
        with_http_date_now(|second| assert_eq!(second.len(), 29));

        for invalid in [
            &b"Sunday, broken 08:49:37 GMT"[..],
            b"Sun, 06 Nov 1994 24:49:37 GMT",
            b"Sun, 06 Nov 1994 08:60:37 GMT",
            b"Sun, 06 Nov 1994 08:49:61 GMT",
            b"Sun, 06 Nov 1994 08:49:37:00 GMT",
            b"Sun, 06 Xxx 1994 08:49:37 GMT",
        ] {
            assert!(parse_http_date(invalid).is_none());
        }

        assert!(eq_ignore_ascii_case(b"Host", b"hOsT"));
        assert!(!eq_ignore_ascii_case(b"Host", b"hosts"));
        assert!(!eq_ignore_ascii_case(b"Host", b"post"));
        assert_eq!(trim_ascii(b" \t "), b"");
        assert_eq!(comma_list(b" a, ,b\t,"), [b"a".to_vec(), b"b".to_vec()]);

        assert!(!is_canonical_path(b""));
        assert!(!is_canonical_path(b"relative"));
        assert!(!is_canonical_path(b"/bad\x01"));
        assert!(path_to_rel(b"relative").is_none());
        assert_eq!(path_to_rel(b"/"), Some(Vec::new()));

        assert_eq!(
            html_escape(b"&<>\"' printable \x01"),
            "&amp;&lt;&gt;&quot;&#39; printable \u{fffd}"
        );
        assert_eq!(parse_hex_u64(b""), None);
        assert_eq!(parse_hex_u64(b"aF"), Some(0xaf));
        assert_eq!(parse_hex_u64(b"G"), None);
        assert_eq!(parse_hex_u64(b"10000000000000000"), None);
        assert_eq!(parse_u64(b""), None);
        assert_eq!(parse_u64(b"x"), None);
        assert_eq!(parse_u64(b"18446744073709551616"), None);

        assert_eq!(route_prefix_suffix("/x", "/x"), Some(""));
        assert_eq!(route_prefix_suffix("/x", "/x/y"), Some("y"));
        assert_eq!(route_prefix_suffix("/app/", "/app/child"), Some("child"));
        assert_eq!(route_prefix_suffix("/", "/child"), Some("child"));
        assert_eq!(route_prefix_suffix("/x", "/xy"), None);
        assert_eq!(route_prefix_suffix("/app/", "/app"), None);
    }

    #[test]
    fn capture_expansion_is_bounded_before_replacement() {
        let regex = regex::bytes::Regex::new("^/(.*)$").unwrap();
        let input = format!("/{}", "x".repeat(8190));
        let captures = regex.captures(input.as_bytes()).unwrap();
        assert_eq!(
            expand_regex_captures("/safe/$1", &captures).unwrap(),
            format!("/safe/{}", "x".repeat(8190))
        );
        let amplification = "$1".repeat(16);
        assert!(expand_regex_captures(&amplification, &captures).is_none());
    }
}
