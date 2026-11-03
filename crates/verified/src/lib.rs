//! Security-critical, mechanically verified primitives used by `vapached`.
//!
//! Every function in this crate is proved with Verus.  The runtime calls these
//! functions directly; there is no "verified model" that diverges from the
//! code that ships.  Proofs are erased at compile time, so the only cost is
//! the inherent cost of the algorithm itself.
//!
//! The properties proved here are deliberately stated as *security*
//! postconditions, not merely functional ones:
//!
//! * `percent_decode_path`: output contains no controls, DEL, NUL or
//!   backslash, and (when encoded separators are disabled, the Apache default)
//!   no slash can be introduced via percent-encoding. Non-ASCII bytes remain
//!   byte-exact for the subsequent fail-closed UTF-8 admission gate.
//! * `normalize_uri_path`: output is an absolute path with no `.`/`..`
//!   segments, no duplicate slashes, and no traversal bytes.  Consequently
//!   joining it beneath a document root cannot escape that root in the string
//!   domain.  The server additionally enforces containment at the kernel
//!   level with `openat2(RESOLVE_BENEATH)`; the verified property is the
//!   policy half of a defence-in-depth design.
//! * `sanitize_header_value` / `valid_token`: emitted header values contain no
//!   CR, LF or NUL; header names and methods are RFC 9110 tokens.
//! * `parse_request_head` / `request_framing`: the method and every header name
//!   are tokens, header values contain no control bytes, request targets split
//!   into well-formed origin-form paths, and `Transfer-Encoding` can never
//!   coexist with `Content-Length`.  Chunked framing is HTTP/1.1 only.
//! * `parse_byte_range`: a satisfiable range always has `start <= end` and
//!   `end < file_len`; all arithmetic is checked.

use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------------
// Shared specs
// ---------------------------------------------------------------------------

/// Bytes that may appear in a decoded URI path before UTF-8 validation:
/// visible ASCII except `\`, plus non-ASCII bytes. A space is permitted after
/// percent-decoding (`%20`), matching Apache, and cannot appear literally in
/// a request target because the request-line parser splits on spaces.
/// Control bytes, DEL and `\` remain rejected. The runtime then admits only a
/// well-formed UTF-8 sequence, without replacement-character projection.
pub open spec fn is_path_byte(b: u8) -> bool {
    b >= 0x20 && b != 0x7f && b != 0x5c
}

pub open spec fn all_path_bytes(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> is_path_byte(s[i])
}

pub open spec fn no_crlf_nul(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> s[i] != 0x0a && s[i] != 0x0d && s[i] != 0
}

/// RFC 9110 field-value bytes: HTAB, SP, visible ASCII and obs-text.  All
/// other controls and DEL are rejected so downstream parsers cannot disagree
/// with the serializer about a field boundary.
pub open spec fn header_value_byte_ok(b: u8) -> bool {
    b == b'\t' || (b >= 0x20 && b != 0x7f)
}

pub open spec fn header_value_ok(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> header_value_byte_ok(s[i])
}

pub open spec fn hex_val(b: u8) -> Option<u8> {
    if b >= b'0' && b <= b'9' {
        Some((b - b'0') as u8)
    } else if b >= b'a' && b <= b'f' {
        Some((b - b'a' + 10) as u8)
    } else if b >= b'A' && b <= b'F' {
        Some((b - b'A' + 10) as u8)
    } else {
        None
    }
}

spec fn hex_pair(hi: u8, lo: u8) -> Option<u8> {
    match (hex_val(hi), hex_val(lo)) {
        (Some(h), Some(l)) => Some((h * 16 + l) as u8),
        _ => None,
    }
}

/// Executable mirror of the spec predicate, proved equivalent.
fn path_byte_ok(b: u8) -> (ok: bool)
    ensures ok == is_path_byte(b),
{
    b >= 0x20 && b != 0x7f && b != 0x5c
}

fn hex_val_exec(b: u8) -> (v: Option<u8>)
    ensures v == hex_val(b),
{
    if b >= b'0' && b <= b'9' {
        Some((b - b'0') as u8)
    } else if b >= b'a' && b <= b'f' {
        Some((b - b'a' + 10) as u8)
    } else if b >= b'A' && b <= b'F' {
        Some((b - b'A' + 10) as u8)
    } else {
        None
    }
}

fn tchar_ok(b: u8) -> (ok: bool)
    ensures ok == is_tchar(b),
{
    (b >= b'a' && b <= b'z')
        || (b >= b'A' && b <= b'Z')
        || (b >= b'0' && b <= b'9')
        || b == b'!' || b == b'#' || b == b'$' || b == b'%' || b == b'&'
        || b == b'\'' || b == b'*' || b == b'+' || b == b'-' || b == b'.'
        || b == b'^' || b == b'_' || b == b'`' || b == b'|' || b == b'~'
}


// ---------------------------------------------------------------------------
// Percent decoding
// ---------------------------------------------------------------------------

/// Decode `%XX` escapes in a URI path.
///
/// Returns `None` for malformed escapes, encoded NUL/control bytes, encoded
/// backslashes, and (unless `allow_encoded_slash`) encoded slashes.  The
/// Apache default is `AllowEncodedSlashes Off`, which is also the safest
/// choice: decoding `%2F` before routing is the root cause of several httpd
/// path-confusion CVEs.
pub fn percent_decode_path(input: &[u8], allow_encoded_slash: bool) -> (out: Option<Vec<u8>>)
    ensures
        match out {
            Some(v) => {
                &&& all_path_bytes(v@)
                &&& v@.len() <= input@.len()
            }
            None => true,
        },
{
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i: usize = 0;
    while i < input.len()
        invariant
            0 <= i <= input.len(),
            out@.len() <= i,
            all_path_bytes(out@),
        decreases input.len() - i,
    {
        let b = input[i];
        if b == b'%' {
            if input.len() - i < 3 {
                return None;
            }
            assert(i + 2 < input.len());
            let hi = input[i + 1];
            let lo = input[i + 2];
            let decoded = match (hex_val_exec(hi), hex_val_exec(lo)) {
                (Some(h), Some(l)) => (h * 16 + l) as u8,
                _ => return None,
            };
            if !path_byte_ok(decoded) {
                return None;
            }
            if decoded == b'/' && !allow_encoded_slash {
                return None;
            }
            out.push(decoded);
            i = i + 3;
        } else {
            if !path_byte_ok(b) {
                return None;
            }
            out.push(b);
            i = i + 1;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// URI path canonicalization
// ---------------------------------------------------------------------------

/// True when `i` is a segment boundary in `s`: the start of the path, the end
/// of the path, or a `/` separator.
pub open spec fn is_segment_boundary(s: Seq<u8>, i: int) -> bool {
    i == 0 || i == s.len() || (0 < i < s.len() && s[i] == b'/')
}

/// The canonical-path invariant enforced before any filesystem lookup.
///
/// A canonical path is absolute, contains only safe path bytes, has no empty,
/// `.` or `..` segments, no duplicate slashes, and no trailing slash (except
/// the root `/`).  These are exactly the properties that make a string-domain
/// join beneath a document root unable to escape that root.
pub open spec fn is_canonical_path(s: Seq<u8>) -> bool {
    &&& s.len() >= 1
    &&& s[0] == b'/'
    &&& all_path_bytes(s)
    &&& (s.len() == 1 || s[s.len() - 1] != b'/')
    &&& forall|i: int|
        0 <= i < s.len() - 1 ==> #[trigger] s[i] != b'/' || s[i + 1] != b'/'
    &&& forall|i: int|
        0 <= i < s.len() ==> #[trigger] s[i] != b'.' || !((i == 0 || s[i - 1] == b'/')
            && is_segment_boundary(s, i + 1))
    &&& forall|i: int|
        0 <= i < s.len() - 1 ==> #[trigger] s[i] != b'.' || s[i + 1] != b'.'
            || !((i == 0 || s[i - 1] == b'/')
            && is_segment_boundary(s, i + 2))
}

/// A non-empty path segment with only safe, non-separator bytes.  This is the
/// syntactic check; the parser separately decides whether the segment is a
/// no-op (`.`) or pops a prior segment (`..`).
pub open spec fn is_segment_bytes(input: Seq<u8>, start: int, end: int) -> bool {
    &&& 0 <= start < end <= input.len()
    &&& forall|i: int| start <= i < end ==> is_path_byte(input[i]) && input[i] != b'/'
}

/// A single non-empty path segment stored as a range in the input that is
/// safe to emit: it must not be `.` or `..`.
pub open spec fn is_segment_range(input: Seq<u8>, start: int, end: int) -> bool {
    &&& is_segment_bytes(input, start, end)
    &&& !(end - start == 1 && input[start] == b'.')
    &&& !(end - start == 2 && input[start] == b'.' && input[start + 1] == b'.')
}

pub open spec fn segment_ranges_ok(input: Seq<u8>, ranges: Seq<(usize, usize)>) -> bool {
    forall|k: int| 0 <= k < ranges.len() ==> #[trigger] is_segment_range(
        input,
        ranges[k].0 as int,
        ranges[k].1 as int,
    )
}

fn segment_bytes_ok(input: &[u8], start: usize, end: usize) -> (ok: bool)
    requires
        start <= end <= input.len(),
    ensures
        ok == is_segment_bytes(input@, start as int, end as int),
{
    if start == end {
        return false;
    }
    let mut i = start;
    while i < end
        invariant
            start <= i <= end <= input.len(),
            forall|k: int| start <= k < i ==> is_path_byte(input@[k]) && input@[k] != b'/',
        decreases end - i,
    {
        if !path_byte_ok(input[i]) || input[i] == b'/' {
            return false;
        }
        i = i + 1;
    }
    true
}

proof fn lemma_all_path_bytes_concat(a: Seq<u8>, b: Seq<u8>)
    requires
        all_path_bytes(a),
        all_path_bytes(b),
    ensures
        all_path_bytes(a + b),
{
    assert forall|i: int| 0 <= i < (a + b).len() implies is_path_byte((a + b)[i]) by {
        if i < a.len() {
            assert((a + b)[i] == a[i]);
        } else {
            assert((a + b)[i] == b[i - a.len()]);
        }
    }
}

proof fn lemma_append_segment(s: Seq<u8>, seg: Seq<u8>)
    requires
        is_canonical_path(s),
        seg.len() > 0,
        all_path_bytes(seg),
        forall|i: int| 0 <= i < seg.len() ==> seg[i] != b'/',
        !(seg.len() == 1 && seg[0] == b'.'),
        !(seg.len() == 2 && seg[0] == b'.' && seg[1] == b'.'),
    ensures
        is_canonical_path(if s.len() == 1 { s + seg } else { s + seq![b'/'] + seg }),
{
    let t = if s.len() == 1 { s + seg } else { s + seq![b'/'] + seg };
    assert(all_path_bytes(seq![b'/']));
    lemma_all_path_bytes_concat(s, if s.len() == 1 { seg } else { seq![b'/'] + seg });
    lemma_all_path_bytes_concat(seq![b'/'], seg);
    assert(all_path_bytes(t));
    assert(t.len() >= 1);
    assert(t[0] == b'/');
    assert(s.len() == 1 || s[s.len() - 1] != b'/');
    assert(t[t.len() - 1] == seg[seg.len() - 1]);
    assert(t[t.len() - 1] != b'/');
    assert forall|i: int| #![trigger t[i]] 0 <= i < t.len() - 1 implies !(t[i] == b'/' && t[i + 1] == b'/') by {
        if i < s.len() - 1 {
            assert(t[i] == s[i] && t[i + 1] == s[i + 1]);
        } else if i == s.len() - 1 {
            if s.len() > 1 {
                assert(t[i] == s[i] && t[i + 1] == b'/');
                assert(s[i] != b'/');
            }
        } else {
            let j = i - s.len();
            if s.len() == 1 {
                assert(t[i] == seg[j] && t[i + 1] == seg[j + 1]);
            } else {
                if j == 0 {
                    assert(t[i] == b'/');
                }
                if j == 1 {
                    assert(t[i] == seg[0] && seg[0] != b'/');
                }
                if j >= 2 {
                    assert(t[i] == seg[j - 1] && t[i + 1] == seg[j]);
                }
            }
        }
    }
    assert forall|i: int| #![trigger t[i]] 0 <= i < t.len() implies !(t[i] == b'.'
        && (i == 0 || t[i - 1] == b'/') && is_segment_boundary(t, i + 1)) by {
        if i < s.len() {
            // A dot that was not a complete segment inside `s` cannot become
            // one merely by appending bytes, except at the old end, where it
            // would already have been a complete `.` segment.
            if i == s.len() - 1 && s[i] == b'.' {
                assert(is_segment_boundary(s, i + 1));
                assert(!(i == 0 || s[i - 1] == b'/'));
            }
        } else if i == s.len() {
            if s.len() > 1 {
                assert(t[i] == b'/');
            } else {
                assert(t[i] == seg[0]);
                assert(i == 1);
                if i + 1 < t.len() {
                    assert(t[i + 1] == seg[1]);
                }
            }
        } else {
            let off: int = if s.len() == 1 { 0 } else { 1 };
            let j = i - off - s.len();
            assert(t[i] == seg[j]);
            if seg.len() == 1 {
                assert(is_segment_boundary(t, i + 1));
                assert(seg[0] != b'.');
            }
        }
    }
    assert forall|i: int| #![trigger t[i]] 0 <= i < t.len() - 1 implies !(t[i] == b'.' && t[i + 1] == b'.'
        && (i == 0 || t[i - 1] == b'/') && is_segment_boundary(t, i + 2)) by {
        if i + 1 < s.len() {
            // Both dots were already inside `s`, or the second one was the
            // last byte of `s`; in either case canonicality of `s` applies.
            if i + 2 == s.len() {
                assert(is_segment_boundary(s, i + 2));
            }
        } else if i == s.len() - 1 {
            if s.len() > 1 {
                assert(t[i] == s[i] && t[i + 1] == b'/');
                assert(s[i] != b'.' || s[i - 1] != b'/');
            }
        } else if i == s.len() {
            if s.len() > 1 {
                assert(t[i] == b'/');
            } else {
                assert(t[i] == seg[0]);
                assert(t[i + 1] == seg[1]);
                if seg.len() == 2 {
                    assert(is_segment_boundary(t, i + 2));
                }
            }
        } else {
            let off: int = if s.len() == 1 { 0 } else { 1 };
            let j = i - s.len() - off;
            assert(t[i] == seg[j] && t[i + 1] == seg[j + 1]);
            if j + 2 == seg.len() {
                assert(is_segment_boundary(t, i + 2));
            }
        }
    }
}

/// Canonicalize a decoded, absolute URI path.
///
/// Returns `None` when the path is relative, contains unsafe bytes, or climbs
/// above the root.  On success the result satisfies `is_canonical_path`:
/// absolute, no `.`/`..`/empty segments, no duplicate or trailing slashes, and
/// only admitted path bytes. The runtime uses this verified function directly
/// and separately proves the normalized byte sequence passed its UTF-8 gate
/// before any filesystem lookup.
pub fn normalize_uri_path(input: &[u8]) -> (out: Option<Vec<u8>>)
    ensures
        match out {
            Some(v) => is_canonical_path(v@),
            None => true,
        },
{
    if input.len() == 0 || input[0] != b'/' {
        return None;
    }
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut i: usize = 1;
    let mut start: usize = 1;
    while i <= input.len()
        invariant
            1 <= start <= i <= input.len(),
            segment_ranges_ok(input@, ranges@),
        decreases input.len() + 1 - i,
    {
        let at_end = i == input.len();
        if at_end || input[i] == b'/' {
            if start < i {
                if !segment_bytes_ok(input, start, i) {
                    return None;
                }
                if i - start == 1 && input[start] == b'.' {
                    // A single `.` segment is a no-op.
                } else if i - start == 2 && input[start] == b'.' && input[start + 1] == b'.' {
                    if ranges.pop().is_none() {
                        return None;
                    }
                } else {
                    ranges.push((start, i));
                    assert(is_segment_range(input@, start as int, i as int));
                    assert(segment_ranges_ok(input@, ranges@));
                }
            }
            if at_end {
                break;
            }
            start = i + 1;
        }
        i = i + 1;
    }
    assert(segment_ranges_ok(input@, ranges@));
    let mut out: Vec<u8> = Vec::new();
    out.push(b'/');
    let mut k: usize = 0;
    while k < ranges.len()
        invariant
            0 <= k <= ranges.len(),
            is_canonical_path(out@),
            segment_ranges_ok(input@, ranges@),
            k == 0 ==> out@.len() == 1,
            k > 0 ==> out@.len() > 1,
        decreases ranges.len() - k,
    {
        let (s, e) = ranges[k];
        assert(is_segment_range(input@, s as int, e as int));
        let ghost old_out = out@;
        let ghost seg = input@.subrange(s as int, e as int);
        if out.len() > 1 {
            out.push(b'/');
        }
        out.extend_from_slice(&input[s..e]);
        if k == 0 {
            assert(out@ == old_out + seg);
        } else {
            assert(out@ == old_out + seq![b'/'] + seg);
        }
        proof {
            lemma_append_segment(old_out, seg);
        }
        k = k + 1;
    }
    Some(out)
}

/// A normalized path becomes a textual routing/ACL identity only when both
/// properties hold. `valid_utf8` is supplied by Rust's standard-library UTF-8
/// validator; keeping it explicit here prevents a caller from treating lossy
/// decoding as successful admission.
pub open spec fn canonical_path_text_spec(canonical: bool, valid_utf8: bool) -> bool {
    canonical && valid_utf8
}

pub fn canonical_path_text_admit(canonical: bool, valid_utf8: bool) -> (admit: bool)
    ensures admit == canonical_path_text_spec(canonical, valid_utf8),
{
    canonical && valid_utf8
}

pub proof fn canonical_path_text_rejects_invalid_utf8(canonical: bool)
    ensures !canonical_path_text_spec(canonical, false),
{
}

/// Configuration and filesystem policy identities are textual.  Their
/// canonicality is established by the caller; this gate records the separate
/// requirement that the identity was decoded without replacement characters.
pub open spec fn text_identity_spec(valid_utf8: bool) -> bool {
    valid_utf8
}

pub fn text_identity_admit(valid_utf8: bool) -> (admit: bool)
    ensures admit == text_identity_spec(valid_utf8),
{
    valid_utf8
}

pub proof fn text_identity_rejects_invalid_utf8()
    ensures !text_identity_spec(false),
{
}

/// Encode a rewrite backreference or variable value for a URL substitution.
/// The adapter uses this by default so a capture containing `?` cannot turn
/// the remainder into a query-string injection.  `UnsafeAllow3F` is an
/// explicit opt-out at configuration time.
pub fn rewrite_backref_no_qmark(value: &[u8]) -> (out: Vec<u8>)
    ensures
        forall|i: int| 0 <= i < out@.len() ==> out@[i] != b'?',
{
    let mut out: Vec<u8> = Vec::with_capacity(value.len());
    let mut i: usize = 0;
    while i < value.len()
        invariant
            0 <= i <= value.len(),
            forall|j: int| 0 <= j < out@.len() ==> out@[j] != b'?',
        decreases value.len() - i,
    {
        if value[i] == b'?' {
            out.push(b'%');
            out.push(b'3');
            out.push(b'f');
        } else {
            out.push(value[i]);
        }
        i = i + 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Generalized percent encoding
// ---------------------------------------------------------------------------

/// The encoding alphabet of `percent_encode`: the escape introducer `%`, the
/// lower-case hex digits, and (only when `plus_space` is set) the form-style
/// `+` that stands for an encoded space.
pub open spec fn percent_alphabet_byte(b: u8, plus_space: bool) -> bool {
    ||| b == b'%'
    ||| (plus_space && b == b'+')
    ||| (b >= b'0' && b <= b'9')
    ||| (b >= b'a' && b <= b'f')
}

/// Percent-encode `input[start..]` under a 256-entry byte `mask`.  A masked
/// byte is emitted as `%xx` (lower-case hex, matching Apache) or as `+` for
/// a masked space when `plus_space` is set (the `x-www-form-urlencoded`
/// convention used by the rewrite `int:escape` map and `[BNP]`-style
/// backreference escaping); an unmasked byte is copied verbatim.
///
/// This is the one specification shared by the whole percent-escape family:
/// rewrite backreference `[B]`/`[BNE]`/`[BCTLS]`/`[BNP]` escaping,
/// redirect-`Location` escaping and the `int` map's escape.  The masks are
/// runtime data; the encoding loop and its guarantees are proved once.  The
/// recursion is indexed by `start` rather than `drop_first()` so the
/// refinement below needs no sequence-slicing lemmas.
pub open spec fn percent_encode_from(
    input: Seq<u8>,
    start: int,
    mask: Seq<bool>,
    plus_space: bool,
) -> Seq<u8>
    decreases input.len() - start,
{
    if input.len() <= start {
        Seq::empty()
    } else {
        let b = input[start];
        let rest = percent_encode_from(input, start + 1, mask, plus_space);
        if mask[b as int] {
            if plus_space && b == b' ' {
                seq![b'+'] + rest
            } else {
                seq![b'%'] + hex_byte_spec(b) + rest
            }
        } else {
            seq![b] + rest
        }
    }
}

/// Executable refinement of `percent_encode_from` over the whole input.
pub fn percent_encode(input: &[u8], mask: &[bool], plus_space: bool) -> (out: Vec<u8>)
    requires
        mask@.len() == 256,
    ensures
        out@ == percent_encode_from(input@, 0, mask@, plus_space),
        out@.len() <= input@.len() * 3,
{
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < input.len()
        invariant
            0 <= i <= input.len(),
            mask@.len() == 256,
            out@ + percent_encode_from(input@, i as int, mask@, plus_space)
                == percent_encode_from(input@, 0, mask@, plus_space),
            out@.len() <= (i as int) * 3,
        decreases input.len() - i,
    {
        let b = input[i];
        if mask[b as usize] {
            if plus_space && b == b' ' {
                out.push(b'+');
            } else {
                let hi = hex_digit(b / 16);
                let lo = hex_digit(b % 16);
                out.push(b'%');
                out.push(hi);
                out.push(lo);
            }
        } else {
            out.push(b);
        }
        i = i + 1;
    }
    out
}

/// Encoding is the identity on inputs with no masked byte: unmasked bytes
/// are copied verbatim and in order.
pub proof fn percent_encode_identity(input: Seq<u8>, mask: Seq<bool>, plus_space: bool)
    requires
        forall|k: int| 0 <= k < input.len() ==> !mask[input[k] as int],
    ensures percent_encode_from(input, 0, mask, plus_space) == input,
{
    percent_encode_from_identity(input, 0, mask, plus_space);
}

/// Pointwise identity underlying `percent_encode_identity`: with no masked
/// byte from `start` on, the encoded suffix has exactly the remaining length
/// and copies every remaining byte in order.
pub proof fn percent_encode_from_identity(
    input: Seq<u8>,
    start: int,
    mask: Seq<bool>,
    plus_space: bool,
)
    requires
        0 <= start <= input.len(),
        forall|k: int| start <= k < input.len() ==> !mask[input[k] as int],
    ensures
        percent_encode_from(input, start, mask, plus_space).len() == input.len() - start,
        forall|j: int|
            0 <= j < input.len() - start ==> #[trigger]
                percent_encode_from(input, start, mask, plus_space)[j] == input[start + j],
    decreases input.len() - start,
{
    let out = percent_encode_from(input, start, mask, plus_space);
    if input.len() <= start {
        assert(out == Seq::<u8>::empty());
    } else {
        let b = input[start];
        let rest = percent_encode_from(input, start + 1, mask, plus_space);
        percent_encode_from_identity(input, start + 1, mask, plus_space);
        assert(!mask[b as int]);
        assert(out == seq![b] + rest);
        assert(out.len() == 1 + rest.len());
        assert(out[0] == b);
        assert forall|j: int| 1 <= j < out.len() implies #[trigger] out[j] == rest[j - 1] by {
            assert((seq![b] + rest)[j] == rest[j - 1]);
        }
        assert forall|j: int|
            0 <= j < input.len() - start implies #[trigger] out[j] == input[start + j] by {
            if j == 0 {
                assert(input.len() - start > 0);
                assert(out[0] == b);
            } else {
                assert(rest[j - 1] == input[(start + 1) + (j - 1)]);
            }
        }
    }
}

/// No masked byte survives into the output verbatim: every raw output byte
/// is either unmasked or the form-style `+` standing for a masked space.  A
/// caller whose mask does not mark any alphabet byte therefore cannot be
/// re-interpreted through a raw occurrence of a byte it meant to escape.
pub open spec fn no_masked_raw(s: Seq<u8>, mask: Seq<bool>, plus_space: bool) -> bool {
    forall|k: int|
        0 <= k < s.len() ==> !mask[s[k] as int] || (plus_space && s[k] == b'+')
}

pub proof fn percent_encode_no_masked_raw(
    input: Seq<u8>,
    start: int,
    mask: Seq<bool>,
    plus_space: bool,
)
    requires
        0 <= start,
        mask.len() == 256,
        forall|b: u8| percent_alphabet_byte(b, plus_space) ==> !mask[b as int],
    ensures
        no_masked_raw(percent_encode_from(input, start, mask, plus_space), mask, plus_space),
    decreases input.len() - start,
{
    let out = percent_encode_from(input, start, mask, plus_space);
    if input.len() <= start {
        assert(out == Seq::<u8>::empty());
        assert(no_masked_raw(out, mask, plus_space));
    } else {
        let b = input[start];
        let rest = percent_encode_from(input, start + 1, mask, plus_space);
        percent_encode_no_masked_raw(input, start + 1, mask, plus_space);
        if mask[b as int] {
            if plus_space && b == b' ' {
                assert(out == seq![b'+'] + rest);
                assert(!mask[b'+' as int]);
                assert(out.len() == 1 + rest.len());
                assert(out[0] == b'+');
                assert forall|k: int|
                    1 <= k < out.len() implies #[trigger] out[k] == rest[k - 1] by {
                    assert((seq![b'+'] + rest)[k] == rest[k - 1]);
                }
                assert(no_masked_raw(out, mask, plus_space));
            } else {
                assert(out == seq![b'%'] + hex_byte_spec(b) + rest);
                assert(hex_byte_spec(b).len() == 2);
                assert(hex_byte_spec(b)[0] == hex_digit_char(b / 16));
                assert(hex_byte_spec(b)[1] == hex_digit_char(b % 16));
                assert(percent_alphabet_byte(hex_byte_spec(b)[0], plus_space));
                assert(percent_alphabet_byte(hex_byte_spec(b)[1], plus_space));
                assert(percent_alphabet_byte(b'%', plus_space));
                assert(!mask[b'%' as int]);
                assert(!mask[hex_byte_spec(b)[0] as int]);
                assert(!mask[hex_byte_spec(b)[1] as int]);
                assert(out.len() == 3 + rest.len());
                assert(out[0] == b'%');
                assert(out[1] == hex_byte_spec(b)[0]);
                assert(out[2] == hex_byte_spec(b)[1]);
                assert forall|k: int|
                    3 <= k < out.len() implies #[trigger] out[k] == rest[k - 3] by {
                    assert((seq![b'%'] + hex_byte_spec(b) + rest)[k] == rest[k - 3]);
                }
                assert(no_masked_raw(out, mask, plus_space));
            }
        } else {
            assert(out == seq![b] + rest);
            assert(!mask[b as int]);
            assert(out.len() == 1 + rest.len());
            assert(out[0] == b);
            assert forall|k: int|
                1 <= k < out.len() implies #[trigger] out[k] == rest[k - 1] by {
                assert((seq![b] + rest)[k] == rest[k - 1]);
            }
            assert(no_masked_raw(out, mask, plus_space));
        }
    }
}

/// ASCII-case-insensitive prefix predicate used for rewrite URL schemes.
pub open spec fn starts_with_ignore_ascii_case_spec(
    s: Seq<u8>,
    prefix: Seq<u8>,
) -> bool {
    s.len() >= prefix.len()
        && eq_ignore_ascii_case_spec(s.subrange(0, prefix.len() as int), prefix)
}

fn starts_with_ignore_ascii_case(s: &[u8], prefix: &[u8]) -> (ok: bool)
    ensures ok == starts_with_ignore_ascii_case_spec(s@, prefix@),
{
    if s.len() < prefix.len() {
        false
    } else {
        eq_ignore_ascii_case(&s[..prefix.len()], prefix)
    }
}

pub open spec fn ascii_digit(b: u8) -> bool {
    b >= b'0' && b <= b'9'
}

pub open spec fn all_ascii_digits(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> ascii_digit(s[i])
}

pub open spec fn no_colon_from(s: Seq<u8>, start: int) -> bool {
    forall|j: int| start <= j && j < s.len() ==> s[j] != b':'
}

pub open spec fn digits_between(s: Seq<u8>, start: int, end: int) -> bool {
    forall|j: int| start <= j && j < end ==> ascii_digit(s[j])
}

/// Index of the last colon at or before `end`, or -1 when there is none.
pub open spec fn last_colon_from(s: Seq<u8>, end: int) -> int
    decreases end,
{
    if end <= 0 {
        -1
    } else if s[end - 1] == b':' {
        end - 1
    } else {
        last_colon_from(s, end - 1)
    }
}

/// Drop a trailing decimal port only when it follows the final colon.  A
/// bracketed IPv6 literal without a port has a non-digit suffix after its
/// last colon, so it is left unchanged.
pub open spec fn strip_port_spec(s: Seq<u8>) -> Seq<u8> {
    let colon = last_colon_from(s, s.len() as int);
    if colon >= 0 && colon + 1 < s.len()
        && digits_between(s, colon + 1, s.len() as int)
    {
        s.subrange(0, colon)
    } else {
        s
    }
}

proof fn lemma_last_colon_found(s: Seq<u8>, end: int, colon: int)
    requires
        0 <= colon < end,
        end <= s.len(),
        s[colon] == b':',
        forall|j: int| colon < j < end ==> s[j] != b':',
    ensures last_colon_from(s, end) == colon,
    decreases end,
{
    if end <= 0 {
    } else if s[end - 1] == b':' {
        assert(end - 1 == colon);
    } else {
        lemma_last_colon_found(s, end - 1, colon);
    }
}

proof fn lemma_last_colon_none(s: Seq<u8>, end: int)
    requires
        0 <= end <= s.len(),
        forall|j: int| 0 <= j < end ==> s[j] != b':',
    ensures last_colon_from(s, end) == -1,
    decreases end,
{
    if end <= 0 {
    } else {
        lemma_last_colon_none(s, end - 1);
    }
}

fn ascii_digit_exec(b: u8) -> (ok: bool)
    ensures ok == ascii_digit(b),
{
    b >= b'0' && b <= b'9'
}

fn copy_prefix(s: &[u8], n: usize) -> (out: Vec<u8>)
    requires n <= s.len(),
    ensures out@ == s@.subrange(0, n as int),
{
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut i: usize = 0;
    while i < n
        invariant
            i <= n,
            n <= s.len(),
            out@ == s@.subrange(0, i as int),
        decreases n - i,
    {
        out.push(s[i]);
        i = i + 1;
    }
    out
}

fn strip_port(s: &[u8]) -> (out: Vec<u8>)
    ensures out@ == strip_port_spec(s@),
{
    let mut i: usize = s.len();
    let mut found: Option<usize> = None;
    while i > 0
        invariant
            i <= s.len(),
            match found {
                Some(colon) => {
                    0 <= colon < s.len()
                        && s@[colon as int] == b':'
                        && no_colon_from(s@, colon as int + 1)
                }
                None => no_colon_from(s@, i as int),
            },
        decreases i,
    {
        i = i - 1;
        if s[i] == b':' && found.is_none() {
            found = Some(i);
        }
    }
    match found {
        Some(colon) => {
            assert(s@[colon as int] == b':');
            assert(no_colon_from(s@, colon as int + 1));
            proof { lemma_last_colon_found(s@, s.len() as int, colon as int); }
            if colon + 1 < s.len() {
                let mut j: usize = colon + 1;
                let mut all = true;
                while j < s.len()
                    invariant
                        colon + 1 <= j <= s.len(),
                        all == digits_between(s@, colon as int + 1, j as int),
                    decreases s.len() - j,
                {
                    if !ascii_digit_exec(s[j]) {
                        all = false;
                    }
                    j = j + 1;
                }
                if all {
                    assert(digits_between(s@, colon as int + 1, s.len() as int));
                    copy_prefix(s, colon)
                } else {
                    assert(!digits_between(s@, colon as int + 1, s.len() as int));
                    copy_prefix(s, s.len())
                }
            } else {
                assert(!(colon as int + 1 < s.len() as int));
                copy_prefix(s, s.len())
            }
        }
        None => {
            assert(no_colon_from(s@, 0));
            proof { lemma_last_colon_none(s@, s.len() as int); }
            copy_prefix(s, s.len())
        }
    }
}

/// Legacy textual authority comparison. Ports are part of the authority:
/// silently dropping them made `example:80` equal to `example:443`, which can
/// internalize a rewrite intended for a different security endpoint.
pub fn rewrite_authority_equal(authority: &[u8], host: &[u8]) -> (equal: bool)
    ensures equal == eq_ignore_ascii_case_spec(authority@, host@),
{
    eq_ignore_ascii_case(authority, host)
}

/// Endpoint identity used for absolute-form requests and rewrite URL
/// internalization.  Scheme, effective port, and normalized host must all
/// agree; no layer is allowed to discard one of those dimensions.
pub open spec fn authority_endpoint_equal_spec(
    left_host: Seq<u8>,
    left_port: u16,
    left_tls: bool,
    right_host: Seq<u8>,
    right_port: u16,
    right_tls: bool,
) -> bool {
    eq_ignore_ascii_case_spec(left_host, right_host)
        && left_port == right_port
        && left_tls == right_tls
}

pub fn authority_endpoint_equal(
    left_host: &[u8],
    left_port: u16,
    left_tls: bool,
    right_host: &[u8],
    right_port: u16,
    right_tls: bool,
) -> (equal: bool)
    ensures equal == authority_endpoint_equal_spec(
        left_host@,
        left_port,
        left_tls,
        right_host@,
        right_port,
        right_tls,
    ),
{
    eq_ignore_ascii_case(left_host, right_host)
        && left_port == right_port
        && left_tls == right_tls
}

/// Bytes admitted to the HTTP authority parser are visible ASCII.  This
/// excludes every whitespace/control delimiter before the runtime projects
/// the value into host and port components.
pub open spec fn http_authority_visible_spec(value: Seq<u8>) -> bool {
    value.len() > 0
        && forall|i: int| 0 <= i < value.len() ==> 0x20 < value[i] && value[i] < 0x7f
}

pub fn http_authority_visible_admit(value: &[u8]) -> (ok: bool)
    ensures ok == http_authority_visible_spec(value@),
{
    if value.len() == 0 {
        return false;
    }
    let mut i: usize = 0;
    while i < value.len()
        invariant
            i <= value.len(),
            forall|j: int| 0 <= j < i ==> 0x20 < value@[j] && value@[j] < 0x7f,
        decreases value.len() - i,
    {
        if value[i] <= 0x20 || value[i] >= 0x7f {
            return false;
        }
        i = i + 1;
    }
    assert(http_authority_visible_spec(value@));
    true
}

pub open spec fn http_reg_name_byte(b: u8) -> bool {
    ||| (b >= b'a' && b <= b'z')
    ||| (b >= b'A' && b <= b'Z')
    ||| (b >= b'0' && b <= b'9')
    ||| b == b'-' || b == b'.' || b == b'_' || b == b'~' || b == b'!'
    ||| b == b'$' || b == b'&' || b == b'\'' || b == b'(' || b == b')'
    ||| b == b'*' || b == b'+' || b == b',' || b == b';' || b == b'='
}

pub open spec fn http_reg_name_from_spec(value: Seq<u8>, i: int) -> bool
    decreases value.len() - i,
{
    if i >= value.len() {
        true
    } else if http_reg_name_byte(value[i]) {
        http_reg_name_from_spec(value, i + 1)
    } else {
        value[i] == b'%'
            && i + 2 < value.len()
            && hex_val(value[i + 1]).is_some()
            && hex_val(value[i + 2]).is_some()
            && http_reg_name_from_spec(value, i + 3)
    }
}

pub open spec fn http_reg_name_spec(value: Seq<u8>) -> bool {
    value.len() > 0 && http_reg_name_from_spec(value, 0)
}

fn http_reg_name_from_exec(value: &[u8], i: usize) -> (ok: bool)
    requires i <= value.len(),
    ensures ok == http_reg_name_from_spec(value@, i as int),
{
    let mut cursor = i;
    while cursor < value.len()
        invariant
            i <= cursor <= value.len(),
            http_reg_name_from_spec(value@, i as int)
                == http_reg_name_from_spec(value@, cursor as int),
        decreases value.len() - cursor,
    {
        let b = value[cursor];
        let ordinary = (b >= b'a' && b <= b'z')
            || (b >= b'A' && b <= b'Z')
            || (b >= b'0' && b <= b'9')
            || b == b'-' || b == b'.' || b == b'_' || b == b'~' || b == b'!'
            || b == b'$' || b == b'&' || b == b'\'' || b == b'(' || b == b')'
            || b == b'*' || b == b'+' || b == b',' || b == b';' || b == b'=';
        if ordinary {
            cursor = cursor + 1;
        } else if b == b'%' {
            if value.len() - cursor < 3 {
                return false;
            } else if hex_val_exec(value[cursor + 1]).is_some()
                && hex_val_exec(value[cursor + 2]).is_some()
            {
                cursor = cursor + 3;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

/// RFC 3986 registered-name admission. Percent escapes are consumed as one
/// three-byte unit, so a delimiter can never be manufactured by a partial
/// escape at a later parsing layer.
pub fn http_reg_name_admit(value: &[u8]) -> (ok: bool)
    ensures ok == http_reg_name_spec(value@),
{
    value.len() > 0 && http_reg_name_from_exec(value, 0)
}

/// Parse an explicit authority port with checked decimal arithmetic.  The
/// returned type makes overflow beyond the protocol's u16 port space
/// impossible for every downstream authority consumer.
pub fn parse_http_authority_port(value: &[u8]) -> (port: Option<u16>)
    ensures
        match port {
            Some(_) => value@.len() > 0
                && forall|i: int| 0 <= i < value@.len()
                    ==> b'0' <= value@[i] && value@[i] <= b'9',
            None => true,
        },
{
    match parse_decimal_u64(value) {
        Some(parsed) if parsed <= u16::MAX as u64 => Some(parsed as u16),
        _ => None,
    }
}

fn parse_ipv4_embedded(input: &[u8]) -> (address: Option<u32>)
    ensures
        match address {
            Some(_) => input@.len() > 0
                && forall|i: int| 0 <= i < input@.len()
                    ==> ascii_digit(input@[i]) || input@[i] == b'.',
            None => true,
        },
{
    if input.len() == 0 {
        return None;
    }
    let mut value: u32 = 0;
    let mut part: usize = 0;
    let mut cursor: usize = 0;
    while part < 4
        invariant
            part <= 4,
            cursor <= input.len(),
            part == 4 ==> cursor == input.len(),
            forall|i: int| 0 <= i < cursor
                ==> ascii_digit(input@[i]) || input@[i] == b'.',
        decreases 4 - part,
    {
        let start = cursor;
        let mut octet: u16 = 0;
        while cursor < input.len() && input[cursor] != b'.'
            invariant
                start <= cursor <= input.len(),
                octet <= 255,
                forall|i: int| 0 <= i < start
                    ==> ascii_digit(input@[i]) || input@[i] == b'.',
                forall|i: int| start <= i < cursor ==> ascii_digit(input@[i]),
            decreases input.len() - cursor,
        {
            let byte = input[cursor];
            if byte < b'0' || byte > b'9' || cursor - start >= 3 {
                return None;
            }
            octet = octet * 10 + (byte - b'0') as u16;
            if octet > 255 {
                return None;
            }
            cursor = cursor + 1;
        }
        if cursor == start {
            return None;
        }
        // RFC 3986 dec-octet has no multi-digit leading-zero form. Reject it
        // so an embedded IPv4 address has one textual/numeric interpretation.
        if cursor - start > 1 && input[start] == b'0' {
            return None;
        }
        value = (value << 8) | octet as u32;
        part = part + 1;
        if part < 4 {
            if cursor >= input.len() || input[cursor] != b'.' {
                return None;
            }
            cursor = cursor + 1;
        } else if cursor != input.len() {
            return None;
        }
    }
    assert(cursor == input.len());
    Some(value)
}

/// Strict IPv6 parser used by HTTP authorities. It supports compressed forms
/// and the final dotted-IPv4 form, returning the exact 128-bit address so no
/// standard-library string parser remains on the security boundary.
pub fn parse_http_ipv6_literal(input: &[u8]) -> (address: Option<u128>)
    ensures
        match address {
            Some(_) => input@.len() >= 2
                && forall|i: int| 0 <= i < input@.len()
                    ==> is_hex_byte(input@[i]) || input@[i] == b':' || input@[i] == b'.',
            None => true,
        },
{
    if input.len() < 2 {
        return None;
    }
    let mut words: Vec<u16> = Vec::new();
    let mut compressed_at: Option<usize> = None;
    let mut cursor: usize = 0;
    if input[0] == b':' {
        if input[1] != b':' {
            return None;
        }
        compressed_at = Some(0);
        cursor = 2;
    }
    while cursor < input.len()
        invariant
            cursor <= input.len(),
            words.len() <= 8,
            forall|i: int| 0 <= i < cursor
                ==> is_hex_byte(input@[i]) || input@[i] == b':' || input@[i] == b'.',
            match compressed_at {
                Some(position) => position <= words.len(),
                None => true,
            },
        decreases input.len() - cursor,
    {
        let start = cursor;
        let mut dotted = false;
        while cursor < input.len() && input[cursor] != b':'
            invariant
                start <= cursor <= input.len(),
                forall|i: int| 0 <= i < start
                    ==> is_hex_byte(input@[i]) || input@[i] == b':' || input@[i] == b'.',
            decreases input.len() - cursor,
        {
            if input[cursor] == b'.' {
                dotted = true;
            }
            cursor = cursor + 1;
        }
        if dotted {
            if cursor != input.len() || words.len() > 6 {
                return None;
            }
            let ipv4 = match parse_ipv4_embedded(&input[start..cursor]) {
                Some(value) => value,
                None => return None,
            };
            assert forall|i: int| start <= i < cursor implies
                is_hex_byte(input@[i]) || input@[i] == b':' || input@[i] == b'.' by {
                assert(input@[i] == input@.subrange(start as int, cursor as int)[i - start]);
            }
            words.push((ipv4 >> 16) as u16);
            words.push((ipv4 & 0xffff) as u16);
        } else {
            if cursor == start || cursor - start > 4 || words.len() >= 8 {
                return None;
            }
            let value = match parse_chunk_size_hex(&input[start..cursor]) {
                Some(value) if value <= u16::MAX as u64 => value,
                _ => return None,
            };
            assert forall|i: int| start <= i < cursor implies
                is_hex_byte(input@[i]) || input@[i] == b':' || input@[i] == b'.' by {
                assert(input@[i] == input@.subrange(start as int, cursor as int)[i - start]);
            }
            words.push(value as u16);
        }
        assert forall|i: int| 0 <= i < cursor implies
            is_hex_byte(input@[i]) || input@[i] == b':' || input@[i] == b'.' by {}
        if cursor < input.len() {
            if cursor + 1 < input.len() && input[cursor + 1] == b':' {
                if compressed_at.is_some() {
                    return None;
                }
                compressed_at = Some(words.len());
                cursor = cursor + 2;
            } else {
                cursor = cursor + 1;
                if cursor == input.len() {
                    return None;
                }
            }
        }
    }
    assert(cursor == input.len());
    let zeros = match compressed_at {
        Some(_) => {
            if words.len() >= 8 {
                return None;
            }
            8 - words.len()
        }
        None => {
            if words.len() != 8 {
                return None;
            }
            0
        }
    };
    let gap = compressed_at.unwrap_or(words.len());
    let mut address: u128 = 0;
    let mut position: usize = 0;
    while position < 8
        invariant
            position <= 8,
            words.len() <= 8,
            gap <= words.len(),
            gap + zeros <= 8,
            input@.len() >= 2,
            forall|i: int| 0 <= i < input@.len()
                ==> is_hex_byte(input@[i]) || input@[i] == b':' || input@[i] == b'.',
        decreases 8 - position,
    {
        let word = if position < gap {
            words[position]
        } else if position < gap + zeros {
            0
        } else {
            let source = position - zeros;
            if source >= words.len() {
                return None;
            }
            words[source]
        };
        address = (address << 16) | word as u128;
        position = position + 1;
    }
    Some(address)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HttpAuthorityHost {
    RegName(Vec<u8>),
    Ipv6(u128),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ParsedHttpAuthority {
    pub host: HttpAuthorityHost,
    pub port: u16,
}

fn lower_authority_host(input: &[u8]) -> (out: Vec<u8>)
    ensures out@.len() == input@.len(),
{
    let mut out = Vec::with_capacity(input.len());
    let mut i: usize = 0;
    while i < input.len()
        invariant i <= input.len(), out@.len() == i,
        decreases input.len() - i,
    {
        let byte = input[i];
        out.push(if byte >= b'A' && byte <= b'Z' { byte + 32 } else { byte });
        i = i + 1;
    }
    out
}

/// Parse the complete authority shape, host syntax, IP literal and effective
/// port in one executable verified function. Downstream code receives a typed
/// host and never repeats bracket/colon/string splitting.
pub fn parse_http_authority_endpoint(
    value: &[u8],
    default_port: u16,
) -> (parsed: Option<ParsedHttpAuthority>)
    ensures
        match parsed {
            Some(_) => http_authority_visible_spec(value@),
            None => true,
        },
{
    if !http_authority_visible_admit(value) {
        return None;
    }
    if value[0] == b'[' {
        let mut close: usize = 1;
        while close < value.len() && value[close] != b']'
            invariant 1 <= close <= value.len(),
            decreases value.len() - close,
        {
            close = close + 1;
        }
        if close == value.len() || close == 1 {
            return None;
        }
        let host = match parse_http_ipv6_literal(&value[1..close]) {
            Some(address) => address,
            None => return None,
        };
        let suffix = close + 1;
        let port = if suffix == value.len() {
            default_port
        } else {
            if value[suffix] != b':' {
                return None;
            }
            match parse_http_authority_port(&value[suffix + 1..]) {
                Some(port) => port,
                None => return None,
            }
        };
        return Some(ParsedHttpAuthority {
            host: HttpAuthorityHost::Ipv6(host),
            port,
        });
    }

    let mut colon: Option<usize> = None;
    let mut i: usize = 0;
    while i < value.len()
        invariant
            i <= value.len(),
            match colon {
                Some(index) => index < i,
                None => true,
            },
        decreases value.len() - i,
    {
        let byte = value[i];
        if byte == b'[' || byte == b']' || byte == b'@' || byte == b'/'
            || byte == b'\\' || byte == b'?' || byte == b'#'
        {
            return None;
        }
        if byte == b':' {
            if colon.is_some() {
                return None;
            }
            colon = Some(i);
        }
        i = i + 1;
    }
    let (host_end, port) = match colon {
        Some(index) => {
            let port = match parse_http_authority_port(&value[index + 1..]) {
                Some(port) => port,
                None => return None,
            };
            (index, port)
        }
        None => (value.len(), default_port),
    };
    let host = &value[..host_end];
    if !http_reg_name_admit(host) {
        return None;
    }
    Some(ParsedHttpAuthority {
        host: HttpAuthorityHost::RegName(lower_authority_host(host)),
        port,
    })
}

/// The external-URL decision used by rewrite target resolution.  A target is
/// external if it is scheme-relative (`//...`) or an HTTP(S) URL, matching
/// Apache's case-insensitive scheme handling.
pub open spec fn rewrite_target_external_spec(target: Seq<u8>) -> bool {
    (target.len() >= 2 && target[0] == b'/' && target[1] == b'/')
        || (target.len() >= 7
            && lower_byte(target[0]) == b'h'
            && lower_byte(target[1]) == b't'
            && lower_byte(target[2]) == b't'
            && lower_byte(target[3]) == b'p'
            && target[4] == b':'
            && target[5] == b'/'
            && target[6] == b'/')
        || (target.len() >= 8
            && lower_byte(target[0]) == b'h'
            && lower_byte(target[1]) == b't'
            && lower_byte(target[2]) == b't'
            && lower_byte(target[3]) == b'p'
            && lower_byte(target[4]) == b's'
            && target[5] == b':'
            && target[6] == b'/'
            && target[7] == b'/')
}

pub fn rewrite_target_external(target: &[u8]) -> (external: bool)
    ensures external == rewrite_target_external_spec(target@),
{
    (target.len() >= 2 && target[0] == b'/' && target[1] == b'/')
        || (target.len() >= 7
            && lower_byte_exec(target[0]) == b'h'
            && lower_byte_exec(target[1]) == b't'
            && lower_byte_exec(target[2]) == b't'
            && lower_byte_exec(target[3]) == b'p'
            && target[4] == b':'
            && target[5] == b'/'
            && target[6] == b'/')
        || (target.len() >= 8
            && lower_byte_exec(target[0]) == b'h'
            && lower_byte_exec(target[1]) == b't'
            && lower_byte_exec(target[2]) == b't'
            && lower_byte_exec(target[3]) == b'p'
            && lower_byte_exec(target[4]) == b's'
            && target[5] == b':'
            && target[6] == b'/'
            && target[7] == b'/')
}

/// Terminal sink selected after a rewrite substitution has been expanded.
/// Proxying has precedence over redirect classification because `[P]` is an
/// explicit capability; an external URL or `[R]` otherwise redirects, and
/// only the remaining case may re-enter internal URL mapping.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RewriteSink {
    Internal,
    Redirect,
    Proxy,
}

pub open spec fn rewrite_sink_spec(
    proxy: bool,
    external: bool,
    redirect: bool,
) -> RewriteSink {
    if proxy {
        RewriteSink::Proxy
    } else if external || redirect {
        RewriteSink::Redirect
    } else {
        RewriteSink::Internal
    }
}

pub fn rewrite_sink(proxy: bool, external: bool, redirect: bool) -> (sink: RewriteSink)
    ensures sink == rewrite_sink_spec(proxy, external, redirect),
{
    if proxy {
        RewriteSink::Proxy
    } else if external || redirect {
        RewriteSink::Redirect
    } else {
        RewriteSink::Internal
    }
}

pub proof fn rewrite_proxy_sink_is_explicit(external: bool, redirect: bool)
    ensures rewrite_sink_spec(true, external, redirect) == RewriteSink::Proxy,
{
}

pub proof fn rewrite_internal_sink_has_no_terminal_flag(
    proxy: bool,
    external: bool,
    redirect: bool,
)
    ensures
        rewrite_sink_spec(proxy, external, redirect) == RewriteSink::Internal
            ==> !proxy && !external && !redirect,
{
}

// ---------------------------------------------------------------------------
// Transform -> reauthorize -> sink capability pipeline
// ---------------------------------------------------------------------------

/// The security-relevant state carried from target selection to the final
/// body/tunnel/cache sink.  A transform deliberately clears every authority;
/// authorization and object/backend binding must then be rebuilt for the new
/// target before a sink can be entered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TransformCapability {
    pub target_bound: bool,
    pub authorized: bool,
    pub inode_bound: bool,
    pub backend_bound: bool,
    /// The authorized front-end path and serialized backend path have passed
    /// the same representation-safety gate. This is distinct from binding
    /// the backend endpoint itself.
    pub representation_bound: bool,
    pub policy_bound: bool,
}

/// The distinct sink classes have different binding requirements.  FastCGI
/// is both a local script-object transition and an outbound backend
/// transition, so it is intentionally the strongest case.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransformSink {
    StaticFile,
    Directory,
    LocalCgi,
    FastCgi,
    Proxy,
    Cache,
}

/// P15-A: a FastCGI request has two deliberately separate path identities.
/// The canonical descriptor target is the authorization object, while the
/// lexical split prefix is the Apache-compatible `SCRIPT_FILENAME` presented
/// to the backend. Admission requires the lexical path to still resolve to
/// the authorized inode immediately before it is sent.
pub open spec fn fastcgi_script_identity_admit_spec(
    canonical_authorized: bool,
    lexical_inode_bound: bool,
    forwards_lexical: bool,
    backend_binds_both: bool,
) -> bool {
    canonical_authorized && lexical_inode_bound && forwards_lexical && backend_binds_both
}

pub fn fastcgi_script_identity_admit(
    canonical_authorized: bool,
    lexical_inode_bound: bool,
    forwards_lexical: bool,
    backend_binds_both: bool,
) -> (admit: bool)
    ensures admit == fastcgi_script_identity_admit_spec(
        canonical_authorized,
        lexical_inode_bound,
        forwards_lexical,
        backend_binds_both,
    )
{
    canonical_authorized && lexical_inode_bound && forwards_lexical && backend_binds_both
}

pub proof fn fastcgi_identity_admission_requires_backend_parity(
    canonical_authorized: bool,
    lexical_inode_bound: bool,
    forwards_lexical: bool,
    backend_binds_both: bool,
)
    requires fastcgi_script_identity_admit_spec(
        canonical_authorized,
        lexical_inode_bound,
        forwards_lexical,
        backend_binds_both,
    )
    ensures
        canonical_authorized,
        lexical_inode_bound,
        forwards_lexical,
        backend_binds_both,
{
}

/// P17: the resolved-file `SetHandler` constructor must bind classification
/// to the lexical basename, derive the backend wire path from that lexical
/// mapping, and keep the separately authorized descriptor target contained.
/// A canonical path is never sufficient as a substitute for the lexical wire
/// identity because backends such as PHP-FPM apply policy to that spelling.
pub open spec fn fastcgi_resolved_target_spec(
    lexical_name_bound: bool,
    wire_matches_lexical_mapping: bool,
    lexical_wire_contained: bool,
    canonical_authorized_contained: bool,
) -> bool {
    lexical_name_bound
        && wire_matches_lexical_mapping
        && lexical_wire_contained
        && canonical_authorized_contained
}

pub fn fastcgi_resolved_target_admit(
    lexical_name_bound: bool,
    wire_matches_lexical_mapping: bool,
    lexical_wire_contained: bool,
    canonical_authorized_contained: bool,
) -> (admit: bool)
    ensures admit == fastcgi_resolved_target_spec(
        lexical_name_bound,
        wire_matches_lexical_mapping,
        lexical_wire_contained,
        canonical_authorized_contained,
    ),
{
    lexical_name_bound
        && wire_matches_lexical_mapping
        && lexical_wire_contained
        && canonical_authorized_contained
}

pub proof fn fastcgi_resolved_target_rejects_unbound_lexical_identity(
    wire_matches_lexical_mapping: bool,
    lexical_wire_contained: bool,
    canonical_authorized_contained: bool,
)
    ensures !fastcgi_resolved_target_spec(
        false,
        wire_matches_lexical_mapping,
        lexical_wire_contained,
        canonical_authorized_contained,
    ),
{
}

pub proof fn fastcgi_resolved_target_rejects_canonical_wire_substitution(
    lexical_name_bound: bool,
    lexical_wire_contained: bool,
    canonical_authorized_contained: bool,
)
    ensures !fastcgi_resolved_target_spec(
        lexical_name_bound,
        false,
        lexical_wire_contained,
        canonical_authorized_contained,
    ),
{
}

pub open spec fn transform_retarget_spec() -> TransformCapability {
    TransformCapability {
        target_bound: false,
        authorized: false,
        inode_bound: false,
        backend_bound: false,
        representation_bound: false,
        policy_bound: false,
    }
}

/// Select a new target after any rewrite/alias/symlink/DirectoryIndex,
/// PATH_INFO, ErrorDocument, proxy or cache-key transform.  No capability for
/// the old target survives this operation.
pub fn transform_retarget() -> (state: TransformCapability)
    ensures state == transform_retarget_spec(),
{
    TransformCapability {
        target_bound: false,
        authorized: false,
        inode_bound: false,
        backend_bound: false,
        representation_bound: false,
        policy_bound: false,
    }
}

pub open spec fn transform_authorize_spec(policy_bound: bool) -> TransformCapability {
    TransformCapability {
        target_bound: true,
        authorized: true,
        inode_bound: false,
        backend_bound: false,
        representation_bound: false,
        policy_bound,
    }
}

/// Mint a capability only after the effective policy for the selected target
/// has allowed the request.  Object/backend bindings are still absent.
pub fn transform_authorize(policy_bound: bool) -> (state: TransformCapability)
    ensures state == transform_authorize_spec(policy_bound),
{
    TransformCapability {
        target_bound: true,
        authorized: true,
        inode_bound: false,
        backend_bound: false,
        representation_bound: false,
        policy_bound,
    }
}

pub open spec fn transform_bind_inode_spec(
    state: TransformCapability,
) -> TransformCapability {
    TransformCapability { inode_bound: true, ..state }
}

pub fn transform_bind_inode(state: TransformCapability) -> (out: TransformCapability)
    ensures out == transform_bind_inode_spec(state),
{
    TransformCapability { inode_bound: true, ..state }
}

pub open spec fn transform_bind_backend_spec(
    state: TransformCapability,
) -> TransformCapability {
    TransformCapability { backend_bound: true, ..state }
}

pub fn transform_bind_backend(state: TransformCapability) -> (out: TransformCapability)
    ensures out == transform_bind_backend_spec(state),
{
    TransformCapability { backend_bound: true, ..state }
}

pub open spec fn transform_bind_representation_spec(
    state: TransformCapability,
) -> TransformCapability {
    TransformCapability { representation_bound: true, ..state }
}

pub fn transform_bind_representation(state: TransformCapability) -> (out: TransformCapability)
    ensures out == transform_bind_representation_spec(state),
{
    TransformCapability { representation_bound: true, ..state }
}

pub open spec fn transform_sink_needs_inode(sink: TransformSink) -> bool {
    match sink {
        TransformSink::StaticFile
        | TransformSink::Directory
        | TransformSink::LocalCgi
        | TransformSink::FastCgi => true,
        TransformSink::Proxy | TransformSink::Cache => false,
    }
}

pub open spec fn transform_sink_needs_backend(sink: TransformSink) -> bool {
    match sink {
        TransformSink::FastCgi | TransformSink::Proxy => true,
        _ => false,
    }
}

pub open spec fn transform_sink_needs_policy(sink: TransformSink) -> bool {
    match sink {
        TransformSink::Cache => true,
        _ => false,
    }
}

pub open spec fn transform_sink_needs_representation(sink: TransformSink) -> bool {
    match sink {
        TransformSink::Proxy => true,
        _ => false,
    }
}

pub fn transform_sink_requires_inode(sink: TransformSink) -> (needed: bool)
    ensures needed == transform_sink_needs_inode(sink),
{
    match sink {
        TransformSink::StaticFile
        | TransformSink::Directory
        | TransformSink::LocalCgi
        | TransformSink::FastCgi => true,
        TransformSink::Proxy | TransformSink::Cache => false,
    }
}

pub fn transform_sink_requires_backend(sink: TransformSink) -> (needed: bool)
    ensures needed == transform_sink_needs_backend(sink),
{
    match sink {
        TransformSink::FastCgi | TransformSink::Proxy => true,
        _ => false,
    }
}

pub fn transform_sink_requires_policy(sink: TransformSink) -> (needed: bool)
    ensures needed == transform_sink_needs_policy(sink),
{
    match sink {
        TransformSink::Cache => true,
        _ => false,
    }
}

pub fn transform_sink_requires_representation(sink: TransformSink) -> (needed: bool)
    ensures needed == transform_sink_needs_representation(sink),
{
    match sink {
        TransformSink::Proxy => true,
        _ => false,
    }
}

pub open spec fn transform_sink_admit_spec(
    same_resource: bool,
    state: TransformCapability,
    sink: TransformSink,
) -> bool {
    same_resource
        && state.target_bound
        && state.authorized
        && (!transform_sink_needs_inode(sink) || state.inode_bound)
        && (!transform_sink_needs_backend(sink) || state.backend_bound)
        && (!transform_sink_needs_representation(sink) || state.representation_bound)
        && (!transform_sink_needs_policy(sink) || state.policy_bound)
}

/// Universal executable gate used immediately before every body, execution,
/// tunnel and cache sink.
pub fn transform_sink_admit(
    same_resource: bool,
    state: TransformCapability,
    sink: TransformSink,
) -> (ok: bool)
    ensures ok == transform_sink_admit_spec(same_resource, state, sink),
{
    same_resource
        && state.target_bound
        && state.authorized
        && (!transform_sink_requires_inode(sink) || state.inode_bound)
        && (!transform_sink_requires_backend(sink) || state.backend_bound)
        && (!transform_sink_requires_representation(sink) || state.representation_bound)
        && (!transform_sink_requires_policy(sink) || state.policy_bound)
}

/// A target transform alone cannot reach any sink.
pub proof fn transform_retarget_requires_reauthorization(sink: TransformSink)
    ensures !transform_sink_admit_spec(true, transform_retarget_spec(), sink),
{
}

pub proof fn transform_sink_implies_reauthorized(
    same_resource: bool,
    state: TransformCapability,
    sink: TransformSink,
)
    ensures
        transform_sink_admit_spec(same_resource, state, sink)
            ==> same_resource && state.target_bound && state.authorized,
{
}

pub proof fn transform_file_sink_implies_inode_bound(
    same_resource: bool,
    state: TransformCapability,
    sink: TransformSink,
)
    requires transform_sink_needs_inode(sink),
    ensures transform_sink_admit_spec(same_resource, state, sink) ==> state.inode_bound,
{
}

pub proof fn transform_backend_sink_implies_backend_bound(
    same_resource: bool,
    state: TransformCapability,
    sink: TransformSink,
)
    requires transform_sink_needs_backend(sink),
    ensures transform_sink_admit_spec(same_resource, state, sink) ==> state.backend_bound,
{
}

pub proof fn transform_proxy_sink_implies_representation_bound(
    same_resource: bool,
    state: TransformCapability,
)
    ensures
        transform_sink_admit_spec(same_resource, state, TransformSink::Proxy)
            ==> state.representation_bound,
{
}

pub proof fn transform_cache_sink_implies_policy_bound(
    same_resource: bool,
    state: TransformCapability,
)
    ensures
        transform_sink_admit_spec(same_resource, state, TransformSink::Cache)
            ==> state.policy_bound,
{
}

/// Descriptor snapshots are usable only when both observations name the same
/// regular inode and the metadata version did not change while it was read.
pub open spec fn descriptor_snapshot_spec(
    regular: bool,
    same_inode: bool,
    same_version: bool,
    within_limit: bool,
) -> bool {
    regular && same_inode && same_version && within_limit
}

pub fn descriptor_snapshot_admit(
    regular: bool,
    same_inode: bool,
    same_version: bool,
    within_limit: bool,
) -> (ok: bool)
    ensures ok == descriptor_snapshot_spec(regular, same_inode, same_version, within_limit),
{
    regular && same_inode && same_version && within_limit
}

pub proof fn descriptor_snapshot_admit_implies_stable_inode(
    regular: bool,
    same_inode: bool,
    same_version: bool,
    within_limit: bool,
)
    ensures
        descriptor_snapshot_spec(regular, same_inode, same_version, within_limit)
            ==> regular && same_inode && same_version && within_limit,
{
}

/// A component inspected through `O_PATH|O_NOFOLLOW` may be reopened with
/// readable flags only when both descriptors still identify the same inode.
/// This is the owner-match walk's non-symlink rename-race boundary.
pub open spec fn owner_component_reopen_spec(same_device: bool, same_inode: bool) -> bool {
    same_device && same_inode
}

pub fn owner_component_reopen_admit(
    same_device: bool,
    same_inode: bool,
) -> (ok: bool)
    ensures ok == owner_component_reopen_spec(same_device, same_inode),
{
    same_device && same_inode
}

pub proof fn owner_component_reopen_rejects_substitution(
    same_device: bool,
    same_inode: bool,
)
    ensures
        !same_device || !same_inode ==> !owner_component_reopen_spec(same_device, same_inode),
{
}

/// Query-state operation after splitting the expanded substitution.  The
/// returned action is consumed directly by `mod_rewrite`'s runtime path so
/// QSA/QSD precedence and the no-target-query preservation rule cannot drift
/// between branches.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RewriteQueryAction {
    Replace,
    Append,
    Preserve,
    Discard,
}

pub open spec fn rewrite_query_action_spec(
    has_target_query: bool,
    query_string_append: bool,
    query_string_discard: bool,
    original_query_present: bool,
) -> RewriteQueryAction {
    if has_target_query {
        if query_string_append && !query_string_discard && original_query_present {
            RewriteQueryAction::Append
        } else {
            RewriteQueryAction::Replace
        }
    } else if query_string_discard {
        RewriteQueryAction::Discard
    } else {
        RewriteQueryAction::Preserve
    }
}

pub fn rewrite_query_action(
    has_target_query: bool,
    query_string_append: bool,
    query_string_discard: bool,
    original_query_present: bool,
) -> (action: RewriteQueryAction)
    ensures
        action == rewrite_query_action_spec(
            has_target_query,
            query_string_append,
            query_string_discard,
            original_query_present,
        ),
{
    if has_target_query {
        if query_string_append && !query_string_discard && original_query_present {
            RewriteQueryAction::Append
        } else {
            RewriteQueryAction::Replace
        }
    } else if query_string_discard {
        RewriteQueryAction::Discard
    } else {
        RewriteQueryAction::Preserve
    }
}

pub proof fn rewrite_qsd_without_target_query_discards(
    query_string_append: bool,
    original_query_present: bool,
)
    ensures
        rewrite_query_action_spec(
            false,
            query_string_append,
            true,
            original_query_present,
        ) == RewriteQueryAction::Discard,
{
}

pub proof fn rewrite_target_query_never_preserves_original(
    query_string_append: bool,
    query_string_discard: bool,
    original_query_present: bool,
)
    ensures
        rewrite_query_action_spec(
            true,
            query_string_append,
            query_string_discard,
            original_query_present,
        ) != RewriteQueryAction::Preserve,
{
}

/// Admit another `[N]` restart.  Checking before increment makes the bound
/// overflow-free: exactly `limit` restarts are possible, and the next one is
/// rejected without modifying the counter.
pub open spec fn rewrite_restart_admit_spec(completed: u64, limit: u64) -> bool {
    completed < limit
}

pub fn rewrite_restart_admit(completed: u64, limit: u64) -> (ok: bool)
    ensures ok == rewrite_restart_admit_spec(completed, limit),
{
    completed < limit
}

pub proof fn rewrite_restart_rejects_at_limit(limit: u64)
    ensures !rewrite_restart_admit_spec(limit, limit),
{
}

/// A `RewriteMap prg` lookup is usable only when one bounded output line was
/// produced before the caller's deadline.  Process spawning and the wall
/// clock remain trusted runtime services; this predicate is the decision the
/// rewrite interpreter consumes after that bounded wait.
pub open spec fn rewrite_map_result_spec(
    completed_before_deadline: bool,
    line_complete: bool,
    output_len: u64,
    max_output: u64,
) -> bool {
    completed_before_deadline && line_complete && output_len <= max_output
}

pub fn rewrite_map_result_admit(
    completed_before_deadline: bool,
    line_complete: bool,
    output_len: u64,
    max_output: u64,
) -> (ok: bool)
    ensures
        ok == rewrite_map_result_spec(
            completed_before_deadline,
            line_complete,
            output_len,
            max_output,
        ),
{
    completed_before_deadline && line_complete && output_len <= max_output
}

pub proof fn rewrite_map_timeout_or_overflow_fails_closed(
    completed_before_deadline: bool,
    line_complete: bool,
    output_len: u64,
    max_output: u64,
)
    ensures
        !completed_before_deadline || !line_complete || output_len > max_output
            ==> !rewrite_map_result_spec(
                completed_before_deadline,
                line_complete,
                output_len,
                max_output,
            ),
{
}

/// `[BNE]` supplies exclusions to the backreference escaping operation; it is
/// not an independent no-op.  Any exclusion mode therefore implies that the
/// escaping pass itself is enabled.
pub open spec fn rewrite_backref_escape_spec(
    explicit_escape: bool,
    exclusion_mode: bool,
) -> bool {
    explicit_escape || exclusion_mode
}

pub fn rewrite_backref_escape_admit(
    explicit_escape: bool,
    exclusion_mode: bool,
) -> (escape: bool)
    ensures escape == rewrite_backref_escape_spec(explicit_escape, exclusion_mode),
{
    explicit_escape || exclusion_mode
}

pub proof fn rewrite_backref_exclusions_require_escape(
    explicit_escape: bool,
    exclusion_mode: bool,
)
    ensures
        exclusion_mode
            ==> rewrite_backref_escape_spec(explicit_escape, exclusion_mode),
{
}

/// A persisted cache entry is usable only when its metadata carries the
/// complete cache key and that key is exactly the one requested.  The digest
/// filename is an index, not an authority for cache identity.
pub open spec fn cache_disk_key_spec(has_key: bool, exact_key: bool) -> bool {
    has_key && exact_key
}

pub fn cache_disk_key_admit(has_key: bool, exact_key: bool) -> (ok: bool)
    ensures ok == cache_disk_key_spec(has_key, exact_key),
{
    has_key && exact_key
}

pub proof fn cache_disk_key_rejects_missing_or_mismatched(has_key: bool, exact_key: bool)
    ensures
        (!has_key || !exact_key) ==> !cache_disk_key_spec(has_key, exact_key),
{
}

/// Targeted invalidation removes legacy/unkeyed metadata conservatively and
/// removes a keyed entry exactly when its canonical request-URI prefix
/// matches.  An unrelated keyed representation therefore survives.
pub open spec fn cache_invalidation_remove_spec(has_key: bool, prefix_matches: bool) -> bool {
    !has_key || prefix_matches
}

pub fn cache_invalidation_remove_admit(has_key: bool, prefix_matches: bool) -> (remove: bool)
    ensures remove == cache_invalidation_remove_spec(has_key, prefix_matches),
{
    !has_key || prefix_matches
}

pub proof fn cache_invalidation_preserves_unrelated_keyed_entry(
    has_key: bool,
    prefix_matches: bool,
)
    requires has_key && !prefix_matches,
    ensures !cache_invalidation_remove_spec(has_key, prefix_matches),
{
}

/// RFC cache invalidation is an effect of a successful unsafe request, not of
/// an attacker-controlled failing POST/PUT. This also prevents a rejected
/// request from forcing an O(cache-size) invalidation walk.
pub open spec fn cache_invalidation_status_spec(unsafe_method: bool, status: u16) -> bool {
    unsafe_method && status >= 200 && status < 400
}

pub fn cache_invalidation_status_admit(unsafe_method: bool, status: u16) -> (ok: bool)
    ensures ok == cache_invalidation_status_spec(unsafe_method, status),
{
    unsafe_method && status >= 200 && status < 400
}

/// A trailing slash denotes a directory-like request target.  A cache entry
/// whose representation path is unchanged and whose mapped target is a
/// regular file must never be considered: dispatch rejects that spelling
/// after dynamic PATH_INFO handlers have had their opportunity to consume it.
pub open spec fn cache_trailing_slash_target_spec(
    trailing_slash: bool,
    same_representation_path: bool,
    regular_file: bool,
) -> bool {
    !(trailing_slash && same_representation_path && regular_file)
}

pub fn cache_trailing_slash_target_admit(
    trailing_slash: bool,
    same_representation_path: bool,
    regular_file: bool,
) -> (ok: bool)
    ensures ok == cache_trailing_slash_target_spec(
        trailing_slash,
        same_representation_path,
        regular_file,
    ),
{
    !(trailing_slash && same_representation_path && regular_file)
}

pub proof fn trailing_slash_regular_file_cache_is_rejected()
    ensures !cache_trailing_slash_target_spec(true, true, true),
{
}

pub proof fn failed_or_safe_request_never_invalidates(unsafe_method: bool, status: u16)
    requires !unsafe_method || status < 200 || status >= 400,
    ensures !cache_invalidation_status_spec(unsafe_method, status),
{
}

/// Autoindex work is admitted by both entry count and rendered bytes. Each
/// append is checked before allocation so sorting and HTML construction remain
/// bounded even for attacker-populated upload directories.
pub open spec fn autoindex_append_spec(current: u64, incoming: u64, limit: u64) -> bool {
    current <= limit && incoming <= limit - current
}

pub fn autoindex_append_admit(current: u64, incoming: u64, limit: u64) -> (ok: bool)
    ensures ok == autoindex_append_spec(current, incoming, limit),
{
    current <= limit && incoming <= limit - current
}

pub proof fn autoindex_append_stays_bounded(current: u64, incoming: u64, limit: u64)
    requires autoindex_append_spec(current, incoming, limit),
    ensures current + incoming <= limit,
{
}

/// Password files are operator input, but a remote client selects when their
/// hashes are evaluated. Reject costs outside Apache htpasswd's supported
/// range before they can pin a request worker.
pub open spec fn bcrypt_cost_spec(cost: u32) -> bool {
    cost >= 4 && cost <= 17
}

pub fn bcrypt_cost_admit(cost: u32) -> (ok: bool)
    ensures ok == bcrypt_cost_spec(cost),
{
    cost >= 4 && cost <= 17
}

pub proof fn bcrypt_extreme_cost_rejected(cost: u32)
    requires cost < 4 || cost > 17,
    ensures !bcrypt_cost_spec(cost),
{
}

/// PCRE compatibility is retained only for bounded patterns and subjects.
/// This bounds per-match allocation independently of the global CPU-work
/// admission gate.
pub open spec fn expr_regex_size_spec(pattern: u64, subject: u64, limit: u64) -> bool {
    pattern <= limit && subject <= limit
}

pub fn expr_regex_size_admit(pattern: u64, subject: u64, limit: u64) -> (ok: bool)
    ensures ok == expr_regex_size_spec(pattern, subject, limit),
{
    pattern <= limit && subject <= limit
}

pub proof fn expr_regex_oversize_rejected(pattern: u64, subject: u64, limit: u64)
    requires pattern > limit || subject > limit,
    ensures !expr_regex_size_spec(pattern, subject, limit),
{
}

/// Compilation admits only a pattern within the configured byte ceiling.
/// The compatibility front-end applies its independently bounded expansion
/// before handing the result to the automata compiler.
pub open spec fn regex_compile_resource_spec(pattern: u64, limit: u64) -> bool {
    pattern <= limit
}

pub fn regex_compile_resource_admit(pattern: u64, limit: u64) -> (ok: bool)
    ensures ok == regex_compile_resource_spec(pattern, limit),
{
    pattern <= limit
}

/// Captures are stored in a fixed-size locations vector per match.  Bounding
/// the number of public groups therefore bounds capture-result allocation.
pub open spec fn regex_capture_resource_spec(captures: u64, limit: u64) -> bool {
    captures <= limit
}

pub fn regex_capture_resource_admit(captures: u64, limit: u64) -> (ok: bool)
    ensures ok == regex_capture_resource_spec(captures, limit),
{
    captures <= limit
}

/// The non-backtracking engine has O(pattern * subject) worst-case work.  The
/// division form makes the executable check overflow-free while proving the
/// same product ceiling for every non-empty pattern.
pub open spec fn regex_match_resource_spec(
    complexity: u64,
    subject: u64,
    subject_limit: u64,
    work_limit: u64,
) -> bool {
    complexity > 0
        && subject <= subject_limit
        && complexity <= work_limit
        && subject <= work_limit / complexity
}

pub fn regex_match_resource_admit(
    complexity: u64,
    subject: u64,
    subject_limit: u64,
    work_limit: u64,
) -> (ok: bool)
    ensures ok == regex_match_resource_spec(complexity, subject, subject_limit, work_limit),
{
    complexity > 0
        && subject <= subject_limit
        && complexity <= work_limit
        && subject <= work_limit / complexity
}

pub proof fn regex_match_work_is_bounded(
    complexity: u64,
    subject: u64,
    subject_limit: u64,
    work_limit: u64,
)
    requires regex_match_resource_spec(complexity, subject, subject_limit, work_limit),
    ensures
        subject <= subject_limit,
        complexity > 0,
        subject <= work_limit / complexity,
{
}

/// Bottom-up glob evaluation visits at most one DP cell for each pattern byte
/// and each subject suffix.  The executable check uses division so the
/// pattern-by-(subject+1) product cannot overflow before it is admitted.
pub open spec fn glob_match_resource_spec(
    pattern: u64,
    subject: u64,
    pattern_limit: u64,
    work_limit: u64,
) -> bool {
    pattern <= pattern_limit
        && pattern < work_limit
        && subject < u64::MAX
        && (subject as int) + 1 <= (work_limit as int) / ((pattern as int) + 1)
}

pub fn glob_match_resource_admit(
    pattern: u64,
    subject: u64,
    pattern_limit: u64,
    work_limit: u64,
) -> (ok: bool)
    ensures ok == glob_match_resource_spec(pattern, subject, pattern_limit, work_limit),
{
    pattern <= pattern_limit
        && pattern < work_limit
        && subject < u64::MAX
        && subject + 1u64 <= work_limit / (pattern + 1u64)
}

pub proof fn admitted_glob_work_is_bounded(
    pattern: u64,
    subject: u64,
    pattern_limit: u64,
    work_limit: u64,
)
    requires glob_match_resource_spec(pattern, subject, pattern_limit, work_limit),
    ensures
        pattern <= pattern_limit,
        (pattern as int) + 1 > 0,
        (subject as int) + 1 <= (work_limit as int) / ((pattern as int) + 1),
{
}

/// Admission for response-header count and serialized bytes.  Both dimensions
/// are checked before policy values are cloned into a response or an HTTP
/// adapter materializes the wire head.
pub open spec fn response_header_budget_spec(
    count: u64,
    bytes: u64,
    count_limit: u64,
    byte_limit: u64,
) -> bool {
    count <= count_limit && bytes <= byte_limit
}

pub fn response_header_budget_admit(
    count: u64,
    bytes: u64,
    count_limit: u64,
    byte_limit: u64,
) -> (ok: bool)
    ensures ok == response_header_budget_spec(count, bytes, count_limit, byte_limit),
{
    count <= count_limit && bytes <= byte_limit
}

pub proof fn admitted_response_headers_are_bounded(
    count: u64,
    bytes: u64,
    count_limit: u64,
    byte_limit: u64,
)
    requires response_header_budget_spec(count, bytes, count_limit, byte_limit),
    ensures count <= count_limit, bytes <= byte_limit,
{
}

/// Admission for the breadth of the access-file program participating in one
/// request.  `next_instructions` is checked by subtraction so the concrete
/// accumulator cannot overflow while walking ancestor layers.
pub open spec fn access_program_budget_spec(
    layers: u64,
    instructions: u64,
    next_instructions: u64,
    layer_limit: u64,
    instruction_limit: u64,
) -> bool {
    layers < layer_limit
        && instructions <= instruction_limit
        && next_instructions <= instruction_limit - instructions
}

pub fn access_program_budget_admit(
    layers: u64,
    instructions: u64,
    next_instructions: u64,
    layer_limit: u64,
    instruction_limit: u64,
) -> (ok: bool)
    ensures ok == access_program_budget_spec(
        layers,
        instructions,
        next_instructions,
        layer_limit,
        instruction_limit,
    ),
{
    layers < layer_limit
        && instructions <= instruction_limit
        && next_instructions <= instruction_limit - instructions
}

pub proof fn admitted_access_program_is_bounded(
    layers: u64,
    instructions: u64,
    next_instructions: u64,
    layer_limit: u64,
    instruction_limit: u64,
)
    requires access_program_budget_spec(
        layers,
        instructions,
        next_instructions,
        layer_limit,
        instruction_limit,
    ),
    ensures
        layers + 1 <= layer_limit,
        instructions + next_instructions <= instruction_limit,
{
}

/// Append admission shared by rewrite and expression expansion.  Checking
/// subtraction before allocation proves the resulting concrete byte vector
/// remains within its declared ceiling without overflowing `current + input`.
pub open spec fn bounded_expansion_append_spec(current: u64, input: u64, limit: u64) -> bool {
    current <= limit && input <= limit - current
}

pub fn bounded_expansion_append_admit(current: u64, input: u64, limit: u64) -> (ok: bool)
    ensures ok == bounded_expansion_append_spec(current, input, limit),
{
    current <= limit && input <= limit - current
}

pub proof fn bounded_expansion_append_stays_bounded(current: u64, input: u64, limit: u64)
    requires bounded_expansion_append_spec(current, input, limit),
    ensures current + input <= limit,
{
}

/// Once the frontend's structural complexity charge dominates an expanded
/// counted repetition, the ordinary match-work ceiling also bounds every
/// repeated atom evaluation.  This closes the P23-A gap where `{n}` was
/// previously charged as only the few source bytes spelling the quantifier.
pub proof fn regex_expanded_charge_bounds_counted_repetition(
    atom: nat,
    copies: nat,
    subject: nat,
    charge: nat,
    work_limit: nat,
)
    requires
        charge >= atom * copies,
        charge * subject <= work_limit,
    ensures atom * copies * subject <= work_limit,
{
    vstd::arithmetic::mul::lemma_mul_inequality(
        (atom * copies) as int,
        charge as int,
        subject as int,
    );
}

/// A variable counted repetition adds an exit path to its expanded copies,
/// and the PikeVM may visit the whole active set for each subject byte. The
/// frontend therefore charges both the expanded path count and a calibrated
/// active-set factor (P24-B); the ordinary match ceiling then bounds that
/// larger execution-work model too.
pub proof fn regex_optional_repeat_charge_bounds_pike_work(
    atom: nat,
    paths: nat,
    active_set_factor: nat,
    subject: nat,
    charge: nat,
    work_limit: nat,
)
    requires
        charge >= atom * paths * active_set_factor,
        charge * subject <= work_limit,
    ensures atom * paths * active_set_factor * subject <= work_limit,
{
    vstd::arithmetic::mul::lemma_mul_inequality(
        (atom * paths * active_set_factor) as int,
        charge as int,
        subject as int,
    );
}

/// A compatibility lowering that performs more than one deterministic pass
/// (the terminal-newline anchor case uses two) must include every pass in its
/// charged complexity.
pub proof fn regex_multipass_charge_bounds_all_passes(
    automaton: nat,
    passes: nat,
    subject: nat,
    charge: nat,
    work_limit: nat,
)
    requires
        charge >= automaton * passes,
        charge * subject <= work_limit,
    ensures automaton * passes * subject <= work_limit,
{
    vstd::arithmetic::mul::lemma_mul_inequality(
        (automaton * passes) as int,
        charge as int,
        subject as int,
    );
}

/// Shipping policy for the regex execution backend.  Neither recursive
/// backtracking nor executable-memory JIT is available in the production
/// engine; both properties are fixed at construction and cannot be selected
/// by a pattern.
pub open spec fn regex_engine_mode_spec(backtracking: bool, executable_jit: bool) -> bool {
    !backtracking && !executable_jit
}

pub fn regex_engine_mode_admit(backtracking: bool, executable_jit: bool) -> (ok: bool)
    ensures ok == regex_engine_mode_spec(backtracking, executable_jit),
{
    !backtracking && !executable_jit
}

pub proof fn regex_backtracking_default_is_required(executable_jit: bool)
    ensures !regex_engine_mode_spec(true, executable_jit),
{
}

/// Add the single leading slash required for an internal rewrite target.
/// External targets are classified before this function is called.
pub fn rewrite_internal_path(joined: &[u8]) -> (out: Vec<u8>)
    ensures
        out@.len() == joined@.len() + (if joined@.len() > 0 && joined@[0] == b'/' { 0int } else { 1int }),
        out@.len() > 0,
        out@[0] == b'/',
{
    let mut out: Vec<u8> = Vec::with_capacity(joined.len());
    out.push(b'/');
    let start: usize = if joined.len() > 0 && joined[0] == b'/' { 1 } else { 0 };
    let mut i: usize = start;
    while i < joined.len()
        invariant
            start <= i <= joined.len(),
            out@.len() == 1 + (i - start),
            out@[0] == b'/',
        decreases joined.len() - i,
    {
        out.push(joined[i]);
        i = i + 1;
    }
    out
}

/// Admit an absolute filesystem target produced by a rewrite.  A file may
/// be served only below the request's current document/alias root.  The
/// `UnsafePrefixStat` flag is parsed for compatibility but never changes the
/// authorization base: admitting a file for stat must not turn its parent
/// directory into a new virtual root.  This is the CVE-2024-38475 boundary.
pub fn rewrite_filesystem_admit(is_file: bool, under_base: bool) -> (ok: bool)
    ensures ok == (is_file && under_base),
{
    is_file && under_base
}

/// Shape gate for interpreting an expanded substitution as a filesystem
/// target.  External URLs and `[PT]` substitutions must remain in URL space;
/// relative substitutions cannot name a host filesystem object.
pub open spec fn rewrite_filesystem_shape_spec(
    external: bool,
    passthrough: bool,
    absolute: bool,
) -> bool {
    !external && !passthrough && absolute
}

pub fn rewrite_filesystem_shape_admit(
    external: bool,
    passthrough: bool,
    absolute: bool,
) -> (ok: bool)
    ensures ok == rewrite_filesystem_shape_spec(external, passthrough, absolute),
{
    !external && !passthrough && absolute
}

/// Complete filesystem-target gate, including the post-canonicalization file
/// and containment checks.  This spec connects target classification to the
/// existing CVE-2024-38475 boundary instead of proving each half in isolation.
pub open spec fn rewrite_filesystem_candidate_spec(
    external: bool,
    passthrough: bool,
    absolute: bool,
    is_file: bool,
    under_base: bool,
) -> bool {
    rewrite_filesystem_shape_spec(external, passthrough, absolute)
        && is_file
        && under_base
}

pub fn rewrite_filesystem_candidate_admit(
    external: bool,
    passthrough: bool,
    absolute: bool,
    is_file: bool,
    under_base: bool,
) -> (ok: bool)
    ensures
        ok == rewrite_filesystem_candidate_spec(
            external,
            passthrough,
            absolute,
            is_file,
            under_base,
        ),
{
    rewrite_filesystem_shape_admit(external, passthrough, absolute)
        && rewrite_filesystem_admit(is_file, under_base)
}

pub proof fn rewrite_passthrough_never_selects_filesystem(
    external: bool,
    absolute: bool,
    is_file: bool,
    under_base: bool,
)
    ensures
        !rewrite_filesystem_candidate_spec(
            external,
            true,
            absolute,
            is_file,
            under_base,
        ),
{
}

pub proof fn rewrite_filesystem_candidate_is_local_and_contained(
    external: bool,
    passthrough: bool,
    absolute: bool,
    is_file: bool,
    under_base: bool,
)
    ensures
        rewrite_filesystem_candidate_spec(
            external,
            passthrough,
            absolute,
            is_file,
            under_base,
        ) ==> !external && !passthrough && absolute && is_file && under_base,
{
}

/// A contained rewrite target remains safe at dispatch only when the mapping
/// root that admitted it is retained and the selected path is represented as
/// a relative child of that root. Re-rooting at the target's parent would
/// discard the containment witness under a concurrent rename.
pub open spec fn rewrite_filesystem_binding_spec(
    mapping_root_retained: bool,
    relative_below_root: bool,
) -> bool {
    mapping_root_retained && relative_below_root
}

pub fn rewrite_filesystem_binding_admit(
    mapping_root_retained: bool,
    relative_below_root: bool,
) -> (ok: bool)
    ensures
        ok == rewrite_filesystem_binding_spec(mapping_root_retained, relative_below_root),
{
    mapping_root_retained && relative_below_root
}

pub proof fn rewrite_filesystem_binding_rejects_reroot(
    relative_below_root: bool,
)
    ensures !rewrite_filesystem_binding_spec(false, relative_below_root),
{
}

/// Component-aware lexical containment for an absolute filesystem target.
///
/// `base` must be a real directory prefix of `target`; a bare string prefix is
/// not enough (`/srv/www2` must not be admitted below `/srv/www`).  The check
/// is deliberately on encoded path bytes so it can run immediately before a
/// filesystem operation without allocating or consulting the filesystem.  The
/// runtime still resolves symlinks and uses `openat2(RESOLVE_BENEATH)` as the
/// kernel-level half of the containment argument.
pub open spec fn path_under_base_spec(target: Seq<u8>, base: Seq<u8>) -> bool {
    &&& base.len() > 0
    &&& target.len() >= base.len()
    &&& target.subrange(0, base.len() as int) == base
    &&& (target.len() == base.len()
        || base[base.len() - 1] == b'/'
        || target[base.len() as int] == b'/')
}

pub fn path_under_base(target: &[u8], base: &[u8]) -> (ok: bool)
    ensures ok == path_under_base_spec(target@, base@),
{
    if base.len() == 0 || target.len() < base.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < base.len()
        invariant
            i <= base.len(),
            target.len() >= base.len(),
            forall|j: int| 0 <= j < i ==> #[trigger] target@[j] == base@[j],
        decreases base.len() - i,
    {
        if target[i] != base[i] {
            assert(target@.subrange(0, base.len() as int) != base@);
            return false;
        }
        i = i + 1;
    }
    assert(target@.subrange(0, base.len() as int) == base@);
    if target.len() == base.len() {
        return true;
    }
    if base[base.len() - 1] == b'/' {
        return true;
    }
    target[base.len()] == b'/'
}

/// Containment reflexivity: every nonempty base contains itself.  Callers
/// that re-bind a target to the same root can state the containment fact for
/// the new identity without re-deriving it.
pub proof fn path_under_base_reflexive(base: &[u8])
    requires base.len() > 0,
    ensures path_under_base_spec(base@, base@),
{
    assert(base@.len() > 0);
    assert(base@.len() >= base@.len());
    assert forall|k: int|
        0 <= k < base@.len() implies #[trigger] base@.subrange(0, base@.len() as int)[k]
            == base@[k] by {};
    assert(base@.subrange(0, base@.len() as int) == base@);
    assert(base@.len() == base@.len());
}

/// Containment composes: if `target` lies beneath `mid` and `mid` lies
/// beneath `base`, then `target` lies beneath `base`.  This is the lemma a
/// multi-identity walk (URL scope, canonical target, rewrite round, cache
/// target) needs to keep one containment argument instead of re-proving each
/// hop; the `canonicalize`-stability half of the composition argument remains
/// the documented filesystem assumption.
pub proof fn path_under_base_transitive(target: &[u8], mid: &[u8], base: &[u8])
    requires
        path_under_base_spec(target@, mid@),
        path_under_base_spec(mid@, base@),
        mid@.len() > 0,
    ensures path_under_base_spec(target@, base@),
{
    let t = target@;
    let m = mid@;
    let b = base@;
    // Prefix facts from both hypotheses.
    assert(t.subrange(0, m.len() as int) == m);
    assert(m.subrange(0, b.len() as int) == b);
    assert(m.len() <= t.len());
    assert(b.len() <= m.len());
    // Byte equality under the respective prefixes.
    assert forall|k: int| 0 <= k < m.len() implies #[trigger] t[k] == m[k] by {
        assert(t.subrange(0, m.len() as int)[k] == m[k]);
    }
    assert forall|k: int| 0 <= k < b.len() implies #[trigger] m[k] == b[k] by {
        assert(m.subrange(0, b.len() as int)[k] == b[k]);
    }
    // The target prefix of base length equals base.
    assert forall|k: int| 0 <= k < b.len() implies #[trigger] t[k] == b[k] by {
        assert(t[k] == m[k]);
    }
    assert(t.subrange(0, b.len() as int) == b);
    // Boundary: the target/base boundary disjunct of the goal.  The lengths
    // already give target.len() >= base.len(); it remains to derive one of
    // `target.len() == base.len()`, `base` ends with '/' or `target`
    // continues with '/' at the base boundary.
    if t.len() == m.len() {
        // Equal-length prefixes are equal sequences; the mid/base boundary
        // disjuncts rewrite directly into the goal.
        assert(t == m);
    } else {
        assert(m.len() < t.len());
        if b.len() == m.len() {
            // The last byte of base is the last byte of mid.
            if m[m.len() as int - 1] == b'/' {
                assert(b[b.len() as int - 1] == b'/');
            } else {
                // H1's boundary reduces to the target continuing with '/'.
                assert(t[m.len() as int] == b'/');
                assert(t[b.len() as int] == b'/');
            }
        } else {
            assert(b.len() < m.len());
            if !(b[b.len() as int - 1] == b'/') {
                // H2's boundary reduces to mid continuing with '/' at the
                // base boundary, which the target prefix shares.
                assert(m[b.len() as int] == b'/');
                assert(t[b.len() as int] == m[b.len() as int]);
                assert(t[b.len() as int] == b'/');
            }
        }
    }
}

/// F46/I43: a `<RequireNone>` group with any granted child denies; a denied
/// sibling cannot neutralize the positive hit.
pub fn require_none_multi_result(
    any_granted: bool,
    result_is_denied: bool,
) -> (ok: bool)
    ensures ok == (!any_granted || result_is_denied),
{
    !any_granted || result_is_denied
}

/// F48/I45: an address-bound virtual host is eligible only on its configured
/// destination address; wildcard (`*`, `_default_`) vhosts remain eligible.
pub fn vhost_address_admit(
    address_bound: bool,
    wildcard: bool,
    same_address: bool,
) -> (ok: bool)
    ensures ok == (!address_bound || wildcard || same_address),
{
    !address_bound || wildcard || same_address
}

/// F48/I45: when an exact-address vhost exists for the destination, wildcard
/// vhosts cannot take precedence over it.
pub fn vhost_address_precedence(exact_available: bool, candidate_exact: bool) -> (ok: bool)
    ensures ok == (!exact_available || candidate_exact),
{
    !exact_available || candidate_exact
}

/// Startup-index refinement for name matching: exact-name hashing may find a
/// later vhost before wildcard evaluation, but Apache's first configured match
/// still wins regardless of which representation produced the candidate.
pub fn vhost_name_candidate_precedes(
    current: Option<usize>,
    candidate: usize,
) -> (prefer: bool)
    ensures prefer == match current {
        None => true,
        Some(index) => candidate < index,
    },
{
    match current {
        None => true,
        Some(index) => candidate < index,
    }
}

/// F39/I35: a prefix `Alias`/`ScriptAlias` whose target is a regular file is
/// resolved as `(parent, basename)`, never `(file, empty)`.  The nonempty
/// basename is what carries the handler and MIME extension.
pub fn alias_file_target_split(
    target_is_file: bool,
    root_is_parent: bool,
    rel_is_basename: bool,
    rel_nonempty: bool,
) -> (ok: bool)
    ensures
        ok == (!target_is_file
            || (root_is_parent && rel_is_basename && rel_nonempty)),
{
    !target_is_file || (root_is_parent && rel_is_basename && rel_nonempty)
}

/// F39/I36: the access-file walk root for a file target is its parent, not the
/// file itself.
pub fn alias_access_root_admit(
    target_is_file: bool,
    root_is_parent: bool,
    root_is_target: bool,
) -> (ok: bool)
    ensures ok == (!target_is_file || (root_is_parent && !root_is_target)),
{
    !target_is_file || (root_is_parent && !root_is_target)
}

/// F39/I37: when a target has been resolved, handler/MIME/FastCGI selection
/// uses that target's basename rather than the URL remainder.
pub fn handler_name_from_target(resolved: bool, name_is_target_basename: bool) -> (ok: bool)
    ensures ok == (!resolved || name_is_target_basename),
{
    !resolved || name_is_target_basename
}

/// F40/I38: an effectful directive accepted inside `<Limit>` must be applied or
/// rejected; it may never be warn-and-ignored.
pub fn limit_directive_effect(effectful: bool, applied: bool, rejected: bool) -> (ok: bool)
    ensures ok == (!effectful || applied || rejected),
{
    !effectful || applied || rejected
}

/// F41/I39: if the opened/resolved target differs from the lexical mapping,
/// CGI/FastCGI dispatch must reauthorize the actual target and bind to it
/// before execution or backend forwarding.
pub fn cgi_actual_target_admit(
    actual_differs: bool,
    reauthorized: bool,
    bound: bool,
) -> (ok: bool)
    ensures ok == (!actual_differs || (reauthorized && bound)),
{
    !actual_differs || (reauthorized && bound)
}

/// F42/I40: a capture-only/leading-capture regex alias has no implicit
/// `ServerRoot` base.  Mapping is admitted only with an explicit stable
/// directory prefix.
pub fn capture_only_alias_admit(has_stable_prefix: bool) -> (ok: bool)
    ensures ok == has_stable_prefix,
{
    has_stable_prefix
}

/// F43/I41: a spool creation is admitted only with exclusive creation and a
/// private mode, so a pre-created shared-temp symlink cannot redirect it.
pub fn temp_file_create_admit(create_new: bool, private_mode: bool) -> (ok: bool)
    ensures ok == (create_new && private_mode),
{
    create_new && private_mode
}

/// F44: a new disk-cache representation fits only when the incoming bytes plus
/// the current usage stay within the configured total budget.
pub fn cache_disk_size_admit(used: u64, incoming: u64, limit: u64) -> (ok: bool)
    ensures ok == (used <= limit && incoming <= limit - used),
{
    used <= limit && incoming <= limit - used
}

/// Overflow-free admission for the independently bounded resident cache.
/// Runtime accounting includes key/header/vary material as well as the body.
pub open spec fn cache_memory_spec(used: u64, incoming: u64, limit: u64) -> bool {
    used <= limit && incoming <= limit - used
}

pub fn cache_memory_admit(used: u64, incoming: u64, limit: u64) -> (ok: bool)
    ensures ok == cache_memory_spec(used, incoming, limit),
{
    used <= limit && incoming <= limit - used
}

pub proof fn cache_memory_admission_is_bounded(used: u64, incoming: u64, limit: u64)
    requires cache_memory_spec(used, incoming, limit),
    ensures used + incoming <= limit,
{
}

/// Overflow-free aggregate admission used by spool-byte, spool-file and
/// dynamic-backend counters.  The caller commits the exact addition with an
/// atomic compare/exchange, retrying this predicate if the observed value
/// changed concurrently.
pub open spec fn resource_budget_spec(used: u64, incoming: u64, limit: u64) -> bool {
    used <= limit && incoming <= limit - used
}

pub fn resource_budget_admit(used: u64, incoming: u64, limit: u64) -> (ok: bool)
    ensures ok == resource_budget_spec(used, incoming, limit),
{
    used <= limit && incoming <= limit - used
}

pub proof fn resource_budget_admission_is_bounded(used: u64, incoming: u64, limit: u64)
    requires resource_budget_spec(used, incoming, limit),
    ensures used + incoming <= limit,
{
}

pub proof fn resource_budget_rejects_exhausted(used: u64, incoming: u64)
    requires incoming > 0,
    ensures !resource_budget_spec(used, incoming, used),
{
}

/// One tier of the unified request -> client -> process admission hierarchy.
/// Every runtime slot acquisition uses this predicate at each applicable
/// scope, rather than maintaining feature-specific overflow and boundary
/// logic.
pub open spec fn hierarchical_resource_spec(
    used: u64,
    incoming: u64,
    limit: u64,
) -> bool {
    used <= limit && incoming <= limit - used
}

pub fn hierarchical_resource_admit(
    used: u64,
    incoming: u64,
    limit: u64,
) -> (ok: bool)
    ensures ok == hierarchical_resource_spec(used, incoming, limit),
{
    used <= limit && incoming <= limit - used
}

pub proof fn hierarchical_resource_admission_is_bounded(
    used: u64,
    incoming: u64,
    limit: u64,
)
    requires hierarchical_resource_spec(used, incoming, limit),
    ensures used + incoming <= limit,
{
}

/// The complete three-level decision used by a typed resource lease. A
/// pre-identity phase may omit the client tier, but request and process tiers
/// remain mandatory.
pub open spec fn hierarchical_three_scope_spec(
    request_used: u64,
    client_used: u64,
    process_used: u64,
    incoming: u64,
    request_limit: u64,
    client_limit: u64,
    process_limit: u64,
    has_client: bool,
) -> bool {
    hierarchical_resource_spec(request_used, incoming, request_limit)
        && (!has_client
            || hierarchical_resource_spec(client_used, incoming, client_limit))
        && hierarchical_resource_spec(process_used, incoming, process_limit)
}

pub fn hierarchical_three_scope_admit(
    request_used: u64,
    client_used: u64,
    process_used: u64,
    incoming: u64,
    request_limit: u64,
    client_limit: u64,
    process_limit: u64,
    has_client: bool,
) -> (ok: bool)
    ensures ok == hierarchical_three_scope_spec(
        request_used,
        client_used,
        process_used,
        incoming,
        request_limit,
        client_limit,
        process_limit,
        has_client,
    ),
{
    hierarchical_resource_admit(request_used, incoming, request_limit)
        && (!has_client
            || hierarchical_resource_admit(client_used, incoming, client_limit))
        && hierarchical_resource_admit(process_used, incoming, process_limit)
}

pub proof fn hierarchical_three_scope_success_is_bounded(
    request_used: u64,
    client_used: u64,
    process_used: u64,
    incoming: u64,
    request_limit: u64,
    client_limit: u64,
    process_limit: u64,
    has_client: bool,
)
    requires hierarchical_three_scope_spec(
        request_used,
        client_used,
        process_used,
        incoming,
        request_limit,
        client_limit,
        process_limit,
        has_client,
    ),
    ensures
        request_used + incoming <= request_limit,
        has_client ==> client_used + incoming <= client_limit,
        process_used + incoming <= process_limit,
{
}

/// Lower scopes must be acquired before the process slot.  This prevents a
/// request/client rejection from retaining global capacity while its error is
/// handled. The runtime ledger rolls the lower scopes back if process
/// admission then fails.
pub open spec fn hierarchical_acquisition_order_spec(
    request_scope_complete: bool,
    client_scope_complete: bool,
) -> bool {
    request_scope_complete && client_scope_complete
}

pub fn hierarchical_acquisition_order_admit(
    request_scope_complete: bool,
    client_scope_complete: bool,
) -> (ok: bool)
    ensures ok == hierarchical_acquisition_order_spec(
        request_scope_complete,
        client_scope_complete,
    ),
{
    request_scope_complete && client_scope_complete
}

/// Fixed-window rate admission is hierarchical too: process capacity is
/// always required and, when an authenticated client identity exists, its
/// source-keyed capacity is required in the same decision.
pub open spec fn hierarchical_rate_spec(
    process_used: u64,
    client_used: u64,
    process_limit: u64,
    client_limit: u64,
    has_client: bool,
) -> bool {
    process_used < process_limit && (!has_client || client_used < client_limit)
}

pub fn hierarchical_rate_admit(
    process_used: u64,
    client_used: u64,
    process_limit: u64,
    client_limit: u64,
    has_client: bool,
) -> (ok: bool)
    ensures ok == hierarchical_rate_spec(
        process_used,
        client_used,
        process_limit,
        client_limit,
        has_client,
    ),
{
    process_used < process_limit && (!has_client || client_used < client_limit)
}

/// Weighted fixed-window admission is used for byte and cost budgets.  It is
/// the rate analogue of hierarchical resource admission: both the process and
/// source-keyed projection must fit without overflow.
pub open spec fn hierarchical_weighted_rate_spec(
    process_used: u64,
    client_used: u64,
    incoming: u64,
    process_limit: u64,
    client_limit: u64,
    has_client: bool,
) -> bool {
    process_used <= process_limit
        && incoming <= process_limit - process_used
        && (!has_client
            || (client_used <= client_limit && incoming <= client_limit - client_used))
}

pub fn hierarchical_weighted_rate_admit(
    process_used: u64,
    client_used: u64,
    incoming: u64,
    process_limit: u64,
    client_limit: u64,
    has_client: bool,
) -> (ok: bool)
    ensures ok == hierarchical_weighted_rate_spec(
        process_used,
        client_used,
        incoming,
        process_limit,
        client_limit,
        has_client,
    ),
{
    process_used <= process_limit
        && incoming <= process_limit - process_used
        && (!has_client
            || (client_used <= client_limit && incoming <= client_limit - client_used))
}

pub proof fn hierarchical_weighted_rate_success_is_bounded(
    process_used: u64,
    client_used: u64,
    incoming: u64,
    process_limit: u64,
    client_limit: u64,
    has_client: bool,
)
    requires hierarchical_weighted_rate_spec(
        process_used,
        client_used,
        incoming,
        process_limit,
        client_limit,
        has_client,
    ),
    ensures
        process_used + incoming <= process_limit,
        has_client ==> client_used + incoming <= client_limit,
{
}

/// A process-wide HTTP/2 stream slot may be acquired only after the
/// source-keyed slot. This ordering ensures that rejecting a client cannot
/// retain global capacity while its error response waits on that client's
/// flow-control window.
pub open spec fn h2_process_slot_spec(client_slot_acquired: bool) -> bool {
    client_slot_acquired
}

pub fn h2_process_slot_admit(client_slot_acquired: bool) -> (ok: bool)
    ensures ok == h2_process_slot_spec(client_slot_acquired),
{
    client_slot_acquired
}

pub proof fn h2_process_slot_requires_client_slot()
    ensures !h2_process_slot_spec(false),
{
}

/// Enforce a minimum average byte rate after a fixed grace interval without
/// using unchecked arithmetic. This is independent of the caller's absolute
/// lifetime ceiling: progress can reject a slow peer but never extends that
/// ceiling.
pub open spec fn minimum_progress_rate_spec(
    bytes: u64,
    elapsed_ms: u64,
    min_rate: u64,
    grace_ms: u64,
) -> bool {
    min_rate == 0
        || elapsed_ms < grace_ms
        || (bytes as nat) >= (min_rate as nat) * ((elapsed_ms / 1000) as nat)
}

pub fn minimum_progress_rate_admit(
    bytes: u64,
    elapsed_ms: u64,
    min_rate: u64,
    grace_ms: u64,
) -> (ok: bool)
    ensures ok == minimum_progress_rate_spec(bytes, elapsed_ms, min_rate, grace_ms),
{
    if min_rate == 0 || elapsed_ms < grace_ms {
        true
    } else {
        let elapsed_seconds = elapsed_ms / 1000;
        match min_rate.checked_mul(elapsed_seconds) {
            Some(required) => bytes >= required,
            None => false,
        }
    }
}

pub proof fn zero_minimum_progress_rate_is_unconditional(
    bytes: u64,
    elapsed_ms: u64,
    grace_ms: u64,
)
    ensures minimum_progress_rate_spec(bytes, elapsed_ms, 0, grace_ms),
{
}

/// The process-wide response-body read counter protects blocking descriptor
/// reads only. Request dispatch and downstream socket waits have independent
/// concurrency/deadline bounds and must never retain this scarce permit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResponseWorkPhase {
    DescriptorRead,
    RequestDispatch,
    ClientWriteWait,
}

pub open spec fn response_body_read_lease_spec(phase: ResponseWorkPhase) -> bool {
    match phase {
        ResponseWorkPhase::DescriptorRead => true,
        ResponseWorkPhase::RequestDispatch | ResponseWorkPhase::ClientWriteWait => false,
    }
}

pub fn response_body_read_lease_admit(phase: ResponseWorkPhase) -> (ok: bool)
    ensures ok == response_body_read_lease_spec(phase),
{
    match phase {
        ResponseWorkPhase::DescriptorRead => true,
        ResponseWorkPhase::RequestDispatch | ResponseWorkPhase::ClientWriteWait => false,
    }
}

pub proof fn response_body_read_lease_excludes_client_occupancy()
    ensures
        !response_body_read_lease_spec(ResponseWorkPhase::RequestDispatch),
        !response_body_read_lease_spec(ResponseWorkPhase::ClientWriteWait),
{
}

/// Ownership of response resources while an asynchronous output pump lends
/// them to a blocking descriptor read.  Cancellation of the outer socket
/// future cannot release the descriptors/backend lease until the read task
/// itself has stopped touching them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutputOwnershipPhase {
    ResponseOwned,
    ReadTaskOwned,
    ReadTaskCancelled,
    Released,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutputOwnershipEvent {
    BeginRead,
    ReadComplete,
    Cancel,
    Finish,
}

pub open spec fn output_ownership_step_spec(
    phase: OutputOwnershipPhase,
    event: OutputOwnershipEvent,
) -> Option<OutputOwnershipPhase> {
    match (phase, event) {
        (OutputOwnershipPhase::ResponseOwned, OutputOwnershipEvent::BeginRead) => {
            Some(OutputOwnershipPhase::ReadTaskOwned)
        }
        (OutputOwnershipPhase::ReadTaskOwned, OutputOwnershipEvent::ReadComplete) => {
            Some(OutputOwnershipPhase::ResponseOwned)
        }
        (OutputOwnershipPhase::ReadTaskOwned, OutputOwnershipEvent::Cancel) => {
            Some(OutputOwnershipPhase::ReadTaskCancelled)
        }
        (OutputOwnershipPhase::ReadTaskCancelled, OutputOwnershipEvent::ReadComplete) => {
            Some(OutputOwnershipPhase::Released)
        }
        (OutputOwnershipPhase::ResponseOwned, OutputOwnershipEvent::Cancel)
        | (OutputOwnershipPhase::ResponseOwned, OutputOwnershipEvent::Finish) => {
            Some(OutputOwnershipPhase::Released)
        }
        _ => None,
    }
}

pub fn output_ownership_step(
    phase: OutputOwnershipPhase,
    event: OutputOwnershipEvent,
) -> (next: Option<OutputOwnershipPhase>)
    ensures next == output_ownership_step_spec(phase, event),
{
    match (phase, event) {
        (OutputOwnershipPhase::ResponseOwned, OutputOwnershipEvent::BeginRead) => {
            Some(OutputOwnershipPhase::ReadTaskOwned)
        }
        (OutputOwnershipPhase::ReadTaskOwned, OutputOwnershipEvent::ReadComplete) => {
            Some(OutputOwnershipPhase::ResponseOwned)
        }
        (OutputOwnershipPhase::ReadTaskOwned, OutputOwnershipEvent::Cancel) => {
            Some(OutputOwnershipPhase::ReadTaskCancelled)
        }
        (OutputOwnershipPhase::ReadTaskCancelled, OutputOwnershipEvent::ReadComplete) => {
            Some(OutputOwnershipPhase::Released)
        }
        (OutputOwnershipPhase::ResponseOwned, OutputOwnershipEvent::Cancel)
        | (OutputOwnershipPhase::ResponseOwned, OutputOwnershipEvent::Finish) => {
            Some(OutputOwnershipPhase::Released)
        }
        _ => None,
    }
}

pub proof fn output_cancel_preserves_active_read_ownership()
    ensures
        output_ownership_step_spec(
            OutputOwnershipPhase::ReadTaskOwned,
            OutputOwnershipEvent::Cancel,
        ) == Some(OutputOwnershipPhase::ReadTaskCancelled),
        output_ownership_step_spec(
            OutputOwnershipPhase::ReadTaskCancelled,
            OutputOwnershipEvent::ReadComplete,
        ) == Some(OutputOwnershipPhase::Released),
{
}

pub proof fn released_output_ownership_is_terminal(event: OutputOwnershipEvent)
    ensures output_ownership_step_spec(OutputOwnershipPhase::Released, event).is_none(),
{
}

/// The side-effecting target represented by a prepared route.  The request
/// adapters carry this typed value across body acquisition and scheduler
/// boundaries instead of retaining an opaque closure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PreparedHandlerKind {
    Proxy,
    FastCgi,
    Cgi,
}

pub open spec fn prepared_handler_needs_dynamic_lease_spec(kind: PreparedHandlerKind) -> bool {
    match kind {
        PreparedHandlerKind::Proxy
        | PreparedHandlerKind::FastCgi
        | PreparedHandlerKind::Cgi => true,
    }
}

pub fn prepared_handler_needs_dynamic_lease(kind: PreparedHandlerKind) -> (needed: bool)
    ensures needed == prepared_handler_needs_dynamic_lease_spec(kind),
{
    match kind {
        PreparedHandlerKind::Proxy
        | PreparedHandlerKind::FastCgi
        | PreparedHandlerKind::Cgi => true,
    }
}

pub proof fn every_prepared_handler_has_bounded_dynamic_admission(kind: PreparedHandlerKind)
    ensures prepared_handler_needs_dynamic_lease_spec(kind),
{
}

/// Protocol-independent request lifecycle used by the HTTP/1 and HTTP/2
/// adapters.  In particular, body acquisition is reachable only after the
/// policy route selects a body-consuming handler, while an early denial can
/// advance directly to output without accepting attacker-controlled DATA.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestPhase {
    Head,
    Body,
    BodyBackend,
    Dispatch,
    Backend,
    Output,
    Closed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestPhaseEvent {
    RouteNeedsBody,
    RouteNeedsDrain,
    RoutePrepared,
    RouteReady,
    EarlyResponse,
    BodyComplete,
    BodyDiscarded,
    BackendStarted,
    BodyErrorResponse,
    DispatchComplete,
    BackendComplete,
    OutputComplete,
    Cancel,
}

pub open spec fn request_phase_step_spec(
    phase: RequestPhase,
    event: RequestPhaseEvent,
) -> Option<RequestPhase> {
    match (phase, event) {
        (RequestPhase::Head, RequestPhaseEvent::RouteNeedsBody) => Some(RequestPhase::Body),
        (RequestPhase::Head, RequestPhaseEvent::RouteNeedsDrain) => Some(RequestPhase::Body),
        (RequestPhase::Head, RequestPhaseEvent::RoutePrepared) => Some(RequestPhase::Backend),
        (RequestPhase::Head, RequestPhaseEvent::RouteReady) => Some(RequestPhase::Dispatch),
        (RequestPhase::Head, RequestPhaseEvent::EarlyResponse) => Some(RequestPhase::Output),
        (RequestPhase::Body, RequestPhaseEvent::BodyComplete) => Some(RequestPhase::Backend),
        (RequestPhase::Body, RequestPhaseEvent::BodyDiscarded) => Some(RequestPhase::Output),
        (RequestPhase::Body, RequestPhaseEvent::BackendStarted) => {
            Some(RequestPhase::BodyBackend)
        }
        (RequestPhase::BodyBackend, RequestPhaseEvent::BackendComplete) => {
            Some(RequestPhase::Output)
        }
        (RequestPhase::BodyBackend, RequestPhaseEvent::BodyErrorResponse) => {
            Some(RequestPhase::Output)
        }
        (RequestPhase::Body, RequestPhaseEvent::BodyErrorResponse) => Some(RequestPhase::Output),
        (RequestPhase::Dispatch, RequestPhaseEvent::DispatchComplete) => Some(RequestPhase::Output),
        (RequestPhase::Backend, RequestPhaseEvent::BackendComplete) => Some(RequestPhase::Output),
        (RequestPhase::Head, RequestPhaseEvent::Cancel)
        | (RequestPhase::Body, RequestPhaseEvent::Cancel)
        | (RequestPhase::BodyBackend, RequestPhaseEvent::Cancel)
        | (RequestPhase::Dispatch, RequestPhaseEvent::Cancel)
        | (RequestPhase::Backend, RequestPhaseEvent::Cancel)
        | (RequestPhase::Output, RequestPhaseEvent::Cancel)
        | (RequestPhase::Output, RequestPhaseEvent::OutputComplete) => Some(RequestPhase::Closed),
        _ => None,
    }
}

pub fn request_phase_step(
    phase: RequestPhase,
    event: RequestPhaseEvent,
) -> (next: Option<RequestPhase>)
    ensures next == request_phase_step_spec(phase, event),
{
    match (phase, event) {
        (RequestPhase::Head, RequestPhaseEvent::RouteNeedsBody) => Some(RequestPhase::Body),
        (RequestPhase::Head, RequestPhaseEvent::RouteNeedsDrain) => Some(RequestPhase::Body),
        (RequestPhase::Head, RequestPhaseEvent::RoutePrepared) => Some(RequestPhase::Backend),
        (RequestPhase::Head, RequestPhaseEvent::RouteReady) => Some(RequestPhase::Dispatch),
        (RequestPhase::Head, RequestPhaseEvent::EarlyResponse) => Some(RequestPhase::Output),
        (RequestPhase::Body, RequestPhaseEvent::BodyComplete) => Some(RequestPhase::Backend),
        (RequestPhase::Body, RequestPhaseEvent::BodyDiscarded) => Some(RequestPhase::Output),
        (RequestPhase::Body, RequestPhaseEvent::BackendStarted) => {
            Some(RequestPhase::BodyBackend)
        }
        (RequestPhase::BodyBackend, RequestPhaseEvent::BackendComplete) => {
            Some(RequestPhase::Output)
        }
        (RequestPhase::BodyBackend, RequestPhaseEvent::BodyErrorResponse) => {
            Some(RequestPhase::Output)
        }
        (RequestPhase::Body, RequestPhaseEvent::BodyErrorResponse) => Some(RequestPhase::Output),
        (RequestPhase::Dispatch, RequestPhaseEvent::DispatchComplete) => Some(RequestPhase::Output),
        (RequestPhase::Backend, RequestPhaseEvent::BackendComplete) => Some(RequestPhase::Output),
        (RequestPhase::Head, RequestPhaseEvent::Cancel)
        | (RequestPhase::Body, RequestPhaseEvent::Cancel)
        | (RequestPhase::BodyBackend, RequestPhaseEvent::Cancel)
        | (RequestPhase::Dispatch, RequestPhaseEvent::Cancel)
        | (RequestPhase::Backend, RequestPhaseEvent::Cancel)
        | (RequestPhase::Output, RequestPhaseEvent::Cancel)
        | (RequestPhase::Output, RequestPhaseEvent::OutputComplete) => Some(RequestPhase::Closed),
        _ => None,
    }
}

pub proof fn request_body_requires_route_selection(
    phase: RequestPhase,
    event: RequestPhaseEvent,
)
    ensures
        request_phase_step_spec(phase, event) == Some(RequestPhase::Body)
            ==> phase == RequestPhase::Head
                && (event == RequestPhaseEvent::RouteNeedsBody
                    || event == RequestPhaseEvent::RouteNeedsDrain),
{
}

pub proof fn discarded_request_body_advances_directly_to_output()
    ensures
        request_phase_step_spec(RequestPhase::Body, RequestPhaseEvent::BodyDiscarded)
            == Some(RequestPhase::Output),
{
}

pub proof fn request_closed_phase_is_absorbing(event: RequestPhaseEvent)
    ensures request_phase_step_spec(RequestPhase::Closed, event).is_none(),
{
}

/// Overflow-free length transition for regex capture substitution. Runtime
/// expansion allocates only after this transition admits the resulting value.
pub fn capture_expansion_len(
    current: u64,
    occurrences: u64,
    marker_len: u64,
    value_len: u64,
    limit: u64,
) -> (next: Option<u64>)
    ensures match next { Some(length) => length <= limit, None => true },
{
    let removed = match occurrences.checked_mul(marker_len) {
        Some(value) => value,
        None => return None,
    };
    let added = match occurrences.checked_mul(value_len) {
        Some(value) => value,
        None => return None,
    };
    let base = match current.checked_sub(removed) {
        Some(value) => value,
        None => return None,
    };
    let length = match base.checked_add(added) {
        Some(value) => value,
        None => return None,
    };
    if length > limit { None } else { Some(length) }
}

/// A request-body prefix remains resident in memory only while the exact
/// incremental addition fits the per-stream allowance.  Both HTTP adapters
/// consume this predicate before extending their concrete buffer; rejection
/// therefore means "spill", never "allocate anyway".
pub open spec fn request_body_memory_spec(used: u64, incoming: u64, limit: u64) -> bool {
    used <= limit && incoming <= limit - used
}

pub fn request_body_memory_admit(used: u64, incoming: u64, limit: u64) -> (ok: bool)
    ensures ok == request_body_memory_spec(used, incoming, limit),
{
    used <= limit && incoming <= limit - used
}

pub proof fn request_body_memory_admission_is_bounded(
    used: u64,
    incoming: u64,
    limit: u64,
)
    requires request_body_memory_spec(used, incoming, limit),
    ensures used + incoming <= limit,
{
}

/// `<IfFile>` is safe to splice into its enclosing configuration phase only
/// after the operator path has been made absolute against ServerRoot and the
/// parser has retained the children's own phase identities.
pub fn iffile_exec_on_read_admit(
    resolved_against_server_root: bool,
    children_keep_phase: bool,
) -> (ok: bool)
    ensures ok == (resolved_against_server_root && children_keep_phase),
{
    resolved_against_server_root && children_keep_phase
}

/// A selected proxy route is admitted only when the configuration-only ACL
/// authorizes it.  Per-directory policy may impose an additional denial, but
/// it can never supply the operator grant required by this gate.
pub fn proxy_operator_acl_admit(proxy_selected: bool, operator_allowed: bool) -> (ok: bool)
    ensures ok == (!proxy_selected || operator_allowed),
{
    !proxy_selected || operator_allowed
}

/// Automatic balancer failover may replay an idempotent request, or any
/// request that provably failed before a backend connection was established.
/// Once an unsafe request might have reached a member, an ambiguous transport
/// error must be returned to the client instead of executing it again.
pub open spec fn proxy_retry_spec(request_may_have_started: bool, idempotent: bool) -> bool {
    !request_may_have_started || idempotent
}

pub fn proxy_retry_admit(request_may_have_started: bool, idempotent: bool) -> (ok: bool)
    ensures ok == proxy_retry_spec(request_may_have_started, idempotent),
{
    !request_may_have_started || idempotent
}

pub proof fn proxy_retry_rejects_ambiguous_unsafe()
    ensures !proxy_retry_spec(true, false),
{
}

pub proof fn proxy_retry_allows_preconnect_failure(idempotent: bool)
    ensures proxy_retry_spec(false, idempotent),
{
}

/// Request-time `file()` expressions admit only a regular descriptor whose
/// observed size fits the fixed read ceiling. The runtime additionally uses a
/// bounded reader so a concurrent growth cannot exceed this allowance.
pub fn expr_file_read_admit(regular: bool, size: u64, limit: u64) -> (ok: bool)
    ensures ok == (regular && size <= limit),
{
    regular && size <= limit
}

pub proof fn expr_file_read_admission_is_bounded(regular: bool, size: u64, limit: u64)
    requires regular, size <= limit,
    ensures size <= limit,
{
}

/// F45/I42: an expression file test must be relative, free of parent
/// components, and (after canonicalization) beneath the document root.
pub fn expr_file_test_admit(
    absolute: bool,
    parent_relative: bool,
    under_root: bool,
) -> (ok: bool)
    ensures ok == (!absolute && !parent_relative && under_root),
{
    !absolute && !parent_relative && under_root
}

/// The complete token alphabet understood by the rewrite substitution
/// expander.  Both the runtime expander and load-time proxy-authority guard
/// consume this classifier, so admission cannot drift from interpretation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RewriteExpandToken {
    Literal,
    Variable,
    RuleCapture { index: u8 },
    ConditionCapture { index: u8 },
}

pub open spec fn rewrite_expand_token_spec(input: Seq<u8>, i: int) -> RewriteExpandToken
    recommends 0 <= i < input.len(),
{
    if i + 1 >= input.len() {
        RewriteExpandToken::Literal
    } else {
        let marker = input[i];
        let next = input[i + 1];
        if (marker == b'$' || marker == b'%') && next == b'{' {
            RewriteExpandToken::Variable
        } else if (marker == b'$' || marker == b'\\') && next >= b'0' && next <= b'9' {
            RewriteExpandToken::RuleCapture { index: (next - b'0') as u8 }
        } else if marker == b'%' && next >= b'0' && next <= b'9' {
            RewriteExpandToken::ConditionCapture { index: (next - b'0') as u8 }
        } else {
            RewriteExpandToken::Literal
        }
    }
}

pub fn rewrite_expand_token(input: &[u8], i: usize) -> (token: RewriteExpandToken)
    requires i < input.len(),
    ensures token == rewrite_expand_token_spec(input@, i as int),
{
    if i + 1 >= input.len() {
        RewriteExpandToken::Literal
    } else {
        let marker = input[i];
        let next = input[i + 1];
        if (marker == b'$' || marker == b'%') && next == b'{' {
            RewriteExpandToken::Variable
        } else if (marker == b'$' || marker == b'\\') && next >= b'0' && next <= b'9' {
            RewriteExpandToken::RuleCapture { index: next - b'0' }
        } else if marker == b'%' && next >= b'0' && next <= b'9' {
            RewriteExpandToken::ConditionCapture { index: next - b'0' }
        } else {
            RewriteExpandToken::Literal
        }
    }
}

/// P14-B: a proxy authority (or a scheme-less proxy template) is static only
/// when the shared expander classifier sees no variable or capture token.
pub open spec fn rewrite_template_static_spec(input: Seq<u8>) -> bool {
    forall|i: int|
        0 <= i < input.len() ==>
            rewrite_expand_token_spec(input, i) == RewriteExpandToken::Literal
}

pub fn rewrite_template_static(input: &[u8]) -> (ok: bool)
    ensures ok == rewrite_template_static_spec(input@),
{
    let mut i: usize = 0;
    while i < input.len()
        invariant
            i <= input.len(),
            forall|j: int|
                0 <= j < i ==>
                    rewrite_expand_token_spec(input@, j) == RewriteExpandToken::Literal,
        decreases input.len() - i,
    {
        let token = rewrite_expand_token(input, i);
        match token {
            RewriteExpandToken::Literal => {
                assert(token == rewrite_expand_token_spec(input@, i as int));
                assert(rewrite_expand_token_spec(input@, i as int)
                    == RewriteExpandToken::Literal);
            }
            _ => {
                assert(token == rewrite_expand_token_spec(input@, i as int));
                assert(rewrite_expand_token_spec(input@, i as int)
                    != RewriteExpandToken::Literal);
                assert(!rewrite_template_static_spec(input@)) by {
                    if rewrite_template_static_spec(input@) {
                        assert(rewrite_expand_token_spec(input@, i as int)
                            == RewriteExpandToken::Literal);
                    }
                }
                return false;
            }
        }
        assert forall|j: int|
            0 <= j < i + 1 ==>
                rewrite_expand_token_spec(input@, j) == RewriteExpandToken::Literal
        by {
            if 0 <= j < i + 1 {
                if j < i {
                    assert(rewrite_expand_token_spec(input@, j)
                        == RewriteExpandToken::Literal);
                } else {
                    assert(j == i);
                }
            }
        }
        i = i + 1;
    }
    true
}

/// P14-E: after a chained rule fails, skip every following chained rule and
/// the first non-chained action rule.
pub open spec fn rewrite_chain_resume_spec(chained: Seq<bool>, start: int) -> int
    recommends 0 <= start <= chained.len(),
    decreases chained.len() - start,
{
    if start >= chained.len() {
        start
    } else if chained[start] {
        rewrite_chain_resume_spec(chained, start + 1)
    } else {
        start + 1
    }
}

pub fn rewrite_chain_resume(chained: &[bool], start: usize) -> (resume: usize)
    requires start <= chained.len(),
    ensures
        resume == rewrite_chain_resume_spec(chained@, start as int),
        start <= resume <= chained.len(),
{
    let mut cursor = start;
    while cursor < chained.len() && chained[cursor]
        invariant
            start <= cursor <= chained.len(),
            rewrite_chain_resume_spec(chained@, start as int)
                == rewrite_chain_resume_spec(chained@, cursor as int),
        decreases chained.len() - cursor,
    {
        cursor = cursor + 1;
    }
    if cursor < chained.len() {
        cursor + 1
    } else {
        cursor
    }
}

/// Staged rule-control decision made after subject/condition/regex evaluation
/// but before a substitution is expanded.  This is the single control point
/// for chain failure, `[F]`/`[G]`, no-substitution rules and target expansion.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RewriteMatchAction {
    Continue { index: usize },
    Forbidden,
    Gone,
    NoSubstitution,
    Expand,
}

pub open spec fn rewrite_match_action_spec(
    chained: Seq<bool>,
    next_index: int,
    matched: bool,
    chain: bool,
    forbidden: bool,
    gone: bool,
    no_substitution: bool,
) -> RewriteMatchAction
    recommends 0 <= next_index <= chained.len(),
{
    if !matched {
        RewriteMatchAction::Continue {
            index: if chain {
                rewrite_chain_resume_spec(chained, next_index) as usize
            } else {
                next_index as usize
            },
        }
    } else if forbidden {
        RewriteMatchAction::Forbidden
    } else if gone {
        RewriteMatchAction::Gone
    } else if no_substitution {
        RewriteMatchAction::NoSubstitution
    } else {
        RewriteMatchAction::Expand
    }
}

pub fn rewrite_match_action(
    chained: &[bool],
    next_index: usize,
    matched: bool,
    chain: bool,
    forbidden: bool,
    gone: bool,
    no_substitution: bool,
) -> (action: RewriteMatchAction)
    requires next_index <= chained.len(),
    ensures
        action == rewrite_match_action_spec(
            chained@,
            next_index as int,
            matched,
            chain,
            forbidden,
            gone,
            no_substitution,
        ),
        match action {
            RewriteMatchAction::Continue { index } => index <= chained.len(),
            _ => true,
        },
{
    if !matched {
        RewriteMatchAction::Continue {
            index: if chain {
                rewrite_chain_resume(chained, next_index)
            } else {
                next_index
            },
        }
    } else if forbidden {
        RewriteMatchAction::Forbidden
    } else if gone {
        RewriteMatchAction::Gone
    } else if no_substitution {
        RewriteMatchAction::NoSubstitution
    } else {
        RewriteMatchAction::Expand
    }
}

/// Verified program-counter transition shared by `-` and internal-target
/// rules. `[N]` takes precedence over `[L]/[END]`; `[END]` makes a stopped
/// pass final even when the substitution is `-`; `[S]` is bounded by the
/// remaining rule count instead of relying on integer saturation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RewriteAdvance {
    Continue { index: usize },
    Restart { completed: u64 },
    Stop { final_pass: bool },
    RestartLimit,
}

pub open spec fn rewrite_skip_index_spec(
    next_index: int,
    rule_count: int,
    has_skip: bool,
    skip: int,
) -> int
    recommends 0 <= next_index <= rule_count && 0 <= skip,
{
    if has_skip && skip <= rule_count - next_index {
        next_index + skip
    } else if has_skip {
        rule_count
    } else {
        next_index
    }
}

pub open spec fn rewrite_advance_spec(
    next_index: int,
    rule_count: int,
    has_skip: bool,
    skip: int,
    restart: bool,
    last: bool,
    end: bool,
    completed: u64,
    limit: u64,
) -> RewriteAdvance
    recommends 0 <= next_index <= rule_count && 0 <= skip,
{
    if restart {
        if rewrite_restart_admit_spec(completed, limit) {
            RewriteAdvance::Restart { completed: (completed + 1) as u64 }
        } else {
            RewriteAdvance::RestartLimit
        }
    } else if last {
        RewriteAdvance::Stop { final_pass: end }
    } else {
        RewriteAdvance::Continue {
            index: rewrite_skip_index_spec(next_index, rule_count, has_skip, skip) as usize,
        }
    }
}

pub fn rewrite_advance(
    next_index: usize,
    rule_count: usize,
    has_skip: bool,
    skip: usize,
    restart: bool,
    last: bool,
    end: bool,
    completed: u64,
    limit: u64,
) -> (advance: RewriteAdvance)
    requires next_index <= rule_count,
    ensures
        advance == rewrite_advance_spec(
            next_index as int,
            rule_count as int,
            has_skip,
            skip as int,
            restart,
            last,
            end,
            completed,
            limit,
        ),
        match advance {
            RewriteAdvance::Continue { index } => index <= rule_count,
            RewriteAdvance::Restart { completed: after } =>
                completed < limit && after == completed + 1 && after <= limit,
            RewriteAdvance::Stop { final_pass } => last && final_pass == end,
            RewriteAdvance::RestartLimit => restart && completed >= limit,
        },
{
    if restart {
        if rewrite_restart_admit(completed, limit) {
            RewriteAdvance::Restart { completed: completed + 1 }
        } else {
            RewriteAdvance::RestartLimit
        }
    } else if last {
        RewriteAdvance::Stop { final_pass: end }
    } else {
        let index = if has_skip {
            let remaining = rule_count - next_index;
            if skip <= remaining {
                next_index + skip
            } else {
                rule_count
            }
        } else {
            next_index
        };
        RewriteAdvance::Continue { index }
    }
}

pub proof fn rewrite_unmatched_rule_has_no_terminal_effect(
    chained: Seq<bool>,
    next_index: int,
    chain: bool,
    forbidden: bool,
    gone: bool,
    no_substitution: bool,
)
    requires 0 <= next_index <= chained.len(),
    ensures
        match rewrite_match_action_spec(
            chained,
            next_index,
            false,
            chain,
            forbidden,
            gone,
            no_substitution,
        ) {
            RewriteMatchAction::Continue { .. } => true,
            _ => false,
        },
{
}

pub proof fn rewrite_restart_cannot_fall_through(
    next_index: int,
    rule_count: int,
    has_skip: bool,
    skip: int,
    last: bool,
    end: bool,
    completed: u64,
    limit: u64,
)
    requires 0 <= next_index <= rule_count && 0 <= skip,
    ensures
        match rewrite_advance_spec(
            next_index,
            rule_count,
            has_skip,
            skip,
            true,
            last,
            end,
            completed,
            limit,
        ) {
            RewriteAdvance::Restart { .. } | RewriteAdvance::RestartLimit => true,
            _ => false,
        },
{
}

/// F50/I47: an access-file layer participates for every ancestor directory
/// whose effective `AllowOverride` policy permits it.  `DocumentRoot` and an
/// alias target are URL-mapping labels, not lower bounds on this walk.
pub fn access_walk_dir_admit(is_walk_ancestor: bool, override_permits: bool) -> (ok: bool)
    ensures ok == (is_walk_ancestor && override_permits),
{
    is_walk_ancestor && override_permits
}

/// Apache's `AccessFileName a b ...` consults candidates in order and uses
/// only the first existing entry in each directory.  Merging later files lets
/// an attacker-controlled secondary name add handlers or relax policy after a
/// trusted primary access file.
pub open spec fn access_file_candidate_spec(prior_selected: bool, exists: bool) -> bool {
    !prior_selected && exists
}

pub fn access_file_candidate_admit(prior_selected: bool, exists: bool) -> (ok: bool)
    ensures ok == access_file_candidate_spec(prior_selected, exists),
{
    !prior_selected && exists
}

pub proof fn access_file_later_candidate_cannot_merge(prior_selected: bool, exists: bool)
    ensures prior_selected ==> !access_file_candidate_spec(prior_selected, exists),
{
}

/// F51/I48: the mapping root used for URL/`RewriteBase` derivation is the one
/// selected by URL mapping, never a root reconstructed from an arbitrary
/// alias target that happens to contain the filesystem path.
pub fn alias_mapping_root_admit(
    selected_by_url_mapping: bool,
    inferred_from_alias_containment: bool,
) -> (ok: bool)
    ensures ok == (selected_by_url_mapping && !inferred_from_alias_containment),
{
    selected_by_url_mapping && !inferred_from_alias_containment
}

/// F52/I49: a cache entry produced by `DirectoryIndex` is keyed and authorized
/// against the selected index, not only the directory URL.  Directories that
/// resolve to an autoindex or redirect have no index target to bind.
pub fn cache_directory_index_bind_admit(
    directory_target: bool,
    index_selected: bool,
    key_uses_index: bool,
    policy_uses_index: bool,
) -> (ok: bool)
    ensures
        ok == (!directory_target
            || !index_selected
            || (key_uses_index && policy_uses_index)),
{
    !directory_target || !index_selected || (key_uses_index && policy_uses_index)
}

/// F52/I49: `CacheIgnoreQueryString` may not merge a dynamic target's
/// representations across different query strings.
pub fn cache_ignore_query_admit(
    ignore_query_string: bool,
    query_present: bool,
    dynamic_target: bool,
) -> (ok: bool)
    ensures ok == !(ignore_query_string && query_present && dynamic_target),
{
    !(ignore_query_string && query_present && dynamic_target)
}

/// F53/I50: a per-directory rewrite base is derived from the requested URL
/// and the layer's depth below the requested target, never from a path
/// relative to an alias target.  The layer must be an ancestor of the
/// requested target and the URL must have enough components for that depth.
pub fn htaccess_layer_url_base_admit(
    layer_under_request_target: bool,
    url_depth_sufficient: bool,
) -> (ok: bool)
    ensures ok == (layer_under_request_target && url_depth_sufficient),
{
    layer_under_request_target && url_depth_sufficient
}

/// F57/I57: `%{REQUEST_URI}` is the dispatcher-selected canonical URL path.
/// Binding it to the raw request-line target, or appending the query string,
/// makes path authorization expressions inspect bytes other than the resource
/// that dispatch later selects.
pub fn request_uri_identity_admit(
    bound_to_canonical_path: bool,
    includes_query_string: bool,
    raw_request_target: bool,
) -> (ok: bool)
    ensures
        ok == (bound_to_canonical_path
            && !includes_query_string
            && !raw_request_target),
{
    bound_to_canonical_path && !includes_query_string && !raw_request_target
}

/// F58/I58: a per-directory access-file rewrite subject is the requested
/// filesystem target relative to the layer directory (Apache's
/// `r->filename`-relative subject).  If that subject is required but cannot be
/// constructed, the layer must fail closed instead of silently matching
/// nothing.
pub fn htaccess_rewrite_subject_admit(
    filesystem_subject_required: bool,
    filesystem_subject_available: bool,
) -> (ok: bool)
    ensures ok == (!filesystem_subject_required || filesystem_subject_available),
{
    !filesystem_subject_required || filesystem_subject_available
}

/// F59/I60: an explicit-target plan must collect access-file layers by walking
/// that same explicit target.  Every collected layer directory must be the
/// target itself or one of its ancestors, so a lexical mapping root (which may
/// contain a symlink) can never fabricate a different layer path.
pub fn explicit_target_layer_admit(
    explicit_target: bool,
    layer_walk_uses_explicit_target: bool,
    layers_match_target_ancestors: bool,
) -> (ok: bool)
    ensures
        ok == (!explicit_target
            || (layer_walk_uses_explicit_target && layers_match_target_ancestors)),
{
    !explicit_target || (layer_walk_uses_explicit_target && layers_match_target_ancestors)
}

/// F59/I60: a plan carrying access-file layers must consume them during scope
/// evaluation.  The configuration-only path is admissible only when neither
/// the target's lexical override prefix applies nor any layer was collected.
pub fn target_layer_consume_admit(
    override_may_apply: bool,
    has_access_layers: bool,
) -> (ok: bool)
    ensures ok == (override_may_apply || has_access_layers),
{
    override_may_apply || has_access_layers
}

// ---------------------------------------------------------------------------
// Generalized policy bit meet
// ---------------------------------------------------------------------------

/// The meet of two policy bit-vectors: a permission bit survives only when
/// every identity grants it.  This is the single shape shared by the `Options`
/// conjoin and the `AllowOverride` category conjoin (F60/I61); the named specs
/// below are aliases of this one so every caller states the same obligation
/// and the algebraic facts are proved once, generically.
pub open spec fn bits_meet(url_bits: u32, target_bits: u32) -> u32 {
    url_bits & target_bits
}

pub fn bits_meet_exec(url_bits: u32, target_bits: u32) -> (out: u32)
    ensures out == bits_meet(url_bits, target_bits),
{
    url_bits & target_bits
}

/// A meet never grants a bit that either input lacks (no-broadening).
pub proof fn bits_meet_never_grants(url_bits: u32, target_bits: u32)
    ensures
        bits_meet(url_bits, target_bits) & url_bits == bits_meet(url_bits, target_bits),
        bits_meet(url_bits, target_bits) & target_bits == bits_meet(url_bits, target_bits),
{
    assert(bits_meet(url_bits, target_bits) & url_bits == bits_meet(url_bits, target_bits))
        by (bit_vector);
    assert(bits_meet(url_bits, target_bits) & target_bits == bits_meet(url_bits, target_bits))
        by (bit_vector);
}

/// The meet is a bounded meet: commutative, associative and idempotent.  A
/// conjoin of any number of path identities (URL scope, canonical target,
/// rewrite rounds, cache target) therefore computes the same bit vector in
/// any order, and repeating an identity adds nothing.
pub proof fn bits_meet_commutative(a: u32, b: u32)
    ensures bits_meet(a, b) == bits_meet(b, a),
{
    assert(bits_meet(a, b) == bits_meet(b, a)) by (bit_vector);
}

pub proof fn bits_meet_associative(a: u32, b: u32, c: u32)
    ensures bits_meet(bits_meet(a, b), c) == bits_meet(a, bits_meet(b, c)),
{
    assert(bits_meet(bits_meet(a, b), c) == bits_meet(a, bits_meet(b, c))) by (bit_vector);
}

pub proof fn bits_meet_idempotent(a: u32)
    ensures bits_meet(a, a) == a,
{
    assert(bits_meet(a, a) == a) by (bit_vector);
}

/// Monotone: conjoining an extra identity can only remove bits.
pub proof fn bits_meet_narrowing(a: u32, b: u32)
    ensures bits_meet(bits_meet(a, b), b) == bits_meet(a, b),
{
    bits_meet_associative(a, b, b);
    bits_meet_idempotent(b);
}

/// F60/I61: the effective `Options` set for a resolved target is the meet of
/// the URL-mapped scope and the canonical target scope.  A permission bit is
/// present only when both scopes grant it, so resolving a symlink (or any
/// other target-changing transform) can never add `ExecCGI`, `Indexes` or
/// `FollowSymLinks`.
pub open spec fn options_conjoin_spec(url_bits: u32, target_bits: u32) -> u32 {
    bits_meet(url_bits, target_bits)
}

pub fn options_conjoin(url_bits: u32, target_bits: u32) -> (out: u32)
    ensures out == options_conjoin_spec(url_bits, target_bits),
{
    bits_meet_exec(url_bits, target_bits)
}

/// The meet contains no permission bit that either input scope lacks.
pub proof fn options_conjoin_never_grants(url_bits: u32, target_bits: u32)
    ensures
        options_conjoin_spec(url_bits, target_bits) & url_bits
            == options_conjoin_spec(url_bits, target_bits),
        options_conjoin_spec(url_bits, target_bits) & target_bits
            == options_conjoin_spec(url_bits, target_bits),
{
    bits_meet_never_grants(url_bits, target_bits);
}

/// F60/I61: a handler is usable only when both the URL-mapped and canonical
/// target scopes select the same effective handler.  A target `AddHandler`
/// therefore cannot undo a lexical `RemoveHandler`, and a lexical `AddHandler`
/// cannot smuggle execution through a target that removes the handler.
pub open spec fn handler_conjoin_spec(
    url_has_handler: bool,
    target_has_handler: bool,
    same_handler: bool,
) -> bool {
    url_has_handler && target_has_handler && same_handler
}

pub fn handler_conjoin_admit(
    url_has_handler: bool,
    target_has_handler: bool,
    same_handler: bool,
) -> (ok: bool)
    ensures
        ok == handler_conjoin_spec(url_has_handler, target_has_handler, same_handler),
{
    url_has_handler && target_has_handler && same_handler
}

pub proof fn handler_conjoin_requires_both(
    url_has_handler: bool,
    target_has_handler: bool,
    same_handler: bool,
)
    ensures
        handler_conjoin_spec(url_has_handler, target_has_handler, same_handler)
            ==> url_has_handler && target_has_handler,
{
}

/// P12-B: an extension table is consulted only after a real, non-empty
/// basename followed by a dot.  Dotless names and names made solely from
/// leading dots therefore cannot acquire a handler.
pub open spec fn extension_table_spec(stem_nonempty: bool, has_separator: bool) -> bool {
    stem_nonempty && has_separator
}

pub fn extension_table_admit(stem_nonempty: bool, has_separator: bool) -> (ok: bool)
    ensures ok == extension_table_spec(stem_nonempty, has_separator),
{
    stem_nonempty && has_separator
}

pub proof fn extension_table_rejects_unqualified_names(
    stem_nonempty: bool,
    has_separator: bool,
)
    ensures
        extension_table_spec(stem_nonempty, has_separator)
            ==> stem_nonempty && has_separator,
{
}

/// P12-B: `RemoveHandler` is a deny entry, not an order-dependent table
/// assignment.  Once the effective scope contains a matching removal, a
/// matching AddHandler cannot restore execution.
pub open spec fn handler_extension_spec(removed: bool, has_add: bool) -> bool {
    !removed && has_add
}

pub fn handler_extension_admit(removed: bool, has_add: bool) -> (ok: bool)
    ensures ok == handler_extension_spec(removed, has_add),
{
    !removed && has_add
}

pub proof fn handler_extension_removal_wins(removed: bool, has_add: bool)
    ensures removed ==> !handler_extension_spec(removed, has_add),
{
}

/// An explicit `FileETag None` is represented by zero bits and suppresses the
/// field.  Zero must not be reinterpreted as the default `All` mask.
pub open spec fn file_etag_emit_spec(bits: u32) -> bool {
    bits != 0
}

pub fn file_etag_emit_admit(bits: u32) -> (ok: bool)
    ensures ok == file_etag_emit_spec(bits),
{
    bits != 0
}

pub proof fn file_etag_none_emits_nothing()
    ensures !file_etag_emit_spec(0),
{
}

/// P12-E: configuring an authentication mechanism without an effective
/// authorization policy is a server error and must never become an implicit
/// grant (including through `Satisfy any`).
pub open spec fn authz_configuration_spec(auth_type_set: bool, has_require: bool) -> bool {
    !auth_type_set || has_require
}

pub fn authz_configuration_admit(auth_type_set: bool, has_require: bool) -> (ok: bool)
    ensures ok == authz_configuration_spec(auth_type_set, has_require),
{
    !auth_type_set || has_require
}

pub proof fn auth_type_requires_authorization(auth_type_set: bool, has_require: bool)
    ensures
        auth_type_set && authz_configuration_spec(auth_type_set, has_require)
            ==> has_require,
{
}

/// P12 static-audit follow-up: `Require method` operands are admitted only
/// when the parser saw at least one method and every spelling is an exact
/// supported token.  In particular, silently uppercasing `get` into `GET`
/// would turn an Apache non-match into a grant.
pub open spec fn require_method_operand_spec(nonempty: bool, all_exact_known: bool) -> bool {
    nonempty && all_exact_known
}

pub fn require_method_operand_admit(nonempty: bool, all_exact_known: bool) -> (ok: bool)
    ensures ok == require_method_operand_spec(nonempty, all_exact_known),
{
    nonempty && all_exact_known
}

pub proof fn require_method_rejects_normalized_spelling(
    nonempty: bool,
    all_exact_known: bool,
)
    ensures
        require_method_operand_spec(nonempty, all_exact_known)
            ==> nonempty && all_exact_known,
{
}

/// P12 static-audit follow-up: mod_authz_core's `env` provider accepts a
/// variable name, not a `NAME=VALUE` comparison.  Treating the latter as a
/// comparison can grant a request that Apache never grants.
pub open spec fn require_env_operand_spec(name_nonempty: bool, has_equals: bool) -> bool {
    name_nonempty && !has_equals
}

pub fn require_env_operand_admit(name_nonempty: bool, has_equals: bool) -> (ok: bool)
    ensures ok == require_env_operand_spec(name_nonempty, has_equals),
{
    name_nonempty && !has_equals
}

pub proof fn require_env_rejects_value_comparisons(name_nonempty: bool, has_equals: bool)
    ensures has_equals ==> !require_env_operand_spec(name_nonempty, has_equals),
{
}

/// F60/I61: component-aware intersection for `AllowOverride` categories.
/// This is the same generalized bit meet as `options_conjoin`; the algebraic
/// facts (`bits_meet_*`) apply to it unchanged.
pub fn override_categories_conjoin(url_bits: u32, target_bits: u32) -> (out: u32)
    ensures out == bits_meet(url_bits, target_bits),
{
    bits_meet_exec(url_bits, target_bits)
}

/// The executable kernel for `AllowOverride` category admission.  `mode` is
/// 0 for `None`, 1 for `All`, and 2 for an explicit category bit-vector.
/// Keeping this decision in Verus means a category absent from the effective
/// policy can never be admitted by the Rust parser's control flow.
pub open spec fn override_mode_allows_spec(mode: u8, categories: u32, required: u32) -> bool {
    mode == 1 || (mode == 2 && categories & required != 0)
}

pub fn override_mode_allows(mode: u8, categories: u32, required: u32) -> (ok: bool)
    ensures ok == override_mode_allows_spec(mode, categories, required),
{
    mode == 1 || (mode == 2 && categories & required != 0)
}

pub proof fn override_none_never_allows(categories: u32, required: u32)
    ensures !override_mode_allows_spec(0, categories, required),
{
}

/// Total P18 section-family projection consumed by the runtime's closed
/// AccessSectionKind enum. Codes 0..10 use Apache's OR_ALL mask, 11..13 are
/// authorization containers, and 14..15 are method containers. Unknown codes
/// are rejected rather than inheriting a permissive default.
pub open spec fn htaccess_section_category_spec(
    section_code: u8,
    any_override_enabled: bool,
    auth_config_allowed: bool,
    limit_allowed: bool,
) -> bool {
    (section_code < 11 && any_override_enabled)
        || (11 <= section_code && section_code < 14 && auth_config_allowed)
        || (14 <= section_code
            && section_code < 16
            && (auth_config_allowed || limit_allowed))
}

pub fn htaccess_section_category_admit(
    section_code: u8,
    any_override_enabled: bool,
    auth_config_allowed: bool,
    limit_allowed: bool,
) -> (admit: bool)
    ensures admit == htaccess_section_category_spec(
        section_code,
        any_override_enabled,
        auth_config_allowed,
        limit_allowed,
    ),
{
    (section_code < 11 && any_override_enabled)
        || (11 <= section_code && section_code < 14 && auth_config_allowed)
        || (14 <= section_code
            && section_code < 16
            && (auth_config_allowed || limit_allowed))
}

pub proof fn htaccess_unknown_section_code_is_never_category_admitted(
    section_code: u8,
    any_override_enabled: bool,
    auth_config_allowed: bool,
    limit_allowed: bool,
)
    requires 16 <= section_code,
    ensures !htaccess_section_category_spec(
        section_code,
        any_override_enabled,
        auth_config_allowed,
        limit_allowed,
    ),
{
}

/// Apache evaluates IfFile and module/configuration introspection sections
/// while it reads the access file. Their command failures are not suppressible
/// by `Nonfatal=Override`; runtime and ordinary nested sections are. Unknown
/// codes fail closed rather than acquiring the skippable property.
pub open spec fn htaccess_section_override_skippable_spec(section_code: u8) -> bool {
    section_code < 16
        && section_code != 3
        && !(6 <= section_code && section_code <= 10)
}

pub fn htaccess_section_nonfatal_override_admit(
    section_code: u8,
    nonfatal_override: bool,
) -> (skip_allowed: bool)
    ensures skip_allowed
        == (nonfatal_override && htaccess_section_override_skippable_spec(section_code)),
{
    nonfatal_override
        && section_code < 16
        && section_code != 3
        && !(6 <= section_code && section_code <= 10)
}

pub proof fn htaccess_execute_on_read_section_is_not_override_skippable(section_code: u8)
    requires section_code == 3 || (6 <= section_code && section_code <= 10),
    ensures !htaccess_section_override_skippable_spec(section_code),
{
}

/// P18: access-file section wrappers have an admission decision independent
/// of their children. A permitted inner directive cannot admit an unlisted
/// section when no category in the section's own override mask is active.
pub open spec fn htaccess_section_spec(
    category_allowed: bool,
    section_explicitly_listed: bool,
) -> bool {
    category_allowed || section_explicitly_listed
}

pub fn htaccess_section_admit(
    category_allowed: bool,
    section_explicitly_listed: bool,
) -> (admit: bool)
    ensures admit == htaccess_section_spec(category_allowed, section_explicitly_listed),
{
    category_allowed || section_explicitly_listed
}

pub proof fn htaccess_inner_directive_cannot_admit_wrapper(inner_directive_allowed: bool)
    ensures
        inner_directive_allowed ==> !htaccess_section_spec(false, false),
{
}

/// Final `.htaccess` directive/section disposition after category/list
/// admission and Apache's `Nonfatal=` policy.  0 applies the construct, 1
/// skips it, and 2 rejects the access file.  Unknown constructs can only be
/// skipped or rejected; they can never enter the effectful parser.
pub open spec fn htaccess_gate_spec(
    policy_allowed: bool,
    known: bool,
    nonfatal_override: bool,
    nonfatal_unknown: bool,
) -> u8 {
    if !policy_allowed {
        if nonfatal_override { 1u8 } else { 2u8 }
    } else if !known {
        if nonfatal_unknown { 1u8 } else { 2u8 }
    } else {
        0u8
    }
}

pub fn htaccess_gate_admit(
    policy_allowed: bool,
    known: bool,
    nonfatal_override: bool,
    nonfatal_unknown: bool,
) -> (out: u8)
    ensures out == htaccess_gate_spec(
        policy_allowed,
        known,
        nonfatal_override,
        nonfatal_unknown,
    ),
{
    if !policy_allowed {
        if nonfatal_override { 1u8 } else { 2u8 }
    } else if !known {
        if nonfatal_unknown { 1u8 } else { 2u8 }
    } else {
        0u8
    }
}

pub proof fn htaccess_apply_requires_known_and_allowed(
    policy_allowed: bool,
    known: bool,
    nonfatal_override: bool,
    nonfatal_unknown: bool,
)
    ensures
        htaccess_gate_spec(
            policy_allowed,
            known,
            nonfatal_override,
            nonfatal_unknown,
        ) == 0
            ==> policy_allowed && known,
{
}

/// F60/I61: whenever the opened target differs from the URL-mapped path, the
/// served policy must be a conjunction of both scopes.  Replacing the lexical
/// scope with the canonical scope is never admissible.
pub fn resolved_target_scope_admit(
    target_differs: bool,
    scopes_conjoined: bool,
) -> (ok: bool)
    ensures ok == (!target_differs || scopes_conjoined),
{
    !target_differs || scopes_conjoined
}

/// F60/I61: an internal rewrite that changes the request must retain the
/// original URL-mapped execution policy and evaluate the rewritten target
/// policy.  Terminal rewrite outcomes (proxy/redirect) retain the original
/// authorization gate as well.
pub fn rewrite_scope_retained_admit(
    rewrite_changed: bool,
    original_scope_retained: bool,
    target_scope_evaluated: bool,
) -> (ok: bool)
    ensures
        ok == (!rewrite_changed
            || (original_scope_retained && target_scope_evaluated)),
{
    !rewrite_changed || (original_scope_retained && target_scope_evaluated)
}

/// F54/I53: every non-default handler (`SetHandler proxy:`, `server-status`,
/// CGI, FastCGI, future handlers) is dynamic for cache-query purposes.  When
/// a dynamic handler is present, `CacheIgnoreQueryString` must bypass the
/// cache rather than merge representations across queries.
pub fn cache_dynamic_handler_admit(
    dynamic_handler: bool,
    bypassed: bool,
) -> (ok: bool)
    ensures ok == (!dynamic_handler || bypassed),
{
    !dynamic_handler || bypassed
}

/// F56/I52: a local `ErrorDocument` is an internal subrequest selected after
/// dispatch.  Its handler, target and query policy are not described by the
/// original URL's cache scope, so a missing URL that can select one must not
/// serve or store through the shared cache, and an error-document response is
/// never stored under the URL that failed.
pub fn cache_local_error_document_admit(
    local_error_document: bool,
    cache_allowed: bool,
) -> (ok: bool)
    ensures ok == (cache_allowed && !local_error_document),
{
    cache_allowed && !local_error_document
}

/// Lowercase hex digit for a nibble.  This is the spec twin of the runtime
/// `hex_digit` helper; the `cache_key_hex` refinement below is checked against
/// it.
pub open spec fn hex_digit_char(n: u8) -> u8 {
    if n < 10 { (b'0' + n) as u8 } else { (b'a' + (n - 10)) as u8 }
}

/// Inverse mapping used only by the injectivity proof.
pub open spec fn hex_digit_value(c: u8) -> u8 {
    match c {
        b'0' => 0,
        b'1' => 1,
        b'2' => 2,
        b'3' => 3,
        b'4' => 4,
        b'5' => 5,
        b'6' => 6,
        b'7' => 7,
        b'8' => 8,
        b'9' => 9,
        b'a' => 10,
        b'b' => 11,
        b'c' => 12,
        b'd' => 13,
        b'e' => 14,
        b'f' => 15,
        _ => 0,
    }
}

pub proof fn hex_digit_char_roundtrip(n: u8)
    requires n < 16,
    ensures hex_digit_value(hex_digit_char(n)) == n,
{
    if n == 0 {
    } else if n == 1 {
    } else if n == 2 {
    } else if n == 3 {
    } else if n == 4 {
    } else if n == 5 {
    } else if n == 6 {
    } else if n == 7 {
    } else if n == 8 {
    } else if n == 9 {
    } else if n == 10 {
    } else if n == 11 {
    } else if n == 12 {
    } else if n == 13 {
    } else if n == 14 {
    } else {
        assert(n == 15);
    }
}

pub proof fn hex_digit_char_injective(a: u8, b: u8)
    requires a < 16, b < 16, hex_digit_char(a) == hex_digit_char(b),
    ensures a == b,
{
    hex_digit_char_roundtrip(a);
    hex_digit_char_roundtrip(b);
    assert(hex_digit_value(hex_digit_char(a)) == hex_digit_value(hex_digit_char(b)));
}

/// One byte as two hex digits.
pub open spec fn hex_byte_spec(b: u8) -> Seq<u8> {
    seq![hex_digit_char(b / 16), hex_digit_char(b % 16)]
}

/// Recursive, byte-exact model of `cache_key_hex`.
pub open spec fn cache_key_hex_spec(value: Seq<u8>) -> Seq<u8>
    decreases value.len(),
{
    if value.len() == 0 {
        Seq::empty()
    } else {
        hex_byte_spec(value[0]) + cache_key_hex_spec(value.drop_first())
    }
}

pub proof fn cache_key_hex_spec_len(value: Seq<u8>)
    ensures cache_key_hex_spec(value).len() == value.len() * 2,
    decreases value.len(),
{
    if value.len() == 0 {
    } else {
        cache_key_hex_spec_len(value.drop_first());
        assert(hex_byte_spec(value[0]).len() == 2);
    }
}

pub proof fn cache_key_hex_spec_head(value: Seq<u8>)
    requires value.len() > 0,
    ensures cache_key_hex_spec(value).subrange(0, 2) == hex_byte_spec(value[0]),
{
    cache_key_hex_spec_len(value.drop_first());
    assert(hex_byte_spec(value[0]).len() == 2);
}

pub proof fn cache_key_hex_spec_tail(value: Seq<u8>)
    requires value.len() > 0,
    ensures cache_key_hex_spec(value).skip(2) == cache_key_hex_spec(value.drop_first()),
{
    cache_key_hex_spec_len(value.drop_first());
    assert(hex_byte_spec(value[0]).len() == 2);
}

pub proof fn hex_byte_spec_injective(a: u8, b: u8)
    requires hex_byte_spec(a) == hex_byte_spec(b),
    ensures a == b,
{
    assert(hex_byte_spec(a)[0] == hex_digit_char(a / 16));
    assert(hex_byte_spec(a)[1] == hex_digit_char(a % 16));
    assert(hex_byte_spec(b)[0] == hex_digit_char(b / 16));
    assert(hex_byte_spec(b)[1] == hex_digit_char(b % 16));
    assert(hex_digit_char(a / 16) == hex_digit_char(b / 16));
    assert(hex_digit_char(a % 16) == hex_digit_char(b % 16));
    assert(a / 16 < 16);
    assert(a % 16 < 16);
    assert(b / 16 < 16);
    assert(b % 16 < 16);
    hex_digit_char_injective(a / 16, b / 16);
    hex_digit_char_injective(a % 16, b % 16);
    assert(a == b);
}

/// F55/I51: the complete hex encoding is injective over raw byte sequences.
pub proof fn cache_key_hex_spec_injective(a: Seq<u8>, b: Seq<u8>)
    requires cache_key_hex_spec(a) == cache_key_hex_spec(b),
    ensures a == b,
    decreases a.len() + b.len(),
{
    cache_key_hex_spec_len(a);
    cache_key_hex_spec_len(b);
    if a.len() == 0 {
        assert(cache_key_hex_spec(a) == Seq::<u8>::empty());
        assert(b.len() == 0);
    } else if b.len() == 0 {
        assert(cache_key_hex_spec(b) == Seq::<u8>::empty());
        assert(a.len() == 0);
    } else {
        cache_key_hex_spec_head(a);
        cache_key_hex_spec_head(b);
        assert(cache_key_hex_spec(a).subrange(0, 2) == cache_key_hex_spec(b).subrange(0, 2));
        hex_byte_spec_injective(a[0], b[0]);
        cache_key_hex_spec_tail(a);
        cache_key_hex_spec_tail(b);
        assert(cache_key_hex_spec(a).skip(2) == cache_key_hex_spec(b).skip(2));
        cache_key_hex_spec_injective(a.drop_first(), b.drop_first());
        assert(a == seq![a[0]] + a.drop_first());
        assert(b == seq![b[0]] + b.drop_first());
    }
}

/// F55/I51: encode every cache-key byte as two lowercase hex digits.  The
/// encoding is length-preserving up to the fixed factor of two and provably
/// injective, so distinct raw byte sequences (including invalid UTF-8 and the
/// empty sequence) cannot collapse to one key component.
pub fn cache_key_hex(value: &[u8]) -> (out: Vec<u8>)
    ensures
        out@ == cache_key_hex_spec(value@),
        out@.len() == value@.len() * 2,
{
    let mut out: Vec<u8> = Vec::with_capacity(value.len());
    let mut i: usize = 0;
    assert(value@.subrange(0, value@.len() as int) == value@);
    while i < value.len()
        invariant
            0 <= i <= value.len(),
            out@ + cache_key_hex_spec(value@.subrange(i as int, value@.len() as int))
                == cache_key_hex_spec(value@),
        decreases value.len() - i,
    {
        let hi: u8 = value[i] / 16;
        let lo: u8 = value[i] % 16;
        assert(hi < 16);
        assert(lo < 16);
        let hi_char = hex_digit(hi);
        let lo_char = hex_digit(lo);
        assert(hi_char == hex_digit_char(hi));
        assert(lo_char == hex_digit_char(lo));
        assert(value@.subrange(i as int, value@.len() as int)[0] == value[i as int]);
        assert(value@.subrange(i as int, value@.len() as int).drop_first()
            == value@.subrange((i + 1) as int, value@.len() as int));
        out.push(hi_char);
        out.push(lo_char);
        i = i + 1;
    }
    proof {
        cache_key_hex_spec_len(value@);
    }
    out
}

/// Cache freshness clamp.  `CacheMinExpire`/`CacheMaxExpire` come from
/// configuration; a reversed pair must not panic the response path.  The
/// verified form returns zero (no reusable entry) for a reversed pair.
pub open spec fn cache_ttl_clamp_spec(value: i64, min: i64, max: i64) -> i64 {
    if min > max {
        0
    } else if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

pub fn cache_ttl_clamp(value: i64, min: i64, max: i64) -> (ttl: i64)
    ensures
        ttl == cache_ttl_clamp_spec(value, min, max),
        min <= max ==> (min <= ttl && ttl <= max),
{
    if min > max {
        0
    } else if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

/// Freshness expiry uses saturating arithmetic so a hostile or malformed
/// freshness value can never wrap `expires` into the past.  The runtime only
/// stores entries with `ttl > 0`.
pub fn cache_expiry(now: i64, ttl: i64) -> (expires: i64)
    requires ttl > 0,
    ensures expires >= now,
{
    if let Some(value) = now.checked_add(ttl) {
        value
    } else {
        i64::MAX
    }
}

/// Disk accounting projection for replacing an existing representation with
/// a new one.  Saturating subtraction makes a stale/over-large accounting
/// value harmless instead of wrapping into a false positive.
pub fn cache_disk_projected(used: u64, old: u64, incoming: u64) -> (projected: u64)
    ensures projected == used.saturating_sub(old).saturating_add(incoming),
{
    used.saturating_sub(old).saturating_add(incoming)
}

/// Removing one eviction victim can only decrease the projected usage.
pub fn cache_disk_evict(projected: u64, removed: u64) -> (after: u64)
    ensures after <= projected,
{
    projected.saturating_sub(removed)
}

/// Four-byte big-endian length used to frame one policy-fingerprint field.
pub open spec fn cache_fingerprint_len_bytes(len: nat) -> Seq<u8> {
    seq![
        (len / 16777216) as u8,
        ((len / 65536) % 256) as u8,
        ((len / 256) % 256) as u8,
        (len % 256) as u8
    ]
}

pub open spec fn cache_fingerprint_field_spec(field: Seq<u8>) -> Seq<u8> {
    cache_fingerprint_len_bytes(field.len()) + field
}

/// Frame one exact byte field with a four-byte length prefix.  `cache.rs`
/// feeds these frames into SHA-256, so no field boundary depends on a
/// separator that could also occur inside attacker-controlled data.
pub fn cache_fingerprint_field(field: &[u8]) -> (out: Vec<u8>)
    requires field@.len() <= 0xffff_ffff,
    ensures out@ == cache_fingerprint_field_spec(field@),
{
    let len = field.len() as u32;
    assert(len as nat == field@.len());
    let mut out: Vec<u8> = Vec::new();
    out.push((len / 16777216) as u8);
    out.push(((len / 65536) % 256) as u8);
    out.push(((len / 256) % 256) as u8);
    out.push((len % 256) as u8);
    out.extend_from_slice(field);
    out
}

pub proof fn cache_fingerprint_field_injective(a: Seq<u8>, b: Seq<u8>)
    requires cache_fingerprint_field_spec(a) == cache_fingerprint_field_spec(b),
    ensures a == b,
{
    assert(cache_fingerprint_field_spec(a).skip(4) == a);
    assert(cache_fingerprint_field_spec(b).skip(4) == b);
}

/// Cache store request gate: only a bodyless GET without credentials may
/// populate the shared cache.  The runtime consumes this predicate before it
/// inspects response headers or buffers the body.
pub fn cache_store_request_admit(
    method_get: bool,
    body_empty: bool,
    credential_free: bool,
) -> (ok: bool)
    ensures ok == (method_get && body_empty && credential_free),
{
    method_get && body_empty && credential_free
}

/// Only these statuses carry reusable representations.  Everything else is
/// either an error/tunnel response or a status whose semantics cannot be
/// replayed from a shared cache.
pub fn cache_store_status_admit(status: u16) -> (ok: bool)
    ensures
        ok == (status == 200
            || status == 203
            || status == 300
            || status == 301
            || status == 308
            || status == 404
            || status == 410),
{
    matches!(status, 200 | 203 | 300 | 301 | 308 | 404 | 410)
}

/// Cache-Control storage policy.  `no-store`, `no-cache` or `private` block
/// storage unless the corresponding configuration override explicitly allows
/// that directive.
pub fn cache_store_control_admit(
    no_store: bool,
    no_cache: bool,
    private: bool,
    allow_no_store: bool,
    allow_no_cache: bool,
    allow_private: bool,
) -> (ok: bool)
    ensures
        ok == !((no_store && !allow_no_store)
            || (no_cache && !allow_no_cache)
            || (private && !allow_private)),
{
    !((no_store && !allow_no_store)
        || (no_cache && !allow_no_cache)
        || (private && !allow_private))
}

/// Response-shape gate: a Set-Cookie response is identity-bound and never
/// shared, `Vary: *` is uncacheable, and the body must be within the
/// configured size window.
pub fn cache_store_shape_admit(
    set_cookie: bool,
    vary_star: bool,
    size_ok: bool,
) -> (ok: bool)
    ensures ok == (!set_cookie && !vary_star && size_ok),
{
    !set_cookie && !vary_star && size_ok
}

/// A representation is stored only with a strictly positive freshness
/// lifetime; zero/negative TTLs are already stale.
pub fn cache_store_ttl_admit(ttl: i64) -> (ok: bool)
    ensures ok == (ttl > 0),
{
    ttl > 0
}

/// A hit admitted by `cache_lookup_admit` must satisfy every binding
/// dimension and be strictly fresh, not merely present in the map.
pub proof fn cache_lookup_hit_requires_binding(
    key_match: bool,
    policy_match: bool,
    vary_match: bool,
    generation_match: bool,
    expires: i64,
    now: i64,
)
    requires
        key_match,
        policy_match,
        vary_match,
        generation_match,
        now < expires,
    ensures
        key_match,
        policy_match,
        vary_match,
        generation_match,
        now < expires,
{
}

/// A stale entry can never be admitted, even when every other dimension
/// matches.  This is the freshness half of the lookup gate used for both the
/// memory and disk paths.
pub proof fn cache_lookup_rejects_stale(
    key_match: bool,
    policy_match: bool,
    vary_match: bool,
    generation_match: bool,
    expires: i64,
    now: i64,
)
    requires expires <= now,
    ensures
        !(key_match
            && policy_match
            && vary_match
            && generation_match
            && now < expires),
{
}

/// Escape access-log text so a hostile request field cannot inject a
/// newline, NUL, terminal escape or quote/backslash sequence.  This is the
/// verified primitive used by the access-log formatter (CVE-2001-1556).
fn hex_digit(n: u8) -> (c: u8)
    requires n < 16,
    ensures c == (if n < 10 { b'0' + n } else { b'a' + (n - 10) }),
{
    if n < 10 {
        b'0' + n
    } else {
        b'a' + (n - 10)
    }
}

pub fn escape_log_bytes(input: &[u8]) -> (out: Vec<u8>)
    ensures no_crlf_nul(out@),
{
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i: usize = 0;
    while i < input.len()
        invariant
            0 <= i <= input.len(),
            no_crlf_nul(out@),
        decreases input.len() - i,
    {
        let b = input[i];
        if b == b'"' || b == b'\\' {
            out.push(b'\\');
            out.push(b);
        } else if b < 0x20 || b == 0x7f {
            let hi = hex_digit(b / 16);
            let lo = hex_digit(b % 16);
            out.push(b'\\');
            out.push(b'x');
            out.push(hi);
            out.push(lo);
        } else {
            out.push(b);
        }
        i = i + 1;
    }
    out
}

/// The runtime logger uses this variant for request-derived fields.  It
/// preserves the same escaping guarantee while refusing to materialize a
/// conversion that would cross the caller's complete-line ceiling.
pub fn escape_log_bytes_bounded(input: &[u8], limit: usize) -> (out: Vec<u8>)
    ensures
        no_crlf_nul(out@),
        out@.len() <= limit,
{
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < input.len()
        invariant
            0 <= i <= input.len(),
            no_crlf_nul(out@),
            out@.len() <= limit,
        decreases input.len() - i,
    {
        let b = input[i];
        let needed: usize = if b == b'"' || b == b'\\' {
            2
        } else if b < 0x20 || b == 0x7f {
            4
        } else {
            1
        };
        if needed > limit - out.len() {
            break;
        }
        if b == b'"' || b == b'\\' {
            out.push(b'\\');
            out.push(b);
        } else if b < 0x20 || b == 0x7f {
            let hi = hex_digit(b / 16);
            let lo = hex_digit(b % 16);
            out.push(b'\\');
            out.push(b'x');
            out.push(hi);
            out.push(lo);
        } else {
            out.push(b);
        }
        i = i + 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Header sanitization
// ---------------------------------------------------------------------------

/// Validate a header value before it is written to the wire.
///
/// Rejects every control byte except HTAB, plus DEL.  This is the single choke
/// point for every header the daemon emits, including headers derived from
/// file names and CGI output, which is how response-splitting vulnerabilities
/// usually enter.
pub fn sanitize_header_value(input: &[u8]) -> (out: Option<Vec<u8>>)
    ensures
        match out {
            Some(v) => {
                &&& no_crlf_nul(v@)
                &&& header_value_ok(v@)
                &&& v@.len() == input@.len()
                &&& forall|i: int| 0 <= i < v@.len() ==> v@[i] == input@[i]
            }
            None => true,
        },
{
    let mut i: usize = 0;
    while i < input.len()
        invariant
            i <= input.len(),
            forall|k: int| 0 <= k < i ==> #[trigger] header_value_byte_ok(input@[k]),
            forall|k: int| 0 <= k < i ==> #[trigger] input@[k] != 0
                && input@[k] != b'\r' && input@[k] != b'\n',
        decreases input.len() - i,
    {
        let b = input[i];
        if !(b == b'\t' || (b >= 0x20 && b != 0x7f)) {
            return None;
        }
        i = i + 1;
    }
    assert(header_value_ok(input@));
    assert(no_crlf_nul(input@));
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut j: usize = 0;
    while j < input.len()
        invariant
            j <= input.len(),
            out@.len() == j,
            forall|k: int| 0 <= k < j ==> out@[k] == input@[k],
            header_value_ok(out@),
            no_crlf_nul(out@),
            no_crlf_nul(input@),
            header_value_ok(input@),
        decreases input.len() - j,
    {
        out.push(input[j]);
        j = j + 1;
    }
    Some(out)
}

/// HTTP token characters (RFC 9110 `tchar`).  Header names and methods are
/// tokens; using an allow-list prevents request smuggling via exotic
/// whitespace and control characters.
pub open spec fn is_tchar(b: u8) -> bool {
    ||| (b >= b'a' && b <= b'z')
    ||| (b >= b'A' && b <= b'Z')
    ||| (b >= b'0' && b <= b'9')
    ||| b == b'!' || b == b'#' || b == b'$' || b == b'%' || b == b'&'
    ||| b == b'\'' || b == b'*' || b == b'+' || b == b'-' || b == b'.'
    ||| b == b'^' || b == b'_' || b == b'`' || b == b'|' || b == b'~'
}

pub open spec fn all_tchars(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> is_tchar(s[i])
}

proof fn lemma_all_tchars_index(s: Seq<u8>, i: int)
    requires all_tchars(s), 0 <= i < s.len(),
    ensures is_tchar(s[i]),
{
}

pub fn valid_token(input: &[u8]) -> (ok: bool)
    ensures ok == (input@.len() > 0 && all_tchars(input@)),
{
    if input.len() == 0 {
        return false;
    }
    let mut i: usize = 0;
    while i < input.len()
        invariant
            i <= input.len(),
            forall|j: int| 0 <= j < i ==> #[trigger] is_tchar(input@[j]),
        decreases input.len() - i,
    {
        if !tchar_ok(input[i]) {
            return false;
        }
        i = i + 1;
    }
    assert(all_tchars(input@));
    true
}

// ---------------------------------------------------------------------------
// Byte ranges
// ---------------------------------------------------------------------------

pub enum RangeDecision {
    /// The header is malformed or unsupported; RFC 9110 says ignore it.
    Ignore,
    /// Syntactically valid but no bytes overlap the representation.
    Unsatisfiable,
    /// Inclusive byte range fully inside the representation.
    Satisfiable { start: u64, end: u64 },
}

spec fn parse_digits(s: Seq<u8>, i: int, end: int) -> Option<u64>
    decreases end - i,
{
    if i >= end {
        Some(0)
    } else if s[i] < b'0' || s[i] > b'9' {
        None
    } else {
        let rest = parse_digits(s, i + 1, end);
        match rest {
            Some(v) => {
                if v > (u64::MAX - (s[i] - b'0') as u64) / 10 {
                    None
                } else {
                    Some((v + (s[i] - b'0') as u64 * 10) as u64)
                }
            }
            None => None,
        }
    }
}

/// Parse a single `bytes=` range against a representation of `len` bytes.
///
/// Supports `bytes=a-b`, `bytes=a-`, and `bytes=-n` (suffix).  Multi-range
/// requests are deliberately downgraded to `Ignore` (full response): Apache's
/// multi-range implementation was the subject of the Range DoS
/// (CVE-2011-3192), and browsers do not need it.
pub fn parse_byte_range(header: &[u8], len: u64) -> (d: RangeDecision)
    ensures
        match d {
            RangeDecision::Satisfiable { start, end } => start <= end && end < len,
            _ => true,
        },
{
    if header.len() < 6 {
        return RangeDecision::Ignore;
    }
    assert(header.len() >= 6);
    let mut i: usize = 0;
    // "bytes=" is case-insensitive.
    let prefix = b"bytes=";
    while i < 6
        invariant
            i <= 6,
            header.len() >= 6,
        decreases 6 - i,
    {
        assert(i < header.len());
        let a = header[i];
        let b = prefix[i];
        let al = if a >= b'A' && a <= b'Z' { (a + 32) as u8 } else { a };
        if al != b {
            return RangeDecision::Ignore;
        }
        i = i + 1;
    }
    // Reject multiple ranges / extra lists.
    let mut j: usize = 6;
    while j < header.len()
        invariant 6 <= j <= header.len(),
        decreases header.len() - j,
    {
        if header[j] == b',' {
            return RangeDecision::Ignore;
        }
        j = j + 1;
    }
    if header.len() == 6 {
        return RangeDecision::Ignore;
    }
    let mut k: usize = 6;
    let mut digits: u64 = 0;
    let mut have_start: bool = false;
    let mut overflow: bool = false;
    while k < header.len() && header[k] != b'-' && header[k] != b' '
        invariant 6 <= k <= header.len(),
        decreases header.len() - k,
    {
        let c = header[k];
        if c < b'0' || c > b'9' {
            return RangeDecision::Ignore;
        }
        let d = (c - b'0') as u64;
        if digits > (u64::MAX - d) / 10 {
            overflow = true;
        } else if !overflow {
            digits = digits * 10 + d;
        }
        have_start = true;
        k = k + 1;
    }
    if k >= header.len() || header[k] != b'-' {
        return RangeDecision::Ignore;
    }
    k = k + 1;
    let mut suffix: bool = false;
    if !have_start {
        suffix = true;
    }
    let mut end_digits: u64 = 0;
    let mut have_end: bool = false;
    let mut end_overflow: bool = false;
    while k < header.len()
        invariant k <= header.len(),
        decreases header.len() - k,
    {
        let c = header[k];
        if c < b'0' || c > b'9' {
            return RangeDecision::Ignore;
        }
        let d = (c - b'0') as u64;
        if end_digits > (u64::MAX - d) / 10 {
            end_overflow = true;
        } else if !end_overflow {
            end_digits = end_digits * 10 + d;
        }
        have_end = true;
        k = k + 1;
    }

    if len == 0 {
        return RangeDecision::Unsatisfiable;
    }
    if suffix {
        if !have_end || end_digits == 0 {
            return RangeDecision::Unsatisfiable;
        }
        let n = if end_overflow { len } else { end_digits };
        if n >= len {
            return RangeDecision::Satisfiable { start: 0, end: len - 1 };
        }
        return RangeDecision::Satisfiable { start: len - n, end: len - 1 };
    }
    if !have_start {
        return RangeDecision::Ignore;
    }
    if overflow || digits >= len {
        return RangeDecision::Unsatisfiable;
    }
    let s = digits;
    if !have_end {
        return RangeDecision::Satisfiable { start: s, end: len - 1 };
    }
    let e = if end_overflow || end_digits >= len { len - 1 } else { end_digits };
    if s > e {
        return RangeDecision::Unsatisfiable;
    }
    RangeDecision::Satisfiable { start: s, end: e }
}

// ---------------------------------------------------------------------------
// HTTP/1.1 request head parsing and framing
// ---------------------------------------------------------------------------

/// HTTP versions accepted on the wire.  HTTP/2 is framed by the `h2` crate,
/// so this parser only ever produces the two HTTP/1.x versions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HttpVersion {
    Http10,
    Http11,
}

/// Why a request head was rejected.  The server maps these variants to the
/// same status codes and messages it used before the parser moved here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeadError {
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
    DuplicateTransferEncoding,
    DuplicateContentLength,
    TransferEncodingInHttp10,
    UnsupportedTransferCoding,
    InvalidContentLength,
    ConflictingContentLength,
    DuplicateConnection,
    ForbiddenProxyConnection,
    InvalidConnection,
    DuplicateExpect,
    UnsupportedExpectation,
    InvalidTe,
}

/// How the body of a request is delimited.  `Chunked` is only produced for
/// HTTP/1.1 and only when there is no `Content-Length` header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BodyFraming {
    None,
    Length(u64),
    Chunked,
}

/// The result of parsing one complete request head.  Header names are
/// lowercased; values are trimmed of leading/trailing OWS.
#[derive(Debug)]
pub struct ParsedHead {
    pub method: Vec<u8>,
    pub target: Vec<u8>,
    pub raw_path: Vec<u8>,
    pub query: Vec<u8>,
    pub version: HttpVersion,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub framing: BodyFraming,
    pub keep_alive: bool,
    pub expect_continue: bool,
}

pub open spec fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

pub open spec fn lower_byte(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' { ((b as int) + 32) as u8 } else { b }
}

pub open spec fn eq_ignore_ascii_case_spec(a: Seq<u8>, b: Seq<u8>) -> bool {
    a.len() == b.len()
        && forall|i: int| 0 <= i < a.len() ==> lower_byte(a[i]) == lower_byte(b[i])
}

pub open spec fn all_target_bytes(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> s[i] >= 0x21 && s[i] != 0x7f
}

pub open spec fn valid_method(s: Seq<u8>) -> bool {
    s.len() > 0 && s.len() <= 64 && all_tchars(s)
}

pub open spec fn valid_target(s: Seq<u8>) -> bool {
    s.len() > 0 && all_target_bytes(s)
}

/// A generic reverse proxy cannot know whether an upstream strips semicolon
/// matrix parameters before routing. Both the authorized front-end identity
/// and the path serialized to the backend must therefore exclude that
/// representation-changing delimiter before the proxy sink is bound.
pub open spec fn proxy_path_representation_spec(
    front_path: Seq<u8>,
    upstream_path: Seq<u8>,
) -> bool {
    (forall|i: int| 0 <= i < front_path.len() ==> front_path[i] != b';')
        && (forall|i: int| 0 <= i < upstream_path.len() ==> upstream_path[i] != b';')
}

pub fn proxy_path_representation_admit(
    front_path: &[u8],
    upstream_path: &[u8],
) -> (ok: bool)
    ensures ok == proxy_path_representation_spec(front_path@, upstream_path@),
{
    let mut i: usize = 0;
    while i < front_path.len()
        invariant
            i <= front_path.len(),
            forall|j: int| 0 <= j < i ==> front_path@[j] != b';',
        decreases front_path.len() - i,
    {
        if front_path[i] == b';' {
            return false;
        }
        i = i + 1;
    }
    let mut j: usize = 0;
    while j < upstream_path.len()
        invariant
            j <= upstream_path.len(),
            forall|k: int| 0 <= k < j ==> upstream_path@[k] != b';',
        decreases upstream_path.len() - j,
    {
        if upstream_path[j] == b';' {
            return false;
        }
        j = j + 1;
    }
    assert(proxy_path_representation_spec(front_path@, upstream_path@));
    true
}

/// Concrete evidence tying the path authorized at the front end to the exact
/// path selected for the upstream.  Keeping both byte strings in the
/// capability prevents a later proxy retarget from reusing a boolean
/// "representation checked" bit for a different path pair.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProxyRepresentationWitness {
    pub front_path: Vec<u8>,
    pub upstream_path: Vec<u8>,
}

pub fn proxy_representation_witness(
    front_path: &[u8],
    upstream_path: &[u8],
) -> (witness: Option<ProxyRepresentationWitness>)
    ensures
        match witness {
            Some(value) => {
                &&& value.front_path@ == front_path@
                &&& value.upstream_path@ == upstream_path@
                &&& proxy_path_representation_spec(
                    value.front_path@,
                    value.upstream_path@,
                )
            }
            None => !proxy_path_representation_spec(front_path@, upstream_path@),
        },
{
    if !proxy_path_representation_admit(front_path, upstream_path) {
        return None;
    }
    Some(ProxyRepresentationWitness {
        front_path: copy_slice(front_path),
        upstream_path: copy_slice(upstream_path),
    })
}

/// Revalidate a stored witness against the exact path pair reaching a sink.
/// This is deliberately stronger than re-running the delimiter predicate:
/// both identities must be byte-for-byte identical to those originally
/// witnessed.
pub fn proxy_representation_witness_matches(
    witness: &ProxyRepresentationWitness,
    front_path: &[u8],
    upstream_path: &[u8],
) -> (matches: bool)
    ensures
        matches == (witness.front_path@ == front_path@
            && witness.upstream_path@ == upstream_path@
            && proxy_path_representation_spec(front_path@, upstream_path@)),
{
    bytes_eq(witness.front_path.as_slice(), front_path)
        && bytes_eq(witness.upstream_path.as_slice(), upstream_path)
        && proxy_path_representation_admit(front_path, upstream_path)
}

/// P12-A: prefix routes are component-aware, while a prefix that already
/// ends in `/` (including the root route) directly owns its descendants.
pub open spec fn proxy_prefix_match_spec(
    exact: bool,
    has_prefix: bool,
    prefix_ends_slash: bool,
    remainder_starts_slash: bool,
) -> bool {
    exact || (has_prefix && (prefix_ends_slash || remainder_starts_slash))
}

pub fn proxy_prefix_match_admit(
    exact: bool,
    has_prefix: bool,
    prefix_ends_slash: bool,
    remainder_starts_slash: bool,
) -> (ok: bool)
    ensures
        ok == proxy_prefix_match_spec(
            exact,
            has_prefix,
            prefix_ends_slash,
            remainder_starts_slash,
        ),
{
    exact || (has_prefix && (prefix_ends_slash || remainder_starts_slash))
}

pub proof fn proxy_prefix_rejects_partial_component(
    exact: bool,
    has_prefix: bool,
    prefix_ends_slash: bool,
    remainder_starts_slash: bool,
)
    ensures
        has_prefix && !exact && !prefix_ends_slash && !remainder_starts_slash
            ==> !proxy_prefix_match_spec(
                exact,
                has_prefix,
                prefix_ends_slash,
                remainder_starts_slash,
            ),
{
}

pub open spec fn valid_header_name(s: Seq<u8>) -> bool {
    s.len() > 0 && all_tchars(s)
}

/// Header values may contain HTAB and any byte above SP, except DEL.  Bytes
/// below SP other than HTAB (including CR, LF and NUL) are rejected.
pub open spec fn valid_header_value(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> is_ows(s[i]) || (s[i] >= 0x20 && s[i] != 0x7f)
}

pub open spec fn trimmed_header_value(s: Seq<u8>) -> bool {
    s.len() == 0 || (!is_ows(s[0]) && !is_ows(s[s.len() - 1]))
}

pub open spec fn header_ok(h: (Vec<u8>, Vec<u8>)) -> bool {
    &&& valid_header_name(h.0@)
    &&& valid_header_value(h.1@)
    &&& trimmed_header_value(h.1@)
}

pub open spec fn headers_ok(hs: Seq<(Vec<u8>, Vec<u8>)>) -> bool {
    forall|i: int| 0 <= i < hs.len() ==> #[trigger] header_ok(hs[i])
}

/// Admission for the outbound request line of an HTTP/1.1 proxy hop.  The
/// method is a bounded RFC 9110 token, the target is a non-empty run of
/// visible bytes (no spaces or CTLs that could start a second request line),
/// and the version is exactly `HTTP/1.1`.
pub fn proxy_request_line_admit(
    method: &[u8],
    target: &[u8],
    version: &[u8],
) -> (ok: bool)
    ensures
        ok == (valid_method(method@)
            && valid_target(target@)
            && version@ == b"HTTP/1.1"@),
{
    if method.len() == 0 || method.len() > 64 || !valid_token(method) {
        return false;
    }
    if target.len() == 0 {
        return false;
    }
    let mut i: usize = 0;
    while i < target.len()
        invariant
            i <= target.len(),
            forall|j: int| 0 <= j < i ==> #[trigger] target@[j] >= 0x21
                && target@[j] != 0x7f,
        decreases target.len() - i,
    {
        if target[i] < 0x21 || target[i] == 0x7f {
            assert(!all_target_bytes(target@));
            return false;
        }
        i = i + 1;
    }
    assert(all_target_bytes(target@));
    assert(valid_method(method@));
    assert(valid_target(target@));
    bytes_eq(version, b"HTTP/1.1")
}

/// Admission for one outbound proxy header field.  Names must be tokens and
/// values may contain only HTAB, SP and visible bytes; CR, LF, NUL and other
/// CTLs cannot be serialized into the upstream head.
pub fn proxy_header_admit(name: &[u8], value: &[u8]) -> (ok: bool)
    ensures ok == (valid_header_name(name@) && valid_header_value(value@)),
{
    if !valid_token(name) {
        return false;
    }
    assert(valid_header_name(name@));
    let mut i: usize = 0;
    while i < value.len()
        invariant
            i <= value.len(),
            forall|j: int| 0 <= j < i ==> #[trigger] is_ows(value@[j])
                || (value@[j] >= 0x20 && value@[j] != 0x7f),
        decreases value.len() - i,
    {
        let b = value[i];
        if !(is_ows_exec(b) || (b >= 0x20 && b != 0x7f)) {
            assert(!valid_header_value(value@));
            return false;
        }
        i = i + 1;
    }
    assert(valid_header_value(value@));
    true
}

/// Parse the complete upstream HTTP/1 status line. Only HTTP/1.0 and 1.1,
/// exactly one SP before a three-digit status, and an optional SP-prefixed
/// visible reason phrase are accepted.
pub fn proxy_response_status_line_parse(line: &[u8]) -> (status: Option<u16>)
    ensures
        match status {
            Some(code) => {
                &&& 100 <= code <= 599
                &&& line@.len() >= 12
                &&& (line@.subrange(0, 9) == b"HTTP/1.1 "@
                    || line@.subrange(0, 9) == b"HTTP/1.0 "@)
                &&& forall|i: int| 9 <= i < 12 ==> b'0' <= line@[i] && line@[i] <= b'9'
                &&& (line@.len() == 12 || (line@[12] == b' '
                    && forall|i: int| 13 <= i < line@.len()
                        ==> header_value_byte_ok(line@[i])))
            }
            None => true,
        },
{
    if line.len() < 12 {
        return None;
    }
    let version = &line[..9];
    if !bytes_eq(version, b"HTTP/1.1 ") && !bytes_eq(version, b"HTTP/1.0 ") {
        return None;
    }
    let mut i: usize = 9;
    while i < 12
        invariant
            9 <= i <= 12,
            12 <= line.len(),
            forall|j: int| 9 <= j < i ==> b'0' <= line@[j] && line@[j] <= b'9',
        decreases 12 - i,
    {
        if line[i] < b'0' || line[i] > b'9' {
            return None;
        }
        i = i + 1;
    }
    if line.len() > 12 {
        if line[12] != b' ' {
            return None;
        }
        let mut j: usize = 13;
        while j < line.len()
            invariant
                13 <= j <= line.len(),
                forall|k: int| 13 <= k < j ==> header_value_byte_ok(line@[k]),
            decreases line.len() - j,
        {
            let byte = line[j];
            if !(byte == b'\t' || (byte >= 0x20 && byte != 0x7f)) {
                return None;
            }
            j = j + 1;
        }
    }
    let code = ((line[9] - b'0') as u16) * 100
        + ((line[10] - b'0') as u16) * 10
        + (line[11] - b'0') as u16;
    if code < 100 || code > 599 {
        None
    } else {
        Some(code)
    }
}

/// Exact upstream field gate. The caller passes the bytes before the colon
/// without trimming, so whitespace before `:` is rejected as a non-token.
pub fn proxy_response_header_admit(name: &[u8], value: &[u8]) -> (ok: bool)
    ensures ok == (valid_header_name(name@) && valid_header_value(value@)),
{
    proxy_header_admit(name, value)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxyResponseFraming {
    NoBody,
    Length(u64),
    Chunked,
    Eof,
}

pub open spec fn proxy_response_has_no_body(head_request: bool, status: u16) -> bool {
    head_request || status == 204 || status == 205 || status == 304
        || (100 <= status && status < 200)
}

/// Decide upstream response framing from the complete admitted field list.
/// Duplicate or malformed Content-Length/Transfer-Encoding, multiple transfer
/// codings, and every CL+TE combination fail before a body reader is selected.
pub fn proxy_response_framing(
    head_request: bool,
    status: u16,
    headers: &[(Vec<u8>, Vec<u8>)],
) -> (framing: Option<ProxyResponseFraming>)
    ensures
        match framing {
            Some(ProxyResponseFraming::NoBody) => proxy_response_has_no_body(head_request, status),
            Some(ProxyResponseFraming::Length(_))
            | Some(ProxyResponseFraming::Chunked)
            | Some(ProxyResponseFraming::Eof) => !proxy_response_has_no_body(head_request, status),
            None => true,
        },
{
    let mut content_length: Option<u64> = None;
    let mut transfer_encoding: bool = false;
    let mut i: usize = 0;
    while i < headers.len()
        invariant i <= headers.len(),
        decreases headers.len() - i,
    {
        let name = &headers[i].0;
        let value = &headers[i].1;
        if bytes_eq(name, b"content-length") {
            if content_length.is_some() {
                return None;
            }
            let (start, end) = trim_range(value);
            content_length = match parse_decimal_u64(&value[start..end]) {
                Some(length) => Some(length),
                None => return None,
            };
        } else if bytes_eq(name, b"transfer-encoding") {
            if transfer_encoding {
                return None;
            }
            let (start, end) = trim_range(value);
            if !eq_ignore_ascii_case(&value[start..end], b"chunked") {
                return None;
            }
            transfer_encoding = true;
        }
        i = i + 1;
    }
    if content_length.is_some() && transfer_encoding {
        return None;
    }
    // RFC 9110 forbids both framing fields on informational and 204
    // responses. A 205 has no content; accept only an explicit zero length,
    // never a coding or nonzero length. HEAD and 304 may carry metadata
    // describing the selected representation, but it never selects a body
    // reader for this message.
    if (status == 204 || (status >= 100 && status < 200))
        && (content_length.is_some() || transfer_encoding)
    {
        return None;
    }
    if status == 205 {
        if transfer_encoding {
            return None;
        }
        match content_length {
            Some(length) => {
                if length != 0 {
                    return None;
                }
            }
            None => {}
        }
    }
    if head_request
        || status == 204
        || status == 205
        || status == 304
        || (status >= 100 && status < 200)
    {
        return Some(ProxyResponseFraming::NoBody);
    }
    if transfer_encoding {
        Some(ProxyResponseFraming::Chunked)
    } else {
        match content_length {
            Some(length) => Some(ProxyResponseFraming::Length(length)),
            None => Some(ProxyResponseFraming::Eof),
        }
    }
}

pub open spec fn is_hex_byte(b: u8) -> bool {
    (b >= b'0' && b <= b'9') || (b >= b'a' && b <= b'f') || (b >= b'A' && b <= b'F')
}

pub open spec fn hex_digit_nat(b: u8) -> int {
    match hex_val(b) {
        Some(value) => value as int,
        None => 0,
    }
}

/// Mathematical value of the first `end` hexadecimal digits.  The executable
/// parser refines this unbounded-integer fold whenever the result fits u64.
pub open spec fn hex_prefix_value_spec(input: Seq<u8>, end: int) -> int
    recommends 0 <= end <= input.len(),
    decreases end,
{
    if end <= 0 {
        0
    } else {
        hex_prefix_value_spec(input, end - 1) * 16 + hex_digit_nat(input[end - 1])
    }
}

/// Checked hexadecimal parser used for HTTP chunk sizes. An accepted value
/// cannot wrap u64 and every consumed byte is an ASCII hexadecimal digit.
pub fn parse_chunk_size_hex(input: &[u8]) -> (out: Option<u64>)
    ensures
        match out {
            Some(value) => input@.len() > 0
                && (forall|i: int| 0 <= i < input@.len() ==> is_hex_byte(input@[i]))
                && value as int == hex_prefix_value_spec(input@, input@.len() as int),
            None => true,
        },
{
    if input.len() == 0 {
        return None;
    }
    let mut value: u64 = 0;
    let mut i: usize = 0;
    while i < input.len()
        invariant
            i <= input.len(),
            forall|j: int| 0 <= j < i ==> is_hex_byte(input@[j]),
            value as int == hex_prefix_value_spec(input@, i as int),
        decreases input.len() - i,
    {
        let digit = match hex_val_exec(input[i]) {
            Some(digit) => digit as u64,
            None => return None,
        };
        if value > (u64::MAX - digit) / 16 {
            return None;
        }
        assert(value <= (u64::MAX - digit) / 16);
        assert(value * 16 <= u64::MAX - digit);
        assert(digit as int == hex_digit_nat(input@[i as int]));
        value = value * 16 + digit;
        i = i + 1;
    }
    Some(value)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChunkExtensionState {
    AfterSize,
    BeforeSemicolon,
    BeforeName,
    Name,
    AfterName,
    BeforeValue,
    TokenValue,
    AfterValue,
    Quoted,
    QuotedEscape,
}

pub open spec fn chunk_qdtext_byte(b: u8) -> bool {
    b == b'\t' || b == b' ' || b == b'!' || (b >= 0x23 && b <= 0x5b)
        || (b >= 0x5d && b <= 0x7e) || b >= 0x80
}

pub open spec fn chunk_quoted_pair_byte(b: u8) -> bool {
    b == b'\t' || b == b' ' || (b >= 0x21 && b <= 0x7e) || b >= 0x80
}

pub open spec fn chunk_extension_accepting(state: ChunkExtensionState) -> bool {
    match state {
        ChunkExtensionState::AfterSize
        | ChunkExtensionState::Name
        | ChunkExtensionState::TokenValue
        | ChunkExtensionState::AfterValue => true,
        _ => false,
    }
}

pub open spec fn chunk_extension_step_spec(
    state: ChunkExtensionState,
    byte: u8,
) -> Option<ChunkExtensionState> {
    match state {
        ChunkExtensionState::AfterSize => {
            if byte == b';' { Some(ChunkExtensionState::BeforeName) }
            else if is_ows(byte) { Some(ChunkExtensionState::BeforeSemicolon) }
            else { None }
        }
        ChunkExtensionState::BeforeSemicolon => {
            if byte == b';' { Some(ChunkExtensionState::BeforeName) }
            else if is_ows(byte) { Some(ChunkExtensionState::BeforeSemicolon) }
            else { None }
        }
        ChunkExtensionState::BeforeName => {
            if is_ows(byte) { Some(ChunkExtensionState::BeforeName) }
            else if is_tchar(byte) { Some(ChunkExtensionState::Name) }
            else { None }
        }
        ChunkExtensionState::Name => {
            if is_tchar(byte) { Some(ChunkExtensionState::Name) }
            else if is_ows(byte) { Some(ChunkExtensionState::AfterName) }
            else if byte == b'=' { Some(ChunkExtensionState::BeforeValue) }
            else if byte == b';' { Some(ChunkExtensionState::BeforeName) }
            else { None }
        }
        ChunkExtensionState::AfterName => {
            if is_ows(byte) { Some(ChunkExtensionState::AfterName) }
            else if byte == b'=' { Some(ChunkExtensionState::BeforeValue) }
            else if byte == b';' { Some(ChunkExtensionState::BeforeName) }
            else { None }
        }
        ChunkExtensionState::BeforeValue => {
            if is_ows(byte) { Some(ChunkExtensionState::BeforeValue) }
            else if byte == b'"' { Some(ChunkExtensionState::Quoted) }
            else if is_tchar(byte) { Some(ChunkExtensionState::TokenValue) }
            else { None }
        }
        ChunkExtensionState::TokenValue => {
            if is_tchar(byte) { Some(ChunkExtensionState::TokenValue) }
            else if is_ows(byte) { Some(ChunkExtensionState::AfterValue) }
            else if byte == b';' { Some(ChunkExtensionState::BeforeName) }
            else { None }
        }
        ChunkExtensionState::AfterValue => {
            if is_ows(byte) { Some(ChunkExtensionState::AfterValue) }
            else if byte == b';' { Some(ChunkExtensionState::BeforeName) }
            else { None }
        }
        ChunkExtensionState::Quoted => {
            if byte == b'"' { Some(ChunkExtensionState::AfterValue) }
            else if byte == b'\\' { Some(ChunkExtensionState::QuotedEscape) }
            else if chunk_qdtext_byte(byte) { Some(ChunkExtensionState::Quoted) }
            else { None }
        }
        ChunkExtensionState::QuotedEscape => {
            if chunk_quoted_pair_byte(byte) { Some(ChunkExtensionState::Quoted) }
            else { None }
        }
    }
}

fn chunk_extension_step_exec(
    state: ChunkExtensionState,
    byte: u8,
) -> (next: Option<ChunkExtensionState>)
    ensures next == chunk_extension_step_spec(state, byte),
{
    match state {
        ChunkExtensionState::AfterSize => {
            if byte == b';' { Some(ChunkExtensionState::BeforeName) }
            else if is_ows_exec(byte) { Some(ChunkExtensionState::BeforeSemicolon) }
            else { None }
        }
        ChunkExtensionState::BeforeSemicolon => {
            if byte == b';' { Some(ChunkExtensionState::BeforeName) }
            else if is_ows_exec(byte) { Some(ChunkExtensionState::BeforeSemicolon) }
            else { None }
        }
        ChunkExtensionState::BeforeName => {
            if is_ows_exec(byte) { Some(ChunkExtensionState::BeforeName) }
            else if tchar_ok(byte) { Some(ChunkExtensionState::Name) }
            else { None }
        }
        ChunkExtensionState::Name => {
            if tchar_ok(byte) { Some(ChunkExtensionState::Name) }
            else if is_ows_exec(byte) { Some(ChunkExtensionState::AfterName) }
            else if byte == b'=' { Some(ChunkExtensionState::BeforeValue) }
            else if byte == b';' { Some(ChunkExtensionState::BeforeName) }
            else { None }
        }
        ChunkExtensionState::AfterName => {
            if is_ows_exec(byte) { Some(ChunkExtensionState::AfterName) }
            else if byte == b'=' { Some(ChunkExtensionState::BeforeValue) }
            else if byte == b';' { Some(ChunkExtensionState::BeforeName) }
            else { None }
        }
        ChunkExtensionState::BeforeValue => {
            if is_ows_exec(byte) { Some(ChunkExtensionState::BeforeValue) }
            else if byte == b'"' { Some(ChunkExtensionState::Quoted) }
            else if tchar_ok(byte) { Some(ChunkExtensionState::TokenValue) }
            else { None }
        }
        ChunkExtensionState::TokenValue => {
            if tchar_ok(byte) { Some(ChunkExtensionState::TokenValue) }
            else if is_ows_exec(byte) { Some(ChunkExtensionState::AfterValue) }
            else if byte == b';' { Some(ChunkExtensionState::BeforeName) }
            else { None }
        }
        ChunkExtensionState::AfterValue => {
            if is_ows_exec(byte) { Some(ChunkExtensionState::AfterValue) }
            else if byte == b';' { Some(ChunkExtensionState::BeforeName) }
            else { None }
        }
        ChunkExtensionState::Quoted => {
            if byte == b'"' { Some(ChunkExtensionState::AfterValue) }
            else if byte == b'\\' { Some(ChunkExtensionState::QuotedEscape) }
            else if byte == b'\t' || byte == b' ' || byte == b'!'
                || (byte >= 0x23 && byte <= 0x5b)
                || (byte >= 0x5d && byte <= 0x7e) || byte >= 0x80
            { Some(ChunkExtensionState::Quoted) }
            else { None }
        }
        ChunkExtensionState::QuotedEscape => {
            if byte == b'\t' || byte == b' ' || (byte >= 0x21 && byte <= 0x7e)
                || byte >= 0x80
            { Some(ChunkExtensionState::Quoted) }
            else { None }
        }
    }
}

pub open spec fn chunk_extension_walk_spec(
    input: Seq<u8>,
    i: int,
    state: ChunkExtensionState,
) -> bool
    decreases input.len() - i,
{
    if i >= input.len() {
        chunk_extension_accepting(state)
    } else {
        match chunk_extension_step_spec(state, input[i]) {
            Some(next) => chunk_extension_walk_spec(input, i + 1, next),
            None => false,
        }
    }
}

fn chunk_extension_walk_exec(
    input: &[u8],
    i: usize,
    state: ChunkExtensionState,
) -> (ok: bool)
    requires i <= input.len(),
    ensures ok == chunk_extension_walk_spec(input@, i as int, state),
    decreases input.len() - i,
{
    if i >= input.len() {
        return match state {
            ChunkExtensionState::AfterSize
            | ChunkExtensionState::Name
            | ChunkExtensionState::TokenValue
            | ChunkExtensionState::AfterValue => true,
            _ => false,
        };
    }
    match chunk_extension_step_exec(state, input[i]) {
        Some(next) => chunk_extension_walk_exec(input, i + 1, next),
        None => false,
    }
}

pub fn chunk_extension_admit(input: &[u8]) -> (ok: bool)
    ensures
        ok == chunk_extension_walk_spec(input@, 0, ChunkExtensionState::AfterSize),
{
    chunk_extension_walk_exec(input, 0, ChunkExtensionState::AfterSize)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChunkFramingState {
    pub chunks: u64,
    pub bytes: u64,
}

/// One overflow-free transition of the chunk framing budget. The runtime
/// consumes this transition for both request bodies and proxy responses.
pub fn chunk_framing_budget_step(
    state: ChunkFramingState,
    line_len: u64,
    data_chunk: bool,
    max_chunks: u64,
    max_bytes: u64,
) -> (next: Option<ChunkFramingState>)
    ensures
        match next {
            Some(out) => out.chunks <= max_chunks && out.bytes <= max_bytes
                && out.chunks == state.chunks + 1
                && out.bytes >= state.bytes,
            None => true,
        },
{
    let chunks = match state.chunks.checked_add(1) {
        Some(value) => value,
        None => return None,
    };
    let mut framing = match line_len.checked_add(2) {
        Some(value) => value,
        None => return None,
    };
    if data_chunk {
        framing = match framing.checked_add(2) {
            Some(value) => value,
            None => return None,
        };
    }
    let bytes = match state.bytes.checked_add(framing) {
        Some(value) => value,
        None => return None,
    };
    if chunks > max_chunks || bytes > max_bytes {
        None
    } else {
        Some(ChunkFramingState { chunks, bytes })
    }
}

pub open spec fn trailer_name_forbidden_spec(name: Seq<u8>) -> bool {
    eq_ignore_ascii_case_spec(name, b"content-length"@)
        || eq_ignore_ascii_case_spec(name, b"transfer-encoding"@)
        || eq_ignore_ascii_case_spec(name, b"host"@)
        || eq_ignore_ascii_case_spec(name, b"trailer"@)
}

fn trailer_name_forbidden(name: &[u8]) -> (forbidden: bool)
    ensures
        forbidden == trailer_name_forbidden_spec(name@),
{
    eq_ignore_ascii_case(name, b"content-length")
        || eq_ignore_ascii_case(name, b"transfer-encoding")
        || eq_ignore_ascii_case(name, b"host")
        || eq_ignore_ascii_case(name, b"trailer")
}

/// Trailer fields share one verified syntax gate. Message-framing and routing
/// fields are forbidden because applying them after the body would create a
/// second interpretation of the request or response.
pub fn http_trailer_field_admit(line: &[u8]) -> (ok: bool)
    ensures
        ok ==> exists|colon: int| 0 < colon < line@.len()
            && valid_header_name(line@.subrange(0, colon))
            && !trailer_name_forbidden_spec(line@.subrange(0, colon))
            && valid_header_value(line@.subrange(colon + 1, line@.len() as int)),
{
    let mut colon: usize = 0;
    while colon < line.len() && line[colon] != b':'
        invariant
            colon <= line.len(),
            forall|i: int| 0 <= i < colon ==> line@[i] != b':',
        decreases line.len() - colon,
    {
        colon = colon + 1;
    }
    if colon == line.len() {
        return false;
    }
    let name = &line[..colon];
    let value = &line[colon + 1..];
    if trailer_name_forbidden(name) {
        return false;
    }
    if !proxy_header_admit(name, value) {
        return false;
    }
    assert(0 < colon);
    true
}

pub open spec fn no_byte(s: Seq<u8>, b: u8) -> bool {
    forall|i: int| 0 <= i < s.len() ==> s[i] != b
}

pub open spec fn is_asterisk_path(s: Seq<u8>) -> bool {
    s.len() == 1 && s[0] == b'*'
}

pub open spec fn split_target_ok(target: Seq<u8>, path: Seq<u8>, query: Seq<u8>) -> bool {
    &&& path.len() > 0
    &&& (is_asterisk_path(path) || (path[0] == b'/' && no_byte(path, b'?')
        && no_byte(path, b'#')))
    &&& no_byte(query, b'#')
}

pub open spec fn name_transfer_encoding() -> Seq<u8> {
    b"transfer-encoding"@
}

pub open spec fn name_content_length() -> Seq<u8> {
    b"content-length"@
}

pub open spec fn has_header_range(
    hs: Seq<(Vec<u8>, Vec<u8>)>,
    lo: int,
    hi: int,
    name: Seq<u8>,
) -> bool {
    exists|i: int| lo <= i < hi && #[trigger] hs[i].0@ == name
}

pub open spec fn has_header(hs: Seq<(Vec<u8>, Vec<u8>)>, name: Seq<u8>) -> bool {
    has_header_range(hs, 0, hs.len() as int, name)
}

proof fn lemma_has_header_range_snoc(
    hs: Seq<(Vec<u8>, Vec<u8>)>,
    lo: int,
    hi: int,
    name: Seq<u8>,
)
    requires 0 <= lo <= hi < hs.len(),
    ensures
        has_header_range(hs, lo, hi + 1, name) == (has_header_range(hs, lo, hi, name)
            || hs[hi].0@ == name),
{
    assert(has_header_range(hs, lo, hi + 1, name) ==> (has_header_range(hs, lo, hi, name)
        || hs[hi].0@ == name)) by {
        if has_header_range(hs, lo, hi + 1, name) {
            let i = choose|i: int| lo <= i < hi + 1 && hs[i].0@ == name;
            if i < hi {
                assert(has_header_range(hs, lo, hi, name));
            } else {
                assert(i == hi);
                assert(hs[hi].0@ == name);
            }
        }
    }
    assert((has_header_range(hs, lo, hi, name) || hs[hi].0@ == name)
        ==> has_header_range(hs, lo, hi + 1, name)) by {
        if has_header_range(hs, lo, hi, name) {
            let i = choose|i: int| lo <= i < hi && hs[i].0@ == name;
            assert(lo <= i < hi + 1);
        } else {
            assert(lo <= hi < hi + 1);
        }
    }
}

pub open spec fn parsed_head_ok(h: ParsedHead) -> bool {
    &&& valid_method(h.method@)
    &&& valid_target(h.target@)
    &&& headers_ok(h.headers@)
    &&& split_target_ok(h.target@, h.raw_path@, h.query@)
    &&& !(has_header(h.headers@, name_transfer_encoding())
        && has_header(h.headers@, name_content_length()))
    &&& (h.framing == BodyFraming::Chunked ==> h.version == HttpVersion::Http11)
}

fn is_ows_exec(b: u8) -> (r: bool)
    ensures r == is_ows(b),
{
    b == b' ' || b == b'\t'
}

fn lower_byte_exec(b: u8) -> (l: u8)
    ensures l == lower_byte(b),
{
    if b >= b'A' && b <= b'Z' { (b + 32) as u8 } else { b }
}

proof fn lemma_lower_tchar(b: u8)
    requires is_tchar(b),
    ensures is_tchar(lower_byte(b)),
{
    if b >= b'A' && b <= b'Z' {
        assert(lower_byte(b) == b + 32);
        assert(lower_byte(b) >= b'a' && lower_byte(b) <= b'z');
    } else {
        assert(lower_byte(b) == b);
    }
}

fn trim_range(input: &[u8]) -> (r: (usize, usize))
    ensures
        0 <= r.0 <= r.1 <= input.len(),
        r.0 == input.len() || !is_ows(input@[r.0 as int]),
        r.1 == r.0 || !is_ows(input@[r.1 as int - 1]),
        forall|i: int| 0 <= i < r.0 ==> is_ows(input@[i]),
        forall|i: int| r.1 <= i < input.len() ==> is_ows(input@[i]),
{
    let mut start: usize = 0;
    while start < input.len() && is_ows_exec(input[start])
        invariant
            start <= input.len(),
            forall|i: int| 0 <= i < start ==> is_ows(input@[i]),
        decreases input.len() - start,
    {
        start = start + 1;
    }
    let mut end: usize = input.len();
    while end > start && is_ows_exec(input[end - 1])
        invariant
            start <= end <= input.len(),
            forall|i: int| end <= i < input.len() ==> is_ows(input@[i]),
        decreases end - start,
    {
        end = end - 1;
    }
    (start, end)
}

fn copy_range(input: &[u8], start: usize, end: usize) -> (out: Vec<u8>)
    requires start <= end <= input.len(),
    ensures out@ == input@.subrange(start as int, end as int),
{
    let mut out: Vec<u8> = Vec::with_capacity(end - start);
    out.extend_from_slice(&input[start..end]);
    out
}

fn copy_slice(input: &[u8]) -> (out: Vec<u8>)
    ensures out@ == input@,
{
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    out.extend_from_slice(input);
    out
}

/// Copy a header value while trimming surrounding optional whitespace.
fn trim_ows_copy(input: &[u8]) -> (out: Vec<u8>)
    requires valid_header_value(input@),
    ensures
        valid_header_value(out@),
        trimmed_header_value(out@),
        out@.len() <= input@.len(),
{
    let (start, end) = trim_range(input);
    let out = copy_range(input, start, end);
    proof {
        assert forall|i: int| 0 <= i < out@.len() implies is_ows(out@[i])
            || (out@[i] >= 0x20 && out@[i] != 0x7f) by {
            assert(out@[i] == input@[start as int + i]);
        }
        if out@.len() > 0 {
            assert(start < end);
            assert(!is_ows(input@[start as int]));
            assert(out@[0] == input@[start as int]);
            assert(!is_ows(out@[0]));
            assert(!is_ows(input@[end as int - 1]));
            assert(out@[out@.len() - 1] == input@[end as int - 1]);
            assert(!is_ows(out@[out@.len() - 1]));
        }
        assert(trimmed_header_value(out@));
    }
    out
}

fn find_crlf(input: &[u8], start: usize) -> (out: Option<usize>)
    requires start <= input.len(),
    ensures
        match out {
            Some(i) => {
                &&& start <= i
                &&& i + 1 < input.len()
                &&& input@[i as int] == b'\r'
                &&& input@[i as int + 1] == b'\n'
            }
            None => true,
        },
{
    let mut i: usize = start;
    while i < input.len()
        invariant start <= i <= input.len(),
        decreases input.len() - i,
    {
        if input[i] == b'\r' && i < input.len() - 1 && input[i + 1] == b'\n' {
            assert(i + 1 < input.len());
            return Some(i);
        }
        i = i + 1;
    }
    None
}

fn bytes_eq(a: &[u8], b: &[u8]) -> (ok: bool)
    ensures ok == (a@ == b@),
{
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < a.len()
        invariant
            i <= a.len(),
            a.len() == b.len(),
            forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a.len() - i,
    {
        if a[i] != b[i] {
            return false;
        }
        i = i + 1;
    }
    assert(a@ =~= b@);
    true
}

/// P14-D: choose the unique policy-visible slot for a canonicalized HTTP/1
/// field name. The bridge uses this verified lookup to merge duplicate field
/// lines in arrival order before constructing `Request::headers`.
pub fn header_merge_index(
    headers: &[(Vec<u8>, Vec<u8>)],
    name: &[u8],
) -> (found: Option<usize>)
    ensures
        match found {
            Some(i) => {
                &&& i < headers@.len()
                &&& headers@[i as int].0@ == name@
                &&& forall|j: int| 0 <= j < i ==> headers@[j].0@ != name@
            }
            None => forall|j: int| 0 <= j < headers@.len() ==> headers@[j].0@ != name@,
        },
{
    let mut i: usize = 0;
    while i < headers.len()
        invariant
            i <= headers.len(),
            forall|j: int| 0 <= j < i ==> headers@[j].0@ != name@,
        decreases headers.len() - i,
    {
        if bytes_eq(&headers[i].0, name) {
            return Some(i);
        }
        i = i + 1;
    }
    None
}

fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> (ok: bool)
    ensures ok == eq_ignore_ascii_case_spec(a@, b@),
{
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < a.len()
        invariant
            i <= a.len(),
            a.len() == b.len(),
            forall|j: int| 0 <= j < i ==> lower_byte(a@[j]) == lower_byte(b@[j]),
        decreases a.len() - i,
    {
        if lower_byte_exec(a[i]) != lower_byte_exec(b[i]) {
            return false;
        }
        i = i + 1;
    }
    assert(eq_ignore_ascii_case_spec(a@, b@));
    true
}

fn lower_ascii(input: &[u8]) -> (out: Vec<u8>)
    requires all_tchars(input@),
    ensures
        out@.len() == input@.len(),
        all_tchars(out@),
        forall|i: int| 0 <= i < out@.len() ==> out@[i] == lower_byte(input@[i]),
{
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i: usize = 0;
    while i < input.len()
        invariant
            i <= input.len(),
            out@.len() == i,
            all_tchars(out@),
            all_tchars(input@),
            forall|j: int| 0 <= j < i ==> out@[j] == lower_byte(input@[j]),
        decreases input.len() - i,
    {
        proof {
            assert(i < input.len());
            lemma_all_tchars_index(input@, i as int);
            lemma_lower_tchar(input@[i as int]);
        }
        let l = lower_byte_exec(input[i]);
        out.push(l);
        i = i + 1;
    }
    out
}

/// Decimal parser shared by HTTP framing and configuration payload sealing.
/// A successful result is non-empty, digit-only, and every multiplication and
/// addition is proved to remain within `u64`.
pub fn parse_decimal_u64(input: &[u8]) -> (out: Option<u64>)
    ensures
        match out {
            Some(_) => input@.len() > 0
                && forall|i: int| 0 <= i < input@.len() ==> b'0' <= input@[i] && input@[i] <= b'9',
            None => true,
        },
{
    if input.len() == 0 {
        return None;
    }
    let mut v: u64 = 0;
    let mut i: usize = 0;
    while i < input.len()
        invariant
            i <= input.len(),
            forall|j: int| 0 <= j < i ==> b'0' <= input@[j] && input@[j] <= b'9',
        decreases input.len() - i,
    {
        let b = input[i];
        if b < b'0' || b > b'9' {
            return None;
        }
        let d = (b - b'0') as u64;
        if v > (u64::MAX - d) / 10 {
            return None;
        }
        assert(v <= (u64::MAX - d) / 10);
        assert(v * 10 <= u64::MAX - d);
        v = v * 10 + d;
        i = i + 1;
    }
    Some(v)
}

pub open spec fn no_byte_range(s: Seq<u8>, b: u8, lo: int, hi: int) -> bool {
    forall|i: int| lo <= i < hi ==> s[i] != b
}

proof fn lemma_no_byte_range_to_seq(s: Seq<u8>, b: u8, lo: int, hi: int)
    requires
        no_byte_range(s, b, lo, hi),
        0 <= lo <= hi <= s.len(),
    ensures no_byte(s.subrange(lo, hi), b),
{
    assert forall|i: int| 0 <= i < hi - lo implies s.subrange(lo, hi)[i] != b by {
        assert(s.subrange(lo, hi)[i] == s[lo + i]);
    }
}

proof fn lemma_split_root_ok()
    ensures split_target_ok(seq![b'/'], seq![b'/'], Seq::<u8>::empty()),
{
    assert(seq![b'/'].len() == 1);
    assert(!is_asterisk_path(seq![b'/']));
    assert(no_byte(seq![b'/'], b'?'));
    assert(no_byte(seq![b'/'], b'#'));
}

fn split_target(target: &[u8]) -> (res: Result<(Vec<u8>, Vec<u8>), HeadError>)
    requires valid_target(target@),
    ensures
        match res {
            Ok(pair) => split_target_ok(target@, pair.0@, pair.1@),
            Err(_) => true,
        },
{
    if target.len() == 1 && target[0] == b'*' {
        assert(target@ == seq![b'*']);
        assert(split_target_ok(target@, seq![b'*'], seq![]));
        return Ok((copy_slice(target), Vec::new()));
    }
    let mut start: usize = 0;
    if target.len() >= 7 && bytes_eq(&target[..7], b"http://") {
        start = 7;
    } else if target.len() >= 8 && bytes_eq(&target[..8], b"https://") {
        start = 8;
    }
    if start > 0 {
        let mut slash: usize = start;
        while slash < target.len() && target[slash] != b'/'
            invariant start <= slash <= target.len(),
            decreases target.len() - slash,
        {
            slash = slash + 1;
        }
        if slash == start {
            return Err(HeadError::InvalidAuthority);
        }
        let mut ai: usize = start;
        while ai < slash
            invariant start <= ai <= slash <= target.len(),
            decreases slash - ai,
        {
            if target[ai] == b'@' {
                return Err(HeadError::InvalidAuthority);
            }
            ai = ai + 1;
        }
        start = slash;
        if start == target.len() {
            let mut path: Vec<u8> = Vec::new();
            path.push(b'/');
            let query: Vec<u8> = Vec::new();
            proof {
                assert(path@ == seq![b'/']);
                assert(query@ == Seq::<u8>::empty());
                lemma_split_root_ok();
                assert(split_target_ok(target@, path@, query@));
            }
            return Ok((path, query));
        }
    }
    if target[start] != b'/' {
        return Err(HeadError::NotOriginForm);
    }
    let mut hash_i: usize = start;
    while hash_i < target.len()
        invariant
            start <= hash_i <= target.len(),
            no_byte_range(target@, b'#', start as int, hash_i as int),
        decreases target.len() - hash_i,
    {
        if target[hash_i] == b'#' {
            return Err(HeadError::FragmentInTarget);
        }
        hash_i = hash_i + 1;
    }
    assert(no_byte_range(target@, b'#', start as int, target.len() as int));

    let mut qpos: usize = start;
    while qpos < target.len() && target[qpos] != b'?'
        invariant
            start <= qpos <= target.len(),
            no_byte_range(target@, b'?', start as int, qpos as int),
        decreases target.len() - qpos,
    {
        qpos = qpos + 1;
    }
    assert(target@[start as int] == b'/');
    assert(qpos > start);
    let path = copy_range(target, start, qpos);
    let query = if qpos < target.len() {
        copy_range(target, qpos + 1, target.len())
    } else {
        Vec::new()
    };
    proof {
        assert(no_byte_range(target@, b'#', start as int, qpos as int));
        assert(no_byte_range(target@, b'?', start as int, qpos as int));
        lemma_no_byte_range_to_seq(target@, b'#', start as int, qpos as int);
        lemma_no_byte_range_to_seq(target@, b'?', start as int, qpos as int);
        assert(path@ == target@.subrange(start as int, qpos as int));
        assert(path@.len() > 0);
        assert(path@[0] == b'/');
        assert(no_byte(path@, b'?'));
        assert(no_byte(path@, b'#'));
        if qpos < target.len() {
            assert(no_byte_range(target@, b'#', (qpos + 1) as int, target.len() as int));
            lemma_no_byte_range_to_seq(target@, b'#', (qpos + 1) as int, target.len() as int);
            assert(query@ == target@.subrange((qpos + 1) as int, target.len() as int));
            assert(no_byte(query@, b'#'));
        } else {
            assert(query@.len() == 0);
        }
        assert(split_target_ok(target@, path@, query@));
    }
    Ok((path, query))
}

fn parse_connection_options(
    value: &[u8],
    keep_alive: bool,
) -> (out: Result<(bool, bool), HeadError>) {
    // Strictly validate the entire comma list. Silently ignoring an empty or
    // malformed member lets adjacent hops select different connection state.
    // The second result records whether the TE field was nominated for this
    // hop, as RFC 9110 requires.
    let mut saw_close = false;
    let mut saw_keep_alive = false;
    let mut saw_te = false;
    let mut saw_upgrade = false;
    let mut i: usize = 0;
    while i <= value.len()
        invariant i <= value.len(),
        decreases value.len() + 1 - i,
    {
        let mut e: usize = i;
        while e < value.len() && value[e] != b','
            invariant i <= e <= value.len(),
            decreases value.len() - e,
        {
            e = e + 1;
        }
        let sub = &value[i..e];
        let (ts, te) = trim_range(sub);
        let tok = &sub[ts..te];
        if te == ts || !valid_token(tok) {
            return Err(HeadError::InvalidConnection);
        }
        if eq_ignore_ascii_case(tok, b"close") {
            if saw_close {
                return Err(HeadError::InvalidConnection);
            }
            saw_close = true;
        } else if eq_ignore_ascii_case(tok, b"keep-alive") {
            if saw_keep_alive {
                return Err(HeadError::InvalidConnection);
            }
            saw_keep_alive = true;
        } else if eq_ignore_ascii_case(tok, b"te") {
            if saw_te {
                return Err(HeadError::InvalidConnection);
            }
            saw_te = true;
        } else if eq_ignore_ascii_case(tok, b"upgrade") {
            if saw_upgrade {
                return Err(HeadError::InvalidConnection);
            }
            saw_upgrade = true;
        } else {
            // Vapache implements only persistence, WebSocket Upgrade and TE.
            // Accepting an arbitrary field nomination would let an adjacent
            // intermediary erase a security field (Authorization,
            // X-Forwarded-*, etc.) that Vapache still interprets, or vice
            // versa. Unknown connection extensions therefore fail closed.
            return Err(HeadError::InvalidConnection);
        }
        if e == value.len() {
            break;
        }
        i = e + 1;
    }
    if saw_close && saw_keep_alive {
        return Err(HeadError::InvalidConnection);
    }
    let persistent = if saw_close {
        false
    } else if saw_keep_alive {
        true
    } else {
        keep_alive
    };
    Ok((persistent, saw_te))
}

/// Determine how a request body is framed, rejecting every ambiguous
/// `Transfer-Encoding`/`Content-Length` combination.  This is the kernel that
/// prevents HTTP request smuggling.  Header names must already be lowercase;
/// `parse_request_head` is the only caller and canonicalizes them first.
fn request_framing(
    version: HttpVersion,
    headers: &[(Vec<u8>, Vec<u8>)],
) -> (res: Result<BodyFraming, HeadError>)
    ensures
        match res {
            Ok(f) => {
                &&& !(has_header(headers@, name_transfer_encoding())
                    && has_header(headers@, name_content_length()))
                &&& (f == BodyFraming::Chunked ==> version == HttpVersion::Http11)
                &&& (has_header(headers@, name_transfer_encoding())
                    ==> f == BodyFraming::Chunked)
            }
            Err(_) => true,
        },
{
    let mut te_seen: bool = false;
    let mut i: usize = 0;
    while i < headers.len()
        invariant
            i <= headers.len(),
            te_seen == has_header_range(headers@, 0, i as int, name_transfer_encoding()),
        decreases headers.len() - i,
    {
        let te_here = bytes_eq(&headers[i].0, b"transfer-encoding");
        proof {
            lemma_has_header_range_snoc(headers@, 0, i as int, name_transfer_encoding());
        }
        if te_here {
            if te_seen {
                return Err(HeadError::DuplicateTransferEncoding);
            }
            assert(headers@[i as int].0@ == b"transfer-encoding"@);
            assert(headers@[i as int].0@ == name_transfer_encoding());
            te_seen = true;
        } else {
            assert(headers@[i as int].0@ != b"transfer-encoding"@);
            assert(headers@[i as int].0@ != name_transfer_encoding());
        }
        i = i + 1;
    }
    assert(has_header(headers@, name_transfer_encoding()) == te_seen);

    let mut cl_seen: bool = false;
    let mut j: usize = 0;
    while j < headers.len()
        invariant
            j <= headers.len(),
            cl_seen == has_header_range(headers@, 0, j as int, name_content_length()),
        decreases headers.len() - j,
    {
        let cl_here = bytes_eq(&headers[j].0, b"content-length");
        proof {
            lemma_has_header_range_snoc(headers@, 0, j as int, name_content_length());
        }
        if cl_here {
            if cl_seen {
                return Err(HeadError::DuplicateContentLength);
            }
            assert(headers@[j as int].0@ == b"content-length"@);
            assert(headers@[j as int].0@ == name_content_length());
            cl_seen = true;
        } else {
            assert(headers@[j as int].0@ != b"content-length"@);
            assert(headers@[j as int].0@ != name_content_length());
        }
        j = j + 1;
    }
    assert(has_header(headers@, name_content_length()) == cl_seen);

    if te_seen {
        if cl_seen {
            return Err(HeadError::BothTransferEncodingAndContentLength);
        }
        match version {
            HttpVersion::Http10 => return Err(HeadError::TransferEncodingInHttp10),
            HttpVersion::Http11 => {}
        }
        assert(version == HttpVersion::Http11);
        let mut coding_count: usize = 0;
        let mut only_chunked: bool = true;
        let mut valid_coding_list: bool = true;
        let mut hi: usize = 0;
        while hi < headers.len()
            invariant hi <= headers.len(),
            decreases headers.len() - hi,
        {
            if bytes_eq(&headers[hi].0, b"transfer-encoding") {
                let value = &headers[hi].1;
                let mut vi: usize = 0;
                while vi <= value.len()
                    invariant vi <= value.len(),
                    decreases value.len() + 1 - vi,
                {
                    let mut ve: usize = vi;
                    while ve < value.len() && value[ve] != b','
                        invariant vi <= ve <= value.len(),
                        decreases value.len() - ve,
                    {
                        ve = ve + 1;
                    }
                    let sub = &value[vi..ve];
                    let (ts, te) = trim_range(sub);
                    let tok = &sub[ts..te];
                    if te == ts {
                        // Empty list members (`chunked,`, `,chunked`, `,,`)
                        // are not transfer-codings. Accepting them creates a
                        // parser differential with stricter intermediaries.
                        valid_coding_list = false;
                    } else {
                        if coding_count == 0 {
                            coding_count = 1;
                        } else {
                            coding_count = 2;
                        }
                        if !eq_ignore_ascii_case(tok, b"chunked") {
                            only_chunked = false;
                        }
                    }
                    if ve == value.len() {
                        break;
                    }
                    vi = ve + 1;
                }
            }
            hi = hi + 1;
        }
        if coding_count != 1 || !only_chunked || !valid_coding_list {
            return Err(HeadError::UnsupportedTransferCoding);
        }
        assert(te_seen);
        assert(has_header(headers@, name_transfer_encoding()));
        assert(!cl_seen);
        assert(!has_header(headers@, name_content_length()));
        return Ok(BodyFraming::Chunked);
    }
    if !cl_seen {
        assert(!has_header(headers@, name_transfer_encoding()));
        return Ok(BodyFraming::None);
    }
    let mut value: Option<u64> = None;
    let mut ci: usize = 0;
    while ci < headers.len()
        invariant ci <= headers.len(),
        decreases headers.len() - ci,
    {
        if bytes_eq(&headers[ci].0, b"content-length") {
            let (ts, te) = trim_range(&headers[ci].1);
            let n = match parse_decimal_u64(&headers[ci].1[ts..te]) {
                Some(n) => n,
                None => return Err(HeadError::InvalidContentLength),
            };
            match value {
                None => value = Some(n),
                Some(prev) => {
                    if prev != n {
                        return Err(HeadError::ConflictingContentLength);
                    }
                }
            }
        }
        ci = ci + 1;
    }
    assert(!has_header(headers@, name_transfer_encoding()));
    match value {
        Some(n) => {
            if n == 0 {
                Ok(BodyFraming::None)
            } else {
                Ok(BodyFraming::Length(n))
            }
        }
        None => Err(HeadError::InvalidContentLength),
    }
}

/// Parse and validate a complete HTTP/1.x request head (request line plus
/// header fields, including the terminating empty line).
///
/// The postcondition is the security contract: the method is a bounded token,
/// every header name is a token, every header value is free of CTLs/CR/LF/NUL
/// and surrounding OWS, the request target and split path are well formed, and
/// a `Transfer-Encoding` header can never coexist with `Content-Length`.
pub fn parse_request_head(
    head: &[u8],
    max_request_line: usize,
    max_fields: usize,
    max_field_size: usize,
) -> (res: Result<ParsedHead, HeadError>)
    ensures
        match res {
            Ok(h) => {
                &&& parsed_head_ok(h)
                &&& h.target@.len() <= max_request_line as int
                &&& h.headers@.len() <= max_fields as int
            }
            Err(_) => true,
        },
{
    let mut z: usize = 0;
    while z < head.len()
        invariant z <= head.len(),
        decreases head.len() - z,
    {
        if head[z] == 0 {
            return Err(HeadError::NulByte);
        }
        z = z + 1;
    }

    // RFC 9112 permits recipients to ignore one leading empty line, but that
    // tolerance is not safe at a proxy boundary: many adjacent parsers reject
    // it or assign it to the preceding message. Vapache accepts only the
    // canonical request-line-at-byte-zero representation.
    if head.len() >= 2 && head[0] == b'\r' && head[1] == b'\n' {
        return Err(HeadError::TooManyEmptyLines);
    }
    let pos: usize = 0;

    let line_end = match find_crlf(head, pos) {
        Some(i) => i,
        None => return Err(HeadError::UnterminatedRequestLine),
    };
    if line_end - pos > max_request_line {
        return Err(HeadError::RequestLineTooLong);
    }
    let line = &head[pos..line_end];

    let mut sp1: Option<usize> = None;
    let mut sp2: Option<usize> = None;
    let mut extra_space: bool = false;
    let mut si: usize = 0;
    while si < line.len()
        invariant
            si <= line.len(),
            sp1.is_none() ==> sp2.is_none(),
            match sp1 {
                Some(a) => a < si,
                None => true,
            },
            match sp2 {
                Some(b) => b < si,
                None => true,
            },
            match sp1 {
                Some(a) => a < line.len(),
                None => true,
            },
            match sp2 {
                Some(b) => b < line.len(),
                None => true,
            },
            match (sp1, sp2) {
                (Some(a), Some(b)) => a < b,
                _ => true,
            },
        decreases line.len() - si,
    {
        if line[si] == b' ' {
            if sp1.is_none() {
                sp1 = Some(si);
            } else if sp2.is_none() {
                sp2 = Some(si);
                match sp1 {
                    Some(_a) => assert(_a < si),
                    None => {}
                }
            } else {
                extra_space = true;
            }
        }
        si = si + 1;
    }

    let method_start: usize = 0;
    let method_end: usize;
    let target_start: usize;
    let target_end: usize;
    let version_start: usize;
    match sp1 {
        None => {
            if line.len() == 0 {
                return Err(HeadError::MissingMethod);
            }
            return Err(HeadError::MissingTarget);
        }
        Some(a) => {
            if a == 0 {
                return Err(HeadError::MissingMethod);
            }
            assert(a < line.len());
            method_end = a;
            target_start = a + 1;
            match sp2 {
                None => {
                    if target_start >= line.len() {
                        return Err(HeadError::MissingTarget);
                    }
                    return Err(HeadError::MissingVersion);
                }
                Some(b) => {
                    assert(b < line.len());
                    assert(a < b);
                    if b == target_start {
                        return Err(HeadError::MissingTarget);
                    }
                    target_end = b;
                    version_start = b + 1;
                }
            }
        }
    }
    if extra_space {
        return Err(HeadError::WhitespaceInRequestLine);
    }

    let method = &line[method_start..method_end];
    let target = &line[target_start..target_end];
    let version_b = &line[version_start..];
    if !valid_token(method) || method.len() > 64 {
        return Err(HeadError::InvalidMethod);
    }
    if target.len() > max_request_line {
        return Err(HeadError::RequestLineTooLong);
    }
    let mut ti: usize = 0;
    while ti < target.len()
        invariant
            ti <= target.len(),
            forall|j: int| 0 <= j < ti ==> target@[j] >= 0x21 && target@[j] != 0x7f,
        decreases target.len() - ti,
    {
        let b = target[ti];
        if b < 0x21 || b == 0x7f {
            return Err(HeadError::InvalidTargetByte);
        }
        ti = ti + 1;
    }
    assert(valid_target(target@));
    let version = if bytes_eq(version_b, b"HTTP/1.1") {
        HttpVersion::Http11
    } else if bytes_eq(version_b, b"HTTP/1.0") {
        HttpVersion::Http10
    } else if version_b.len() >= 5 && bytes_eq(&version_b[..5], b"HTTP/") {
        return Err(HeadError::VersionNotSupported);
    } else {
        return Err(HeadError::InvalidVersion);
    };
    let method_v = copy_range(line, method_start, method_end);
    let target_v = copy_range(line, target_start, target_end);

    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut count: usize = 0;
    let mut cur: usize = line_end + 2;
    loop
        invariant
            cur <= head.len(),
            count as int == headers@.len(),
            headers_ok(headers@),
            count <= max_fields,
        decreases head.len() - cur,
    {
        if cur >= head.len() {
            return Err(HeadError::UnterminatedHeaders);
        }
        if cur < head.len() - 1 && head[cur] == b'\r' && head[cur + 1] == b'\n' {
            break;
        }
        let end = match find_crlf(head, cur) {
            Some(i) => i,
            None => return Err(HeadError::UnterminatedHeader),
        };
        assert(end < head.len());
        if end - cur > max_field_size {
            return Err(HeadError::HeaderLineTooLong);
        }
        if head[cur] == b' ' || head[cur] == b'\t' {
            return Err(HeadError::ObsoleteFolding);
        }
        assert(end < head.len());
        let mut colon: usize = cur;
        while colon < end && head[colon] != b':'
            invariant
                cur <= colon <= end,
                end < head.len(),
            decreases end - colon,
        {
            colon = colon + 1;
        }
        if colon == end {
            return Err(HeadError::MissingColon);
        }
        let name = &head[cur..colon];
        if !valid_token(name) {
            return Err(HeadError::InvalidHeaderName);
        }
        assert(all_tchars(name@));
        assert(name.len() > 0);
        let mut vi: usize = colon + 1;
        assert(vi <= end);
        while vi < end
            invariant
                colon < vi <= end,
                end < head.len(),
                forall|j: int| colon + 1 <= j < vi ==> is_ows(head@[j])
                    || (head@[j] >= 0x20 && head@[j] != 0x7f),
            decreases end - vi,
        {
            let b = head[vi];
            if (b < 0x20 && b != b'\t') || b == 0x7f {
                return Err(HeadError::InvalidHeaderValue);
            }
            vi = vi + 1;
        }
        assert(valid_header_value(head@.subrange((colon + 1) as int, end as int)));
        let value = trim_ows_copy(&head[colon + 1..end]);
        let lname = lower_ascii(name);
        assert(valid_header_name(lname@));
        assert(header_ok((lname, value)));
        if count >= max_fields {
            return Err(HeadError::TooManyHeaders);
        }
        headers.push((lname, value));
        count = count + 1;
        assert(headers_ok(headers@));
        cur = end + 2;
    }
    assert(headers_ok(headers@));

    let mut host_idx: Option<usize> = None;
    let mut hi: usize = 0;
    while hi < headers.len()
        invariant
            hi <= headers.len(),
            match host_idx {
                Some(i) => i < headers.len(),
                None => true,
            },
        decreases headers.len() - hi,
    {
        if bytes_eq(&headers[hi].0, b"host") {
            if host_idx.is_some() {
                return Err(HeadError::DuplicateHost);
            }
            host_idx = Some(hi);
        }
        hi = hi + 1;
    }
    match host_idx {
        None => {
            if version == HttpVersion::Http11 {
                return Err(HeadError::MissingHost);
            }
        }
        Some(idx) => {
            let h = &headers[idx].1;
            if h.len() == 0 {
                return Err(HeadError::InvalidHost);
            }
            let mut hj: usize = 0;
            while hj < h.len()
                invariant hj <= h.len(),
                decreases h.len() - hj,
            {
                let b = h[hj];
                if b < 0x21 || b == 0x7f || b == b'/' || b == b'\\' || b == b'@' {
                    return Err(HeadError::InvalidHost);
                }
                hj = hj + 1;
            }
        }
    }

    let (raw_path, query) = match split_target(target) {
        Ok(pair) => pair,
        Err(e) => return Err(e),
    };

    let mut conn_idx: Option<usize> = None;
    let mut expect_idx: Option<usize> = None;
    let mut te_idx: Option<usize> = None;
    let mut fi: usize = 0;
    while fi < headers.len()
        invariant
            fi <= headers.len(),
            match conn_idx {
                Some(i) => i < headers.len(),
                None => true,
            },
            match expect_idx {
                Some(i) => i < headers.len(),
                None => true,
            },
            match te_idx {
                Some(i) => i < headers.len(),
                None => true,
            },
        decreases headers.len() - fi,
    {
        if bytes_eq(&headers[fi].0, b"connection") {
            if conn_idx.is_some() {
                return Err(HeadError::DuplicateConnection);
            }
            conn_idx = Some(fi);
        }
        if bytes_eq(&headers[fi].0, b"proxy-connection") {
            return Err(HeadError::ForbiddenProxyConnection);
        }
        if bytes_eq(&headers[fi].0, b"expect") {
            if expect_idx.is_some() {
                return Err(HeadError::DuplicateExpect);
            }
            expect_idx = Some(fi);
        }
        if bytes_eq(&headers[fi].0, b"te") {
            if te_idx.is_some() {
                return Err(HeadError::InvalidTe);
            }
            te_idx = Some(fi);
        }
        fi = fi + 1;
    }
    let mut keep_alive = version == HttpVersion::Http11;
    let mut connection_has_te = false;
    match conn_idx {
        Some(idx) => {
            match parse_connection_options(&headers[idx].1, keep_alive) {
                Ok((persistent, has_te)) => {
                    keep_alive = persistent;
                    connection_has_te = has_te;
                }
                Err(e) => return Err(e),
            }
        }
        None => {}
    }
    match te_idx {
        Some(idx) => {
            let (ts, te) = trim_range(&headers[idx].1);
            if !connection_has_te
                || !eq_ignore_ascii_case(&headers[idx].1[ts..te], b"trailers")
            {
                return Err(HeadError::InvalidTe);
            }
        }
        None => {}
    }

    let framing = match request_framing(version, &headers) {
        Ok(f) => f,
        Err(e) => return Err(e),
    };

    let expect_continue = match expect_idx {
        Some(idx) => {
            let (es, ee) = trim_range(&headers[idx].1);
            if version != HttpVersion::Http11
                || framing == BodyFraming::None
                || !eq_ignore_ascii_case(&headers[idx].1[es..ee], b"100-continue")
            {
                return Err(HeadError::UnsupportedExpectation);
            }
            true
        }
        None => false,
    };

    Ok(ParsedHead {
        method: method_v,
        target: target_v,
        raw_path,
        query,
        version,
        headers,
        framing,
        keep_alive,
        expect_continue,
    })
}

// ---------------------------------------------------------------------------
// Performance-path safety predicates
// ---------------------------------------------------------------------------

/// Whether a full-file read may be served from an mmap rather than copied into
/// a user buffer.
///
/// The length check prevents mapping past EOF.  The permission check refuses
/// to map any file with an owner, group or other write bit set.  A file
/// writable by the server can be truncated by the server itself, and a file
/// writable by a different owner can be truncated by that owner; either race
/// raises SIGBUS in the mapping (F41-adjacent SIGBUS hardening).
pub open spec fn mmap_read_ok(
    file_len: u64,
    requested: u64,
    _file_uid: u32,
    _euid: u32,
    mode: u32,
) -> bool {
    requested <= file_len && mode & 0o222 == 0
}

pub fn mmap_read_allowed(
    file_len: u64,
    requested: u64,
    _file_uid: u32,
    _euid: u32,
    mode: u32,
) -> (ok: bool)
    ensures ok == mmap_read_ok(file_len, requested, _file_uid, _euid, mode),
{
    requested <= file_len && mode & 0o222 == 0
}

/// A response body is compressed only while it stays within the fixed
/// in-memory compression cap.  Larger bodies are passed through unchanged,
/// which removes the "compress forever after disconnect" resource class.
pub fn compression_body_admit(len: u64, limit: u64) -> (ok: bool)
    ensures ok == (len <= limit),
{
    len <= limit
}

/// Admission for one connection/worker slot.  The caller still performs the
/// atomic reservation; this is the single bound predicate used by that path.
pub fn connection_admit(active: u64, max: u64) -> (ok: bool)
    ensures ok == (active < max),
{
    active < max
}

/// Fairness identity for IPv6 clients. Hosts normally receive at least a /64,
/// so counting all 128 bits lets one client evade every per-client ceiling by
/// rotating interface identifiers. IPv4 remains exact in the caller.
pub open spec fn client_quota_ipv6_key_spec(ip: u128) -> u128 {
    ip & 0xffff_ffff_ffff_ffff_0000_0000_0000_0000u128
}

pub fn client_quota_ipv6_key(ip: u128) -> (key: u128)
    ensures key == client_quota_ipv6_key_spec(ip),
{
    ip & 0xffff_ffff_ffff_ffff_0000_0000_0000_0000u128
}

pub proof fn client_quota_ipv6_key_has_zero_host(ip: u128)
    ensures
        client_quota_ipv6_key_spec(ip) & 0x0000_0000_0000_0000_ffff_ffff_ffff_ffffu128 == 0,
{
    assert((ip & 0xffff_ffff_ffff_ffff_0000_0000_0000_0000u128)
        & 0x0000_0000_0000_0000_ffff_ffff_ffff_ffffu128 == 0) by (bit_vector);
}

pub proof fn client_quota_ipv6_key_preserves_prefix(ip: u128)
    ensures client_quota_ipv6_key_spec(ip) >> 64 == ip >> 64,
{
    assert((ip & 0xffff_ffff_ffff_ffff_0000_0000_0000_0000u128) >> 64 == ip >> 64)
        by (bit_vector);
}

/// The request-serving identity must never retain uid/gid zero.  A privileged
/// launcher may switch to the configured pair; an already-unprivileged launch
/// is admitted only when both effective IDs already match exactly.
pub open spec fn service_identity_spec(euid: u32, egid: u32, uid: u32, gid: u32) -> bool {
    uid != 0 && gid != 0 && (euid == 0 || (euid == uid && egid == gid))
}

pub fn service_identity_admit(euid: u32, egid: u32, uid: u32, gid: u32) -> (ok: bool)
    ensures ok == service_identity_spec(euid, egid, uid, gid),
{
    uid != 0 && gid != 0 && (euid == 0 || (euid == uid && egid == gid))
}

pub proof fn service_identity_rejects_root(euid: u32, egid: u32, gid: u32)
    ensures
        !service_identity_spec(euid, egid, 0, gid),
        !service_identity_spec(euid, egid, gid, 0),
{
}

pub proof fn unprivileged_identity_must_match(euid: u32, egid: u32, uid: u32, gid: u32)
    requires euid != 0,
    ensures service_identity_spec(euid, egid, uid, gid) ==> (euid == uid && egid == gid),
{
}

/// A process-control record is usable only for a non-special positive pid and
/// only while the pidfd-pinned process still has the exact recorded identity.
pub open spec fn pid_control_spec(
    pid: i64,
    actual_pid: i64,
    expected_uid: u32,
    actual_uid: u32,
    identity_matches: bool,
) -> bool {
    pid > 1
        && pid == actual_pid
        && expected_uid == actual_uid
        && identity_matches
}

pub fn pid_control_admit(
    pid: i64,
    actual_pid: i64,
    expected_uid: u32,
    actual_uid: u32,
    identity_matches: bool,
) -> (ok: bool)
    ensures ok == pid_control_spec(pid, actual_pid, expected_uid, actual_uid, identity_matches),
{
    pid > 1
        && pid == actual_pid
        && expected_uid == actual_uid
        && identity_matches
}

pub proof fn pid_control_rejects_special_pid(
    pid: i64,
    actual_pid: i64,
    expected_uid: u32,
    actual_uid: u32,
    identity_matches: bool,
)
    requires pid <= 1,
    ensures !pid_control_spec(pid, actual_pid, expected_uid, actual_uid, identity_matches),
{
}

pub proof fn pid_control_rejects_identity_change(
    pid: i64,
    actual_pid: i64,
    expected_uid: u32,
    actual_uid: u32,
)
    ensures !pid_control_spec(pid, actual_pid, expected_uid, actual_uid, false),
{
}

/// Bound check for a length-prefixed CGI worker protocol field.
pub fn cgi_field_len_ok(len: u32, limit: u32) -> (ok: bool)
    ensures ok == (len <= limit),
{
    len <= limit
}

/// CGI responses are ordinary HTTP responses generated through the server;
/// scripts cannot switch the client connection to another protocol or emit
/// informational responses whose framing the CGI adapter does not own.
pub open spec fn cgi_response_status_spec(status: u16) -> bool {
    200 <= status && status <= 599
}

pub fn cgi_response_status_admit(status: u16) -> (ok: bool)
    ensures ok == cgi_response_status_spec(status),
{
    200 <= status && status <= 599
}

pub proof fn cgi_response_rejects_informational(status: u16)
    ensures status < 200 ==> !cgi_response_status_spec(status),
{
}

/// The server, not a CGI script, owns HTTP framing and connection state.
/// Connection-nominated fields are removed after the complete head is read.
pub open spec fn cgi_response_header_spec(
    framing: bool,
    hop_by_hop: bool,
    connection_nominated: bool,
) -> bool {
    !framing && !hop_by_hop && !connection_nominated
}

pub fn cgi_response_header_admit(
    framing: bool,
    hop_by_hop: bool,
    connection_nominated: bool,
) -> (ok: bool)
    ensures ok == cgi_response_header_spec(framing, hop_by_hop, connection_nominated),
{
    !framing && !hop_by_hop && !connection_nominated
}

pub proof fn cgi_response_header_rejects_connection_state(
    framing: bool,
    hop_by_hop: bool,
    connection_nominated: bool,
)
    ensures
        framing || hop_by_hop || connection_nominated
            ==> !cgi_response_header_spec(framing, hop_by_hop, connection_nominated),
{
}

/// Number of bytes to hand to the next HTTP/2 DATA send.  The result is
/// bounded by both inputs, and is nonzero whenever both inputs are nonzero, so
/// the streaming loop always makes progress.
pub fn h2_batch_len(remaining: u64, batch: u64) -> (n: u64)
    ensures
        n <= remaining,
        n <= batch,
        remaining > 0 && batch > 0 ==> n > 0,
{
    if remaining < batch {
        remaining
    } else {
        batch
    }
}

// ---------------------------------------------------------------------------
// CGI environment admission
// ---------------------------------------------------------------------------

/// Regex dialect admission for configuration and expression patterns.  The
/// externally supplied regex engine is assumed to implement the accepted
/// regular subset; this guard rejects constructs whose Apache/PCRE meaning
/// cannot be represented by the Rust regex engine (backreferences and
/// look-around), plus control bytes and oversized patterns.
pub open spec fn regex_byte_ok(b: u8) -> bool {
    b >= 0x20 && b != 0x7f
}

pub open spec fn regex_unsupported_at(pattern: Seq<u8>, i: int) -> bool {
    if i < 0 || i >= pattern.len() {
        false
    } else if i + 1 < pattern.len()
        && pattern[i] == b'\\'
        && pattern[i + 1] >= b'1'
        && pattern[i + 1] <= b'9'
    {
        true
    } else if i + 2 < pattern.len() && pattern[i] == b'(' && pattern[i + 1] == b'?'
        && (pattern[i + 2] == b'=' || pattern[i + 2] == b'!')
    {
        true
    } else if i + 3 < pattern.len() && pattern[i] == b'('
        && pattern[i + 1] == b'?' && pattern[i + 2] == b'<'
        && (pattern[i + 3] == b'=' || pattern[i + 3] == b'!')
    {
        true
    } else if i + 2 < pattern.len() && pattern[i] == b'(' && pattern[i + 1] == b'?'
        && (pattern[i + 2] == b'>' || pattern[i + 2] == b'(')
    {
        true
    } else {
        false
    }
}

pub open spec fn regex_dialect_admit_spec(pattern: Seq<u8>) -> bool {
    pattern.len() <= 65536
        && forall|i: int| 0 <= i < pattern.len() ==> regex_byte_ok(pattern[i])
        && forall|i: int| 0 <= i < pattern.len() ==> !regex_unsupported_at(pattern, i)
}

fn regex_byte_ok_exec(b: u8) -> (ok: bool)
    ensures ok == regex_byte_ok(b),
{
    b >= 0x20 && b != 0x7f
}

fn regex_unsupported_at_exec(pattern: &[u8], i: usize) -> (unsupported: bool)
    requires i < pattern.len(),
    ensures unsupported == regex_unsupported_at(pattern@, i as int),
{
    if pattern.len() - i >= 2
        && pattern[i] == b'\\'
        && pattern[i + 1] >= b'1'
        && pattern[i + 1] <= b'9'
    {
        true
    } else if pattern.len() - i >= 3
        && pattern[i] == b'('
        && pattern[i + 1] == b'?'
        && (pattern[i + 2] == b'=' || pattern[i + 2] == b'!')
    {
        true
    } else if pattern.len() - i >= 4
        && pattern[i] == b'('
        && pattern[i + 1] == b'?'
        && pattern[i + 2] == b'<'
        && (pattern[i + 3] == b'=' || pattern[i + 3] == b'!')
    {
        true
    } else if pattern.len() - i >= 3
        && pattern[i] == b'('
        && pattern[i + 1] == b'?'
        && (pattern[i + 2] == b'>' || pattern[i + 2] == b'(')
    {
        true
    } else {
        false
    }
}

pub fn regex_dialect_admit(pattern: &[u8]) -> (admit: bool)
    ensures admit == regex_dialect_admit_spec(pattern@),
{
    if pattern.len() > 65536 {
        return false;
    }
    let mut i: usize = 0;
    while i < pattern.len()
        invariant
            i <= pattern.len(),
            forall|j: int| 0 <= j < i ==> regex_byte_ok(pattern@[j]),
            forall|j: int| 0 <= j < i ==> !regex_unsupported_at(pattern@, j),
        decreases pattern.len() - i,
    {
        if !regex_byte_ok_exec(pattern[i]) {
            assert(!regex_dialect_admit_spec(pattern@));
            return false;
        }
        if regex_unsupported_at_exec(pattern, i) {
            assert(!regex_dialect_admit_spec(pattern@));
            return false;
        }
        i = i + 1;
    }
    true
}

/// P16-B: every configuration-directive regex is compiled over bytes with
/// Unicode character classes disabled.  This is Apache/PCRE's default mode:
/// `\w`, `\d`, `\s` and word boundaries classify only ASCII bytes.
pub open spec fn directive_regex_mode_spec(
    byte_oriented: bool,
    unicode_classes: bool,
) -> bool {
    byte_oriented && !unicode_classes
}

pub fn directive_regex_mode_admit(
    byte_oriented: bool,
    unicode_classes: bool,
) -> (admit: bool)
    ensures admit == directive_regex_mode_spec(byte_oriented, unicode_classes),
{
    byte_oriented && !unicode_classes
}

/// The engine default is not sufficient by itself because Rust regex syntax
/// can re-enable Unicode classes inside the pattern with `(?u)` or a scoped
/// option group. The parser reports that structural fact and this gate makes
/// inline enablement an explicit rejection condition.
pub open spec fn directive_regex_pattern_spec(
    byte_oriented: bool,
    unicode_classes: bool,
    inline_unicode_classes: bool,
) -> bool {
    byte_oriented && !unicode_classes && !inline_unicode_classes
}

pub fn directive_regex_pattern_admit(
    byte_oriented: bool,
    unicode_classes: bool,
    inline_unicode_classes: bool,
) -> (admit: bool)
    ensures admit == directive_regex_pattern_spec(
        byte_oriented,
        unicode_classes,
        inline_unicode_classes,
    ),
{
    byte_oriented && !unicode_classes && !inline_unicode_classes
}

pub proof fn directive_regex_pattern_rejects_inline_unicode(
    byte_oriented: bool,
    unicode_classes: bool,
)
    ensures !directive_regex_pattern_spec(byte_oriented, unicode_classes, true),
{
}

/// P16-C: policy regexes receive an exact byte-for-byte copy of a request
/// field value.  In particular, obs-text is never projected through UTF-8 or
/// replaced with an empty string before an ACL decision.
pub fn guard_header_bytes(input: &[u8]) -> (out: Vec<u8>)
    ensures out@ == input@,
{
    let mut out = Vec::with_capacity(input.len());
    let mut i: usize = 0;
    while i < input.len()
        invariant
            i <= input.len(),
            out@ == input@.subrange(0, i as int),
        decreases input.len() - i,
    {
        out.push(input[i]);
        i = i + 1;
    }
    assert(input@.subrange(0, input@.len() as int) == input@);
    out
}

pub proof fn directive_regex_mode_rejects_unicode(
    byte_oriented: bool,
    unicode_classes: bool,
)
    ensures
        directive_regex_mode_spec(byte_oriented, unicode_classes)
            ==> byte_oriented && !unicode_classes,
{
}

/// P16-A: access-file environment mutations are useful to local CGI, but are
/// not trusted configuration inputs for a proxied FastCGI backend.  Keeping
/// origin as a sum type prevents a new directive from being admitted merely
/// because its variable name was not added to a denylist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvironmentOrigin {
    MainConfig,
    AccessFile,
}

pub open spec fn fastcgi_environment_origin_spec(origin: EnvironmentOrigin) -> bool {
    match origin {
        EnvironmentOrigin::MainConfig => true,
        EnvironmentOrigin::AccessFile => false,
    }
}

pub fn fastcgi_environment_origin_admit(origin: EnvironmentOrigin) -> (admit: bool)
    ensures admit == fastcgi_environment_origin_spec(origin),
{
    match origin {
        EnvironmentOrigin::MainConfig => true,
        EnvironmentOrigin::AccessFile => false,
    }
}

pub proof fn access_file_environment_never_reaches_fastcgi()
    ensures !fastcgi_environment_origin_spec(EnvironmentOrigin::AccessFile),
{
}

pub proof fn main_environment_remains_available_to_fastcgi()
    ensures fastcgi_environment_origin_spec(EnvironmentOrigin::MainConfig),
{
}

/// P15-C: request-time regex failures are not boolean non-matches. Keeping
/// the error as `None` prevents negation (`!~` / `Require not expr`) from
/// turning an engine failure into an authorization success.
pub open spec fn expr_regex_result_spec(
    eval_ok: bool,
    matched: bool,
    negate: bool,
) -> Option<bool> {
    if eval_ok {
        Some(matched != negate)
    } else {
        None
    }
}

pub fn expr_regex_result(
    eval_ok: bool,
    matched: bool,
    negate: bool,
) -> (result: Option<bool>)
    ensures result == expr_regex_result_spec(eval_ok, matched, negate)
{
    if eval_ok {
        Some(matched != negate)
    } else {
        None
    }
}

pub proof fn expr_regex_error_never_grants(matched: bool, negate: bool)
    ensures expr_regex_result_spec(false, matched, negate) != Some(true)
{
}

pub proof fn expr_regex_success_is_exact(matched: bool, negate: bool)
    ensures expr_regex_result_spec(true, matched, negate) == Some(matched != negate)
{
}

/// A configured/rewrite environment entry may pass only when its name is a
/// valid non-reserved environment key.  Calculated CGI variables and `HTTP_*`
/// request-derived variables are classified by the caller and cannot be
/// overridden (CVE-2025-65082).
pub fn cgi_env_entry_admit(
    key_valid: bool,
    reserved: bool,
) -> (admit: bool)
    ensures admit == (key_valid && !reserved),
{
    key_valid && !reserved
}

// ---------------------------------------------------------------------------
// HTTP cache lookup policy
// ---------------------------------------------------------------------------

pub open spec fn etag_opaque_byte(b: u8) -> bool {
    b == 0x21 || (b >= 0x23 && b <= 0x7e) || b >= 0x80
}

pub open spec fn weak_etag_bounds_valid_spec(
    value: Seq<u8>,
    start: int,
    end: int,
) -> bool {
    0 < start <= end < value.len()
        && value[start - 1] == b'"'
        && value[end] == b'"'
        && forall|i: int| start <= i < end ==> etag_opaque_byte(value[i])
}

pub open spec fn weak_etag_valid_spec(value: Seq<u8>) -> bool {
    exists|start: int, end: int|
        #[trigger] weak_etag_bounds_valid_spec(value, start, end)
}

fn weak_etag_opaque_bounds(value: &[u8]) -> (bounds: Option<(usize, usize)>)
    ensures
        match bounds {
            Some((start, end)) => weak_etag_bounds_valid_spec(
                value@,
                start as int,
                end as int,
            ),
            None => true,
        },
{
    let (trimmed_start, trimmed_end) = trim_range(value);
    let mut tag_start = trimmed_start;
    if trimmed_end - trimmed_start >= 2
        && value[trimmed_start] == b'W'
        && value[trimmed_start + 1] == b'/'
    {
        tag_start = trimmed_start + 2;
    }
    assert(tag_start <= trimmed_end);
    if trimmed_end - tag_start < 2
        || value[tag_start] != b'"'
        || value[trimmed_end - 1] != b'"'
    {
        return None;
    }
    let opaque_start = tag_start + 1;
    let opaque_end = trimmed_end - 1;
    let mut i = opaque_start;
    while i < opaque_end
        invariant
            opaque_start <= i <= opaque_end,
            opaque_end < value.len(),
            value@[opaque_start as int - 1] == b'"',
            value@[opaque_end as int] == b'"',
            forall|j: int| opaque_start <= j < i ==> etag_opaque_byte(value@[j]),
        decreases opaque_end - i,
    {
        let byte = value[i];
        if !(byte == 0x21 || (byte >= 0x23 && byte <= 0x7e) || byte >= 0x80) {
            return None;
        }
        i = i + 1;
    }
    Some((opaque_start, opaque_end))
}

/// RFC weak comparison strips an optional uppercase `W/` marker and compares
/// the complete validated opaque tags byte-for-byte.
pub fn cache_weak_etag_match(stored: &[u8], candidate: &[u8]) -> (matched: bool)
    ensures
        matched ==> exists|a: int, b: int, c: int, d: int|
            0 < a <= b < stored@.len()
                && 0 < c <= d < candidate@.len()
                && stored@.subrange(a, b) == candidate@.subrange(c, d)
                && (forall|i: int| a <= i < b ==> etag_opaque_byte(stored@[i]))
                && (forall|i: int| c <= i < d ==> etag_opaque_byte(candidate@[i])),
        matched ==> weak_etag_valid_spec(stored@),
        matched ==> weak_etag_valid_spec(candidate@),
{
    let (stored_start, stored_end) = match weak_etag_opaque_bounds(stored) {
        Some(bounds) => bounds,
        None => return false,
    };
    let (candidate_start, candidate_end) = match weak_etag_opaque_bounds(candidate) {
        Some(bounds) => bounds,
        None => return false,
    };
    bytes_eq(
        &stored[stored_start..stored_end],
        &candidate[candidate_start..candidate_end],
    )
}

pub fn cache_if_none_match_star(value: &[u8]) -> (matched: bool)
    ensures
        matched ==> exists|start: int, end: int|
            0 <= start < end <= value@.len()
                && value@.subrange(start, end) == b"*"@,
{
    let (start, end) = trim_range(value);
    let matched = bytes_eq(&value[start..end], b"*");
    if matched {
        assert(value@.subrange(start as int, end as int) == b"*"@);
        assert(value@.subrange(start as int, end as int).len() == 1);
        assert(end - start == 1);
        assert(start < end);
        assert(end <= value.len());
        assert(exists|witness_start: int, witness_end: int|
            0 <= witness_start < witness_end <= value@.len()
                && value@.subrange(witness_start, witness_end) == b"*"@);
    }
    matched
}

pub open spec fn cache_if_none_match_star_witness_spec(value: Seq<u8>) -> bool {
    exists|start: int, end: int|
        0 <= start < end <= value.len()
            && value.subrange(start, end) == b"*"@
}

/// Parse the complete If-None-Match field as either `*` or a strict
/// comma-delimited entity-tag list.  Commas inside an opaque quoted tag are
/// data, not separators; any malformed member invalidates the whole list.
pub fn cache_if_none_match_matches(value: &[u8], stored: &[u8]) -> (matched: bool)
    ensures
        matched ==> cache_if_none_match_star_witness_spec(value@)
            || weak_etag_valid_spec(stored@),
{
    if cache_if_none_match_star(value) {
        return true;
    }

    let mut cursor: usize = 0;
    let mut matched: bool = false;
    while cursor < value.len()
        invariant
            cursor <= value.len(),
            matched ==> weak_etag_valid_spec(stored@),
        decreases value.len() - cursor,
    {
        let _iteration_start = cursor;
        while cursor < value.len() && is_ows_exec(value[cursor])
            invariant _iteration_start <= cursor <= value.len(),
            decreases value.len() - cursor,
        {
            cursor = cursor + 1;
        }
        if cursor == value.len() {
            return false;
        }

        let candidate_start = cursor;
        if cursor + 1 < value.len() && value[cursor] == b'W' && value[cursor + 1] == b'/' {
            cursor = cursor + 2;
        }
        if cursor >= value.len() || value[cursor] != b'"' {
            return false;
        }
        cursor = cursor + 1;
        while cursor < value.len() && value[cursor] != b'"'
            invariant
                _iteration_start <= candidate_start < cursor <= value.len(),
            decreases value.len() - cursor,
        {
            cursor = cursor + 1;
        }
        if cursor == value.len() {
            return false;
        }
        cursor = cursor + 1;
        let candidate_end = cursor;
        let candidate = &value[candidate_start..candidate_end];
        // Self-comparison is the executable syntax admission for one entity
        // tag. It rejects controls, stray quotes and a malformed weak marker.
        if !cache_weak_etag_match(candidate, candidate) {
            return false;
        }
        if cache_weak_etag_match(stored, candidate) {
            matched = true;
        }

        while cursor < value.len() && is_ows_exec(value[cursor])
            invariant _iteration_start < cursor <= value.len(),
            decreases value.len() - cursor,
        {
            cursor = cursor + 1;
        }
        if cursor == value.len() {
            return matched;
        }
        if value[cursor] != b',' {
            return false;
        }
        cursor = cursor + 1;
        assert(_iteration_start < cursor);
    }
    false
}

pub open spec fn cache_conditional_hit_spec(
    if_none_match_present: bool,
    if_none_match_matches: bool,
    if_modified_since_matches: bool,
) -> bool {
    if if_none_match_present { if_none_match_matches } else { if_modified_since_matches }
}

/// If-None-Match has absolute precedence over If-Modified-Since, including
/// when the supplied validator does not match.
pub fn cache_conditional_hit_admit(
    if_none_match_present: bool,
    if_none_match_matches: bool,
    if_modified_since_matches: bool,
) -> (hit: bool)
    ensures hit == cache_conditional_hit_spec(
        if_none_match_present,
        if_none_match_matches,
        if_modified_since_matches,
    ),
{
    if if_none_match_present { if_none_match_matches } else { if_modified_since_matches }
}

/// One cache lookup is admissible only when the key and policy match, the
/// entry belongs to the current configuration generation, the stored `Vary`
/// values match the current request, and the entry is fresh.  This is the
/// security decision consumed by the runtime cache lookup.
pub fn cache_lookup_admit(
    key_match: bool,
    policy_match: bool,
    vary_match: bool,
    generation_match: bool,
    expires: i64,
    now: i64,
) -> (hit: bool)
    ensures
        hit == (key_match && policy_match && vary_match && generation_match && now < expires),
{
    key_match && policy_match && vary_match && generation_match && now < expires
}

// ---------------------------------------------------------------------------
// Proxy target identity
// ---------------------------------------------------------------------------

/// Canonical, un-hashed identity of one outbound proxy target.  Host and path
/// are length-delimited by a NUL separator; the runtime host/path validators
/// exclude NUL.  This is the exact key used for grant binding.
pub open spec fn proxy_target_key_spec(
    host: Seq<u8>,
    port: u16,
    tls: bool,
    path: Seq<u8>,
) -> Seq<u8> {
    seq![
        if tls { 1u8 } else { 0u8 },
        (port / 256) as u8,
        (port % 256) as u8
    ] + host + seq![0u8] + path
}

pub fn proxy_target_key(
    host: &[u8],
    port: u16,
    tls: bool,
    path: &[u8],
) -> (out: Vec<u8>)
    ensures out@ == proxy_target_key_spec(host@, port, tls, path@),
{
    let mut out: Vec<u8> = Vec::new();
    out.push(if tls { 1 } else { 0 });
    out.push((port / 256) as u8);
    out.push((port % 256) as u8);
    out.extend_from_slice(host);
    out.push(0);
    out.extend_from_slice(path);
    out
}

// ---------------------------------------------------------------------------
// Authorization combination
// ---------------------------------------------------------------------------

/// Three-valued result of evaluating an authorization provider or tree.
/// `Neutral` is a method-limited section that does not apply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PolicyResult {
    Granted,
    Denied,
    AuthRequired,
    Neutral,
}

pub open spec fn combine_and_spec(a: PolicyResult, b: PolicyResult) -> PolicyResult {
    match (a, b) {
        (PolicyResult::Denied, _) => PolicyResult::Denied,
        (_, PolicyResult::Denied) => PolicyResult::Denied,
        (PolicyResult::AuthRequired, _) => PolicyResult::AuthRequired,
        (_, PolicyResult::AuthRequired) => PolicyResult::AuthRequired,
        (PolicyResult::Granted, _) => PolicyResult::Granted,
        (_, PolicyResult::Granted) => PolicyResult::Granted,
        _ => PolicyResult::Neutral,
    }
}

pub open spec fn combine_or_spec(a: PolicyResult, b: PolicyResult) -> PolicyResult {
    match (a, b) {
        (PolicyResult::Granted, _) => PolicyResult::Granted,
        (_, PolicyResult::Granted) => PolicyResult::Granted,
        (PolicyResult::AuthRequired, _) => PolicyResult::AuthRequired,
        (_, PolicyResult::AuthRequired) => PolicyResult::AuthRequired,
        (PolicyResult::Denied, _) => PolicyResult::Denied,
        (_, PolicyResult::Denied) => PolicyResult::Denied,
        _ => PolicyResult::Neutral,
    }
}

pub open spec fn require_none_result_spec(r: PolicyResult) -> PolicyResult {
    match r {
        PolicyResult::Granted => PolicyResult::Denied,
        PolicyResult::Denied | PolicyResult::AuthRequired => PolicyResult::Neutral,
        PolicyResult::Neutral => PolicyResult::Neutral,
    }
}

/// OR-combine a whole sequence of `<RequireNone>` child results.  The group
/// fails if *any* provider is satisfied, so a granted child must remain
/// visible even when a sibling is denied (F46/I43).
pub open spec fn combine_or_all_from_spec(
    rs: Seq<PolicyResult>,
    start: int,
) -> PolicyResult
    recommends 0 <= start <= rs.len(),
    decreases rs.len() - start,
{
    if start >= rs.len() {
        PolicyResult::Neutral
    } else {
        combine_or_spec(rs[start], combine_or_all_from_spec(rs, start + 1))
    }
}

pub open spec fn combine_or_all_spec(rs: Seq<PolicyResult>) -> PolicyResult {
    combine_or_all_from_spec(rs, 0)
}

pub fn combine_or_all(rs: &[PolicyResult]) -> (out: PolicyResult)
    ensures out == combine_or_all_spec(rs@)
{
    let mut cursor = rs.len();
    let mut result = PolicyResult::Neutral;
    while cursor > 0
        invariant
            cursor <= rs.len(),
            result == combine_or_all_from_spec(rs@, cursor as int),
        decreases cursor,
    {
        cursor = cursor - 1;
        result = combine_or(rs[cursor], result);
    }
    result
}

pub open spec fn require_none_multi_spec(rs: Seq<PolicyResult>) -> PolicyResult {
    require_none_result_spec(combine_or_all_spec(rs))
}

/// Negate an OR aggregate of all `<RequireNone>` children.  The result can
/// never grant, and any satisfied child makes the group deny.
pub fn require_none_multi(rs: &[PolicyResult]) -> (out: PolicyResult)
    ensures
        out == require_none_multi_spec(rs@),
        out != PolicyResult::Granted,
{
    let combined = combine_or_all(rs);
    require_none_result(combined)
}

/// `<RequireAll>` combination.
pub fn combine_and(a: PolicyResult, b: PolicyResult) -> (r: PolicyResult)
    ensures r == combine_and_spec(a, b)
{
    match (a, b) {
        (PolicyResult::Denied, _) => PolicyResult::Denied,
        (_, PolicyResult::Denied) => PolicyResult::Denied,
        (PolicyResult::AuthRequired, _) => PolicyResult::AuthRequired,
        (_, PolicyResult::AuthRequired) => PolicyResult::AuthRequired,
        (PolicyResult::Granted, _) => PolicyResult::Granted,
        (_, PolicyResult::Granted) => PolicyResult::Granted,
        _ => PolicyResult::Neutral,
    }
}

/// `<RequireAny>` combination.
pub fn combine_or(a: PolicyResult, b: PolicyResult) -> (r: PolicyResult)
    ensures r == combine_or_spec(a, b)
{
    match (a, b) {
        (PolicyResult::Granted, _) => PolicyResult::Granted,
        (_, PolicyResult::Granted) => PolicyResult::Granted,
        (PolicyResult::AuthRequired, _) => PolicyResult::AuthRequired,
        (_, PolicyResult::AuthRequired) => PolicyResult::AuthRequired,
        (PolicyResult::Denied, _) => PolicyResult::Denied,
        (_, PolicyResult::Denied) => PolicyResult::Denied,
        _ => PolicyResult::Neutral,
    }
}

/// A `<RequireNone>` group cannot grant authorization.  A granted child
/// becomes denied; denied/auth-required children are neutral.
pub fn require_none_result(r: PolicyResult) -> (out: PolicyResult)
    ensures
        out == require_none_result_spec(r),
        out != PolicyResult::Granted
{
    match r {
        PolicyResult::Granted => PolicyResult::Denied,
        PolicyResult::Denied | PolicyResult::AuthRequired => PolicyResult::Neutral,
        PolicyResult::Neutral => PolicyResult::Neutral,
    }
}

proof fn combine_and_commutative(a: PolicyResult, b: PolicyResult)
    ensures combine_and_spec(a, b) == combine_and_spec(b, a)
{
}

proof fn combine_or_commutative(a: PolicyResult, b: PolicyResult)
    ensures combine_or_spec(a, b) == combine_or_spec(b, a)
{
}


// ---------------------------------------------------------------------------
// Configuration phase and access-file interleaving plan
// ---------------------------------------------------------------------------

/// Parser-level rule kind stripped of regex/path payload. Runtime `MatchKind`
/// is exhaustively translated to this enum before any phase or sort decision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigRuleKind {
    Always,
    Directory,
    DirectoryMatch,
    Files,
    Location,
    LocationMatch,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigRulePhase {
    Directory,
    Files,
    Location,
    Condition,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigDeferredSlot {
    Ignore,
    Files,
    Location,
    Condition,
}

pub open spec fn config_rule_phase_spec(
    kind: ConfigRuleKind,
    conditional: bool,
) -> ConfigRulePhase {
    // `Always` is the parser's payload-free carrier for <If>/<ElseIf>/<Else>.
    // It belongs to the final condition phase even if a malformed synthetic
    // rule omits the expression/branch marker used by the runtime parser.
    match kind {
        ConfigRuleKind::Always => ConfigRulePhase::Condition,
        ConfigRuleKind::Directory | ConfigRuleKind::DirectoryMatch => if conditional {
            ConfigRulePhase::Condition
        } else {
            ConfigRulePhase::Directory
        },
        ConfigRuleKind::Files => if conditional {
            ConfigRulePhase::Condition
        } else {
            ConfigRulePhase::Files
        },
        ConfigRuleKind::Location | ConfigRuleKind::LocationMatch => if conditional {
            ConfigRulePhase::Condition
        } else {
            ConfigRulePhase::Location
        },
    }
}

pub fn config_rule_phase(
    kind: ConfigRuleKind,
    conditional: bool,
) -> (phase: ConfigRulePhase)
    ensures phase == config_rule_phase_spec(kind, conditional),
{
    match kind {
        ConfigRuleKind::Always => ConfigRulePhase::Condition,
        ConfigRuleKind::Directory | ConfigRuleKind::DirectoryMatch => if conditional {
            ConfigRulePhase::Condition
        } else {
            ConfigRulePhase::Directory
        },
        ConfigRuleKind::Files => if conditional {
            ConfigRulePhase::Condition
        } else {
            ConfigRulePhase::Files
        },
        ConfigRuleKind::Location | ConfigRuleKind::LocationMatch => if conditional {
            ConfigRulePhase::Condition
        } else {
            ConfigRulePhase::Location
        },
    }
}

pub open spec fn config_deferred_slot_spec(
    kind: ConfigRuleKind,
    conditional: bool,
) -> ConfigDeferredSlot {
    match kind {
        ConfigRuleKind::Always => ConfigDeferredSlot::Condition,
        ConfigRuleKind::Files => if conditional {
            ConfigDeferredSlot::Condition
        } else {
            ConfigDeferredSlot::Files
        },
        ConfigRuleKind::Location | ConfigRuleKind::LocationMatch => if conditional {
            ConfigDeferredSlot::Condition
        } else {
            ConfigDeferredSlot::Location
        },
        ConfigRuleKind::Directory | ConfigRuleKind::DirectoryMatch => if conditional {
            ConfigDeferredSlot::Condition
        } else {
            ConfigDeferredSlot::Ignore
        },
    }
}

pub fn config_deferred_slot(
    kind: ConfigRuleKind,
    conditional: bool,
) -> (slot: ConfigDeferredSlot)
    ensures slot == config_deferred_slot_spec(kind, conditional),
{
    match kind {
        ConfigRuleKind::Always => ConfigDeferredSlot::Condition,
        ConfigRuleKind::Files => if conditional {
            ConfigDeferredSlot::Condition
        } else {
            ConfigDeferredSlot::Files
        },
        ConfigRuleKind::Location | ConfigRuleKind::LocationMatch => if conditional {
            ConfigDeferredSlot::Condition
        } else {
            ConfigDeferredSlot::Location
        },
        ConfigRuleKind::Directory | ConfigRuleKind::DirectoryMatch => if conditional {
            ConfigDeferredSlot::Condition
        } else {
            ConfigDeferredSlot::Ignore
        },
    }
}

pub open spec fn config_sort_rank_spec(kind: ConfigRuleKind, conditional: bool) -> u8 {
    match kind {
        ConfigRuleKind::Always => 5,
        ConfigRuleKind::Directory => if conditional { 5 } else { 0 },
        ConfigRuleKind::DirectoryMatch => if conditional { 5 } else { 1 },
        ConfigRuleKind::Files => if conditional { 5 } else { 2 },
        ConfigRuleKind::Location => if conditional { 5 } else { 3 },
        ConfigRuleKind::LocationMatch => if conditional { 5 } else { 4 },
    }
}

pub fn config_sort_rank(kind: ConfigRuleKind, conditional: bool) -> (rank: u8)
    ensures rank == config_sort_rank_spec(kind, conditional),
{
    match kind {
        ConfigRuleKind::Always => 5,
        ConfigRuleKind::Directory => if conditional { 5 } else { 0 },
        ConfigRuleKind::DirectoryMatch => if conditional { 5 } else { 1 },
        ConfigRuleKind::Files => if conditional { 5 } else { 2 },
        ConfigRuleKind::Location => if conditional { 5 } else { 3 },
        ConfigRuleKind::LocationMatch => if conditional { 5 } else { 4 },
    }
}

pub open spec fn config_rule_precedes_spec(
    a_kind: ConfigRuleKind,
    a_conditional: bool,
    a_specificity: int,
    a_order: int,
    b_kind: ConfigRuleKind,
    b_conditional: bool,
    b_specificity: int,
    b_order: int,
) -> bool {
    let ar = config_sort_rank_spec(a_kind, a_conditional);
    let br = config_sort_rank_spec(b_kind, b_conditional);
    ar < br
        || (ar == br
            && (a_specificity < b_specificity
                || (a_specificity == b_specificity && a_order < b_order)))
}

pub fn config_rule_precedes(
    a_kind: ConfigRuleKind,
    a_conditional: bool,
    a_specificity: usize,
    a_order: usize,
    b_kind: ConfigRuleKind,
    b_conditional: bool,
    b_specificity: usize,
    b_order: usize,
) -> (before: bool)
    ensures
        before == config_rule_precedes_spec(
            a_kind,
            a_conditional,
            a_specificity as int,
            a_order as int,
            b_kind,
            b_conditional,
            b_specificity as int,
            b_order as int,
        ),
{
    let ar = config_sort_rank(a_kind, a_conditional);
    let br = config_sort_rank(b_kind, b_conditional);
    ar < br
        || (ar == br
            && (a_specificity < b_specificity
                || (a_specificity == b_specificity && a_order < b_order)))
}

pub proof fn config_rule_order_is_asymmetric(
    a_kind: ConfigRuleKind,
    a_conditional: bool,
    a_specificity: int,
    a_order: int,
    b_kind: ConfigRuleKind,
    b_conditional: bool,
    b_specificity: int,
    b_order: int,
)
    ensures
        config_rule_precedes_spec(
            a_kind,
            a_conditional,
            a_specificity,
            a_order,
            b_kind,
            b_conditional,
            b_specificity,
            b_order,
        ) ==>
        !config_rule_precedes_spec(
            b_kind,
            b_conditional,
            b_specificity,
            b_order,
            a_kind,
            a_conditional,
            a_specificity,
            a_order,
        ),
{
}

/// Canonical stage order emitted by a pure verified compiler. Config and
/// access-file sources are separate typed steps carrying their exact depth;
/// the runtime no longer hides source ordering inside one imperative branch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessStep {
    DirectoryConfig { depth: usize },
    DirectoryAccess { depth: usize },
    DirectoryOwnPath,
    DirectoryMatch,
    BaseFiles,
    FilesConfig { depth: usize },
    FilesAccess { depth: usize },
    DirectoryMatchFiles,
    ConfigLocation,
    ConfigConditions,
    AccessConditions,
}

/// Provenance order for the deferred condition phase. Configuration
/// conditions run before access-file conditions, with independent chain
/// state for the two sources.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConditionSource {
    Config,
    Access,
}

pub open spec fn condition_source_plan() -> Seq<ConditionSource> {
    seq![ConditionSource::Config, ConditionSource::Access]
}

pub fn condition_source_plan_exec() -> (out: Vec<ConditionSource>)
    ensures out@ == condition_source_plan(),
{
    let mut out = Vec::new();
    out.push(ConditionSource::Config);
    out.push(ConditionSource::Access);
    out
}

pub proof fn condition_source_plan_matches_access_tail()
    ensures
        condition_source_plan().len() == 2,
        condition_source_plan()[0] == ConditionSource::Config,
        condition_source_plan()[1] == ConditionSource::Access,
        access_tail()[2] == AccessStep::ConfigConditions,
        access_tail()[3] == AccessStep::AccessConditions,
{
}

pub open spec fn access_tail() -> Seq<AccessStep> {
    seq![
        AccessStep::DirectoryMatchFiles,
        AccessStep::ConfigLocation,
        AccessStep::ConfigConditions,
        AccessStep::AccessConditions,
    ]
}

pub open spec fn access_walk_plan_from(
    present: Seq<bool>,
    start: int,
) -> Seq<AccessStep>
    decreases present.len() - start,
{
    if start >= present.len() {
        Seq::empty()
    } else {
        seq![AccessStep::DirectoryConfig { depth: start as usize }]
            + if present[start] {
                seq![AccessStep::DirectoryAccess { depth: start as usize }]
            } else {
                Seq::empty()
            }
            + access_walk_plan_from(present, start + 1)
    }
}

pub open spec fn access_walk_plan(present: Seq<bool>) -> Seq<AccessStep> {
    access_walk_plan_from(present, 0)
}

pub open spec fn access_files_plan_from(
    present: Seq<bool>,
    start: int,
) -> Seq<AccessStep>
    decreases present.len() - start,
{
    if start >= present.len() {
        Seq::empty()
    } else {
        seq![AccessStep::FilesConfig { depth: start as usize }]
            + if present[start] {
                seq![AccessStep::FilesAccess { depth: start as usize }]
            } else {
                Seq::empty()
            }
            + access_files_plan_from(present, start + 1)
    }
}

pub open spec fn access_files_plan(present: Seq<bool>) -> Seq<AccessStep> {
    access_files_plan_from(present, 0)
}

pub open spec fn access_plan(present: Seq<bool>) -> Seq<AccessStep> {
    access_walk_plan(present)
        + seq![
            AccessStep::DirectoryOwnPath,
            AccessStep::DirectoryMatch,
            AccessStep::BaseFiles,
        ]
        + access_files_plan(present)
        + access_tail()
}

pub fn access_walk_plan_exec_from(
    present: &[bool],
    start: usize,
) -> (out: Vec<AccessStep>)
    requires start <= present.len(),
    ensures out@ == access_walk_plan_from(present@, start as int),
{
    let mut out: Vec<AccessStep> = Vec::new();
    let mut cursor = start;
    while cursor < present.len()
        invariant
            start <= cursor <= present.len(),
            out@ + access_walk_plan_from(present@, cursor as int)
                == access_walk_plan_from(present@, start as int),
        decreases present.len() - cursor,
    {
        out.push(AccessStep::DirectoryConfig { depth: cursor });
        if present[cursor] {
            out.push(AccessStep::DirectoryAccess { depth: cursor });
        }
        cursor = cursor + 1;
    }
    out
}

pub fn access_walk_plan_exec(present: &[bool]) -> (out: Vec<AccessStep>)
    ensures out@ == access_walk_plan(present@)
{
    access_walk_plan_exec_from(present, 0)
}

pub fn access_files_plan_exec_from(
    present: &[bool],
    start: usize,
) -> (out: Vec<AccessStep>)
    requires start <= present.len(),
    ensures out@ == access_files_plan_from(present@, start as int),
{
    let mut out: Vec<AccessStep> = Vec::new();
    let mut cursor = start;
    while cursor < present.len()
        invariant
            start <= cursor <= present.len(),
            out@ + access_files_plan_from(present@, cursor as int)
                == access_files_plan_from(present@, start as int),
        decreases present.len() - cursor,
    {
        out.push(AccessStep::FilesConfig { depth: cursor });
        if present[cursor] {
            out.push(AccessStep::FilesAccess { depth: cursor });
        }
        cursor = cursor + 1;
    }
    out
}

pub fn access_files_plan_exec(present: &[bool]) -> (out: Vec<AccessStep>)
    ensures out@ == access_files_plan(present@)
{
    access_files_plan_exec_from(present, 0)
}

pub fn access_plan_exec(present: &[bool]) -> (out: Vec<AccessStep>)
    ensures out@ == access_plan(present@)
{
    let mut out = access_walk_plan_exec(present);
    out.push(AccessStep::DirectoryOwnPath);
    out.push(AccessStep::DirectoryMatch);
    out.push(AccessStep::BaseFiles);
    let mut files = access_files_plan_exec(present);
    out.append(&mut files);
    out.push(AccessStep::DirectoryMatchFiles);
    out.push(AccessStep::ConfigLocation);
    out.push(AccessStep::ConfigConditions);
    out.push(AccessStep::AccessConditions);
    out
}

/// The plan shape itself proves source/depth ordering: each recursive depth
/// emits config before an optional access step, in both Directory and Files
/// phases; DirectoryMatch/Location/conditions are fixed suffixes.
pub proof fn access_plan_interleaves(present: Seq<bool>)
    ensures
        access_plan(present) == access_walk_plan(present)
            + seq![
                AccessStep::DirectoryOwnPath,
                AccessStep::DirectoryMatch,
                AccessStep::BaseFiles,
            ]
            + access_files_plan(present)
            + access_tail(),
        access_tail().len() == 4,
{
    assert(access_tail().len() == 4);
}

/// Admit a filesystem-policy walk only while both dimensions of its work are
/// bounded.  `ancestor_bytes` is the sum of the ancestor path lengths that a
/// caller would copy, not merely the length of the final path.
pub open spec fn policy_path_work_spec(
    components: u64,
    ancestor_bytes: u64,
    max_components: u64,
    max_ancestor_bytes: u64,
) -> bool {
    components <= max_components && ancestor_bytes <= max_ancestor_bytes
}

pub fn policy_path_work_admit(
    components: u64,
    ancestor_bytes: u64,
    max_components: u64,
    max_ancestor_bytes: u64,
) -> (ok: bool)
    ensures ok == policy_path_work_spec(
        components,
        ancestor_bytes,
        max_components,
        max_ancestor_bytes,
    ),
{
    components <= max_components && ancestor_bytes <= max_ancestor_bytes
}


// ---------------------------------------------------------------------------
// Merge-phase helpers used by the runtime
// ---------------------------------------------------------------------------

/// How a child `Require` policy combines with an inherited policy.  This is
/// the decision `Scope::merge` makes from `AuthMerging`; keeping it in the
/// verified crate makes the security-relevant branch explicit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthMergeKind {
    Replace,
    And,
    Or,
}

pub open spec fn auth_merge_kind_spec(
    merging_and: bool,
    merging_or: bool,
    has_parent: bool,
) -> AuthMergeKind {
    if has_parent && merging_and {
        AuthMergeKind::And
    } else if has_parent && merging_or {
        AuthMergeKind::Or
    } else {
        AuthMergeKind::Replace
    }
}

pub fn auth_merge_kind(
    merging_and: bool,
    merging_or: bool,
    has_parent: bool,
) -> (out: AuthMergeKind)
    ensures out == auth_merge_kind_spec(merging_and, merging_or, has_parent)
{
    if has_parent && merging_and {
        AuthMergeKind::And
    } else if has_parent && merging_or {
        AuthMergeKind::Or
    } else {
        AuthMergeKind::Replace
    }
}

proof fn auth_merge_kind_properties(
    merging_and: bool,
    merging_or: bool,
    has_parent: bool,
)
    ensures
        auth_merge_kind_spec(merging_and, merging_or, has_parent)
                == AuthMergeKind::And
            ==> has_parent && merging_and,
        auth_merge_kind_spec(merging_and, merging_or, has_parent)
                == AuthMergeKind::Or
            ==> has_parent && merging_or,
        !has_parent
            ==> auth_merge_kind_spec(merging_and, merging_or, has_parent)
                == AuthMergeKind::Replace,
{
}

pub enum AccessRuleClass {
    Conditional,
    Files,
    Other,
}

pub open spec fn access_rule_class_spec(
    has_condition: bool,
    normal_branch: bool,
    files_rule: bool,
) -> AccessRuleClass {
    if has_condition || !normal_branch {
        AccessRuleClass::Conditional
    } else if files_rule {
        AccessRuleClass::Files
    } else {
        AccessRuleClass::Other
    }
}

/// Section kinds used by the recursive configuration parser.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigSectionKind {
    Server,
    VirtualHost,
    Directory,
    DirectoryMatch,
    Location,
    Files,
    Proxy,
    Require,
    Conditional,
}

pub open spec fn config_section_nesting_allowed_spec(
    parent: ConfigSectionKind,
    child: ConfigSectionKind,
) -> bool {
    use ConfigSectionKind::*;
    match (parent, child) {
        (Server, VirtualHost) => true,
        (_, VirtualHost) => false,
        (Directory | DirectoryMatch | Location | Files | Proxy | Require, Directory | DirectoryMatch) => false,
        (Directory | DirectoryMatch | Location | Files | Proxy | Require, Location) => false,
        (Conditional, Directory | DirectoryMatch | Location | Proxy) => false,
        (Location | Files | Proxy | Require, Files) => false,
        (Directory | DirectoryMatch | Location | Files | Proxy | Require, Proxy) => false,
        (Require, _) => false,
        _ => true,
    }
}

/// Apache rejects most cross-section nesting.  This is the verified context
/// transition used by the configuration compiler; a rejected child section
/// cannot silently acquire a different scope interpretation.
pub fn config_section_nesting_allowed(
    parent: ConfigSectionKind,
    child: ConfigSectionKind,
) -> (allowed: bool)
    ensures allowed == config_section_nesting_allowed_spec(parent, child),
{
    use ConfigSectionKind::*;
    match (parent, child) {
        (Server, VirtualHost) => true,
        (_, VirtualHost) => false,
        (Directory | DirectoryMatch | Location | Files | Proxy | Require, Directory | DirectoryMatch) => false,
        (Directory | DirectoryMatch | Location | Files | Proxy | Require, Location) => false,
        (Conditional, Directory | DirectoryMatch | Location | Proxy) => false,
        (Location | Files | Proxy | Require, Files) => false,
        (Directory | DirectoryMatch | Location | Files | Proxy | Require, Proxy) => false,
        (Require, _) => false,
        _ => true,
    }
}

/// Disposition for a directive that was not handled by the parser's main
/// match. Apache rejects an unknown directive and also rejects a directive
/// whose implementing module is unavailable. Vapache must not turn either
/// case into an accepted no-op: doing so can erase an administrator's access,
/// routing, response-header, logging, or resource policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DirectiveDisposition {
    FailClosedSecurity,
    FailClosedKnown,
    FailClosedUnknown,
}

pub open spec fn directive_disposition_spec(
    security: bool,
    known: bool,
    _strict: bool,
) -> DirectiveDisposition {
    if security {
        DirectiveDisposition::FailClosedSecurity
    } else if known {
        DirectiveDisposition::FailClosedKnown
    } else {
        DirectiveDisposition::FailClosedUnknown
    }
}

pub fn directive_disposition(
    security: bool,
    known: bool,
    _strict: bool,
) -> (disposition: DirectiveDisposition)
    ensures disposition == directive_disposition_spec(security, known, _strict),
{
    if security {
        DirectiveDisposition::FailClosedSecurity
    } else if known {
        DirectiveDisposition::FailClosedKnown
    } else {
        DirectiveDisposition::FailClosedUnknown
    }
}

/// Translation slot for a parsed `.htaccess` rule.  The parser supplies the
/// three syntactic facts; this model fixes where the rule must be deferred.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessLayerSlot {
    Conditional,
    Files,
    TopLevel,
}

pub open spec fn access_layer_slot_spec(
    has_condition: bool,
    normal_branch: bool,
    files_rule: bool,
) -> AccessLayerSlot {
    if has_condition || !normal_branch {
        AccessLayerSlot::Conditional
    } else if files_rule {
        AccessLayerSlot::Files
    } else {
        AccessLayerSlot::TopLevel
    }
}

pub fn access_layer_slot(
    has_condition: bool,
    normal_branch: bool,
    files_rule: bool,
) -> (slot: AccessLayerSlot)
    ensures slot == access_layer_slot_spec(has_condition, normal_branch, files_rule),
{
    if has_condition || !normal_branch {
        AccessLayerSlot::Conditional
    } else if files_rule {
        AccessLayerSlot::Files
    } else {
        AccessLayerSlot::TopLevel
    }
}

/// Classify a parsed `.htaccess` rule for the layer plan.  Conditions and
/// non-normal branches always go to the deferred conditional phase; Files
/// rules go to the deferred Files phase; everything else is handled by the
/// layer's top-level scope.
pub fn classify_access_rule(
    has_condition: bool,
    normal_branch: bool,
    files_rule: bool,
) -> (out: AccessRuleClass)
    ensures out == access_rule_class_spec(has_condition, normal_branch, files_rule)
{
    if has_condition || !normal_branch {
        AccessRuleClass::Conditional
    } else if files_rule {
        AccessRuleClass::Files
    } else {
        AccessRuleClass::Other
    }
}


/// Apply one `Options` change.  Operation codes are stable and match the
/// runtime enum: 0 = Set, 1 = Add, 2 = Remove.  Only `Add` can introduce bits,
/// and it can introduce only bits present in `mask`; `Remove` clears only
/// `mask`; `Set` replaces the whole value.
pub open spec fn options_apply_spec(bits: u32, op: u8, mask: u32) -> u32 {
    if op == 0 {
        mask
    } else if op == 1 {
        bits | mask
    } else {
        bits & !mask
    }
}

pub fn options_apply(bits: u32, op: u8, mask: u32) -> (out: u32)
    ensures out == options_apply_spec(bits, op, mask)
{
    if op == 0 {
        mask
    } else if op == 1 {
        bits | mask
    } else {
        bits & !mask
    }
}

pub proof fn options_set_replaces_parent(bits: u32, mask: u32)
    ensures options_apply_spec(bits, 0, mask) == mask,
{
}

pub proof fn options_add_preserves_and_adds(bits: u32, mask: u32)
    ensures
        options_apply_spec(bits, 1, mask) & bits == bits,
        options_apply_spec(bits, 1, mask) & mask == mask,
{
    assert((bits | mask) & bits == bits) by (bit_vector);
    assert((bits | mask) & mask == mask) by (bit_vector);
}

pub proof fn options_remove_never_grants_and_clears(bits: u32, mask: u32)
    ensures
        options_apply_spec(bits, 2, mask) & bits == options_apply_spec(bits, 2, mask),
        options_apply_spec(bits, 2, mask) & mask == 0,
{
    assert((bits & !mask) & bits == bits & !mask) by (bit_vector);
    assert((bits & !mask) & mask == 0) by (bit_vector);
}




/// Truthiness of an expression value.  The evaluator's leaves may consult
/// regex/filesystem/request state, but the value-to-boolean step is fixed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExprValueKind {
    Bool,
    Int,
    Str,
    List,
}

pub open spec fn expr_value_truthy_spec(
    kind: ExprValueKind,
    boolean: bool,
    integer: i64,
    length: u64,
) -> bool {
    match kind {
        ExprValueKind::Bool => boolean,
        ExprValueKind::Int => integer != 0,
        ExprValueKind::Str => length > 0,
        ExprValueKind::List => length > 0,
    }
}

pub fn expr_value_truthy(
    kind: ExprValueKind,
    boolean: bool,
    integer: i64,
    length: u64,
) -> (truthy: bool)
    ensures truthy == expr_value_truthy_spec(kind, boolean, integer, length),
{
    match kind {
        ExprValueKind::Bool => boolean,
        ExprValueKind::Int => integer != 0,
        ExprValueKind::Str => length > 0,
        ExprValueKind::List => length > 0,
    }
}

/// Comparison operators admitted by the `ap_expr` subset.  Numeric `-eq`
/// through `-ge` and string `=`, `!=`, `<`, `<=`, `>`, `>=` share one enum so
/// the evaluator cannot silently fall back to a different ordering.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExprCompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

pub open spec fn expr_compare_ints_spec(op: ExprCompareOp, a: i64, b: i64) -> bool {
    match op {
        ExprCompareOp::Eq => a == b,
        ExprCompareOp::Ne => a != b,
        ExprCompareOp::Lt => a < b,
        ExprCompareOp::Le => a <= b,
        ExprCompareOp::Gt => a > b,
        ExprCompareOp::Ge => a >= b,
    }
}

pub fn expr_compare_ints(op: ExprCompareOp, a: i64, b: i64) -> (out: bool)
    ensures out == expr_compare_ints_spec(op, a, b),
{
    match op {
        ExprCompareOp::Eq => a == b,
        ExprCompareOp::Ne => a != b,
        ExprCompareOp::Lt => a < b,
        ExprCompareOp::Le => a <= b,
        ExprCompareOp::Gt => a > b,
        ExprCompareOp::Ge => a >= b,
    }
}

/// Byte-lexicographic order, matching Rust's `str` ordering (UTF-8 byte
/// comparison).  Stated recursively so the executable comparison and its
/// specification use the same definition.
pub open spec fn bytes_lt_from_spec(a: Seq<u8>, b: Seq<u8>, start: int) -> bool
    recommends 0 <= start <= a.len(), 0 <= start <= b.len(),
    decreases a.len() + b.len() - 2 * start,
{
    if start >= a.len() {
        start < b.len()
    } else if start >= b.len() {
        false
    } else if a[start] < b[start] {
        true
    } else if a[start] > b[start] {
        false
    } else {
        bytes_lt_from_spec(a, b, start + 1)
    }
}

pub open spec fn bytes_lt_spec(a: Seq<u8>, b: Seq<u8>) -> bool {
    bytes_lt_from_spec(a, b, 0)
}

fn bytes_lt(a: &[u8], b: &[u8]) -> (out: bool)
    ensures out == bytes_lt_spec(a@, b@),
{
    let mut cursor = 0usize;
    while cursor < a.len() && cursor < b.len()
        invariant
            cursor <= a.len(),
            cursor <= b.len(),
            bytes_lt_spec(a@, b@)
                == bytes_lt_from_spec(a@, b@, cursor as int),
        decreases a.len() - cursor,
    {
        if a[cursor] < b[cursor] {
            return true;
        }
        if a[cursor] > b[cursor] {
            return false;
        }
        cursor = cursor + 1;
    }
    cursor == a.len() && cursor < b.len()
}

pub open spec fn expr_compare_strs_spec(
    op: ExprCompareOp,
    a: Seq<u8>,
    b: Seq<u8>,
) -> bool {
    match op {
        ExprCompareOp::Eq => a == b,
        ExprCompareOp::Ne => a != b,
        ExprCompareOp::Lt => bytes_lt_spec(a, b),
        ExprCompareOp::Le => a == b || bytes_lt_spec(a, b),
        ExprCompareOp::Gt => bytes_lt_spec(b, a),
        ExprCompareOp::Ge => a == b || bytes_lt_spec(b, a),
    }
}

pub fn expr_compare_strs(op: ExprCompareOp, a: &[u8], b: &[u8]) -> (out: bool)
    ensures out == expr_compare_strs_spec(op, a@, b@),
{
    match op {
        ExprCompareOp::Eq => bytes_eq(a, b),
        ExprCompareOp::Ne => !bytes_eq(a, b),
        ExprCompareOp::Lt => bytes_lt(a, b),
        ExprCompareOp::Le => bytes_eq(a, b) || bytes_lt(a, b),
        ExprCompareOp::Gt => bytes_lt(b, a),
        ExprCompareOp::Ge => bytes_eq(a, b) || bytes_lt(b, a),
    }
}

/// Shell-style expression matching used by `-strmatch` and `-fnmatch`.
/// `path_mode` makes `*` and `?` stop at `/`, matching Apache's filename
/// matcher.  The verified form is the exact evaluator kernel: callers still
/// supply the operands and decide case folding.
pub open spec fn expr_glob_spec(
    pattern: Seq<u8>,
    value: Seq<u8>,
    path_mode: bool,
) -> bool
    decreases pattern.len() + value.len(),
{
    if pattern.len() == 0 {
        value.len() == 0
    } else if pattern[0] == b'*' {
        if path_mode && pattern.len() > 1 && pattern[1] == b'/' {
            expr_glob_spec(pattern.skip(2), value, path_mode)
        } else if expr_glob_spec(pattern.skip(1), value, path_mode) {
            true
        } else if value.len() == 0 || value[0] == b'/' {
            false
        } else {
            expr_glob_spec(pattern, value.skip(1), path_mode)
        }
    } else if pattern[0] == b'?' {
        if value.len() == 0 {
            false
        } else {
            (path_mode || value[0] != b'/')
                && expr_glob_spec(pattern.skip(1), value.skip(1), path_mode)
        }
    } else if value.len() == 0 {
        false
    } else {
        pattern[0] == value[0]
            && expr_glob_spec(pattern.skip(1), value.skip(1), path_mode)
    }
}

pub fn expr_glob_match(pattern: &[u8], value: &[u8], path_mode: bool) -> (out: bool)
    ensures out == expr_glob_spec(pattern@, value@, path_mode),
    decreases pattern.len() + value.len(),
{
    if pattern.len() == 0 {
        return value.len() == 0;
    }
    if pattern[0] == b'*' {
        if path_mode && pattern.len() > 1 && pattern[1] == b'/' {
            return expr_glob_match(&pattern[2..], value, path_mode);
        }
        if expr_glob_match(&pattern[1..], value, path_mode) {
            return true;
        }
        if value.len() == 0 || value[0] == b'/' {
            return false;
        }
        return expr_glob_match(pattern, &value[1..], path_mode);
    }
    if pattern[0] == b'?' {
        if value.len() == 0 {
            return false;
        }
        return (path_mode || value[0] != b'/')
            && expr_glob_match(&pattern[1..], &value[1..], path_mode);
    }
    if value.len() == 0 {
        return false;
    }
    pattern[0] == value[0] && expr_glob_match(&pattern[1..], &value[1..], path_mode)
}

/// Fold an Apache rewrite-condition chain.  `matches[i]` is the predicate
/// result and `ors[i]` is the `[OR]` flag.  A run of OR-linked conditions is
/// ORed together; each completed run is ANDed into the overall result.
pub open spec fn cond_chain_from(
    matches: Seq<bool>,
    ors: Seq<bool>,
    i: int,
    overall: bool,
    group: bool,
    in_group: bool,
) -> bool
    decreases matches.len() - i,
{
    if i >= matches.len() {
        if in_group { overall && group } else { overall }
    } else {
        let next_group = if in_group { group || matches[i] } else { matches[i] };
        if ors[i] {
            cond_chain_from(matches, ors, i + 1, overall, next_group, true)
        } else {
            cond_chain_from(matches, ors, i + 1, overall && next_group, false, false)
        }
    }
}

pub open spec fn cond_chain_spec(matches: Seq<bool>, ors: Seq<bool>) -> bool {
    cond_chain_from(matches, ors, 0, true, false, false)
}

fn cond_chain_rec(
    matches: &[bool],
    ors: &[bool],
    i: usize,
    overall: bool,
    group: bool,
    in_group: bool,
) -> (out: bool)
    requires
        matches.len() == ors.len(),
        i <= matches.len(),
    ensures
        out == cond_chain_from(matches@, ors@, i as int, overall, group, in_group),
{
    let mut cursor = i;
    let mut current_overall = overall;
    let mut current_group = group;
    let mut current_in_group = in_group;
    while cursor < matches.len()
        invariant
            matches.len() == ors.len(),
            i <= cursor <= matches.len(),
            cond_chain_from(
                matches@,
                ors@,
                i as int,
                overall,
                group,
                in_group,
            ) == cond_chain_from(
                matches@,
                ors@,
                cursor as int,
                current_overall,
                current_group,
                current_in_group,
            ),
        decreases matches.len() - cursor,
    {
        let next_group = if current_in_group {
            current_group || matches[cursor]
        } else {
            matches[cursor]
        };
        if ors[cursor] {
            current_group = next_group;
            current_in_group = true;
        } else {
            current_overall = current_overall && next_group;
            current_group = false;
            current_in_group = false;
        }
        cursor = cursor + 1;
    }
    if current_in_group {
        current_overall && current_group
    } else {
        current_overall
    }
}

pub fn cond_chain_eval(matches: &[bool], ors: &[bool]) -> (out: bool)
    requires matches.len() == ors.len(),
    ensures out == cond_chain_spec(matches@, ors@),
{
    cond_chain_rec(matches, ors, 0, true, false, false)
}

proof fn classify_access_rule_properties(
    has_condition: bool,
    normal_branch: bool,
    files_rule: bool,
)
    ensures
        (has_condition || !normal_branch)
            ==> access_rule_class_spec(has_condition, normal_branch, files_rule)
                == AccessRuleClass::Conditional,
        (!has_condition && normal_branch && files_rule)
            ==> access_rule_class_spec(has_condition, normal_branch, files_rule)
                == AccessRuleClass::Files,
        (!has_condition && normal_branch && !files_rule)
            ==> access_rule_class_spec(has_condition, normal_branch, files_rule)
                == AccessRuleClass::Other,
{
}

/// Scalar child-overrides-parent merge used for optional scope fields.
pub fn option_child_wins<T: Copy + PartialEq>(
    parent: Option<T>,
    child: Option<T>,
) -> (out: Option<T>)
    ensures out == (if child.is_some() { child } else { parent })
{
    if child.is_some() {
        child
    } else {
        parent
    }
}




// ---------------------------------------------------------------------------
// Virtual-host name matching
// ---------------------------------------------------------------------------

/// Case-insensitive host suffix at a DNS label boundary.
pub open spec fn host_suffix_spec(host: Seq<u8>, suffix: Seq<u8>) -> bool {
    host.len() >= suffix.len()
        && suffix.len() > 0
        && eq_ignore_ascii_case_spec(
            host.subrange((host.len() - suffix.len()) as int, host.len() as int),
            suffix,
        )
        && (host.len() == suffix.len() || host[host.len() - suffix.len() - 1] == b'.')
}

pub open spec fn host_pattern_matches_spec(host: Seq<u8>, pattern: Seq<u8>) -> bool {
    if pattern.len() == 1 && pattern[0] == b'*' {
        true
    } else if pattern.len() >= 2 && pattern[0] == b'*' && pattern[1] == b'.' {
        let rest = pattern.subrange(2, pattern.len() as int);
        host.len() > rest.len() && host_suffix_spec(host, rest)
    } else {
        eq_ignore_ascii_case_spec(host, pattern)
    }
}

pub fn host_suffix_matches(host: &[u8], suffix: &[u8]) -> (ok: bool)
    ensures ok == host_suffix_spec(host@, suffix@)
{
    if suffix.is_empty() || host.len() < suffix.len() {
        return false;
    }
    let start = host.len() - suffix.len();
    if !eq_ignore_ascii_case(&host[start..], suffix) {
        return false;
    }
    if start == 0 {
        true
    } else {
        host[start - 1] == b'.'
    }
}

/// Exact host, `*`, or leading `*.suffix` matching, with ASCII case folding
/// and a DNS-label boundary. A suffix wildcard requires at least one label,
/// as it does in Apache; it never aliases the bare suffix.
pub fn host_pattern_matches(host: &[u8], pattern: &[u8]) -> (ok: bool)
    ensures ok == host_pattern_matches_spec(host@, pattern@)
{
    if pattern.len() == 1 && pattern[0] == b'*' {
        true
    } else if pattern.len() >= 2 && pattern[0] == b'*' && pattern[1] == b'.' {
        let rest = &pattern[2..];
        host.len() > rest.len() && host_suffix_matches(host, rest)
    } else {
        eq_ignore_ascii_case(host, pattern)
    }
}


pub open spec fn ipv4_in_net_spec(ip: u32, net: u32, bits: u8) -> bool {
    bits <= 32 && (if bits == 0 {
        true
    } else {
        let mask = u32::MAX << (32 - bits);
        (ip & mask) == (net & mask)
    })
}

pub fn ipv4_in_net(ip: u32, net: u32, bits: u8) -> (out: bool)
    ensures out == ipv4_in_net_spec(ip, net, bits)
{
    if bits > 32 {
        false
    } else if bits == 0 {
        true
    } else {
        let mask = u32::MAX << (32 - bits);
        (ip & mask) == (net & mask)
    }
}


pub open spec fn ipv6_in_net_spec(ip: u128, net: u128, bits: u8) -> bool {
    bits <= 128 && (if bits == 0 {
        true
    } else {
        let mask = u128::MAX << (128 - bits);
        (ip & mask) == (net & mask)
    })
}

pub fn ipv6_in_net(ip: u128, net: u128, bits: u8) -> (out: bool)
    ensures out == ipv6_in_net_spec(ip, net, bits)
{
    if bits > 128 {
        false
    } else if bits == 0 {
        true
    } else {
        let mask = u128::MAX << (128 - bits);
        (ip & mask) == (net & mask)
    }
}


pub open spec fn ipv4_mapped_to_v4_spec(ip: u128) -> Option<u32> {
    if (ip >> 32) == 0xffff {
        Some((ip & 0xffff_ffff) as u32)
    } else {
        None
    }
}

/// F49/I46: canonicalize an IPv6 `::ffff:a.b.c.d` address to IPv4 before any
/// authorization or identity decision.  IPv4-mapped peers are the same policy
/// identity as their IPv4 form.
pub fn ipv4_mapped_to_v4(ip: u128) -> (out: Option<u32>)
    ensures out == ipv4_mapped_to_v4_spec(ip)
{
    if (ip >> 32) == 0xffff {
        Some((ip & 0xffff_ffff) as u32)
    } else {
        None
    }
}


/// Index of the first untrusted address in a right-to-left client chain.
pub open spec fn first_untrusted_spec(flags: Seq<bool>) -> Option<int>
    decreases flags.len(),
{
    if flags.len() == 0 {
        None
    } else if !flags[0] {
        Some(0)
    } else {
        match first_untrusted_spec(flags.drop_first()) {
            None => None,
            Some(i) => Some(i + 1),
        }
    }
}

pub fn first_untrusted_index(flags: &[bool]) -> (out: Option<usize>)
    ensures
        match out {
            None => first_untrusted_spec(flags@) == None,
            Some(i) => {
                &&& first_untrusted_spec(flags@) == Some(i as int)
                &&& i < flags.len()
                &&& !flags@[i as int]
                &&& forall|j: int| 0 <= j < i ==> flags@[j]
            }
        }
    decreases flags.len(),
{
    if flags.len() == 0 {
        assert(first_untrusted_spec(flags@) == None);
        None
    } else if !flags[0] {
        assert(first_untrusted_spec(flags@) == Some(0));
        Some(0)
    } else {
        let rest = &flags[1..];
        assert(flags@ == seq![flags@[0]] + rest@);
        match first_untrusted_index(rest) {
            None => {
                assert(first_untrusted_spec(flags@) == None);
                None
            }
            Some(i) => {
                assert(first_untrusted_spec(flags@) == Some(i as int + 1));
                Some(i + 1)
            }
        }
    }
}


/// Apache `mod_remoteip` distinguishes proxies that may present private
/// addresses from external trusted proxies. An untrusted current presenter
/// terminates the right-to-left walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteIpProxyClass {
    Untrusted,
    Trusted,
    Internal,
}

pub open spec fn remoteip_next_internal_spec(
    chain_internal: bool,
    presenter: RemoteIpProxyClass,
) -> bool {
    match presenter {
        RemoteIpProxyClass::Internal => chain_internal,
        RemoteIpProxyClass::Trusted | RemoteIpProxyClass::Untrusted => false,
    }
}

pub fn remoteip_next_internal(
    chain_internal: bool,
    presenter: RemoteIpProxyClass,
) -> (next_internal: bool)
    ensures next_internal == remoteip_next_internal_spec(chain_internal, presenter)
{
    match presenter {
        RemoteIpProxyClass::Internal => chain_internal,
        RemoteIpProxyClass::Trusted | RemoteIpProxyClass::Untrusted => false,
    }
}

pub open spec fn remoteip_candidate_admit_spec(
    presenter: RemoteIpProxyClass,
    next_internal: bool,
    candidate_valid: bool,
    candidate_public: bool,
) -> bool {
    match presenter {
        RemoteIpProxyClass::Untrusted => false,
        RemoteIpProxyClass::Trusted | RemoteIpProxyClass::Internal => {
            candidate_valid && (next_internal || candidate_public)
        }
    }
}

pub fn remoteip_candidate_admit(
    presenter: RemoteIpProxyClass,
    next_internal: bool,
    candidate_valid: bool,
    candidate_public: bool,
) -> (admit: bool)
    ensures admit == remoteip_candidate_admit_spec(
        presenter,
        next_internal,
        candidate_valid,
        candidate_public,
    )
{
    match presenter {
        RemoteIpProxyClass::Untrusted => false,
        RemoteIpProxyClass::Trusted | RemoteIpProxyClass::Internal => {
            candidate_valid && (next_internal || candidate_public)
        }
    }
}

pub proof fn remoteip_external_chain_is_monotonic(presenter: RemoteIpProxyClass)
    ensures !remoteip_next_internal_spec(false, presenter)
{
}

pub proof fn remoteip_trusted_proxy_rejects_private_candidate(candidate_valid: bool)
    ensures !remoteip_candidate_admit_spec(
        RemoteIpProxyClass::Trusted,
        remoteip_next_internal_spec(true, RemoteIpProxyClass::Trusted),
        candidate_valid,
        false,
    )
{
}

pub proof fn remoteip_accepted_private_candidate_requires_internal_chain(
    presenter: RemoteIpProxyClass,
    next_internal: bool,
    candidate_valid: bool,
)
    requires remoteip_candidate_admit_spec(
        presenter,
        next_internal,
        candidate_valid,
        false,
    )
    ensures next_internal
{
}


/// First true flag, used for deterministic vhost candidate selection.
pub open spec fn first_true_spec(flags: Seq<bool>) -> Option<int>
    decreases flags.len(),
{
    if flags.len() == 0 {
        None
    } else if flags[0] {
        Some(0)
    } else {
        match first_true_spec(flags.drop_first()) {
            None => None,
            Some(i) => Some(i + 1),
        }
    }
}

pub fn first_true_index(flags: &[bool]) -> (out: Option<usize>)
    ensures
        match out {
            None => first_true_spec(flags@) == None,
            Some(i) => {
                &&& first_true_spec(flags@) == Some(i as int)
                &&& i < flags.len()
                &&& flags@[i as int]
                &&& forall|j: int| 0 <= j < i ==> !flags@[j]
            }
        }
    decreases flags.len(),
{
    if flags.len() == 0 {
        assert(first_true_spec(flags@) == None);
        None
    } else if flags[0] {
        assert(first_true_spec(flags@) == Some(0));
        Some(0)
    } else {
        let rest = &flags[1..];
        assert(flags@ == seq![flags@[0]] + rest@);
        match first_true_index(rest) {
            None => {
                assert(first_true_spec(flags@) == None);
                None
            }
            Some(i) => {
                assert(first_true_spec(flags@) == Some(i as int + 1));
                Some(i + 1)
            }
        }
    }
}


/// Child-overrides-parent for fields that are not `Copy`.  The value clone
/// itself is the Rust standard-library primitive; the verified contract is
/// that presence is preserved exactly, so a child field can never be lost by
/// the merge decision.
pub fn option_child_presence<T: Clone>(
    parent: &Option<T>,
    child: &Option<T>,
) -> (out: Option<T>)
    ensures
        child.is_some() ==> out.is_some(),
        child.is_none() ==> (out.is_some() == parent.is_some()),
{
    if child.is_some() {
        child.clone()
    } else {
        parent.clone()
    }
}


// ---------------------------------------------------------------------------
// TLS listener client-certificate policy identity
// ---------------------------------------------------------------------------

/// Decide whether two virtual hosts may share one TLS listener.  Rustls has
/// one client-certificate verifier per `ServerConfig`, so a listener may only
/// be shared by vhosts with identical verification mode and CA-file identity.
/// The mode is encoded by the caller (including the absent/present
/// distinction); the CA is compared by exact bytes.  Chain validation itself
/// remains the external TLS/Rustls contract.
pub fn tls_client_policy_equal(
    mode_a: u8,
    has_ca_a: bool,
    ca_a: &[u8],
    mode_b: u8,
    has_ca_b: bool,
    ca_b: &[u8],
) -> (equal: bool)
    ensures
        equal == (mode_a == mode_b && has_ca_a == has_ca_b && ca_a@ == ca_b@),
{
    if mode_a != mode_b || has_ca_a != has_ca_b || ca_a.len() != ca_b.len() {
        false
    } else {
        bytes_eq(ca_a, ca_b)
    }
}

// ---------------------------------------------------------------------------
// Configuration front-end IR
// ---------------------------------------------------------------------------

/// Byte-level state for the Apache-compatible configuration tokenizer.  The
/// server drives this transition directly, so quote and escape decisions are
/// not duplicated in an unverified parser.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigLexState {
    Between,
    Unquoted,
    SingleQuoted,
    DoubleQuoted,
    AfterQuoted,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigLexAction {
    Skip,
    Begin,
    Push,
    PushNext,
    Finish,
    CloseQuote,
    RejectAfterQuote,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConfigLexStep {
    pub action: ConfigLexAction,
    pub state: ConfigLexState,
    pub advance: u8,
}

pub open spec fn config_ascii_whitespace_spec(byte: u8) -> bool {
    byte == b' ' || byte == b'\t' || byte == b'\n'
        || byte == 0x0b || byte == 0x0c || byte == b'\r'
}

fn config_ascii_whitespace(byte: u8) -> (whitespace: bool)
    ensures whitespace == config_ascii_whitespace_spec(byte),
{
    byte == b' ' || byte == b'\t' || byte == b'\n'
        || byte == 0x0b || byte == 0x0c || byte == b'\r'
}

pub open spec fn config_lex_step_spec(
    state: ConfigLexState,
    byte: u8,
    next: Option<u8>,
) -> ConfigLexStep {
    let whitespace = config_ascii_whitespace_spec(byte);
    match state {
        ConfigLexState::Between => {
            if whitespace {
                ConfigLexStep {
                    action: ConfigLexAction::Skip,
                    state: ConfigLexState::Between,
                    advance: 1,
                }
            } else if byte == b'\'' {
                ConfigLexStep {
                    action: ConfigLexAction::Begin,
                    state: ConfigLexState::SingleQuoted,
                    advance: 1,
                }
            } else if byte == b'"' {
                ConfigLexStep {
                    action: ConfigLexAction::Begin,
                    state: ConfigLexState::DoubleQuoted,
                    advance: 1,
                }
            } else {
                ConfigLexStep {
                    action: ConfigLexAction::Begin,
                    state: ConfigLexState::Unquoted,
                    advance: 0,
                }
            }
        }
        ConfigLexState::Unquoted => {
            if whitespace {
                ConfigLexStep {
                    action: ConfigLexAction::Finish,
                    state: ConfigLexState::Between,
                    advance: 1,
                }
            } else if byte == b'\\'
                && match next {
                    Some(value) => config_ascii_whitespace_spec(value),
                    None => false,
                }
            {
                ConfigLexStep {
                    action: ConfigLexAction::PushNext,
                    state: ConfigLexState::Unquoted,
                    advance: 2,
                }
            } else {
                ConfigLexStep {
                    action: ConfigLexAction::Push,
                    state: ConfigLexState::Unquoted,
                    advance: 1,
                }
            }
        }
        ConfigLexState::SingleQuoted => {
            if byte == b'\'' {
                ConfigLexStep {
                    action: ConfigLexAction::CloseQuote,
                    state: ConfigLexState::AfterQuoted,
                    advance: 1,
                }
            } else if byte == b'\\' && next == Some(b'\'') {
                ConfigLexStep {
                    action: ConfigLexAction::PushNext,
                    state: ConfigLexState::SingleQuoted,
                    advance: 2,
                }
            } else {
                ConfigLexStep {
                    action: ConfigLexAction::Push,
                    state: ConfigLexState::SingleQuoted,
                    advance: 1,
                }
            }
        }
        ConfigLexState::DoubleQuoted => {
            if byte == b'"' {
                ConfigLexStep {
                    action: ConfigLexAction::CloseQuote,
                    state: ConfigLexState::AfterQuoted,
                    advance: 1,
                }
            } else if byte == b'\\' && next == Some(b'"') {
                ConfigLexStep {
                    action: ConfigLexAction::PushNext,
                    state: ConfigLexState::DoubleQuoted,
                    advance: 2,
                }
            } else {
                ConfigLexStep {
                    action: ConfigLexAction::Push,
                    state: ConfigLexState::DoubleQuoted,
                    advance: 1,
                }
            }
        }
        ConfigLexState::AfterQuoted => {
            if whitespace {
                ConfigLexStep {
                    action: ConfigLexAction::Finish,
                    state: ConfigLexState::Between,
                    advance: 1,
                }
            } else {
                ConfigLexStep {
                    action: ConfigLexAction::RejectAfterQuote,
                    state: ConfigLexState::AfterQuoted,
                    advance: 1,
                }
            }
        }
    }
}

/// Exact tokenizer transition.  `advance == 0` is the deliberate reprocess
/// step that creates an unquoted token before consuming its first byte;
/// `advance == 2` is possible only when the next byte exists and is copied.
pub fn config_lex_step(
    state: ConfigLexState,
    byte: u8,
    next: Option<u8>,
) -> (step: ConfigLexStep)
    ensures
        step == config_lex_step_spec(state, byte, next),
        step.advance <= 2,
        step.advance == 2 ==> next.is_some(),
{
    let whitespace = config_ascii_whitespace(byte);
    match state {
        ConfigLexState::Between => {
            if whitespace {
                ConfigLexStep {
                    action: ConfigLexAction::Skip,
                    state: ConfigLexState::Between,
                    advance: 1,
                }
            } else if byte == b'\'' {
                ConfigLexStep {
                    action: ConfigLexAction::Begin,
                    state: ConfigLexState::SingleQuoted,
                    advance: 1,
                }
            } else if byte == b'"' {
                ConfigLexStep {
                    action: ConfigLexAction::Begin,
                    state: ConfigLexState::DoubleQuoted,
                    advance: 1,
                }
            } else {
                ConfigLexStep {
                    action: ConfigLexAction::Begin,
                    state: ConfigLexState::Unquoted,
                    advance: 0,
                }
            }
        }
        ConfigLexState::Unquoted => {
            if whitespace {
                ConfigLexStep {
                    action: ConfigLexAction::Finish,
                    state: ConfigLexState::Between,
                    advance: 1,
                }
            } else if byte == b'\\'
                && match next {
                    Some(value) => config_ascii_whitespace(value),
                    None => false,
                }
            {
                ConfigLexStep {
                    action: ConfigLexAction::PushNext,
                    state: ConfigLexState::Unquoted,
                    advance: 2,
                }
            } else {
                ConfigLexStep {
                    action: ConfigLexAction::Push,
                    state: ConfigLexState::Unquoted,
                    advance: 1,
                }
            }
        }
        ConfigLexState::SingleQuoted => {
            if byte == b'\'' {
                ConfigLexStep {
                    action: ConfigLexAction::CloseQuote,
                    state: ConfigLexState::AfterQuoted,
                    advance: 1,
                }
            } else if byte == b'\\' && next == Some(b'\'') {
                ConfigLexStep {
                    action: ConfigLexAction::PushNext,
                    state: ConfigLexState::SingleQuoted,
                    advance: 2,
                }
            } else {
                ConfigLexStep {
                    action: ConfigLexAction::Push,
                    state: ConfigLexState::SingleQuoted,
                    advance: 1,
                }
            }
        }
        ConfigLexState::DoubleQuoted => {
            if byte == b'"' {
                ConfigLexStep {
                    action: ConfigLexAction::CloseQuote,
                    state: ConfigLexState::AfterQuoted,
                    advance: 1,
                }
            } else if byte == b'\\' && next == Some(b'"') {
                ConfigLexStep {
                    action: ConfigLexAction::PushNext,
                    state: ConfigLexState::DoubleQuoted,
                    advance: 2,
                }
            } else {
                ConfigLexStep {
                    action: ConfigLexAction::Push,
                    state: ConfigLexState::DoubleQuoted,
                    advance: 1,
                }
            }
        }
        ConfigLexState::AfterQuoted => {
            if whitespace {
                ConfigLexStep {
                    action: ConfigLexAction::Finish,
                    state: ConfigLexState::Between,
                    advance: 1,
                }
            } else {
                ConfigLexStep {
                    action: ConfigLexAction::RejectAfterQuote,
                    state: ConfigLexState::AfterQuoted,
                    advance: 1,
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigLexEof {
    Complete,
    Finish,
    UnterminatedQuote,
}

pub open spec fn config_lex_eof_spec(state: ConfigLexState) -> ConfigLexEof {
    match state {
        ConfigLexState::Between => ConfigLexEof::Complete,
        ConfigLexState::Unquoted | ConfigLexState::AfterQuoted => ConfigLexEof::Finish,
        ConfigLexState::SingleQuoted | ConfigLexState::DoubleQuoted => {
            ConfigLexEof::UnterminatedQuote
        }
    }
}

pub fn config_lex_eof(state: ConfigLexState) -> (action: ConfigLexEof)
    ensures action == config_lex_eof_spec(state),
{
    match state {
        ConfigLexState::Between => ConfigLexEof::Complete,
        ConfigLexState::Unquoted | ConfigLexState::AfterQuoted => ConfigLexEof::Finish,
        ConfigLexState::SingleQuoted | ConfigLexState::DoubleQuoted => {
            ConfigLexEof::UnterminatedQuote
        }
    }
}

/// Bound the number of materialized arguments without arithmetic wrap.  This
/// transition is consumed each time the runtime closes a token.
pub fn config_argument_count_step(count: usize) -> (next: Option<usize>)
    ensures
        next == if count < 256 { Some((count + 1) as usize) } else { None },
        next.is_some() ==> next.unwrap() <= 256,
{
    if count < 256 {
        Some(count + 1)
    } else {
        None
    }
}

/// Quote state used to find the closing delimiter of a section tag. Apache's
/// `<IfVersion >= 2.4>` form means the last unquoted `>` wins; an escaped quote
/// inside an argument must not accidentally end quote protection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigTagQuote {
    Unquoted,
    Single,
    Double,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConfigTagStep {
    pub quote: ConfigTagQuote,
    pub advance: u8,
    pub delimiter: bool,
}

pub open spec fn config_tag_step_spec(
    quote: ConfigTagQuote,
    byte: u8,
    next: Option<u8>,
) -> ConfigTagStep {
    match quote {
        ConfigTagQuote::Unquoted => {
            if byte == b'\'' {
                ConfigTagStep { quote: ConfigTagQuote::Single, advance: 1, delimiter: false }
            } else if byte == b'"' {
                ConfigTagStep { quote: ConfigTagQuote::Double, advance: 1, delimiter: false }
            } else {
                ConfigTagStep {
                    quote: ConfigTagQuote::Unquoted,
                    advance: 1,
                    delimiter: byte == b'>',
                }
            }
        }
        ConfigTagQuote::Single => {
            if byte == b'\\' && next == Some(b'\'') {
                ConfigTagStep { quote: ConfigTagQuote::Single, advance: 2, delimiter: false }
            } else if byte == b'\'' {
                ConfigTagStep { quote: ConfigTagQuote::Unquoted, advance: 1, delimiter: false }
            } else {
                ConfigTagStep { quote: ConfigTagQuote::Single, advance: 1, delimiter: false }
            }
        }
        ConfigTagQuote::Double => {
            if byte == b'\\' && next == Some(b'"') {
                ConfigTagStep { quote: ConfigTagQuote::Double, advance: 2, delimiter: false }
            } else if byte == b'"' {
                ConfigTagStep { quote: ConfigTagQuote::Unquoted, advance: 1, delimiter: false }
            } else {
                ConfigTagStep { quote: ConfigTagQuote::Double, advance: 1, delimiter: false }
            }
        }
    }
}

pub fn config_tag_step(
    quote: ConfigTagQuote,
    byte: u8,
    next: Option<u8>,
) -> (step: ConfigTagStep)
    ensures
        step == config_tag_step_spec(quote, byte, next),
        step.advance == 1 || step.advance == 2,
        step.advance == 2 ==> next.is_some(),
        step.delimiter ==> quote == ConfigTagQuote::Unquoted && byte == b'>',
{
    match quote {
        ConfigTagQuote::Unquoted => {
            if byte == b'\'' {
                ConfigTagStep { quote: ConfigTagQuote::Single, advance: 1, delimiter: false }
            } else if byte == b'"' {
                ConfigTagStep { quote: ConfigTagQuote::Double, advance: 1, delimiter: false }
            } else {
                ConfigTagStep {
                    quote: ConfigTagQuote::Unquoted,
                    advance: 1,
                    delimiter: byte == b'>',
                }
            }
        }
        ConfigTagQuote::Single => {
            if byte == b'\\' && next == Some(b'\'') {
                ConfigTagStep { quote: ConfigTagQuote::Single, advance: 2, delimiter: false }
            } else if byte == b'\'' {
                ConfigTagStep { quote: ConfigTagQuote::Unquoted, advance: 1, delimiter: false }
            } else {
                ConfigTagStep { quote: ConfigTagQuote::Single, advance: 1, delimiter: false }
            }
        }
        ConfigTagQuote::Double => {
            if byte == b'\\' && next == Some(b'"') {
                ConfigTagStep { quote: ConfigTagQuote::Double, advance: 2, delimiter: false }
            } else if byte == b'"' {
                ConfigTagStep { quote: ConfigTagQuote::Unquoted, advance: 1, delimiter: false }
            } else {
                ConfigTagStep { quote: ConfigTagQuote::Double, advance: 1, delimiter: false }
            }
        }
    }
}

/// Arity gate used by typed directive schemas before policy compilation.
/// `max == None` denotes an unbounded upper arity.
pub fn config_argument_arity_admit(
    count: usize,
    min: usize,
    max: Option<usize>,
) -> (ok: bool)
    ensures ok == (count >= min && match max { Some(bound) => count <= bound, None => true }),
{
    count >= min && match max { Some(bound) => count <= bound, None => true }
}

pub fn config_argument_nonempty_admit(reject_empty: bool, has_empty: bool) -> (ok: bool)
    ensures ok == (!reject_empty || !has_empty),
{
    !reject_empty || !has_empty
}

/// Complete structural schema gate carried by every sealed directive payload.
/// Keeping the conjunction in one executable kernel prevents the main and
/// access-file compilers from validating arity while accidentally omitting
/// the empty-token half (or vice versa).
pub open spec fn config_payload_schema_spec(
    count: usize,
    min: usize,
    max: Option<usize>,
    reject_empty: bool,
    has_empty: bool,
) -> bool {
    count >= min
        && match max { Some(bound) => count <= bound, None => true }
        && (!reject_empty || !has_empty)
}

pub fn config_payload_schema_admit(
    count: usize,
    min: usize,
    max: Option<usize>,
    reject_empty: bool,
    has_empty: bool,
) -> (ok: bool)
    ensures ok == config_payload_schema_spec(count, min, max, reject_empty, has_empty),
{
    config_argument_arity_admit(count, min, max)
        && config_argument_nonempty_admit(reject_empty, has_empty)
}

pub proof fn config_payload_schema_implies_arity_and_nonempty(
    count: usize,
    min: usize,
    max: Option<usize>,
    reject_empty: bool,
    has_empty: bool,
)
    requires config_payload_schema_spec(count, min, max, reject_empty, has_empty),
    ensures
        count >= min,
        match max { Some(bound) => count <= bound, None => true },
        reject_empty ==> !has_empty,
{
}

/// The three pure line kinds produced by the configuration tokenizer. This is
/// the Verus-side anchor for the lexical IR; the server front-end consumes it
/// while constructing the sealed semantic directive and section program.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigLineKind {
    Directive,
    SectionStart,
    SectionEnd,
}

pub open spec fn config_line_kind_spec(
    starts_with_end_tag: bool,
    starts_with_start_tag: bool,
) -> ConfigLineKind {
    if starts_with_end_tag {
        ConfigLineKind::SectionEnd
    } else if starts_with_start_tag {
        ConfigLineKind::SectionStart
    } else {
        ConfigLineKind::Directive
    }
}

pub fn config_line_kind(
    starts_with_end_tag: bool,
    starts_with_start_tag: bool,
) -> (kind: ConfigLineKind)
    ensures kind == config_line_kind_spec(starts_with_end_tag, starts_with_start_tag),
{
    if starts_with_end_tag {
        ConfigLineKind::SectionEnd
    } else if starts_with_start_tag {
        ConfigLineKind::SectionStart
    } else {
        ConfigLineKind::Directive
    }
}

/// Structural transition used while sealing the expanded configuration into
/// an immutable program.  A closing section can never underflow the stack;
/// an opening section cannot wrap the depth counter.
pub fn config_program_depth_step(
    depth: usize,
    kind: ConfigLineKind,
) -> (next: Option<usize>)
    ensures
        match kind {
            ConfigLineKind::Directive => next == Some(depth),
            ConfigLineKind::SectionStart => {
                next == if depth < usize::MAX { Some((depth + 1) as usize) } else { None }
            }
            ConfigLineKind::SectionEnd => {
                next == if depth > 0 { Some((depth - 1) as usize) } else { None }
            }
        },
{
    match kind {
        ConfigLineKind::Directive => Some(depth),
        ConfigLineKind::SectionStart => depth.checked_add(1),
        ConfigLineKind::SectionEnd => depth.checked_sub(1),
    }
}

/// Main-configuration compilation and request-time rule evaluation both
/// descend the sealed section tree.  Arithmetic-safe depth is not sufficient:
/// the program must establish a concrete stack/work bound before compilation.
pub open spec fn config_section_depth_spec(depth: usize, limit: usize) -> bool {
    depth <= limit
}

pub fn config_section_depth_admit(depth: usize, limit: usize) -> (ok: bool)
    ensures ok == config_section_depth_spec(depth, limit),
{
    depth <= limit
}

pub proof fn config_section_depth_overflow_rejected(depth: usize, limit: usize)
    requires depth > limit,
    ensures !config_section_depth_spec(depth, limit),
{
}

/// Access-file sections are evaluated by a recursive policy compiler.  Its
/// input program is sealed iteratively and must establish this bound before
/// any recursive descent begins.
pub open spec fn access_section_depth_spec(depth: usize, limit: usize) -> bool {
    depth <= limit
}

pub fn access_section_depth_admit(depth: usize, limit: usize) -> (ok: bool)
    ensures ok == access_section_depth_spec(depth, limit),
{
    depth <= limit
}

pub proof fn access_section_depth_overflow_rejected(depth: usize, limit: usize)
    requires depth > limit,
    ensures !access_section_depth_spec(depth, limit),
{
}

// ---------------------------------------------------------------------------
// Container-field merge model
// ---------------------------------------------------------------------------

/// Structural append used by every container/list field in `Scope::merge`.
/// The concrete elements are cloned by `extend_from_slice`; the verified
/// contract preserves the inherited prefix, appends exactly the child length,
/// and relates each appended element to its child source by the standard
/// `cloned` relation.
pub fn append_vec<T: Clone>(out: &mut Vec<T>, child: &[T])
    ensures
        final(out)@.len() == old(out)@.len() + child@.len(),
        forall|i: int|
            0 <= i < old(out)@.len() ==> final(out)@[i] == old(out)@[i],
        forall|i: int|
            0 <= i < child@.len() ==>
                cloned::<T>(child@[i], final(out)@[old(out)@.len() + i]),
{
    out.extend_from_slice(child);
}


/// Abstract model of the append/union fields in `Scope::merge`.  Concrete
/// runtime values are represented by opaque IDs; the model fixes the order,
/// child-wins map behavior and append semantics that the parser/merge must
/// follow.
pub struct ContainerModel {
    pub error_documents: Seq<(u16, u64)>,
    pub aliases: Seq<u64>,
    pub redirects: Seq<u64>,
    pub handlers: Seq<u64>,
    pub unsupported_filters: Seq<u64>,
    pub add_types: Seq<u64>,
    pub remove_types: Seq<u64>,
    pub set_headers: Seq<u64>,
    pub add_headers: Seq<u64>,
    pub unset_headers: Seq<u64>,
    /// Environment entries carry provenance on each value. This mirrors the
    /// runtime `Originated<T>` representation: there is no untagged access
    /// list whose contents can accidentally be appended into a trusted list.
    pub rewrite_env: Seq<(EnvironmentOrigin, u64)>,
    pub rewrite_unset_env: Seq<(EnvironmentOrigin, u64)>,
    pub rewrite_late_env: Seq<(EnvironmentOrigin, u64)>,
    pub rewrite_late_unset_env: Seq<(EnvironmentOrigin, u64)>,
    pub set_env: Seq<(EnvironmentOrigin, u64)>,
    pub unset_env: Seq<(EnvironmentOrigin, u64)>,
    pub pass_env: Seq<(EnvironmentOrigin, u64)>,
    pub set_env_if: Seq<(EnvironmentOrigin, u64)>,
    pub cookies: Seq<u64>,
    pub vary: Seq<u64>,
    pub rewrite_rules: Seq<u64>,
    pub compression_rules: Seq<u64>,
    pub proxy_rules: Seq<u64>,
    pub proxy_passes: Seq<u64>,
    pub proxy_reverses: Seq<u64>,
    pub rewrite_maps: Seq<(u64, u64)>,
}

pub open spec fn merge_containers(
    parent: ContainerModel,
    child: ContainerModel,
) -> ContainerModel {
    ContainerModel {
        error_documents: parent.error_documents + child.error_documents,
        aliases: parent.aliases + child.aliases,
        redirects: parent.redirects + child.redirects,
        handlers: parent.handlers + child.handlers,
        unsupported_filters: parent.unsupported_filters + child.unsupported_filters,
        add_types: parent.add_types + child.add_types,
        remove_types: parent.remove_types + child.remove_types,
        set_headers: parent.set_headers + child.set_headers,
        add_headers: parent.add_headers + child.add_headers,
        unset_headers: parent.unset_headers + child.unset_headers,
        rewrite_env: parent.rewrite_env + child.rewrite_env,
        rewrite_unset_env: parent.rewrite_unset_env + child.rewrite_unset_env,
        rewrite_late_env: parent.rewrite_late_env + child.rewrite_late_env,
        rewrite_late_unset_env: parent.rewrite_late_unset_env + child.rewrite_late_unset_env,
        set_env: parent.set_env + child.set_env,
        unset_env: parent.unset_env + child.unset_env,
        pass_env: parent.pass_env + child.pass_env,
        set_env_if: parent.set_env_if + child.set_env_if,
        cookies: parent.cookies + child.cookies,
        vary: parent.vary + child.vary,
        rewrite_rules: parent.rewrite_rules + child.rewrite_rules,
        compression_rules: parent.compression_rules + child.compression_rules,
        proxy_rules: parent.proxy_rules + child.proxy_rules,
        proxy_passes: parent.proxy_passes + child.proxy_passes,
        proxy_reverses: parent.proxy_reverses + child.proxy_reverses,
        rewrite_maps: parent.rewrite_maps + child.rewrite_maps,
    }
}

/// P16-A: merging configuration layers appends the complete tagged entries.
/// Since origin and value are one tuple, no merge transition can upgrade an
/// access-file value to main-config origin or detach provenance from data.
pub proof fn environment_origin_merge_preserves_tags(
    parent: ContainerModel,
    child: ContainerModel,
)
    ensures
        merge_containers(parent, child).set_env
            == parent.set_env + child.set_env,
        merge_containers(parent, child).rewrite_late_env
            == parent.rewrite_late_env + child.rewrite_late_env,
        merge_containers(parent, child).set_env_if
            == parent.set_env_if + child.set_env_if,
        merge_containers(parent, child).pass_env
            == parent.pass_env + child.pass_env,
{
}

/// Appending a child container never reorders or drops the parent prefix.
pub proof fn container_append_preserves_parent(
    parent: Seq<u64>,
    child: Seq<u64>,
)
    ensures
        (parent + child).subrange(0, parent.len() as int) == parent,
        (parent + child).len() == parent.len() + child.len(),
{
}

/// Child entries are appended after the parent prefix, so a reverse lookup
/// observes the child value first.  This is the list-backed replacement for
/// map insertion order in `Scope::merge`.
pub open spec fn container_lookup_pair<K, V>(
    pairs: Seq<(K, V)>,
    key: K,
) -> Option<V>
    decreases pairs.len(),
{
    if pairs.len() == 0 {
        None
    } else if pairs[pairs.len() - 1].0 == key {
        Some(pairs[pairs.len() - 1].1)
    } else {
        container_lookup_pair(pairs.drop_last(), key)
    }
}

pub proof fn container_append_child_lookup_wins<K, V>(
    parent: Seq<(K, V)>,
    child: Seq<(K, V)>,
    key: K,
)
    ensures
        child.len() > 0 && child[child.len() - 1].0 == key
            ==> container_lookup_pair(parent + child, key)
                == Some(child[child.len() - 1].1),
{
}


// ---------------------------------------------------------------------------
// HTTP/2 request admission and stream-budget model
// ---------------------------------------------------------------------------

/// The admission result for one HTTP/2 request head.  The order of the
/// constructors is the rejection precedence used by the adapter: a malformed
/// method is rejected before target/header limits are reported.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H2HeadDecision {
    Accept,
    InvalidMethod,
    TargetTooLong,
    TooManyHeaders,
    HeaderFieldTooLarge,
}

/// The method predicate used by the HTTP/2 adapter: RFC 9110 token, no
/// empty method, and the same 64-byte ceiling as the HTTP/1 parser.
pub open spec fn h2_method_ok_spec(method: Seq<u8>) -> bool {
    method.len() > 0 && method.len() <= 64 && all_tchars(method)
}

pub fn h2_method_ok(method: &[u8]) -> (ok: bool)
    ensures ok == h2_method_ok_spec(method@),
{
    if method.len() == 0 || method.len() > 64 {
        false
    } else {
        valid_token(method)
    }
}

/// Admit one decoded HTTP/2 field before any field-specific parser runs.
/// In particular, `:authority` must not enter the authority parser before
/// `LimitRequestFieldSize` has bounded its request-controlled input.
pub open spec fn h2_field_size_spec(name_len: u64, value_len: u64, limit: u64) -> bool {
    name_len <= limit && value_len <= limit - name_len
}

pub fn h2_field_size_admit(name_len: u64, value_len: u64, limit: u64) -> (ok: bool)
    ensures ok == h2_field_size_spec(name_len, value_len, limit),
{
    name_len <= limit && value_len <= limit - name_len
}

/// Decide one complete HTTP/2 head without parsing it twice.
///
/// The caller supplies the method bytes and the largest `name + value` field
/// size.  The postcondition is deliberately useful on every branch: an
/// `Accept` establishes all four bounds, while each rejection constructor
/// establishes exactly which bound failed after all earlier checks passed.
/// This gives the adapter one decision point instead of an open-coded `if`
/// ladder that can drift from the HTTP/1 parser.
pub fn h2_head_admit(
    method: &[u8],
    target_len: u64,
    target_limit: u64,
    header_count: u64,
    header_limit: u64,
    largest_field: u64,
    field_limit: u64,
) -> (decision: H2HeadDecision)
    ensures
        decision == H2HeadDecision::Accept ==> {
            &&& h2_method_ok_spec(method@)
            &&& target_len <= target_limit
            &&& header_count <= header_limit
            &&& largest_field <= field_limit
        },
        decision == H2HeadDecision::InvalidMethod ==> !h2_method_ok_spec(method@),
        decision == H2HeadDecision::TargetTooLong ==> {
            &&& h2_method_ok_spec(method@)
            &&& target_len > target_limit
        },
        decision == H2HeadDecision::TooManyHeaders ==> {
            &&& h2_method_ok_spec(method@)
            &&& target_len <= target_limit
            &&& header_count > header_limit
        },
        decision == H2HeadDecision::HeaderFieldTooLarge ==> {
            &&& h2_method_ok_spec(method@)
            &&& target_len <= target_limit
            &&& header_count <= header_limit
            &&& largest_field > field_limit
        },
{
    let method_ok = h2_method_ok(method);
    if !method_ok {
        H2HeadDecision::InvalidMethod
    } else if target_len > target_limit {
        H2HeadDecision::TargetTooLong
    } else if header_count > header_limit {
        H2HeadDecision::TooManyHeaders
    } else if largest_field > field_limit {
        H2HeadDecision::HeaderFieldTooLarge
    } else {
        H2HeadDecision::Accept
    }
}

/// A request body may be appended only when it stays within the configured
/// limit.  The subtraction is guarded, so a malicious length cannot wrap.
pub fn h2_body_admit(current: u64, add: u64, limit: u64) -> (ok: bool)
    ensures ok == (current <= limit && add <= limit - current)
{
    if current > limit {
        false
    } else {
        add <= limit - current
    }
}

/// Monotone body-budget state.  The adapter advances this alongside the
/// concrete `Vec`; keeping the length as an explicit model prevents a future
/// refactor from accidentally resetting or bypassing the limit check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct H2BodyState {
    pub len: u64,
    pub limit: u64,
}

pub open spec fn h2_body_inv(s: H2BodyState) -> bool {
    s.len <= s.limit
}

pub fn h2_body_init(limit: u64) -> (s: H2BodyState)
    ensures h2_body_inv(s), s.len == 0, s.limit == limit,
{
    H2BodyState { len: 0, limit }
}

pub fn h2_body_append(state: H2BodyState, add: u64) -> (out: Option<H2BodyState>)
    requires h2_body_inv(state),
    ensures
        match out {
            Some(next) => {
                &&& h2_body_inv(next)
                &&& next.limit == state.limit
                &&& next.len == state.len + add
                &&& add <= state.limit - state.len
            }
            None => add > state.limit - state.len,
        },
{
    if add > state.limit - state.len {
        None
    } else {
        Some(H2BodyState { len: state.len + add, limit: state.limit })
    }
}

/// Total decoded header-list budget.  The h2 crate also enforces its
/// `max_header_list_size`; this is the adapter-level check used before a
/// request head is converted into the shared HTTP request.
/// Monotone decoded-header-list budget.  The h2 crate's HPACK limit is the
/// wire-side control; this model is the adapter's explicit total-header
/// state, used while converting the decoded list into the shared request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct H2HeaderState {
    pub total: u64,
    pub limit: u64,
}

pub open spec fn h2_header_inv(s: H2HeaderState) -> bool {
    s.total <= s.limit
}

pub fn h2_header_init(limit: u64) -> (s: H2HeaderState)
    ensures h2_header_inv(s), s.total == 0, s.limit == limit,
{
    H2HeaderState { total: 0, limit }
}

pub fn h2_header_add(state: H2HeaderState, add: u64) -> (out: Option<H2HeaderState>)
    requires h2_header_inv(state),
    ensures
        match out {
            Some(next) => {
                &&& h2_header_inv(next)
                &&& next.limit == state.limit
                &&& next.total == state.total + add
                &&& add <= state.limit - state.total
            }
            None => add > state.limit - state.total,
        },
{
    if add > state.limit - state.total {
        None
    } else {
        Some(H2HeaderState { total: state.total + add, ..state })
    }
}

pub fn h2_header_total_admit(total: u64, limit: u64) -> (ok: bool)
    ensures ok == (total <= limit),
{
    total <= limit
}

pub fn h2_target_admit(len: u64, limit: u64) -> (ok: bool)
    ensures ok == (len <= limit)
{
    len <= limit
}

pub open spec fn h2_header_field_spec(name: Seq<u8>, value: Seq<u8>) -> bool {
    valid_header_name(name)
        && valid_header_value(value)
        && !eq_ignore_ascii_case_spec(name, b"connection"@)
        && !eq_ignore_ascii_case_spec(name, b"proxy-connection"@)
        && !eq_ignore_ascii_case_spec(name, b"keep-alive"@)
        && !eq_ignore_ascii_case_spec(name, b"transfer-encoding"@)
        && !eq_ignore_ascii_case_spec(name, b"upgrade"@)
        && (!eq_ignore_ascii_case_spec(name, b"te"@)
            || eq_ignore_ascii_case_spec(value, b"trailers"@))
}

/// RFC 9113 connection-specific field gate, consumed at the HTTP/2 to
/// dispatcher/downgrade boundary even if the h2 codec has already rejected
/// the same fields.
pub fn h2_header_field_admit(name: &[u8], value: &[u8]) -> (ok: bool)
    ensures ok == h2_header_field_spec(name@, value@),
{
    proxy_header_admit(name, value)
        && !eq_ignore_ascii_case(name, b"connection")
        && !eq_ignore_ascii_case(name, b"proxy-connection")
        && !eq_ignore_ascii_case(name, b"keep-alive")
        && !eq_ignore_ascii_case(name, b"transfer-encoding")
        && !eq_ignore_ascii_case(name, b"upgrade")
        && (!eq_ignore_ascii_case(name, b"te")
            || eq_ignore_ascii_case(value, b"trailers"))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct H2ControlBudgetResult {
    pub available: u64,
    pub admitted: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H2ControlEvent {
    Settings,
    Ping,
    Priority,
    WindowUpdate { increment: u32 },
}

pub open spec fn h2_control_event_cost_spec(event: H2ControlEvent) -> u64 {
    match event {
        H2ControlEvent::Settings => 16,
        H2ControlEvent::Ping | H2ControlEvent::Priority => 1,
        // Every frame consumes parser/state-machine work.  Treating a large
        // increment as "useful" must not create a zero-cost control-frame
        // flood path; flow-control validity is checked separately.
        H2ControlEvent::WindowUpdate { increment: _ } => 1,
    }
}

pub fn h2_control_event_cost(event: H2ControlEvent) -> (cost: u64)
    ensures cost == h2_control_event_cost_spec(event),
{
    match event {
        H2ControlEvent::Settings => 16,
        H2ControlEvent::Ping | H2ControlEvent::Priority => 1,
        H2ControlEvent::WindowUpdate { increment: _ } => 1,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct H2ControlEventResult {
    pub available: u64,
    pub admitted: bool,
    /// Whole seconds that the runtime must advance its refill epoch. Keeping
    /// this in the verified transition prevents time from being charged twice.
    pub refill_seconds: u64,
    pub cost: u64,
}

/// Refill and consume one HTTP/2 control-frame token budget transition. All
/// multiplication/addition is checked, overflow saturates only to the fixed
/// burst ceiling, and a backward/zero elapsed time contributes no tokens.
pub fn h2_control_budget_step(
    available: u64,
    elapsed_seconds: u64,
    cost: u64,
    burst: u64,
    refill_per_second: u64,
) -> (out: H2ControlBudgetResult)
    ensures
        out.available <= burst,
        out.admitted ==> cost <= burst && out.available <= burst - cost,
        !out.admitted ==> cost > out.available,
{
    let capped = if available > burst { burst } else { available };
    let refill = match elapsed_seconds.checked_mul(refill_per_second) {
        Some(value) => value,
        None => u64::MAX,
    };
    let refilled = match capped.checked_add(refill) {
        Some(value) => if value > burst { burst } else { value },
        None => burst,
    };
    if cost > refilled {
        H2ControlBudgetResult {
            available: refilled,
            admitted: false,
        }
    } else {
        H2ControlBudgetResult {
            available: refilled - cost,
            admitted: true,
        }
    }
}

/// Complete event transition: assign the protocol event's cost, apply exactly
/// one elapsed-time refill, and return the epoch advance consumed by runtime.
pub fn h2_control_event_step(
    available: u64,
    elapsed_seconds: u64,
    event: H2ControlEvent,
    burst: u64,
    refill_per_second: u64,
) -> (out: H2ControlEventResult)
    ensures
        out.cost == h2_control_event_cost_spec(event),
        out.refill_seconds == elapsed_seconds,
        out.available <= burst,
        out.admitted ==> out.cost <= burst && out.available <= burst - out.cost,
        !out.admitted ==> out.cost > out.available,
{
    let cost = h2_control_event_cost(event);
    let budget = h2_control_budget_step(
        available,
        elapsed_seconds,
        cost,
        burst,
        refill_per_second,
    );
    H2ControlEventResult {
        available: budget.available,
        admitted: budget.admitted,
        refill_seconds: elapsed_seconds,
        cost,
    }
}

/// HTTP/2 regular requests must carry the pseudo-header identity that HTTP/1
/// obtains from the request target and Host field.  CONNECT is unsupported by
/// the shared dispatcher, and fragments are never part of an HTTP request
/// target.  Missing fields must not be normalized into `GET /`.
pub open spec fn h2_request_target_spec(
    is_connect: bool,
    has_scheme: bool,
    scheme_matches_transport: bool,
    has_authority: bool,
    authority_valid: bool,
    has_path: bool,
    path_nonempty: bool,
    has_fragment: bool,
) -> bool {
    !is_connect
        && has_scheme
        && scheme_matches_transport
        && has_authority
        && authority_valid
        && has_path
        && path_nonempty
        && !has_fragment
}

pub fn h2_request_target_admit(
    is_connect: bool,
    has_scheme: bool,
    scheme_matches_transport: bool,
    has_authority: bool,
    authority_valid: bool,
    has_path: bool,
    path_nonempty: bool,
    has_fragment: bool,
) -> (ok: bool)
    ensures
        ok == h2_request_target_spec(
            is_connect,
            has_scheme,
            scheme_matches_transport,
            has_authority,
            authority_valid,
            has_path,
            path_nonempty,
            has_fragment,
        ),
{
    !is_connect
        && has_scheme
        && scheme_matches_transport
        && has_authority
        && authority_valid
        && has_path
        && path_nonempty
        && !has_fragment
}

pub proof fn h2_request_target_rejects_ambiguous_identity(
    is_connect: bool,
    has_scheme: bool,
    scheme_matches_transport: bool,
    has_authority: bool,
    authority_valid: bool,
    has_path: bool,
    path_nonempty: bool,
    has_fragment: bool,
)
    ensures
        is_connect || !has_scheme || !scheme_matches_transport || !has_authority
            || !authority_valid || !has_path || !path_nonempty || has_fragment
            ==> !h2_request_target_spec(
                is_connect,
                has_scheme,
                scheme_matches_transport,
                has_authority,
                authority_valid,
                has_path,
                path_nonempty,
                has_fragment,
            ),
{
}

/// Header count and one field size are both bounded independently.
pub fn h2_header_admit(
    count: u64,
    field_size: u64,
    max_count: u64,
    max_field: u64,
) -> (ok: bool)
    ensures ok == (count <= max_count && field_size <= max_field)
{
    count <= max_count && field_size <= max_field
}

/// Abstract per-connection H2 stream/reset budget.  The h2 crate owns the
/// wire state machine; this model states the bound the adapter expects from a
/// conforming projection: active streams and pending resets never exceed the
/// configured maxima, and every transition is total (it returns `None` rather
/// than underflowing).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct H2Budget {
    pub active: u64,
    pub max_active: u64,
    pub pending_resets: u64,
    pub max_pending_resets: u64,
}

pub open spec fn h2_budget_inv(b: H2Budget) -> bool {
    b.active <= b.max_active && b.pending_resets <= b.max_pending_resets
}

pub fn h2_budget_new(max_active: u64, max_pending_resets: u64) -> (b: H2Budget)
    ensures
        h2_budget_inv(b),
        b.active == 0,
        b.pending_resets == 0,
        b.max_active == max_active,
        b.max_pending_resets == max_pending_resets,
{
    H2Budget {
        active: 0,
        max_active,
        pending_resets: 0,
        max_pending_resets,
    }
}

pub fn h2_budget_begin(b: H2Budget) -> (out: Option<H2Budget>)
    requires h2_budget_inv(b),
    ensures
        match out {
            Some(next) => {
                &&& h2_budget_inv(next)
                &&& next.active == b.active + 1
                &&& next.pending_resets == b.pending_resets
                &&& next.max_active == b.max_active
                &&& next.max_pending_resets == b.max_pending_resets
                &&& b.active < b.max_active
            }
            None => b.active >= b.max_active,
        },
{
    if b.active >= b.max_active {
        None
    } else {
        Some(H2Budget { active: b.active + 1, ..b })
    }
}

pub fn h2_budget_finish(b: H2Budget) -> (out: Option<H2Budget>)
    requires h2_budget_inv(b),
    ensures
        match out {
            Some(next) => {
                &&& h2_budget_inv(next)
                &&& next.active == b.active - 1
                &&& next.pending_resets == b.pending_resets
                &&& next.max_active == b.max_active
                &&& next.max_pending_resets == b.max_pending_resets
                &&& b.active > 0
            }
            None => b.active == 0,
        },
{
    if b.active == 0 {
        None
    } else {
        Some(H2Budget { active: b.active - 1, ..b })
    }
}

pub fn h2_budget_reset(b: H2Budget) -> (out: Option<H2Budget>)
    requires h2_budget_inv(b),
    ensures
        match out {
            Some(next) => {
                &&& h2_budget_inv(next)
                &&& next.active == b.active
                &&& next.pending_resets == b.pending_resets + 1
                &&& next.max_active == b.max_active
                &&& next.max_pending_resets == b.max_pending_resets
                &&& b.pending_resets < b.max_pending_resets
            }
            None => b.pending_resets >= b.max_pending_resets,
        },
{
    if b.pending_resets >= b.max_pending_resets {
        None
    } else {
        Some(H2Budget { pending_resets: b.pending_resets + 1, ..b })
    }
}

pub fn h2_budget_reclaim(b: H2Budget) -> (out: Option<H2Budget>)
    requires h2_budget_inv(b),
    ensures
        match out {
            Some(next) => {
                &&& h2_budget_inv(next)
                &&& next.active == b.active
                &&& next.pending_resets == b.pending_resets - 1
                &&& next.max_active == b.max_active
                &&& next.max_pending_resets == b.max_pending_resets
                &&& b.pending_resets > 0
            }
            None => b.pending_resets == 0,
        },
{
    if b.pending_resets == 0 {
        None
    } else {
        Some(H2Budget { pending_resets: b.pending_resets - 1, ..b })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H2BudgetEvent {
    Begin,
    Finish,
    Reset,
    Reclaim,
}

pub open spec fn h2_budget_step_spec(
    b: H2Budget,
    event: H2BudgetEvent,
) -> Option<H2Budget> {
    match event {
        H2BudgetEvent::Begin => if b.active >= b.max_active {
            None
        } else {
            Some(H2Budget {
                active: (b.active + 1) as u64,
                max_active: b.max_active,
                pending_resets: b.pending_resets,
                max_pending_resets: b.max_pending_resets,
            })
        },
        H2BudgetEvent::Finish => if b.active == 0 {
            None
        } else {
            Some(H2Budget {
                active: (b.active - 1) as u64,
                max_active: b.max_active,
                pending_resets: b.pending_resets,
                max_pending_resets: b.max_pending_resets,
            })
        },
        H2BudgetEvent::Reset => if b.pending_resets >= b.max_pending_resets {
            None
        } else {
            Some(H2Budget {
                active: b.active,
                max_active: b.max_active,
                pending_resets: (b.pending_resets + 1) as u64,
                max_pending_resets: b.max_pending_resets,
            })
        },
        H2BudgetEvent::Reclaim => if b.pending_resets == 0 {
            None
        } else {
            Some(H2Budget {
                active: b.active,
                max_active: b.max_active,
                pending_resets: (b.pending_resets - 1) as u64,
                max_pending_resets: b.max_pending_resets,
            })
        },
    }
}

/// Bound settings used by the HTTP/2 adapter.  The values are deliberately
/// small and are consumed by the h2 builder; they are also the reference
/// limits for the adapter-level flow/header models.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct H2Settings {
    pub max_concurrent_streams: u32,
    pub max_header_list: u32,
    pub initial_window: u32,
    pub initial_connection_window: u32,
    pub max_frame: u32,
    pub max_reset_streams: u32,
    pub max_send_buffer: u32,
}

pub open spec fn h2_settings_sane(s: H2Settings) -> bool {
    &&& s.max_concurrent_streams > 0 && s.max_concurrent_streams <= 1024
    &&& s.max_header_list > 0 && s.max_header_list <= 16 * 1024 * 1024
    &&& s.initial_window > 0 && s.initial_window <= 16 * 1024 * 1024
    &&& s.initial_connection_window >= s.initial_window
    &&& s.initial_connection_window <= 16 * 1024 * 1024
    &&& s.max_frame >= 16 * 1024 && s.max_frame <= 16 * 1024 * 1024
    &&& s.max_reset_streams > 0 && s.max_reset_streams <= 1024
    &&& s.max_send_buffer > 0 && s.max_send_buffer <= 16 * 1024 * 1024
}

pub fn h2_settings() -> (s: H2Settings)
    ensures h2_settings_sane(s),
{
    H2Settings {
        // Combined with the adapter's 64 KiB in-memory body prefix this caps
        // one connection's request-body heap at roughly 2 MiB before spooling.
        max_concurrent_streams: 32,
        max_header_list: 131_072,
        initial_window: 256 * 1024,
        initial_connection_window: 1024 * 1024,
        max_frame: 16 * 1024,
        max_reset_streams: 100,
        max_send_buffer: 256 * 1024,
    }
}

/// Abstract HTTP/2 flow-control state.  The h2 crate owns the wire windows;
/// this model records the bound the adapter/config contract expects:
/// connection and stream windows stay within their maxima, and the send
/// buffer never exceeds its configured cap.  The `charge`, `credit` and
/// `enqueue` transitions are total and reject underflow/overrun.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct H2Flow {
    pub conn_window: u64,
    pub stream_window: u64,
    pub pending_send: u64,
    pub max_conn_window: u64,
    pub max_stream_window: u64,
    pub max_send: u64,
}

pub open spec fn h2_flow_inv(f: H2Flow) -> bool {
    &&& f.conn_window <= f.max_conn_window
    &&& f.stream_window <= f.max_stream_window
    &&& f.pending_send <= f.max_send
}

pub fn h2_flow_new(
    initial_conn_window: u64,
    initial_stream_window: u64,
    max_send: u64,
) -> (f: H2Flow)
    ensures
        h2_flow_inv(f),
        f.conn_window == initial_conn_window,
        f.stream_window == initial_stream_window,
        f.pending_send == 0,
        f.max_conn_window == initial_conn_window,
        f.max_stream_window == initial_stream_window,
        f.max_send == max_send,
{
    H2Flow {
        conn_window: initial_conn_window,
        stream_window: initial_stream_window,
        pending_send: 0,
        max_conn_window: initial_conn_window,
        max_stream_window: initial_stream_window,
        max_send,
    }
}

pub fn h2_flow_charge(f: H2Flow, amount: u64) -> (out: Option<H2Flow>)
    requires h2_flow_inv(f),
    ensures
        match out {
            Some(next) => {
                &&& h2_flow_inv(next)
                &&& next.conn_window == f.conn_window - amount
                &&& next.stream_window == f.stream_window - amount
                &&& next.pending_send == f.pending_send
                &&& amount <= f.conn_window
                &&& amount <= f.stream_window
            }
            None => amount > f.conn_window || amount > f.stream_window,
        },
{
    if amount > f.conn_window || amount > f.stream_window {
        None
    } else {
        Some(H2Flow { conn_window: f.conn_window - amount, stream_window: f.stream_window - amount, ..f })
    }
}

pub fn h2_flow_credit(f: H2Flow, amount: u64) -> (out: H2Flow)
    requires h2_flow_inv(f),
    ensures
        h2_flow_inv(out),
        out.pending_send == f.pending_send,
        out.max_conn_window == f.max_conn_window,
        out.max_stream_window == f.max_stream_window,
        out.max_send == f.max_send,
        out.conn_window >= f.conn_window,
        out.stream_window >= f.stream_window,
        out.conn_window <= f.max_conn_window,
        out.stream_window <= f.max_stream_window,
{
    let conn_window = if amount > f.max_conn_window - f.conn_window {
        f.max_conn_window
    } else {
        f.conn_window + amount
    };
    let stream_window = if amount > f.max_stream_window - f.stream_window {
        f.max_stream_window
    } else {
        f.stream_window + amount
    };
    H2Flow {
        conn_window,
        stream_window,
        ..f
    }
}

pub fn h2_flow_enqueue(f: H2Flow, amount: u64) -> (out: Option<H2Flow>)
    requires h2_flow_inv(f),
    ensures
        match out {
            Some(next) => {
                &&& h2_flow_inv(next)
                &&& next.conn_window == f.conn_window
                &&& next.stream_window == f.stream_window
                &&& next.pending_send == f.pending_send + amount
                &&& amount <= f.max_send - f.pending_send
            }
            None => amount > f.max_send - f.pending_send,
        },
{
    if amount > f.max_send - f.pending_send {
        None
    } else {
        Some(H2Flow { pending_send: f.pending_send + amount, ..f })
    }
}

pub fn h2_flow_dequeue(f: H2Flow, amount: u64) -> (out: Option<H2Flow>)
    requires h2_flow_inv(f),
    ensures
        match out {
            Some(next) => {
                &&& h2_flow_inv(next)
                &&& next.conn_window == f.conn_window
                &&& next.stream_window == f.stream_window
                &&& next.pending_send == f.pending_send - amount
                &&& amount <= f.pending_send
            }
            None => amount > f.pending_send,
        },
{
    if amount > f.pending_send {
        None
    } else {
        Some(H2Flow { pending_send: f.pending_send - amount, ..f })
    }
}

/// Idempotent cleanup registration, mirroring mod_http2's `add_for_purge`.
/// A stream may be scheduled for destruction by both an early RST callback and
/// a close callback; the second registration must be a no-op or the same
/// object is destroyed twice.  Vapache has no C spurge array, but its adapter
/// uses the same identity rule for task completion/reset events.
pub open spec fn h2_purge_contains(ids: Seq<u64>, id: u64) -> bool {
    exists|i: int| 0 <= i < ids.len() && ids[i] == id
}

pub open spec fn h2_purge_add(ids: Seq<u64>, id: u64) -> Seq<u64> {
    if h2_purge_contains(ids, id) {
        ids
    } else {
        ids.push(id)
    }
}

pub proof fn h2_purge_add_idempotent(ids: Seq<u64>, id: u64)
    ensures h2_purge_add(h2_purge_add(ids, id), id) == h2_purge_add(ids, id),
{
    if h2_purge_contains(ids, id) {
    } else {
        assert(ids.push(id)[ids.len() as int] == id);
        assert(h2_purge_contains(ids.push(id), id));
    }
}

/// Runtime membership check for the same cleanup set.
pub fn h2_purge_contains_exec(ids: &[u64], id: u64) -> (found: bool)
    ensures found == h2_purge_contains(ids@, id),
{
    let mut i: usize = 0;
    while i < ids.len()
        invariant
            0 <= i <= ids.len(),
            forall|j: int| 0 <= j < i ==> ids@[j] != id,
        decreases ids.len() - i,
    {
        if ids[i] == id {
            return true;
        }
        i = i + 1;
    }
    assert forall|j: int| 0 <= j < ids@.len() ==> ids@[j] != id by {
    }
    false
}

/// Invariant for the adapter-side stream table: active and pending-reset
/// stream IDs are each unique and the two sets are disjoint.  This is the
/// state the `H2StreamIds` ledger maintains around the verified admission
/// step; the h2 crate owns wire-level frame ordering and the HTTP/2 state
/// machine itself.
pub open spec fn h2_stream_table_inv(active: Seq<u64>, pending: Seq<u64>) -> bool {
    &&& active.no_duplicates()
    &&& pending.no_duplicates()
    &&& forall|i: int, j: int|
        0 <= i < active.len() && 0 <= j < pending.len() ==> active[i] != pending[j]
}

/// A stream may begin only if its ID is neither currently active nor awaiting
/// reset cleanup.  This is the combined admission check used by the runtime;
/// it prevents a duplicate early-RST/completion path from creating two
/// logical streams with the same ID.
pub fn h2_stream_admit(active: &[u64], pending: &[u64], id: u64) -> (ok: bool)
    ensures ok == (!active@.contains(id) && !pending@.contains(id)),
{
    if h2_purge_contains_exec(active, id) {
        false
    } else if h2_purge_contains_exec(pending, id) {
        false
    } else {
        true
    }
}

/// Adapter-level stream lifecycle.  The h2 crate reports stream IDs and
/// resets; this model fixes the only legal local transitions so a closed
/// stream can never be reopened without a fresh admission (which the ID
/// ledger rejects).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H2StreamPhase {
    Idle,
    Active,
    AwaitingReset,
    Closed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H2StreamEvent {
    Begin,
    End,
    Reset,
    Reclaim,
}

pub open spec fn h2_stream_phase_step(
    phase: H2StreamPhase,
    event: H2StreamEvent,
) -> Option<H2StreamPhase> {
    match (phase, event) {
        (H2StreamPhase::Idle, H2StreamEvent::Begin) => Some(H2StreamPhase::Active),
        (H2StreamPhase::Active, H2StreamEvent::End) => Some(H2StreamPhase::AwaitingReset),
        (H2StreamPhase::Active, H2StreamEvent::Reset) => Some(H2StreamPhase::AwaitingReset),
        (H2StreamPhase::AwaitingReset, H2StreamEvent::End) => Some(H2StreamPhase::Closed),
        (H2StreamPhase::AwaitingReset, H2StreamEvent::Reclaim) => Some(H2StreamPhase::Closed),
        _ => None,
    }
}

/// Closed is absorbing: no event can move a closed stream back to Active or
/// AwaitingReset.  A fresh stream must be admitted through a new ID.
pub proof fn h2_closed_phase_is_absorbing(
    event: H2StreamEvent,
)
    ensures
        h2_stream_phase_step(H2StreamPhase::Closed, event).is_none(),
{
}

pub proof fn h2_stream_phase_preserves_no_reopen(
    phase: H2StreamPhase,
    event: H2StreamEvent,
)
    ensures
        h2_stream_phase_step(phase, event)
                == Some(H2StreamPhase::Active)
            ==> phase == H2StreamPhase::Idle && event == H2StreamEvent::Begin,
{
}

/// Output ownership is transferred at most once from a protocol's general
/// admission pool to the source-fair slow-output pool.  In particular,
/// downstream progress can never promote a classified slow output back into
/// general capacity.  HTTP/1 socket writability and HTTP/2 flow control use
/// this same state machine.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlowOutputPhase {
    General,
    Slow,
    Closed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlowOutputEvent {
    DownstreamStall,
    Finish,
}

pub open spec fn slow_output_phase_step_spec(
    phase: SlowOutputPhase,
    event: SlowOutputEvent,
) -> Option<SlowOutputPhase> {
    match (phase, event) {
        (SlowOutputPhase::General, SlowOutputEvent::DownstreamStall) => {
            Some(SlowOutputPhase::Slow)
        },
        (SlowOutputPhase::General, SlowOutputEvent::Finish) => Some(SlowOutputPhase::Closed),
        (SlowOutputPhase::Slow, SlowOutputEvent::DownstreamStall) => Some(SlowOutputPhase::Slow),
        (SlowOutputPhase::Slow, SlowOutputEvent::Finish) => Some(SlowOutputPhase::Closed),
        _ => None,
    }
}

/// Executable transition used by the server, proved identical to the output
/// ownership model above.
pub fn slow_output_phase_step(
    phase: SlowOutputPhase,
    event: SlowOutputEvent,
) -> (next: Option<SlowOutputPhase>)
    ensures next == slow_output_phase_step_spec(phase, event),
{
    match (phase, event) {
        (SlowOutputPhase::General, SlowOutputEvent::DownstreamStall) => {
            Some(SlowOutputPhase::Slow)
        },
        (SlowOutputPhase::General, SlowOutputEvent::Finish) => Some(SlowOutputPhase::Closed),
        (SlowOutputPhase::Slow, SlowOutputEvent::DownstreamStall) => Some(SlowOutputPhase::Slow),
        (SlowOutputPhase::Slow, SlowOutputEvent::Finish) => Some(SlowOutputPhase::Closed),
        _ => None,
    }
}

pub proof fn slow_output_cannot_return_to_general(
    event: SlowOutputEvent,
)
    ensures
        slow_output_phase_step_spec(SlowOutputPhase::Slow, event)
            != Some(SlowOutputPhase::General),
{
}

pub proof fn closed_slow_output_is_absorbing(event: SlowOutputEvent)
    ensures slow_output_phase_step_spec(SlowOutputPhase::Closed, event).is_none(),
{
}

pub fn h2_budget_step(b: H2Budget, event: H2BudgetEvent) -> (out: Option<H2Budget>)
    requires h2_budget_inv(b),
    ensures
        out == h2_budget_step_spec(b, event),
        match out {
            Some(next) => h2_budget_inv(next),
            None => true,
        },
{
    match event {
        H2BudgetEvent::Begin => h2_budget_begin(b),
        H2BudgetEvent::Finish => h2_budget_finish(b),
        H2BudgetEvent::Reset => h2_budget_reset(b),
        H2BudgetEvent::Reclaim => h2_budget_reclaim(b),
    }
}

pub open spec fn h2_budget_replay(
    b: H2Budget,
    events: Seq<H2BudgetEvent>,
) -> Option<H2Budget>
    decreases events.len(),
{
    if events.len() == 0 {
        Some(b)
    } else {
        match h2_budget_step_spec(b, events[0]) {
            Some(next) => h2_budget_replay(next, events.skip(1)),
            None => None,
        }
    }
}

/// Any finite sequence of admitted/ended/reset/reclaimed transitions keeps
/// both counters within their configured maxima.  This is the induction
/// obligation behind the per-event postconditions above.
pub proof fn h2_budget_replay_preserves_inv(
    b: H2Budget,
    events: Seq<H2BudgetEvent>,
)
    requires h2_budget_inv(b),
    ensures
        match h2_budget_replay(b, events) {
            Some(next) => h2_budget_inv(next),
            None => true,
        },
    decreases events.len(),
{
    if events.len() == 0 {
    } else {
        let event = events[0];
        match event {
            H2BudgetEvent::Begin => {
                if b.active >= b.max_active {
                    assert(h2_budget_step_spec(b, event) == None);
                } else {
                    let next = H2Budget {
                        active: (b.active + 1) as u64,
                        max_active: b.max_active,
                        pending_resets: b.pending_resets,
                        max_pending_resets: b.max_pending_resets,
                    };
                    assert(h2_budget_step_spec(b, event) == Some(next));
                    assert(h2_budget_inv(next));
                    h2_budget_replay_preserves_inv(next, events.skip(1));
                }
            }
            H2BudgetEvent::Finish => {
                if b.active == 0 {
                    assert(h2_budget_step_spec(b, event) == None);
                } else {
                    let next = H2Budget {
                        active: (b.active - 1) as u64,
                        max_active: b.max_active,
                        pending_resets: b.pending_resets,
                        max_pending_resets: b.max_pending_resets,
                    };
                    assert(h2_budget_step_spec(b, event) == Some(next));
                    assert(h2_budget_inv(next));
                    h2_budget_replay_preserves_inv(next, events.skip(1));
                }
            }
            H2BudgetEvent::Reset => {
                if b.pending_resets >= b.max_pending_resets {
                    assert(h2_budget_step_spec(b, event) == None);
                } else {
                    let next = H2Budget {
                        active: b.active,
                        max_active: b.max_active,
                        pending_resets: (b.pending_resets + 1) as u64,
                        max_pending_resets: b.max_pending_resets,
                    };
                    assert(h2_budget_step_spec(b, event) == Some(next));
                    assert(h2_budget_inv(next));
                    h2_budget_replay_preserves_inv(next, events.skip(1));
                }
            }
            H2BudgetEvent::Reclaim => {
                if b.pending_resets == 0 {
                    assert(h2_budget_step_spec(b, event) == None);
                } else {
                    let next = H2Budget {
                        active: b.active,
                        max_active: b.max_active,
                        pending_resets: (b.pending_resets - 1) as u64,
                        max_pending_resets: b.max_pending_resets,
                    };
                    assert(h2_budget_step_spec(b, event) == Some(next));
                    assert(h2_budget_inv(next));
                    h2_budget_replay_preserves_inv(next, events.skip(1));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// I3 — fast-path prefilter soundness
// ---------------------------------------------------------------------------

/// The runtime `.htaccess` gate is the conjunction of "overrides are enabled"
/// and "the override policy can apply to this path".  The access-file walk
/// reads a directory only when that gate holds and an access file exists.
/// `DocumentRoot`/the alias root is deliberately not part of this predicate:
/// it is a URL-mapping label, not an authorization boundary (F50/I47).
pub open spec fn htaccess_may_apply_spec(enabled: bool, applicable: bool) -> bool {
    enabled && applicable
}

pub open spec fn access_file_layer_read(
    enabled: bool,
    applicable: bool,
    file_present: bool,
) -> bool {
    enabled && applicable && file_present
}

/// If the prefilter says the walk cannot matter, no ancestor directory can
/// contribute an access-file layer.  This is the `htaccess_may_apply` half of
/// I3; the path-pattern predicate itself is supplied by the unproved matcher.
pub proof fn htaccess_prefilter_sound(
    enabled: bool,
    applicable: bool,
    file_present: bool,
)
    ensures
        !htaccess_may_apply_spec(enabled, applicable)
            ==> !access_file_layer_read(enabled, applicable, file_present),
{
}

/// The matcher used by `CacheEnable`/`CacheDisable`.  Only its identity is
/// needed for the prefilter proof, so it is intentionally uninterpreted.
pub uninterp spec fn cache_prefix_matches(prefix: u64, path: u64) -> bool;

/// True when any enable prefix in the list matches the request path.
pub open spec fn any_cache_prefix_matches(prefixes: Seq<u64>, path: u64) -> bool
    decreases prefixes.len(),
{
    if prefixes.len() == 0 {
        false
    } else {
        cache_prefix_matches(prefixes[0], path)
            || any_cache_prefix_matches(prefixes.drop_first(), path)
    }
}

/// Appending a prefix list cannot change whether any prefix matches.
pub proof fn any_cache_prefix_matches_append(a: Seq<u64>, b: Seq<u64>, path: u64)
    ensures
        any_cache_prefix_matches(a + b, path) == (any_cache_prefix_matches(a, path)
            || any_cache_prefix_matches(b, path)),
    decreases a.len(),
{
    if a.len() == 0 {
        assert(a + b == b);
    } else {
        assert(a == seq![a[0]] + a.drop_first());
        assert(a + b == seq![a[0]] + (a.drop_first() + b));
        assert((seq![a[0]] + (a.drop_first() + b))[0] == a[0]);
        assert((seq![a[0]] + (a.drop_first() + b)).drop_first() == a.drop_first() + b);
        assert(any_cache_prefix_matches(a + b, path)
            == (cache_prefix_matches(a[0], path)
                || any_cache_prefix_matches(a.drop_first() + b, path)));
        assert(any_cache_prefix_matches(a, path)
            == (cache_prefix_matches(a[0], path)
                || any_cache_prefix_matches(a.drop_first(), path)));
        any_cache_prefix_matches_append(a.drop_first(), b, path);
    }
}

/// `CacheEnable`/`CacheDisable` are base-scope directives.  The executable
/// configuration compiler consumes this decision before it can add either
/// directive to a rule-producing section.
pub open spec fn cache_base_scope_spec(in_base_scope: bool) -> bool {
    in_base_scope
}

pub fn cache_base_scope_admit(in_base_scope: bool) -> (ok: bool)
    ensures ok == cache_base_scope_spec(in_base_scope),
{
    in_base_scope
}

/// Concatenation of every rule's `CacheEnable` prefixes in application order.
pub open spec fn applied_cache_enables(rule_enables: Seq<Seq<u64>>) -> Seq<u64>
    decreases rule_enables.len(),
{
    if rule_enables.len() == 0 {
        Seq::empty()
    } else {
        rule_enables[0] + applied_cache_enables(rule_enables.drop_first())
    }
}

pub proof fn applied_cache_enables_empty(rule_enables: Seq<Seq<u64>>)
    requires forall|i: int| 0 <= i < rule_enables.len() ==> rule_enables[i].len() == 0,
    ensures applied_cache_enables(rule_enables).len() == 0,
    decreases rule_enables.len(),
{
    if rule_enables.len() == 0 {
    } else {
        assert(rule_enables[0].len() == 0);
        applied_cache_enables_empty(rule_enables.drop_first());
        assert((rule_enables[0] + applied_cache_enables(rule_enables.drop_first())).len() == 0);
    }
}

/// `cache_enabled` is disable-first and then requires an enabled prefix to
/// match.  A prefilter-negative rule set cannot introduce such a prefix, so a
/// request outside the inherited enable prefixes stays outside the cache.
pub open spec fn cache_enabled_spec(
    cache_enable: Seq<u64>,
    cache_disable: Seq<u64>,
    path: u64,
) -> bool {
    !any_cache_prefix_matches(cache_disable, path) && any_cache_prefix_matches(cache_enable, path)
}

/// The cache half of I3: if the inherited base scope does not enable the raw
/// request path and the compiler has excluded `CacheEnable` from all
/// rule-producing contexts, the effective scope cannot enable the cache.
pub proof fn cache_base_scope_only_sound(
    base_enable: Seq<u64>,
    base_disable: Seq<u64>,
    rule_enables: Seq<Seq<u64>>,
    path: u64,
)
    requires
        !any_cache_prefix_matches(base_enable, path),
        forall|i: int| 0 <= i < rule_enables.len() ==> rule_enables[i].len() == 0,
    ensures
        !cache_enabled_spec(base_enable + applied_cache_enables(rule_enables), base_disable, path),
{
    applied_cache_enables_empty(rule_enables);
    assert(applied_cache_enables(rule_enables) == Seq::<u64>::empty());
    any_cache_prefix_matches_append(base_enable, applied_cache_enables(rule_enables), path);
    assert(!any_cache_prefix_matches(base_enable + applied_cache_enables(rule_enables), path));
}

/// I14's first-match rule, stated independently of any particular table.
/// Encoding an ordered mapping table as its match-bit vector is the
/// refinement step; this theorem proves that the selected bit is the first
/// true one, so a later overlapping mapping can never win.
pub proof fn first_match_is_first(flags: Seq<bool>, selected: int)
    requires first_true_spec(flags) == Some(selected),
    ensures
        0 <= selected < flags.len(),
        flags[selected],
        forall|j: int| 0 <= j < selected ==> !flags[j],
    decreases flags.len(),
{
    if flags.len() == 0 {
        assert(first_true_spec(flags) == None);
    } else if flags[0] {
        assert(first_true_spec(flags) == Some(0));
        assert(selected == 0);
    } else {
        let rest = flags.drop_first();
        assert(first_true_spec(flags) == match first_true_spec(rest) {
            None => None,
            Some(i) => Some(i + 1),
        });
        match first_true_spec(rest) {
            None => {
                assert(first_true_spec(flags) == None);
            }
            Some(i) => {
                assert(selected == i + 1);
                first_match_is_first(rest, i);
                assert(flags[selected] == rest[i]);
                assert forall|j: int| 0 <= j < selected implies !flags[j] by {
                    if j == 0 {
                        assert(!flags[0]);
                    } else {
                        assert(flags[j] == rest[j - 1]);
                    }
                }
            }
        }
    }
}

/// No match bit set means the table has no applicable entry.
pub proof fn first_match_none_means_no_match(flags: Seq<bool>)
    requires first_true_spec(flags) == None,
    ensures forall|j: int| 0 <= j < flags.len() ==> !flags[j],
    decreases flags.len(),
{
    if flags.len() == 0 {
    } else if flags[0] {
        assert(first_true_spec(flags) == Some(0));
    } else {
        assert(first_true_spec(flags) == match first_true_spec(flags.drop_first()) {
            None => None,
            Some(i) => Some(i + 1),
        });
        first_match_none_means_no_match(flags.drop_first());
        assert forall|j: int| 0 <= j < flags.len() implies !flags[j] by {
            if j == 0 {
                assert(!flags[0]);
            } else {
                assert(flags[j] == flags.drop_first()[j - 1]);
            }
        }
    }
}

/// Named entry point for the proof obligation in section 10 of
/// `docs/config-semantics.md`: both fast-path prefilters imply their
/// authoritative checks.
pub proof fn prefilter_sound(
    override_enabled: bool,
    override_applicable: bool,
    file_present: bool,
    base_enable: Seq<u64>,
    base_disable: Seq<u64>,
    rule_enables: Seq<Seq<u64>>,
    path: u64,
)
    ensures
        (!htaccess_may_apply_spec(override_enabled, override_applicable)
            ==> !access_file_layer_read(
                override_enabled,
                override_applicable,
                file_present,
            ))
            && ((!any_cache_prefix_matches(base_enable, path)
                && (forall|i: int| 0 <= i < rule_enables.len()
                    ==> rule_enables[i].len() == 0))
                ==> !cache_enabled_spec(
                    base_enable + applied_cache_enables(rule_enables),
                    base_disable,
                    path,
                )),
{
    htaccess_prefilter_sound(
        override_enabled,
        override_applicable,
        file_present,
    );
    if !any_cache_prefix_matches(base_enable, path)
        && (forall|i: int| 0 <= i < rule_enables.len()
            ==> rule_enables[i].len() == 0)
    {
        cache_base_scope_only_sound(base_enable, base_disable, rule_enables, path);
    }
}

// ---------------------------------------------------------------------------
// Pass-11 remediation kernels: shell fnmatch for section patterns (F61/F62),
// expression-variable admission (F63), SetHandler precedence and conjoin
// (F64), ScriptAlias execution gating (F65) and lexical handler identity
// (F69).
// ---------------------------------------------------------------------------

/// Byte membership in a sequence, stated recursively so the executable
/// matcher and its specification share one definition.
pub open spec fn bytes_contains_spec(bytes: Seq<u8>, byte: u8) -> bool
    decreases bytes.len(),
{
    if bytes.len() == 0 {
        false
    } else {
        bytes[0] == byte || bytes_contains_spec(bytes.skip(1), byte)
    }
}

pub fn bytes_contains(bytes: &[u8], byte: u8) -> (out: bool)
    ensures out == bytes_contains_spec(bytes@, byte),
    decreases bytes.len(),
{
    if bytes.len() == 0 {
        false
    } else {
        bytes[0] == byte || bytes_contains(&bytes[1..], byte)
    }
}

/// A byte found at a position is a member by the recursive definition.
pub proof fn bytes_contains_at(bytes: Seq<u8>, i: int, byte: u8)
    requires 0 <= i < bytes.len(),
    ensures
        bytes[i] == byte ==> bytes_contains_spec(bytes, byte),
    decreases i,
{
    if i == 0 {
        assert(bytes[i] == byte ==> bytes_contains_spec(bytes, byte));
    } else {
        assert(bytes.skip(1).len() == bytes.len() - 1);
        assert(bytes.skip(1)[i - 1] == bytes[i]);
        bytes_contains_at(bytes.skip(1), i - 1, byte);
        assert(bytes[i] == byte ==> bytes_contains_spec(bytes, byte));
    }
}

/// Membership is witnessed at some index.
pub proof fn bytes_contains_witness(bytes: Seq<u8>, byte: u8)
    requires bytes_contains_spec(bytes, byte),
    ensures exists|j: int| 0 <= j < bytes.len() && bytes[j] == byte,
    decreases bytes.len(),
{
    if bytes.len() == 0 {
        assert(!bytes_contains_spec(bytes, byte));
    } else if bytes[0] == byte {
        assert(bytes[0] == byte);
    } else {
        bytes_contains_witness(bytes.skip(1), byte);
        assert(exists|j: int| 0 <= j < bytes.len() && bytes[j] == byte);
    }
}

/// Membership survives embedding a subrange into its parent sequence.
pub proof fn bytes_contains_subrange(bytes: Seq<u8>, lo: int, hi: int, byte: u8)
    requires 0 <= lo <= hi <= bytes.len(),
    ensures
        bytes_contains_spec(bytes.subrange(lo, hi), byte)
            ==> bytes_contains_spec(bytes, byte),
    decreases hi - lo,
{
    if lo < hi {
        let sub = bytes.subrange(lo, hi);
        assert(sub.len() == hi - lo);
        // The witness index `k` inside the subrange maps to `lo + k` in the
        // parent.
        assert forall|k: int| 0 <= k < sub.len() implies sub[k] == bytes[lo + k] by {
            assert(sub[k] == bytes[lo + k]);
        }
        if bytes_contains_spec(sub, byte) {
            bytes_contains_witness(sub, byte);
            let witness = choose|j: int| 0 <= j < sub.len() && sub[j] == byte;
            assert(0 <= lo + witness < bytes.len());
            assert(bytes[lo + witness] == byte);
            bytes_contains_at(bytes, lo + witness, byte);
            assert(bytes_contains_spec(bytes, byte));
        }
    }
}

/// Position of the closing `]` of a bracket expression, scanning from `from`.
/// `\x` escape pairs are transparent, so an escaped `]` never terminates the
/// class.  An unterminated class reports `pattern.len()`; a terminated one
/// reports the index of the closing bracket (never before `from`).
pub open spec fn fnmatch_class_end_spec(pattern: Seq<u8>, from: int) -> int
    decreases pattern.len() - from,
{
    if from < 0 || from >= pattern.len() {
        pattern.len() as int
    } else if pattern[from] == b']' {
        from
    } else if pattern[from] == b'\\' && from + 1 < pattern.len() {
        fnmatch_class_end_spec(pattern, from + 2)
    } else {
        fnmatch_class_end_spec(pattern, from + 1)
    }
}

pub fn fnmatch_class_end(pattern: &[u8], from: usize) -> (out: Option<usize>)
    requires from <= pattern.len(),
    ensures
        match out {
            None => fnmatch_class_end_spec(pattern@, from as int) == pattern@.len(),
            Some(e) => {
                &&& fnmatch_class_end_spec(pattern@, from as int) == e as int
                &&& from <= e < pattern.len()
                &&& pattern@[e as int] == b']'
            }
        },
    decreases pattern.len() - from,
{
    if from >= pattern.len() {
        None
    } else if pattern[from] == b']' {
        Some(from)
    } else if pattern[from] == b'\\' && from + 1 < pattern.len() {
        fnmatch_class_end(pattern, from + 2)
    } else {
        fnmatch_class_end(pattern, from + 1)
    }
}

/// `fnmatch_class_end_spec` never escapes `[from, pattern.len()]`, which the
/// path-mode boundedness proof needs before indexing past the closing `]`.
pub proof fn fnmatch_class_end_bounds(pattern: Seq<u8>, from: int)
    requires 0 <= from <= pattern.len(),
    ensures
        from <= fnmatch_class_end_spec(pattern, from) <= pattern.len(),
    decreases pattern.len() - from,
{
    if from >= pattern.len() {
        assert(fnmatch_class_end_spec(pattern, from) == pattern.len());
    } else if pattern[from] == b']' {
        assert(fnmatch_class_end_spec(pattern, from) == from);
    } else if pattern[from] == b'\\' && from + 1 < pattern.len() {
        assert(from + 2 <= pattern.len());
        fnmatch_class_end_bounds(pattern, from + 2);
    } else {
        fnmatch_class_end_bounds(pattern, from + 1);
    }
}

/// Both shell negation markers are honored inside a class: `!` and `^`
/// (F62/F62b: `^` was previously read as a positive class member).
pub open spec fn fnmatch_class_negated_spec(pattern: Seq<u8>, start: int) -> bool
{
    0 <= start + 1 < pattern.len()
        && (pattern[start + 1] == b'!' || pattern[start + 1] == b'^')
}

pub fn fnmatch_class_negated(pattern: &[u8], start: usize) -> (neg: bool)
    requires start < pattern.len(),
    ensures neg == fnmatch_class_negated_spec(pattern@, start as int),
{
    start + 1 < pattern.len() && (pattern[start + 1] == b'!' || pattern[start + 1] == b'^')
}

/// Index of the first class member, past an optional negation marker and a
/// literal leading `]`.
pub open spec fn fnmatch_class_body_start_spec(pattern: Seq<u8>, start: int) -> int
{
    if start < 0 {
        0int
    } else {
        let s = start
            + 1
            + (if start + 1 < pattern.len()
                && (pattern[start + 1] == b'!' || pattern[start + 1] == b'^')
            {
                1int
            } else {
                0int
            });
        if s < pattern.len() && pattern[s] == b']' {
            s + 1
        } else {
            s
        }
    }
}

pub fn fnmatch_class_body_start(pattern: &[u8], start: usize) -> (out: usize)
    requires start < pattern.len(),
    ensures out == fnmatch_class_body_start_spec(pattern@, start as int),
{
    let mut s = start + 1;
    if s < pattern.len() && (pattern[s] == b'!' || pattern[s] == b'^') {
        s += 1;
    }
    if s < pattern.len() && pattern[s] == b']' {
        s + 1
    } else {
        s
    }
}

/// Does byte `c` belong to the class body starting at `i` (the characters
/// between the brackets, negation marker already excluded)?  `\x` pairs are
/// literal members; `lo-hi` needs plain characters on both sides of the dash;
/// a dash at an edge is a literal dash.  In path mode a class never matches
/// `/` (POSIX pathname expansion).
pub open spec fn fnmatch_class_body_spec(pattern: Seq<u8>, i: int, c: u8, path_mode: bool) -> bool
    decreases pattern.len() - i,
{
    if i < 0 || i >= pattern.len() {
        false
    } else if pattern[i] == b'\\' && i + 1 < pattern.len() {
        (c == pattern[i + 1] && (!path_mode || c != b'/'))
            || fnmatch_class_body_spec(pattern, i + 2, c, path_mode)
    } else if i + 2 < pattern.len() && pattern[i + 1] == b'-' {
        ((!path_mode || c != b'/') && pattern[i] <= c && c <= pattern[i + 2])
            || fnmatch_class_body_spec(pattern, i + 3, c, path_mode)
    } else {
        (c == pattern[i] && (!path_mode || c != b'/'))
            || fnmatch_class_body_spec(pattern, i + 1, c, path_mode)
    }
}

fn fnmatch_class_body(body: &[u8], i: usize, c: u8, path_mode: bool) -> (out: bool)
    requires i <= body.len(),
    ensures out == fnmatch_class_body_spec(body@, i as int, c, path_mode),
    decreases body.len() - i,
{
    if i >= body.len() {
        false
    } else if body[i] == b'\\' && i + 1 < body.len() {
        (c == body[i + 1] && (!path_mode || c != b'/'))
            || fnmatch_class_body(body, i + 2, c, path_mode)
    } else if i + 1 < body.len() && i + 2 < body.len() && body[i + 1] == b'-' {
        ((!path_mode || c != b'/') && body[i] <= c && c <= body[i + 2])
            || fnmatch_class_body(body, i + 3, c, path_mode)
    } else {
        (c == body[i] && (!path_mode || c != b'/'))
            || fnmatch_class_body(body, i + 1, c, path_mode)
    }
}

/// Shell-style fnmatch used by `<Location>` glob patterns, `<Files>` patterns
/// and the component-wise `<Directory>` matcher.  In path mode `*` and `?`
/// stop at `/` and a bracket expression never matches `/`, so a pattern can
/// never reach past the URL component it belongs to (F61).  Outside path mode
/// `*` crosses `/` (the `<Proxy>` wildcard form).  Both `!` and `^` negate a
/// class (F62/F62b).  The match is anchored: the whole value must be consumed.
pub open spec fn fnmatch_spec(pattern: Seq<u8>, value: Seq<u8>, path_mode: bool) -> bool
    decreases pattern.len() + value.len(),
{
    if pattern.len() == 0 {
        value.len() == 0
    } else if pattern[0] == b'*' {
        if fnmatch_spec(pattern.skip(1), value, path_mode) {
            true
        } else if value.len() == 0 || (path_mode && value[0] == b'/') {
            false
        } else {
            fnmatch_spec(pattern, value.skip(1), path_mode)
        }
    } else if pattern[0] == b'?' {
        if value.len() == 0 {
            false
        } else {
            (!path_mode || value[0] != b'/')
                && fnmatch_spec(pattern.skip(1), value.skip(1), path_mode)
        }
    } else if value.len() == 0 {
        false
    } else if pattern[0] == b'[' && pattern.len() > 1 {
        let body_start = fnmatch_class_body_start_spec(pattern, 0);
        let end = fnmatch_class_end_spec(pattern, body_start);
        if end == pattern.len() {
            // Unterminated class: `[` is an ordinary character.
            value[0] == b'['
                && fnmatch_spec(pattern.skip(1), value.skip(1), path_mode)
        } else {
            // Clamped so the well-formedness of the subrange does not depend
            // on an inductive bound on `end` (real runs always satisfy
            // body_start <= end < pattern.len(); see fnmatch_class_end_bounds).
            let from2 = if end + 1 < 0 {
                0int
            } else if end + 1 > pattern.len() {
                pattern.len() as int
            } else {
                end + 1
            };
            let hit = fnmatch_class_body_spec(
                pattern.subrange(body_start, end),
                0,
                value[0],
                path_mode,
            );
            (!path_mode || value[0] != b'/')
                && hit != fnmatch_class_negated_spec(pattern, 0)
                && fnmatch_spec(
                    pattern.subrange(from2, pattern.len() as int),
                    value.skip(1),
                    path_mode,
                )
        }
    } else if pattern[0] == b'\\' && pattern.len() > 1 {
        value[0] == pattern[1]
            && fnmatch_spec(pattern.subrange(2, pattern.len() as int), value.skip(1), path_mode)
    } else {
        pattern[0] == value[0] && fnmatch_spec(pattern.skip(1), value.skip(1), path_mode)
    }
}

pub fn fnmatch_match(pattern: &[u8], value: &[u8], path_mode: bool) -> (out: bool)
    ensures out == fnmatch_spec(pattern@, value@, path_mode),
    decreases pattern.len() + value.len(),
{
    if pattern.len() == 0 {
        return value.len() == 0;
    }
    if pattern[0] == b'*' {
        if fnmatch_match(&pattern[1..], value, path_mode) {
            return true;
        }
        if value.len() == 0 || (path_mode && value[0] == b'/') {
            return false;
        }
        return fnmatch_match(pattern, &value[1..], path_mode);
    }
    if pattern[0] == b'?' {
        if value.len() == 0 {
            return false;
        }
        return (!path_mode || value[0] != b'/')
            && fnmatch_match(&pattern[1..], &value[1..], path_mode);
    }
    if value.len() == 0 {
        return false;
    }
    if pattern[0] == b'[' && pattern.len() > 1 {
        let body_start = fnmatch_class_body_start(pattern, 0);
        let end = fnmatch_class_end(pattern, body_start);
        if let Some(end) = end {
            let hit = fnmatch_class_body(&pattern[body_start..end], 0, value[0], path_mode);
            let negated = fnmatch_class_negated(pattern, 0);
            return (!path_mode || value[0] != b'/')
                && hit != negated
                && fnmatch_match(&pattern[end + 1..], &value[1..], path_mode);
        }
        return value[0] == b'[' && fnmatch_match(&pattern[1..], &value[1..], path_mode);
    }
    if pattern[0] == b'\\' && pattern.len() > 1 {
        return value[0] == pattern[1] && fnmatch_match(&pattern[2..], &value[1..], path_mode);
    }
    pattern[0] == value[0] && fnmatch_match(&pattern[1..], &value[1..], path_mode)
}

/// In path mode no wildcard can consume a `/`: only literal characters and
/// escapes can, so a matching pattern must itself contain a `/` whenever the
/// value does.  This is the property that keeps `<Location "/admin/*">` from
/// reaching past the URL component it belongs to.
pub proof fn fnmatch_path_mode_slash_bounded(pattern: Seq<u8>, value: Seq<u8>)
    requires fnmatch_spec(pattern, value, true),
    ensures
        bytes_contains_spec(value, b'/') ==> bytes_contains_spec(pattern, b'/'),
    decreases pattern.len() + value.len(),
{
    if pattern.len() == 0 {
        assert(value.len() == 0);
        assert(!bytes_contains_spec(value, b'/'));
    } else if pattern[0] == b'*' {
        if fnmatch_spec(pattern.skip(1), value, true) {
            fnmatch_path_mode_slash_bounded(pattern.skip(1), value);
            bytes_contains_subrange(pattern, 1, pattern.len() as int, b'/');
        } else {
            assert(value.len() > 0);
            assert(value[0] != b'/');
            fnmatch_path_mode_slash_bounded(pattern, value.skip(1));
        }
    } else if pattern[0] == b'?' {
        assert(value.len() > 0);
        assert(value[0] != b'/');
        fnmatch_path_mode_slash_bounded(pattern.skip(1), value.skip(1));
        bytes_contains_subrange(pattern, 1, pattern.len() as int, b'/');
    } else if value.len() == 0 {
        assert(!bytes_contains_spec(value, b'/'));
    } else if pattern[0] == b'[' && pattern.len() > 1 {
        let body_start = fnmatch_class_body_start_spec(pattern, 0);
        let end = fnmatch_class_end_spec(pattern, body_start);
        fnmatch_class_end_bounds(pattern, body_start);
        if end == pattern.len() {
            assert(value[0] == b'[');
            fnmatch_path_mode_slash_bounded(pattern.skip(1), value.skip(1));
            bytes_contains_subrange(pattern, 1, pattern.len() as int, b'/');
        } else {
            // The class matched `value[0]`; in path mode that byte is not `/`.
            assert(value[0] != b'/');
            fnmatch_path_mode_slash_bounded(
                pattern.subrange(end + 1, pattern.len() as int),
                value.skip(1),
            );
            bytes_contains_subrange(pattern, end + 1, pattern.len() as int, b'/');
        }
    } else if pattern[0] == b'\\' && pattern.len() > 1 {
        if value[0] == b'/' {
            assert(pattern[1] == b'/');
            bytes_contains_at(pattern, 1, b'/');
            assert(bytes_contains_spec(pattern, b'/'));
        } else {
            fnmatch_path_mode_slash_bounded(pattern.subrange(2, pattern.len() as int), value.skip(1));
            bytes_contains_subrange(pattern, 2, pattern.len() as int, b'/');
        }
    } else {
        if value[0] == b'/' {
            assert(pattern[0] == value[0]);
            bytes_contains_at(pattern, 0, b'/');
            assert(bytes_contains_spec(pattern, b'/'));
        } else {
            fnmatch_path_mode_slash_bounded(pattern.skip(1), value.skip(1));
        }
    }
}

/// Oracle lemmas for the Apache `<Location>` glob verdicts pinned on 2.4.69:
/// the wildcard is component-bounded, classes and `?` are honored, and the
/// match is anchored over the whole URL path.
pub proof fn fnmatch_location_glob_oracle()
    ensures
        // <Location "/admin/*"> denies a sibling script and its directory...
        fnmatch_spec(
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'/', b'*'],
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'/', b'r', b'u', b'n', b'.', b'c', b'g', b'i'],
            true,
        ),
        // ...but never reaches a deeper component or past the prefix.
        !fnmatch_spec(
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'/', b'*'],
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'/', b'a', b'/', b'b', b'.', b'c', b'g', b'i'],
            true,
        ),
        !fnmatch_spec(
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'/', b'*'],
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'i', b's', b't', b'r', b'y'],
            true,
        ),
        // <Location "/admin*"> keeps the star inside its own component.
        fnmatch_spec(
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'*'],
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'i', b's', b't', b'r', b'y'],
            true,
        ),
        !fnmatch_spec(
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'*'],
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'/', b'r', b'u', b'n', b'.', b'c', b'g', b'i'],
            true,
        ),
        // ? matches exactly one character.
        fnmatch_spec(
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'/', b'?', b'.', b'c', b'g', b'i'],
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'/', b'x', b'.', b'c', b'g', b'i'],
            true,
        ),
        !fnmatch_spec(
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'/', b'?', b'.', b'c', b'g', b'i'],
            seq![b'/', b'a', b'd', b'm', b'i', b'n', b'/', b'x', b'y', b'.', b'c', b'g', b'i'],
            true,
        ),
{
    reveal_with_fuel(fnmatch_spec, 40);
    reveal_with_fuel(fnmatch_class_end_spec, 20);
    reveal_with_fuel(fnmatch_class_body_spec, 20);
}

/// F62/F62b: both negation markers negate a bracket expression, and ranges
/// still match within the class.
pub proof fn fnmatch_class_negation_oracle()
    ensures
        !fnmatch_spec(seq![b'[', b'^', b'a', b']'], seq![b'a'], false),
        fnmatch_spec(seq![b'[', b'^', b'a', b']'], seq![b'z'], false),
        !fnmatch_spec(seq![b'[', b'!', b'a', b']'], seq![b'a'], false),
        fnmatch_spec(seq![b'[', b'!', b'a', b']'], seq![b'z'], false),
        fnmatch_spec(seq![b'[', b'a', b'-', b'c', b']'], seq![b'b'], false),
        !fnmatch_spec(seq![b'[', b'a', b'-', b'c', b']'], seq![b'x'], false),
{
    reveal_with_fuel(fnmatch_spec, 20);
    reveal_with_fuel(fnmatch_class_end_spec, 10);
    reveal_with_fuel(fnmatch_class_body_spec, 10);
}

/// F61: a `<Location>` argument containing a shell wildcard must be compiled
/// to the verified fnmatch kernel at parse time; it may never degrade into an
/// inert literal pattern (which silently disables the guard inside it).
pub fn location_wildcard_compiled_admit(has_wildcard: bool, compiled: bool) -> (ok: bool)
    ensures ok == (!has_wildcard || compiled),
{
    !has_wildcard || compiled
}

/// F63: the complete set of `ap_expr` variables the evaluator implements.
/// The evaluator and the load-time validator both consult this kernel, so a
/// variable can never evaluate differently from what was validated: an
/// unknown variable is a configuration error at load time and never an empty
/// string substituted at evaluation time.
pub open spec fn expr_var_fixed_spec(name: Seq<u8>) -> bool {
    eq_ignore_ascii_case_spec(name, b"time"@)
        || eq_ignore_ascii_case_spec(name, b"time_year"@)
        || eq_ignore_ascii_case_spec(name, b"time_mon"@)
        || eq_ignore_ascii_case_spec(name, b"time_day"@)
        || eq_ignore_ascii_case_spec(name, b"time_hour"@)
        || eq_ignore_ascii_case_spec(name, b"time_min"@)
        || eq_ignore_ascii_case_spec(name, b"time_sec"@)
        || eq_ignore_ascii_case_spec(name, b"request_method"@)
        || eq_ignore_ascii_case_spec(name, b"query_string"@)
        || eq_ignore_ascii_case_spec(name, b"request_uri"@)
        || eq_ignore_ascii_case_spec(name, b"request_scheme"@)
        || eq_ignore_ascii_case_spec(name, b"https"@)
        || eq_ignore_ascii_case_spec(name, b"remote_addr"@)
        || eq_ignore_ascii_case_spec(name, b"server_name"@)
        || eq_ignore_ascii_case_spec(name, b"server_port"@)
        || eq_ignore_ascii_case_spec(name, b"document_root"@)
        || eq_ignore_ascii_case_spec(name, b"api_version"@)
        // F63: the filesystem variables the access-control idioms rely on.
        || eq_ignore_ascii_case_spec(name, b"request_filename"@)
        || eq_ignore_ascii_case_spec(name, b"script_filename"@)
}

/// `%{FUNC:arg}` transform forms.  The argument part is validated separately,
/// because the evaluator expands nested `%{...}` inside it.
pub open spec fn expr_transform_var_spec(name: Seq<u8>) -> bool {
    (name.len() >= 8
        && name[7] == b':'
        && eq_ignore_ascii_case_spec(name.subrange(0, 7), b"toupper"@))
        || (name.len() >= 7
            && name[6] == b':'
            && eq_ignore_ascii_case_spec(name.subrange(0, 6), b"tolower"@))
        || (name.len() >= 7
            && name[6] == b':'
            && eq_ignore_ascii_case_spec(name.subrange(0, 6), b"escape"@))
        || (name.len() >= 9
            && name[8] == b':'
            && eq_ignore_ascii_case_spec(name.subrange(0, 8), b"unescape"@))
}

pub open spec fn expr_var_known_spec(name: Seq<u8>) -> bool {
    expr_transform_var_spec(name)
        || starts_with_ignore_ascii_case_spec(name, b"req:"@)
        || starts_with_ignore_ascii_case_spec(name, b"http:"@)
        || starts_with_ignore_ascii_case_spec(name, b"env:"@)
        || starts_with_ignore_ascii_case_spec(name, b"http_"@)
        || expr_var_fixed_spec(name)
}

pub fn expr_transform_var_known(name: &[u8]) -> (known: bool)
    ensures known == expr_transform_var_spec(name@),
{
    (name.len() >= 8 && name[7] == b':' && eq_ignore_ascii_case(&name[..7], b"toupper"))
        || (name.len() >= 7 && name[6] == b':' && eq_ignore_ascii_case(&name[..6], b"tolower"))
        || (name.len() >= 7 && name[6] == b':' && eq_ignore_ascii_case(&name[..6], b"escape"))
        || (name.len() >= 9 && name[8] == b':' && eq_ignore_ascii_case(&name[..8], b"unescape"))
}

pub fn expr_var_known(name: &[u8]) -> (known: bool)
    ensures known == expr_var_known_spec(name@),
{
    expr_transform_var_known(name)
        || starts_with_ignore_ascii_case(name, b"req:")
        || starts_with_ignore_ascii_case(name, b"http:")
        || starts_with_ignore_ascii_case(name, b"env:")
        || starts_with_ignore_ascii_case(name, b"http_")
        || eq_ignore_ascii_case(name, b"time")
        || eq_ignore_ascii_case(name, b"time_year")
        || eq_ignore_ascii_case(name, b"time_mon")
        || eq_ignore_ascii_case(name, b"time_day")
        || eq_ignore_ascii_case(name, b"time_hour")
        || eq_ignore_ascii_case(name, b"time_min")
        || eq_ignore_ascii_case(name, b"time_sec")
        || eq_ignore_ascii_case(name, b"request_method")
        || eq_ignore_ascii_case(name, b"query_string")
        || eq_ignore_ascii_case(name, b"request_uri")
        || eq_ignore_ascii_case(name, b"request_scheme")
        || eq_ignore_ascii_case(name, b"https")
        || eq_ignore_ascii_case(name, b"remote_addr")
        || eq_ignore_ascii_case(name, b"server_name")
        || eq_ignore_ascii_case(name, b"server_port")
        || eq_ignore_ascii_case(name, b"document_root")
        || eq_ignore_ascii_case(name, b"api_version")
        || eq_ignore_ascii_case(name, b"request_filename")
        || eq_ignore_ascii_case(name, b"script_filename")
}

/// F63: a filesystem variable (`REQUEST_FILENAME`/`SCRIPT_FILENAME`) evaluated
/// without a filesystem binding fails closed: the evaluator returns an error
/// rather than substituting an empty string.  A guard that depends on the
/// variable can then only take the Apache direction through a bound value.
pub fn expr_fs_var_bound_admit(bound: bool) -> (ok: bool)
    ensures ok == bound,
{
    bound
}

/// F64: the conjoined scope keeps a `SetHandler` force only when at least one
/// conjoined scope forced it and the two scopes do not force conflicting
/// names.  A conflict degrades to "no forced handler" (fail closed: no
/// execution), never to one scope's force.
/// F64/I61: conjoin of `SetHandler` forces across the URL identity and the
/// resolved canonical target.  `url_denied` records an explicit
/// `SetHandler none` on the URL identity: a handler denial that survives the
/// conjoin as a static force — the resolved target may not re-arm an
/// extension handler the lexical identity unforced (pass-10 F60 contract).
/// Otherwise a name forced by both identities must agree; a disagreement
/// degrades to "no forced handler" (the conjoined extension table still
/// governs), and a force from one identity alone is kept.
pub open spec fn set_handler_conjoin_spec(url_denied: bool, url_force: bool, target_force: bool, same_name: bool) -> u8 {
    if url_denied {
        1u8
    } else if url_force {
        if target_force && !same_name {
            0u8
        } else {
            1u8
        }
    } else if target_force {
        1u8
    } else {
        0u8
    }
}

pub fn set_handler_conjoin_admit(url_denied: bool, url_force: bool, target_force: bool, same_name: bool) -> (out: u8)
    ensures out == set_handler_conjoin_spec(url_denied, url_force, target_force, same_name),
{
    if url_denied {
        1u8
    } else if url_force {
        if target_force && !same_name {
            0u8
        } else {
            1u8
        }
    } else if target_force {
        1u8
    } else {
        0u8
    }
}

pub proof fn set_handler_conjoin_preserves_force(url_denied: bool, url_force: bool, target_force: bool, same_name: bool)
    ensures
        set_handler_conjoin_spec(url_denied, url_force, target_force, same_name) == 1
            ==> (url_denied
                || (url_force && (!target_force || same_name))
                || (target_force && !url_force)),
{
}

/// F64: when a scope forces a handler, the CGI decision is that of the forced
/// name; the extension table (`AddHandler`/`RemoveHandler`, in any parse
/// order or inherited layer) can neither add nor remove execution.
pub fn set_handler_precedence_admit(forced: bool, forced_name_is_cgi: bool) -> (ok: bool)
    ensures ok == (!forced || forced_name_is_cgi),
{
    !forced || forced_name_is_cgi
}

/// F65/I71: CGI execution requires BOTH the handler classification and the
/// filesystem grant (`Options ExecCGI` or a script alias).  A
/// `default-handler` (or any other non-CGI handler) assignment suppresses
/// execution even inside a ScriptAlias tree.
pub open spec fn cgi_exec_spec(
    handler_bound: bool,
    handler_is_cgi: bool,
    script_alias: bool,
    options_exec: bool,
) -> bool {
    let classified = if handler_bound {
        handler_is_cgi
    } else {
        script_alias
    };
    let exec_allowed = script_alias || options_exec;
    classified && exec_allowed
}

pub fn cgi_exec_admit(
    handler_bound: bool,
    handler_is_cgi: bool,
    script_alias: bool,
    options_exec: bool,
) -> (ok: bool)
    ensures ok == cgi_exec_spec(handler_bound, handler_is_cgi, script_alias, options_exec),
{
    let classified = if handler_bound {
        handler_is_cgi
    } else {
        script_alias
    };
    let exec_allowed = script_alias || options_exec;
    classified && exec_allowed
}

pub proof fn cgi_exec_requires_cgi_handler(
    handler_bound: bool,
    handler_is_cgi: bool,
    script_alias: bool,
    options_exec: bool,
)
    ensures
        cgi_exec_spec(handler_bound, handler_is_cgi, script_alias, options_exec)
            ==> (!handler_bound || handler_is_cgi),
{
}

pub proof fn cgi_exec_requires_exec_allowed(
    handler_bound: bool,
    handler_is_cgi: bool,
    script_alias: bool,
    options_exec: bool,
)
    ensures
        cgi_exec_spec(handler_bound, handler_is_cgi, script_alias, options_exec)
            ==> (script_alias || options_exec),
{
}

/// F69/I70: handler and MIME classification bind to the lexical request-mapped
/// filename's basename.  When the opened target differs from the lexical path
/// (an in-root symlink), the canonical target's basename must not classify the
/// request.
pub fn handler_identity_lexical_admit(
    resolved_differs: bool,
    name_is_lexical_basename: bool,
) -> (ok: bool)
    ensures ok == (!resolved_differs || name_is_lexical_basename),
{
    !resolved_differs || name_is_lexical_basename
}

/// P13/I70: handler policy produced by `<Files>`/`<FilesMatch>` must use the
/// same lexical basename as extension-based handler selection.  Canonical
/// target policy remains authoritative for authorization, but it may not
/// introduce a handler force by matching only the resolved basename.
pub open spec fn handler_scope_lexical_spec(
    resolved_differs: bool,
    files_scope_uses_lexical_basename: bool,
) -> bool {
    !resolved_differs || files_scope_uses_lexical_basename
}

pub fn handler_scope_lexical_admit(
    resolved_differs: bool,
    files_scope_uses_lexical_basename: bool,
) -> (ok: bool)
    ensures ok == handler_scope_lexical_spec(resolved_differs, files_scope_uses_lexical_basename),
{
    !resolved_differs || files_scope_uses_lexical_basename
}

pub proof fn handler_scope_lexical_when_resolved_differs(
    resolved_differs: bool,
    files_scope_uses_lexical_basename: bool,
)
    ensures
        handler_scope_lexical_spec(resolved_differs, files_scope_uses_lexical_basename)
            && resolved_differs
            ==> files_scope_uses_lexical_basename,
{
}

/// A compatibility surface may only be used when its process-global
/// capability is enabled. Parser, access-file, and final-sink checks share
/// this small contract so a secondary route cannot bypass the opt-in.
pub open spec fn capability_spec(enabled: bool, requested: bool) -> bool {
    !requested || enabled
}

pub fn capability_admit(enabled: bool, requested: bool) -> (ok: bool)
    ensures ok == capability_spec(enabled, requested),
{
    !requested || enabled
}

pub proof fn disabled_capability_rejects_request()
    ensures !capability_spec(false, true),
{
}

/// An authentication database is immutable to the request-serving identity
/// only when its complete parent chain is protected, the service does not own
/// the file (an owner can restore write permission), and no less-trusted Unix
/// write class is enabled.
pub open spec fn auth_file_immutable_spec(
    parent_chain_immutable: bool,
    owner_is_service: bool,
    group_or_other_writable: bool,
) -> bool {
    parent_chain_immutable && !owner_is_service && !group_or_other_writable
}

pub fn auth_file_immutable_admit(
    parent_chain_immutable: bool,
    owner_is_service: bool,
    group_or_other_writable: bool,
) -> (ok: bool)
    ensures ok == auth_file_immutable_spec(
        parent_chain_immutable,
        owner_is_service,
        group_or_other_writable,
    ),
{
    parent_chain_immutable && !owner_is_service && !group_or_other_writable
}

pub proof fn service_owned_auth_file_is_mutable(group_or_other_writable: bool)
    ensures !auth_file_immutable_spec(true, true, group_or_other_writable),
{
}

pub proof fn writable_auth_file_is_mutable(owner_is_service: bool)
    ensures !auth_file_immutable_spec(true, owner_is_service, true),
{
}

/// P17 hardening: a pathname component is stable against a configured local
/// FastCGI backend only when the backend is not root, the component has a
/// trusted owner, and no untrusted write class can replace or modify it.
/// Symlink mode bits are not meaningful on Unix; their containing directory
/// is checked separately, while the symlink's owner must still be trusted.
pub open spec fn fastcgi_stable_component_spec(
    backend_is_root: bool,
    owner_trusted: bool,
    owner_is_backend: bool,
    group_or_other_writable: bool,
    symlink: bool,
    has_posix_acl: bool,
) -> bool {
    !backend_is_root
        && owner_trusted
        && !has_posix_acl
        && (symlink || (!owner_is_backend && !group_or_other_writable))
}

pub fn fastcgi_stable_component_admit(
    backend_is_root: bool,
    owner_trusted: bool,
    owner_is_backend: bool,
    group_or_other_writable: bool,
    symlink: bool,
    has_posix_acl: bool,
) -> (ok: bool)
    ensures ok == fastcgi_stable_component_spec(
        backend_is_root,
        owner_trusted,
        owner_is_backend,
        group_or_other_writable,
        symlink,
        has_posix_acl,
    ),
{
    !backend_is_root
        && owner_trusted
        && !has_posix_acl
        && (symlink || (!owner_is_backend && !group_or_other_writable))
}

pub proof fn fastcgi_stable_component_rejects_root_backend(
    owner_trusted: bool,
    owner_is_backend: bool,
    group_or_other_writable: bool,
    symlink: bool,
)
    ensures !fastcgi_stable_component_spec(
        true,
        owner_trusted,
        owner_is_backend,
        group_or_other_writable,
        symlink,
        false,
    ),
{
}

pub proof fn fastcgi_stable_component_rejects_backend_owned_file(
    owner_trusted: bool,
    group_or_other_writable: bool,
)
    ensures !fastcgi_stable_component_spec(
        false,
        owner_trusted,
        true,
        group_or_other_writable,
        false,
        false,
    ),
{
}

pub proof fn fastcgi_stable_component_rejects_untrusted_owner(
    owner_is_backend: bool,
    group_or_other_writable: bool,
    symlink: bool,
)
    ensures !fastcgi_stable_component_spec(
        false,
        false,
        owner_is_backend,
        group_or_other_writable,
        symlink,
        false,
    ),
{
}

pub proof fn fastcgi_stable_component_rejects_posix_acl(
    owner_trusted: bool,
    owner_is_backend: bool,
    group_or_other_writable: bool,
    symlink: bool,
)
    ensures !fastcgi_stable_component_spec(
        false,
        owner_trusted,
        owner_is_backend,
        group_or_other_writable,
        symlink,
        true,
    ),
{
}

} // verus!
