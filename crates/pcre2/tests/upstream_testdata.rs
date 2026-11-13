//! Rust runner for the public-domain PCRE2 `pcre2test` corpus.
//!
//! Set `PCRE2_TESTDATA` to a PCRE2 10.46 `testdata` directory. The runner
//! imports the single-line 8-bit cases from `testinput1`, compiles every case
//! admitted by httpd-rs's non-backtracking dialect in both engines, and checks
//! captures byte-for-byte. Complex `pcre2test` control records are skipped;
//! the deterministic corpus and libFuzzer target cover the importer itself.

use std::path::Path;

use httpd_rs_pcre2::bytes as rust;
use pcre2_c_oracle::bytes as oracle;

#[derive(Clone, Copy, Default)]
struct Flags {
    caseless: bool,
    dotall: bool,
    extended: bool,
    multiline: bool,
}

fn pattern_record(line: &str) -> Option<(String, Flags)> {
    if !line.starts_with('/') {
        return None;
    }
    let bytes = line.as_bytes();
    let mut closing = None;
    for index in (1..bytes.len()).rev() {
        if bytes[index] != b'/' {
            continue;
        }
        let slashes = bytes[..index]
            .iter()
            .rev()
            .take_while(|&&b| b == b'\\')
            .count();
        if slashes % 2 == 0 {
            closing = Some(index);
            break;
        }
    }
    let closing = closing?;
    let modifiers = line[closing + 1..].trim();
    if !modifiers
        .chars()
        .all(|flag| matches!(flag, 'i' | 'm' | 's' | 'x'))
    {
        return None;
    }
    let mut pattern = String::new();
    let mut chars = line[1..closing].chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' && chars.peek() == Some(&'/') {
            chars.next();
            pattern.push('/');
        } else {
            pattern.push(ch);
        }
    }
    Some((
        pattern,
        Flags {
            caseless: modifiers.contains('i'),
            dotall: modifiers.contains('s'),
            extended: modifiers.contains('x'),
            multiline: modifiers.contains('m'),
        },
    ))
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn subject_record(line: &str) -> Option<Vec<u8>> {
    if !line.starts_with(char::is_whitespace) {
        return None;
    }
    let text = line.trim_start();
    if text.is_empty()
        || text.starts_with('#')
        || text.starts_with('>')
        || text.starts_with("\\=")
        || text.contains("\\O")
        || text.contains("\\C")
        || text.contains("\\G")
        || text.contains("\\L")
        || text.contains("\\M")
        || text.contains("\\P")
        || text.contains("\\S")
    {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            let ch = text[i..].chars().next()?;
            let length = ch.len_utf8();
            out.extend_from_slice(&bytes[i..i + length]);
            i += length;
            continue;
        }
        let escaped = *bytes.get(i + 1)?;
        match escaped {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'f' => out.push(0x0c),
            b'a' => out.push(0x07),
            b'e' => out.push(0x1b),
            b'b' => out.push(0x08),
            b'\\' => out.push(b'\\'),
            b'x' if bytes.get(i + 2) == Some(&b'{') => {
                let end = bytes[i + 3..].iter().position(|&b| b == b'}')? + i + 3;
                let value = u32::from_str_radix(&text[i + 3..end], 16).ok()?;
                let byte = u8::try_from(value).ok()?;
                out.push(byte);
                i = end + 1;
                continue;
            }
            b'x' => {
                let hi = hex(*bytes.get(i + 2)?)?;
                let lo = hex(*bytes.get(i + 3)?)?;
                out.push((hi << 4) | lo);
                i += 4;
                continue;
            }
            b'0'..=b'7' => {
                let mut end = i + 1;
                while end < bytes.len() && end < i + 4 && matches!(bytes[end], b'0'..=b'7') {
                    end += 1;
                }
                out.push(u8::from_str_radix(&text[i + 1..end], 8).ok()?);
                i = end;
                continue;
            }
            b'$' | b'?' | b'/' | b'"' | b'\'' => out.push(escaped),
            _ => return None,
        }
        i += 2;
    }
    Some(out)
}

fn rust_regex(pattern: &str, flags: Flags) -> Option<rust::Regex> {
    let mut builder = rust::RegexBuilder::new();
    builder
        .caseless(flags.caseless)
        .dotall(flags.dotall)
        .extended(flags.extended)
        .multi_line(flags.multiline)
        .max_subject_size(256 * 1024)
        .match_limit(256 * 1024 * 1024);
    builder.build(pattern).ok()
}

fn oracle_regex(pattern: &str, flags: Flags) -> oracle::Regex {
    let mut builder = oracle::RegexBuilder::new();
    builder
        .caseless(flags.caseless)
        .dotall(flags.dotall)
        .extended(flags.extended)
        .multi_line(flags.multiline);
    builder.build(pattern).unwrap_or_else(|error| {
        panic!("admitted pattern {pattern:?} did not compile in PCRE2: {error}")
    })
}

fn rust_spans(regex: &rust::Regex, subject: &[u8]) -> Option<Vec<Option<(usize, usize)>>> {
    regex.captures(subject).unwrap().map(|captures| {
        (0..captures.len())
            .map(|index| captures.get(index).map(|m| (m.start(), m.end())))
            .collect()
    })
}

fn oracle_spans(regex: &oracle::Regex, subject: &[u8]) -> Option<Vec<Option<(usize, usize)>>> {
    regex.captures(subject).unwrap().map(|captures| {
        (0..captures.len())
            .map(|index| captures.get(index).map(|m| (m.start(), m.end())))
            .collect()
    })
}

#[test]
fn ported_upstream_testinput1_matches_c_oracle() {
    let Some(root) = std::env::var_os("PCRE2_TESTDATA") else {
        eprintln!("PCRE2_TESTDATA not set; committed and exhaustive differential cases still ran");
        return;
    };
    let input =
        std::fs::read(Path::new(&root).join("testinput1")).expect("read PCRE2 10.46 testinput1");
    let mut current = None;
    let mut checked = 0usize;
    for (line_number, raw_line) in input.split(|&byte| byte == b'\n').enumerate() {
        let Ok(line) = std::str::from_utf8(raw_line.strip_suffix(b"\r").unwrap_or(raw_line)) else {
            current = None;
            continue;
        };
        if let Some((pattern, flags)) = pattern_record(line) {
            current = rust_regex(&pattern, flags).map(|rust| {
                let oracle = oracle_regex(&pattern, flags);
                (pattern, rust, oracle)
            });
            continue;
        }
        let Some(subject) = subject_record(line) else {
            continue;
        };
        let Some((pattern, rust, oracle)) = &current else {
            continue;
        };
        assert_eq!(
            rust_spans(rust, &subject),
            oracle_spans(oracle, &subject),
            "testinput1:{}, pattern {pattern:?}, subject {subject:?}, translated {:?}",
            line_number + 1,
            rust.translated_pattern(),
        );
        checked += 1;
    }
    assert!(
        checked >= 1_000,
        "only {checked} upstream subject cases were imported"
    );
    eprintln!("checked {checked} upstream PCRE2 subject cases");
}
