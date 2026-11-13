// Coverage-guided differential fuzzer for the P23 PCRE2 compatibility work.
//
// The first byte selects PCRE2 flags, a NUL separates the UTF-8 pattern from
// the raw-byte subject, and PCRE2 10.46 is the behavioral oracle. Production
// deliberately rejects recursive/backtracking-only syntax, so rejected Rust
// patterns are outside this target's comparison domain.

use libfuzzer_sys::fuzz_target;
use pcre2_c_oracle::bytes as oracle;
use httpd_rs_pcre2::bytes as rust;

fn rust_spans(regex: &rust::Regex, subject: &[u8]) -> Result<Vec<Vec<Option<(usize, usize)>>>, ()> {
    regex
        .captures_iter(subject)
        .map(|result| {
            result.map_err(|_| ()).map(|captures| {
                (0..captures.len())
                    .map(|index| captures.get(index).map(|m| (m.start(), m.end())))
                    .collect()
            })
        })
        .collect()
}

fn oracle_spans(
    regex: &oracle::Regex,
    subject: &[u8],
) -> Result<Vec<Vec<Option<(usize, usize)>>>, ()> {
    regex
        .captures_iter(subject)
        .map(|result| {
            result.map_err(|_| ()).map(|captures| {
                (0..captures.len())
                    .map(|index| captures.get(index).map(|m| (m.start(), m.end())))
                    .collect()
            })
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let Some(split) = rest.iter().position(|&byte| byte == 0) else {
        return;
    };
    let Ok(pattern) = std::str::from_utf8(&rest[..split]) else {
        return;
    };
    let subject = &rest[split + 1..];
    if pattern.len() > 4096 || subject.len() > 16 * 1024 {
        return;
    }

    let caseless = flags & 1 != 0;
    let dotall = flags & 2 != 0;
    let multiline = flags & 4 != 0;
    let extended = flags & 8 != 0;

    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder
        .caseless(caseless)
        .dotall(dotall)
        .multi_line(multiline)
        .extended(extended)
        .max_subject_size(16 * 1024)
        .match_limit(256 * 1024 * 1024);
    let Ok(rust_regex) = rust_builder.build(pattern) else {
        return;
    };

    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder
        .caseless(caseless)
        .dotall(dotall)
        .multi_line(multiline)
        .extended(extended);
    let oracle_regex = oracle_builder
        .build(pattern)
        .expect("the Rust compatibility parser accepted a pattern rejected by PCRE2");

    assert_eq!(
        rust_spans(&rust_regex, subject),
        oracle_spans(&oracle_regex, subject),
        "pattern {pattern:?}, subject {subject:?}, translated {:?}",
        rust_regex.translated_pattern(),
    );
});
