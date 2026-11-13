#![no_main]

// Full API differential for the in-tree PCRE2 compatibility engine.
//
// Byte zero remains the legacy pattern/subject separator. A newline is also
// accepted so important seeds can be reviewed as text. The first byte selects
// builder flags; printable bytes are biased by subtracting ASCII space, which
// lets text seeds use ` ` for byte mode, `0` for CRLF, `@` for UTF and `` ` ``
// for UCP. The historical P23 binary corpus remains compatible.

use libfuzzer_sys::fuzz_target;
use pcre2_c_oracle::bytes as oracle;
use httpd_rs_pcre2::bytes as rust;

type CaptureSpans = Vec<Option<(usize, usize)>>;
type AllCaptureSpans = Vec<CaptureSpans>;

// The high control bit selects a grammar that emits only constructs in the
// documented admitted subset. Raw mutation remains useful for totality and
// Rust-accepts/PCRE2-rejects checks, while this mode makes an unexpected Rust
// rejection a fuzz failure instead of silently classifying it as fail-closed.
fn admitted_pattern(data: &[u8], flags: u8) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut pattern = String::new();
    if data[0] & 1 != 0 {
        pattern.push_str(r"\A");
    }
    let count = usize::from(data[0] >> 1).clamp(1, 8);
    for index in 0..count {
        let atom_control = data.get(1 + index * 2).copied().unwrap_or(0);
        let repeat_control = data.get(2 + index * 2).copied().unwrap_or(0);
        let quantifiable = match atom_control % 14 {
            0 => {
                pattern.push('a');
                true
            }
            1 => {
                pattern.push('b');
                true
            }
            2 if flags & 18 != 18 => {
                pattern.push('.');
                true
            }
            2 => {
                pattern.push('c');
                true
            }
            3 => {
                pattern.push_str("[ab]");
                true
            }
            4 if flags & 16 == 0 => {
                pattern.push_str("[^a]");
                true
            }
            4 => {
                pattern.push_str("[bc]");
                true
            }
            5 => {
                pattern.push_str(r"\d");
                true
            }
            6 => {
                pattern.push_str(r"\w");
                true
            }
            7 if flags & 16 == 0 => {
                pattern.push_str(r"\s");
                true
            }
            7 => {
                pattern.push_str(r"[ \t]");
                true
            }
            8 => {
                pattern.push_str(r"\x61");
                true
            }
            9 => {
                pattern.push_str(r"\Qa.b\E");
                true
            }
            10 => {
                pattern.push_str("(?:a|b)");
                true
            }
            11 => {
                pattern.push_str(&format!("(?<n{index}>a)"));
                false
            }
            12 => {
                pattern.push_str("(?#comment)a");
                true
            }
            13 => {
                pattern.push_str(r"a\Kb");
                false
            }
            _ => unreachable!(),
        };
        if quantifiable {
            pattern.push_str(match repeat_control % 7 {
                0 => "",
                1 => "?",
                2 => "*",
                3 => "+",
                4 => "{0,2}",
                5 => "{1,3}",
                6 => "*?",
                _ => unreachable!(),
            });
        }
    }
    if data[0] & 2 != 0 {
        pattern.push_str(r"\z");
    }
    pattern
}

fn rust_match_span(
    result: Result<Option<rust::Match<'_>>, httpd_rs_pcre2::Error>,
) -> Result<Option<(usize, usize)>, ()> {
    result
        .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
        .map_err(|_| ())
}

fn oracle_match_span(
    result: Result<Option<oracle::Match<'_>>, pcre2_c_oracle::Error>,
) -> Result<Option<(usize, usize)>, ()> {
    result
        .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
        .map_err(|_| ())
}

fn rust_captures_at(
    regex: &rust::Regex,
    subject: &[u8],
    start: usize,
) -> Result<Option<CaptureSpans>, ()> {
    let mut locations = regex.capture_locations();
    let matched = regex
        .captures_read_at(&mut locations, subject, start)
        .map_err(|_| ())?;
    Ok(matched.map(|_| {
        (0..locations.len())
            .map(|index| locations.get(index))
            .collect()
    }))
}

fn oracle_captures_at(
    regex: &oracle::Regex,
    subject: &[u8],
    start: usize,
) -> Result<Option<CaptureSpans>, ()> {
    let mut locations = regex.capture_locations();
    let matched = regex
        .captures_read_at(&mut locations, subject, start)
        .map_err(|_| ())?;
    Ok(matched.map(|_| {
        (0..locations.len())
            .map(|index| locations.get(index))
            .collect()
    }))
}

fn rust_direct_captures(regex: &rust::Regex, subject: &[u8]) -> Result<Option<CaptureSpans>, ()> {
    regex
        .captures(subject)
        .map(|captures| {
            captures.map(|captures| {
                (0..captures.len())
                    .map(|index| captures.get(index).map(|m| (m.start(), m.end())))
                    .collect()
            })
        })
        .map_err(|_| ())
}

fn oracle_direct_captures(
    regex: &oracle::Regex,
    subject: &[u8],
) -> Result<Option<CaptureSpans>, ()> {
    regex
        .captures(subject)
        .map(|captures| {
            captures.map(|captures| {
                (0..captures.len())
                    .map(|index| captures.get(index).map(|m| (m.start(), m.end())))
                    .collect()
            })
        })
        .map_err(|_| ())
}

fn rust_capture_iter(regex: &rust::Regex, subject: &[u8]) -> Result<AllCaptureSpans, ()> {
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

fn oracle_capture_iter(regex: &oracle::Regex, subject: &[u8]) -> Result<AllCaptureSpans, ()> {
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

fn rust_find_iter(regex: &rust::Regex, subject: &[u8]) -> Result<Vec<(usize, usize)>, ()> {
    regex
        .find_iter(subject)
        .map(|result| {
            result
                .map(|matched| (matched.start(), matched.end()))
                .map_err(|_| ())
        })
        .collect()
}

fn oracle_find_iter(regex: &oracle::Regex, subject: &[u8]) -> Result<Vec<(usize, usize)>, ()> {
    regex
        .find_iter(subject)
        .map(|result| {
            result
                .map(|matched| (matched.start(), matched.end()))
                .map_err(|_| ())
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, rest)) = data.split_first() else {
        return;
    };
    let Some(split) = rest.iter().position(|&byte| byte == 0 || byte == b'\n') else {
        return;
    };
    let structured = control & 0x80 != 0;
    let generated_pattern;
    let pattern = if structured {
        generated_pattern = admitted_pattern(&rest[..split], control & 0x7f);
        generated_pattern.as_str()
    } else {
        let Ok(pattern) = std::str::from_utf8(&rest[..split]) else {
            return;
        };
        pattern
    };
    let subject = &rest[split + 1..];
    if pattern.len() > 4096 || subject.len() > 16 * 1024 {
        return;
    }

    let flags = if structured {
        control & 0x7f
    } else if control.is_ascii_graphic() || control == b' ' {
        control - b' '
    } else {
        control
    };
    let caseless = flags & 1 != 0;
    let dotall = flags & 2 != 0;
    let multiline = flags & 4 != 0;
    let extended = flags & 8 != 0;
    let crlf = flags & 16 != 0;
    let utf = flags & 32 != 0;
    let ucp = flags & 64 != 0;

    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder
        .caseless(caseless)
        .dotall(dotall)
        .multi_line(multiline)
        .extended(extended)
        .crlf(crlf)
        .utf(utf)
        .ucp(ucp)
        .max_subject_size(16 * 1024)
        .match_limit(u64::MAX);
    let rust_regex = match rust_builder.build(pattern) {
        Ok(regex) => regex,
        Err(error) if structured => {
            panic!(
                "Rust rejected admitted grammar pattern {pattern:?}, flags={flags:#04x}: {error}"
            )
        }
        Err(_) => {
            // Raw mutation deliberately reaches constructs whose priority or
            // capture history requires backtracking. Their fail-closed
            // rejection is checked by focused tests; the structured mode
            // above prevents this exemption from hiding admission regressions
            // in the supported grammar.
            return;
        }
    };

    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder
        .caseless(caseless)
        .dotall(dotall)
        .multi_line(multiline)
        .extended(extended)
        .crlf(crlf)
        .utf(utf)
        .ucp(ucp);
    let oracle_regex = oracle_builder.build(pattern).unwrap_or_else(|error| {
        panic!("Rust accepted a PCRE2-rejected pattern {pattern:?}, flags={flags:#04x}: {error}")
    });

    assert_eq!(
        rust_regex.captures_len(),
        oracle_regex.captures_len(),
        "capture count: pattern {pattern:?}, flags={flags:#04x}, translated {:?}",
        rust_regex.translated_pattern(),
    );
    assert_eq!(
        rust_regex.capture_names(),
        oracle_regex.capture_names(),
        "capture names: pattern {pattern:?}, flags={flags:#04x}, translated {:?}",
        rust_regex.translated_pattern(),
    );

    let starts = [
        0,
        subject.len(),
        (usize::from(control).wrapping_mul(257) + pattern.len()) % (subject.len() + 1),
    ];
    if (utf || ucp) && std::str::from_utf8(subject).is_err() {
        // Strict PCRE2 validation windows move with offsets, anchors and word
        // boundaries, while UCP's MATCH_INVALID_UTF uses fragment barriers.
        // Production deliberately rejects the complete malformed subject for
        // both modes. Exercise every API and require that fail-closed boundary.
        for &start in &starts {
            assert!(rust_regex.is_match_at(subject, start).is_err());
            assert!(rust_regex.find_at(subject, start).is_err());
            assert!(rust_captures_at(&rust_regex, subject, start).is_err());
        }
        assert!(rust_direct_captures(&rust_regex, subject).is_err());
        assert!(rust_capture_iter(&rust_regex, subject).is_err());
        assert!(rust_find_iter(&rust_regex, subject).is_err());
        return;
    }
    for (position, &start) in starts.iter().enumerate() {
        if starts[..position].contains(&start) {
            continue;
        }

        let rust_is_match = rust_regex.is_match_at(subject, start).map_err(|_| ());
        let oracle_is_match = oracle_regex.is_match_at(subject, start).map_err(|_| ());
        assert_eq!(
            rust_is_match,
            oracle_is_match,
            "is_match_at({start}): pattern {pattern:?}, subject {subject:?}, flags={flags:#04x}, translated {:?}",
            rust_regex.translated_pattern(),
        );

        let rust_find = rust_match_span(rust_regex.find_at(subject, start));
        let oracle_find = oracle_match_span(oracle_regex.find_at(subject, start));
        assert_eq!(
            rust_find,
            oracle_find,
            "find_at({start}): pattern {pattern:?}, subject {subject:?}, flags={flags:#04x}, translated {:?}",
            rust_regex.translated_pattern(),
        );
        assert_eq!(rust_is_match, rust_find.map(|matched| matched.is_some()));
        assert_eq!(
            oracle_is_match,
            oracle_find.map(|matched| matched.is_some())
        );

        let rust_captures = rust_captures_at(&rust_regex, subject, start);
        let oracle_captures = oracle_captures_at(&oracle_regex, subject, start);
        assert_eq!(
            rust_captures,
            oracle_captures,
            "captures_read_at({start}): pattern {pattern:?}, subject {subject:?}, flags={flags:#04x}, translated {:?}",
            rust_regex.translated_pattern(),
        );
        assert_eq!(
            rust_find,
            rust_captures.map(|captures| captures.and_then(|captures| captures[0]))
        );
        assert_eq!(
            oracle_find,
            oracle_captures.map(|captures| captures.and_then(|captures| captures[0]))
        );

        // Tier promotion occurs after the first search. Repeating an API call
        // makes cold PikeVM and hot lazy-DFA behavior part of every input.
        assert_eq!(
            rust_find,
            rust_match_span(rust_regex.find_at(subject, start)),
            "cold/hot mismatch: pattern {pattern:?}, subject {subject:?}, flags={flags:#04x}"
        );
    }

    let rust_direct = rust_direct_captures(&rust_regex, subject);
    let oracle_direct = oracle_direct_captures(&oracle_regex, subject);
    assert_eq!(
        rust_direct,
        oracle_direct,
        "captures: pattern {pattern:?}, subject {subject:?}, flags={flags:#04x}, translated {:?}",
        rust_regex.translated_pattern(),
    );

    let rust_captures = rust_capture_iter(&rust_regex, subject);
    let oracle_captures = oracle_capture_iter(&oracle_regex, subject);
    assert_eq!(
        rust_captures,
        oracle_captures,
        "captures_iter: pattern {pattern:?}, subject {subject:?}, flags={flags:#04x}, translated {:?}",
        rust_regex.translated_pattern(),
    );

    let rust_matches = rust_find_iter(&rust_regex, subject);
    let oracle_matches = oracle_find_iter(&oracle_regex, subject);
    assert_eq!(
        rust_matches,
        oracle_matches,
        "find_iter: pattern {pattern:?}, subject {subject:?}, flags={flags:#04x}, translated {:?}",
        rust_regex.translated_pattern(),
    );
    assert_eq!(
        rust_matches,
        rust_captures.map(|captures| {
            captures
                .into_iter()
                .map(|captures| captures[0].expect("group zero always matches"))
                .collect()
        })
    );
});
