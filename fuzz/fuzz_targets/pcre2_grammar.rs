#![no_main]

// Admission-focused complement to `pcre2_differential`.
//
// Input byte zero selects one of four independent checks:
//   0. raw UTF-8: every vapache-accepted pattern must compile in PCRE2;
//   1. generated whitelist: both engines must compile and agree on captures;
//   2. generated exclusion: constructs outside vapache's grammar must reject;
//   3. lexical control: excluded-looking text in literals/classes/comments
//      must not be mistaken for active syntax.
//
// Byte one supplies the seven RegexBuilder flags. Remaining bytes drive the
// generator and an ASCII subject. Keeping this target admission-focused makes
// it substantially faster than the full API/tier differential while retaining
// the C PCRE2 10.46 parser as an independent oracle.

use libfuzzer_sys::fuzz_target;
use pcre2_c_oracle::bytes as oracle;
use vapache_pcre2::bytes as rust;

type CaptureSpans = Vec<Option<(usize, usize)>>;

fn configure_rust(flags: u8) -> rust::RegexBuilder {
    let mut builder = rust::RegexBuilder::new();
    builder
        .caseless(flags & 1 != 0)
        .dotall(flags & 2 != 0)
        .multi_line(flags & 4 != 0)
        .extended(flags & 8 != 0)
        .crlf(flags & 16 != 0)
        .utf(flags & 32 != 0)
        .ucp(flags & 64 != 0)
        .max_subject_size(1024)
        .match_limit(u64::MAX);
    builder
}

fn configure_oracle(flags: u8) -> oracle::RegexBuilder {
    let mut builder = oracle::RegexBuilder::new();
    builder
        .caseless(flags & 1 != 0)
        .dotall(flags & 2 != 0)
        .multi_line(flags & 4 != 0)
        .extended(flags & 8 != 0)
        .crlf(flags & 16 != 0)
        .utf(flags & 32 != 0)
        .ucp(flags & 64 != 0);
    builder
}

fn generated_subject(data: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8] = b"abcABC09._-<> \t\r\n";
    data.iter()
        .take(256)
        .map(|byte| ALPHABET[usize::from(*byte) % ALPHABET.len()])
        .collect()
}

fn generated_admitted(data: &[u8], flags: u8) -> String {
    let control = data.first().copied().unwrap_or(0);
    let unicode = flags & (32 | 64) != 0;
    let crlf = flags & 16 != 0;
    let dotall = flags & 2 != 0 || control % 8 == 3;
    let mut pattern = String::new();
    pattern.push_str(match control % 8 {
        0 => "",
        1 => "(?i)",
        2 => "(?m)",
        3 => "(?s)",
        4 => "(?U)",
        5 => "(?x)",
        6 => "(?im-s)",
        7 => "(?x-i)",
        _ => unreachable!(),
    });
    if control & 8 != 0 {
        pattern.push_str(r"\A");
    }

    let count = usize::from(control >> 4).clamp(1, 12);
    for index in 0..count {
        let atom = data.get(1 + index * 2).copied().unwrap_or(0);
        let repetition = data.get(2 + index * 2).copied().unwrap_or(0);
        let quantifiable = match atom % 32 {
            0 => {
                pattern.push('a');
                true
            }
            1 => {
                pattern.push('b');
                true
            }
            2 if !(crlf && dotall) => {
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
            4 if !crlf => {
                pattern.push_str("[^a]");
                true
            }
            4 => {
                pattern.push_str("[bc]");
                true
            }
            5 if !unicode => {
                pattern.push_str("[[:digit:]]");
                true
            }
            6 if !unicode && !crlf => {
                pattern.push_str("[[:^space:]]");
                true
            }
            5 | 6 => {
                pattern.push_str("[A-F0-9]");
                true
            }
            7 => {
                pattern.push_str(r"[\x20-\x7E]");
                true
            }
            8 => {
                pattern.push_str(r"\d");
                true
            }
            9 if !crlf => {
                pattern.push_str(r"\D");
                true
            }
            9 => {
                pattern.push_str(r"\d");
                true
            }
            10 => {
                pattern.push_str(r"\w");
                true
            }
            11 if !crlf => {
                pattern.push_str(r"\W");
                true
            }
            11 => {
                pattern.push_str(r"\w");
                true
            }
            12 if !crlf => {
                pattern.push_str(r"\s");
                true
            }
            12 => {
                pattern.push_str(r"[ \t]");
                true
            }
            13 => {
                pattern.push_str(r"\S");
                true
            }
            14 => {
                pattern.push_str(r"\x61");
                true
            }
            15 => {
                pattern.push_str(r"\x{62}");
                true
            }
            16 => {
                pattern.push_str(r"\o{143}");
                true
            }
            17 => {
                pattern.push_str(r"\cA");
                true
            }
            18 => {
                pattern.push_str(r"\Q.[](){}*+?\E");
                false
            }
            19 => {
                pattern.push_str(r"\<");
                true
            }
            20 => {
                pattern.push_str(r"\>");
                true
            }
            21 => {
                pattern.push_str(r"\(");
                true
            }
            22 => {
                pattern.push_str("(?:a|b)");
                false
            }
            23 => {
                pattern.push_str("(a)");
                false
            }
            24 => {
                pattern.push_str(&format!("(?<n{index}>a)"));
                false
            }
            25 => {
                pattern.push_str(&format!("(?P<p{index}>b)"));
                false
            }
            26 => {
                pattern.push_str(&format!("(?'q{index}'c)"));
                false
            }
            27 => {
                pattern.push_str("(?i:a)");
                false
            }
            28 => {
                pattern.push_str("(?im-s:a)");
                false
            }
            29 => {
                pattern.push_str("(?#comment)a");
                false
            }
            30 => {
                pattern.push_str(r"a\Kb");
                false
            }
            31 => {
                pattern.push('é');
                false
            }
            _ => unreachable!(),
        };
        if quantifiable {
            pattern.push_str(match repetition % 9 {
                0 => "",
                1 => "?",
                2 => "*",
                3 => "+",
                4 => "{0,2}",
                5 => "{1,3}",
                6 => "*?",
                7 => "+?",
                8 => "{2}",
                _ => unreachable!(),
            });
        }
    }
    if control & 4 != 0 {
        pattern.push_str(r"\z");
    }
    pattern
}

fn generated_excluded(data: &[u8], flags: u8) -> &'static str {
    const EXCLUDED: &[&str] = &[
        r"(?=a)",
        r"(?!a)",
        r"(?<=a)",
        r"(?<!a)",
        r"(?>a)",
        r"(?|a)",
        r"(?(1)a|b)",
        r"(?R)",
        r"(?0)",
        r"(?&name)",
        r"(?P=name)",
        r"(?P>name)",
        r"(a)\1",
        r"\g{name}",
        r"\k<name>",
        r"a++",
        r"(*ACCEPT)",
        r"(?u:a)",
        r"(?R:a)",
        r"\b{start}",
        r"\B{end-half}",
        r"\pL",
        r"\P{L}",
        r"\X",
        r"\G",
        r"\R",
        r"\R\s",
        r"(?m)^",
        r"\D(?m:^)$",
        r"\y",
        r"(?J)",
        "\\c\t",
        r"a{word}",
        r"a]",
        r"a}",
    ];
    const CRLF_EXCLUDED: &[&str] = &[
        r"\sX",
        r"\DX",
        r"\WX",
        r"\HX",
        r"\vX",
        r"\CX",
        r"[^x]X",
        r"[[:space:]]X",
        r"[[:cntrl:]]X",
        r"[[:ascii:]]X",
    ];
    const UCP_EXCLUDED: &[&str] = &[r"\b", r"\B"];
    const CRLF_EXTENDED_EXCLUDED: &[&str] = &["# comment\r(("];
    const EXTENDED_EXCLUDED: &[&str] = &["\\++\x0B?"];
    let control = data.first().copied().unwrap_or(0);
    if flags & (8 | 16) == (8 | 16) && control & 0x20 != 0 {
        CRLF_EXTENDED_EXCLUDED[usize::from(control) % CRLF_EXTENDED_EXCLUDED.len()]
    } else if flags & 8 != 0 && control & 0x10 != 0 {
        EXTENDED_EXCLUDED[usize::from(control) % EXTENDED_EXCLUDED.len()]
    } else if flags & 64 != 0 && control & 0x40 != 0 {
        UCP_EXCLUDED[usize::from(control) % UCP_EXCLUDED.len()]
    } else if flags & 16 != 0 && control & 0x80 != 0 {
        CRLF_EXCLUDED[usize::from(control) % CRLF_EXCLUDED.len()]
    } else {
        EXCLUDED[usize::from(control) % EXCLUDED.len()]
    }
}

fn generated_lexical_control(data: &[u8]) -> &'static str {
    const CONTROLS: &[&str] = &[
        r"\Q(?u:a)\E",
        r"\Q(?R)\E",
        r"\Q\R\E",
        r"\Q\b{start}\E",
        r"[(?uR)]",
        r"(?m:\^)",
        r"[<>{}]",
        r"(?#u R recursion)a",
        "(?x)# (?u:a)\na",
        r"\(\?u:a\)",
        r"\<",
        r"\>",
    ];
    CONTROLS[usize::from(data.first().copied().unwrap_or(0)) % CONTROLS.len()]
}

fn rust_captures(regex: &rust::Regex, subject: &[u8]) -> Result<Option<CaptureSpans>, ()> {
    regex
        .captures(subject)
        .map(|captures| {
            captures.map(|captures| {
                captures
                    .iter()
                    .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
                    .collect()
            })
        })
        .map_err(|_| ())
}

fn oracle_captures(regex: &oracle::Regex, subject: &[u8]) -> Result<Option<CaptureSpans>, ()> {
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

fn assert_admitted_conformance(pattern: &str, subject: &[u8], flags: u8) {
    let rust_regex = configure_rust(flags).build(pattern).unwrap_or_else(|error| {
        panic!("whitelist generator produced rejected pattern {pattern:?}, flags={flags:#04x}: {error}")
    });
    let oracle_regex = configure_oracle(flags)
        .build(pattern)
        .unwrap_or_else(|error| {
            panic!("whitelist pattern is not PCRE2 syntax {pattern:?}, flags={flags:#04x}: {error}")
        });
    assert_eq!(
        rust_regex.captures_len(),
        oracle_regex.captures_len(),
        "capture count: pattern={pattern:?}, flags={flags:#04x}, translated={:?}",
        rust_regex.translated_pattern(),
    );
    assert_eq!(
        rust_regex.capture_names(),
        oracle_regex.capture_names(),
        "capture names: pattern={pattern:?}, flags={flags:#04x}, translated={:?}",
        rust_regex.translated_pattern(),
    );
    // C PCRE2 retains its own backtracking match limit. Admission is already
    // established above; compare semantics whenever the oracle completes and
    // leave resource monotonicity to the dedicated resource target.
    if let Ok(oracle_captures) = oracle_captures(&oracle_regex, subject) {
        assert_eq!(
            rust_captures(&rust_regex, subject),
            Ok(oracle_captures),
            "captures: pattern={pattern:?}, subject={subject:?}, flags={flags:#04x}, translated={:?}",
            rust_regex.translated_pattern(),
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, tail)) = data.split_first() else {
        return;
    };
    let flags = tail.first().copied().unwrap_or(0) & 0x7f;
    let controls = tail.get(1..).unwrap_or_default();
    let subject = generated_subject(controls);

    match mode % 4 {
        0 => {
            let Some(split) = controls.iter().position(|&byte| byte == 0 || byte == b'\n') else {
                return;
            };
            let Ok(pattern) = std::str::from_utf8(&controls[..split]) else {
                return;
            };
            if pattern.len() > 4096 {
                return;
            }
            if let Ok(rust_regex) = configure_rust(flags).build(pattern) {
                let oracle_regex = configure_oracle(flags).build(pattern).unwrap_or_else(|error| {
                    panic!(
                        "vapache admitted PCRE2-rejected syntax {pattern:?}, flags={flags:#04x}, translated={:?}: {error}",
                        rust_regex.translated_pattern(),
                    )
                });
                assert_eq!(rust_regex.captures_len(), oracle_regex.captures_len());
                assert_eq!(rust_regex.capture_names(), oracle_regex.capture_names());
            }
        }
        1 => {
            let pattern = generated_admitted(controls, flags);
            assert_admitted_conformance(&pattern, &subject, flags);
        }
        2 => {
            let pattern = generated_excluded(controls, flags);
            assert!(
                configure_rust(flags).build(pattern).is_err(),
                "vapache admitted construct outside the whitelist: {pattern:?}, flags={flags:#04x}",
            );
        }
        3 => {
            let pattern = generated_lexical_control(controls);
            assert_admitted_conformance(pattern, &subject, flags);
        }
        _ => unreachable!(),
    }
});
