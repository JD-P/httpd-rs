//! Regressions promoted from the continuously run PCRE2 differential fuzzer.

use pcre2_c_oracle::bytes as oracle;
use vapache_pcre2::bytes as rust;

fn spans_rust(pattern: &str, subject: &[u8]) -> Vec<Vec<Option<(usize, usize)>>> {
    rust::Regex::new(pattern)
        .unwrap()
        .captures_iter(subject)
        .map(|captures| {
            let captures = captures.unwrap();
            (0..captures.len())
                .map(|index| captures.get(index).map(|m| (m.start(), m.end())))
                .collect()
        })
        .collect()
}

fn spans_oracle(pattern: &str, subject: &[u8]) -> Vec<Vec<Option<(usize, usize)>>> {
    oracle::Regex::new(pattern)
        .unwrap()
        .captures_iter(subject)
        .map(|captures| {
            let captures = captures.unwrap();
            (0..captures.len())
                .map(|index| captures.get(index).map(|m| (m.start(), m.end())))
                .collect()
        })
        .collect()
}

#[test]
fn byte_mode_quantifies_non_ascii_pattern_bytes_like_pcre2() {
    for (pattern, subject) in [
        ("é*", b"".as_slice()),
        ("é*", b"\xC3\xA9\xA9".as_slice()),
        ("ˈ?", b"\xCB".as_slice()),
        ("(é)+", b"\xC3\xA9\xC3\xA9".as_slice()),
    ] {
        assert_eq!(
            spans_rust(pattern, subject),
            spans_oracle(pattern, subject),
            "pattern {pattern:?}, subject {subject:?}",
        );
    }

    assert_eq!(
        rust::Regex::new("é*").unwrap().translated_pattern(),
        r"\xC3\xA9*"
    );

    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder.ucp(true);
    let rust = rust_builder.build("é*").unwrap();
    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder.ucp(true);
    let oracle = oracle_builder.build("é*").unwrap();
    let subject = b"\xC3\xA9\xC3\xA9";
    assert_eq!(
        rust.find(subject)
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
        oracle
            .find(subject)
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
    );
    assert_eq!(rust.translated_pattern(), "é*");
}

#[test]
fn utf_and_ucp_modes_fail_closed_on_invalid_subjects_and_align_valid_offsets() {
    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder.utf(true);
    let rust = rust_builder.build("é+").unwrap();

    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder.utf(true);
    let oracle = oracle_builder.build("é+").unwrap();

    let invalid = b"\xA9\xC3\xA9";
    assert!(rust.is_match(invalid).is_err());
    assert!(oracle.is_match(invalid).is_err());

    let valid = "éé".as_bytes();
    assert!(rust.is_match_at(valid, 1).is_err());
    assert!(oracle.is_match_at(valid, 1).is_err());

    let rust_empty = rust_builder.build("").unwrap();
    let oracle_empty = oracle_builder.build("").unwrap();
    assert!(rust_empty.find_at(valid, 1).is_err());
    assert!(oracle_empty.find_at(valid, 1).is_err());
    assert!(rust_empty
        .captures_iter(valid)
        .any(|result| result.is_err()));
    assert!(oracle_empty
        .captures_iter(valid)
        .any(|result| result.is_err()));

    // PCRE2 validates the entire suffix even when an empty pattern could
    // otherwise succeed immediately. Its non-zero-offset window can exclude
    // malformed prefix bytes; vapache deliberately rejects the whole subject
    // so anchors and word boundaries cannot create a false-positive window.
    let invalid_suffix = b"\x04\xAB";
    assert!(rust_empty.is_match_at(invalid_suffix, 0).is_err());
    assert!(oracle_empty.is_match_at(invalid_suffix, 0).is_err());
    assert!(rust_empty
        .find_at(invalid_suffix, invalid_suffix.len())
        .is_err());
    assert!(oracle_empty
        .find_at(invalid_suffix, invalid_suffix.len())
        .unwrap()
        .is_some());

    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder.ucp(true);
    let rust = rust_builder.build("\u{1}").unwrap();
    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder.ucp(true);
    let oracle = oracle_builder.build("\u{1}").unwrap();
    assert_eq!(
        rust.is_match_at(valid, 1).unwrap(),
        oracle.is_match_at(valid, 1).unwrap(),
    );
    assert!(!rust.is_match_at(valid, 1).unwrap());

    // PCRE2_MATCH_INVALID_UTF models malformed sequences as barriers. The
    // byte automaton deliberately rejects such UCP subjects instead of
    // risking a match that crosses or stops on the wrong side of a barrier.
    let malformed = b"\xA9\n";
    assert!(rust.is_match(malformed).is_err());

    let subject = "éé\n".as_bytes();
    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder.ucp(true);
    let rust = rust_builder.build("é*").unwrap();
    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder.ucp(true);
    let oracle = oracle_builder.build("é*").unwrap();
    assert_eq!(
        rust.find_at(subject, 3)
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
        oracle
            .find_at(subject, 3)
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
    );
}

#[test]
fn multiline_start_anchor_fails_closed_before_offset_apis() {
    assert_eq!(
        rust::Regex::new(r"(?m)^$").unwrap_err().kind(),
        vapache_pcre2::ErrorKind::Unsupported,
    );
}

#[test]
fn posix_named_class_requires_an_outer_character_class() {
    for pattern in ["[:alpha:]]", "[:^digit:]]", "[:not-a-class:]]"] {
        assert!(
            oracle::Regex::new(pattern).is_err(),
            "oracle unexpectedly accepted {pattern:?}",
        );
        assert!(
            rust::Regex::new(pattern).is_err(),
            "compatibility layer unexpectedly accepted {pattern:?}",
        );
    }

    for pattern in ["[[:alpha:]]", "[[:^digit:]]"] {
        assert!(
            oracle::Regex::new(pattern).is_ok(),
            "oracle unexpectedly rejected {pattern:?}",
        );
        assert!(
            rust::Regex::new(pattern).is_ok(),
            "compatibility layer unexpectedly rejected {pattern:?}",
        );
    }
}

#[test]
fn named_capture_syntax_matches_pcre2_admission() {
    for pattern in [
        r"(?<wor]>a)",
        r"(?P<wor]>a)",
        r"(?'wor]'a)",
        r"(?<1>a)",
        r"[\N]",
    ] {
        assert!(
            oracle::Regex::new(pattern).is_err(),
            "oracle unexpectedly accepted {pattern:?}",
        );
        assert!(
            rust::Regex::new(pattern).is_err(),
            "compatibility layer unexpectedly accepted {pattern:?}",
        );
    }

    for pattern in [r"(?<word>a)", r"(?P<word_2>a)", r"(?'_word'a)"] {
        assert!(oracle::Regex::new(pattern).is_ok());
        assert!(rust::Regex::new(pattern).is_ok());
    }
}

#[test]
fn unicode_sensitive_classes_fail_closed_instead_of_narrowing() {
    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder.ucp(true);
    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder.ucp(true);

    for pattern in [
        r"[[:alpha:]]",
        r"[[:^alpha:]]",
        r"[\w]",
        "[é]",
        r"\R",
        r"\b",
        r"\B",
    ] {
        assert!(
            oracle_builder.build(pattern).is_ok(),
            "oracle unexpectedly rejected {pattern:?}",
        );
        assert!(
            rust_builder.build(pattern).is_err(),
            "compatibility layer must fail closed for {pattern:?}",
        );
    }

    for pattern in [r"[A-Za-z]", r"[^\n]"] {
        assert!(oracle_builder.build(pattern).is_ok());
        assert!(rust_builder.build(pattern).is_ok());
    }

    let rust = rust_builder.build("\\QéE").unwrap();
    let oracle = oracle_builder.build("\\QéE").unwrap();
    assert_eq!(
        rust.find("éE".as_bytes())
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
        oracle
            .find("éE".as_bytes())
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
    );
}

#[test]
fn extended_comments_do_not_create_anchor_metadata() {
    for pattern in [r"#/^#0\o{101}", "(?x:# hidden ^\n)"] {
        let mut rust_builder = rust::RegexBuilder::new();
        rust_builder.extended(true).multi_line(true);
        let rust = rust_builder.build(pattern).unwrap();
        let mut oracle_builder = oracle::RegexBuilder::new();
        oracle_builder.extended(true).multi_line(true);
        let oracle = oracle_builder.build(pattern).unwrap();
        let subject = b"%\n";
        let start = subject.len();
        assert_eq!(
            rust.find_at(subject, start)
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            oracle
                .find_at(subject, start)
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            "pattern {pattern:?}",
        );
    }
}

#[test]
fn rust_only_inline_options_are_rejected_like_pcre2() {
    for pattern in [
        r"(?u)^safe$",
        r"(?u:^safe$)",
        r"(?iu:^safe$)",
        r"(?-u:^safe$)",
        r"(?i-u:^safe$)",
        r"(?iR)^safe$",
        r"(?iR:^safe$)",
        r"(?-R:^safe$)",
        r"(?i-R:^safe$)",
        r"(?i--m:^safe$)",
        r"(?i-m-s:^safe$)",
    ] {
        assert!(
            oracle::Regex::new(pattern).is_err(),
            "oracle unexpectedly accepted {pattern:?}",
        );
        assert!(
            rust::Regex::new(pattern).is_err(),
            "compatibility layer unexpectedly accepted {pattern:?}",
        );
    }

    // Do not mistake quoted text, byte classes, comments, or PCRE2's valid
    // ungreedy option for a Rust-only inline option.
    for pattern in [r"\Q(?u)\E", r"[(?u)]", "(?x)# (?u)\na", r"(?U)^safe$"] {
        assert!(oracle::Regex::new(pattern).is_ok(), "{pattern:?}");
        assert!(rust::Regex::new(pattern).is_ok(), "{pattern:?}");
    }
}

#[test]
fn finite_inline_option_admission_is_a_subset_of_pcre2() {
    // Exhaust the complete Rust-regex flag alphabet through four positions.
    // The compatibility layer may intentionally reject PCRE2 syntax that its
    // bounded engine does not implement, but it must never admit a header
    // that the C oracle rejects or gives another meaning.
    let alphabet = b"imsUuxR-";
    let mut frontier = vec![Vec::new()];
    for _ in 0..=4 {
        for header in &frontier {
            let flags = std::str::from_utf8(header).unwrap();
            for pattern in [format!("(?{flags})a"), format!("(?{flags}:a)")] {
                if rust::Regex::new(&pattern).is_ok() {
                    assert!(
                        oracle::Regex::new(&pattern).is_ok(),
                        "compatibility layer admitted PCRE2-rejected inline header {pattern:?}",
                    );
                }
            }
        }
        frontier = frontier
            .iter()
            .flat_map(|prefix| {
                alphabet.iter().map(move |&byte| {
                    let mut next = prefix.clone();
                    next.push(byte);
                    next
                })
            })
            .collect();
    }
}

#[test]
fn escaped_angle_brackets_remain_pcre2_literals() {
    for pattern in [r"\<", r"\>", r"a\<b", r"a\>b"] {
        for subject in [
            b"".as_slice(),
            b"word".as_slice(),
            b"<".as_slice(),
            b">".as_slice(),
            b"a<b".as_slice(),
            b"a>b".as_slice(),
        ] {
            assert_eq!(
                spans_rust(pattern, subject),
                spans_oracle(pattern, subject),
                "pattern {pattern:?}, subject {subject:?}",
            );
        }
    }
    assert_eq!(rust::Regex::new(r"\<").unwrap().translated_pattern(), "<");
    assert_eq!(rust::Regex::new(r"\>").unwrap().translated_pattern(), ">");
}

#[test]
fn admitted_single_ascii_escapes_match_pcre2() {
    let subjects: &[&[u8]] = &[
        b"",
        b"a",
        b"word boundary",
        b"<>",
        b"0123456789",
        b"\r\n",
        b"\x00\x01\x7f\x80\xff",
    ];
    for escaped in 0x20_u8..=0x7e {
        let pattern = format!(r"\{}", char::from(escaped));
        let Ok(regex) = rust::Regex::new(&pattern) else {
            continue;
        };
        assert!(
            oracle::Regex::new(&pattern).is_ok(),
            "compatibility layer admitted PCRE2-rejected escape {pattern:?}",
        );
        for subject in subjects {
            assert_eq!(
                regex
                    .captures_iter(subject)
                    .map(|captures| {
                        let captures = captures.unwrap();
                        (0..captures.len())
                            .map(|index| captures.get(index).map(|m| (m.start(), m.end())))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>(),
                spans_oracle(&pattern, subject),
                "escape {pattern:?}, subject {subject:?}",
            );
        }
    }
}

#[test]
fn rust_only_extended_word_boundaries_fail_closed() {
    for pattern in [
        r"\b{start}",
        r"\b{end}",
        r"\b{start-half}",
        r"\b{end-half}",
        r"\B{start}",
        r"\B{end}",
        r"\B{start-half}",
        r"\B{end-half}",
    ] {
        assert!(
            oracle::Regex::new(pattern).is_ok(),
            "PCRE2 unexpectedly rejected the distinct brace spelling {pattern:?}",
        );
        assert!(
            rust::Regex::new(pattern).is_err(),
            "accepted Rust-only word-boundary extension {pattern:?}",
        );
    }
}

#[test]
fn extended_mode_does_not_erase_invalid_special_group_syntax() {
    for whitespace in [" ", "\t", "\r", "\n"] {
        for pattern in [
            format!("(?{whitespace})"),
            format!("(?i{whitespace}:a)"),
            format!("(?x)(?{whitespace})"),
        ] {
            let mut oracle_builder = oracle::RegexBuilder::new();
            oracle_builder.extended(true);
            assert!(
                oracle_builder.build(&pattern).is_err(),
                "PCRE2 unexpectedly accepted {pattern:?}",
            );

            let mut rust_builder = rust::RegexBuilder::new();
            rust_builder.extended(true);
            assert!(
                rust_builder.build(&pattern).is_err(),
                "compatibility layer accepted {pattern:?}",
            );
        }
    }
}

#[test]
fn non_ascii_extended_pattern_whitespace_fails_closed() {
    // In byte mode PCRE2 lexes each UTF-8 code unit separately. The second
    // byte of U+00C5 is NEL (0x85), which extended mode discards, so `*`
    // quantifies 0xC3. Rust strings expose the complete scalar instead. Reject
    // the ambiguous spelling before translation rather than changing meaning.
    let byte_pattern = " Å*";
    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder.extended(true);
    assert!(oracle_builder
        .build(byte_pattern)
        .unwrap()
        .is_match(b"")
        .unwrap());
    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder.extended(true);
    assert!(rust_builder.build(byte_pattern).is_err());
    assert!(rust::Regex::new("(?x)Å*").is_err());

    // In UTF mode PCRE2 additionally ignores the non-ASCII Unicode Pattern
    // White Space scalars. They remain supported when quoted because extended
    // lexing is inactive inside \Q...\E.
    for whitespace in ['\u{0085}', '\u{200E}', '\u{200F}', '\u{2028}', '\u{2029}'] {
        let pattern = format!("{whitespace}a");
        let mut oracle_builder = oracle::RegexBuilder::new();
        oracle_builder.extended(true).utf(true);
        assert!(oracle_builder.build(&pattern).is_ok(), "{whitespace:?}");
        let mut rust_builder = rust::RegexBuilder::new();
        rust_builder.extended(true).utf(true);
        assert!(rust_builder.build(&pattern).is_err(), "{whitespace:?}");

        let quoted = format!(r"\Q{whitespace}\E");
        assert!(oracle_builder.build(&quoted).is_ok(), "{whitespace:?}");
        assert!(rust_builder.build(&quoted).is_ok(), "{whitespace:?}");
    }
}

#[test]
fn vertical_tab_uses_pcre2_extended_whitespace_semantics() {
    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder.extended(true);
    let quantifier = "\\++\u{000B}?";
    assert!(!oracle_builder
        .build(quantifier)
        .unwrap()
        .is_match(b"not-plus")
        .unwrap());
    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder.extended(true);
    assert!(rust_builder.build(quantifier).is_err());

    for (pattern, subject) in [
        ("a\u{000B}b", b"ab".as_slice()),
        ("\\Q\u{000B}\\E", b"\x0B"),
    ] {
        let rust = rust_builder.build(pattern).unwrap();
        let oracle = oracle_builder.build(pattern).unwrap();
        assert_eq!(
            rust.is_match(subject).unwrap(),
            oracle.is_match(subject).unwrap()
        );
    }
}

#[test]
fn crlf_generic_character_class_search_starts_fail_closed() {
    // PCRE2's ANYCRLF search does not begin a generic character-class match
    // at the LF half of CRLF. Its explicit LF productions do. Reject the
    // generic forms rather than allowing the automata engine to find a match
    // that PCRE2 skips.
    for pattern in [r"\sX", r"\DX", r"\WX", r"[^x]X", r"[[:space:]]X"] {
        let mut oracle_builder = oracle::RegexBuilder::new();
        oracle_builder.crlf(true);
        assert!(!oracle_builder
            .build(pattern)
            .unwrap()
            .is_match(b"\r\nX")
            .unwrap());

        let mut rust_builder = rust::RegexBuilder::new();
        rust_builder.crlf(true);
        assert!(rust_builder.build(pattern).is_err(), "{pattern:?}");
    }

    for pattern in [r"\nX", r"[\r\n]X"] {
        let mut rust_builder = rust::RegexBuilder::new();
        rust_builder.crlf(true);
        let rust = rust_builder.build(pattern).unwrap();
        let mut oracle_builder = oracle::RegexBuilder::new();
        oracle_builder.crlf(true);
        let oracle = oracle_builder.build(pattern).unwrap();
        assert_eq!(
            rust.is_match(b"\r\nX").unwrap(),
            oracle.is_match(b"\r\nX").unwrap()
        );
    }
}

#[test]
fn control_escape_admission_matches_pcre2_printable_ascii_rule() {
    for control in 0u8..=127 {
        let pattern = String::from_utf8(vec![b'\\', b'c', control]).unwrap();
        let rust = rust::Regex::new(&pattern);
        let oracle = oracle::Regex::new(&pattern);
        assert_eq!(
            rust.is_ok(),
            oracle.is_ok(),
            "control escape target {control:#04x}"
        );
        assert_eq!(rust.is_ok(), (b' '..=b'~').contains(&control));
    }
}

#[test]
fn lone_cr_extended_comment_fails_closed_under_anycrlf() {
    let pattern = "# comment\r((";
    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder.extended(true).crlf(true);
    assert!(oracle_builder.build(pattern).is_err());

    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder.extended(true).crlf(true);
    assert!(rust_builder.build(pattern).is_err());

    let positive = "# comment\r\na";
    let rust = rust_builder.build(positive).unwrap();
    let oracle = oracle_builder.build(positive).unwrap();
    assert_eq!(rust.is_match(b"a").unwrap(), oracle.is_match(b"a").unwrap());
}

#[test]
fn utf_without_ucp_keeps_ascii_character_types() {
    let subject = "ěa ٣".as_bytes();
    for pattern in [r"\w+", r"\W+", r"\d+", r"\D+", r"\s+", r"\S+"] {
        let mut rust_builder = rust::RegexBuilder::new();
        rust_builder.utf(true);
        let rust = rust_builder.build(pattern).unwrap();
        let mut oracle_builder = oracle::RegexBuilder::new();
        oracle_builder.utf(true);
        let oracle = oracle_builder.build(pattern).unwrap();
        assert_eq!(
            rust.find(subject)
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            oracle
                .find(subject)
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            "{pattern:?}",
        );
    }

    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder.utf(true);
    let rust = rust_builder.build(r"\b").unwrap();
    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder.utf(true);
    let oracle = oracle_builder.build(r"\b").unwrap();
    let subject = "aěb".as_bytes();
    let rust_boundaries: Result<Vec<_>, _> = rust
        .find_iter(subject)
        .map(|result| result.map(|matched| (matched.start(), matched.end())))
        .collect();
    let oracle_boundaries: Result<Vec<_>, _> = oracle
        .find_iter(subject)
        .map(|result| result.map(|matched| (matched.start(), matched.end())))
        .collect();
    assert_eq!(rust_boundaries.is_err(), oracle_boundaries.is_err());

    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder.ucp(true);
    let rust = rust_builder.build(r"\w+").unwrap();
    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder.ucp(true);
    let oracle = oracle_builder.build(r"\w+").unwrap();
    assert_eq!(
        rust.find("é".as_bytes())
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
        oracle
            .find("é".as_bytes())
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
    );
}
