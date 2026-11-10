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
fn multiline_terminal_empty_match_is_suppressed_for_offset_apis() {
    let rust = rust::Regex::new(r"(?m)^$").unwrap();
    let oracle = oracle::Regex::new(r"(?m)^$").unwrap();
    let subject = b"\n\n";
    let start = subject.len();

    assert_eq!(
        rust.is_match_at(subject, start).unwrap(),
        oracle.is_match_at(subject, start).unwrap()
    );
    assert_eq!(
        rust.find_at(subject, start)
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
        oracle
            .find_at(subject, start)
            .unwrap()
            .map(|matched| (matched.start(), matched.end()))
    );

    let mut rust_locations = rust.capture_locations();
    let mut oracle_locations = oracle.capture_locations();
    assert_eq!(
        rust.captures_read_at(&mut rust_locations, subject, start)
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
        oracle
            .captures_read_at(&mut oracle_locations, subject, start)
            .unwrap()
            .map(|matched| (matched.start(), matched.end()))
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

    for pattern in [r"[[:alpha:]]", r"[[:^alpha:]]", r"[\w]", "[é]", r"\R"] {
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
