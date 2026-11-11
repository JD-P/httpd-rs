//! Fixed regressions from adversarial pass P37.

use pcre2_c_oracle::bytes as oracle;
use vapache_pcre2::bytes as rust;
use vapache_pcre2::ErrorKind;

fn assert_unsupported(pattern: &str) {
    assert!(
        oracle::Regex::new(pattern).is_ok(),
        "oracle unexpectedly rejected {pattern:?}",
    );
    assert_eq!(
        rust::Regex::new(pattern).unwrap_err().kind(),
        ErrorKind::Unsupported,
        "compatibility grammar admitted {pattern:?}",
    );
}

#[test]
fn p37_a_atomic_crlf_escape_is_outside_the_closed_grammar() {
    for pattern in [
        r"\R",
        r"a\Rb",
        r"\R\s",
        r"\R\v",
        r"\R$",
        r"\R\Z",
        r"(?:\R)",
        r"(?x:\R )",
    ] {
        assert_unsupported(pattern);
    }

    for (pattern, subject) in [(r"\Q\R\E", b"\\R".as_slice()), (r"[R]", b"R")] {
        let rust = rust::Regex::new(pattern).unwrap();
        let oracle = oracle::Regex::new(pattern).unwrap();
        assert_eq!(
            rust.find(subject)
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            oracle
                .find(subject)
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
        );
    }
}

#[test]
fn p37_b_multiline_start_anchor_is_outside_the_closed_grammar() {
    for pattern in [r"(?m)^", r"\D(?m:^)$", r"(?:[^]a](?m:^))", r"(?m:a)(?m:^)"] {
        assert_unsupported(pattern);
    }

    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder.crlf(true);
    assert_eq!(
        rust_builder.build(r"(?m)^").unwrap_err().kind(),
        ErrorKind::Unsupported,
    );

    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder.crlf(true).multi_line(true);
    assert_eq!(
        rust_builder.build(r"\r^").unwrap_err().kind(),
        ErrorKind::Unsupported,
    );
}

#[test]
fn p37_lexical_and_scoped_non_multiline_controls_remain_supported() {
    for (pattern, subject) in [
        (r"^a", b"a".as_slice()),
        (r"(?m:a)^", b"a"),
        (r"(?m:\^)", b"^"),
    ] {
        let rust = rust::Regex::new(pattern).unwrap();
        let oracle = oracle::Regex::new(pattern).unwrap();
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
    rust_builder.multi_line(true);
    let rust = rust_builder.build(r"(?-m:^a)").unwrap();
    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder.multi_line(true);
    let oracle = oracle_builder.build(r"(?-m:^a)").unwrap();
    assert_eq!(
        rust.find(b"a\na")
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
        oracle
            .find(b"a\na")
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
    );
}
