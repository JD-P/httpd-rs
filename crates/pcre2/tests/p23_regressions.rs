//! Fixed regressions from adversarial pass P23.

use pcre2_c_oracle::bytes as oracle;
use vapache_pcre2::bytes as rust;
use vapache_pcre2::ErrorKind;

fn spans_rust(pattern: &str, subject: &[u8]) -> Option<Vec<Option<(usize, usize)>>> {
    let regex = rust::Regex::new(pattern).unwrap();
    regex.captures(subject).unwrap().map(|captures| {
        (0..captures.len())
            .map(|index| captures.get(index).map(|m| (m.start(), m.end())))
            .collect()
    })
}

fn spans_oracle(pattern: &str, subject: &[u8]) -> Option<Vec<Option<(usize, usize)>>> {
    let regex = oracle::Regex::new(pattern).unwrap();
    regex.captures(subject).unwrap().map(|captures| {
        (0..captures.len())
            .map(|index| captures.get(index).map(|m| (m.start(), m.end())))
            .collect()
    })
}

fn assert_oracle(pattern: &str, subject: &[u8]) {
    assert_eq!(
        spans_rust(pattern, subject),
        spans_oracle(pattern, subject),
        "pattern {pattern:?}, subject {subject:?}",
    );
}

#[test]
fn p23_a_counted_repetition_is_charged_by_expansion() {
    let regex = rust::Regex::new("a{8000}").unwrap();
    let error = regex.captures(&vec![b'a'; 8190]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ResourceLimit);
}

#[test]
fn p23_b_terminal_anchor_cases_match_and_unrepresentable_cases_fail_closed() {
    for (pattern, subject) in [
        (r"^foo\z$", b"foo\n".as_slice()),
        (r"^\z$", b"\n".as_slice()),
        (r"\z$", b"\n".as_slice()),
        (r"a$|a\n", b"a\n".as_slice()),
    ] {
        assert_oracle(pattern, subject);
    }
    for pattern in [r"^\Z\v", "secret$\n", r"$\s", r"\D*?$"] {
        assert_eq!(
            rust::Regex::new(pattern).unwrap_err().kind(),
            ErrorKind::Unsupported
        );
    }
}

#[test]
fn p23_c_d_f_classes_ranges_and_inline_extended_are_lossless() {
    for (pattern, subject) in [
        (r"[[:^alpha:]]", b"1".as_slice()),
        (r"[[:^alpha:]]", b"a]".as_slice()),
        (r"[--1]", b"0".as_slice()),
        (r"[ --]", b"#".as_slice()),
        (r"[]-a]", b"-".as_slice()),
        (r"(?x)\Qa b\E", b"a b".as_slice()),
        (r"(?x)\Qa b\E", b"ab".as_slice()),
        (r"(?x)[ a#b ]", b" ".as_slice()),
        (r"(?x:\Qa b\E)", b"a b".as_slice()),
    ] {
        assert_oracle(pattern, subject);
    }
    assert_eq!(
        rust::Regex::new(r"[a--]").unwrap_err().kind(),
        ErrorKind::Syntax
    );
}

#[test]
fn p23_e_i_m_unrepresentable_priority_cases_fail_closed() {
    for pattern in [
        r"\R\R",
        r"\R\C",
        r"\R+?$",
        r"(\z|\C)+",
        r"(a|\b)+",
        r"\N*?\R",
    ] {
        assert_eq!(
            rust::Regex::new(pattern).unwrap_err().kind(),
            ErrorKind::Unsupported
        );
    }
}

#[test]
fn p23_g_h_i_j_capture_escape_and_empty_alternative_compatibility() {
    for (pattern, subject) in [
        (r"a(?P<__vapache_pcre2_keep_0>b)", b"ab".as_slice()),
        (r"\101", b"A".as_slice()),
        (r"\10", b"\x08".as_slice()),
        (r"\x9", b"\t".as_slice()),
        (r"\x{0}", b"\0".as_slice()),
        (r"\o{101}", b"A".as_slice()),
        (r"\x{42}{2}", b"BB".as_slice()),
        (r"(\x{42})+", b"BB".as_slice()),
        (r"(\d{2})+", b"1234".as_slice()),
        (r"^/(.*\.php(/.*)?)$", b"/script.php/info".as_slice()),
        (r"^(?:/.*)?$", b"/path\n".as_slice()),
        (r"\??$", b"?\n".as_slice()),
        (r"\x{42}?$", b"B\n".as_slice()),
        (r"[[:alpha:]]-[a-z]", b"a-b".as_slice()),
        (r"a|", b"a".as_slice()),
    ] {
        assert_oracle(pattern, subject);
    }
    assert_eq!(
        rust::Regex::new(r"(?J)(?<n>a)(?<n>b)").unwrap_err().kind(),
        ErrorKind::Unsupported
    );
}

#[test]
fn p23_k_l_crlf_and_multiline_iteration_match_oracle() {
    let mut rust_builder = rust::RegexBuilder::new();
    rust_builder.crlf(true);
    let mut oracle_builder = oracle::RegexBuilder::new();
    oracle_builder.crlf(true);
    for (pattern, subject) in [(r"\N", b"\r".as_slice()), (r"a$", b"a\r".as_slice())] {
        let rust = rust_builder.build(pattern).unwrap();
        let oracle = oracle_builder.build(pattern).unwrap();
        let rust = rust.find(subject).unwrap().map(|m| (m.start(), m.end()));
        let oracle = oracle.find(subject).unwrap().map(|m| (m.start(), m.end()));
        assert_eq!(rust, oracle, "{pattern:?}");
    }

    for (pattern, subject) in [
        (r"(?m)^", b"a\n".as_slice()),
        (r"(?m)^$", b"\n\n".as_slice()),
    ] {
        let rust: Vec<_> = rust::Regex::new(pattern)
            .unwrap()
            .find_iter(subject)
            .map(|m| m.map(|m| (m.start(), m.end())).unwrap())
            .collect();
        let oracle: Vec<_> = oracle::Regex::new(pattern)
            .unwrap()
            .find_iter(subject)
            .map(|m| m.map(|m| (m.start(), m.end())).unwrap())
            .collect();
        assert_eq!(rust, oracle, "{pattern:?}");
    }
}

#[test]
fn p23_fuzzer_followups_preserve_caseless_classes_and_fail_closed() {
    let mut rust_caseless = rust::RegexBuilder::new();
    rust_caseless.caseless(true);
    let mut oracle_caseless = oracle::RegexBuilder::new();
    oracle_caseless.caseless(true);
    for (pattern, subject) in [
        (r"[1[:^alpha:]a]", b"a".as_slice()),
        (r"[1[:^alpha:]a]", b"0".as_slice()),
        (r"[^-a[:^alpha:]]", b"b".as_slice()),
    ] {
        let rust = rust_caseless.build(pattern).unwrap();
        let oracle = oracle_caseless.build(pattern).unwrap();
        let rust = rust.find(subject).unwrap().map(|m| (m.start(), m.end()));
        let oracle = oracle.find(subject).unwrap().map(|m| (m.start(), m.end()));
        assert_eq!(rust, oracle, "{pattern:?}");
    }
    assert_oracle(r"(?i:[^-a[:^alpha:]])", b"b");

    for pattern in [r"(?i-s:\R)*[^a]", r"(?m)(a|^)"] {
        assert_eq!(
            rust::Regex::new(pattern).unwrap_err().kind(),
            ErrorKind::Unsupported,
            "{pattern:?}",
        );
    }
    assert_eq!(
        rust::Regex::new(r"(?x:\A *)").unwrap_err().kind(),
        ErrorKind::Syntax,
    );

    let mut crlf_multiline = rust::RegexBuilder::new();
    crlf_multiline.crlf(true).multi_line(true);
    for pattern in [r"$", r"\B"] {
        assert_eq!(
            crlf_multiline.build(pattern).unwrap_err().kind(),
            ErrorKind::Unsupported,
            "{pattern:?}",
        );
    }
}
