//! Fixed regressions from adversarial pass P35.

use httpd_rs_pcre2::bytes as rust;
use httpd_rs_pcre2::ErrorKind;
use pcre2_c_oracle::bytes as oracle;

#[test]
fn p35_greedy_classes_before_line_atoms_fail_closed() {
    for class in [r"\S", r"\N"] {
        for repetition in ["*", "+"] {
            for line_atom in [r"\v", r"\h"] {
                let pattern = format!("{class}{repetition}{line_atom}");
                assert!(oracle::Regex::new(&pattern).is_ok(), "{pattern:?}");
                assert_eq!(
                    rust::Regex::new(&pattern).unwrap_err().kind(),
                    ErrorKind::Unsupported,
                    "{pattern:?}",
                );
            }
        }
    }

    for pattern in [
        r"(?:x|\S*\v)",
        r"(\N+\R)",
        r"(?x)\S* \v",
        "(?x)\\N+ # ignored\n\\R",
        r"(?x:\S* \v)",
        r"\N*(?# ignored)\R",
    ] {
        assert!(oracle::Regex::new(pattern).is_ok(), "{pattern:?}");
        assert_eq!(
            rust::Regex::new(pattern).unwrap_err().kind(),
            ErrorKind::Unsupported,
            "{pattern:?}",
        );
    }
}

#[test]
fn p35_simple_line_atoms_remain_supported() {
    for (pattern, subject) in [(r"\v", b"\x85".as_slice()), (r"\h", b"\t".as_slice())] {
        let rust_match = rust::Regex::new(pattern)
            .unwrap()
            .find(subject)
            .unwrap()
            .map(|matched| (matched.start(), matched.end()));
        let oracle_match = oracle::Regex::new(pattern)
            .unwrap()
            .find(subject)
            .unwrap()
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(rust_match, oracle_match, "{pattern:?}");
    }
}
