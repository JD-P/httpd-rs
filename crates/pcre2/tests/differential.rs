//! Differential conformance against the bundled PCRE2 10.46 C oracle.
//!
//! The table below is a Rust port of representative regular-language cases
//! from upstream `testdata/testinput1`, plus cases for the PCRE extensions
//! translated by vapache. Backtracking-only constructs have separate
//! fail-closed tests in the library.

use pcre2_c_oracle::bytes as oracle;
use vapache_pcre2::bytes as rust;

#[derive(Clone, Copy)]
struct Case {
    pattern: &'static str,
    subject: &'static [u8],
    caseless: bool,
}

const CASES: &[Case] = &[
    Case {
        pattern: "the quick brown fox",
        subject: b"What about the quick brown fox?",
        caseless: false,
    },
    Case {
        pattern: "The quick brown fox",
        subject: b"the quick brown FOX",
        caseless: true,
    },
    Case {
        pattern: r"abcd\t\n\r\f\a\e\071\x3b\$\\\?caxyz",
        subject: b"abcd\t\n\r\x0c\x07\x1b9;$\\?caxyz",
        caseless: false,
    },
    Case {
        pattern: r"a*abc?xyz+pqr{3}ab{2,}xy{4,5}pq{0,6}AB{0,}zz",
        subject: b"aaabcxyzpqrrrabbxyyyypqqAzz",
        caseless: false,
    },
    Case {
        pattern: r"^(abc){1,2}zz",
        subject: b"abcabczz",
        caseless: false,
    },
    Case {
        pattern: r"^(?:b+?|a){1,2}?c",
        subject: b"bbac",
        caseless: false,
    },
    Case {
        pattern: r"^(?:b+|a){1,2}c",
        subject: b"abbbbbbbbbbbc",
        caseless: false,
    },
    Case {
        pattern: r"^[ab\]cde]",
        subject: b"]thing",
        caseless: false,
    },
    Case {
        pattern: r"^[^ab\]cde]",
        subject: b"fthing",
        caseless: false,
    },
    Case {
        pattern: r"^(a|b)+$",
        subject: b"abba",
        caseless: false,
    },
    Case {
        pattern: r"(?:foo|bar)+",
        subject: b"xxfoobarbar!",
        caseless: false,
    },
    Case {
        pattern: r"\Afoo.*bar\z",
        subject: b"foo--bar",
        caseless: false,
    },
    Case {
        pattern: r"\b\w{1,8}\b",
        subject: b"--word--",
        caseless: false,
    },
    Case {
        pattern: r"(?P<key>[A-Za-z_]+)=(?<value>\d+)",
        subject: b"port=443",
        caseless: false,
    },
    Case {
        pattern: r"\Q[a-z]+.txt\E\Z",
        subject: b"[a-z]+.txt",
        caseless: false,
    },
    Case {
        pattern: r"sec(?# upstream comment syntax)ret",
        subject: b"secret",
        caseless: false,
    },
    Case {
        pattern: r"prefix\K(secret)",
        subject: b"prefixsecret",
        caseless: false,
    },
    Case {
        pattern: r"\h+",
        subject: b"\t \xa0",
        caseless: false,
    },
    Case {
        pattern: r"\v+",
        subject: b"\n\x0b\x0c\r\x85",
        caseless: false,
    },
    Case {
        pattern: r"a\vb",
        subject: b"a\nb",
        caseless: false,
    },
    Case {
        pattern: r"a\Nb",
        subject: b"a\xffb",
        caseless: false,
    },
    Case {
        pattern: r"\ca\cA\c[",
        subject: b"\x01\x01\x1b",
        caseless: false,
    },
    Case {
        pattern: r"colou?r",
        subject: b"color colour",
        caseless: false,
    },
    Case {
        pattern: r"^$",
        subject: b"",
        caseless: false,
    },
    Case {
        pattern: r"a$",
        subject: b"a\n",
        caseless: false,
    },
];

fn rust_regex(pattern: &str, caseless: bool) -> rust::Regex {
    let mut builder = rust::RegexBuilder::new();
    builder
        .caseless(caseless)
        .max_subject_size(256 * 1024)
        .match_limit(256 * 1024 * 1024);
    builder
        .build(pattern)
        .unwrap_or_else(|error| panic!("Rust rejected {pattern:?}: {error}"))
}

fn oracle_regex(pattern: &str, caseless: bool) -> oracle::Regex {
    let mut builder = oracle::RegexBuilder::new();
    builder.caseless(caseless);
    builder
        .build(pattern)
        .unwrap_or_else(|error| panic!("PCRE2 rejected {pattern:?}: {error}"))
}

fn all_spans_rust(regex: &rust::Regex, subject: &[u8]) -> Vec<Vec<Option<(usize, usize)>>> {
    regex
        .captures_iter(subject)
        .map(|result| {
            let captures = result.unwrap();
            (0..captures.len())
                .map(|index| captures.get(index).map(|m| (m.start(), m.end())))
                .collect()
        })
        .collect()
}

fn all_spans_oracle(regex: &oracle::Regex, subject: &[u8]) -> Vec<Vec<Option<(usize, usize)>>> {
    regex
        .captures_iter(subject)
        .map(|result| {
            let captures = result.unwrap();
            (0..captures.len())
                .map(|index| captures.get(index).map(|m| (m.start(), m.end())))
                .collect()
        })
        .collect()
}

#[test]
fn upstream_10_46_regular_subset_matches_c_oracle() {
    for case in CASES {
        let rust = rust_regex(case.pattern, case.caseless);
        let oracle = oracle_regex(case.pattern, case.caseless);
        assert_eq!(
            all_spans_rust(&rust, case.subject),
            all_spans_oracle(&oracle, case.subject),
            "pattern {:?}, subject {:?}, translated {:?}",
            case.pattern,
            case.subject,
            rust.translated_pattern(),
        );
    }
}

fn subjects(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &byte in alphabet {
                let mut value = prefix.clone();
                value.push(byte);
                next.push(value);
            }
        }
        all.extend(next.iter().cloned());
        frontier = next;
    }
    all
}

fn finite_regular_grammar() -> Vec<String> {
    let atoms = ["a", "b", ".", "[ab]", "[^a]", r"\d", r"\w", r"\s"];
    let mut patterns: Vec<String> = atoms.iter().map(|atom| (*atom).to_owned()).collect();
    for atom in atoms {
        for quantifier in ["?", "*", "+", "{1,2}", "*?", "+?"] {
            patterns.push(format!("(?:{atom}){quantifier}"));
        }
        patterns.push(format!("^({atom})$"));
    }
    for left in atoms {
        for right in atoms {
            patterns.push(format!("{left}{right}"));
            patterns.push(format!("({left}|{right})"));
        }
    }
    patterns.sort();
    patterns.dedup();
    patterns
}

#[test]
fn exhaustive_finite_regular_grammar_matches_c_oracle() {
    // This is exhaustive over the stated finite grammar and every subject of
    // length <= 4 over the alphabet below. The unbounded language is covered
    // by the companion libFuzzer target; no finite test can enumerate every
    // possible regex and subject.
    let subjects = subjects(b"ab1 \n", 4);
    for pattern in finite_regular_grammar() {
        let rust = rust_regex(&pattern, false);
        let oracle = oracle_regex(&pattern, false);
        for subject in &subjects {
            assert_eq!(
                all_spans_rust(&rust, subject),
                all_spans_oracle(&oracle, subject),
                "pattern {pattern:?}, subject {subject:?}, translated {:?}",
                rust.translated_pattern(),
            );
        }
    }
}
