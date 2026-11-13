//! One fail-closed regex boundary for every Apache directive surface.
//!
//! The underlying compatibility crate admits a closed, byte-oriented PCRE2
//! subset and executes only its translated IR. Runtime resource errors are a
//! non-match here because directive regexes frequently guard authorization and
//! routing decisions.

#[derive(Clone, Debug)]
pub struct Regex {
    inner: httpd_rs_pcre2::bytes::Regex,
}

impl Regex {
    pub fn new(pattern: &str) -> Result<Self, String> {
        Self::compile(pattern, false)
    }

    pub fn compile(pattern: &str, caseless: bool) -> Result<Self, String> {
        let mut builder = httpd_rs_pcre2::bytes::RegexBuilder::new();
        builder.caseless(caseless).utf(false).ucp(false);
        builder
            .build(pattern)
            .map(|inner| Self { inner })
            .map_err(|error| error.to_string())
    }

    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    pub fn is_match(&self, subject: &[u8]) -> bool {
        self.inner.is_match(subject).unwrap_or(false)
    }

    pub fn captures<'s>(&self, subject: &'s [u8]) -> Option<httpd_rs_pcre2::bytes::Captures<'s>> {
        self.inner.captures(subject).ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::Regex;

    #[test]
    fn directive_boundary_uses_the_closed_pcre_grammar() {
        for pattern in [
            "",
            r"^literal$",
            r"^(?:one|two)+$",
            r"(?i:admin)",
            r"(?<word>[A-Za-z_][A-Za-z0-9_]*)",
            r"\A\Q.*\E\z",
            r"[[:digit:]A-F]+",
        ] {
            assert!(Regex::new(pattern).is_ok(), "rejected {pattern:?}");
        }

        for pattern in [
            r"(?=lookahead)",
            r"(?<=lookbehind)",
            r"(?>atomic)",
            r"(?R)",
            r"(capture)\1",
            r"(*ACCEPT)",
            r"possessive++",
            r"(?u:rust_unicode)",
            r"(?R:rust_crlf)",
            r"\b{start}",
            r"\R",
            r"\R\s",
            r"(?m)^",
            r"\D(?m:^)$",
            r"\y",
            "(?x)(?\r)",
        ] {
            assert!(Regex::new(pattern).is_err(), "admitted {pattern:?}");
        }
    }

    #[test]
    fn pcre_literal_escapes_cannot_become_backend_assertions() {
        let left = Regex::new(r"\<").unwrap();
        let right = Regex::new(r"\>").unwrap();
        assert!(left.is_match(b"<"));
        assert!(!left.is_match(b"word"));
        assert!(right.is_match(b">"));
        assert!(!right.is_match(b"word"));
    }
}
