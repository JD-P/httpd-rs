use pcre2_c_oracle::bytes as oracle;
use httpd_rs_pcre2::bytes as rust;

fn rbuild(p: &str, flags: (bool, bool, bool, bool)) -> Result<rust::Regex, String> {
    let (i, s, m, crlf) = flags;
    let mut b = rust::RegexBuilder::new();
    b.caseless(i)
        .dotall(s)
        .multi_line(m)
        .crlf(crlf)
        .max_subject_size(1 << 20)
        .match_limit(1 << 30);
    b.build(p).map_err(|e| e.to_string())
}

fn obuild(p: &str, flags: (bool, bool, bool, bool)) -> Result<oracle::Regex, String> {
    let (i, s, m, crlf) = flags;
    let mut b = oracle::RegexBuilder::new();
    b.caseless(i).dotall(s).multi_line(m).crlf(crlf);
    b.build(p).map_err(|e| e.to_string())
}

fn rspans(re: &rust::Regex, s: &[u8]) -> String {
    match re.captures(s) {
        Ok(Some(c)) => format!(
            "{:?}",
            (0..c.len())
                .map(|i| c.get(i).map(|m| (m.start(), m.end())))
                .collect::<Vec<_>>()
        ),
        Ok(None) => "None".into(),
        Err(e) => format!("MERR {e}"),
    }
}

fn ospans(re: &oracle::Regex, s: &[u8]) -> String {
    match re.captures(s) {
        Ok(Some(c)) => format!(
            "{:?}",
            (0..c.len())
                .map(|i| c.get(i).map(|m| (m.start(), m.end())))
                .collect::<Vec<_>>()
        ),
        Ok(None) => "None".into(),
        Err(e) => format!("MERR {e}"),
    }
}

fn show(name: &str, p: &str, s: &[u8], flags: (bool, bool, bool, bool)) {
    let rr = rbuild(p, flags);
    let oo = obuild(p, flags);
    let rs = match &rr {
        Ok(re) => rspans(re, s),
        Err(e) => format!("CERR {e}"),
    };
    let os = match &oo {
        Ok(re) => ospans(re, s),
        Err(e) => format!("CERR {e}"),
    };
    println!("{name}: p={p:?} s={s:?}\n  rust  = {rs}\n  oracle= {os}");
    if let Ok(re) = &rr {
        println!("  translated={:?}", re.translated_pattern());
    }
}

fn show_iter(name: &str, p: &str, s: &[u8]) {
    let rr = rbuild(p, (false, false, false, false));
    let oo = obuild(p, (false, false, false, false));
    let rs = match &rr {
        Ok(re) => format!(
            "{:?}",
            re.captures_iter(s)
                .map(|r| r.map(|c| (0..c.len()).map(|i| c.get(i).map(|m| (m.start(), m.end()))).collect::<Vec<_>>()))
                .collect::<Result<Vec<_>, _>>()
        ),
        Err(e) => format!("CERR {e}"),
    };
    let os = match &oo {
        Ok(re) => format!(
            "{:?}",
            re.captures_iter(s)
                .map(|r| r.map(|c| (0..c.len()).map(|i| c.get(i).map(|m| (m.start(), m.end()))).collect::<Vec<_>>()))
                .collect::<Result<Vec<_>, _>>()
        ),
        Err(e) => format!("CERR {e}"),
    };
    println!("{name}: p={p:?} s={s:?}\n  rust  = {rs}\n  oracle= {os}");
}

fn main() {
    let n = (false, false, false, false);
    let c = (false, false, false, true);

    show("P23-B Z-then-v", r"^\Z\v", b"\n", n);
    show("P23-B dollar-newline", "secret$\n", b"secret\n", n);
    show("P23-B lazy-star", r".*?$", b"abc\n", n);
    show("P23-B lazy-D", r"\D*?$", b"abcdefghij\n", n);
    show("P23-B lazy-class", r"[^]]+?$", b"abcdefghij\n", n);
    show("P23-B lazy-optional", r"[^a]??$", b"\n", n);
    show("P23-B z-dollar", r"^foo\z$", b"foo\n", n);
    show("P23-B z-dollar-empty", r"^\z$", b"\n", n);
    show("P23-B alt-dollar", r"a$|a\n", b"a\n", n);
    show("P23-B dollar-space", r"$\s", b"abcdef\n", n);
    show("P23-B Z-class", r"\Z[^- #]$", b"a-\n", n);
    show("P23-B z-extra", r"\z$", b"\n", n);

    show("P23-C neg-posix", r"[[:^alpha:]]", b"1", n);
    show("P23-C neg-posix-fp", r"[[:^alpha:]]", b"a]", n);
    show("P23-C neg-posix-digit", r"[[:^digit:]]", b"x", n);

    show("P23-D range-0", r"[--1]", b"0", n);
    show("P23-D range-dot", r"[--1]", b".", n);
    show("P23-D range-space", r"[ --]", b"#", n);
    show("P23-D leading-bracket-range", r"[]-a]", b"-", n);
    show("P23-D overaccept", r"[a--]", b"a", n);

    show("P23-E RR", r"\R\R", b"\r\n", n);
    show("P23-E RC", r"\R\C", b"\r\n", n);
    show("P23-E lazy-R", r"\R+?$", b"\r\n\n", n);

    show("P23-F inline-x-Q", r"(?x)\Qa b\E", b"a b", n);
    show("P23-F inline-x-Q2", r"(?x)\Qa b\E", b"ab", n);
    show("P23-F inline-x-class", r"(?x)[ a#b ]", b" ", n);
    show("P23-F scoped-x", r"(?x:\Qa b\E)", b"a b", n);

    show("P23-G keep-name", r"a(?P<__httpd_rs_pcre2_keep_0>b)", b"ab", n);

    show("P23-H octal101", r"\101", b"A", n);
    show("P23-H octal10", r"\10", b"\x08", n);
    show("P23-H hex1", r"\x9", b"\t", n);
    show("P23-H hex0", r"\x{0}", b"\0", n);
    show("P23-H octal-brace", r"\o{101}", b"A", n);
    show("P23-H hex-quant", r"\x{42}{2}", b"BB", n);
    show("P23-H hex-plus", r"\x{42}+", b"BB", n);

    show("P23-I capture-hex", r"(\x{42})+", b"BB", n);
    show("P23-I capture-digit", r"(\d{2})+", b"1234", n);
    show("P23-I zero-width-z", r"(\z|\C)+", b"abcde", n);
    show("P23-I zero-width-b", r"(a|\b)+", b"aa", n);
    show("P23-I zero-width-dollar", r"(a|$)+", b"aa", n);

    show("P23-J posix-range", r"[[:alpha:]]-[a-z]", b"a-b", n);
    show("P23-J posix-star", r"[[:space:]]*-", b" -", n);
    show("P23-J empty-alt", r"a|", b"a", n);
    show("P23-J dup-names", r"(?J)(?<n>a)(?<n>b)", b"ab", n);

    show("P23-K N-crlf", r"\N", b"\r", c);
    show("P23-K dollar-crlf", r"a$", b"a\r", c);

    show("P23-L captures-caret", r"(?m)^", b"a\n", n);
    show("P23-L captures-empty", r"(?m)^$", b"\n\n", n);
    show_iter("P23-L multiline-caret", r"(?m)^", b"a\n");
    show_iter("P23-L multiline-empty", r"(?m)^$", b"\n\n");

    show("P23-M N-star-R", r"\N*?\R", b"\x85", n);
    show("P23-M grouped-N-star-R", r"(?:\N)*?\R", b"\x85", n);
}
