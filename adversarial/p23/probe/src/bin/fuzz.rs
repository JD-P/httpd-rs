use pcre2_c_oracle::bytes as oracle;
use httpd_rs_pcre2::bytes as rust;

#[derive(Clone, Copy, Default, Debug)]
struct Flags {
    caseless: bool,
    dotall: bool,
    extended: bool,
    multiline: bool,
    crlf: bool,
}

fn rust_regex(pattern: &str, flags: Flags) -> Result<rust::Regex, String> {
    let mut b = rust::RegexBuilder::new();
    b.caseless(flags.caseless)
        .dotall(flags.dotall)
        .extended(flags.extended)
        .multi_line(flags.multiline)
        .crlf(flags.crlf)
        .max_subject_size(1 << 20)
        .match_limit(1 << 30);
    b.build(pattern).map_err(|e| e.to_string())
}

fn oracle_regex(pattern: &str, flags: Flags) -> Result<oracle::Regex, String> {
    let mut b = oracle::RegexBuilder::new();
    b.caseless(flags.caseless)
        .dotall(flags.dotall)
        .extended(flags.extended)
        .multi_line(flags.multiline)
        .crlf(flags.crlf);
    b.build(pattern).map_err(|e| e.to_string())
}

type Spans = Vec<Vec<Option<(usize, usize)>>>;

fn rust_spans(re: &rust::Regex, subject: &[u8]) -> Result<Spans, String> {
    re.captures_iter(subject)
        .map(|r| {
            r.map_err(|e| e.to_string()).map(|c| {
                (0..c.len())
                    .map(|i| c.get(i).map(|m| (m.start(), m.end())))
                    .collect()
            })
        })
        .collect()
}

fn oracle_spans(re: &oracle::Regex, subject: &[u8]) -> Result<Spans, String> {
    re.captures_iter(subject)
        .map(|r| {
            r.map_err(|e| e.to_string()).map(|c| {
                (0..c.len())
                    .map(|i| c.get(i).map(|m| (m.start(), m.end())))
                    .collect()
            })
        })
        .collect()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }
}

const ATOMS: &[&str] = &[
    "a", "b", "c", "1", " ", ".", "\\d", "\\w", "\\s", "\\D", "\\W", "\\S", "\\b", "\\B",
    "\\h", "\\v", "\\H", "\\V", "\\R", "\\N", "\\C", "\\A", "\\z", "\\Z", "\\K", "$", "^",
    "\\x41", "\\x{42}", "\\101", "\\cA", "\\ca", "\\c?", "\\c:", "\\t", "\\n", "\\r", "\\f",
    "\\a", "\\e", "\\0", "\\07", "\\077", "[ab]", "[^a]", "[a-z]", "[[:alpha:]]", "[[:^alpha:]]",
    "[[:digit:]]", "[[:^digit:]]", "[[:space:]]", "[[:^space:]]", "[\\d]", "[\\w-]", "[a\\-z]",
    "[]]", "[^]]", "[a[b]", "[\\Qab\\E]", "[\\h]", "[\\v]", "[\\b]", "[\\x41-\\x5A]",
    "\\Qa b\\E", "\\Qa#b\\E", "\\Q[a-z]+.txt\\E", "(?#c)", "a#c", "a b",
];

const GROUP_OPEN: &[&str] = &["(", "(?:", "(?P<n>", "(?<n>", "(?'n'"];
const QUANT: &[&str] = &["", "", "", "?", "*", "+", "{1,2}", "{0,1}", "{2}", "*?", "+?", "??"];

fn gen_atom(rng: &mut Rng, depth: usize, extended: bool) -> String {
    if depth == 0 {
        return ATOMS[rng.below(ATOMS.len())].to_string();
    }
    match rng.below(12) {
        0..=5 => ATOMS[rng.below(ATOMS.len())].to_string(),
        6 => {
            let open = GROUP_OPEN[rng.below(GROUP_OPEN.len())];
            format!("{}{}{}", open, gen_seq(rng, depth - 1, extended), ")")
        }
        7 => format!("(?:{}|{})", gen_seq(rng, depth - 1, extended), gen_seq(rng, depth - 1, extended)),
        8 => format!("({}|{})", gen_seq(rng, depth - 1, extended), gen_seq(rng, depth - 1, extended)),
        9 => {
            let a = gen_atom(rng, depth - 1, extended);
            let q = QUANT[rng.below(QUANT.len())];
            format!("{a}{q}")
        }
        10 => {
            if extended {
                match rng.below(4) {
                    0 => " ".to_string(),
                    1 => "#comment\n".to_string(),
                    2 => "\t".to_string(),
                    _ => format!("[{}]", gen_class(rng, depth - 1, extended)),
                }
            } else {
                format!("[{}]", gen_class(rng, depth - 1, extended))
            }
        }
        _ => {
            // inline option groups
            let opt = ["i", "s", "m", "x", "-i", "-m", "i-s"][rng.below(7)];
            format!("(?{opt}:{})", gen_seq(rng, depth - 1, extended))
        }
    }
}

fn gen_class(rng: &mut Rng, depth: usize, extended: bool) -> String {
    if depth == 0 {
        return "a".to_string();
    }
    let mut out = String::new();
    if rng.chance(5) {
        out.push('^');
    }
    let n = 1 + rng.below(4);
    for _ in 0..n {
        match rng.below(14) {
            0 => out.push_str("a"),
            1 => out.push_str("b"),
            2 => out.push_str("1"),
            3 => out.push(' '),
            4 => out.push('#'),
            5 => out.push_str("\\d"),
            6 => out.push_str("\\w"),
            7 => out.push_str("\\s"),
            8 => out.push_str("[:alpha:]"),
            9 => out.push_str("[:^alpha:]"),
            10 => out.push_str("[:digit:]"),
            11 => out.push_str("\\h"),
            12 => out.push_str("\\v"),
            _ => {
                if extended && rng.chance(2) {
                    out.push_str("\\x20");
                } else {
                    out.push('-');
                }
            }
        }
    }
    out
}

fn gen_seq(rng: &mut Rng, depth: usize, extended: bool) -> String {
    let n = 1 + rng.below(3);
    let mut out = String::new();
    for _ in 0..n {
        out.push_str(&gen_atom(rng, depth, extended));
    }
    out
}

fn gen_pattern(rng: &mut Rng, extended: bool) -> String {
    let mut p = gen_seq(rng, 3, extended);
    // sometimes add anchors / inline flags
    match rng.below(6) {
        0 => p = format!("^{p}$"),
        1 => p = format!("(?x){p}"),
        2 => p = format!("(?x:{p})"),
        3 => p = format!("{p}$"),
        4 => p = format!("^{p}"),
        _ => {}
    }
    p
}

const SUBJECT_BYTES: &[u8] = b"abABcC019 _#[]-~\t\n\r\x00\x7f\x85\xa0\xff";

fn gen_subject(rng: &mut Rng) -> Vec<u8> {
    let n = rng.below(12);
    (0..n).map(|_| SUBJECT_BYTES[rng.below(SUBJECT_BYTES.len())]).collect()
}

fn has_multidigit_escape(pattern: &str) -> bool {
    let b = pattern.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'\\' {
            if b[i + 1].is_ascii_digit() && b[i + 1] != b'0' {
                if let Some(&next) = b.get(i + 2) {
                    if next.is_ascii_digit() {
                        return true;
                    }
                }
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    false
}

fn fmt_flags(f: Flags) -> String {
    let mut s = String::new();
    if f.caseless { s.push('i'); }
    if f.dotall { s.push('s'); }
    if f.extended { s.push('x'); }
    if f.multiline { s.push('m'); }
    if f.crlf { s.push_str("R"); }
    s
}

fn main() {
    let only_match = std::env::var("ONLY_MATCH").is_ok();
    let only_accept = std::env::var("ONLY_ACCEPT").is_ok();
    let only_reject = std::env::var("ONLY_REJECT").is_ok();
    let clean = std::env::var("CLEAN").is_ok();
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let iterations: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000_000);
    let mut both_diff = 0u64;
    let mut over_accept = 0u64;
    let mut over_reject = 0u64;
    let mut printed = 0u64;
    let mut seen = std::collections::HashSet::new();
    for i in 0..iterations {
        let extended = rng.chance(4);
        let pattern = gen_pattern(&mut rng, extended);
        if pattern.len() > 512 {
            continue;
        }
        if clean && (pattern.contains("[:")
            || pattern.contains("(?x")
            || pattern.contains("\\x{0")
            || has_multidigit_escape(&pattern))
        {
            continue;
        }
        let flags = if std::env::var("EXPR").is_ok() {
            Flags {
                caseless: rng.chance(2),
                dotall: false,
                extended: false,
                multiline: false,
                crlf: false,
            }
        } else {
            Flags {
                caseless: rng.chance(4),
                dotall: rng.chance(4),
                extended,
                multiline: rng.chance(4),
                crlf: rng.chance(8),
            }
        };
        let subject = gen_subject(&mut rng);
        let rr = rust_regex(&pattern, flags);
        let or = oracle_regex(&pattern, flags);
        let mut is_match_diff = false;
        let (r, o) = match (&rr, &or) {
            (Ok(rr), Ok(or)) => {
                let r = rust_spans(rr, &subject);
                let o = oracle_spans(or, &subject);
                if r != o {
                    both_diff += 1;
                    is_match_diff = true;
                    (format!("{:?}", r), format!("{:?}", o))
                } else {
                    continue;
                }
            }
            (Ok(_), Err(e)) => {
                over_accept += 1;
                ("COMPILES".into(), format!("PCRE2-ERR {e}"))
            }
            (Err(e), Ok(_)) => {
                over_reject += 1;
                (format!("RUST-ERR {e}"), "COMPILES".into())
            }
            (Err(_), Err(_)) => continue,
        };
        if only_match && !is_match_diff {
            continue;
        }
        if only_accept && !matches!((&rr, &or), (Ok(_), Err(_))) {
            continue;
        }
        if only_reject && !matches!((&rr, &or), (Err(_), Ok(_))) {
            continue;
        }
        let key = format!("{pattern}\u{1}{}\u{1}{:?}", fmt_flags(flags), subject);
        if !seen.insert(key) {
            continue;
        }
        if printed < 200 {
            printed += 1;
            println!(
                "DIFF#{printed} iter={i} pattern={pattern:?} flags={flags:?} subject={subject:?}\n  rust  = {r}\n  oracle= {o}"
            );
            if let Ok(rr) = &rr {
                println!("  translated={:?}", rr.translated_pattern());
            }
        }
    }
    eprintln!(
        "iterations={iterations} match-diffs={both_diff} rust-accepts-pcre2-rejects={over_accept} pcre2-accepts-rust-rejects={over_reject} printed={printed}"
    );
}
