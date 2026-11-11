//! Pass-37 PCRE2 compatibility probe.
//!
//! Reproduces the `pcre2_differential` crash artifact and the offset-0
//! production-surface divergences that escape the P23-E / P35-B fail-closed
//! gate. Every case is compared against the pinned PCRE2 10.46 oracle
//! (`pcre2` 0.2.11 / `pcre2-sys` 0.2.10).
//!
//! Run with:
//!
//! ```sh
//! cd adversarial/p37/probe
//! cargo run --release
//! ```

use pcre2_c_oracle::bytes as oracle;
use vapache_pcre2::bytes as rust;

fn rust_regex(pattern: &str, caseless: bool, crlf: bool, multiline: bool) -> rust::Regex {
    let mut builder = rust::RegexBuilder::new();
    builder.caseless(caseless).crlf(crlf).multi_line(multiline);
    builder
        .build(pattern)
        .unwrap_or_else(|error| panic!("rust rejected {pattern:?}: {error}"))
}

fn oracle_regex(pattern: &str, caseless: bool, crlf: bool, multiline: bool) -> oracle::Regex {
    let mut builder = oracle::RegexBuilder::new();
    builder.caseless(caseless).crlf(crlf).multi_line(multiline);
    builder
        .build(pattern)
        .unwrap_or_else(|error| panic!("oracle rejected {pattern:?}: {error}"))
}

fn show_match(
    label: &str,
    pattern: &str,
    caseless: bool,
    crlf: bool,
    multiline: bool,
    subject: &[u8],
) {
    let rust = rust_regex(pattern, caseless, crlf, multiline);
    let oracle = oracle_regex(pattern, caseless, crlf, multiline);
    let rust_match = rust.is_match(subject).map_err(|error| error.to_string());
    let oracle_match = oracle.is_match(subject).map_err(|error| error.to_string());
    let rust_caps = rust.captures(subject).ok().flatten().map(|caps| {
        (0..caps.len())
            .map(|index| caps.get(index).map(|m| (m.start(), m.end())))
            .collect::<Vec<_>>()
    });
    let oracle_caps = oracle.captures(subject).ok().flatten().map(|caps| {
        (0..caps.len())
            .map(|index| caps.get(index).map(|m| (m.start(), m.end())))
            .collect::<Vec<_>>()
    });
    println!("## {label}");
    println!("   pattern={pattern:?} caseless={caseless} crlf={crlf} multiline={multiline} subject={subject:?}");
    println!("   is_match rust={rust_match:?} oracle={oracle_match:?}");
    println!("   captures rust={rust_caps:?} oracle={oracle_caps:?}");
    if rust_match == oracle_match && rust_caps == oracle_caps {
        println!("   VERDICT: agree");
    } else {
        println!("   VERDICT: DIVERGE");
    }
    println!();
}

fn show_find_at(
    label: &str,
    pattern: &str,
    caseless: bool,
    crlf: bool,
    multiline: bool,
    subject: &[u8],
    start: usize,
) {
    let rust = rust_regex(pattern, caseless, crlf, multiline);
    let oracle = oracle_regex(pattern, caseless, crlf, multiline);
    let rust_match = rust.is_match_at(subject, start).map_err(|error| error.to_string());
    let oracle_match = oracle.is_match_at(subject, start).map_err(|error| error.to_string());
    let rust_find = rust
        .find_at(subject, start)
        .map(|m| m.map(|m| (m.start(), m.end())))
        .map_err(|error| error.to_string());
    let oracle_find = oracle
        .find_at(subject, start)
        .map(|m| m.map(|m| (m.start(), m.end())))
        .map_err(|error| error.to_string());
    println!("## {label}");
    println!("   pattern={pattern:?} caseless={caseless} crlf={crlf} multiline={multiline} subject={subject:?} start={start}");
    println!("   is_match_at rust={rust_match:?} oracle={oracle_match:?}");
    println!("   find_at rust={rust_find:?} oracle={oracle_find:?}");
    if rust_match == oracle_match && rust_find == oracle_find {
        println!("   VERDICT: agree");
    } else {
        println!("   VERDICT: DIVERGE");
    }
    println!();
}

fn main() {
    println!("=== P37-A: retained pcre2_differential crash case (`find_at` offset API) ===");
    let crash_subject: Vec<u8> = vec![
        0, 0, 13, 10, 40, 48, 40, 63, 109, 41, 94, 0, 0, 66, 97, 10, 40, 255, 255, 255, 255, 42,
        255, 255, 255, 255, 255, 255, 10, 10,
    ];
    show_find_at(
        "fuzz artifact crash-ee05338c89e80f39263bb634ec1f86df8d3497cf",
        "(?m)^",
        false,
        true,
        false,
        &crash_subject,
        3,
    );
    show_match(
        "same artifact evaluated at production offset 0",
        "(?m)^",
        false,
        true,
        false,
        &crash_subject,
    );

    show_find_at(
        "second fuzz artifact crash-eb581b07f45ed837314ced5e21c3d9f8c06240df",
        "\r^",
        false,
        true,
        true,
        &[13, 13, 13],
        2,
    );
    show_match(
        "second artifact shape evaluated at production offset 0 (multiline + crlf)",
        "\r^",
        false,
        true,
        true,
        &[13, 13, 13],
    );

    println!("=== P37-A: offset-0 / caseless-only divergences accepted by the configuration surface ===");
    show_match(
        "split-capable `\\R\\s`: Rust matches CR LF NUL, PCRE2 requires CRLF then whitespace",
        r"\R\s",
        false,
        false,
        false,
        b"\r\n\0",
    );
    show_match(
        "split-capable `\\R\\v`",
        r"\R\v",
        false,
        false,
        false,
        b"\r\n",
    );
    show_match(
        "`\\R$` capture span: Rust consumes only CR of CRLF",
        r"\R$",
        true,
        false,
        false,
        b"x\r\n",
    );
    show_match(
        "`\\R\\Z` capture span",
        r"\R\Z",
        false,
        false,
        false,
        b"\0\r\n",
    );
    show_match(
        "multiline circumflex after a final newline",
        r"\D(?m:^)$",
        false,
        false,
        false,
        b"\n",
    );
    show_match(
        "multiline circumflex after CRLF via a preceding atom",
        r"(?:[^]a](?m:^))",
        true,
        false,
        false,
        b"\r\n",
    );
    show_match(
        "`\\R(?m:^)$` combination",
        r"\R(?m:^)$",
        false,
        false,
        false,
        b"x\n",
    );

    println!("=== Controls: request-reachable subject bytes (no CR/LF/NUL) agree ===");
    let controls: &[(&str, &str, &[u8])] = &[
        (r"\R\s", "path with NEL", b"/a\x85b"),
        (r"\R\s", "path with obs-text", b"/caf\xc3\xa9"),
        (r"(?m:^)$", "ordinary path", b"/public.txt"),
        (r"\D(?m:^)$", "ordinary path 2", b"/a/b"),
        (r"\R$", "path with NEL", b"/x\x85"),
        (r"\R\Z", "path with obs-text", b"/y\xff"),
    ];
    for (pattern, label, subject) in controls {
        let rust = rust_regex(pattern, false, false, false);
        let oracle = oracle_regex(pattern, false, false, false);
        let rust_match = rust.is_match(subject).map_err(|error| error.to_string());
        let oracle_match = oracle.is_match(subject).map_err(|error| error.to_string());
        let verdict = if rust_match == oracle_match {
            "agree"
        } else {
            "DIVERGE"
        };
        println!("   {label}: pattern={pattern:?} rust={rust_match:?} oracle={oracle_match:?} {verdict}");
    }
    println!();

    println!("=== P37-A: gate closure in the current tree ===");
    for pattern in [r"\R\R", r"\R\C", r"\R+?$", r"\N*?\R", r"\S*\R"] {
        match rust::Regex::new(pattern) {
            Ok(_) => println!("   {pattern:?}: admitted by the Rust frontend"),
            Err(error) => println!("   {pattern:?}: rejected ({})", error.kind() as u8),
        }
    }
    for pattern in [r"\R\s", r"\R\v", r"\R$", r"\R\Z", r"\D(?m:^)$"] {
        match rust::Regex::new(pattern) {
            Ok(_) => println!("   {pattern:?}: admitted by the Rust frontend"),
            Err(error) => println!("   {pattern:?}: rejected ({})", error.kind() as u8),
        }
    }
}
