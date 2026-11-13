//! Reproducible microbenchmark for the httpd-rs compatibility engine and the
//! PCRE2 10.46 C oracle. Run with `cargo run -p httpd-rs-pcre2 --release
//! --example pcre2_benchmark`.

use std::hint::black_box;
use std::time::Instant;

use httpd_rs_pcre2::bytes as v;
use pcre2_c_oracle::bytes as c;

struct Case {
    name: &'static str,
    pattern: &'static str,
    subject: Vec<u8>,
}

fn median_ns(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

fn sample(mut operation: impl FnMut(), iterations: usize) -> f64 {
    let mut samples = Vec::with_capacity(7);
    for _ in 0..7 {
        let started = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        samples.push(started.elapsed().as_nanos() as f64 / iterations as f64);
    }
    median_ns(samples)
}

fn v_compile(pattern: &str) -> v::Regex {
    v::Regex::new(black_box(pattern)).unwrap()
}

fn c_compile(pattern: &str, jit: bool) -> c::Regex {
    let mut builder = c::RegexBuilder::new();
    builder.jit(jit);
    builder.build(black_box(pattern)).unwrap()
}

fn main() {
    let mut scan = vec![b'x'; 4096];
    scan.extend_from_slice(b" key_123=987654");
    let cases = [
        Case {
            name: "literal-anchor",
            pattern: r"\AGET /health\z",
            subject: b"GET /health".to_vec(),
        },
        Case {
            name: "captures",
            pattern: r"(?P<key>[A-Za-z_]+)=(?<value>\d+)",
            subject: scan,
        },
        Case {
            name: "alternation",
            pattern: r"(?:foo|bar|baz)+quux",
            subject: [vec![b'f'; 4096], b"foobarbazquux".to_vec()].concat(),
        },
        Case {
            name: "byte-class",
            pattern: r"[[:^alpha:]]+[[:digit:]]{2,8}",
            subject: b"header-value: ---12345".to_vec(),
        },
        Case {
            name: "pcre-lowering",
            pattern: r"\Qsecret.txt\E\Z",
            subject: b"secret.txt\n".to_vec(),
        },
    ];

    println!("case,operation,httpd_rs_ns,c_interpreter_ns,c_jit_ns,httpd_rs_over_c_interpreter");
    for case in &cases {
        let compile_iterations = 250;
        let v_compile_ns = sample(
            || {
                black_box(v_compile(case.pattern));
            },
            compile_iterations,
        );
        let c_compile_ns = sample(
            || {
                black_box(c_compile(case.pattern, false));
            },
            compile_iterations,
        );
        let c_jit_compile_ns = sample(
            || {
                black_box(c_compile(case.pattern, true));
            },
            compile_iterations,
        );
        println!(
            "{},compile,{v_compile_ns:.1},{c_compile_ns:.1},{c_jit_compile_ns:.1},{:.3}",
            case.name,
            v_compile_ns / c_compile_ns,
        );

        // Tiered engines can make construction cheap by deferring work. Keep
        // that trade-off visible by measuring construction plus the first
        // capture search as a separate cold-path operation.
        let cold_iterations = if case.subject.len() > 1024 { 50 } else { 250 };
        let v_first_ns = sample(
            || {
                let regex = v_compile(case.pattern);
                black_box(regex.captures(black_box(&case.subject)).unwrap());
            },
            cold_iterations,
        );
        let c_first_ns = sample(
            || {
                let regex = c_compile(case.pattern, false);
                black_box(regex.captures(black_box(&case.subject)).unwrap());
            },
            cold_iterations,
        );
        let c_jit_first_ns = sample(
            || {
                let regex = c_compile(case.pattern, true);
                black_box(regex.captures(black_box(&case.subject)).unwrap());
            },
            cold_iterations,
        );
        println!(
            "{},compile+first-captures,{v_first_ns:.1},{c_first_ns:.1},{c_jit_first_ns:.1},{:.3}",
            case.name,
            v_first_ns / c_first_ns,
        );

        let v_regex = v_compile(case.pattern);
        let c_regex = c_compile(case.pattern, false);
        let c_jit_regex = c_compile(case.pattern, true);
        let expected = c_regex.captures(&case.subject).unwrap().is_some();
        assert_eq!(v_regex.captures(&case.subject).unwrap().is_some(), expected);
        assert_eq!(
            c_jit_regex.captures(&case.subject).unwrap().is_some(),
            expected
        );
        let iterations = if case.subject.len() > 1024 {
            500
        } else {
            10_000
        };
        let v_match_ns = sample(
            || {
                black_box(v_regex.captures(black_box(&case.subject)).unwrap());
            },
            iterations,
        );
        let c_match_ns = sample(
            || {
                black_box(c_regex.captures(black_box(&case.subject)).unwrap());
            },
            iterations,
        );
        let c_jit_match_ns = sample(
            || {
                black_box(c_jit_regex.captures(black_box(&case.subject)).unwrap());
            },
            iterations,
        );
        println!(
            "{},captures,{v_match_ns:.1},{c_match_ns:.1},{c_jit_match_ns:.1},{:.6}",
            case.name,
            v_match_ns / c_match_ns,
        );
    }

    // P23-A security case: the compatibility engine must reject at its work
    // gate before entering the large expanded automaton. Each engine still
    // uses the median-of-seven sampler; the C engines run once per sample.
    let pattern = "a{8000}";
    let subject = vec![b'a'; 8190];
    let v_regex = v_compile(pattern);
    let c_regex = c_compile(pattern, false);
    let c_jit_regex = c_compile(pattern, true);
    let v_ns = sample(
        || assert!(v_regex.is_match(black_box(&subject)).is_err()),
        10_000,
    );
    let c_ns = sample(
        || {
            black_box(c_regex.captures(black_box(&subject)).unwrap());
        },
        1,
    );
    let c_jit_ns = sample(
        || {
            black_box(c_jit_regex.captures(black_box(&subject)).unwrap());
        },
        1,
    );
    println!(
        "counted-repeat-resource,guard,{:.1},{:.1},{:.1},{:.6}",
        v_ns,
        c_ns,
        c_jit_ns,
        v_ns / c_ns,
    );

    // P24-B security case: optional counted repetitions add terminal paths
    // and can force the PikeVM active-set path. The original 1,328-byte
    // subject is rejected after charging that cost; the admitted boundary
    // remains reproducibly measurable on deployment hardware.
    let pattern = r"1(?:[[:^alpha:]]{0,3}){4208}a";
    let admitted = vec![b'1'; 249];
    let rejected = vec![b'1'; 1328];
    let v_regex = v_compile(pattern);
    assert!(v_regex.captures(&rejected).is_err());
    let v_guard_ns = sample(
        || assert!(v_regex.captures(black_box(&rejected)).is_err()),
        10_000,
    );
    let v_cold_ns = sample(
        || {
            let regex = v_compile(pattern);
            black_box(regex.captures(black_box(&admitted)).unwrap());
        },
        1,
    );
    let v_warm_ns = sample(
        || {
            black_box(v_regex.captures(black_box(&admitted)).unwrap());
        },
        1,
    );
    println!("nested-optional-resource,guard,{v_guard_ns:.1},,,");
    println!("nested-optional-boundary,compile+first-captures,{v_cold_ns:.1},,,");
    println!("nested-optional-boundary,captures,{v_warm_ns:.1},,,");
}
