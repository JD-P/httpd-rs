use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

use httpd_rs_pcre2::bytes::Regex;

fn rss_kib() -> u64 {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap()
}

fn main() {
    let threads: usize = std::env::var("P42_THREADS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(64);
    let iterations: usize = std::env::var("P42_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100);

    let captures: usize = std::env::var("P42_CAPTURES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    // Pass 24's admitted near-boundary Pike/lazy-DFA shape. Optional capture
    // groups expose the part of each dependency cache that scales with both
    // the automaton state count and the capture-slot count.
    let pattern = format!(
        "{}1(?:[[:^alpha:]]{{0,3}}){{4208}}a",
        "(x?)".repeat(captures)
    );
    let subject_bytes: usize = std::env::var("P42_SUBJECT_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(249);
    let subject = Arc::new(vec![b'1'; subject_bytes]);
    let before = rss_kib();
    let regex = Arc::new(Regex::new(&pattern).unwrap());
    let compiled = rss_kib();
    assert!(!regex.is_match(&subject).unwrap());
    let one_search = rss_kib();

    let start = Arc::new(Barrier::new(threads + 1));
    let mut workers = Vec::with_capacity(threads);
    for _ in 0..threads {
        let regex = Arc::clone(&regex);
        let subject = Arc::clone(&subject);
        let start = Arc::clone(&start);
        workers.push(thread::spawn(move || {
            start.wait();
            for _ in 0..iterations {
                assert!(!regex.is_match(&subject).unwrap());
            }
        }));
    }
    start.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    let concurrent = rss_kib();
    println!("threads={threads} iterations={iterations} captures={captures}");
    println!("pattern_bytes={}", pattern.len());
    println!("subject_bytes={subject_bytes}");
    println!("rss_before_kib={before}");
    println!("rss_after_compile_kib={compiled}");
    println!("rss_after_one_search_kib={one_search}");
    println!("rss_after_concurrent_search_kib={concurrent}");
    println!(
        "retained_pool_growth_kib={}",
        concurrent.saturating_sub(one_search)
    );
}
