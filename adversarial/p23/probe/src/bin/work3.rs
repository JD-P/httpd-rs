use std::time::Instant;
use httpd_rs_pcre2::bytes::RegexBuilder;

fn main() {
    for slen in [8190usize, 16384, 32768, 65536] {
        let subject = vec![b'a'; slen];
        for n in [1000usize, 2000, 4000, 8000, 16000] {
            if n > slen { continue; }
            let pattern = format!("a{{{n}}}");
            let mut b = RegexBuilder::new();
            b.max_pattern_size(64 * 1024)
                .max_subject_size(64 * 1024)
                .match_limit(16 * 1024 * 1024)
                .size_limit(2 * 1024 * 1024);
            let Ok(re) = b.build(&pattern) else { continue };
            let t = Instant::now();
            let r = re.captures(&subject);
            println!(
                "slen={slen} n={n} plen={} match={:?} result={:?}",
                pattern.len(),
                t.elapsed(),
                r.map(|c| c.map(|c| c.len()))
            );
        }
    }
}
