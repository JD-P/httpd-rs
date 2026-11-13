use std::time::Instant;
use httpd_rs_pcre2::bytes::RegexBuilder;

fn main() {
    let subject = vec![b'a'; 64 * 1024];
    for n in [25000usize, 30000, 40000, 50000, 60000, 65535] {
        let pattern = format!("a{{{n}}}");
        let mut b = RegexBuilder::new();
        b.max_pattern_size(64 * 1024)
            .max_subject_size(64 * 1024)
            .match_limit(16 * 1024 * 1024)
            .size_limit(2 * 1024 * 1024);
        let t = Instant::now();
        match b.build(&pattern) {
            Ok(re) => {
                let ct = t.elapsed();
                let t = Instant::now();
                let r = re.captures(&subject);
                println!(
                    "n={n} plen={} compile={ct:?} match={:?} result={:?}",
                    pattern.len(),
                    t.elapsed(),
                    r.map(|c| c.map(|c| c.len()))
                );
            }
            Err(e) => println!("n={n} compile={:?} CERR {e}", t.elapsed()),
        }
    }
}
