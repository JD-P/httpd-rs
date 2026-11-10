//! Shared-engine regressions for concurrent cold-to-hot tier promotion.

use std::sync::{Arc, Barrier};

use vapache_pcre2::bytes::Regex;

#[test]
fn cloned_regexes_promote_once_and_match_consistently() {
    const THREADS: usize = 8;
    const ITERATIONS: usize = 128;
    const SUBJECT: &[u8] = b"aaaaabbb";

    let regex = Regex::new(r"\A(?<head>a+)(?<tail>b*)\z").unwrap();
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut workers = Vec::new();
    for _ in 0..THREADS {
        let regex = regex.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            for _ in 0..ITERATIONS {
                let matched = regex.find(SUBJECT).unwrap().unwrap();
                assert_eq!((matched.start(), matched.end()), (0, SUBJECT.len()));

                let captures = regex.captures(SUBJECT).unwrap().unwrap();
                assert_eq!(captures.name("head").unwrap().as_bytes(), b"aaaaa");
                assert_eq!(captures.name("tail").unwrap().as_bytes(), b"bbb");

                let mut locations = regex.capture_locations();
                let matched = regex
                    .captures_read(&mut locations, SUBJECT)
                    .unwrap()
                    .unwrap();
                assert_eq!((matched.start(), matched.end()), (0, SUBJECT.len()));
                assert_eq!(locations.get(1), Some((0, 5)));
                assert_eq!(locations.get(2), Some((5, 8)));
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
}
