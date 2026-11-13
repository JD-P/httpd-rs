#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use httpd_rs::http::{read_request, Limits};

fuzz_target!(|data: &[u8]| {
    let mut input = Cursor::new(data.to_vec());
    let mut buffered = Vec::new();
    let mut limits = Limits::default();
    limits.body = 2 * 1024 * 1024;
    limits.max_spool_bytes = 4 * 1024 * 1024;
    limits.max_spool_files = 4;
    let _ = read_request(&mut input, &mut buffered, &limits, |_| {});
});
