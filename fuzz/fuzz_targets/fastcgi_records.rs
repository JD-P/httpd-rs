#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    httpd_rs::fastcgi::fuzz_parse_fastcgi_records(data);
});
