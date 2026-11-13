#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    httpd_rs::ocsp::fuzz_ocsp_parsers(data);
});
