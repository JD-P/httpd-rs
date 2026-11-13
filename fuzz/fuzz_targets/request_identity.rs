#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    httpd_rs::access::fuzz_request_identity_environment(data);
});
