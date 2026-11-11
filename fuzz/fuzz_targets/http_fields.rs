#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    vapached::http_fields::fuzz_http_fields(data);
});
