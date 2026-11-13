#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    httpd_rs::h2::fuzz_h2_frames(data);
});
