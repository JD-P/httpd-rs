#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    httpd_rs::nginx_frontend::fuzz_nginx_frontend(data);
});
