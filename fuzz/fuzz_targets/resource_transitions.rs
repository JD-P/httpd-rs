#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    httpd_rs::resource::fuzz_resource_transitions(data);
});
