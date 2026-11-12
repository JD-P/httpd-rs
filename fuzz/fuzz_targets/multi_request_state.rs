#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    vapached::whole_request_fuzz::run_stateful(data);
});
