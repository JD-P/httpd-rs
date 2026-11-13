#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    vapached::cache::fuzz_cache_stateful(data);
});
