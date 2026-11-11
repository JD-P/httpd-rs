#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    vapached::policy_ref::fuzz_policy_path(data);
});
