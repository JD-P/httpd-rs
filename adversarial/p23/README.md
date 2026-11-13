# P23 regex adversarial tooling

This directory retains both forms of the PCRE2 differential audit:

- `probe/src/bin/fuzz.rs` is the deterministic grammar generator used during
  the original P23 investigation.
- `pcre2_differential_fuzzer.rs` is the coverage-guided libFuzzer target. The
  conventional entry point in `fuzz/fuzz_targets/` includes this file so the
  ordinary smoke and nightly campaigns exercise the reviewed artifact.
- `exploit_p23.py` replays the live Apache-versus-httpd-rs expression cases.

Run the coverage-guided target from the repository root:

```sh
cargo +nightly fuzz run pcre2_differential
```

Its input is one flag byte, a UTF-8 pattern, a NUL separator, and an arbitrary
byte subject. The target compares every capture from the admitted Rust subset
with the PCRE2 10.46 C oracle.
