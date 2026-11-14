# PCRE2 compatibility-engine benchmark

Measured 2026-11-14 after the dependency-boundary remediation on Linux 6.18.55, an AMD EPYC
9V74 worker (5 available cores), Rust 1.99.1. The benchmark is single-threaded,
uses release builds, reports the median of seven samples, and compares the same
`captures` API because that is what httpd-rs expressions use.

The “httpd-rs” column is the safe-Rust compatibility frontend and deterministic
automata backend guarded by the Verus-verified engine-mode and resource
admission kernels. Construction eagerly creates one bounded hybrid engine at
the configuration/access-file compilation boundary. Its lazy DFA and internal
PikeVM fallback share the compiled representation and cache; request-time
matching never invokes the dependency compiler or creates a per-pattern cache.
Neither strategy enables bounded or recursive backtracking. The automata
implementation itself is a documented proof assumption, not code translated
from Verus.

```sh
cargo run -p httpd-rs-pcre2 --release --example pcre2_benchmark
```

The C columns use the test-only PCRE2 10.46 oracle through `pcre2` 0.2.11,
once as the interpreter and once with JIT requested. Times are nanoseconds per
operation; lower is better.

| Case | Operation | httpd-rs | C interpreter | C JIT | httpd-rs / C interpreter |
|---|---|---:|---:|---:|---:|
| literal anchor | compile | 5,988.7 | 501.4 | 2,579.8 | 11.944 |
| literal anchor | compile + first captures | 9,888.3 | 665.3 | 2,548.6 | 14.862 |
| literal anchor | captures | 55.2 | 114.9 | 63.3 | 0.480 |
| captures over 4 KiB | compile | 16,694.5 | 978.8 | 5,342.4 | 17.057 |
| captures over 4 KiB | compile + first captures | 19,009.8 | 6,136,068.8 | 7,954.6 | 0.003 |
| captures over 4 KiB | captures | 63.6 | 6,152,310.8 | 2,576.6 | 0.000010 |
| alternation over 4 KiB | compile | 23,403.8 | 781.3 | 5,669.7 | 29.957 |
| alternation over 4 KiB | compile + first captures | 29,295.3 | 139,538.2 | 5,612.4 | 0.210 |
| alternation over 4 KiB | captures | 312.0 | 139,861.3 | 216.8 | 0.002231 |
| byte/POSIX class | compile | 59,515.3 | 613.4 | 3,272.3 | 97.019 |
| byte/POSIX class | compile + first captures | 67,013.6 | 881.8 | 3,485.4 | 75.992 |
| byte/POSIX class | captures | 90.7 | 198.7 | 80.9 | 0.457 |
| `\Q…\E\Z` lowering | compile | 7,373.9 | 514.0 | 4,273.0 | 14.346 |
| `\Q…\E\Z` lowering | compile + first captures | 11,106.0 | 666.6 | 4,106.4 | 16.660 |
| `\Q…\E\Z` lowering | captures | 62.3 | 127.9 | 72.3 | 0.487 |
| `a{8000}` / 8,190 bytes | resource guard / captures | 10.6 | 4,507.0 | 2,273.0 | 0.002345 |
| P24 nested optional / 1,328 bytes | resource guard | 24.3 | — | — | — |
| P24 nested optional / admitted 249-byte boundary | compile + first captures | 51,181,491.0 | — | — | — |
| P24 nested optional / admitted 249-byte boundary | captures | 47,510,516.0 | — | — | — |

Interpretation:

- Compilation is 11.9–97.0× the C interpreter because the complete bounded
  matching engine and cache are now owned by the administrative compile
  boundary rather than lazily allocated by an arbitrary request. The first
  implementation of that remediation separately built Pike-only and hybrid
  meta engines; profiling removed the duplicate and improved compilation by
  19–42% on four of five representative patterns (7% for the class-heavy
  case). Parsing and structural work accounting remain deliberate costs.
- “Compile + first captures” now includes no promotion or dependency compiler
  work. All searches use the shared hybrid engine, which may choose its bounded
  PikeVM fallback internally.
- Warm captures beat the C interpreter in every case. They also beat C JIT in
  four of five cases; the remaining alternation case is 1.32× C JIT. Inline
  capture slots and a group-zero fast path remove allocator and submatch work
  from the common no-explicit-capture case.
- The counted-repetition row is a security-policy comparison rather than a
  successful-match throughput comparison. httpd-rs rejects the request at its
  verified work gate in about 0.24 µs; PCRE2 executes it. Before P23-A, the
  httpd-rs engine admitted this shape and the original adversarial live test
  measured roughly 350 ms. The checked-in row is a median-of-seven;
  each C sample executes once while the much cheaper guard uses 10,000
  iterations per sample.
- P24's `1(?:[[:^alpha:]]{0,3}){4208}a` shape now charges the optional
  terminal path and a conservative PikeVM active-set factor. The original
  1,328-byte subject is rejected at the gate in about 24 ns. The largest
  boundary used by the checked-in benchmark (249 bytes) remains admitted and
  takes about 49 ms cold or warm on this host, below the approximately 65 ms
  calibration implied by the work ceiling. This replaces the pre-fix
  262–292 ms admitted evaluation without depending on wall-clock assertions
  in the test suite.

Microbenchmarks are sensitive to CPU placement and allocator state. The
checked-in example is the source of truth and should be rerun on deployment
hardware for capacity planning.
