# PCRE2 compatibility-engine benchmark

Measured 2026-10-30 after the P23/P24 remediation on Linux 6.18.55, an AMD EPYC
9V74 worker (5 available cores), Rust 1.99.1. The benchmark is single-threaded,
uses release builds, reports the median of seven samples, and compares the same
`captures` API because that is what httpd-rs expressions use.

The “httpd-rs” column is the safe-Rust compatibility frontend and deterministic
automata backend guarded by the Verus-verified engine-mode and resource
admission kernels. The engine is tiered: construction creates a bounded Pike
VM, the first search uses it, and the second search builds a shared lazy-DFA
tier. Neither tier enables bounded or recursive backtracking. The automata
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
| literal anchor | compile | 3,634.1 | 511.5 | 2,498.2 | 7.104 |
| literal anchor | compile + first captures | 4,106.6 | 666.5 | 2,618.6 | 6.162 |
| literal anchor | captures | 48.4 | 114.6 | 76.6 | 0.423 |
| captures over 4 KiB | compile | 8,118.9 | 992.2 | 5,697.5 | 8.183 |
| captures over 4 KiB | compile + first captures | 207,810.8 | 5,964,188.0 | 8,028.1 | 0.035 |
| captures over 4 KiB | captures | 64.5 | 6,015,957.3 | 2,480.0 | 0.000011 |
| alternation over 4 KiB | compile | 18,312.9 | 740.5 | 5,689.0 | 24.731 |
| alternation over 4 KiB | compile + first captures | 19,302.2 | 137,004.2 | 5,859.4 | 0.141 |
| alternation over 4 KiB | captures | 301.8 | 132,475.0 | 228.1 | 0.002278 |
| byte/POSIX class | compile | 7,517.4 | 686.5 | 3,483.5 | 10.951 |
| byte/POSIX class | compile + first captures | 9,079.3 | 977.9 | 3,789.0 | 9.284 |
| byte/POSIX class | captures | 82.2 | 181.9 | 83.5 | 0.452 |
| `\Q…\E\Z` lowering | compile | 4,822.3 | 499.9 | 4,068.7 | 9.647 |
| `\Q…\E\Z` lowering | compile + first captures | 5,786.3 | 685.5 | 4,117.3 | 8.441 |
| `\Q…\E\Z` lowering | captures | 61.7 | 116.5 | 77.2 | 0.530 |
| `a{8000}` / 8,190 bytes | resource guard / captures | 10.6 | 4,547.0 | 2,284.0 | 0.002320 |
| P24 nested optional / 1,328 bytes | resource guard | 23.6 | — | — | — |
| P24 nested optional / admitted 249-byte boundary | compile + first captures | 49,615,790.0 | — | — | — |
| P24 nested optional / admitted 249-byte boundary | captures | 49,039,751.0 | — | — | — |

Interpretation:

- Compilation is now 7.1–24.7× the C interpreter (previously 13.9–96.0×) and
  1.2–3.2× C JIT compilation. Parsing and structural work accounting remain
  deliberate costs; lazy-DFA construction is deferred until reuse proves the
  expression hot.
- “Compile + first captures” makes that deferral visible. The first search is
  bounded Pike-VM execution, so one-shot long scans beat the C interpreter but
  can trail C JIT. The second and later searches use the shared lazy-DFA tier.
- Warm captures beat the C interpreter in every case. They also beat C JIT in
  four of five cases; the remaining alternation case is 1.32× C JIT. Inline
  capture slots and a group-zero fast path remove allocator and submatch work
  from the common no-explicit-capture case.
- The counted-repetition row is a security-policy comparison rather than a
  successful-match throughput comparison. httpd-rs rejects the request at its
  verified work gate in about 0.24 µs; PCRE2 executes it. Before P23-A, the
  httpd-rs engine admitted this shape and the original adversarial live test
  measured roughly 350 ms. The checked-in row is a warmed median-of-seven;
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
