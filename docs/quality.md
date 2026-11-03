# Defect detection and quality gates

The repository uses several independent detectors because no one technique is
a substitute for the others. Pull-request gates are deterministic and short;
nightly and weekly workflows spend more time on state-space, protocol and
mutation coverage.

## Local tiers

The normal correctness gate is:

```sh
cargo fmt --all -- --check
cargo clippy -p vapached --lib --bins --no-deps -- \
  -D clippy::correctness -D clippy::suspicious \
  -D unused_must_use -A unsafe_code
cargo test --workspace --all-targets --all-features -- --test-threads=1
python3 tests/unsafe_inventory.py
python3 tests/resource_inventory.py
python3 tests/verification_status.py
```

`tests/pre_adversarial.sh` is the fail-closed release gate. It additionally
requires Apache, PHP-FPM, a matching Verus release, nightly Rust and
`cargo-fuzz`; missing tools are failures rather than skips.

## Generative and concurrency testing

`crates/server/tests/properties.rs` runs 512 cases per property over URI
normalization, cache-key injectivity, monotone scope/capability restriction,
overflow-safe resource admission and HTTP read fragmentation. The resource
budget's production compare/exchange algorithm also runs under Loom to explore
admission/release interleavings deterministically.

`tests/resource_inventory.py` locks attacker-facing slots and adjustable byte
reservations to the request/client/process hierarchy. It also inventories
bounded process-owned caches, queues, telemetry, and lifecycle state, so a new
mutable static cannot silently become a second resource ledger.

Thirteen libFuzzer targets cover:

- HTTP request parsing and whole fragmented/pipelined connections;
- configuration sections, full configuration compilation and `.htaccess`
  discovery/compilation;
- rewrite expressions;
- CGI, FastCGI and reverse-proxy response framing;
- HTTP/2 frames, cache metadata, TLS policy and OCSP DER.

Each target has a seed corpus and, where useful, a protocol dictionary.
`tests/fuzz_smoke.sh` is bounded; `tests/fuzz_campaign.sh` is the scheduled,
time-based campaign and retains minimized corpora plus crash artifacts.

## Failure and memory models

The `fault-injection` feature exposes deterministic one-shot failures at HTTP
head/body/chunk reads, secure filesystem open, proxy connect, TLS certificate
and key reads, and CGI spawn. Integration tests sweep short-read boundaries,
retry `EINTR`, and require every other injected failure to remain fail closed.
The feature is off in production and the hook compiles to success.

`tests/chaos.sh` complements those hooks with an isolated nightly container.
It runs the release daemon with a read-only root, no external network, cgroup
memory/PID/CPU limits and a small descriptor limit; injects real `openat2(2)`
and `sendfile(2)` failures with `strace`; and kills the privileged TLS file
broker before a reload. The checks require complete response bodies, continued
server health and atomic retention of the previous TLS configuration. The
container drops all capabilities and adds back only identity switching,
fixture access/ownership, child termination, and (for the syscall scenario
only) ptrace.

Weekly Miri runs exercise pure parser and resource paths. Nightly ASan runs the
library except the intentionally forking CGI test, LSan runs standalone
property/failpoint binaries with clean process-global state, and TSan runs the
real concurrent resource-admission path with an instrumented standard library.
`cargo-careful` checks standard-library unsafe preconditions separately.

## Mutation, protocol and operational gates

`tests/mutation.sh` mutates the access, request-plan, scope, cache, HTTP,
rewrite and resource security kernels in place. The only resource exclusion is
an explicitly documented equivalent stale initial atomic read; its nonzero
counterpart remains enabled and is caught. Any surviving non-excluded mutant
fails the weekly job.

The nightly external suite enforces TLS 1.2/1.3 policy and ALPN, runs strict
h2spec, and drives concurrent valid, malformed, fragmented and pipelined
connections while checking liveness and RSS growth. The weekly same-host
Apache differential benchmark rejects vapache errors and gross throughput
regressions. A separate adversarial complexity suite bounds malformed-input
runtime.

## Unsafe and dependency boundaries

`unsafe_op_in_unsafe_fn` is denied. `tests/unsafe_inventory.py` rejects any
increase above the per-file baseline in `docs/unsafe-baseline.json`; moving or
adding an unsafe boundary therefore requires an explicit review and baseline
change.

`cargo-deny` enforces licenses, registries and wildcard-dependency policy;
`cargo-audit` checks RustSec; Dependabot proposes Cargo and workflow updates.
`supply-chain/config.toml` is the cargo-vet review ledger. Its initial exact
versions are exemptions, not claimed audits: a dependency update must be
explicitly reviewed and added or imported before `cargo vet --locked` passes.
Weekly jobs also build a CycloneDX SBOM, check public API compatibility and
compare two isolated release-build hashes.

Production expression matching uses the in-tree, safe-Rust
`vapache-pcre2` compatibility engine. It compiles the admitted regular PCRE2
subset to bounded automata, uses no recursive backtracking or executable-memory
JIT, and applies verified pattern, subject, capture and pattern-times-subject
work ceilings. The pull-request native-dependency gate rejects a production
PCRE2 dependency and inspects the binary for a dynamic `libpcre2` dependency.
The `pcre2`/`pcre2-sys` crates remain test/fuzz-only C oracles for differential
conformance and therefore remain visible in the review ledger and test SBOM.

The pinned Verus installer uses release `0.2026.10.18.7d82994`, matching the
`vstd` revision in the lockfile. `tests/verification_status.py --run-verus`
machine-checks the security kernels and rejects proof escapes or ledger drift.
