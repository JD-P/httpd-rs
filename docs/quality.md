# Defect detection and quality gates

The repository uses several independent detectors because no one technique is
a substitute for the others. Pull-request gates are deterministic and short;
nightly and weekly workflows spend more time on state-space, protocol and
mutation coverage.

## Local tiers

The normal correctness gate is:

```sh
cargo fmt --all -- --check
cargo clippy -p httpd-rs --lib --bins --no-deps -- \
  -D clippy::correctness -D clippy::suspicious \
  -D unused_must_use -A unsafe_code
cargo test --workspace --all-targets --all-features -- --test-threads=1
cargo build --locked -p httpd-rs
python3 tests/docs.py
python3 tests/unsafe_inventory.py
python3 tests/resource_inventory.py
python3 tests/verification_status.py
python3 tests/apache_warrant.py
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

### Generated transform and secrecy campaigns

`tests/transform_differential.py` generates 147 Apache/httpd-rs comparisons
across 21 transform/sink pairs, seven authorization phases, seven URL
spellings and six terminal sinks. It targets early returns and fallback paths
through rewrites, aliases, MultiViews, DirectoryIndex, CGI/PATH_INFO,
ErrorDocument, proxying and cache planning. Failures retain the generated case
and exact replay command as JSON under `artifacts/transform-differential/`.
The comparator has one narrow security equivalence: Apache's 403 for a denied
implicit MultiViews/CGI-PATH_INFO target may be httpd-rs's 404, provided neither
response contains the selected fixture. This intentionally suppresses the
target-existence oracle and does not relax any other status comparison.

`tests/information_disclosure.py` is the complementary noninterference oracle.
One rotation has 105 cases that run httpd-rs in paired worlds differing only in
protected existence, contents/metadata, directory state or denied backend
output. The pre-adversarial gate runs all ten deterministic probe rotations:
1,050 cases and 4,190 cold-state observations cover every generated
transform/policy/state/probe intersection. Four additional stateful sequences
compare 30 attacker observations after credentialed cache exclusion and a
principal switch, a grant-to-deny reload for static and CGI/PATH_INFO targets,
and live mutation of denied autoindex metadata, for 4,220 total attacker
observations. The oracle compares HTTP version, status, reason,
ordered headers except `Date`, and body; it also rejects secret markers,
temporary filesystem paths, denied autoindex names and any contact with a
denied backend. Failures are replayable from JSON under
`artifacts/information-disclosure/`.

Pull-request CI checks deterministic generation and matrix completeness without
requiring Apache modules. The fail-closed pre-adversarial/nightly gate runs both
live campaigns against the release daemon.

Twenty-nine libFuzzer targets cover:

- HTTP request parsing and whole fragmented/pipelined connections;
- configuration physical-line refinement against an independent Apache
  continuation model, sections, full configuration compilation and
  `.htaccess` discovery/compilation;
- rewrite expressions;
- CGI, FastCGI and reverse-proxy response framing, plus WebSocket negotiation;
- raw HTTP/2 frames and structured multi-frame HTTP/2 state transitions;
- cache metadata plus stateful disk publication, corruption, quota and reload
  cleanup; TLS policy plus SNI/Host/client-identity reload transitions; OCSP
  DER; and H1/H2 RemoteIP/environment provenance;
- PCRE2 compile metadata and every public match/capture API, differentially
  checked against the pinned PCRE2 10.46 C oracle across byte, CRLF, UTF and
  UCP modes, plus production resource-limit monotonicity and cost boundaries;
- hierarchical resource leases as a state machine, including boundary
  reservation/release, source and request attribution, physical/disk/transport
  parent exhaustion, H1/H2 slow-input/output ownership transfer, mixed-ledger
  rejection and complete RAII teardown.

Each target has a seed corpus and, where useful, a protocol dictionary.
`tests/fuzz_smoke.sh` is bounded; `tests/fuzz_campaign.sh` is the scheduled,
time-based campaign. Nightly jobs restore each target's latest coverage corpus,
merge new coverage, minimize the result and cache that next generation in
addition to uploading the corpus and crash artifacts for inspection.
`tests/long_fuzz.sh` provides the corresponding resumable workstation run. Its
default full schedule touches every target once before using duplicate slots
to weight historically high-yield composed and stateful targets, while keeping
content-addressed corpora, logs and artifacts in an ignored state directory.
`--nightly latest` merges the
uploaded cumulative nightly corpora before the run, and `--import` accepts the
same artifact tree when GitHub's artifact redirect is unavailable. The runner
generates a finite semantic seed matrix and emits baseline/final JSON censuses
for all 29 targets, covering wire and grammar families, identity/reload
dimensions, request route/method pairs, multi-request transitions, policy/H2/
resource opcodes, PCRE modes/flags and continuation classes separately from
libFuzzer edge/features. The warrant validator rejects a target without a
census and an Apache-derived family without a corresponding fuzz target.
The same closure check requires Cargo, the smoke/sustained/local schedules and
the nightly matrix to name exactly the same target set.
`--strict-semantic` enforces those buckets, while
`--coverage` replays retained inputs under LLVM line/branch instrumentation.
Its continuation profile focuses on the physical/logical configuration
boundary implicated by P38-A. That finite boundary is also deterministically
enumerated across every insertion point, LF/CRLF, ordered split pair, chain,
slash run, whitespace near miss and EOF form before mutation begins.
The configuration physical-line, expression-parser and both PCRE2 targets
receive 16,384 smoke executions by default because their adversarial boundary
failures required sustained mutation to discover; the resource state machine
receives 1,024.

### Apache-derived warrant closure

`tests/apache_warrant.py` keeps Apache observation separate from httpd-rs
support policy. A checksum-pinned 2.4.69 source manifest inventories directive,
hook, provider, filter and configuration-callback registrations, runtime source
files, tests shipped in the source tarball, and the commit-pinned external
`apache-httpd-test` suite with its submodule. The reviewed policy maps relevant
source to eight state-space families, assigns independent authorities and
dimensions to all fuzz targets, and explicitly records deliberately unsupported
module families. Every unclaimed Apache item defaults outside the compatibility
surface; source discovery never generates implementation or parser support.

The policy acknowledges the exact inventory digest, so source or extractor
drift fails CI until its diff is reviewed. The weekly gate reproduces the
manifest from the official archive. A second weekly job builds that source
with GCC branch coverage, drives the Apache differential corpus, and emits a
per-family uncovered-branch queue; a family with no compiled file or covered
line/branch, or a covered-branch count below its checked-in ratchet, fails. The
pre-adversarial gate also checks that the executable Apache oracle is version
2.4.69 and that every module named by the differential harnesses is available.
See `docs/apache-warrant.md` for the dispositions and update procedure.

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
Apache differential benchmark rejects httpd-rs errors and gross throughput
regressions. A separate adversarial complexity suite bounds malformed-input
runtime.

## Unsafe and dependency boundaries

Production server code forbids `unsafe`; the only production exception is the
small `httpd-rs-os` crate. Its safe API accepts `BorrowedFd` for existing
descriptors and returns owning `File`, `OwnedFd`, `UnixStream`, or
`TcpListener` values for newly acquired descriptors. Raw descriptor numbers
remain only where an exec boundary makes an owner impossible to carry, and
they are validated before an I/O-safety type is constructed.

Every unsafe block in that crate has a unique `SAFETY[OSnnn]` contract.
`tests/unsafe_inventory.py` hashes both the contract and the complete block in
`docs/unsafe-baseline.json`; it also hashes the remaining test-only syscall
probes exactly. A changed, moved, added, or removed block therefore requires a
reviewed baseline update, rather than merely fitting below a textual budget.
The in-tree PCRE2 engine, verified kernels, server binary, and vendored h2 fork
all forbid unsafe code independently.

The process boundary has two additional runtime invariants. The privileged TLS
broker refuses to call `fork` after any thread exists, and `Command` children
use one fixed `ChildSetup` state applied by a syscall-only `pre_exec` closure.
Descriptor isolation, parent-death binding, session creation, dump policy, and
resource limits are data in that state rather than arbitrary post-fork Rust
callbacks. Unit tests exercise invalid inherited descriptors, retained
descriptor ownership, descriptor isolation, and the multithreaded-fork guard.

Nightly ASan first runs the syscall crate in isolation and then the composed
server suite; LSan uses clean-exit integration binaries to avoid intentional
process-global caches. TSan remains focused on concurrent resource admission
and regex compilation.

`cargo-deny` enforces licenses, registries and wildcard-dependency policy;
`cargo-audit` checks RustSec; Dependabot proposes Cargo and workflow updates.
`supply-chain/config.toml` is the cargo-vet review ledger. Its initial exact
versions are exemptions, not claimed audits: a dependency update must be
explicitly reviewed and added or imported before `cargo vet --locked` passes.
Weekly jobs also build a CycloneDX SBOM, check public API compatibility and
compare two isolated release-build hashes.

`tests/dependency_unsafe.py` separately records the exact syntactic unsafe,
build-script, and native-source exposure of the locked Linux production graph
in `docs/dependency-unsafe.json`. The main concentrations are generated syscall
bindings and wrappers (`linux-raw-sys`, `libc`, `rustix`), async/storage
primitives (`tokio`, `mio`, `bytes`, `hashbrown`, `smallvec`), and `ring`.
`ring` is the only runtime dependency in that graph with a material native-code
implementation; `cc` is present as its build tool. This inventory is an
update-review ratchet, while cargo-vet supplies the source-review evidence.

Production expression matching uses the in-tree, safe-Rust
`httpd-rs-pcre2` compatibility engine. It compiles the admitted regular PCRE2
subset to bounded automata, uses no recursive backtracking or executable-memory
JIT, and applies verified pattern, subject, capture and pattern-times-subject
work ceilings. The pull-request native-dependency gate rejects a production
PCRE2 dependency and inspects the binary for a dynamic `libpcre2` dependency.
The `pcre2`/`pcre2-sys` crates remain test/fuzz-only C oracles for differential
conformance and therefore remain visible in the review ledger and test SBOM.

The pinned Verus installer uses release `0.2026.10.18.7d82994`, matching the
`vstd` revision in the lockfile. `tests/verification_status.py --run-verus`
machine-checks the security kernels and rejects proof escapes or ledger drift.
