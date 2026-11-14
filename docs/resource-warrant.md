# Request resource warrant

The resource warrant combines two kinds of evidence that answer different
questions:

- `tests/resource_warrant.py` conservatively inventories resource-effect sinks
  in every production Rust source file and the vendored h2 fork, including
  branches that no benchmark reaches.
- `tests/resource_profile.py` records the physical resources actually consumed
  while deployment cases, benchmarks, conformance tests, fuzz reproducers or
  another local workload exercise `httpd-rs`.

Neither one substitutes for a bound. Their union defines the accounting and
proof worklist. Every request-reachable variable-cost effect must ultimately be
mapped to a typed lease, proved to have a constant hard bound, or retained as a
pinned external assumption with an independent runtime backstop.

## Static closure

`docs/resource-warrant-policy.json` is the reviewed classification policy. It
names physical resources, attacker-controlled axes, measurement sources,
accounting APIs, intended Verus targets, OS backstops, effect families and
external assumptions. `docs/resource-warrant-static.json` is generated from
that policy and the source tree:

```sh
python3 tests/resource_warrant.py
python3 tests/resource_warrant.py --write-static
```

The first command is the CI check. The second is a security-review action used
after inspecting added or removed sites. Site identities do not include line
numbers, so unrelated movement does not invalidate the inventory; changing an
effectful expression does. Test-only modules are excluded, while startup code
is retained because configuration and reload are attacker-relevant in some
deployments and because process-owned resource use still needs a bound.

The scanner recognizes allocation and collection growth, whole-stream and
incremental data growth, CPU iteration, task/process creation, filesystem and
network I/O, synchronization/queues, compression/regex/crypto work, and
unsafe/FFI/syscall boundaries. Its status labels mean:

- `accounting-boundary`: the effect expression itself names an accounting API.
- `accounted-context`: its containing function has a relevant accounting
  marker; the eventual refinement must still prove that acquisition dominates
  the effect and that the charge is sufficient.
- `audited-gateway`: the effect is inside the centralized resource, OS or
  process gateway.
- `external-source-inventory`: vendored source is visible to the scan but its
  adapter contract and independent backstop remain explicit assumptions.
- `local-bound-candidate`: checked/saturating arithmetic or an obvious maximum
  appears at the site and still needs review.
- `review-required`: no local accounting evidence was inferred.

These labels are triage, not proofs. In particular, `accounted-context` does
not establish dominance, release on cancellation, or a correct cost formula.

Every site also has one independent closure disposition:

- `typed-lease`: the site is owned by a reviewed slot, byte, disk, transport,
  rate or physical-parent contract;
- `proved-constant-bound`: its accepted input/cardinality is closed by an
  executable checked bound and named verification target;
- `external-assumption`: the effect crosses into pinned dependency or kernel
  behavior with an explicit runtime backstop.

`closure_contracts` in the policy supply module-level evidence where a local
expression does not itself name the owning lease. CI requires exactly one
disposition for every effect and fails if `unclassified_effect_sites` is not
zero. The current closure is 2,236 typed-lease sites, 665 constant-bound sites
and 448 external/kernel sites. Classification closes discovery debt; it does
not promote a partial dominance or cost-refinement proof to mechanized status.

## Dynamic collection

The profiler wraps an existing workload and discovers only executable names
matching `httpd-rs`. It follows all descendants of a matched server so CGI and
server-created helpers remain attributed, while Apache, load generators and
independently started application backends are excluded. It samples:

- process CPU ticks, faults, context switches and optional `perf` counters or
  call stacks;
- aggregate RSS, high-water RSS, PSS, anonymous/private memory and swap;
- process and thread cardinality;
- descriptors classified as sockets, pipes, files and anonymous kernel
  objects;
- procfs read/write bytes, characters and syscall counts;
- scheduler running/waiting time plus per-thread wait channels, including
  futex/rwsem/mutex waiters;
- network-namespace ingress/egress deltas, explicitly scoped as containment
  rather than exclusive process attribution;
- statvfs byte/inode capacity and minimum free headroom for every filesystem
  visible through the process root or an open descriptor;
- cgroup-v2 CPU, I/O, PID and memory counters, including kernel, socket, slab,
  page-table and kernel-stack memory, plus configured hard limits.

Process-tree values are the attribution view. Cgroup values are a separate
containment view: when the test runner shares the server's cgroup they may
include peer processes, so the report records that scope explicitly and never
pretends those counters belong exclusively to one request or server.

Profile ordinary benchmarks without modifying them:

```sh
python3 tests/resource_profile.py run \
  --output artifacts/resource-warrant/profiles/core.json \
  --label benchmark-core -- \
  python3 bench/bench.py --quick

python3 tests/resource_profile.py run \
  --perf record \
  --output artifacts/resource-warrant/profiles/deployments.json \
  --label deployments-canonical -- \
  python3 tests/deployments/harness.py --profile canonical --benchmark
```

`--perf stat` adds hardware/software counters where kernel policy permits.
`--perf record` additionally writes one `perf.data` file per observed server
process with DWARF call stacks. Procfs collection remains available when perf
is absent or `perf_event_paranoid` prohibits attachment. Full profiling is
kept out of throughput baselines because sampling and stack unwinding perturb
the result.

To profile the standard benchmark and deployment matrix and immediately merge
the evidence:

```sh
python3 tests/resource_profile_campaign.py \
  --output artifacts/resource-warrant \
  --perf record --keep-going
```

Individual workloads may be selected with `--benchmarks`; deployments may be
`nightly`, `canonical`, `sample`, `full` or `none`. Missing workload
dependencies are reported as failures rather than silently changing coverage.
On an unprivileged developer machine without passwordless sudo,
`--allow-same-identity` forwards the deployment harness's explicit
developer-only compatibility mode; CI and release evidence must omit it so
the service-identity boundary remains exercised. That mode enables
`MutableAuthFiles` and `UnstableFastCgiPaths` and omits exact stable-path
declarations because an operator and daemon sharing one unprivileged identity
cannot establish either invariant. Its results are functional/profile evidence,
not evidence for those two security boundaries.

## Budget calibration

The broad profiler answers which physical resources a workload exercised.
`tests/resource_budget_sweep.py` answers how those resources and the typed
ledgers move as one attacker-controlled axis grows. It drives a live release
server through static output, request headers, known-length and chunked proxy
uploads, access-file depth, regex subject length, overlapping proxy requests,
cache population, bcrypt authentication, TLS/HTTP/2, and every representative
request-time Brotli quality:

```sh
cargo build --release -p httpd-rs
python3 tests/resource_budget_sweep.py --quick
python3 tests/resource_budget_sweep.py --no-quick \
  --output artifacts/resource-warrant/budget-calibration.json
```

Each point snapshots process CPU/RSS/private memory/thread/descriptor use and
the extended resource ledger before and after the workload. `server-status`
exports current use, monotonic high-water, the smallest observed hard limit,
admission rejections and a shadow candidate for every slot, byte and physical
parent. Writable-disk and transport parents expose the same information.

Shadow candidates are deliberately reporting-only. The executable Verus
function `resource_shadow_budget_candidate` proves that a candidate is never
below its observation and never above its enforced hard ceiling. A candidate
uses the larger of one additional observed peak or a resource-specific fixed
reserve, then clamps to the hard ceiling. It may support a reviewed tightening
after representative deployment and adversarial runs; one machine or workload
can never automatically weaken a security limit.

The JSON and Markdown reports separately enumerate ledgers exercised by the
live protocol sweep and by deterministic state-machine calibration. The latter
acquires RewriteMap, slow-input, slow-output, slow resident/spool and WebSocket
ownership, checks current/high-water telemetry, drops every lease and requires
all current counters to return to zero. A live absence is never converted into
evidence that the resource does not exist.

The campaign runner executes this targeted sweep by default after its broader
profiles. `--no-budget-sweep` is available when only inventory evidence is
needed. The first calibration caught a data-shape-dependent Brotli workspace
underestimate that ordinary benchmark input did not expose, which is why both
high-entropy and highly compressible maximum-size inputs remain regression
cases for every runtime-admissible quality.

## Async lifetime closure

Request cancellation and resource release are deliberately separate events.
Before request-controlled work enters a blocking pool or DNS queue it acquires
a move-only `AsyncWorkLease` under process, canonical-client, and request
ceilings. The child owns that lease and a clone of the shared cancellation
lineage. Dropping an awaiter therefore requests cancellation but cannot make a
queued or running child disappear from accounting; the slot releases only when
the child exits. Admission samples cancellation on both sides of slot
acquisition, rejecting a handoff which races with cancellation.

This boundary covers HTTP/1 backend/dispatch jobs, HTTP/2 policy/backend jobs,
proxy forward DNS, and `Require host` reverse DNS. Blocking response-body reads
already use the narrower `ResponseBodyReadLease` and transfer output ownership
into the read closure. Connection tasks and H2 stream tasks similarly move
their pending/connection/stream ownership into the spawned future. The Verus
predicate `async_work_handoff_admit` proves the admission race, while detach,
queue-cancellation, exact-ceiling, and terminal-zero regressions exercise the
Rust ownership half.

## Filesystem and blocking-I/O closure

Request-time filesystem and dependency calls have a distinct move-only
`BlockingIoLease` with 48-process, 8-canonical-client and 1-request ceilings.
It charges the task and conservative resident-memory physical parents before
the call starts. The process ceiling is below the fixed 64-thread connection
pool, so filesystem stalls cannot consume that entire scheduling class.

The synchronous gateway is re-entrant and request-lineage aware. The local
filesystem phase acquires one outer `FilesystemPhaseLease`; secure path walks,
metadata calls, descriptor-link reads and bounded file reads reuse that owner
instead of double charging. URL-space authentication, expression and rewrite
file probes acquire the same guard before they reach local dispatch, and body
spool open/write operations acquire it independently. A nested call must carry
the exact same budget and request scope. Each entry samples cancellation, so
new I/O is rejected after request cancellation while an admitted in-flight
call remains charged until its guard drops.

HTTP/2 body spool writes use `block_in_place` on the production multi-thread
runtime, preventing regular-file writes from parking a Tokio scheduler worker.
HTTP/1 is already isolated in the fixed connection work pool. Response-body
reads, dynamic backends, DNS, CGI/FastCGI, RewriteMap helpers and log writers
retain their narrower existing leases, queues, deadlines or nonblocking gates;
the general blocking-I/O slot is the fallback ownership boundary rather than a
replacement for those more precise contracts.

## Dependency-call closure

The Cargo manifests form the discovery root: every one of the 23 direct
dependencies has exactly one resource-review class, and manifest drift fails
CI. Exact namespace counts then make additions to variable-cost families a
review event even in a file which already imports that dependency. Nine
source-backed boundary contracts cover the request/backend-influenced bcrypt,
compression, regex, TLS, H2 and OCSP/webpki entry points.

`dependency_call_admit` binds input bytes, abstract work and dependency-owned
workspace to the surrounding live owner in one predicate. Specialized owners
remain authoritative: bcrypt and compression keep their weighted leases,
TLS/H2/proxy calls retain their concurrency/transport owners and deadlines,
and OCSP validation retains its complete response bound. The dependency gate
prevents a call from documenting only its CPU cost while silently omitting
workspace.

The inbound TLS boundary no longer supplies one fixed self-asserted workspace
constant. `tls_dependency_budget` selects a proved ordinary/mTLS profile;
weighted CPU and typed dependency-workspace leases are acquired together
before rustls and released after the handshake. Rustls's 65,535-byte reassembly
limit is dependency-derived, while a local verifier wrapper enforces eight
presented certificates before webpki. The remaining 1/16-unit CPU and 128/256
KiB workspace envelopes come from the retained adversarial calibration across
chain ambiguity, name constraints and P-256, P-384, Ed25519 and RSA signatures
through webpki's 8192-bit maximum. Dependency
upgrades must rerun that matrix.

The first application found regex tier construction occurring on the second
request rather than at configuration compilation. Both tiers now compile at
the declared boundary. Access-file parsing reserves a typed dependency-byte
lease for the conservative aggregate automata/cache workspace before any
pattern is compiled. The lease has 256 MiB process, 64 MiB client and 32 MiB
request ceilings, consumes the resident-memory parent, shrinks to the retained
charge and is included in the 32 MiB cache weight, closing the
many-small-pattern multiplier.

The executable Verus predicate `blocking_io_start_admit` models the
before/acquire/after cancellation race. Unit tests cover exact per-request
saturation, nested reuse, cross-context rejection, cancellation and terminal
zero; the resource-transition fuzzer mutates blocking owners alongside every
other lease class. The live budget sweep must observe the new ledger and all
current counts must return to zero.

## Reconciliation

Existing profiles can be merged without rerunning their workloads:

```sh
python3 tests/resource_warrant.py --report \
  --profile 'artifacts/resource-warrant/profiles/*.json' \
  --output artifacts/resource-warrant/request-resource-warrant.json
```

The JSON report contains the complete live static inventory and machine-
readable dynamic measurements. The adjacent Markdown report summarizes effect
families, observed physical resources and the highest-priority unclassified
sites. A resource observed dynamically but absent from the reviewed policy is
an error. A statically present but dynamically unobserved site remains visible;
it is never declared unreachable merely because typical traffic missed it.

The intended proof progression for each site is:

1. identify the attacker-controlled cardinality, size, quality or lifetime;
2. give it a conservative cost function and request/client/process scope;
3. acquire a move-only typed lease before the effect;
4. prove acquisition dominates the effect and every terminal path releases it;
5. prove the charge dominates the runtime cost function;
6. retain a deployment-level cgroup/RLIMIT/filesystem backstop for assumptions
   below Rust or inside pinned dependencies.

The `request_resource_effect_closure` verification obligation tracks this
progress. Discovery closure requires zero unclassified sites and is now a CI
invariant. Full proof closure additionally requires each typed-lease contract
to prove dominance/release, each constant-bound contract to prove its complete
cost formula, every external assumption to retain its independent backstop,
and the composed request lifecycle to return all leases to zero.
