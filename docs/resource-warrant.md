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
- procfs read/write bytes, characters and syscall counts.
- cgroup-v2 CPU, I/O, memory and PID counters plus the configured hard limits.

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
progress. The warrant is complete only when every `review-required` site has
been promoted to an accounting boundary, a proved hard bound, or an explicit
external assumption and the composed request lifecycle proves all leases
return to zero.
