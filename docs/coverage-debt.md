# Production coverage debt

`tests/security_coverage.py` measures executable production lines before each
module's test module. It does not count tests, build scripts, dependencies or
proof-only Verus code. Raw profiles are paired with the exact executable build
ID, so the debt below is source that the current corpus genuinely does not
execute, not stale or mismatched instrumentation.

The 2026-11-03 full corpus covers 29,828 of 32,056 lines (93.05%); 2,228 lines
remain. `--check` preserves this floor per module and in aggregate. `--strict`
continues to require zero missed lines.

## Why lines remain uncovered

The remaining lines fall into four testability classes:

1. **Reachable input and protocol rejection paths.** Configuration has a large
   typed directive/context/value matrix. FastCGI, proxy, HTTP/1, HTTP/2, TLS and
   OCSP also contain malformed-peer and timeout combinations that the fixed
   corpus has not yet generated. These are ordinary test debt and should be
   closed with table-driven negative cases and scripted peers.
2. **Kernel, filesystem and privilege failures.** Secure path traversal,
   `sendfile`, nonblocking connect, certificate brokering, daemonization and
   privilege dropping depend on specific syscall failures or races. These need
   failpoints, namespaces or short-lived subprocesses; normal happy-path tests
   cannot reliably cause them.
3. **Asynchronous schedules.** Cancellation, socket closure, backpressure and
   stream-reset branches depend on which task wins a race. These need
   deterministic I/O adapters or state-machine/loom-style tests rather than
   timing sleeps.
4. **Defensive invariant branches.** A small number of arms are precluded by a
   preceding parser whitelist, verified transition or library state-machine
   contract. They remain counted unless the invariant is both documented and
   independently checked. Merely being difficult to trigger is not grounds
   for excluding a line.

## Current module map

| Module | Missed | Coverage | Dominant unexecuted behavior | Closure mechanism |
|---|---:|---:|---|---|
| `config` | 292 | 95.75% | Parser and directive-context combinations plus filesystem/listener errors | Generated typed negative matrix and injected I/O faults |
| `server` | 417 | 91.37% | TLS/H1 adapter failures, streaming-body cancellation, admission and drain errors | Deterministic stream adapters and phase-state tests |
| `proxy` | 239 | 88.97% | Backend timeout/malformed response/failover errors | Scripted backend and injected resolver/connect faults |
| `http` | 243 | 87.30% | Chunk/trailer read faults, short files, `sendfile` and response-write errors | Fault-injected readers, files and sockets |
| `files` | 155 | 87.82% | Metadata/permission races, administrative symlinks and resource denial | Filesystem failpoints and namespace tests |
| `h2` | 156 | 86.39% | Reset, body timeout, backpressure and response-send schedules | Controllable H2 peer and deterministic scheduling |
| `ocsp` | 135 | 83.66% | DER/crypto rejection and HTTP/cache/network failures | Generated DER cases and scripted responder |
| `resource` | 127 | 88.54% | Rollback, rehome, overflow, poisoning and concurrent admission schedules | Loom/model tests and injected ledger failures |
| `fastcgi` | 107 | 89.43% | Nonblocking Unix connect, timeout and malformed record matrices | Scripted FastCGI peer and syscall failpoints |
| `tls` | 120 | 83.43% | Privileged certificate broker lifecycle, IPC and file-read failures | Broker subprocess/failpoint tests |
| `main` | 92 | 90.19% | Daemon lifecycle, privilege/admin validation and fatal exits | CLI subprocesses plus user-namespace tests |
| `htaccess` | 70 | 96.18% | Access-file discovery, parse and filesystem error combinations | Generated layer matrix and filesystem faults |
| `cache` | 11 | 99.20% | Release-only context invariants, bounded invalidation stops and admission failures | Deterministic async tests and invariant seams |
| `cgi` | 33 | 96.77% | Worker setup/syscall and early child failure paths | Worker subprocess failpoints |
| `access` | 16 | 97.69% | DNS child-process failures, timeout and queue-saturation schedules | Resolver shim and deterministic child-process faults |
| `rewrite` | 3 | 99.73% | Redundant query-size defenses and absent-context invariant | Documented invariant checks or a release-mode context seam |
| `log` | 6 | 98.65% | Canonical-path invariants after successful parent validation | Filesystem failpoints or documented invariant checks |
| `expr` | 5 | 99.48% | Regex-engine error defenses and a whitelist-precluded transform arm | Engine fault seam or documented invariant proof |
| `compression` | 1 | 99.72% | Fail-closed absence of a request resource context | Explicit release-mode context test seam |

`auth`, `config_frontend`, `expires`, `policy_ref`, `request_plan`, `scope_policy`,
`status` and `util` are at 100%. The table is a work queue, not an exclusion
list: every row remains in the strict denominator.

## Rules for reducing the debt

- Prefer an assertion about the returned status, resource balance and
  connection state over executing a line only for the counter.
- Add a deterministic seam when a branch currently requires a race or rare
  syscall failure. Do not add sleeps to manufacture coverage.
- Keep production fail-closed checks even when their preconditions are already
  validated elsewhere. Exclude a branch only when an independent invariant or
  upstream state-machine contract makes execution impossible, and record that
  reason at the source.
- Tighten `tests/security_coverage_baseline.json` in the same change that adds
  coverage. New production lines must arrive covered or explicitly reviewed.
