# Pass 29 — recursive ancestor plan aborts the process; quadratic 404 prefix walk burns a core

- **Date:** 2026-11-02
- **Subject:** HEAD `de8853b` (`target/release/vapached`; no product source was
  edited).
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` (`mime`, `dir`, `alias`,
  `rewrite`, `authz_core`, `authz_host`), loopback only.
- **Harness:** `adversarial/p29/exploit_p29.py` — 5 differential verdicts in
  two groups (stack-overflow abort, prefix-walk CPU amplification).
- **Retained evidence:** `/tmp/opencode/p29-harness/` (fixtures, configs and
  per-server logs, kept with `--keep`), `/tmp/opencode/p29/gdb3.log` (gdb
  backtrace of the exact P29-A shape), `/tmp/opencode/p29/gdb2.log` (the
  no-access-file variant), `/tmp/opencode/p29/probe_*.py`,
  `/tmp/opencode/p29/saturate*.py` (lab calibration).
- **Method:** call-graph audit from the request path into the verified
  planning kernels, then live Apache-versus-vapached differentials on the
  project's own conformance and static benchmark configuration shapes.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | vapache HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P29-A** | An attacker-written `.htaccess` `RewriteRule ^(.*)$ /x/$1…$1 [L]` (80 repeats, ~200 bytes) expands a **518-byte request** into a ~40 KiB internal target with **~20,000 path components**. The rewritten target is not under the `AllowOverride` directory, so the access-file component/ancestor caps never fire. Dispatch calls `policy_ref::effective_scope_with_layers_and_file_name`, which hands the whole ancestor vector to the recursive verified kernel `access_walk_plan_exec_from`; 18,042 frames exhaust the 2 MiB blocking-pool stack and `panic = "abort"` kills the whole process (`thread 'vapache-io' has overflowed its stack`, `fatal runtime error: stack overflow, aborting`, `SIGABRT`). `LimitRequestLine` stays at the default 8190. | `500` in 1 ms, alive | `SIGABRT` after 310 ms, no response | remote one-request whole-process denial of service |
| **P29-A′** | The same kernel is reachable with **no access file at all**: on the default static configuration a single request whose URL has ≥ ~18,500 components (a ~37 KiB path) reaches the same recursion. That only needs `LimitRequestLine ≥ ~38 KiB` (a documented, commonly raised compatibility knob; the default 8190 caps the path at ~4,000 components). | `403` in < 1 ms, alive | `SIGABRT`, no response | remote one-request whole-process denial of service |
| **P29-B** | `cgi::find_script_checked` runs on **every** `Target::NotFound` (and from the cache scope) even when no CGI/PATH_INFO handler exists, rebuilding a growing `PathBuf` for every prefix of the request path. One maximum-length 404 (8,175-byte request line, 4,080 components) burns **39–45 ms of CPU**; 16 connections from one address consume **7.7 of 8 cores** at ~190 rps and raise a control GET to ~9 ms. | `0.15 ms/req`; 53,359 reqs in 5 s using 1.3 cores; control 1.9 ms | `39 ms/req`; 981 reqs in 5 s using 7.7 cores; control 9.2 ms | remote CPU exhaustion (≈260× CPU per request) |

Both are remote, unauthenticated and need no request body, no upload
execution and no symlink. P29-A is reachable on the project's own
access-file benchmark shape (`VapacheCapability AccessFiles On` plus
`AllowOverride FileInfo`/`All`, the `tests/conformance.py` /
`bench/feature_bench.py` tree). P29-B is reachable on the plain static
`bench/bench.py` shape (`AllowOverride None`, no capabilities).

---

## 2. Root cause

### 2.1 P29-A — the verified ancestor-plan kernel is recursive per component

The live scope evaluator builds one `AccessStep` plan from a vector with one
entry per ancestor directory and no length bound
(`crates/server/src/policy_ref.rs`, `effective_scope_with_layers_and_file_name`):

```rust
let mut dirs = Vec::new();
let mut cur = Some(start);
while let Some(d) = cur {                       // walks to the filesystem root
    dirs.push(d.to_path_buf());
    let Some(parent) = d.parent() else { break };
    cur = Some(parent);
}
...
let mut present = Vec::with_capacity(dirs.len());
...
for step in crate::verified::access_plan_exec(&present) {   // policy_ref.rs:143
```

`access_plan_exec` calls the recursion (`crates/verified/src/lib.rs:8156`):

```rust
pub fn access_walk_plan_exec_from(present: &[bool], start: usize) -> Vec<AccessStep> {
    if start >= present.len() {
        Vec::new()
    } else {
        ...
        let mut rest = access_walk_plan_exec_from(present, start + 1);  // one frame/component
        out.append(&mut rest);
        out
    }
}
```

Verus proves termination with `decreases present.len() - start`, but neither
the proof nor the runtime carries a **stack-depth** bound. Each frame costs
on the order of 100 bytes of stack (the backtrace shows `Vec<AccessStep>` and
`RawVec` growth), so ~18,000 components exhaust the 2 MiB stack that Tokio
gives the blocking connection task (`spawn_blocking`,
`server.rs:683`). `panic = "abort"` (`Cargo.toml:20`) turns the guard-page
hit into whole-process death.

**Why the P28 fix does not cover this.** P28-A closed rewrite amplification
with a **byte** cap: every rewritten path/query is capped at 64 KiB
(`MAX_REWRITE_OUTPUT_BYTES = 64 * 1024`, `bounded_expansion_append_admit`).
A path of 20,000 one-byte components is only ~40 KiB, and the rewrite rule
that builds it is ~200 bytes, so the cap admits it and the dispatcher
evaluates the rewritten target. The access-file caps from the same hardening
round (`MAX_ACCESS_PATH_COMPONENTS = 256`,
`MAX_ACCESS_ANCESTOR_BYTES = 512 KiB` in `htaccess.rs`) do not fire either,
because the rewritten target lives outside every `AllowOverride` directory:
`RequestPlan::from_request` skips the access-layer walk for a
non-applicable path, and the deferred walk that would have called
`ancestor_dirs()` is never entered. Dispatch then reaches
`RequestPlan::evaluate_scope` → `policy_ref` — the one ancestor walk that has
no cap and no budget.

The gdb backtrace of the exact exploit (retained as
`/tmp/opencode/p29/gdb3.log`) shows 18,042 recursive frames and the caller
chain:

```text
access_walk_plan_exec_from × 18,042          (#0..#18044)
vapache_verified::access_plan_exec           (#18045)
vapached::policy_ref::effective_scope_with_layers_and_file_name   (#18046)
vapached::policy_ref::effective_scope_with_layers                (#18047)
<vapached::config::Config>::effective_scope_req_cached            (#18048)
<vapached::request_plan::RequestPlan>::evaluate_scope             (#18049)
vapached::server::dispatch_inner                                  (#18050)
```

### 2.2 P29-A′ — the same kernel on a stock static configuration

Without any access file, `policy_ref` still walks `fs_path` to the root. With
`LimitRequestLine` raised above ~38 KiB, one request with an 18,500-component
path hits the same recursion. The crash threshold was bisected with
`LimitRequestLine 65536`: 32,002-byte path alive, 40,002-byte path `SIGABRT`,
then 36,002 alive / 38,002 dead. The default 8190 limit keeps the URL short
enough that this shape alone does not abort, but the CPU burn of P29-B still
applies at the default.

### 2.3 P29-B — quadratic prefix rebuild on every 404

`cgi::find_script_checked` (`crates/server/src/cgi.rs:74`) is the PATH_INFO
script search:

```rust
let comps: Vec<&OsStr> = rel.iter().collect();
for n in (1..=comps.len()).rev() {          // one iteration per component
    let mut prefix = PathBuf::new();
    for c in &comps[..n] {                  // re-copies the whole path
        prefix.push(c);
    }
    if let Target::File { .. } = resolve_target_checked(root, &prefix, ...) { ... }
}
```

It is called for every missing target (`server.rs:4102`) and for every
cache-scope request (`cache.rs:627`) **without asking whether any configured
handler could ever be a CGI or PATH_INFO target**. Each iteration builds the
prefix with `PathBuf::push` (O(n)) and `openat2` copies the whole path string
again in the kernel, so a request with n components costs O(n²) time and
O(n²) bytes copied. A maximum-length 8,175-byte request (4,080 components)
measures 39–45 ms of CPU; Apache answers the identical `404` in 0.15 ms. The
shape needs only a missing path — no upload, no `.htaccess`, no CGI
configuration.

The same call is why an existing deep directory tree is worse: when the
terminal component is missing but every prefix is an existing directory,
each iteration additionally walks the full prefix in the kernel (measured
67 ms for 1,800 existing directories at a 3.6 KiB URL).

---

## 3. Live evidence

`python3 adversarial/p29/exploit_p29.py --keep` (5/5 verdicts passed):

```text
PASS  A1 vapache stack-overflow abort: request_line=558B k=250 rc=-6 status=<no response> in 310 ms;
      log: thread 'vapache-io' (47941) has overflowed its stack | fatal runtime error: stack overflow, aborting
PASS  A2 Apache oracle: apache HTTP/1.1 500 Internal Server Error in 1 ms alive=True
PASS  A3 rewrite-removal control: vapache HTTP/1.1 404 Not Found in 6 ms alive=True
PASS  B1 single-request CPU amplification: request_line=8215B: vapache 39.1 ms/req (25 rps),
      apache 0.15 ms/req (4878 rps)
PASS  B2 16-connection saturation: vapache 981 reqs in 5.1s cpu=39.2s (7.7 cores) control=9.2 ms HTTP/1.1 200 OK;
      apache 53359 reqs cpu=6.5s (1.3 cores) control=1.9 ms HTTP/1.1 200 OK
```

### 3.1 P29-A (access-file route, default `LimitRequestLine`)

Fixture (`/tmp/opencode/p29-harness/htdocs/rw/.htaccess`; the `$1` token is
written 80 times on the rule's logical line):

```apache
RewriteEngine On
RewriteRule ^(.*)$ /x/$1$1$1…$1 [L]
```

Request (518 bytes, `GET /rw/` + `a/`×250 + `a`):

```http
GET /rw/a/a/…/a HTTP/1.1
Host: localhost
Connection: close
```

- vapache: no response; after ~310 ms the process aborts. Kept log:
  `thread 'vapache-io' (47941) has overflowed its stack` /
  `fatal runtime error: stack overflow, aborting`; `rc=-6`.
- Rewritten target: `/x/` + 80 × 501-byte subject ≈ 40,083 bytes, ≈ 20,080
  components — inside the P28 64 KiB byte cap, far outside any stack bound.
- Apache: `500 Internal Server Error` in 1 ms (`mod_rewrite` logs the
  over-long URI), process alive.
- Control: with the access file removed, the same request is `404` in 6 ms
  on vapache and the process stays up.

The gdb replay of this exact request (`/tmp/opencode/p29/gdb3.log`) captures
the signal with **18,042 `access_walk_plan_exec_from` frames** and the caller
chain in §2.1.

### 3.2 P29-A′ (static route, raised `LimitRequestLine`)

Config: `/tmp/opencode/p29/httpd-big.conf` (the `bench.py` static shape plus
`LimitRequestLine 65536`). One request:

```
GET /a/a/…/a HTTP/1.1
```

Threshold bisection on this shape:

```text
components  path bytes  result
16,500      33,002      404, alive
18,000      36,002      404, alive
19,000      38,002      SIGABRT: thread 'vapache-io' has overflowed its stack
20,000      40,002      SIGABRT
32,000      64,002      SIGABRT
```

The same backtrace (`/tmp/opencode/p29/gdb2.log`) shows the identical
18,042-frame recursion from `policy_ref` with no access file involved.

### 3.3 P29-B (stock static configuration)

Config: the `bench/bench.py` shape (`DocumentRoot`, `AllowOverride None`,
`Options FollowSymLinks`, `Require all granted`, default 8190 request line).
Request: `GET /a/a/…/a/b` (8,175-byte request line, 4,080 components,
`404`).

- Single stream: 200 requests for vapache cost 39.1 ms/req (25 rps);
  Apache 0.15 ms/req (4,878 rps) — ≈260× more CPU per request.
- 16 simultaneous connections from 127.0.0.1 for 5 s: vapache serves 981
  requests and consumes 39.2 s of CPU (**7.7 of 8 cores**) while a control
  `GET /index.html` rises to 9.2 ms; Apache serves 53,359 requests using
  1.3 cores with the control at 1.9 ms.
- A calibrated profile (`perf`) attributes 45% of self time to
  `find_script_checked` and another ~16% to the `openat2` path copies it
  issues.

---

## 4. Reachability and threat model

- **Precondition for P29-A:** one attacker-written `.htaccess` in a writable
  directory of a tree that enables access files (`VapacheCapability
  AccessFiles On`) with a category that admits `RewriteEngine`/`RewriteRule`
  (`FileInfo` or `All`) — exactly the conformance/feature-benchmark shape
  (`www/htaccess` `AllowOverride All`, `www/htaccess/cat-fileinfo`
  `AllowOverride FileInfo`). The `.htaccess` is ~200 bytes; the request is
  518 bytes; no further primitive is needed. The rewritten target itself
  must be outside every `AllowOverride` directory (any path that does not
  start with the override prefix works, e.g. `/x/…`).
- **Precondition for P29-A′:** the default static configuration plus any
  `LimitRequestLine` of at least ~38 KiB (e.g. 65536). No access file, no
  other directive.
- **Precondition for P29-B:** none beyond serving files; the request only
  has to miss. Any static deployment, including `bench/bench.py`, is
  affected. One client address is enough: the per-client worker limit (32)
  is never reached by 16 connections because each request ends in ~40 ms.
- **Blast radius:** P29-A/P29-A′ abort the entire process (all listeners,
  all vhosts) with a single unauthenticated request. P29-B degrades the
  whole server to ~190 rps from one address and can keep it saturated with a
  ~3 Mbit/s request stream; CPU pressure also starves compression, regex,
  auth and the HTTP/2 adapter through the shared expensive-work gate.
- **Apache:** every identical request is answered in about a millisecond
  (`404`/`403`/`500`) with a flat CPU profile, and the process never grows a
  recursion of this shape.

---

## 5. Impact

- **P29-A / P29-A′:** remote, unauthenticated availability loss; the
  process cannot be recovered without a supervisor restart. This is the
  same "one request kills the server" class as P28-C, reached through the
  verified planning kernel rather than the access-file parser. It is novel
  relative to P28 because the P28 remediation bounded rewritten URL
  **bytes** while leaving the **component count** (the actual recursion
  input) unbounded, and because the access-file caps that do bound the
  component count are only consulted for access-file-applicable targets.
- **P29-B:** remote, unauthenticated CPU exhaustion at default
  configuration; ~260× more CPU per request than Apache for the same
  response. Distinct from P27 (glob) and P28 (expansion): the work is the
  PATH_INFO script search, which runs before any handler is known to exist
  and is not charged to any request budget.
- Both are absent from the current resource-bounds evidence:
  `resource_bounds` covers regex work, glob rectangles, chunks, H2 and
  compression, and the access-file caps cover the access walk — but no
  invariant bounds recursion depth for the verified plan kernels or the
  number of components in an internal target, and no budget covers
  `find_script_checked`.

---

## 6. Remediation direction

1. **Make the plan kernels iterative or explicitly bounded.** Build
   `access_*_plan_from`/`access_files_plan_from` bottom-up (a plain loop in
   reverse) so no input length can consume stack, or add a component-count
   admission gate in `policy_ref` before `access_plan_exec` and reject with
   a normal error response. Register the depth bound in `resource_bounds`
   the way `access_section_depth_admit` did for nested sections (P28-C).
2. **Apply the existing access-path caps to every plan evaluation.** The
   `MAX_ACCESS_PATH_COMPONENTS`/`MAX_ACCESS_ANCESTOR_BYTES` checks live in
   the access walk; the `policy_ref` walk should share the same helper, and
   internal/rewritten targets should be admitted against a component bound
   in addition to the 64 KiB byte cap.
3. **Gate and linearize `find_script_checked`.** Compute a startup policy
   bit for "a CGI/PATH_INFO-capable handler exists" (the same
   `body_handlers_possible` style used for request bodies) and skip the
   search when it cannot select a handler. When it must run, find the
   longest prefix in one downward pass (remember the last regular file
   instead of rescanning every prefix) and charge its work to
   `RequestPolicyBudget`.
4. **Defense in depth.** Give blocking connection tasks an explicit stack
   size matched to the declared parser/plan bounds, and add a regression
   for both the access-file and raised-`LimitRequestLine` shapes plus a
   maximum-length 404 CPU budget test.

---

## 7. Reproduction

```sh
cd /root/vapache
cargo build --release -p vapached
python3 adversarial/p29/exploit_p29.py            # all 5 verdicts
python3 adversarial/p29/exploit_p29.py A          # stack-overflow abort + oracle
python3 adversarial/p29/exploit_p29.py B          # prefix-walk CPU burn + oracle
python3 adversarial/p29/exploit_p29.py --keep     # retain fixtures and logs
```

Minimal P29-A repro: `.htaccess` with
`RewriteEngine On` / `RewriteRule ^(.*)$ /x/$1$1…$1 [L]` (80 `$1`) under
`AllowOverride FileInfo` + `VapacheCapability AccessFiles On`; request
`/rw/` + `a/`×250 + `a`. vapache aborts in ~310 ms; Apache answers `500` in
~1 ms.

Minimal P29-A′ repro: static config with `LimitRequestLine 65536`; request
`/a/a/…/a` with 19,000 components. vapache aborts; Apache answers
`404`/`403` in under a millisecond.

Minimal P29-B repro: static config; request `/a/a/…/a/b` with 4,080
components. vapache burns ~40 ms of CPU and answers `404`; Apache answers
`404` in ~0.15 ms.

## 8. Retained files

- `adversarial/p29/exploit_p29.py` — the 5-verdict differential battery
  (groups A and B, Apache oracles, loopback only; fixtures under
  `/tmp/opencode/p29-harness` when `--keep` is given).
- `/tmp/opencode/p29-harness/logs/` — per-server output, including
  `vp-a.log` with the `has overflowed its stack` / `fatal runtime error`
  lines and `ap-a-error.log` with the Apache `mod_rewrite` rejection.
- `/tmp/opencode/p29/gdb3.log` — gdb capture of the access-file shape:
  18,042 `access_walk_plan_exec_from` frames and the `policy_ref` caller
  chain.
- `/tmp/opencode/p29/gdb2.log` — gdb capture of the raised-`LimitRequestLine`
  static shape (same kernel, no access file).
- `/tmp/opencode/p29/probe_scale.py`, `probe_findscript.py`, `bisect2.py`,
  `saturate.py`, `saturate_apache.py`, `rw_default_crash.py` — calibration
  probes for the CPU-per-request curve, the component threshold and the
  saturation differential.
