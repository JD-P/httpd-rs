# Pass 27 — adversarial break of the verified glob kernels (one-request process abort and permanent worker starvation)

- **Date:** 2026-11-01
- **Subject:** HEAD `5b5dbb7` (`target/release/vapached`; no product source was
  edited). The two preceding protocol-hardening commits (`ec79965`, `55eff45`)
  are also covered by the same root cause.
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` (+ `authz_core`,
  `authz_host`, `mime`, `dir`, `autoindex`), loopback only.
- **Harness:** `adversarial/p27/exploit_p27.py` — 12 differential verdicts in
  four groups (A kill vectors, B worker exhaustion, C header-controlled
  pattern, D growth ladder).
- **Retained evidence:** `/tmp/opencode/p27-final-run.txt` (full 12/12 run),
  `/tmp/opencode/p27-harness/` (fixtures, per-case server output, the
  `thread 'conn' has overflowed its stack` exits), `/tmp/opencode/p27-glob/`
  (calibration probes), `/tmp/opencode/p27-stack/` (first stack-overflow run).
- **Method:** source audit of the verified `fnmatch`/`glob` kernels and every
  runtime call site, then live Apache-versus-vapached differentials on the
  project's own benchmark/conformance `.htaccess` shapes.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | vapache HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P27-A** | The verified glob kernel `fnmatch_match` is verified total (`decreases pattern.len() + value.len()`) but has no depth cap and recurses once per `*` before matching any input. A `.htaccess` `<Files>` pattern of ~40,000 stars (≈40 KB, carved out of the 1 MiB `MAX_HTACCESS` budget) overflows the default 2 MiB connection-thread stack on the next request; the release profile is `panic = "abort"`, so **one unauthenticated request kills the whole server** (`thread 'conn' … has overflowed its stack / fatal runtime error: stack overflow, aborting`, `SIGABRT`). The same kill works from `IndexIgnore` and under `AllowOverride All`, `AuthConfig` and `Indexes`. | refuses the `.htaccess` line with `500 Line too long` (its own 8190-byte per-line cap), server stays alive | `SIGABRT` (`rc=-6`) on the first request | remote whole-process denial of service (single request) |
| **P27-B** | The same kernel is exponential-time: `*a*a*…*b` against `aaaa…a` explores `C(n+k, k)` recursive paths with no work budget, no `try_expensive` lease and no dispatch deadline. A 12-star pattern plus a 400-byte basename (a <500-byte request) pins a connection worker forever; the worker never returns **even after the client disconnects**, so repeated requests exhaust all `MaxRequestWorkers` permanently (fresh clients receive `503`; the process must be restarted). Under `AllowOverride AuthConfig` the pattern/value pair can be supplied per request through one-line `Require expr "%{HTTP:X-P} -strmatch %{HTTP:X-V}"`, so no large `.htaccess` payload is needed. | `403` in 0.4 ms; workers free | timeout at 2 s, CPU pinned forever; 64/64 workers wedged, fresh client `503` after every attacker socket is closed | remote worker-exhaustion denial of service (no recovery) |

Both findings are remote, unauthenticated and reachable with the access-file
configuration the project itself benchmarks and tests. Apache answers the
identical access files and requests in under a millisecond and never loses a
worker.

---

## 2. Root cause

### 2.1 The kernel proves termination, not work

`crates/verified/src/lib.rs`:

```rust
pub open spec fn fnmatch_spec(pattern: Seq<u8>, value: Seq<u8>, path_mode: bool) -> bool
    decreases pattern.len() + value.len(),
{ ... }                                            // line 10734

pub fn fnmatch_match(pattern: &[u8], value: &[u8], path_mode: bool) -> (out: bool)
    ensures out == fnmatch_spec(pattern@, value@, path_mode),
    decreases pattern.len() + value.len(),
{
    ...
    if pattern[0] == b'*' {
        if fnmatch_match(&pattern[1..], value, path_mode) { return true; }   // branch 1
        if value.len() == 0 || (path_mode && value[0] == b'/') { return false; }
        return fnmatch_match(pattern, &value[1..], path_mode);               // branch 2
    }
    ...
}
```

`expr_glob_spec` / `expr_glob_match` (`lib.rs:8427` / `8461`) are the same
algorithm for the `ap_expr` surfaces. The `decreases` clause proves the
recursion terminates, but each `*` chooses between "consume nothing" and
"consume one value byte" with no memoization, so a failing match of
`*a*a*…*b` against `a^n` costs `Θ(C(n+k, k))` recursive calls; an all-star
pattern against a value of length `m` costs `Θ(C(k+m, m))`. There is no
recursion-depth cap, no step counter and no error path for a work overrun.

The pre-existing `MAX_EXPR_DEPTH` cap (`crates/server/src/expr.rs:968`)
bounds only *parsing* of `ap_expr`; it does not bound glob evaluation, and
the glob kernels are called directly from the runtime.

### 2.2 Runtime call sites with no work budget or deadline

| Site | Code | Reachable from |
|---|---|---|
| `<Files>` glob | `config.rs:7544` `MatchKind::FilesGlob` → `fnmatch_match(pattern, fname, false)` | main config **and `.htaccess`** (`compile_files_pattern`, `config.rs:8045`) |
| `<Location>` glob | `config.rs:7562` `MatchKind::LocationGlob` | main config |
| `<Directory>` wildcard | `config.rs:7530` → `wildcard_path_matches` (`config.rs:7476`) → `glob_match` | main config |
| `<Proxy>` wildcard | `config.rs:14583` `glob_match(pattern, proxy_url)` | main config |
| `IndexIgnore` | `files.rs:1323` → `config::glob_match` (`config.rs:3736`) | main config **and `.htaccess`** (`Indexes`) |
| `-strmatch` / `-fnmatch` | `expr.rs:873` `Expr::StrMatch` → `glob` (`expr.rs:643`) | `<If>`, `Require expr`, `RewriteCond expr` in main config **and `.htaccess`** |

`rule_kind_matches` is invoked for every scope rule on every request
(`apply_normal_rule_list` / `apply_deferred_req`, `config.rs:7625`, `7692`,
`7732`, `7764`), again for the resolved-target and lexical-handler
identities, and once per directory entry for autoindex. The autoindex path
takes a `try_expensive()` lease (`files.rs:1296`), but that only limits
concurrency to the 32-slot process-wide expensive-work budget; it does not
bound the work of a single match. The `<Files>`/expression paths take no
lease at all.

`.htaccess` files are limited to `MAX_HTACCESS = 1 MiB` (`htaccess.rs:23`)
but a `<Files>` pattern has no separate length cap, so a pattern of tens of
thousands of stars is accepted and cached. Connection workers are
`std::thread::Builder::new().name("conn".into()).spawn(work)`
(`server.rs:459-465`) with the default 2 MiB stack, and the release profile
sets `panic = "abort"` (`Cargo.toml:20`): stack exhaustion is not a caught
panic, it is a whole-process abort.

### 2.3 Why the request never times out

`read_request`'s header/body deadlines cover only reading; `handle_connection`
runs dispatch synchronously before `write_response` computes its absolute
write deadline (P26-B). Nothing polls the client socket while the matcher
runs, so a mid-match client disconnect is invisible. The only way to release
a wedged worker is process termination.

### 2.4 Why the Verus ledger did not catch it

`docs/verification-status.json` obligation `resource_bounds` lists bounded
request/proxy trailers, chunk framing, proxy chunk accounting, CGI/FastCGI
caps, HTTP/2 budgets, regex compile/capture/pattern×subject work, and
compression — but no glob/`fnmatch` work or depth bound.
`require_eval_sound` counts `expr_glob_match` as a verified kernel for
*semantics* ("expression integer/string comparison and glob matching run
through verified kernels"), which is accurate but is exactly how the
unbounded-work gap stayed invisible: the kernel is proved correct, and
nothing proves it cheap. The P23 work bound
(`regex_match_resource_admit`, `expr_regex_size_admit`) has no counterpart
for the glob family.

---

## 3. Live evidence

`python3 adversarial/p27/exploit_p27.py --keep` (full 12/12 run,
`/tmp/opencode/p27-final-run.txt`):

```text
PASS  A1 <Files> AllowOverride All: vapache died rc=-6; stack-overflow abort=True; apache HTTP/1.1 500 Internal Server Error alive=True
PASS  A2 <Files> AllowOverride AuthConfig: vapache died rc=-6; stack-overflow abort=True; apache HTTP/1.1 500 Internal Server Error alive=True
PASS  A3 IndexIgnore AllowOverride Indexes: vapache died rc=-6; stack-overflow abort=True; apache HTTP/1.1 500 Internal Server Error alive=True
PASS  B1 benign control: vapache HTTP/1.1 200 OK in 0.5 ms
PASS  B2 exponential wedge: vapache TIMEOUT in 2002.1 ms for *{a*}12b vs 400 a's
PASS  B3 Apache oracle: apache HTTP/1.1 403 Forbidden in 0.4 ms
PASS  B4 all workers exhausted: fresh client HTTP/1.1 503 Service Unavailable in 5.9 ms; threads 3->66; CPU 16.03s in 2.0s
PASS  B5 no recovery after client close: fresh client HTTP/1.1 503 Service Unavailable in 8.0 ms; threads still 66
PASS  C1 access-file control: vapache HTTP/1.1 200 OK in 0.3 ms
PASS  C2 header pattern wedges: vapache TIMEOUT in 2004.4 ms for 8001-byte X-V vs 8000-byte X-P
PASS  C3 Apache oracle: apache HTTP/1.1 403 Forbidden in 0.6 ms alive=True
PASS  D1 growth ladder: stars=2 vapache=404 0.4ms apache=404 0.4ms; stars=4 vapache=404 6.2ms apache=404 0.2ms;
      stars=6 vapache=404 118.7ms apache=404 0.3ms; stars=8 vapache=404 1653.3ms apache=404 0.3ms
```

### 3.1 P27-A — one request aborts the process

`vp-a.log` tail for each vector (identical for all three):

```text
thread 'conn' (28091) has overflowed its stack
fatal runtime error: stack overflow, aborting
```

The waitpid status is `rc=-6` (`SIGABRT`); a client sees an empty response.
Apache refuses the identical 40 KB `<Files>` line itself
(`.htaccess: Error reading … at line 1: Line too long`, Apache's 8190-byte
per-line cap) and returns `500` while staying alive. vapache has no
per-line or pattern-length cap: the whole 1 MiB `MAX_HTACCESS` budget is
available for one glob pattern.

Calibration (`/tmp/opencode/p27-glob/calibrate.py`): a 40,043-byte file with
40,000 stars aborts; a 20,043-byte file with 20,000 stars already wedges
(P27-B). The exact crash threshold is stack/frame-size dependent; 40 KB is
comfortably over it on the default 2 MiB stack.

### 3.2 P27-B — permanent worker starvation

The 12-star pattern (`*a*a*a*a*a*a*a*a*a*a*a*a*b`) against a 400-byte
basename needs `C(412, 12) ≈ 10^25` recursive calls. Even a 2,000-star
pattern against a 10-byte filename (`C(2010, 10) ≈ 2·10^23`) never returns.
Group B fills all 64 workers from two source addresses (`MaxRequestWorkers
64`, per-client cap 32): the process consumes 16.03 CPU-seconds in 2.0 wall
seconds (all 8 test-host cores), a fresh client receives `503 Server busy`,
and **2.5 seconds after every attacker socket is closed the worker threads
are still pinned and the fresh client still receives `503`**. Only killing
the process recovers service.

### 3.3 P27-C — the pattern can arrive in request headers

With `AllowOverride AuthConfig` (the project's `www/htaccess/cat-auth`
shape), the one-line access file

```apache
Require expr "%{HTTP:X-P} -strmatch %{HTTP:X-V}"
```

is evaluated per request. Sending `X-V: *a*a*…*b` (8,001 bytes) and
`X-P: a…a` (8,000 bytes) wedges the worker (timeout at 2 s; Apache returns
`403` in 0.6 ms and stays alive). No large `.htaccess` is needed for P27-B;
only the P27-A kill needs the long star run.

### 3.4 Growth is exponential, not linear

Group D holds the value fixed at 40 `a`s and adds `*a` pairs: 0.4 ms →
6.2 ms → 118.7 ms → 1653.3 ms (≈14-19× per star pair, i.e. exponential in
the star count) while Apache stays at 0.2-0.4 ms on the identical file.

---

## 4. Reachability and threat model

- **Precondition:** the attacker can place or modify a `.htaccess` in a
  writable directory of a tree whose configuration enables access files
  (`VapacheCapability AccessFiles On`) and grants the relevant override
  category: `AllowOverride All` or `AuthConfig` for `<Files>`/`Require expr`,
  `Indexes` for `IndexIgnore`. This is exactly the P15-P18 upload-directory
  threat model and the project's own conformance/benchmark shape
  (`tests/conformance.py`: `www/htaccess` `AllowOverride All`,
  `www/htaccess/cat-auth` `AllowOverride AuthConfig`, autoindex trees with
  `Indexes`; `bench/feature_bench.py` runs the `.htaccess` scenarios).
- **No further primitive:** the request paths used by the kill need not
  exist, no authentication is required, and the payload is plain HTTP.
- **Blast radius:** P27-A aborts the entire process with a single request;
  P27-B permanently consumes workers with no timeout and no recovery. On a
  shared host, one pinned worker per request accumulates until the server
  answers only `503`.
- **Apache:** the identical access files and requests are answered in
  <1 ms (P27-B/C `403`) or rejected with `500` while the server stays alive
  (P27-A). Apache does not expose this behavior.

---

## 5. Impact

- **P27-A:** remote, unauthenticated, single-request denial of service that
  terminates every in-flight request/response and any CGI/FastCGI/proxy
  work served by the process. Under a supervisor the process restarts and
  the attacker repeats the kill; without one, service is down.
- **P27-B:** remote, unauthenticated worker exhaustion with permanent
  effect. Unlike the P25-B stalled-download finding (bounded by the P25
  absolute write deadline), a wedged glob matcher has **no deadline and no
  client dependency**, so capacity is never returned; the operator must
  restart the service.
- Both break the project's resource-bounds invariant for attacker-influenced
  work and are absent from the CVE/strengthening tracking (the
  `resource_bounds` obligation does not mention glob matching).

---

## 6. Remediation direction

1. **Fix the algorithm.** Replace the backtracking recursion with an
   iterative single-backtrack-point matcher (classic two-pointer `*`
   handling, `O(pattern × value)` worst case) or a memoized/bitset dynamic
   program, as the regex engine already uses. This removes both the
   exponential time and the linear-in-pattern recursion depth.
2. **Bound the work regardless of algorithm.** Give `fnmatch_match` and
   `expr_glob_match` an explicit step/depth budget and fail closed (deny,
   or a 500 access-file error) when it is exceeded; charge matches to
   `try_expensive` and/or a per-request work counter. Budget alone must not
   be the only defense (32 `try_expensive` slots would still pin 32
   workers), but it removes head-of-line monopolies.
3. **Bound the pattern at parse time.** Enforce a per-line/pattern cap when
   reading `.htaccess` (Apache refuses over-long lines with
   `500 Line too long`) and a maximum glob pattern length/star run when
   compiling `<Files>`/`<Location>`/`IndexIgnore` patterns. This closes the
   P27-A shape independently (an 8 KB line cannot overflow the 2 MiB stack
   even though it can still wedge), but it does not replace the algorithm
   and work-bound fixes for P27-B.
4. **Add a dispatch deadline.** The HTTP/1 path has no CPU-time bound
   between `read_request` and `write_response`; a per-request wall-clock
   guard around scope evaluation/policy would bound any future
   non-regular kernel (defense in depth, not a substitute for 1-2).
5. **Close the verification gap.** Extend the `resource_bounds` evidence
   with a mechanized pattern×value work/depth bound for `fnmatch_spec` and
   `expr_glob_spec` (or a step-counted exec that refines the spec and fails
   closed), in the same style as the P23 regex work bound.
6. **Regression coverage.** Add differential cases for
   `<Files>`/`IndexIgnore`/`Require expr -strmatch`/`RewriteCond expr`
   with (a) exponential patterns on long values that must complete within a
   fixed work budget, (b) long star runs that must not abort the process,
   and (c) the Apache oracle verdicts recorded here.

---

## 7. Reproduction

```sh
cd /root/vapache
cargo build --release -p vapached
python3 adversarial/p27/exploit_p27.py            # all 12 verdicts
python3 adversarial/p27/exploit_p27.py A           # kill vectors only
python3 adversarial/p27/exploit_p27.py B C         # wedge / header vectors
python3 adversarial/p27/exploit_p27.py --keep      # retain fixtures + logs
```

Expected: `12/12 verdicts passed`; the A groups leave
`thread 'conn' … has overflowed its stack` + `fatal runtime error: stack
overflow, aborting` in `/tmp/opencode/p27-harness/logs/vp-a.log`, and the B
groups leave a process whose threads stay pinned after every attacker socket
is closed.

Minimal P27-A repro (fixture `/tmp/opencode/p27-stack`):

```sh
# .htaccess in an AllowOverride All directory of a VapacheCapability
# AccessFiles On server:
#   <Files "********************************...">    # 40,000 stars
#       Require all denied
#   </Files>
python3 /tmp/opencode/p27-glob/stackkill.py
# -> vapache exited after one request: True (rc=-6)
# -> thread 'conn' (25878) has overflowed its stack
#    fatal runtime error: stack overflow, aborting
# -> apache on identical access file: HTTP/1.1 500, alive
```

Minimal P27-B repro (retained harness, group D ladder + group B wedge):

```sh
python3 adversarial/p27/exploit_p27.py D
# -> stars=2 vapache 404 in 0.4 ms | apache 404 in 0.4 ms
# -> stars=4 vapache 404 in 6.2 ms | apache 404 in 0.2 ms
# -> stars=6 vapache 404 in 118.7 ms | apache 404 in 0.3 ms
# -> stars=8 vapache 404 in 1653.3 ms | apache 404 in 0.3 ms
python3 adversarial/p27/exploit_p27.py B
# -> 12-star pattern + 400-byte basename: vapache TIMEOUT (CPU pinned)
#    while apache answers 403 in 0.4 ms; 64/64 workers exhausted, no recovery
```

---

## 8. Retained files

- `adversarial/p27/exploit_p27.py` — the 12-verdict differential battery
  (groups A-D; Apache oracle included; loopback only; fixtures under
  `/tmp/opencode/p27-harness` when `--keep` is given).
- `/tmp/opencode/p27-final-run.txt` — full 12/12 output.
- `/tmp/opencode/p27-harness/` — kept fixtures and per-server logs for every
  group, including `logs/vp-a.log` with the three stack-overflow aborts and
  `logs/vp-d.log` for the growth ladder.
- `/tmp/opencode/p27-glob/` — `calibrate.py` (kill/wedge thresholds),
  `variants.py` (AuthConfig + IndexIgnore kill oracles), `stackkill.py`
  (minimal single-request abort), `exprvec.py` (early header-controlled
  pattern probe); fixtures and logs alongside.
- `/tmp/opencode/p27-stack/` — the first single-request abort fixture.
