# Pass 28 — unbounded rewrite, expression and section-nesting work aborts the process

- **Date:** 2026-11-01
- **Subject:** HEAD `5b5dbb7` (`target/release/httpd-rs`; no product source was
  edited).
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` (+ `authz_core`,
  `authz_host`, `mime`, `dir`, `rewrite`), loopback only.
- **Harness:** `adversarial/p28/exploit_p28.py` — 8 differential verdicts in
  three groups (rewrite growth, expression expansion, access-file nesting).
- **Retained evidence:** `/tmp/opencode/p28-final-run.txt` (full 8/8 run),
  `/tmp/opencode/p28-harness/` (fixtures and per-case server output, with
  `--keep`), `/tmp/opencode/p28-probes/` (calibration probes),
  `/tmp/opencode/p28-rewrite*/`, `/tmp/opencode/p28-expr/`,
  `/tmp/opencode/p28-nest/`.
- **Method:** audit of the three attacker-influenced evaluators that sit
  behind an upload directory's `.htaccess` (rewrite substitution expansion,
  `ap_expr` value construction, recursive access-file section parsing), then
  live Apache-versus-httpd-rs differentials on the project's own
  conformance/benchmark override shapes.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P28-A** | `RewriteRule ^(.*)$ $1$1…$1 [L]` is re-applied by the dispatcher to its own output for up to 10 rounds. The substitution has no length cap, so the URI grows by `k^10` per request (a 100-byte rule and a 1-byte path reach 10^10×). One request raised httpd-rs RSS to 1.07 GB in 6 s in the retained harness (3.2 GB in the longer probe) and the allocator aborts the process under a 512 MiB address-space limit (`memory allocation of 100000000 bytes failed`, `SIGABRT`). | `403` in 13.6 ms, 1.9 MB RSS, alive | multi-GB allocation, worker pinned, `SIGABRT` under a memory bound | remote one-request denial of service (rewrite amplification) |
| **P28-B** | `Require expr` value construction is unbounded: a quoted expression concatenates `%{HTTP:…}` expansions or `file()` contents with no per-request size or work budget. A 102 KB access file of `file('prot/big')` calls (64 KiB file) materializes >500 MB per request (`memory allocation of 536870912 bytes failed`, `SIGABRT` under 512 MiB); the header form needs only a 1 KB access file and an 8 KB request header to build 7.8 MB per request. | `500` in <1 ms, flat RSS, alive | hundreds of MB per request; abort under a memory bound | remote one-request denial of service (expression expansion) |
| **P28-C** | `parse_block()` recurses once per nested `.htaccess` section with no depth cap. 1,000 nested `<RequireAll>` wrappers (a 27 KB access file) overflow the default 2 MiB connection stack on the first request; `panic = "abort"` turns it into `thread 'conn' has overflowed its stack / fatal runtime error: stack overflow, aborting` (`SIGABRT`). 5,000 nested `<If>` wrappers (90 KB) behave the same. | `200` in 2-87 ms, alive | `SIGABRT` on the first request | remote one-request whole-process denial of service (parser recursion) |

All three are remote, unauthenticated and reachable from a single
attacker-written `.htaccess` in the access-file shape the project benchmarks
and tests (`HttpdRsCapability AccessFiles On` plus `AllowOverride FileInfo`
or `All` for P28-A, `AuthConfig` for P28-B, any override admitting sections
for P28-C). Apache answers the identical access files and requests in
milliseconds and never grows or dies.

---

## 2. Root cause

### 2.1 P28-A — rewrite substitution growth has no size bound

`crates/server/src/rewrite.rs` expands the substitution and rebuilds the
path for the next round:

```rust
let expanded = match expand_backrefs(&rule.substitution, ...) { ... };   // 582
...
path = new_path_from_joined(&joined);                                    // 745
changed = true;
match httpd_rs_verified::rewrite_advance(..., loops, 10) {                // 748
    RewriteAdvance::Restart { completed } => { loops = completed; idx = 0; continue; }
    RewriteAdvance::RestartLimit => return Outcome::Error("rewrite [N] loop limit exceeded".into()),
    ...
}
```

The `[N]` inner loop is capped at 10 restarts, and the dispatcher's outer
round loop is capped at 10 (`server.rs:2316`, `rewrite_rounds > 10` at
`2635-2636`), but nothing bounds the *size* of the substituted URL. A
per-directory rule such as

```apache
RewriteEngine On
RewriteRule ^(.*)$ $1$1$1$1$1 [L]
```

is re-applied to its own output each dispatcher round (the rewritten URL is
re-mapped and the same `.htaccess` layer matches again), so a path of length
`L` becomes `L × 5^10 ≈ 9.8M × L`; with ten `$1` repetitions the factor is
`10^10`. The code has no `MAX_URI`/`MAX_SUBSTITUTION` check anywhere
(`grep MAX_ rewrite.rs` finds only the RewriteMap output cap), and the
request-line limit applies only to the original request. Apache answers
`403` immediately (its internal-redirect limit fires before the URI grows)
and keeps RSS flat.

### 2.2 P28-B — expression value construction has no budget

`crates/server/src/expr.rs`:

- `expand_bytes` (`550-597`) walks every `%{…}`/`%{func:arg}` reference and
  `extend_from_slice`s the expansion into one `Vec<u8>`;
- `Expr::Concat` (`750-756`) extends one output buffer with every part;
- `file()` (`901-906`) reads up to `MAX_EXPR_FILE_BYTES = 64 KiB` per call
  and returns it as a `Value`;
- the only size gates are on **regex** operands (`expr_regex_size_admit`,
  64 KiB at `778-784`) and the server-wide `try_expensive` lease taken only
  around regex evaluation (`785`).

Nothing charges the concrete bytes produced by string expansion, function
results or concatenation to any budget. The `.htaccess` cap is 1 MiB
(`MAX_HTACCESS`), and `Require expr` accepts expressions up to that size, so

```apache
Require expr "file('prot/big').file('prot/big')...file('prot/big')"
```

with a 64 KiB attacker-uploaded `big` file turns a 100 KB access file into a
>500 MB allocation per request (plus a clone on comparison and an open/read
per call); the header form

```apache
Require expr "%{HTTP:X}.%{HTTP:X}...%{HTTP:X}"
```

turns ~12 bytes of access file plus an 8 KiB request header into the same
allocation. Apache rejects the expression at parse time with `500` and stays
flat.

### 2.3 P28-C — the access-file section parser is recursive with no depth cap

`crates/server/src/htaccess.rs` parses nested sections with `parse_block`
(`1051`), recursing at every supported wrapper (`1178`, `1241`, `1271`,
`1353`, `1384`, `1411`, `1434`, `1470`, ...). `MAX_HTACCESS = 1 MiB` bounds
the file *size* only; there is no depth parameter and no nesting check.
Each level of `<RequireAll>`/`<If>` costs one (or more) `parse_block` stack
frames of a few hundred bytes, so ~1,000 levels exhaust the default 2 MiB
connection-thread stack (`server.rs:459-465` spawns without `stack_size`).
The release profile is `panic = "abort"` (`Cargo.toml:20`), so the guard-page
hit aborts the entire process. (The main configuration parser caps
`Include` nesting at 32, `config.rs:3360`; the `.htaccess` parser has no
comparable cap.)

---

## 3. Live evidence

`python3 adversarial/p28/exploit_p28.py --keep` (full 8/8 run,
`/tmp/opencode/p28-final-run.txt`):

```text
PASS  A1 rewrite growth: httpd-rs TIMEOUT in 6014 ms rss 6964->1121520 KiB (Apache oracle next)
PASS  A2 Apache oracle: apache HTTP/1.1 403 Forbidden in 13.6 ms rss=1892 KiB alive
PASS  A3 bounded abort: rc=-6; memory allocation of 100000000 bytes failed | note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
PASS  B1 header expansion: httpd-rs HTTP/1.1 200 OK in 23 ms
PASS  B2 Apache oracle: apache HTTP/1.1 500 Internal Server Error in 0.6 ms alive
PASS  B3 bounded abort: access file 102015 B; rc=-6; memory allocation of 536870912 bytes failed | note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
PASS  C1 RequireAll x1000: access file 27020 B; httpd-rs rc=-6 stack-overflow=True; apache HTTP/1.1 200 OK in 2 ms alive=True
PASS  C2 <If> x5000: access file 90020 B; httpd-rs rc=-6 stack-overflow=True; apache HTTP/1.1 200 OK in 87 ms alive=True
```

### 3.1 P28-A — rewrite growth

Fixture: `AllowOverride FileInfo`, `.htaccess` with
`RewriteRule ^(.*)$ $1$1$1$1$1 [L]`, request `/rw/` + 50 `a`s.

- Natural run: httpd-rs did not answer within 6 s and grew from 7 MB to
  **1.07 GB RSS**; the longer probe (`/tmp/opencode/p28-rewrite2`) reached
  **3.2 GB** and the request stayed pinned.
- Bounded run: with `RLIMIT_AS = 512 MiB` and a ten-`$1` rule, a 1-byte path
  aborts after 0.5 s with `memory allocation of 100000000 bytes failed`
  (`rc=-6`); the five-`$1` rule with a 100-byte path aborts with
  `memory allocation of 39062538 bytes failed`.
- Apache: `403` in 1-14 ms, RSS flat at ~2 MB, process alive on every
  variant (`[L]`, `[PT]`, `[N]`).

Because the growth is `k^rounds` with `rounds ≤ 10`, a rule with enough
`$1` repetitions makes the allocation exceed any host's memory: a 200-byte
access file with 50 repetitions requests `50^10 × L` bytes.

### 3.2 P28-B — expression expansion

- Header form (`%{HTTP:X}` × 1000, `X: A×8000`): `200 OK` after allocating
  ~8 MB; Apache `500` in 0.6 ms.
- `file()` form (`file('prot/big')` × 6000, `big` = 64 KiB): under
  `RLIMIT_AS = 512 MiB` the process aborts with
  `memory allocation of 536870912 bytes failed` (`rc=-6`) after 0.22 s.
  The access file is 102 KB; the 1 MiB cap admits ~5.5 GB of expansion
  (`87k × 64 KiB`), plus a 64 KiB open/read per call.

### 3.3 P28-C — section nesting

- 1,000 nested `<RequireAll>` wrappers (27,020-byte access file): httpd-rs
  aborts with `thread 'conn' has overflowed its stack`; Apache `200` in
  2 ms.
- 5,000 nested `<If "true">` wrappers (90,020 bytes): same abort; Apache
  `200` in 87 ms.
- 20,000-level forms also abort httpd-rs while Apache stays alive.

---

## 4. Reachability and threat model

- **Precondition:** one attacker-written `.htaccess` in a writable directory
  of a tree that enables access files (`HttpdRsCapability AccessFiles On`)
  with the relevant override category:
  - P28-A: `AllowOverride FileInfo` or `All` (tested with `FileInfo`; the
    project's conformance tree has `www/htaccess/cat-fileinfo` and the
    `www/htaccess` `AllowOverride All` tree);
  - P28-B: `AllowOverride AuthConfig` for `Require expr` (the
    `cat-auth`/P24-A2 shape) or `FileInfo` for `<If>`/`RewriteCond expr`;
  - P28-C: any override that admits sections (`RequireAll`, `<If>`, ...).
- **No further primitive:** P28-A and P28-C need no uploaded content beyond
  the access file itself and a short request; P28-B's header form needs only
  an 8 KB request header. Request paths need not exist.
- **Blast radius:** all three abort or OOM the whole process (or pin a
  worker on a multi-GB allocation until it does) with one unauthenticated
  request; P28-A additionally gives an attacker a repeatable memory-pressure
  primitive from a 200-byte payload.
- **Apache:** refuses or serves every identical case in milliseconds with a
  flat memory profile (`403`/`500`), and survives all nesting depths tested.

---

## 5. Impact

- **P28-A:** remote, unauthenticated memory exhaustion and process abort;
  on an unconstrained host the request pins a worker while allocating until
  the OOM killer or the allocator stops it. Distinct from P27 (glob) and
  from the P20/P21/P22 request/response-memory findings: the growth comes
  from the rewrite engine's own output over rounds.
- **P28-B:** remote, unauthenticated memory allocation of hundreds of MB to
  multiple GB per request through `Require expr`, an evaluator that carries
  no resident-byte lease; aborts the process when memory is bounded.
- **P28-C:** remote, unauthenticated whole-process abort from a 27 KB access
  file — the smallest one-request kill found in the engagement so far.
- All three are absent from the current resource-bounds and parser-totality
  evidence (`resource_bounds` covers regex work, chunks, H2 and compression;
  `expr_parser_totality` covers expression *parsing*; nothing bounds rewrite
  substitution size, expression value size or section nesting depth).

---

## 6. Remediation direction

1. **Bound rewrite results.** Cap the canonical URL/path length (`LimitRequestLine`-
   style) after every substitution and before every restart; fail closed
   (500) when the cap is exceeded. Add the cap to `rewrite_internal_path`
   or immediately after `expand_backrefs`, and extend the P23-style work
   bound to substitution size × rounds.
2. **Bound expression values.** Give expression evaluation a concrete
   byte/step budget: cap the sum of expansion output, `Concat` components,
   function results and comparison copies; charge it to
   `MAX_REQUEST_RESIDENT_BYTES` or `try_expensive`; fail the expression
   (deny, 403/500) when exceeded. Cap individual `Require expr` source size
   below the 1 MiB access-file limit.
3. **Bound section nesting.** Track a depth counter in `parse_block` (and
   in the nested authorization evaluation) and reject access files deeper
   than a small bound (Apache handles 5,000 levels; a compatibility-friendly
   cap such as 100-1,000 both suffices and fails closed with a parse error,
   not a signal). Mirror the main-config `Include` depth cap (`config.rs:3360`).
4. **Defense in depth.** Give the connection thread an explicit stack size
   large enough for the declared parser bounds, or move parsing to a
   dedicated stack; make access-file parse failures a normal 500 instead of
   an abort path.
5. **Verification.** Extend `resource_bounds` with (a) a rewrite-result size
   invariant over rounds, (b) an expression-value byte bound, and (c) a
   section-depth bound for the access-file parser; add regression cases for
   each vector (long `$1` runs, long `%{…}`/`file()` concatenations, deeply
   nested sections) with the Apache verdicts recorded here.

---

## 7. Reproduction

```sh
cd /root/httpd-rs
cargo build --release -p httpd-rs
python3 adversarial/p28/exploit_p28.py            # all 8 verdicts
python3 adversarial/p28/exploit_p28.py A           # rewrite growth
python3 adversarial/p28/exploit_p28.py B C         # expression / nesting
python3 adversarial/p28/exploit_p28.py --keep      # retain fixtures + logs
```

Expected: `8/8 verdicts passed`; the `*-kill.log` files contain
`memory allocation of … failed`, and `vp-c.log` contains
`thread 'conn' … has overflowed its stack` +
`fatal runtime error: stack overflow, aborting`.

Minimal P28-A repro: `.htaccess` with
`RewriteEngine On` / `RewriteRule ^(.*)$ $1$1$1$1$1$1$1$1$1$1 [L]` under
`AllowOverride FileInfo` + `HttpdRsCapability AccessFiles On`; request
`/rw/a`. Under `RLIMIT_AS=512 MiB` httpd-rs aborts in ~0.5 s; Apache answers
`403` in ~1 ms.

Minimal P28-C repro: a 27 KB `.htaccess` of 1,000 nested `<RequireAll>`
wrappers around `Require all granted`; one request aborts httpd-rs, Apache
returns `200`.

---

## 8. Retained files

- `adversarial/p28/exploit_p28.py` — the 8-verdict differential battery
  (groups A-C, Apache oracles, `RLIMIT_AS` abort cases; loopback only;
  fixtures under `/tmp/opencode/p28-harness` when `--keep` is given).
- `/tmp/opencode/p28-final-run.txt` — full 8/8 output.
- `/tmp/opencode/p28-harness/logs/` — per-case server logs, including
  `vp-a-kill.log`/`vp-b-kill.log` allocator aborts and `vp-c.log` stack
  overflow.
- `/tmp/opencode/p28-probes/` — `expr_probe.py`, `expr_oracle.py`,
  `fileexpr_probe.py`, `nest_probe.py` (calibration and Apache oracles).
- `/tmp/opencode/p28-rewrite/`, `/tmp/opencode/p28-rewrite2/`,
  `/tmp/opencode/p28-rewrite3/`, `/tmp/opencode/p28-expr/`,
  `/tmp/opencode/p28-nest/` — earlier fixtures and probe output.
