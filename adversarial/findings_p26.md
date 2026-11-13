# Pass 26 — adversarial break of the P25 remediation (stale-cache trailing-slash bypass and absolute-deadline truncation)

- **Date:** 2026-11-01
- **Subject:** commits after the P25 remediation `5545d7f`
  (`Remediate P25 static hosting findings`), up to HEAD `5b5dbb7`.
  No product source was edited; only analysis and release builds were
  performed.
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` (+ `authz_core`,
  `authz_host`, `mime`, `dir`), loopback only.
- **Harnesses:**
  - `/tmp/opencode/p26-cache-repro/repro.py` — P26-A upgrade battery
    (pre-fix binary `fbb26fd` populates a persisted cache; the P25 fix
    binary `5545d7f` serves from it).
  - `/tmp/opencode/p26-cache-repro/slow.py` — P26-B slow-download
    differential (httpd-rs HEAD vs Apache 2.4.69, both `Timeout 2`).
- **Retained evidence:** build trees `/tmp/opencode/httpd-rs-p26-old`
  (`fbb26fd`) and `/tmp/opencode/httpd-rs-p26-fix` (`5545d7f`); fixtures and
  logs under `/tmp/opencode/p26-cache-repro/work` and
  `/tmp/opencode/p26-slow`.
- **Method:** source review of the P25 remediation and the protocol-boundary
  commits (`ec79965`, `55eff45`, `5b5dbb7`), two-binary cache-upgrade
  differentials, and a controlled slow-reader timing differential against
  Apache.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P26-A** | The P25-A trailing-slash fix is applied in `dispatch_inner` **after** the cache lookup in `dispatch_inner_request`. The fix commit `5545d7f` neither bumps `CACHE_EPOCH` nor changes the cache-key policy material. A cache entry for `/private.txt/` written by the immediately preceding release (`fbb26fd`/`93d6172`, which still served the file) therefore remains valid after upgrading to `5545d7f`, and the protected bytes are served from the cache, bypassing the new 404. HEAD is safe only because later commits incidentally changed the policy-fingerprint material (invalidating the key), not because the fix deliberately invalidated the cache. | `404` for `/private.txt/` | upgrade to `5545d7f`: `200` + `SECRET-CONTENT` from the persisted cache; HEAD: `404` only because its cache key material changed | authorization bypass via stale persisted cache (incomplete remediation) |
| **P26-B** | The P25-B fix gives the whole response an **absolute total deadline** (`deadline = now + Timeout`). A legitimate client that reads slowly but continuously is disconnected when the total deadline expires, truncating the transfer. Apache's `Timeout` is per-I/O and keeps sending while the client makes progress. | continues sending while the client reads within each `Timeout` interval | aborts at about `Timeout`; a 64 MiB file read at ~1 MiB/s is cut off after ~4.3 s at `Timeout 2` | availability regression / legitimate download truncation introduced by the P25-B remediation |

P26-A is the pass-26 finding: the security release `5545d7f` leaves the
pre-fix cache live, so the P25-A protected-file disclosure survives the
upgrade for as long as the cache entry lives. P26-B is the collateral
damage of the P25-B remediation: the absolute deadline replaces a
per-I/O stall bound with a total-transfer bound, so slow legitimate
downloads now fail.

---

## 2. P26-A — the P25-A trailing-slash fix does not invalidate pre-fix cache entries

### 2.1 Root cause

The P25-A fix in `5545d7f` added the trailing-slash rejection inside
`dispatch_inner` (`crates/server/src/server.rs:3308-3326`):

```rust
// A trailing slash asserts a directory-like target. ...
if url_path.len() > 1 && url_path.ends_with('/') {
    return error_response(..., 404, ...);
}
```

But the outer request path in `dispatch_inner_request`
(`crates/server/src/server.rs:1488-1590`) performs the cache lookup first:

```rust
if let Some(cache_ctx) = &cache_scope {
    if let Some(resp) = crate::cache::lookup(...) {
        return resp;                       // <-- served before dispatch_inner
    }
}
let mut resp = dispatch_inner(...);        // <-- 404 check lives here
```

The cache key and the persisted cache metadata did not change in the fix
commit. `CACHE_EPOCH` still starts at 1 in every process
(`crates/server/src/cache.rs:48`), and `cache::clear` only bumps it on a
configuration reload (`cache.rs:1632-1633`), not on a restart or an
upgrade. The `cache_policy_material`/`cache_policy_fingerprint`
functions are byte-identical between `fbb26fd` and `5545d7f`, and the
fix commit did not touch `cache.rs`, `config.rs` or `scope_policy.rs`.

Therefore an operator who upgrades from the immediately preceding release
(`fbb26fd`, functionally identical to `93d6172`) to the security release
`5545d7f` keeps any cached 200 for a trailing-slash spelling such as
`/private.txt/`. The first request after the upgrade is answered from the
cache, so the new 404 never runs. The entry survives until its TTL
expires or a configuration reload bumps the epoch.

HEAD happens to be safe because later commits changed the `Scope`
debug/policy material (notably the compression-policy fields), which
changes the policy fingerprint and therefore the cache key. That is an
accident of the later hardening, not an explicit invalidation: HEAD's
`cache.rs` still has no cache-format/epoch bump for the trailing-slash
change. A future change that preserves the material, or a cache populated
by a HEAD build whose material happens to match the upgrading build,
reopens the same window.

### 2.2 Live evidence

`python3 /tmp/opencode/p26-cache-repro/repro.py` (pre-fix `fbb26fd`
populates the cache, then the P25 fix binary `5545d7f` reads it):

```text
== old binary (fbb26fd) populates cache for /private.txt/
old GET /private.txt/ -> 'HTTP/1.1 200 OK' body=b'SECRET-CONTENT\n'
old GET /private.txt  -> 'HTTP/1.1 403 Forbidden' body=b'<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML'
== fix binary (5545d7f) reads persisted cache
fix GET /private.txt/ -> 'HTTP/1.1 200 OK' body=b'SECRET-CONTENT\n'
fix GET /private.txt  -> 'HTTP/1.1 403 Forbidden' body=b'<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML'
fix GET /public.txt/  -> 'HTTP/1.1 404 Not Found' body=b'<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML'
RESULT: fix binary stale cached 200 for /private.txt/ = True
```

The same cache root with HEAD (`python3` run before switching the script to
`FIX`) returned `404 Not Found` for `/private.txt/`, confirming HEAD's cache
key differs. The persisted meta entry contains the canonical identity for
`/private.txt/` (request path and representation path both `/private.txt/`,
target `/tmp/.../htdocs/private.txt`) with `G 1` and `S 200`, so the cache
lookup is a genuine hit under `5545d7f`.

### 2.3 Reachability and threat model

- The exposure requires a one-time cache population by a pre-fix binary and
  then an in-place upgrade to `5545d7f` (or any build whose policy material
  and epoch still match). The cache root must be persisted across the
  upgrade, which is the normal `CacheRoot` deployment.
- The cached URL must be one the operator protects with a URL-scoped rule
  that the pre-fix binary failed to enforce for the trailing-slash spelling
  (`<LocationMatch "^/private\.txt$">`, `<If "%{REQUEST_URI} == ...">`,
  per-directory `RewriteRule ... [F]`, or a redirect/deny keyed to the
  exact URL). The pre-fix binary serves the file and caches the 200; the
  fix binary then serves that cached 200 without dispatching.
- HEAD's later key-material change happens to close the window for the
  `fbb26fd` → HEAD path, but the fix release itself (`5545d7f`) remains
  vulnerable. The review therefore reports it as an incomplete remediation,
  not a HEAD regression.
- Any cache-enabled static host that upgraded through the P25 fix release
  with a persisted `CacheRoot` is affected until TTL/reload. Default
  `CacheDefaultExpire`/`CacheMaxExpire` in the documented recipe are 60 s
  to 1 h, so the window is bounded but real; a longer configured TTL widens
  it.

### 2.4 Impact

Unauthenticated read of files the operator believes are protected, from a
cache-enabled listener, for the life of the stale entry. This is the same
disclosure as P25-A but reachable *after* applying the fix, so an operator
who believes the security release closed the hole is still exposed until
the cache expires. It also defeats the P25-A remediation's stated goal.

### 2.5 Remediation direction

1. Reject the trailing-slash static target **before** the cache lookup
   (in `dispatch_inner_request` or in the request-plan/cache-scope builder),
   so a cached representation can never be served for a URL the dispatcher
   would 404. This is the most direct fix and does not depend on cache-key
   material.
2. Alternatively, bump the persisted cache format/epoch in the fix commit
   (e.g., start `CACHE_EPOCH` from a build-time/format value, or increment
   the metadata version) so pre-fix entries are rejected on upgrade.
   The current epoch is process-local and restarts at 1, so it does not
   invalidate persisted entries on a restart or upgrade.
3. Add a regression row to the cache tests: populate a 200 for a
   trailing-slash static URL with the pre-fix behavior (or inject a cache
   entry directly), then run the fixed binary and assert 404 even with the
   cache hit.

---

## 3. P26-B — the absolute write deadline truncates legitimate slow downloads

### 3.1 Root cause

The P25-B remediation sets a single absolute deadline for the whole
response in `write_response` (`crates/server/src/http.rs:1469-1475`):

```rust
let deadline = Instant::now()
    .checked_add(opts.write_timeout)
    .ok_or_else(write_timeout_error)?;
stream.set_write_deadline(Some(deadline));
```

Every write, sendfile chunk and poll is checked against that same deadline
(`write_all_until`, `sendfile_until`, `poll_writable`). `write_timeout`
is `cfg.timeout`, whose default is 60 s. That bounds the **total** time to
write the response, not the time a single write may stall.

Apache's `Timeout` is per-I/O: a client that keeps reading (each read within
the interval) receives the whole object even if the transfer takes longer
than `Timeout`. The new httpd-rs deadline instead aborts the connection once
`now >= deadline`, regardless of whether the client is still making
progress. For large files on slow links (mobile, congested uplinks, large
video/archive downloads), the transfer is truncated at `Timeout`.

### 3.2 Live evidence

`python3 /tmp/opencode/p26-cache-repro/slow.py` (64 MiB file, `Timeout 2`,
client reads 64 KiB then sleeps 62.5 ms ≈ 1 MiB/s for up to 6 s):

```text
httpd-rs: bytes=4423951 elapsed=4.32s closed=True
apache: bytes=6255552 elapsed=6.01s closed=False
```

- httpd-rs aborted at its ~2 s deadline; the client drained the ~2.5 MiB
  socket buffer and saw EOF at 4.32 s after receiving only 4.42 MB of the
  64 MiB object. A real client would see a truncated/aborted download.
- Apache kept sending for the whole 6.01 s test window (6.26 MB read) and
  did not close; its per-I/O `Timeout` did not truncate a progressing
  client.
- With the default `Timeout 60`, any response whose total write takes more
  than 60 s is truncated — a 1 GiB file at 10 Mbps needs ~14 minutes.

### 3.3 Impact

- Legitimate large downloads over slow or congested links fail partway
  through. This is an availability regression introduced by the security
  fix, not a hardening of the prior stall vector. It affects static assets,
  proxy bodies and any `Body::File`/`Body::Bytes`/`Body::Stream` response
  whose total write exceeds `Timeout`.
- It does not reintroduce the P25-B worker exhaustion (the deadline still
  bounds a fully stalled client), but it over-corrects by treating steady
  progress as a stall.
- Apache's `mpm_event`/`Timeout` behavior on the same fixture keeps the
  transfer alive, so the differential is clear.

### 3.4 Remediation direction

1. Use a **stall deadline** rather than a total deadline: reset the
   deadline after each successful write/poll-progress (or use per-write
   timeouts), so a client that keeps reading is allowed to finish while a
   client that stops reading is still aborted within `Timeout`.
2. If an absolute cap is required, make it a separate, operator-visible
   limit (e.g., a total-response timeout much larger than `Timeout`) and
   document that it truncates large transfers; do not reuse the per-I/O
   `Timeout` as a total-transfer budget.
3. Add a regression row: a slow-but-progressing reader on a large file must
   receive the full object (within a bounded multiple of the transfer
   time), while a non-reading client must be aborted at `Timeout`.

---

## 4. Other observations (not reported as confirmed vulnerabilities)

| Observation | Note |
|---|---|
| Cache-key material changes between releases | The `Scope` debug/policy material changed between `fbb26fd` and HEAD (compression-policy fields), so persisted caches are silently invalidated on upgrade. This closed the P26-A window for the `fbb26fd` → HEAD path, but it is an accidental, undocumented cache-format change rather than an explicit epoch/version bump. |
| HEAD's `cache.rs` still has no trailing-slash invalidation | The fix commit and HEAD both leave the cache lookup before the static trailing-slash rejection. HEAD is only protected by the incidental key-material change. A future material-preserving change would reopen the stale-entry window. |
| H2 control-frame budget zero-cost events | `H2ControlEvent::WindowUpdate { increment }` costs 0 when `increment >= 1024` (`crates/verified/src/lib.rs:9409-9424`). A client can send large-increment `WINDOW_UPDATE` frames without consuming the control-frame budget; the total frame count is bounded by the 2^31-1 window but could still be large enough to consume CPU. Not reproduced as a DoS in this pass. |
| TLS `request_is_https()` change | `ec79965` replaced the inferred HTTPS decision (`local_port == 443 || ssl.engine`) with the actual `request_is_https()` in the cache/dispatch paths. Behind a TLS-terminating proxy on port 443 this may change `%{HTTPS}`/cache-scheme behavior; no concrete bypass was established in this pass. |
| Proxy upstream read timeouts | `connect_tcp` sets per-I/O read/write timeouts from the connection deadline (`crates/server/src/proxy.rs:1888-1889`), so a slow upstream is bounded per read, similar to Apache's per-I/O semantics. Not a regression. |
| Certbot packaging scripts | The reviewed scripts retain the root-owned/symlink checks added in `3d1251a`; no concrete TOCTOU or privilege-escalation path was established in this pass. |

---

## 5. Reproduction

```sh
cd /root/httpd-rs
cargo build --release -p httpd-rs

# P26-A: build the pre-fix and fix binaries in separate worktrees
git worktree add /tmp/opencode/httpd-rs-p26-old fbb26fd
git worktree add /tmp/opencode/httpd-rs-p26-fix 5545d7f
(cd /tmp/opencode/httpd-rs-p26-old && cargo build --release -p httpd-rs)
(cd /tmp/opencode/httpd-rs-p26-fix && cargo build --release -p httpd-rs)
python3 /tmp/opencode/p26-cache-repro/repro.py

# P26-B: slow-download differential (requires Apache 2.4.69 modules)
python3 /tmp/opencode/p26-cache-repro/slow.py
```

Both harnesses bind loopback ports only, run the service as `www-data`, keep
the base directory and configuration root-owned (so the administrative-path
check accepts them), and hand only the document/cache trees to the service
account. The P26-A harness removes its fixture unless the script is edited;
the P26-B harness leaves `/tmp/opencode/p26-slow` for inspection.

---

## 6. Retained files

- `/tmp/opencode/p26-cache-repro/repro.py` — P26-A upgrade battery
  (old binary populates cache; fix binary reads it).
- `/tmp/opencode/p26-cache-repro/slow.py` — P26-B slow-reader differential
  against Apache.
- `/tmp/opencode/p26-cache-repro/work/cache/` — persisted meta/body files
  from the P26-A run (`G 1`, `S 200`, key and policy fingerprint).
- `/tmp/opencode/httpd-rs-p26-old/` — worktree at `fbb26fd`.
- `/tmp/opencode/httpd-rs-p26-fix/` — worktree at `5545d7f`.
