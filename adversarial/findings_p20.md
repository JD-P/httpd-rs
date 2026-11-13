# Pass 20 — adversarial break of HEAD `07c7879` ("Require stable FastCGI paths and openat2")

- **Date:** 2026-10-29
- **Subject:** `target/release/httpd-rs` built at HEAD `07c7879`. No product source was edited. The retained additions for this pass are `adversarial/p20/exploit_p20.py`, this write-up and the `adversarial/README.md` index entry.
- **Oracle:** Apache/2.4.69 (Debian), `/usr/sbin/apache2 -X`, with `mod_http2` + `mod_ssl` for the HTTP/2 memory differential. Loopback only.
- **Harness:** `adversarial/p20/exploit_p20.py` — **4 differential verdicts** across the two findings: HTTP/1 versus HTTP/2 request-body memory (A1/A2), memory-bounded HTTP/2 process death (A3), and the declared-length spool-budget reservation denial (B).
- **Retained evidence:** `/tmp/opencode/p20-harness` (fixtures, configs, per-case stdout/error logs, the allocator-abort log) and the Apache h2 oracle config under `/tmp/opencode/p20-h2`.
- **Method:** audit of the HTTP/2 request-body path against the HTTP/1 spool design and of the `ResourceBudget` spool reservation against its documented exhaustion behavior, followed by live Apache-versus-httpd-rs and HTTP/1-versus-HTTP/2 differentials on the project's own static/HTTP2 benchmark fixtures.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P20-A** | HTTP/2 request bodies are accumulated into a heap `Vec` up to **32 MiB per stream** (`MAX_BODY_BUFFERED`) with up to **100 concurrent streams per connection** (`max_concurrent_streams`), i.e. a ceiling of **≈3.2 GiB of heap for one TLS connection**. The HTTP/1 path spools bodies above **1 MiB** to an unlinked file; the h2 adapter never spools. One h2 connection with enough concurrent large POSTs OOMs or aborts the process. | `mod_http2` streams request bodies through the handler: **+1.3 MiB RSS** for 20 × 8 MiB concurrent streams. | **+162 MiB RSS** for the same 20 × 8 MiB concurrent streams; one 32 MiB stream holds +32.9 MiB; 60 × 8 MiB under a 512 MiB address-space bound aborts the process (`memory allocation of 8388608 bytes failed`). | remote memory-exhaustion denial of service (whole-process) |
| **P20-B** | `read_request` reserves the **declared `Content-Length`** from the process-global `HttpdRsMaxSpoolBytes` budget *before reading any body bytes*. One request that declares the full 1 GiB budget and sends 16 bytes holds the entire budget until the body deadline (30 s default), during which **every** identity upload above 1 MiB and **every** chunked request process-wide is dropped with no HTTP response (not the `503` the dynamic-request ceiling returns). | Apache has no equivalent global declared-length reservation; the victim requests are served normally. | Control uploads return `405`; while the reservation is held the 2 MiB victim gets `ConnectionResetError`, a 5-byte chunked victim gets an empty response, and a 1 KiB identity upload still returns `405`; everything recovers the moment the attacker closes. | remote resource-exhaustion denial of service (all uploads) |

Both findings are remote, unauthenticated and reachable with the stock configuration. P20-A is bounded by attacker bandwidth (the body must actually be sent); P20-B costs the attacker **one short request** and denies all uploads while it is held.

---

## 2. Observed evidence

### 2.1 P20-A — HTTP/2 buffers what HTTP/1 spools

Fixture: the static tree used by the conformance/benchmark suites (`www/index.html`), an 8 MiB POST body, and an HTTPS vhost with ALPN `h2`. `nghttp` posts the body on N concurrent streams over one connection; RSS is sampled every 5 ms during the load.

```text
PASS  P20-A1 HTTP/1 large body is spooled: HTTP/1.1 405 Method Not Allowed,
      peak rss +0.2 MiB for one 8 MiB POST
PASS  P20-A2 HTTP/2 bodies buffered in memory: 20 x 8 MiB concurrent streams,
      peak rss +162 MiB (ceiling = 100 streams x 32 MiB = 3.2 GiB)
PASS  P20-A3 HTTP/2 memory-bound process death: pid 32334 exited=True under
      RLIMIT_AS=512 MiB after 60 x 8 MiB streams; allocator abort=True
```

Single-stream calibration:

```text
single 32 MiB h2 stream: rc=0 peak rss +32.9 MiB
33 MiB h2 stream:        413 Request Entity Too Large (after buffering 32 MiB)
```

Apache oracle, same fixture, same `nghttp -m 20 -d 8m.bin` load:

```text
apache h2 20 x 8 MiB: rc=0 peak rss 15.0 MiB (delta 1.3 MiB), after 14.6 MiB
```

The allocator log for A3:

```text
memory allocation of 8388608 bytes failed
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

`Cargo.toml` sets `panic = "abort"`; the allocation failure kills the whole server, not one stream.

### 2.2 P20-B — one declared length holds the global spool budget

Fixture: the stock static configuration (defaults: `HttpdRsMaxSpoolBytes 1073741824`, `HttpdRsMaxSpoolFiles 128`, `LimitRequestBody 1073741824`, `RequestReadTimeout body=30`).

```text
PASS  P20-B declared-length spool reservation denies uploads:
      controls: 2 MiB='HTTP/1.1 405 Method Not Allowed',
                chunked='HTTP/1.1 405 Method Not Allowed';
      while held: 2 MiB='no response (ConnectionResetError)',
                  tiny chunked='<empty response>',
                  1 KiB identity='HTTP/1.1 405 Method Not Allowed';
      after release='HTTP/1.1 405 Method Not Allowed'
```

Attacker request (16 bytes of body sent, then idle):

```http
POST /index.html HTTP/1.1
Host: p20.local
Content-Length: 1073741824
```

While the reservation is held:

- a legitimate 2 MiB `Content-Length` upload is reset with **no HTTP response**;
- a 5-byte `Transfer-Encoding: chunked` request is closed with **no HTTP response**;
- a 1 KiB identity upload (below the 1 MiB in-memory threshold) still returns `405`, so normal small traffic is unaffected;
- closing the attacker connection releases the budget immediately and the next 2 MiB upload returns `405`.

The hold is refreshed by reconnecting every `RequestReadTimeout` body deadline (30 s default). With `RequestReadTimeout body=…,MinRate=…` the deadline scales with the declared length (`n*1000/min_rate`), so the same request can hold the budget for hours or days.

---

## 3. Root cause

### 3.1 P20-A: the h2 adapter has no spool threshold

`crates/server/src/http.rs:27-30` defines the two thresholds:

```rust
pub const MAX_BODY_BUFFERED: u64 = 32 * 1024 * 1024;
/// Request bodies above this size are spooled to an unlinked temporary file
/// instead of occupying heap memory for the whole request.
pub const MAX_REQUEST_BODY_IN_MEMORY: u64 = 1024 * 1024;
```

The HTTP/1 parser honors both: bodies above 1 MiB take a `SpoolLease`, reserve the declared length and stream into `spool_file()` (`http.rs:362-397`), so the connection holds at most ~1 MiB of body heap. The h2 adapter instead does:

`crates/server/src/h2.rs:738`:

```rust
let max_body = cfg.limit_request_body.min(crate::http::MAX_BODY_BUFFERED);
```

and `read_body` accumulates every DATA frame into a `Vec<u8>` (`h2.rs:309-355`, `body.extend_from_slice(&chunk)` at line 346) up to `max_body`. Each accepted stream runs `read_body` before dispatch (`h2.rs:742-755`), so all concurrent streams hold their bodies simultaneously. With `h2_settings()` (`crates/verified/src/lib.rs:7818-7830`):

```rust
max_concurrent_streams: 100,
...
initial_window: 256 * 1024,
```

the per-connection ceiling is `100 × 32 MiB = 3.2 GiB` of heap. The receive window is released as frames are consumed (`h2.rs:349`), so a fast client can keep the connection full; the only backstop is the 30 s body deadline. `MaxRequestWorkers` (default 512) multiplies this across connections, and the allocation failure aborts the process because of `panic = "abort"` (`Cargo.toml:19`).

The HTTP/1 and HTTP/2 code paths therefore disagree about the same policy by a factor of 32 per request and 100 per connection; Apache's `mod_http2` streams the body and stays flat (A2 oracle).

### 3.2 P20-B: the budget reserves declared bytes before reading them

`crates/server/src/http.rs:362-397`:

```rust
if n > MAX_REQUEST_BODY_IN_MEMORY {
    let mut lease = limits
        .resource_budget
        .try_spool(limits.max_spool_bytes, limits.max_spool_files)?;
    lease.reserve(n)?;            // <-- whole declared Content-Length
    let file = spool_file()?;
    ...
    while remaining > 0 { ... stream ... }
}
```

`ResourceBudget::try_spool`/`SpoolLease::reserve` (`crates/server/src/resource.rs:86-99,132-146`) enforce `current + amount <= max_bytes` against one process-global counter shared by request-body spools, FastCGI response spools and the CGI worker's duplicate body spool. A single request declaring the full `HttpdRsMaxSpoolBytes` (1 GiB default, equal to the default `LimitRequestBody`) therefore consumes the entire budget before a single body byte is read; the attacker only needs the headers plus a trickle of bytes to keep the connection (and the lease) alive until the body deadline.

The chunked branch (`http.rs:409-442`) is hit even harder: it always takes a spool lease and reserves as it reads, so a 5-byte chunked request fails on the first `reserve(5)` once the byte budget is gone.

Finally, the failure is not mapped to an HTTP response. `try_spool`/`reserve` failures propagate as `ReadError::Io`, and `handle_connection` returns the error without writing a response (`crates/server/src/server.rs:500-525`), so the victim sees a dropped connection. The dynamic-request ceiling (`HttpdRsMaxDynamicRequests`) returns `503`; the spool path has no equivalent status, so upload clients cannot even retry meaningfully.

---

## 4. Exploit chains

### 4.1 P20-A — HTTP/2 memory spike

1. The operator serves TLS with ALPN `h2` (the benchmarked HTTP/2 configuration) and any content reachable by POST (a static file is enough; the body is buffered before the handler is selected).
2. The attacker opens one h2 connection and sends N concurrent POSTs with large bodies (up to 32 MiB each; the server buffers up to 100 streams).
3. RSS rises by roughly `streams × body_size` (measured +162 MiB for 20 × 8 MiB; +32.9 MiB for one 32 MiB stream). On a host or container whose free memory is below that spike, the server aborts (`memory allocation of N bytes failed`) or is OOM-killed. Apache streams the same bodies and stays at +1.3 MiB.

### 4.2 P20-B — spool-budget starvation

1. The attacker opens one connection and sends `POST` with `Content-Length: <HttpdRsMaxSpoolBytes>` (1 GiB default) and a few bytes.
2. The server reserves the entire global spool-byte budget and waits for the rest of the body (30 s by default).
3. Every other client's identity upload above 1 MiB and every chunked request is dropped with no response for as long as the reservation is held.
4. The attacker reconnects at the deadline; the denial continues indefinitely. One short request per 30 s is enough.

---

## 5. Impact and preconditions

**Impact.** Two independent remote, unauthenticated resource-exhaustion paths:

- P20-A: a single HTTP/2 connection can spike the process heap by up to ~3.2 GiB and abort it on any host that cannot absorb the spike. It contradicts the HTTP/1 spool design and the README's bounded-memory claims, and Apache does not have the behavior.
- P20-B: one ~100-byte request denies all large and chunked uploads process-wide while it is held, with a dropped connection instead of the documented `503`. Applications behind httpd-rs that accept uploads (PHP/FastCGI form posts, proxy PUT/POST, API chunked uploads) lose that functionality for the duration.

**Preconditions.**

- P20-A: an HTTP/2 listener (TLS + ALPN `h2`; the benchmarked HTTPS/HTTP2 configuration) and any POST target. No authentication, no cache, no CGI/FastCGI/Proxy backend required.
- P20-B: any listener and any POST target; the default spool budget and body timeout are the worst case. The attack does not require TLS, h2, cache or a dynamic backend.

**Severity.** P20-A High (whole-process abort on memory-constrained hosts). P20-B High for upload-serving deployments, Medium otherwise (small GET traffic is unaffected).

---

## 6. Relationship to P19 and prior findings

- **P19** was retained *cache* heap (`cache::store`): the memory grew permanently at ~1 MiB per distinct cache key until a 4096 × `CacheMaxFileSize` ceiling, with no disk-quota relationship. **P20-A** is transient *request-body* heap on the HTTP/2 path: it does not need the cache, grows by `streams × body` within one connection, and is freed after each stream; the differential is against the HTTP/1 spool design and Apache's streaming behavior. Fixing one does not fix the other.
- **P20-B** is a global-budget fairness bug in `ResourceBudget`, not a per-request buffer: the attacker sends almost no data and denies a *different* set of sinks (identity uploads >1 MiB and all chunked requests). It is adjacent to the F43 spool-file work but concerns the byte counter, not the spool-file creation.
- **P12-D** was the HTTP/2 stream/connection flow-control stall (body never completes, window stays charged); P20-A is about bodies that *do* complete and are buffered in full. P15/P17/P18 are handler-identity/access findings and are unrelated.
- The README claims "large request bodies are spooled to an unlinked file before being forwarded to proxy/FastCGI backends" and "exhaustion returns 503": P20-A shows the h2 path never spools, and P20-B shows the request-body spool exhaustion path drops the connection.

---

## 7. Reproduction

```sh
cargo build --release -p httpd-rs
python3 adversarial/p20/exploit_p20.py            # groups A B
python3 adversarial/p20/exploit_p20.py A          # HTTP/2 body buffering + Apache oracle
python3 adversarial/p20/exploit_p20.py B          # spool-budget starvation
python3 adversarial/p20/exploit_p20.py --keep     # retain fixtures and logs
```

The final retained run produced **4/4 PASS**:

```text
PASS  P20-A1 HTTP/1 large body is spooled: HTTP/1.1 405 Method Not Allowed, peak rss +0.2 MiB for one 8 MiB POST
PASS  P20-A2 HTTP/2 bodies buffered in memory: 20 x 8 MiB concurrent streams, peak rss +162 MiB (ceiling = 100 streams x 32 MiB = 3.2 GiB)
PASS  P20-A3 HTTP/2 memory-bound process death: pid 32334 exited=True under RLIMIT_AS=512 MiB after 60 x 8 MiB streams; allocator abort=True
PASS  P20-B declared-length spool reservation denies uploads: controls: 2 MiB='HTTP/1.1 405 Method Not Allowed', chunked='HTTP/1.1 405 Method Not Allowed'; while held: 2 MiB='no response (ConnectionResetError)', tiny chunked='<empty response>', 1 KiB identity='HTTP/1.1 405 Method Not Allowed'; after release='HTTP/1.1 405 Method Not Allowed'
```

Group A requires `nghttp` and `openssl`; group A3 applies `RLIMIT_AS` to the child only. All fixtures live under `/tmp/opencode/p20-harness`.

---

## 8. Suggested remediation direction

The product source was not changed for this pass. Two independent fixes are required:

**P20-A — make HTTP/2 request bodies obey the HTTP/1 spool policy.**

- In `h2::read_body`, once the accumulated body exceeds `MAX_REQUEST_BODY_IN_MEMORY`, move the remainder into the same `SpoolLease` + `spool_file()` path used by HTTP/1, and represent the request as `body_spool` instead of `Request.body`. The dispatch/CGI/FastCGI/proxy paths already understand `body_spool`.
- Alternatively, stream DATA frames directly to the handler and keep only a bounded prefix in memory; the dispatcher would need a streaming request-body interface.
- Bound the aggregate h2 in-memory body bytes per connection (and process-wide) with a `ResourceBudget` counter, not just per-stream `max_body`; return `413`/`503` when the budget is exhausted rather than allocating.
- Consider lowering `max_concurrent_streams` or `MAX_BODY_BUFFERED` as a stopgap, but the structural fix is the spool threshold.
- Add a differential regression that runs the same concurrent POST load over HTTP/1 and HTTP/2 and asserts comparable RSS, plus an Apache `mod_http2` oracle.

**P20-B — reserve what is read, not what is declared.**

- Reserve the declared length only as bytes actually arrive (the chunked path already does this), or reserve a bounded chunk (e.g. `min(n, 1 MiB)`) and grow the reservation with the file. The aggregate limit then still bounds real disk use without letting one idle request consume the whole budget.
- Map spool-budget exhaustion to the documented `503` response instead of `ReadError::Io`/connection drop, so victims get an HTTP status and can retry.
- Consider a per-connection or fair-share cap so one client cannot hold the entire global spool budget, and clamp the `RequestReadTimeout body=…,MinRate=…` extension for spool reservation purposes so a declared length cannot hold the budget for days.
- Add a regression that holds a declared reservation from one connection and asserts that an ordinary large upload and a chunked request still succeed (or receive `503`), then recovers after release.
