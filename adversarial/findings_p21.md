# Pass 21 — adversarial break of HEAD `5398493` ("Harden auth files, reload, and TLS broker")

> Remediation status (2026-10-30): fixed in the current tree. The in-memory
> identity-body reader now grows its resident lease only after each body chunk
> is received; a header-only `Content-Length` declaration retains only its
> bounded request-head bytes. The regression
> `in_memory_content_length_charges_only_received_body_bytes` pins the
> actual-byte accounting and release behavior.

- **Date:** 2026-10-30
- **Subject:** `target/release/httpd-rs` built at HEAD `5398493`. No product source was edited. The retained additions for this pass are `adversarial/p21/exploit_p21.py`, this write-up and the `adversarial/README.md` index entries.
- **Oracle:** Apache/2.4.69 (Debian), `/usr/sbin/apache2` with `mpm_event` and `mod_reqtimeout`, loopback only.
- **Harness:** `adversarial/p21/exploit_p21.py` — **4 differential/closure verdicts** (A multi-source differential, B sustained outage, C1 trusted-proxy single client, C2 IPv6 /64 rotation), plus a cross-protocol HTTP/2 check.
- **Retained evidence:** `/tmp/opencode/p21-harness` (fixtures, configs, per-group stdout and server logs).
- **Method:** audit of the pass-20 remediation (`b4b9192`) for the remaining `Content-Length` reservation seams and of the new process-wide request/response resident budgets (`6d01035`), followed by live Apache-versus-httpd-rs differentials on the project's stock static configuration.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P21-A** | The in-memory identity-body path (`Content-Length` ≤ 1 MiB) reserves the **declared** length against the process-wide `MAX_REQUEST_RESIDENT_BYTES` budget (128 MiB) **before reading a single body byte** (`http.rs:568`). A request that sends only its head and stalls holds `Content-Length + 2 × head_length` of that budget until the body deadline. **128 header-only requests (~9 KiB total, zero body bytes)** fill the budget exactly. From then on **every** request on every connection fails its first byte reservation and receives `503 Service Unavailable` — including a zero-body static GET. The outage is total, process-wide and covers HTTP/1 and HTTP/2; the attacker re-arms a wave every 12–20 s (below the 30 s `RequestReadTimeout` body deadline) for ~9 KiB per wave. | Stalled uploads only occupy their own workers: with `MaxRequestWorkers 400` and 128 stalled bodies the identical GET is served `200 OK` throughout. | `200` baseline → `503 "Request body capacity is temporarily exhausted"` for **all** requests while held → `200` immediately on release. Triggered with 128 requests from 4–6 IPv4 sources; **one** attacker behind a configured `RemoteIPTrustedProxy`; or **one** IPv6 customer rotating six /64s of a delegated prefix. An HTTP/2 GET on a sibling TLS listener is denied by the same HTTP/1 attack. | remote resource-exhaustion denial of service (total availability), incomplete P20-B closure |
| P21-B | (supporting, same root cause) A single wave costs 128 connections × 71 bytes = **9,088 bytes** with **zero body bytes**; the hold expires with the absolute body deadline and is refreshed for another ~9 KiB. ~0.3 KiB/s keeps the server rejecting every request indefinitely. The same global-budget behaviour can also be triggered by 128 *legitimate* concurrent 1 MiB uploads (self-DoS under load). | No global declared-length reservation exists; unrelated requests are unaffected. | Outage sustained across six 10 s samples while waves are re-armed every 12 s; release → immediate `200`. | remote availability denial with negligible attacker cost |

P21-A is remote, unauthenticated, needs no body bytes, no TLS, no CGI/FastCGI/proxy backend, no cache and no non-default configuration. It is the exact failure mode the pass-20 write-up prescribed fixing ("reserve what is read, not what is declared"), applied to the one branch the P20 remediation did not convert to an incremental accumulator.

---

## 2. Observed evidence

All groups run loopback-only under `/tmp/opencode/p21-harness`; the fixture is the stock static tree (`www/index.html`) and the harness's `httpd_rs_config()` is the `bench/bench.py` static configuration shape (`AllowOverride None`, `Require all granted`, default `MaxRequestWorkers 512`, default `RequestReadTimeout body=30`).

### 2.1 P21-A — header-only requests deny everything, Apache does not

```
header-only hold: Content-Length 1048434, head 71 bytes, exact charge 1048576 B; 128 holds fill 128 MiB
PASS  P21-A header-only holds deny every request (Apache differs): 192 header-only holds;
      httpd-rs before/during/after = 200 / 503 / 200;
      apache  before/during/after = 200 / 200 / 200
```

The 128 successful holds each charge exactly `n + 2L = 1,048,576 B` (`n = 2^20 − 2L`, `L = 71` is the raw head length): the head bytes are charged once as they are read (`http.rs:484`) and again when the verified parser creates the owned request (`http.rs:498`), and `Content-Length` is reserved at `http.rs:568` before the first body read.

The victim response captured while the budget is held:

```http
HTTP/1.1 503 Service Unavailable
Date: Fri, 30 Oct 2026 00:49:57 GMT
Server: Apache
Content-Type: text/html; charset=iso-8859-1
Connection: close
Content-Length: 47

Request body capacity is temporarily exhausted
```

Attacker bytes sent for the 128 successful holds: **9,088** (71-byte header each, no body byte at all).

### 2.2 P21-B — the outage survives body-deadline waves

```
PASS  P21-B outage survives body-deadline waves for 60 s:
      victim samples every 10 s: [503, 503, 503, 503, 503, 503]; after release: 200
```

The lease is released by the **absolute** body deadline (`http.rs:529`; the P20 fix removed the declared-length-derived extension), so a wave must be re-armed more often than `RequestReadTimeout body=` (30 s default). Re-arming every 12 s during the 60 s run kept every sample at `503`; closing the holds returned `200` in under a second. Each wave is ~13.6 KiB including the extra connections that are refused once the budget is full; the 128 that hold send 9,088 bytes.

### 2.3 P21-C1 — one client behind a trusted proxy

`RemoteIPHeader X-Forwarded-For` plus a trusted-proxy entry covering the transport peer is the standard reverse-proxy deployment; httpd-rs deliberately lifts the 32-connections-per-client cap for such gateways (`server.rs:409-415`, `config.rs:13389`) so the peer can present many clients.

```
PASS  P21-C1 one client behind a trusted proxy fills the budget: 160 single-source holds;
      before/during/after = 200 / 503 / 200
```

One source address opens all 160 connections and the first 128 reservations deny every request. Apache with `mod_remoteip` and the same `RemoteIPHeader X-Forwarded-For` / `RemoteIPTrustedProxy 127.0.0.1` configuration serves the identical victim request `200 OK` throughout the same 160 holds.

### 2.4 P21-C2 — one IPv6 customer rotating delegated /64s

`client_quota_key` collapses IPv6 to its /64 (`resource.rs:42-49`), which stops intra-prefix rotation but not a delegated prefix: a typical /56 or /48 contains hundreds of /64s. Six /64s opened from one host fill the budget.

```
PASS  P21-C2 one IPv6 customer rotating delegated /64s: 192 holds over 6 /64s;
      before/during/after = 200 / 503 / 200
```

### 2.5 Cross-protocol — HTTP/2 is denied by the HTTP/1 attack

Both adapters share `cfg.resource_budget` (`http.rs:449`, `h2.rs:709`); an HTTP/2 GET on a sibling TLS listener was `200` before, `503` during the plain-HTTP attack and `200` after:

```
h2 before: 2 200
h2 during: 2 503
h2 after:  2 200
```

The HTTP/2 adapter itself uses the incremental `BodyAccumulator` (`h2.rs:329`), so the HTTP/2 half of the budget is only reachable up to 64 KiB of body prefix + headers per stream; the HTTP/1 declared-length path is the cheap vector and its denial covers h2 clients as well.

---

## 3. Root cause

### 3.1 The ≤1 MiB identity path reserves the declared length before reading

`crates/server/src/http.rs:520-577` (HEAD `5398493`):

```rust
BodyFraming::Length(n) => {
    if n > limits.body {
        return Err(ReadError::Parse(ParseError::PayloadTooLarge));
    }
    // ... absolute deadline ...
    if n > MAX_REQUEST_BODY_IN_MEMORY {              // > 1 MiB: incremental accumulator
        let mut body = BodyAccumulator::new(REQUEST_BODY_SPOOL_PREFIX, ...);
        ...
    } else {
        request_resident.reserve(n)?;                // <-- full declared length, before any read
        read_exact_into(stream, buf, &mut req.body, n, body_deadline, limits.body_min_rate)?;
    }
}
```

The spool branch and the chunked branch (`BodyAccumulator`/`ResidentBodyWriter`, `http.rs:534-611`) charge only bytes actually written; the HTTP/2 adapter does the same (`h2.rs:329-366`). The P20 remediation (`b4b9192`) moved exactly these paths to as-read charging but left the single in-memory identity branch reserving on declaration. `read_exact_into` then blocks on the socket until the body arrives or the absolute deadline fires, holding the reservation the whole time.

### 3.2 The reservation is a process-global availability gate

`resource.rs:35` sets `MAX_REQUEST_RESIDENT_BYTES = 128 * 1024 * 1024`; `try_request_bytes()` issues one shared `ResidentLease` per request (`resource.rs:194-208`, `http.rs:449`). Every subsequent request charges this counter before it can be served: the connection buffer at `http.rs:452`, each header read at `http.rs:484`, the parsed head at `http.rs:498`, the body at `http.rs:568`. When the counter is full, the **first** 8 KiB header read of any new request fails:

```rust
// http.rs:483-486
Ok(n) => {
    request_resident.reserve(n as u64)?;   // fails once the global budget is full
    buf.extend_from_slice(&chunk[..n]);
}
```

`handle_connection` maps that to a public 503 (`server.rs:617-645`). So unlike the P20-B spool-budget case (which denied only uploads and chunked requests), this budget is charged on the *read path of every request*, and exhaustion denies even `GET /` with no body.

### 3.3 The per-client caps do not stop a full-fill

`MAX_CONNECTIONS_PER_CLIENT = 32` (`server.rs:265`) would require four source addresses for 128 connections; but the trusted-proxy exemption (`per_client_connection_limit`, `server.rs:409-415`) grants the full process limit to any transport peer classified as internal/trusted (`config.rs:13389`), and the IPv6 quota key is a /64, not a host (`resource.rs:42-49`), so one delegated prefix supplies all six /64s. None of these caps limit how much of the shared byte budget one request may reserve once admitted.

### 3.4 The hold is refreshed, not extended

`http.rs:526-529` made the body deadline absolute ("Deriving it from an untrusted Content-Length let a huge declaration extend a worker lease for hours"), so an attacker cannot stretch a wave. The refresh period is simply shorter than the deadline: at the default 30 s, 128 × 71 bytes per 30 s is ~0.3 KiB/s.

---

## 4. Exploit chains

### 4.1 Multi-source (stock configuration)

1. The target serves any static file over plain HTTP (`bench/bench.py`-style config, defaults for workers/timeouts).
2. From 4–6 source addresses (or /64s) the attacker opens 32 connections each and sends, per connection and nothing else:

```http
POST /index.html HTTP/1.1
Host: p21.local
Content-Length: 1048434

```

`1048434 = 1048576 − 2 × 71` makes the reservation exactly 1 MiB including the double-charged head. Declaring 1 MiB for all of them and using the leftover headroom with smaller declarations works just as well; the arithmetic is not part of the vulnerability.
3. The first 128 reservations fill the 128 MiB budget; every request from every client then receives `503` until the body deadline.
4. Reconnect every ~20 s to keep the budget held. Release is immediate when the holds close.

### 4.2 One client behind a trusted reverse proxy

With `RemoteIPHeader X-Forwarded-For` and any internal/trusted proxy entry covering the transport peer (a normal LB deployment), the per-client connection cap is deliberately lifted; one source opens all 128+ connections and fills the budget. `adversarial/p21/exploit_p21.py C1` reproduces this with `RemoteIPTrustedProxy 127.0.0.1`.

### 4.3 One IPv6 customer

A delegated /56 or /48 yields hundreds of distinct /64s; six are enough. `exploit_p21.py C2` adds six temporary loopback /64s and reproduces the full outage from a single host.

---

## 5. Impact and preconditions

**Impact.** Complete denial of the HTTP service (every request, both adapters) with a client cost of ~9 KiB per 30 s window and no body bytes. Dynamic backends (CGI/FastCGI/proxy) are unreachable while held because dispatch is never reached. The 503 path is process-wide: it does not depend on the target URL, host, authentication, method or protocol. Any deployment whose free memory can coexist with normal traffic is affected; this is an availability bug, not a memory-exhaustion bug, so a host with gigabytes free is just as exposed.

**Preconditions.**

- Any listener and any request target; the default `MaxRequestWorkers 512`, default `HttpdRsMaxSpoolBytes`/`LimitRequestBody`, default `RequestReadTimeout body=30` are the worst case.
- 4–6 source addresses in a direct deployment; **one** source behind a trusted transport proxy; **one** IPv6 customer with a delegated prefix.
- No authentication, TLS, h2, cache, CGI/FastCGI/proxy or upload capability is needed. A POST to any URL is enough.

**Severity.** High — total remote, unauthenticated availability loss at negligible cost, with a same-class Apache differential (`200` throughout).

---

## 6. Relationship to P20 and prior findings

- **P20-B** (pass 20) identified that the spooler "reserves the declared `Content-Length` from the process-global `HttpdRsMaxSpoolBytes` budget before reading any body bytes" and recommended "reserve what is read, not what is declared … or reserve a bounded chunk and grow the reservation". The remediation (`b4b9192`) converted the >1 MiB identity path and the chunked path to the incremental `BodyAccumulator` and made the body deadline absolute, but the ≤1 MiB branch still reserves the declaration (and the later process-wide limits commit added `MAX_REQUEST_RESIDENT_BYTES`, which turned the residual reservation into a **total** outage rather than an upload-only denial). P21-A is the incomplete closure of the same class, not a new mechanism.
- **P20-A** (h2 body buffering) is fixed by the incremental adapter; P21-A does not need h2. P20-B's remaining spool-file/byte budgets are lower-impact siblings; P21-A is strictly stronger because it denies all traffic.
- **P19** (cache heap) is unrelated; P21-A holds zero bytes of body memory, so it is not a variant of it.

---

## 7. Reproduction

```sh
cargo build --release -p httpd-rs
python3 adversarial/p21/exploit_p21.py --keep        # groups A B C1 C2
python3 adversarial/p21/exploit_p21.py A             # Apache differential only
python3 adversarial/p21/exploit_p21.py C1 C2         # single-client variants
```

The final retained run produced **4/4 PASS**:

```text
PASS  P21-A header-only holds deny every request (Apache differs): 192 header-only holds;
      httpd-rs before/during/after = 200 / 503 / 200; apache before/during/after = 200 / 200 / 200
PASS  P21-B outage survives body-deadline waves for 60 s: [503, 503, 503, 503, 503, 503]; after release: 200
PASS  P21-C1 one client behind a trusted proxy fills the budget: 160 single-source holds; 200 / 503 / 200
PASS  P21-C2 one IPv6 customer rotating delegated /64s: 192 holds over 6 /64s; 200 / 503 / 200
```

Group A needs the local Apache 2.4 modules (`mpm_event`, `mod_reqtimeout`); it skips cleanly if `apache2` is absent. Group C2 temporarily adds six `2001:db8:0:N::1/64` addresses to `lo` and removes them afterwards; it skips without `NET_ADMIN`. All fixtures live under `/tmp/opencode/p21-harness`.

---

## 8. Suggested remediation direction

The product source was not changed for this pass.

- **Charge the in-memory identity path as-read.** Replace the up-front `request_resident.reserve(n)?` at `http.rs:568` with the same incremental policy as the spool/chunked/h2 paths: reserve a bounded prefix (or the bytes of each read) and grow the reservation with the body. This is the P20-B prescription applied to the last branch that still reserves a declaration; it alone removes the header-only hold.
- **Bound what a declaration may hold even if charged up front.** If a declared reservation is kept for scheduling reasons, cap it at a small fraction of the global budget (e.g., one per-connection share) so a single idle connection cannot convert the shared budget into a global gate. A separate headroom tier for small requests would also keep `GET /` from failing when large reservations fill the budget.
- **Keep the 503 mapping but make it proportional.** `OutOfMemory` → `503` (`server.rs:617`) is correct; the bug is that a zero-byte request can cause it for every other connection. Consider attributing the failure to the offending reservation (413 on the held request when its declaration cannot be admitted) and/or a per-client share so one client cannot starve the process.
- **Add a differential regression.** Hold 128 header-only declared bodies and assert (a) each hold's charged bytes equal the bytes actually read, (b) a concurrent `GET /index.html` still returns `200`, and (c) the Apache oracle agrees. The pass-20 regressions only covered the >1 MiB spool path, which is why this branch survived.
