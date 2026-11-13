# Pass 30 — one HTTP/1 client exhausts the process-wide blocking-I/O lease budget and denies every response over 64 KiB (HTTP/2 included)

- **Date:** 2026-11-02
- **Subject:** HEAD `b7767cd` (`Bound remaining P29-adjacent work`); no product
  source was edited.
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` (`mime`, `dir`, `authz_core`,
  `authz_host`), loopback only.
- **Harness:** `adversarial/p30/exploit_p30.py` — 8 differential verdicts
  (httpd-rs stall attack, refresh-cycle persistence, recovery, Apache oracle on
  the `bench/bench.py` shape); `adversarial/p30/exploit_p30_h2.py` — the
  HTTP/1-stall → HTTP/2 cross-protocol denial (`nghttp`).
- **Retained evidence:** `/tmp/opencode/p30-harness/` (fixtures, configs and
  per-server logs, kept with `--keep`), `adversarial/p30/exploit_p30_h2.py`
  (HTTP/1-stall → HTTP/2 denial, `nghttp` output), `/tmp/opencode/p30/probe14.py`
  (first version of that probe), `/tmp/opencode/p30/strace-vp11.log`
  (write-deadline expiry while the client keeps reading),
  `/tmp/opencode/p30/probe12.py` (default-`Timeout 60` 48/48 probe run).
- **Method:** prior-pass remediation review (P25-B/P26-B), source audit of the
  lease budget, then live Apache-versus-httpd-rs differentials and an
  HTTP/1-versus-HTTP/2 cross-protocol check on the project's own static
  benchmark configuration.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P30-A** | `serve_connection` takes one of the **32 process-wide** `blocking_reads` leases for every response with `body_len() > 64 KiB` and holds it until the whole body is written. 32 sockets from a **single IPv4 address** send a `GET` for a >64 KiB file, read only the response head, and never read the body. All 32 leases stay occupied for the full `Timeout` (default 60 s); every other response with a body above 64 KiB — static files, CGI/FastCGI output, proxied bodies, cache hits — is replaced by `503 Response memory capacity is temporarily exhausted` process-wide. Reissuing each held request every ~50 s (32 requests/minute, zero body bytes read) sustains the denial indefinitely. | victim `200` + full body on every probe (45/45) | victim `503` with the overload body on every probe (48/48) | remote unauthenticated denial of every >64 KiB response |
| **P30-A′** | The same counter is consumed by `h2::handle_stream` for **every HTTP/2 request dispatch** (`h2.rs:946`). While the plain-HTTP/1 stalls hold the budget, **all** HTTP/2 requests on any listener — including a 3-byte file — receive `503` (`request execution capacity exhausted`). An attacker speaking HTTP/1 on one listener can therefore take down HTTP/2 service on another. | h2 `200` | h2 `503` for every request | cross-protocol denial |
| **P30-B** (observation) | The write-stall deadline is renewed only when the server's socket write makes progress, not when the client reads. A legitimate client reading continuously but not opening the send window is aborted at exactly `Timeout` (`ppoll(...) = 0 (Timeout)` then `close`), contradicting the P26-B statement that "a progressing download is not truncated merely because its total duration exceeds `Timeout`". | continues | truncated at `Timeout` | availability regression and the reason P30-A is so cheap |

P30-A/P30-A′ are remote, unauthenticated, need no request body, no upload, no
CGI, no `.htaccess` and no non-default capability. They work on the plain
static `bench/bench.py` configuration with the default `Timeout 60` and default
worker counts.

---

## 2. Root cause

### 2.1 A whole-response lease with no client identity

`crates/server/src/server.rs`:

```rust
const LARGE_BLOCKING_RESPONSE: u64 = 64 * 1024;            // line 285
...
let large_response_lease = if resp.body_len() > LARGE_BLOCKING_RESPONSE {
    match cfg.resource_budget.try_blocking_read() {       // line 1197
        Ok(lease) => Some(lease),
        Err(_) => {
            resp = Response::memory_overload();           // 503
            None
        }
    }
} else {
    None
};
...
let body_sent = match write_response(stream, &mut resp, &opts) { ... };
drop(large_response_lease);                               // line 1237
```

`crates/server/src/resource.rs`:

```rust
pub const MAX_BLOCKING_READS: u64 = 32;                   // line 36

pub fn try_blocking_read(self: &Arc<Self>) -> io::Result<BlockingReadLease> {
    if !try_add(&self.blocking_reads, 1, MAX_BLOCKING_READS) {
        return Err(... "process-wide blocking-read limit reached");
    }
    ...
}
```

Every other process-wide work permit in this module has a per-client quota —
`try_dynamic_for` (`MAX_DYNAMIC_REQUESTS_PER_CLIENT`), `try_expensive`
(`MAX_EXPENSIVE_OPS_PER_CLIENT`), `try_websocket_for`
(`MAX_WEBSOCKETS_PER_CLIENT`), `try_h2_client_for`
(`MAX_H2_STREAMS_PER_CLIENT`). The blocking-read lease has none: one source
address can hold all 32. It is also taken for the **entire** response, not for
one blocked write, so it is not released until the body finishes or the
response is torn down.

### 2.2 Why the P25-B stall deadline does not bound occupancy

P25-B added a progress-renewed stall deadline (`http.rs` `write_socket_all`,
`sendfile_until`, `write_all_until`): when no byte has been written for
`Timeout` (default 60 s, `config.rs:4592`), the response is aborted and the
lease is released. That bounds each individual stalled response, but the
attacker does not need a permanent stall:

- the lease is held for the whole 60 s window even with zero reads;
- the request costs one connection and one ~60-byte request line;
- the holder reads only the response head, then sleeps;
- after ~50 s it closes the socket, immediately reconnects and re-requests.

The client socket close releases the server lease at the next write/poll
failure, and the replacement request re-acquires it within milliseconds. The
retained harness verifies the denial at t≈2 s and again at t≈62 s, after one
full refresh cycle (verdict A6).

### 2.3 HTTP/2 dispatch shares the same 32-slot counter

`crates/server/src/h2.rs`:

```rust
None => match cfg.resource_budget.try_blocking_read() {    // line 946
    Err(_) => (req, bad(503, "request execution capacity exhausted"), None),
    Ok(dispatch_lease) => { ... spawn_blocking(dispatch ...) }
}
```

Every HTTP/2 request dispatch takes a lease from the same counter (as do the
h2 file/stream chunk reads at lines 596/643). With all 32 leases held by
stalled HTTP/1 responses, any new HTTP/2 request is refused before dispatch,
regardless of its size. `probe14.py` shows `nghttp` receiving `:status: 503`
for `/small.txt` and `/big.bin` while the HTTP/1 stalls are held, and `200`
again after they are released.

---

## 3. Live evidence

### 3.1 Retained battery (`python3 adversarial/p30/exploit_p30.py --keep`)

Apache/2.4.69 on 127.0.0.1:19990 and httpd-rs on 127.0.0.1:19991, identical
static configuration, `Timeout 60`, 32 stalled holders from **127.0.0.2**:

```text
PASS  A1 pre-attack baselines: big=HTTP/1.1 200 OK(4194304B) medium=HTTP/1.1 200 OK(102400B) small=HTTP/1.1 200 OK
    victim /big.bin: HTTP/1.1 503 Service Unavailable (50 bytes) body=b'Response memory capacity is temporarily exhauste'
    victim /medium.bin: HTTP/1.1 503 Service Unavailable (50 bytes) body=b'Response memory capacity is temporarily exhauste'
    victim /small.txt: HTTP/1.1 200 OK (3 bytes)
PASS  A2 all 32 leases held by one source: holders reporting 200 after start=32/32; statuses=['HTTP/1.1 200 OK']
PASS  A3 victim >64 KiB response denied: big=HTTP/1.1 503 Service Unavailable(50B) medium=HTTP/1.1 503 Service Unavailable(50B)
PASS  A4 overload body identifies the lease budget: 503 body is the blocker's overload response, not a worker 503
PASS  A5 small responses stay served: small=HTTP/1.1 200 OK
PASS  A6 denial survives the refresh cycle: big at t~62s=HTTP/1.1 503 Service Unavailable(50B)
PASS  A7 recovery after stalls close: big=HTTP/1.1 200 OK(4194304B)
    victim /big.bin: HTTP/1.1 200 OK (4194304 bytes)
    victim /medium.bin: HTTP/1.1 200 OK (102400 bytes)
    victim /small.txt: HTTP/1.1 200 OK (3 bytes)
PASS  B1 Apache serves the same victims: big=HTTP/1.1 200 OK(4194304B) medium=HTTP/1.1 200 OK(102400B) small=HTTP/1.1 200 OK; holders=32 statuses=['HTTP/1.1 200 OK']

8/8 verdicts passed
```

`probe12.py`, a separate run with 40 holders across several loopback
addresses, probed every 0.25 s for 12 s at the same default `Timeout 60`:

```text
httpd-rs: victim during attack (big, medium): {('503', '503'): 48}
         victim small.txt: 200 OK (3B), holders_held=32
apache:  victim during attack (big, medium): {('200', '200'): 45}
```

### 3.2 Cross-protocol denial (`adversarial/p30/exploit_p30_h2.py`)

httpd-rs with a cleartext listener on 19993 and a TLS/h2 listener
(`Protocols h2 http/1.1`) on 19994; 32 stalled HTTP/1 responses on 19993 from
127.0.0.2:

```text
PASS  H1 HTTP/2 baselines: small.txt=200(stdout=2626B) big.bin=200
PASS  H2 32 HTTP/1 leases held: holders=32/32
PASS  H3 HTTP/2 dispatch denied during the stall: small.txt=503 big.bin=503
PASS  H4 HTTP/2 recovers after release: small.txt=200
```

### 3.3 The deadline is write-progress driven, not read-progress driven

Single slow reader, `Timeout 10`, 128 KiB every 5 s (`strace -e ppoll,sendfile,close`,
`/tmp/opencode/p30/strace-vp11.log`):

```text
09:03:05.598962 sendfile(12, 13, [2659776], 30894656) = -1 EAGAIN
09:03:05.599085 ppoll([{fd=12, events=POLLOUT}], 1, {tv_sec=9, ...}) = 0 (Timeout)
09:03:15.606646 close(13)
09:03:15.606692 close(12)
```

The client received data at t=5 s and t=10 s, yet the server's `ppoll` expired
once and the response was torn down. Renewal follows a successful server write,
so a stalled client and a very slow reader look the same to the lease budget.
The attacker does not even need to read anything to hold a lease for a full
`Timeout`.

---

## 4. Attack economics

- **One source address**, 32 TCP connections, one `GET` for any file over
  64 KiB per connection.
- Zero request body; the holder reads the response head and then stops.
- With default `Timeout 60`, reissue every ~50 s: **32 requests/minute**
  (~0.53 req/s) keeps all 32 leases occupied indefinitely.
- The server writes up to one socket-send-buffer worth of the file into each
  stalled socket before blocking; the attacker reads none of it.
- Recovery is immediate when the attacker stops: closing the sockets produces a
  write error, the lease is released, and the next victim request is served
  `200` (verdict A7).

## 5. Reachability and threat model

- **Configuration:** the stock static benchmark shape — `DocumentRoot`,
  `<Directory>` `Require all granted`, `AllowOverride None`, no capabilities,
  no CGI/FastCGI/proxy/cache. The conformance/feature-benchmark shapes are
  equally affected; the lease is process-wide and independent of TLS.
- **Preconditions:** one writable-socket source and any served object larger
  than 64 KiB (the static benchmark ships `large/1m.bin`; any normal site has
  assets, API payloads or proxy responses above 64 KiB).
- **Blast radius:** every HTTP/1 response with `body_len() > 64 KiB` on every
  listener and vhost, plus **all** HTTP/2 requests through the shared dispatch
  lease. Responses ≤64 KiB (health checks, error pages, redirects) continue to
  succeed, so the outage is silent to simple monitoring.
- **Apache:** `mpm_event` performs the same writes from its event loop, keeps
  no per-response global work permit of this kind, and served every victim
  request in the identical traffic (45/45 probes in `probe12.py` and 8/8
  verdicts in the retained battery).

## 6. Impact

- Remote, unauthenticated denial of service covering the most common
  production response class (assets, downloads, proxied and dynamic bodies
  above 64 KiB) for all clients of the process, from a single address with
  32 sockets.
- HTTP/2 service is denied entirely (including small responses) while the
  HTTP/1 attacker is active, regardless of which listener the attacker uses.
- The P25-B remediation's intent — a stalled writer cannot pin a connection
  worker indefinitely — is bypassed in aggregate: each response is still
  bounded by `Timeout`, but 32 cheap refreshes keep the global budget at zero
  with no per-client limit and no occupancy accounting.

## 7. Remediation direction

1. **Per-client quota for blocking-read leases.** Give `try_blocking_read` (or
   the `large_response_lease` acquisition) the same source-keyed accounting as
   `try_dynamic_for`/`try_expensive`/`try_websocket_for`, e.g. four leases per
   effective client, so one address can never occupy the whole budget.
2. **Scope the HTTP/1 lease to a blocked write.** Acquire the lease around the
   `poll`/`sendfile` wait rather than for the whole response (the h2 request
   reader already scopes its lease to one read), or release it while the
   response is making progress.
3. **Charge stalled lease occupancy to the source's worker quota.** A response
   that is stalled (or below a minimum progress rate) should count against the
   per-client worker/slow-body reserve, not only the response worker.
4. **Require a minimum progress rate, not "any progress ever".** Renew the
   stall deadline only when the transfer makes at least the configured
   `RequestReadTimeout`-style `MinRate` over the interval, so a single byte
   per `Timeout` cannot hold a slot.
5. **Keep HTTP/2 dispatch off the blocking-lease counter** or apply the same
   per-client quota there; an HTTP/1 attacker must not be able to refuse all
   HTTP/2 requests.
6. **Regression.** Add the retained two-window stall replay
   (`adversarial/p30/exploit_p30.py` A2/A3/A6/A7) and the HTTP/1-stall →
   HTTP/2-dispatch case (`adversarial/p30/exploit_p30_h2.py`) to the
   adversarial regression suite.

## 8. Reproduction

```sh
cd /root/httpd-rs
cargo build --release -p httpd-rs
python3 adversarial/p30/exploit_p30.py            # 8 verdicts (httpd-rs + Apache)
python3 adversarial/p30/exploit_p30.py A          # httpd-rs stall attack only
python3 adversarial/p30/exploit_p30.py --keep     # retain fixtures and logs

# Cross-protocol HTTP/1-stall -> HTTP/2 denial (httpd-rs only, needs nghttp):
python3 adversarial/p30/exploit_p30_h2.py
```

Minimal P30-A repro: the `bench/bench.py` static shape with the default
`Timeout 60`; 32 connections from one address request `/big.bin` (or any
>64 KiB object), read only the response head, then stall. A fresh client's
`GET /big.bin` and `GET /medium.bin` (100 KiB) return
`503 Response memory capacity is temporarily exhausted` while `GET /small.txt`
still returns `200`; Apache returns `200` with the full body for all three.

## 9. Retained files

- `adversarial/p30/exploit_p30.py` — the 8-verdict differential battery
  (httpd-rs stall attack, refresh-cycle persistence, recovery, Apache oracle;
  fixtures under `/tmp/opencode/p30-harness` when `--keep` is given).
- `adversarial/p30/exploit_p30_h2.py` — HTTP/1-stall → HTTP/2 (`nghttp`)
  cross-protocol denial harness with a generated self-signed certificate;
  fixtures under `/tmp/opencode/p30-h2-harness`.
- `/tmp/opencode/p30/probe14.py` — first version of the cross-protocol probe.
- `/tmp/opencode/p30/probe12.py` — default-`Timeout 60` 48/48 victim probe
  run with holder refresh.
- `/tmp/opencode/p30/strace-vp11.log` — `ppoll` timeout while the client is
  still reading, followed by `close`.
- `/tmp/opencode/p30/probe4.py`, `probe9.py`, `probe10.py`, `probe13.py` —
  stall/reconnect calibration and the single-address (127.0.0.2) variant.
