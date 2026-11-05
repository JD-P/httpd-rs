# Pass 32 — HTTP/2 request-body waits retain the process-wide 256-stream dispatch pool; eight sources deny every other client by rolling replacement

- **Date:** 2026-11-03
- **Subject:** HEAD `e1251ec` (`target/release/vapached`; no product source was
  edited).
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` + `mod_http2` + `mod_ssl`,
  loopback only.
- **Harness:** `adversarial/p32/h2bodyhold.py` (TLS/h2 fixture, partial-body
  holder and victim probe), `adversarial/p32/rolling.py` (immediate refill of
  expired body streams), `adversarial/p32/waves.py` (wave and threshold
  controls), `adversarial/p32/oracle_apache.py` (the same 256-body hold against
  Apache). Retained run output: `adversarial/p32/results_p32.txt`.
- **Method:** source audit of HTTP/2 stream admission and the request-body read
  path, then live Apache-versus-vapached differentials using Python `h2` and
  the project's TLS/h2 configuration shape. All traffic is loopback.
- **Remediation status:** open at HEAD. A stream waiting for request-body DATA
  still owns one of the 256 general HTTP/2 stream leases. The P31 slow-output
  transfer covers only downstream response stalls, not slow request input.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | vapache HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P32-A** | `admit_stream_before_spawn` acquires a process-wide `H2Stream` lease before dispatch (`MAX_H2_STREAMS = 256`). An HTTP/2 request with `Content-Length: 1000` and no DATA then enters `read_body` while still holding that lease; the lease is stored in `SlowOutputAdmission`, which transfers only on a **downstream output** stall. Eight source addresses × one TLS/h2 connection × 32 partial bodies fill all 256 slots. The body deadline releases one stream at `Timeout`, but the attacker immediately opens a replacement, at roughly 4–9 new stream heads per second. A separate-source victim is refused with `RST_STREAM REFUSED_STREAM` (error 7) before routing for every probe. | victim `200` for every probe while 256 CGI bodies are held | victim refused for 750/750 probes over 150 s; recovery immediate on release | remote cross-client denial of all HTTP/2 service |

The holders send only request headers. No DATA frame, no completed upload, no
response read, no `.htaccess`, and no dynamic backend connection is required
after routing. The cost is eight idle TLS connections and a low-rate stream
replacement loop.

The attack is available whenever the configuration has at least one
body-capable handler, i.e. `Config::body_handlers_possible()` is true
(proxy, CGI, FastCGI, handler/alias, or rewrite-to-handler), and at least one
reachable route reads or drains the body. A configuration with no body
handlers rejects every request body before reading it and is not affected.
The harness uses `ProxyPass "/hold"` only to make the body bit true; the target
path can be any route that reads or drains the body. With the bit true, even a
`GET` with a declared body to a static 200 file enters the drain path and
waits for DATA.

---

## 2. Root cause

### 2.1 The general stream lease is acquired before routing and body ingestion

`crates/server/src/h2.rs` (HEAD `e1251ec`):

```rust
// admit_stream_before_spawn() — h2.rs:884-943
let resource_context = cfg.resource_budget.context(quota_peer.ip());
let stream_quota = cfg.resource_budget.try_h2_stream_in(&resource_context)?;
...
Ok(H2StreamAdmission { ..., stream_quota })
```

`try_h2_stream_in` charges the process-wide stream ledger
(`crates/server/src/resource.rs:2043-2055`) with
`MAX_H2_STREAMS = 256` and `MAX_H2_STREAMS_PER_CLIENT = 64`
(`resource.rs:211-212`). The connection advertises 32 concurrent streams
(`verified/src/lib.rs:11274`), so one connection can legally hold 32 and four
source keys can hold the whole pool with two connections each.

The lease is moved into the slow-output admission object at the start of
`handle_stream`:

```rust
// h2.rs:962-969
let H2StreamAdmission { ..., stream_quota } = admission;
let mut output_admission =
    crate::resource::SlowOutputAdmission::tracked_h2(resource_context.clone(), stream_quota);
```

That object is alive for the whole handler, including the body read and the
possibly slow routing probe. Its only transfer out of the general pool is
`enter_slow_with`, called when response output cannot obtain flow-control
capacity:

```rust
// resource.rs:2662-2685
pub(crate) fn enter_slow_with(...) -> io::Result<()> {
    ...
    let slow = self.context.budget().try_slow_output_in(&self.context)?;
    transfer()?;
    ...
    drop(self.general.take());          // general H2 lease released here
    Ok(())
}
```

`read_body` and `stream_body` never call that path. The buffered body read runs
before dispatch, and both body paths run before any response output exists:

```rust
// h2.rs:1501-1532 (buffered body path)
let body_result = {
    let body_future = read_body(
        recv.take().expect("body route retained its receive stream"),
        max_body,
        body_timeout,
        cfg.request_body_min_rate,
        ...
    );
    ...
    tokio::select! {
        biased;
        _ = &mut reset_watch => return true,
        result = &mut body_future => result,
    }
};
```

The `output_admission` value is still in scope and still owns the `H2Stream`
lease. It is not released when the body read starts; on the normal path it is
dropped when `handle_stream` returns after sending the response
(`h2.rs:1705-1706`). A stream waiting for request DATA is therefore
indistinguishable, for global admission purposes, from a stream actively
dispatching work.

There is an equivalent streaming path for declared bodies above
`MAX_REQUEST_BODY_IN_MEMORY` (`h2.rs:1385-1433`). It starts the backend before
reading the body but still holds the same general lease while `stream_body`
waits. The 256-body fixture uses the buffered path.

### 2.2 The body deadline is absolute per stream, but replacement is cheap

`read_body` correctly uses one absolute deadline for the whole body
(`h2.rs:359-367`):

```rust
let started = Instant::now();
loop {
    let remaining = timeout.saturating_sub(started.elapsed());
    let next = match tokio::time::timeout(remaining, recv.data()).await {
        Ok(next) => next,
        Err(_) => return Err(H2ReadFailure::Response(bad(408, "request body timeout"))),
    };
    ...
}
```

The default is 30 seconds (`config.rs:4780`); `Timeout 60` sets it to 60
(`config.rs:7752-7756`), and `RequestReadTimeout ... body=...` can set another
value (`config.rs:7920-7937`). The attacker cannot renew one stream the way
P31 renewed a response send deadline. The denial is instead a **standing
wave**: when a stream times out and releases its lease, the attacker opens a
replacement on the same connection. At 60 seconds, 256/60 ≈ 4.3 new streams/s
sustain the full pool; at the 30-second default it is 256/30 ≈ 8.5/s. A
single connection can open its 32 replacements in one small burst.

No DATA is needed. Each holder stream consists of a HEADERS frame with
`:method POST`, `:path /hold`, and `content-length: 1000`; the stream is left
open. The body accumulator has no payload to spool, the request never reaches
the proxy backend, and the only eventual response is a small 408.

### 2.3 Process-wide refusal before dispatch

When all 256 general leases are held, admission of a new stream from any other
client fails in `serve` (`h2.rs:1928-1933`):

```rust
let admission = match admit_stream_before_spawn(&cfg, peer, &request) {
    Ok(admission) => admission,
    Err(_) => {
        respond.send_reset(h2::Reason::REFUSED_STREAM);   // error 7
        continue;
    }
};
```

The victim's own 64-stream client quota is untouched. The refusal is the
process-wide 256-lease pool, so it applies to every HTTP/2 listener and vhost
in the process, including tiny bodiless GETs. HTTP/1 has a separate admission
path and remains available, so an HTTP/1 health check need not notice the
HTTP/2 outage.

### 2.4 Precondition: body handling must be enabled

The adapter rejects a body before routing when no configured route can consume
one (`h2.rs:1208-1237`; `Config::body_handlers_possible`,
`config.rs:3017-3065`). Thus a purely static configuration is not vulnerable:
its request-body requests get 400/405 without entering `read_body`.

Once the global bit is true, the request is routed before the body is read
(`h2.rs:1256-1291`). `probe_request_body` returns `Read` for a prepared dynamic
handler and `Drain` for a successful static response
(`server.rs:3844-3869`). Both paths read the body. The fixture's
`ProxyPass "/hold" "http://127.0.0.1:1/"` supplies the bit and a
body-consuming route; a static `GET` with a body to a 200 file also reaches
the drain path when the bit is already true. The attack therefore targets any
deployment with proxy/CGI/FastCGI or another body handler enabled, not just
the exact `/hold` endpoint.

### 2.5 Contrast: the HTTP/1 path already separates body waits

The HTTP/1 side has exactly the ownership split that HTTP/2 lacks. A
`RequestBodyWorker` slot is a separate, much smaller pool:

```rust
// server.rs:539-586
fn body_worker_limit(worker_limit: usize) -> usize {
    (worker_limit.max(1) / 4).clamp(1, 128)
}
fn try_reserve_body_worker(context, limit) -> Option<BodyWorkerGuard> {
    let body_limit = body_worker_limit(limit);
    let client_limit = (body_limit.saturating_add(3) / 4).max(1);
    try_reserve_quota(context, SlotKind::RequestBodyWorker, body_limit, client_limit)
}
```

The body slot is acquired before the general worker slot
(`server.rs:2471-2487`), and the general `WorkerGuard` is dropped when the
short blocking dispatch phase returns. The actual wait for request DATA then
runs in `read_request_body_async` (`server.rs:2643-2676`) holding only the
`BodyWorkerGuard`. A slow HTTP/1 upload therefore consumes the 128-process,
source-fair slow-body pool, not the general request-worker pool, and unrelated
bodiless requests keep the general capacity. HTTP/2 does the opposite: the
body wait keeps the general 256-slot lease and has no body/slow-input sibling
pool at all. That is the missing piece this pass demonstrates live.

---

## 3. Live evidence

All runs use `target/release/vapached` at HEAD `e1251ec`, TLS/h2 on
`127.0.0.1:19994`, one connection per source address, and 32 partial bodies
per connection. The fixture sets `Timeout 60` except in §3.3, which uses the
stock 30-second body timeout. Holders bind `127.0.0.2` through `127.0.0.9`;
the victim uses the otherwise idle loopback source `127.0.0.1`. Full output is
retained in `adversarial/p32/results_p32.txt`.

### 3.1 Full pool, 150-second rolling run

`python3 adversarial/p32/rolling.py --measure-seconds 150 --probe-interval 0.2`:

```text
baseline: status=b'200' reset=None terminated=None body=10
pool filled: active=256 opened=256 victim=status=None reset=7 terminated=None body=0
rolling: probes=750 refused=750 served=0 other=0 refusal_ratio=1.000 max_served_gap=0.00s active=256 opened=768 408s=512 resets=512
after release: status=b'200' reset=None terminated=None body=10
```

`reset=7` is `REFUSED_STREAM`. The pool stayed at `active=256` while the
attacker opened 512 replacement streams and the server produced 512 body
timeouts. The victim was refused in all 750 probes over 150 seconds; after
release it was served immediately.

### 3.2 Repetition

The 90-second run gave the same result, with 180/180 refusals:

```text
pool filled: active=255 opened=256 victim=status=b'200' reset=None terminated=None body=10
rolling: probes=180 refused=180 served=0 other=0 refusal_ratio=1.000 max_served_gap=0.00s active=256 opened=513 408s=256 resets=257
```

### 3.3 Stock default body timeout

`python3 adversarial/p32/rolling.py --timeout 30 --measure-seconds 75 --probe-interval 0.2`
rewrites the fixture's `Timeout` to 30, matching the binary's stock default
body timeout, and measures across two complete timeout cycles:

```text
pool filled: active=255 opened=256 victim=status=b'200' reset=None terminated=None body=10
rolling: probes=375 refused=373 served=2 other=0 refusal_ratio=0.995 max_served_gap=0.20s active=256 opened=770 408s=512 resets=514
after release: status=b'200' reset=None terminated=None body=10
```

The pool was refilled through 512 body timeouts, and the victim was refused in
373 of 375 probes over 75 seconds; the largest interruption in the refusal
stream was 0.20 s, i.e. roughly the time between one timeout and its
replacement. The primitive does not depend on the `Timeout 60` fixture
override.

### 3.4 Threshold control

The threshold control held 7 sources × 1 connection × 32 = 224 streams, below
the 256-slot pool, using the same rolling harness for 35 seconds:

```text
pool filled: active=221 opened=224 victim=status=b'200' reset=None terminated=None body=10
rolling: probes=175 refused=0 served=175 other=0 refusal_ratio=0.000 max_served_gap=0.00s active=224 opened=227 408s=0 resets=3
```

The victim was served in all 175 probes. The denial begins when the process
pool, not the victim's own source quota, is exhausted.

### 3.5 Apache oracle

`python3 adversarial/p32/oracle_apache.py` holds the same 8×32 = 256 partial
request bodies against Apache/2.4.69 `mpm_event`, `mod_http2`, `mod_ssl`, and a
CGI handler that blocks reading stdin, with `MaxRequestWorkers 512`:

```text
baseline: status=b'200' reset=None terminated=None body=10
held: sent=256 active=256 ended=0 statuses=[{}, {}, {}, {}, {}, {}, {}, {}]
t=0s victim=status=b'200' reset=None terminated=None body=10
t=5s victim=status=b'200' reset=None terminated=None body=10
t=10s victim=status=b'200' reset=None terminated=None body=10
t=15s victim=status=b'200' reset=None terminated=None body=10
t=20s victim=status=b'200' reset=None terminated=None body=10
t=25s victim=status=b'200' reset=None terminated=None body=10
t=30s victim=status=b'200' reset=None terminated=None body=10
t=35s victim=status=b'200' reset=None terminated=None body=10
after release: status=b'200' reset=None terminated=None body=10
```

Apache kept serving a fresh source while the same count of request bodies was
held. This oracle demonstrates the specific difference in pool structure: an
h2 stream waiting for input is not a process-wide 256-slot lease. It is not a
claim that Apache cannot be exhausted by a larger number of blocking workers.

---

## 4. Attack economics and preconditions

- **Preconditions:** an HTTP/2 listener (the project default),
  `body_handlers_possible == true` (any ProxyPass/CGI/FastCGI/handler/alias
  configuration), and a reachable route that reads or drains the body (a
  successful static file is enough once the bit is true). A purely static
  configuration is immune because it rejects request bodies before routing.
  The project's own application benchmark shape satisfies this: it configures
  `ProxyPassMatch ... fcgi://` for PHP and `ProxyPass /app` for a Gunicorn
  proxy (`bench/app_bench.py:170-195`), so `body_handlers_possible` is true in
  the benchmarked deployment.
- **Resources:** eight TCP/TLS connections, eight source addresses (or four
  addresses with two connections each), 256 request heads on fill, and no DATA
  frames. Sustained cost is roughly 4–9 stream heads/s depending on the body
  timeout, about 0.5–1 KB/s, plus eight idle sockets and small 408 responses.
  No request body is spooled and no backend connection is made.
- **Source limits:** the h2 connection advertises 32 streams; the process
  per-client cap is 64. Four source keys × two connections, or eight keys ×
  one connection, reach 256. An IPv6 `/64` counts as one key.
- **Blast radius:** every new HTTP/2 stream on every listener and vhost is
  refused before routing, regardless of the victim's address or request size.
  HTTP/1 remains available.
- **Recovery:** immediate when the holders close. If they stop replacing,
  existing streams release at their absolute body deadline.

Raising the body timeout does not remove the primitive; it only lowers the
replacement rate. Lowering the timeout raises the request rate but does not
free the general pool for the victim while replacements continue.

---

## 5. Relationship to prior passes

P22-A held the 256 stream slots with zero-window response bodies and reported
the impact as unaccounted response memory. P31-A showed that a response
deadline could be renewed with one byte of `WINDOW_UPDATE`, and that exhausting
the pool makes unrelated HTTP/2 requests fail with `REFUSED_STREAM`. The P31
remediation introduced the 128-process/32-per-source slow-output pool and
transfers flow-control-blocked **responses** out of the general stream pool.

P32 is the missing input-side half of the same ownership problem. The P31
transfer is only triggered from `send_capacity` after a response body is being
written (`h2.rs:530-565`, `resource.rs:2662-2685`). A stream that has completed
its headers and is still waiting for request DATA never reaches that code, so
it continues to hold the general lease. The body deadline is already absolute
and cannot be renewed, but the stream pool has no separate slow-input reserve
and no source-fair admission for body waiters. The HTTP/1 path already has the
intended split (`RequestBodyWorker`, §2.5); HTTP/2 has no equivalent slot kind
(`SlotKind::H2Stream` and `SlotKind::SlowOutput` are the only H2 classes).
Thus the P31 fix does not regress; it simply does not cover the earlier phase.

P30-A/A′ was the blocking response-read dispatch permit and is fixed. The
`H2Stream` lease is a separate ledger, and `read_body` does not acquire the
response-read permit.

---

## 6. Remediation direction

1. **Transfer body-waiting streams out of the general dispatch pool.** After
   the route probe decides that the body must be read or drained, move the
   `H2Stream` lease into a separate source-fair request-body/slow-input pool
   before the first `recv.data()` wait. The general 256-slot pool should then
   be available to unrelated bodiless requests while the upload is pending.
2. **Give the slow-input pool its own process and per-source ceilings.** A
   shape analogous to the slow-output pool (for example 128 process-wide and
   32 per source, with a reserved general-dispatch fraction) bounds memory and
   connection state without letting one source consume the entire dispatch
   reserve. Do not simply raise `MAX_H2_STREAMS`: the victim would still be
   competing with 256 idle upload streams.
3. **Keep the absolute body deadline and minimum-rate check.** The existing
   whole-body deadline is correct and prevents a single stream from being held
   forever. The missing property is ownership: a stream waiting for input must
   not count as a dispatch-capable stream.
4. **Handle transfer failure explicitly.** If the slow-input pool is full,
   return a bounded 503/408 response and release the general lease; never leave
   the stream parked in the general pool with no timeout.
5. **Regression tests.** With 256 partial bodies outstanding, an unrelated
   client's bodiless h2 GET must still be admitted and receive `200`. Replacing
   timed-out streams at the measured rate must not produce
   `REFUSED_STREAM`. The 224-stream control must continue to serve the victim,
   and the retained rolling/Apache harnesses should be kept as the live
   differential.

---

## 7. Reproduction

```sh
cd /root/vapache
cargo build --release -p vapached

# Full pool, rolling replacement, separate-source victim.
python3 adversarial/p32/rolling.py --measure-seconds 150 --probe-interval 0.2

# Stock default 30-second body timeout across two timeout cycles.
python3 adversarial/p32/rolling.py --timeout 30 --measure-seconds 75 --probe-interval 0.2

# Threshold control: 224 streams, below the 256-slot process pool.
python3 adversarial/p32/rolling.py --sources 7 --per-source 32 \
    --measure-seconds 35 --probe-interval 0.2

# Apache 2.4.69 oracle with the same 256 blocked request bodies.
python3 adversarial/p32/oracle_apache.py
```

`python3-h2` is required for the client (`apt-get install python3-h2`). The
fixture writes its config, certificate, document root, and logs under
`/tmp/opencode/p32-h2bodyhold`; the Apache oracle uses
`/tmp/opencode/p32-apache`.

## 8. Retained files

- `adversarial/p32/h2bodyhold.py` — shared TLS/h2 fixture, partial-body holder,
  victim probe, and source binding.
- `adversarial/p32/rolling.py` — immediate replacement of timed-out body
  streams and refusal-rate measurement; `--timeout` selects the fixture body
  timeout (used for the stock 30-second run).
- `adversarial/p32/waves.py` — wave-based hold/release and threshold controls.
- `adversarial/p32/measure.py` — earlier steady-state measurement harness.
- `adversarial/p32/oracle_apache.py` — the same 256-body hold against
  Apache/2.4.69 `mpm_event` + `mod_http2` + CGI.
- `adversarial/p32/results_p32.txt` — retained output for the 90 s, 150 s, and
  stock-30 s rolling runs, the 224-stream control, and the Apache oracle.
