# Pass 22 — adversarial break of HEAD `5398493` (HTTP/2 zero-window response holds)

> Remediation status (2026-10-30): fixed in the current tree. File and stream
> responses wait for assigned HTTP/2 capacity before reading, allocate at most
> a 64 KiB chunk, and keep that chunk charged to the response-resident budget
> until h2 releases it. Blocking-read leases now cover one actual read only,
> never a flow-control wait. The two `zero_window_*` regressions pin both
> ordering and lease behavior.

- **Date:** 2026-10-30
- **Subject:** `target/release/httpd-rs` built at HEAD `5398493`. No product source was edited. The retained additions for this pass are `adversarial/p22/exploit_p22.py`, this write-up and the `adversarial/README.md` index entries.
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` with `mod_http2`, `mod_ssl` and `mod_proxy_http`, loopback only.
- **Harness:** `adversarial/p22/exploit_p22.py` — **3 verdicts** (A1 memory differential vs the Apache oracle, A2 memory-bounded process death, B global blocking-read lease pin), plus controls for files below the offload range, HTTP/1 and post-release recovery.
- **Retained evidence:** `/tmp/opencode/p22-harness` (fixtures, configs, TLS material, per-group stdout and server logs).
- **Method:** audit of the HTTP/2 response send path (`h2::send_response`) for work held across flow-control waits, followed by live zero-window `nghttp` differentials against `mod_http2` on the project's own TLS/h2 and `ProxyPass` configuration shapes.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P22-A** | `h2::send_response` materialises a file-style response body **before** it waits for flow-control capacity: for `256 KiB ≤ len ≤ 8 MiB` the complete representation is read into a `Bytes` (`h2.rs:600-648`) and then held by `send_data_bounded` while the client's stream/connection window is exhausted (`h2.rs:443-464`). That buffer is charged to **no** budget — the response-resident budget only covers `Body::Bytes`, and the body pool only bounds *free* buffers. 32 zero-window streams on **one** connection hold ~256 MiB of heap; the per-client ceiling (64 streams) holds ~512 MiB; the process-wide h2 ceiling (256 streams) holds ~2 GiB. Under an address-space bound the next 8 MiB allocation fails and `panic = "abort"` kills the whole process. | `mod_http2` streams the representation through its windowed output filter and stays flat: **+13–21 MiB** across runs over the identical 32 × 8 MiB zero-window load. | Peak RSS **+258 MiB** for 32 zero-window 8 MiB responses on one connection; 64 streams under `RLIMIT_AS=550 MiB` aborts with `memory allocation of 8388608 bytes failed`. HTTP/1, small files and > 8 MiB files are unaffected. | remote memory-exhaustion denial of service (whole-process under memory pressure) |
| **P22-B** | A `Body::Stream` response (proxied upstream body > 256 KiB) holds a **process-wide** `try_blocking_read` lease for the entire send (`h2.rs:566`). One h2 connection with 32 zero-window streams to any proxied large response pins all 32 leases for up to `Timeout` (60 s default, refreshable). Every other h2 response whose send needs a lease — static/cached/FastCGI **file bodies in the 256 KiB…8 MiB range** and every other streamed proxy response — fails `try_blocking_read()?` (`h2.rs:603`) and the stream is **reset**. HTTP/1 and h2 responses below 256 KiB keep working, which makes the failure look like a random download corruption to clients. | `mod_proxy_http` + `mod_http2` have no global read lease; the same attack leaves the static 8 MiB download and the proxied download at full `200`/8 MiB. | During the pin: static 8 MiB h2 download = `200 0` with curl exit 92 (stream error), server log `HTTP/2 stream failed: process-wide blocking-read limit reached`; small 128 KiB h2 file = `200 131072`; HTTP/1 = `200`; release → full `200 8388608`. | remote functional denial of a common response class (global lease starvation) |

Both findings are remote, unauthenticated and reachable with the supported TLS + ALPN `h2` configuration. P22-A needs only a static file in the offload range; P22-B additionally needs one `ProxyPass` route that can return a body above 256 KiB (the project's own proxy benchmark shape).

---

## 2. Observed evidence

All groups run loopback-only under `/tmp/opencode/p22-harness`; fixtures are `www/8m.bin` (8 MiB), `www/small.bin` (128 KiB) and a threaded local upstream that serves an 8 MiB `Content-Length` body. The attack is `nghttp -w 0 -W 0 -t 0 -m 32` — `SETTINGS_INITIAL_WINDOW_SIZE = 0`, connection window 0, no client timeout, 32 concurrent streams.

### 2.1 P22-A1 — one connection holds ~256 MiB, Apache holds ~13–21 MiB

```
PASS  P22-A1 h2 zero-window holds full response bodies uncharged:
      32 zero-window streams of 8 MiB: httpd-rs peak rss +258 MiB
      (1 connection, ceiling ~256 MiB); apache mod_http2 +21 MiB
```

Per-stream calibration: the whole 8 MiB body is read before the first capacity wait, so the 32 streams hold `32 × 8 MiB`. A client does not even need to zero the window: any client that stops reading stalls the send after the initial window is consumed and still keeps the full body in `data`; `-w 0` only makes it immediate and deterministic.

### 2.2 P22-A2 — memory-bound process death

```
PASS  P22-A2 h2 zero-window memory-bound process death:
      64 streams x 8 MiB under RLIMIT_AS=550 MiB; exited=True, allocator abort=True
```

Two h2 connections from the same client (2 × 32 streams = the per-client ceiling of 64) reach ~512 MiB; the allocator log is the same whole-process abort as P19/P20:

```text
memory allocation of 8388608 bytes failed
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

The per-client stream ceiling is `MAX_H2_STREAMS_PER_CLIENT = 64`; four IPv4 sources (or four delegated /64s) reach the process-wide `MAX_H2_STREAMS = 256`, i.e. ~2 GiB held at once. The hold is release-bounded by `send_timeout = Timeout.max(5 s)` (60 s default), so a re-armed wave keeps it up indefinitely at zero response bytes read.

### 2.3 P22-B — one connection resets every 256 KiB…8 MiB h2 download

```
PASS  P22-B h2 zero-window streams pin all 32 blocking-read leases:
      before: static='200 8388608' proxy='200 8388608';
      during: static='200 0' (rc 92), small h2='200 131072',
              HTTP/1='HTTP/1.1 200 OK';
      after='200 8388608'; server lease failures=1;
      apache during: static='200 8388608' (rc 0), before='200 8388608'
```

The server log line for the reset stream:

```text
[core:error] [pid ...] HTTP/2 stream failed: process-wide blocking-read limit reached
```

The attacker's 32 streams are requests to `/p/big.bin` (the `ProxyPass` route); the pinned leases deny *unrelated* static file responses in the same size band. `small.bin` (128 KiB, inline read path) and the plain HTTP/1 listener are the controls that keep working, confirming the denial is the per-send lease, not general connection saturation. Release is immediate.

---

## 3. Root cause

### 3.1 The h2 response writer reads the body before waiting for capacity, uncharged

`crates/server/src/h2.rs` (HEAD `5398493`), `Body::File` arm:

```rust
const OFFLOAD_MIN: u64 = 256 * 1024;
const OFFLOAD_MAX: u64 = 8 * 1024 * 1024;
if len >= OFFLOAD_MIN && len <= OFFLOAD_MAX {
    let blocking_read = cfg.resource_budget.try_blocking_read()?;
    let data = tokio::task::spawn_blocking(move || -> io::Result<Bytes> {
        let _blocking_read = blocking_read;          // released when the read returns
        ...
        let buf = read_range(&file, offset, len as usize)?;   // FULL body allocation
        ...
    }).await...;
    sent = data.len() as u64;
    send_data_bounded(&mut send, data, true, send_timeout).await?;   // held across the wait
}
```

`send_data_bounded`/`send_capacity` (`h2.rs:398-464`) wait for `poll_capacity` until `send_timeout = cfg.timeout.max(5 s)` (`h2.rs:551`). The `data` `Bytes` is alive for the whole wait. Nothing reserves that allocation:

- `Response::admit_resident` (`http.rs:1049-1063`) only charges `Body::Bytes`; file bodies return early, and the h2 read happens after dispatch;
- the per-stream `h2::BodyAccumulator` and the request/response resident leases are not involved;
- `POOL_MAX_TOTAL = 128 MiB` (`h2.rs:211`) bounds only the *free pool* (`PooledBuffer::drop`, `h2.rs:248-265`); a live buffer sits outside the pool;
- `try_blocking_read` (`resource.rs:210`, `MAX_BLOCKING_READS = 32`) is a concurrency gate around the read call, not a byte accounting, and is dropped before the wait.

For `len > OFFLOAD_MAX` the writer batches 1 MiB at a time (`h2.rs:649-669`) — still holding a batch across each capacity wait, but the 256 KiB…8 MiB range is where the whole body is materialised. That is also the most common download band, and the same path serves static files, cached disk bodies and FastCGI/CGI spool files.

### 3.2 The blocking-read lease is held across the send wait

`h2.rs:565-594`, `Body::Stream` arm:

```rust
Body::Stream { mut reader, len } => {
    let _blocking_read = cfg.resource_budget.try_blocking_read()?;   // held for the WHOLE response
    let mut left = len;
    while left > 0 {
        ... spawn_blocking read of <=64 KiB ...
        send_data_bounded(&mut send, ..., left == 0, send_timeout).await?;   // can wait 60 s
    }
}
```

`Body::Stream` is produced for proxied upstream responses with a fixed `Content-Length > 256 KiB` (`proxy.rs:2210-2237`). With a zero window, the first `send_data_bounded` waits and the lease is held. Thirty-two such streams on one connection consume all `MAX_BLOCKING_READS = 32` leases. Any other h2 response that needs one then fails its own `try_blocking_read()?` — the static `Body::File` offload at `h2.rs:603` and every additional streamed proxy response — and `send_response` returns `Err`, which `handle_stream` turns into a stream reset (`h2.rs:889-896`). The 32-stream per-connection allowance makes the entire attack one connection; the refresh period is the same 60 s send timeout.

The lease pins are the same object used to keep 8 MiB offload reads off the connection runtime, so the denial is precisely aimed at the 256 KiB…8 MiB h2 response path.

---

## 4. Exploit chains

### 4.1 P22-A — memory hold / whole-process abort

1. Target serves TLS with ALPN `h2` (the benchmarked HTTPS configuration) and any static, cached or FastCGI file between 256 KiB and 8 MiB.
2. One connection, 32 streams, `SETTINGS_INITIAL_WINDOW_SIZE = 0`, requests for the 8 MiB file; do not read.
3. The server reads 32 × 8 MiB into heap and waits for capacity for up to 60 s. Peak +258 MiB measured; a second connection reaches the 64-stream per-client ceiling (+512 MiB); four sources reach the 256-stream process ceiling (~2 GiB). On a host/container that cannot absorb the spike the allocator aborts the process.
4. No response bytes are consumed and no request body is sent; re-arm every < 60 s.

### 4.2 P22-B — one connection resets every mid-size h2 download

1. Target has an h2 listener and at least one `ProxyPass` route whose backend can return a fixed-length body > 256 KiB (a normal app download/API route).
2. One connection, 32 streams, zero window, requests to that route. All 32 global blocking-read leases are pinned for up to `Timeout`.
3. While pinned, every h2 download whose send needs a lease — static, cached and FastCGI file bodies of 256 KiB…8 MiB anywhere on the server, and every other streamed proxy response — is reset (`curl` exit 92, `HTTP/2 stream error`; server log `process-wide blocking-read limit reached`).
4. Files below 256 KiB and above 8 MiB, and all HTTP/1 traffic, are unaffected; refreshing every < 60 s sustains the class denial.

---

## 5. Impact and preconditions

**P22-A.** Remote memory-exhaustion DoS. Precondition: a TLS h2 listener and any file/representation in the 256 KiB…8 MiB band. No proxy, cache, CGI or authentication required. Single source per 512 MiB; four sources for the full ~2 GiB ceiling. A host with sufficient free memory survives with a large temporary spike; a memory-bounded host/container aborts the whole process because `panic = "abort"`.

**P22-B.** Remote functional DoS of a common response class. Precondition: a TLS h2 listener plus one proxy route able to return > 256 KiB (the benchmark `ProxyPass` shape). One source, one connection; mid-size downloads across the whole server fail with stream errors while HTTP/1 and small files stay up, so clients experience it as corrupted/aborted large downloads.

**Severity.** P22-A High (whole-process abort on memory-constrained hosts; up to 2 GiB held from four sources). P22-B Medium–High (sustained reset of the 256 KiB…8 MiB h2 response class and all streamed proxy responses).

---

## 6. Relationship to prior findings

- **P20-A** was *request*-body heap on the h2 adapter and was fixed by the incremental `BodyAccumulator`. **P22-A is the response side of the same design gap**: the writer materialises what it should stream, and the materialised bytes are not covered by the budget introduced for the request side.
- **P21-A** starved the *request*-resident budget with declared bodies; **P22-A** holds *response* bodies that are charged to nothing at all, so no budget needs to be filled first.
- **P22-B** is a distinct primitive: a process-wide concurrency lease taken for one response held across a flow-control wait. It is not a byte budget and cannot be triggered by P21 or P22-A (which do not touch the blocking-read lease for the duration of the wait).
- **P12-D** was a request-body window stall; P22 uses application-controlled zero windows on the response direction.
- The `offload` read design exists to keep the current-thread runtime free; P22-A shows it also creates an unaccounted copy of every 256 KiB…8 MiB body, and P22-B shows the lease that protects the runtime is itself globally starvable.

---

## 7. Reproduction

```sh
cargo build --release -p httpd-rs
python3 adversarial/p22/exploit_p22.py --keep     # groups A B
python3 adversarial/p22/exploit_p22.py A          # memory hold + RLIMIT kill
python3 adversarial/p22/exploit_p22.py B          # lease pin + Apache oracle
```

The final retained run produced **3/3 PASS**:

```text
PASS  P22-A1 h2 zero-window holds full response bodies uncharged: 32 zero-window streams of 8 MiB:
      httpd-rs peak rss +258 MiB (1 connection, ceiling ~256 MiB); apache mod_http2 +21 MiB
PASS  P22-A2 h2 zero-window memory-bound process death: 64 streams x 8 MiB under RLIMIT_AS=550 MiB;
      exited=True, allocator abort=True
PASS  P22-B h2 zero-window streams pin all 32 blocking-read leases: before: static='200 8388608'
      proxy='200 8388608'; during: static='200 0' (rc 92), small h2='200 131072',
      HTTP/1='HTTP/1.1 200 OK'; after='200 8388608'; server lease failures=1;
      apache during: static='200 8388608' (rc 0), before='200 8388608'
```

The harness needs `nghttp` and `openssl`; the oracle needs `mod_http2`, `mod_ssl`, `mod_socache_shmcb` and (for B) `mod_proxy_http`. Missing pieces skip cleanly. All fixtures live under `/tmp/opencode/p22-harness`.

---

## 8. Suggested remediation direction

The product source was not changed for this pass.

**P22-A — never materialise more than the flow-control capacity can take.**

- Reserve send capacity first (or a bounded chunk of it), then read at most that many bytes from the file into the chunk being sent; repeat per iteration. The current shape reads the whole body and *then* asks for capacity.
- If a full-body read is kept for the offload path, charge it against `MAX_RESPONSE_RESIDENT_BYTES` (the same lease as `Body::Bytes`) so the existing 503 overload path bounds it, and add live (not just free-pool) buffers to the pool accounting.
- Consider lowering `OFFLOAD_MAX` or applying the same treatment to the > 8 MiB batch path so no response body sits outside a budget while waiting.

**P22-B — do not hold the global blocking-read lease across the send wait.**

- Scope `try_blocking_read` to each individual read call (as the `Body::File` offload already does) instead of the whole `Body::Stream` response, so a stalled client releases the lease between chunks; the read still runs on the blocking pool.
- Alternatively make the lease per-connection or per-client, and fail only the offending stream when the process is saturated, rather than resetting unrelated responses.
- A stalled `Body::Stream` could also be handled like a spooled response (bounded file) instead of an open upstream connection.

**Regression coverage.**

- Add a zero-window h2 differential: while 32 stalled streams hold 8 MiB responses, (a) RSS must stay within a bounded delta, (b) a concurrent h2 `GET` of a 256 KiB…8 MiB file must still complete, and (c) the Apache `mod_http2` oracle must agree. Cover both the static-body path and the `Body::Stream` overlay.
