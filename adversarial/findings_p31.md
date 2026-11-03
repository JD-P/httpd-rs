# Pass 31 — HTTP/2 stream-slot hold made permanent by flow-control renewal; eight source addresses deny all HTTP/2 to every other client

- **Date:** 2026-11-03
- **Subject:** HEAD `9c595e7` (`target/release/vapached`; no product source was
  edited).
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` + `mod_http2` + `mod_ssl`,
  loopback only.
- **Harness:** `adversarial/p31/h2hold.py` (shared TLS/h2 fixture and raw
  `h2` attack client), `adversarial/p31/h2hold404.py` (8-source zero-window
  stream-pool hold with a one-byte WINDOW_UPDATE trickle),
  `adversarial/p31/h2oracle_apache.py` (the same attack against Apache).
  Retained run output: `adversarial/p31/results_p31.txt`.
- **Method:** source audit of the HTTP/2 stream lease and send-deadline state
  machine, then live Apache-versus-vapached differentials using the vendored
  `h2` framing through Python `h2` (`python3-h2`), with the project's own
  TLS/h2 benchmark shape.
- **Remediation status:** closed after this report. Flow-control-blocked
  outputs transfer out of general dispatch capacity into a 128-process,
  32-per-source slow-response pool. Minimum-rate checkpoints and the absolute
  response lifetime are anchored at response start and cannot be renewed by
  a partial WINDOW_UPDATE grant.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | vapache HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P31-A** | The process-wide HTTP/2 stream lease (`MAX_H2_STREAMS = 256`) is acquired in `admit_stream_before_spawn` and held for the whole `handle_stream` lifetime. A client can set `SETTINGS_INITIAL_WINDOW_SIZE = 0`, leave the response body pending, and then renew the 60-second send deadline **with a single byte of WINDOW_UPDATE per stream per `Timeout`**: `send_data_bounded` resets its deadline on every granted capacity (`h2.rs:575`), not on delivered bytes or a minimum rate. Eight one-connection source addresses (8 × 32 streams; or 4 × 2 connections; or four IPv6 `/64`s × 2 connections) fill all 256 slots and every HTTP/2 request by **any other client on any listener** is refused with `RST_STREAM REFUSED_STREAM` (error 7) before dispatch (`h2.rs:1842-1847`). The hold is sustained at ~13 bytes/s total (one byte per stream every 20 s) and needs no request body, no upload, no `.htaccess` and no dynamic handler; the 295-byte stock 404 body lasts ~98 minutes before the attacker re-opens the completed stream. | victim `200` for the whole held window | victim refused for the whole held window (260 s in the retained run); immediate recovery on release | remote cross-client denial of all HTTP/2 service |

The client bodies can be small `Body::Bytes` responses (the retained harness
uses the 295-byte stock 404 page), so the attack consumes no response-resident
budget, no response-body read permits and no blocking workers; only the stream
slots and eight idle TLS connections are occupied.

---

## 2. Root cause

### 2.1 The stream lease covers the entire response, not the dispatch phase

`crates/server/src/h2.rs` (HEAD `9c595e7`):

```rust
// admit_stream_before_spawn() — h2.rs:850-861
let resource_context = cfg.resource_budget.context(quota_peer.ip());
let stream_quota = cfg.resource_budget.try_h2_stream_in(&resource_context)?;
...
Ok(H2StreamAdmission { ..., _stream_quota: stream_quota })

// handle_stream() — h2.rs:881-886
let H2StreamAdmission { ..., _stream_quota } = admission;
...
// `_stream_quota` is dropped only when handle_stream returns,
// i.e. after send_response() has finished or failed.
```

The lease comes from `resource.rs:1523-1536` (`try_h2_stream_in`) with
`MAX_H2_STREAMS = 256` process-wide and `MAX_H2_STREAMS_PER_CLIENT = 64`
(`resource.rs:154-155`). The h2 builder advertises `max_concurrent_streams: 32`
per connection (`verified/lib.rs` `h2_settings`), so 32 streams per connection
is legal and one source can hold 64 with two connections.

A flow-control wait is therefore not just a wait: it is the owner of one
quarter of the global HTTP/2 service capacity.

### 2.2 The stall deadline is renewed by capacity grants the client controls

`h2.rs:553-578`:

```rust
async fn send_data_bounded(send, data, end, timeout) -> io::Result<()> {
    if data.is_empty() { ... }
    let mut deadline = Instant::now() + timeout;
    let mut offset = 0usize;
    while offset < data.len() {
        let remaining = data.len() - offset;
        let capacity = send_capacity(send, remaining, deadline).await?;
        let n = capacity.min(remaining);
        let last = end && offset + n == data.len();
        send.send_data(data.slice(offset..offset + n), last)?;
        offset += n;
        // "Receiving additional flow-control capacity is downstream progress"
        deadline = Instant::now() + timeout;          // h2.rs:575
    }
    Ok(())
}
```

`send_capacity` (`h2.rs:508-547`) returns as soon as the peer's WINDOW_UPDATE
assigns **any** capacity:

```rust
Ok(Some(Ok(n))) if n > 0 => return Ok(n),
```

One byte of WINDOW_UPDATE per stream per `Timeout` is therefore enough to keep
the deadline permanently fresh. No byte needs to reach a client-side consumer;
`Timeout` is a stall deadline that the attacker renews with a zero-throughput
grant. The `Body::Bytes` arm (`h2.rs:696-709`) uses `send_data_bounded`
directly, so no `ResponseBodyRead` permit is involved; the 295-byte stock 404
body lasts ~98 minutes at one byte per 20 s before a replacement stream is
needed.

The connection itself is never idle-reaped while streams are active:
`h2.rs:1827` enables the connection idle timeout only `if budget.active == 0`.

### 2.3 Process-wide refusal

When the 256 leases are taken, a new stream from an unrelated client fails in
`h2.rs:1842-1847`:

```rust
let admission = match admit_stream_before_spawn(&cfg, peer, &request) {
    Ok(admission) => admission,
    Err(_) => {
        respond.send_reset(h2::Reason::REFUSED_STREAM);   // error 7
        continue;
    }
};
```

The victim's own per-client quota (64) is untouched; the refusal is the
process-wide 256-lease pool. The denial is listener- and vhost-independent:
the ledger is one per process generation.

---

## 3. Live evidence

Retained run (`python3 adversarial/p31/h2hold404.py 8 32 260 20`) against
vapached HEAD `9c595e7` with the default `Timeout 60`, one TLS/h2 connection
per source address, 32 streams each (256 total), one-byte WINDOW_UPDATE per
stream every 20 s:

```text
baseline: status=b'200' reset=None terminated=None body=10
before trickle: status=None reset=7 terminated=None body=0
t=40s  grants_ok=512  failed=0 victim=status=None reset=7 terminated=None body=0
t=80s  grants_ok=1024 failed=0 victim=status=None reset=7 terminated=None body=0
t=120s grants_ok=1536 failed=0 victim=status=None reset=7 terminated=None body=0
t=160s grants_ok=2048 failed=0 victim=status=None reset=7 terminated=None body=0
t=200s grants_ok=2560 failed=0 victim=status=None reset=7 terminated=None body=0
t=240s grants_ok=3072 failed=0 victim=status=None reset=7 terminated=None body=0
final during: status=None reset=7 terminated=None body=0
after release: status=b'200' reset=None terminated=None body=10
```

`reset=7` is `REFUSED_STREAM`; the victim requested the ten-byte `/small.txt`.
No holder stream failed during the 260 s (each received only ~13 of the 295
body bytes, proving the deadline renewed rather than the body completing).

Threshold control (`python3 adversarial/p31/h2hold404.py 4 32 30 20`) —
128 streams, i.e. below the 256-lease pool:

```text
baseline: status=b'200' reset=None terminated=None body=10
before trickle: status=b'200' reset=None terminated=None body=10
t=40s grants_ok=256 failed=0 victim=status=b'200' reset=None terminated=None body=10
final during: status=b'200' reset=None terminated=None body=10
after release: status=b'200' reset=None terminated=None body=10
```

Apache oracle, identical client and fixture, Apache/2.4.69 `mpm_event` +
`mod_http2` + `mod_ssl`, `Timeout 60`
(`python3 adversarial/p31/h2oracle_apache.py`):

```text
baseline: status=b'200' reset=None terminated=None body=10
before trickle: status=b'200' reset=None terminated=None body=10
t=40s  victim=status=b'200' reset=None terminated=None body=10
t=80s  victim=status=b'200' reset=None terminated=None body=10
t=120s victim=status=b'200' reset=None terminated=None body=10
final during: status=b'200' reset=None terminated=None body=10
```

Apache keeps answering a fresh client while the same 256 streams are held;
`mod_http2` streams are not a process-wide lease.

---

## 4. Attack economics and preconditions

- **Preconditions:** an h2 listener (`Protocols h2 http/1.1` is the project
  default), any URL whose response has a body (a 404 page is enough). No
  request body, no upload, no `.htaccess`, no CGI/FastCGI/proxy.
- **Resources:** 8 TCP/TLS connections and 256 GET requests once; thereafter
  one byte per stream every `Timeout/3` (256 bytes per 20 s ≈ 13 bytes/s at
  the default `Timeout 60`; slower intervals still renew as long as they are
  below `Timeout`). The holder connections stay open with no other traffic,
  and completed streams are replaced for another ~98 minutes each.
- **Sources:** the per-client key is the exact IPv4 address or the IPv6 /64;
  64 streams per key means 4 keys × 2 connections, or 4 IPv6 /64s × 2
  connections, reach the 256 pool. In the local test the attacker binds
  loopback aliases; a remote attacker needs four addresses/prefixes.
- **Blast radius:** every HTTP/2 request on every listener and vhost is
  refused before routing (including ten-byte health checks), regardless of
  which address the victim uses. HTTP/1 is unaffected, so simple HTTP/1
  monitoring does not notice the outage.
- **Recovery:** immediate when the holders close or stop granting; the
  deadline then fires within `Timeout` and slots are released.

---

## 5. Relationship to prior passes

P22-A already held the 256 stream slots with zero windows, but reported the
impact as unaccounted response memory (up to ~2 GiB) and explicitly assumed a
release bound of `send_timeout = Timeout.max(5 s)` with a "re-armed wave" every
60 s. The remediation charged response chunks to the resident budget, so the
memory impact is gone, but the stream lease itself is still held across the
send wait. This pass adds:

1. **Unbounded occupancy without reissuing requests.** The deadline is renewed
   by client-controlled flow-control capacity, not by delivered bytes or a
   minimum rate, so one byte per `Timeout` makes each stream permanent; P22's
   release-bound premise no longer holds.
2. **The global refusal impact.** P22 did not identify that exhausting the
   pool resets every unrelated client's stream with `REFUSED_STREAM` before
   dispatch, or that a `Body::Bytes` response (a 404 page) holds the slot with
   no read permit or resident-budget charge.

P30-A′ was the shared blocking-read dispatch lease and is fixed; this finding
is the independent `H2Stream` slot lease that P30 did not touch.

---

## 6. Remediation direction

1. **Renew on delivered throughput, not on granted capacity.** Re-arm the send
   deadline only when the stream has delivered a minimum average rate over the
   interval (the same `MinRate` shape used by `RequestReadTimeout`), not when
   `poll_capacity` returns. A one-byte grant then no longer counts as progress.
2. **Bound zero-throughput waits absolutely.** Give a stream whose window has
   been open but has delivered < N bytes a response-wide ceiling independent
   of renewals.
3. **Charge stalled sends to the source.** A stream stalled below the minimum
   rate should consume the client's slow-response reserve so one key cannot
   convert its 64-stream share into an indefinite global hold.
4. **Regression.** An unrelated client must keep receiving `200` while 256
   streams are held with a one-byte trickle, and a stream that only ever
   receives one byte per `Timeout` must not renew indefinitely (retained
   harness `adversarial/p31/h2hold404.py` plus the Apache oracle).

---

## 7. Reproduction

```sh
cd /root/vapache
cargo build --release -p vapached
python3 adversarial/p31/h2hold404.py 8 32 260 20   # vapache: victim refused throughout
python3 adversarial/p31/h2hold404.py 4 32 30 20    # threshold control: victim 200
python3 adversarial/p31/h2oracle_apache.py         # Apache oracle: victim 200 throughout
```

`python3-h2` is required for the client (`apt-get install python3-h2`); the
harness writes fixtures, certificates and logs under
`/tmp/opencode/p31-h2hold`.

## 8. Retained files

- `adversarial/p31/h2hold.py` — shared TLS/h2 fixture, attack client, victim
  probe and one-byte trickle.
- `adversarial/p31/h2hold404.py` — 8-source zero-window hold over the stock
  404 `Body::Bytes` response.
- `adversarial/p31/h2oracle_apache.py` — the identical attack against
  Apache/2.4.69 `mod_http2`.
- `adversarial/p31/results_p31.txt` — retained run output for both servers and
  the threshold control.
