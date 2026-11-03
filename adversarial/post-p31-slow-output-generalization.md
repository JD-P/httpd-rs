# Post-P31 slow-output resource generalization

- **Date:** 2026-11-03
- **Scope:** HTTP/1 output, HTTP/2 output, dynamic response readers, retained
  response memory, response spools, and WebSocket upgrade ownership.
- **Method:** call-graph and lease-lifetime review followed by deterministic
  saturation, cancellation, and state-transition tests. No live adversarial
  probing or open-ended fuzzing was used.

## Root cause

P31 correctly isolated flow-control-blocked HTTP/2 streams, but encoded that
rule inside the HTTP/2 adapter. HTTP/1 still renewed its write timeout after
every partial write. A client able to accept a small amount of data per
`Timeout` could therefore keep an established HTTP/1 connection, a dynamic
backend slot, response memory, and spool resources indefinitely. Per-source
limits bounded one identity but did not prevent enough identities from filling
the process pool.

The earlier resource hierarchy proved cardinality, acquisition order, source
fairness, and RAII release. It did not express **time in a phase** or require a
lease to leave general capacity when the request entered an attacker-paced
wait. Tests covered “stalled output expires” and “progressing output survives”
separately, not “many progressing outputs saturate a pool while an unrelated
request must still be admitted.” That is why this cousin survived the earlier
passes.

## Remediation

HTTP/1 writability and HTTP/2 flow control now share one verified output state
machine and one process/source slow-output pool:

```text
General --downstream stall--> Slow --finish/cancel--> Closed
```

There is no transition from `Slow` back to `General`. Classification uses
cumulative downstream wait rather than one isolated wait. Once classified,
minimum useful progress and the absolute response lifetime are anchored at the
original response start; a partial write or capacity grant cannot renew them.

The handoff transfers all coupled ownership:

- HTTP/1 established-connection or HTTP/2 stream admission leaves the general
  pool only after the slow-output lease is acquired and every coupled transfer
  succeeds; a failed resident/spool transfer rolls the tentative handoff back;
- dynamic responses release their general backend concurrency slot but retain
  descriptor accounting until the reader actually finishes;
- retained response bytes, still-live HTTP/2 transport slices, and spool
  files/bytes enter slow sibling pools;
- slow spools use at most one quarter of the configured general spool capacity;
- a slow HTTP/1 response closes instead of re-entering keep-alive admission;
- WebSockets acquire their dedicated tunnel lease before releasing the
  established HTTP/1 lease.

The deterministic regressions fill the slow pool across source identities and
show an unrelated general stream remains admissible, force an HTTP/1 duplex
writer into backpressure and observe its general leases disappear, verify
resident/spool/backend transfers and cancellation cleanup, and verify a live
WebSocket owns only its dedicated tunnel class.

## General rule

Every attacker-controlled wait now needs an inventory entry of the form
`phase x held lease x deadline type`. A renewable idle deadline is insufficient
when the phase owns general capacity. Such a phase must either complete under
an anchored lifetime or transfer, acquire-first and irreversibly, into a
smaller source-fair ownership class. Saturation tests must fill that class with
enough distinct source identities and assert that an unrelated general request
still succeeds.
