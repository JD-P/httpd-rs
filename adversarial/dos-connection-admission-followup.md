# Connection-admission denial-of-service follow-up

This review closes five availability gaps left after the P26–P28 remediation.
The common invariant is that an unauthenticated socket must not acquire a
blocking worker, monopolize a listener, or perform unmetered HTTP/2 control
work before it has crossed a bounded admission stage.

| Gap | Remediation | Regression boundary |
|---|---|---|
| An H2 client could stop before completing the connection preface and initial SETTINGS | The server handshake is bounded by `RequestReadTimeout`'s header deadline; the same absolute deadline remains in force until initial SETTINGS and the first request head are processed, and only then does the socket acquire an established-connection slot | Peers that send nothing or stop after the raw preface return `TimedOut` and never invoke the established callback |
| Every accepted socket immediately created an OS thread | TLS handshake and the first HTTP/1 head run on a shared async runtime behind a bounded pending-socket quota. Raw and parsed heads consume the shared request-resident ledger, whose lease transfers into the blocking parser. A blocking worker is created only after strict preflight parsing | First-head size/deadline/reservation-transfer tests, pending/worker RAII tests, and the full HTTP suites |
| One continuously ready listener was drained to `EAGAIN` before another listener ran | Each ready listener receives at most 64 accepts per poll iteration and the starting listener rotates | Listener-order/batch unit coverage |
| A trusted proxy could receive the complete worker pool under its transport identity | The first validated head is used to derive the `RemoteIPHeader` effective identity before HTTP/1 worker admission. The proxy only receives a larger, still bounded, pre-header quota | Per-effective-client worker limits retain the IPv4 and IPv6 `/64` fairness keys and no longer have a trusted-proxy bypass |
| WINDOW_UPDATE frames with increments of at least 1024 consumed no control token | Every WINDOW_UPDATE now costs one token; protocol validity and flow-control effects remain separate. Tiny increments remain on the strict control bucket, while useful larger updates use a finite higher-throughput bucket so ordinary large downloads are not mistaken for a flood | The executable Verus transition and vendored h2 token-bucket tests require `burst - 1` after a large update; the multi-megabyte H2 response regression completes normally |

Two adjacent worker-exhaustion paths are contained by the same change. A
first request with a body may occupy only one quarter of the HTTP/1 worker
pool, keep-alive is disabled before the final quarter is consumed, and a
large HTTP/1 response must acquire the existing 32-slot blocking-I/O lease.
HTTP/2 dispatch runs outside the async I/O runtime and holds that bounded
lease while it performs synchronous filesystem and policy work.

These are process availability limits rather than traffic-shaping promises.
The kernel listen backlog and the configured request deadlines still determine
how excess clients observe overload; Vapache either sends a bounded 503 on
cleartext HTTP/1 or closes the connection when no safe response protocol has
yet been established.

## Exhaustive follow-up

A second review followed each admitted connection through keep-alive, TLS,
logging, rewrite helpers and cache maintenance instead of stopping at the
first request head.

| Gap | Remediation | Regression boundary |
|---|---|---|
| A body on the second or later HTTP/1 keep-alive request bypassed the slow-body reserve | Every parsed request head now acquires a body lease before `100 Continue` or the first body byte; the lease is released after parsing while the body retains its separate byte/spool accounting | A pipelined GET succeeds, then a POST on the same connection receives 503 when the body reserve is saturated |
| TLS cryptographic work shared the admission runtime without its own budget | In-progress handshakes are capped at 64 (4 per source), with fixed-window admission at 128/s process-wide and a 64/s per-source burst; the original pending-socket and 20-second handshake deadline still apply | Deterministic rate tests cover per-source, global and one-second refill boundaries; the TLS/H2 conformance burst stays admitted |
| Access/error diagnostics could expand without a complete-line cap and queue all workers behind blocked files or stderr | Access/error lines are capped at 128 KiB; configured logs and library stderr each use a process-wide single-writer, non-queuing gate, with `try_lock` at each configured descriptor. Request bytes are escaped by a bounded Verus kernel | Repeated `%r` expansion stops exactly at the cap; the proof establishes both the output bound and CR/LF/NUL exclusion |
| Each `RewriteMap prg:` lookup created a child and reader thread without request, concurrency or rate accounting | Eight calls exhaust the shared request-policy meter; at most 8 program helpers run concurrently and 64 start per second, inside the existing 32-operation expensive-work gate | The ninth lookup fails closed and pure rate-boundary tests require refill before another admission |
| Each established HTTP/1 connection created a fresh OS thread, and Apache-sized directives had no implementation ceiling | HTTP/1 work uses Tokio's reusable blocking pool. `MaxRequestWorkers` and `ServerLimit` fail configuration above 512; the pool retains 64 extra blocking slots for bounded H2/filesystem work | Configuration tests accept 512 and reject 513; RAII admission tests retain exact worker release |
| The useful `WINDOW_UPDATE` class still admitted a 16,384-frame burst and 8,192 frames/s | Only increments of at least 16 KiB use the transfer bucket, now capped at a 4,096-frame burst and 2,048 frames/s; smaller increments consume the strict control bucket | Vendored h2 budget tests exhaust both buckets and the multi-megabyte response regression still completes |
| Disk-cache indexing/invalidation recursively walked an externally polluted cache tree | Walks are iterative and fail closed after depth 32 or 32,768 directory records. An incomplete index prevents stores; invalidation advances the cache epoch and clears memory so unvisited disk entries cannot be served | A depth-33 fixture is refused, while ordinary nested cache accounting and invalidation remain covered |
