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
