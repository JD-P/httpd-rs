# Resource ownership inventory

Vapache has one generation-owned `ResourceBudget`. Reloaded configurations
reuse it, so reload cannot reset capacity while old requests still hold
leases. Attacker-reachable admission is hierarchical: request scope is
charged first, then the canonical client key (IPv4 address or IPv6 `/64`),
then process scope and its physical parent. A rejection rolls back every lower
scope. RAII leases release every charge on errors, resets, timeouts, and normal
completion.

The budget is deliberately shared, but policy-bearing mutable state is not.
Each immutable configuration owns a retirement flag, admission gate and cache epoch; proxy
health/failure observations, balancer counters and parsed `.htaccess` IR are
namespaced by its generation ID. The final `Config` clone removes those
records. A successful reload retires transports before new listener admission;
HTTP/1 keep-alive, H2 streams and WebSocket tunnels cannot create new work
under old policy. Rejected candidates do not retire the still-current state.
Admission decisions hold the generation gate's read side; reload commit takes
the write side, so a request is ordered entirely before or after retirement.
One process-wide read/write barrier covers only final cache publication and
administrative generation cleanup, ensuring a retired request cannot recreate
an old-root entry after reload without serializing ordinary cache reads or
response construction.

The slot ledger covers pending connections, HTTP/1 workers, slow-body workers,
TLS handshakes, HTTP/2 connections, ordinary streams and a shared source-fair
slow-input and slow-output class, dynamic backend requests, blocking response reads,
WebSocket tunnels, expensive CPU operations, `RewriteMap prg` helpers, and
general/slow spool files. Filesystem lookup/cache work has a separate
64-process/8-source phase, so a stalled mount cannot occupy every request
worker or any dynamic-backend slot. The adjustable byte ledger covers request memory,
general/slow response memory, general/slow request/backend/proxy spools, and
retained policy expansions and retained memory-cache entries. Fixed-window
rates use the same canonical client identity and process ledger.

HTTP/1 socket backpressure and HTTP/2 flow-control backpressure use one
irreversible `General -> Slow -> Closed` ownership transition. The slow lease
is acquired and every coupled transfer succeeds before general
connection/stream capacity is released. Dynamic backend slots, retained
response bytes, still-live HTTP/2 transport slices, and spool bytes/files
transfer with the response; their descriptors remain charged until the
underlying reader finishes. Every HTTP/2 response attaches its resident
reservation to a never-indexed queued header value, so HPACK cannot retain
ownership in its dynamic table after encoding. One shared transport owner is
also attached to the head and every queued body or end-of-stream object. Once
EOS is queued, the current ordinary-stream or slow-output admission moves into
that owner and remains charged until h2 consumes or discards the final object.
Resets and connection drops release the same owner. A failed coupled transfer
rolls back the tentative slow admission while retaining general protocol
ownership. Slow spools have a separate reserve capped at one quarter of the
configured general spool pool. An HTTP/1 connection that entered the slow
class closes after its response instead of returning to keep-alive capacity.
WebSocket upgrades similarly acquire their dedicated tunnel lease before
releasing the general HTTP/1 connection lease.

HTTP/2 uploads use the verified
`GeneralBeforeBody -> SlowInput -> GeneralAfterBody -> Closed` ownership
transition. The adapter acquires a source-fair slow-input lease before
releasing its general stream lease while awaiting DATA, and reacquires general
capacity before releasing slow-input ownership when the body finishes. A full
slow-input pool therefore leaves all ordinary stream capacity available to
unrelated clients; an overloaded completion remains accounted as slow input
until its stream is reset.

All downstream-bound output is measured from the original response start.
Partial writes and HTTP/2 capacity grants cannot renew the minimum average
rate checkpoint or the absolute sixteen-interval lifetime.

Every typed lease also charges a physical parent for file descriptors, tasks,
and resident memory. A second exact parent combines writable disk bytes and
directory entries across spools, disk cache records, log files, and OCSP
staples, with a 4 GiB/16,384-entry generation ceiling. Each reservation also
charges a child ledger keyed by the target filesystem's kernel `st_dev`; every
child retains one quarter of that filesystem's observed free byte/inode
capacity and is independently capped at 4 GiB/16,384 entries. A small log or
cache mount therefore cannot borrow capacity measured on `ServerRoot` or a
different mount. Cache replacement holds its old-plus-temporary peak until
rename commits. The parent and filesystem ceilings retain
kernel/cgroup/filesystem headroom, so
individually safe pools cannot collectively exhaust the process. Connection
and backend slots include conservative protocol/stack overhead; request,
response, policy-expansion, and memory-cache bytes share the resident parent.
Cache entries retain their reservation until eviction.

Accepted TCP transports and TCP proxy/FastCGI backends request 128 KiB send
and receive buffers and hold a conservative 512 KiB kernel/dependency-buffer
lease under one 256 MiB parent (CGI is conservatively charged through the same
dynamic-backend lease). An established HTTP/2 transport holds another 512 KiB
from that parent for rustls, the 256 KiB h2 send buffer, codec state, and HPACK
scratch. Outbound HPACK uses raw strings whenever Huffman coding would not
shrink them, and releases per-connection scratch whose capacity exceeds 160
KiB. Writable-disk and transport usage/limits, queued H2 output owners, HPACK
scratch high-water, the number of discovered writable filesystems, and the
most constrained filesystem's remaining byte and inode headroom are exported
by `server-status?auto`.

Fixed-window process/source gates bound valid requests, malformed HTTP/1 head
parsing, expensive operations, cache writes, and log bytes. HTTP/2 acquires
its source/process stream lease and request-rate admission before spawning a
stream task. Request-scoped resource APIs reject absent or mismatched contexts
instead of falling back to an unattributed process-only charge.

`ResourceContext` is attached to parsed HTTP/1 and HTTP/2 requests after the
effective RemoteIP-aware address is validated. It is shared by request clones,
internal rewrites, CGI, FastCGI, generic reverse proxying, compression,
authentication, regex evaluation, and filesystem policy evaluation. This is
not a static-site mode: dynamic handlers acquire typed leases from the same
request context and retain their existing execution and timeout behavior.

Some mutable state is intentionally process-owned rather than request-owned:

- bounded content, authentication, `.htaccess`, DNS, proxy-health, OCSP, H2
  buffer, and TLS-session caches;
- bounded DNS/helper queues and the fixed Tokio/CGI worker pools;
- the process-owned TLS file broker and CGI workers, whose readiness protocols
  prove exact descriptor sets, privilege state, parent binding and rlimits
  before they can receive work;
- the process-owned HTTP/1 connection work pool, fixed at 64 threads with a
  fail-closed 1,024-job queue. Bodyless prepared dynamic handlers may retain
  at most eight of those workers after releasing request-worker admission;
  the executable Verus lending predicate therefore preserves at least 56
  workers for filesystem/policy/static work even if every backend stalls;
- configuration-generation state (including the monotonic process-local ID
  allocator and cache-publication barrier), signal flags, logging
  serialization, and privileged TLS file-broker state;
- telemetry counters, thread-local formatting buffers, request-local metadata
  memoization, collision-resistant temporary-name counters, and the
  deterministic task/thread fault plans compiled only for fault-injection
  testing.

These objects have bounds or constant cardinality at their definitions and do
not grant request execution capacity. `tests/resource_inventory.py` makes the
distinction executable: adding a mutable static or a resource class fails CI
until this inventory and its allowlist are reviewed. It also rejects the old
standalone worker, TLS, H2, rewrite-helper, expensive-operation, and policy
resident ledgers.
