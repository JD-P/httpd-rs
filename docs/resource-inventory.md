# Resource ownership inventory

httpd-rs has one generation-owned `ResourceBudget`. Reloaded configurations
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
slow-input and slow-output class, dynamic backend requests, blocking response
reads, synchronous blocking I/O, WebSocket tunnels, expensive CPU operations,
`RewriteMap prg` helpers, and general/slow spool files. Bcrypt additionally
holds a weighted CPU lease whose
charge doubles with each configured cost step; the ordinary expensive-work
lease still caps cheap hashes by operation count. Dynamic response compression
has a separate CPU lease weighted by input size, codec, and quality, plus a
transient-memory lease covering the source, a conservative codec-workspace
bound, and output scratch. Filesystem lookup/cache work has a separate
64-process/8-source phase. Local policy/path and body-spool calls not already
owned by a narrower response/backend/helper contract additionally hold a
48-process/8-source/1-request `BlockingIoLease`, so
nested path, metadata and descriptor helpers cannot multiply one request's
charge and at least sixteen of the fixed 64 connection workers remain outside
this class. The adjustable byte ledger covers request memory,
general/slow response memory, general/slow request/backend/proxy spools, and
retained policy expansions, retained memory-cache entries, and compression
workspaces. A ninth byte class reserves third-party compiler/codec workspace
before dependency entry; access-file regex compilation uses 256 MiB process,
64 MiB source and 32 MiB request ceilings. Fixed-window rates use the same
canonical client identity and process ledger.

Request-controlled work which crosses a blocking-pool or DNS-queue boundary
first acquires an `AsyncWorkLease`. The move-only lease is transferred into
the queued closure/job rather than retained by the awaiting future, so
aborting or dropping the waiter cannot release queue, task, or conservative
resident-memory accounting while the child still exists. Admission samples
the shared `RequestScope` cancellation bit before and after hierarchical slot
acquisition; work which races with cancellation is rejected before handoff,
while already-admitted work retains the same cancellation lineage until exit.
The process/client/request ceilings are 512/64/4. HTTP/1 backend/dispatch
handoffs, HTTP/2 policy/backend blocking work, proxy DNS, and `Require host`
reverse DNS use this boundary. Response file/stream reads retain their more
specific move-only `ResponseBodyReadLease` and output-ownership state instead.

Synchronous filesystem ownership is projected through the same request scope.
The complete local filesystem phase acquires one re-entrant guard; URL-space
authentication, expression and rewrite probes acquire it at their individual
gateways, and request-body spool open/write operations use it even before
local routing. Nested helpers reuse the outer slot but recheck cancellation
and exact context identity on every entry. A pre-cancelled request therefore
cannot start another kernel/dependency call, a cancelled in-flight call remains
charged until it returns, and a helper cannot hide work under another
request's owner. HTTP/2 spool writes leave the Tokio scheduler through
`block_in_place`; HTTP/1 already runs on the fixed connection pool.

Compression is produced only as the downstream writer asks for data: HTTP/1
writes the response head before starting the encoder, and HTTP/2 waits for
flow-control capacity before each bounded read. Cancellation drops the encoder
and both leases. Brotli's public custom allocator is metered against the
admitted workspace bound. Request-time Brotli qualities 10 and 11 are rejected
by both main and access-file configuration grammars because they enter a long,
non-interruptible Zopfli search; immutable assets that require those profiles
must be precompressed. Admission failure preserves the identity response.

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

Before a declared HTTP/2 payload can cause the length-delimited codec to
reserve memory, an executable verified frame-head gate checks the negotiated
length, fixed-size frame families and stream-zero rules. Every admitted wire
frame then consumes one unified per-connection work budget, including unknown
frames and incomplete header-block continuations that never become semantic
connection events. Encoded header blocks have cumulative byte and continuation
ceilings, and HPACK Huffman decode establishes output-allocation and loop-work
bounds before entering the decoder.

HTTP/2 stream ownership is represented once at the adapter boundary. One
ledger stores each stream ID and lifecycle phase together with its active and
delayed-reset counters; a transition is computed in full before any field is
mutated, and connection close applies the verified terminal transition before
clearing every record. The lifecycle fuzz campaign asserts uniqueness, exact
counter/phase agreement, configured maxima and zero terminal ownership after
every generated transition sequence.

Inside the vendored state machine, SETTINGS synchronization and peer
HEADERS/DATA classification consume closed verified transition tables. A
terminal stream's exact close cause is retained in a FIFO tombstone set bounded
by the configured reset limits and an absolute 1,024-entry ceiling. That bound
lets the codec distinguish a closed lower stream (STREAM_CLOSED) from an ID the
peer skipped (PROTOCOL_ERROR) without turning historical stream IDs into an
unbounded connection-lifetime map. Repeated error resets replace queued
application output and reclaim its flow capacity; they do not reopen or change
the retained terminal cause.

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

Inbound rustls work has an additional shape-specific owner selected before the
dependency is entered. Ordinary TLS reserves one work unit and 128 KiB of
dependency workspace; mTLS reserves sixteen units and 256 KiB. The shared
handshake pool admits 64 work units process-wide and 32 per source, while its
rate gate admits 128 and 64 work units per second respectively. A verifier
wrapper rejects client chains above eight total certificates or 65,535 DER
bytes before webpki path construction. The byte ceiling is inherited from the
rustls handshake-message bound; the count, CPU and workspace bounds are pinned
by `adversarial/tls_dependency_profile.py` across ambiguous issuers, dense name
constraints and every ring/webpki signature family, including P-384 and
RSA-8192 extrema.

Outbound rustls verification shares the same 64-process/32-source weighted
concurrency and dependency-workspace ledgers. A generation-cached verifier
uses a handshake-scoped request/health owner and first rejects backend chains
above eight total certificates or 65,535 aggregate DER bytes, counting
duplicates, before webpki path construction. Admitted chains
cost one unit per certificate plus one unit per 8 KiB of DER, up to the proved
sixteen-unit envelope; the lease is acquired immediately before webpki and is
retained through synchronous proxy, asynchronous WSS, or process-owned health-
check handshake completion. The outbound rate envelope is 512 process and 256
source work units per second: an ordinary two-certificate chain costs three
units and preserves measured proxy bursts, while a maximal admitted chain
costs at least nine. Health checks have no downstream source identity but use
the same process rate and concurrency ledger.

Extended status also exports current use, monotonic high-water, the observed
hard limit, a reporting-only shadow candidate and rejection count for every
slot, byte and physical-parent ledger. `tests/resource_budget_sweep.py` varies
one attacker-controlled request axis at a time while recording those gauges
and process CPU, memory, task and descriptor measurements. The shadow formula
is executable Verus code and can only produce a value between the observed
peak and the enforced hard ceiling; it is calibration evidence, never an
automatic limit increase.

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
  allocator and cache-publication barrier), the immutable once-initialized
  directive registry, signal flags, logging serialization, and privileged TLS
  file-broker state;
- telemetry counters, thread-local formatting buffers, request-local metadata
  memoization, collision-resistant temporary-name counters, and the
  deterministic task/thread fault plans and once-initialized whole-request
  fixture compiled only for fuzz/fault-injection testing. Authentication tests
  also use one thread-local verifier-call counter to assert that known and
  unknown usernames each cross the verification boundary exactly once.

These objects have bounds or constant cardinality at their definitions and do
not grant request execution capacity. `tests/resource_inventory.py` makes the
distinction executable: adding a mutable static or a resource class fails CI
until this inventory and its allowlist are reviewed. It also rejects the old
standalone worker, TLS, H2, rewrite-helper, expensive-operation, and policy
resident ledgers.

Shared maps, caches and queues have a second, narrower closure gate. Thirty
process-, generation-, connection- and configuration-owned structures name
their source-level entry/byte capacity, lifetime cleanup and (where work
crosses a task boundary) move-only owner. Authentication, access-file,
compiled-policy, response-memory, OCSP, TLS-session, proxy-session,
backend-identity and generation-state insertions consume the executable Verus
`shared_map_insert_admit` predicate after replacement/eviction. Its proof
establishes that a successful insertion preserves both cardinality and byte
ceilings; a cache cannot accidentally keep only one dimension of its bound.

Every production channel is physically bounded. The fixed connection work
queue consumes `shared_queue_push_admit`; both DNS pools have 64 work slots,
one-slot replies and an `AsyncWorkLease` in every queued job; streaming bodies
have four resource-accounted chunks. The H2 lifecycle queue is sized to the
per-connection stream ceiling, and each stream's move-only drop guard can emit
exactly one terminal event. The connection loop gives those events priority
before another stream admission. `tests/resource_inventory.py` strips
test-only modules and rejects any production `mpsc::channel()` or
`unbounded_channel()` constructor, as well as a declared shared-state contract
whose bound or ownership evidence disappears. The OCSP in-memory staple cache,
which formerly capped each response but not their aggregate, is independently
limited to 256 entries and 64 MiB.

Third-party calls have a separate closed boundary inventory. All 23 direct
dependencies in the OS, proof, PCRE2 and server manifests are assigned one
resource-review class; changing a manifest or adding another occurrence of a
variable-cost namespace fails `tests/resource_inventory.py`. Nine concrete
request/backend-influenced entry points cover bcrypt, gzip/Brotli, regex
compile and match, access-file aggregate regex compilation, rustls listener
and proxy handshakes, the vendored h2 handshake/codec and webpki OCSP
validation. Each consumes the executable Verus `dependency_call_admit`
predicate, which jointly requires a live surrounding owner and input, work and
workspace bounds.

This audit found a real lifetime seam in the regex dependency. Its bounded
lazy-DFA tier used to be constructed on the second search, so compilation and
cache allocation occurred on whichever request happened to arrive next.
Both automata tiers are now constructed at the configuration/access-file
compile boundary. The Apache-facing builder has explicit pattern, automata and
hybrid-cache ceilings; access-file parsing reserves the complete conservative
dependency workspace in a typed byte lease before each compile, caps the
aggregate at 32 MiB, charges the resident-memory parent, shrinks to the
retained amount and includes that charge in the access-cache weight. Many
individually valid patterns therefore cannot multiply dependency-owned memory
outside the cache bound.

The enum/static inventory is complemented by the hybrid request-resource
warrant described in `docs/resource-warrant.md`. Its static scanner inventories
allocation, growth, CPU iteration, task/process, filesystem, network,
synchronization, variable-cost dependency and unsafe/syscall effects across
production Rust and the vendored h2 fork. Its runtime profiler records the CPU,
memory, task, descriptor and I/O resources exercised by the existing benchmark
and deployment workloads. CI rejects a new syntactic effect site until the
checked inventory is deliberately regenerated; dynamic absence never removes a
static obligation. Each site remains proof debt until its cost and lifetime are
refined to a typed lease or constant bound, or documented as a pinned external
assumption with an independent OS backstop.

The reviewed resource ontology is wider than process CPU/RSS: it explicitly
includes network bandwidth, elapsed occupancy, cgroup kernel/socket/slab/page-
table memory, disk bytes, filesystem inodes, queue occupancy and lock waiters.
The profiler samples network namespaces, statvfs headroom, scheduler wait time,
thread wait channels and cgroup `memory.stat` alongside its original process
counters. Static closure assigns every effect exactly one typed-lease,
proved-constant-bound or external-assumption disposition; the generated
inventory currently has zero unclassified sites. That classification is a
discovery invariant, while per-call dominance and cost refinement remain the
separate Verus proof obligation.
