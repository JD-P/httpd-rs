# Resource ownership inventory

Vapache has one generation-owned `ResourceBudget`. Reloaded configurations
reuse it, so reload cannot reset capacity while old requests still hold
leases. Attacker-reachable admission is hierarchical: request scope is
charged first, then the canonical client key (IPv4 address or IPv6 `/64`),
then process scope. A rejection rolls back every lower scope. RAII leases
release all three scopes on errors, resets, timeouts, and normal completion.

The slot ledger covers pending connections, HTTP/1 workers, slow-body workers,
TLS handshakes, HTTP/2 connections and streams, dynamic backend requests,
blocking response reads, WebSocket tunnels, expensive CPU operations,
`RewriteMap prg` helpers, and spool files. The adjustable byte ledger covers
request memory, response memory, request/backend/proxy spools, and retained
policy expansions. Fixed-window TLS and rewrite-helper rates use the same
canonical client identity and process ledger.

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
- configuration-generation state, signal flags, logging serialization, and
  privileged TLS file-broker state;
- telemetry counters, thread-local formatting buffers, request-local metadata
  memoization, and collision-resistant temporary-name counters.

These objects have bounds or constant cardinality at their definitions and do
not grant request execution capacity. `tests/resource_inventory.py` makes the
distinction executable: adding a mutable static or a resource class fails CI
until this inventory and its allowlist are reviewed. It also rejects the old
standalone worker, TLS, H2, rewrite-helper, expensive-operation, and policy
resident ledgers.
