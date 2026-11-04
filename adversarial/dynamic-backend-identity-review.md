# Dynamic backend identity review

## Scope

This campaign followed every supported path from a configured logical backend
to the kernel object which receives bytes:

- direct and balancer HTTP/HTTPS proxy routes;
- WebSocket and WSS tunnels;
- active balancer health checks and failover;
- Unix and TCP FastCGI; and
- OCSP AIA/`SSLStaplingForceURL` fetches.

The security invariant is that authorization of a configured route is not
enough by itself.  The resolved transport endpoint, connected socket peer and,
where available, cryptographic or kernel process identity must remain part of
the same immutable configuration generation.

## Findings

### D1 — Unix FastCGI authenticated a pathname, not the listener

`VapacheFastCGIStablePath` checked the Unix socket's type, owner, ACL, device
and inode before and after `connect(2)`.  It did not query the connected
socket's peer credentials.  A socket file's uid describes the filesystem
object; it does not prove which process created the listener.

On Linux, a strict connection now obtains `SO_PEERCRED` immediately after
connect and before sending FastCGI records.  The listener uid must be the
configured backend uid, the configured endpoint-owner uid (which supports a
rootless pool manager), or uid 0.  Root is admitted because it is already the
operating-system trust root and is commonly the PHP-FPM master which creates
the listening socket before dispatching to an unprivileged pool.  The endpoint
file metadata, listener credential and configured worker uid remain
deliberately separate checks.

This does not claim that the kernel can identify the eventual PHP-FPM worker
behind a root master.  A trusted root master can select its workers; that is
outside Vapache's process boundary.  It does prevent an unrelated
unprivileged listener from inheriting trust merely by appearing at a pathname
with acceptable metadata.

### D2 — DNS could retarget an authorized cleartext backend in place

Proxy DNS was cached process-wide by `(hostname, port)` for 30 seconds.  The
same immutable configuration could therefore connect to one address set,
expire the cache, and later connect to a different set without any policy
transition.  Conversely, a freshly loaded generation could inherit an old
generation's cached answer.  Normal proxy requests, health checks and
WebSockets all consumed that mutable name-to-address mapping.

The first bounded answer is now installed atomically under
`(lowercase-hostname, port)` in a registry owned by exactly one immutable
configuration generation.  Concurrent first lookups may finish differently,
but only the first installed set is returned to every caller.  Entries do not
expire inside a live generation. Background health/OCSP work shares an `Arc`
to that registry, so cleanup is structural and cannot race an in-flight insert;
the complete map disappears with its last generation-local holder. Reload is
the explicit transition at which a new DNS identity may be admitted.

Each generation's identity table is capped at 1,024 entries and fails closed
rather than evicting an active identity.  Literal IP addresses and `localhost`
use their fixed parser-defined address sets without resolver state.

### D3 — Secondary backend paths did not share one identity authority

TCP FastCGI and OCSP used the proxy resolver but had no generation operand.
Leaving either path on an independent cache would preserve the same retargeting
primitive outside ordinary HTTP proxy execution.  Both now consume the shared
generation-bound identity.  Balancer health checks carry the originating
generation registry explicitly, and WebSocket connection setup uses the same
`Config` generation as its authorization grant.

Every successful TCP connection also compares the kernel-reported peer address
with the exact selected `SocketAddr` before any application bytes are sent.
HTTPS/WSS retain Rustls DNS/IP certificate verification on top of this
transport binding.  OCSP responses remain cryptographically validated; the
transport binding additionally prevents a later DNS answer from turning the
OCSP POST itself into a generation-local SSRF primitive.

## Resulting identity chain

```text
configured route / responder URL
        -> authorization grant and concrete balancer member
        -> immutable Config generation
        -> atomically bound, bounded address set
        -> one selected SocketAddr
        -> kernel peer_addr equality
        -> TLS hostname authentication (HTTPS/WSS), or
           SO_PEERCRED listener authentication (strict Unix FastCGI)
```

Rewrite and regex proxy templates were already required to keep their
authority static, balancer failover already rebuilt the grant for the concrete
member, HTTPS already verified the configured name, and strict Unix FastCGI
already performed before/after inode checks.  Those controls were retained.

## Formal boundary and regressions

The runtime now consumes three Verus-verified decisions:

- `backend_resolution_binding_admit` requires the request and bound
  generations to agree and the resolver result to pass bounded validation;
- `backend_connected_endpoint_admit` requires the actual peer to equal the
  endpoint selected from that bound generation; and
- `fastcgi_peer_identity_admit` admits only the configured non-root backend
  uid, configured endpoint owner, or the operating-system trust root.

Unit regressions cover generation separation, case-normalized hostname keys,
failure of in-generation rebinding, generation cleanup, wrong-port resolver
output, selected/actual endpoint inequality, Linux peer-credential retrieval,
and unrelated FastCGI uids.  Existing HTTP, WebSocket, health, FastCGI, TLS and
OCSP suites exercise the integrated call paths.

## Operational consequence

A DNS-named backend which changes addresses now requires a graceful reload.
That is intentional: cleartext DNS is the only available identity for an
HTTP/WS or TCP FastCGI target, so silently refreshing it would silently change
the authorized service.  Operators needing transparent address churn should
use a stable local load balancer, or HTTPS/WSS for cryptographic service
identity, and reload Vapache when the admitted address set changes.

The first answer in a generation is still trusted; Vapache cannot infer an
operator's intended IP set from a hostname alone.  Administrators must use
trusted DNS or literal addresses for cleartext upstreams.  The change removes
identity drift after that trust decision rather than pretending to replace
DNSSEC or backend TLS.
