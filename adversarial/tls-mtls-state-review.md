# TLS/mTLS state campaign

Date: 2026-11-03

## Scope

This campaign followed every security identity established before or during a
TLS handshake through SNI certificate selection, ALPN, HTTP/1 keep-alive,
HTTP/2 multiplexing, client-certificate authentication, session resumption,
reload, OCSP stapling, and HTTPS reverse-proxy verification. The principal
question was whether a later protocol phase could reinterpret a connection
under a policy or identity that was not authenticated by the handshake.

Apache 2.4's current secure SNI-vhost policy was used as the behavioral oracle:
an HTTP authority may reuse an SNI-selected connection only when the two
virtual hosts have the same handshake-relevant TLS policy; otherwise the
server returns 421. Rustls 0.23.46's persisted-session implementation was also
reviewed directly. Its full and resumed server sessions bind SNI, ALPN and the
verified peer certificate chain, and reject resumption under a different SNI.

## Findings and remediation

### 1. SNI and verified client state were discarded after the handshake

The certificate resolver used SNI, but request dispatch independently selected
a virtual host from `Host` or `:authority`. HTTP/1 keep-alive and HTTP/2
coalescing could therefore route a connection authenticated for one TLS vhost
through another vhost's HTTP policy. Listener-wide client-auth checks prevented
the simplest mTLS downgrade, but certificate/key identity was not bound.

Every completed handshake now creates an immutable `TlsConnectionIdentity`
containing normalized SNI, destination address/port, the handshake-selected
vhost and a SHA-256 identity for the verified client leaf certificate. Required
mTLS cannot advance to HTTP if Rustls does not expose a peer certificate.
HTTP/1 checks every request before worker/body admission; HTTP/2 checks every
stream before dispatch. A missing authority after SNI produces 400 and a
transition to a different TLS policy produces 421. Equivalent HTTP aliases that
share the complete TLS policy remain usable.

### 2. TLS and HTTP virtual-host selectors disagreed

The previous TLS resolver always preferred an exact name over an earlier
wildcard vhost, implemented only a single-label `*.` wildcard, treated a
leading-dot alias as a wildcard, ignored underscore-prefixed names, and ignored
the catch-all `ServerAlias *`. HTTP selection uses the first configured vhost
across exact/wildcard candidates and the verified `host_pattern_matches`
semantics. Those disagreements could present one certificate while dispatch
selected another policy.

The resolver now has the same first-match order across exact and wildcard
aliases, uses the verified matcher, supports catch-all and multi-label suffix
matches, and treats `ServerName`, leading-dot and underscore names literally.
General `*`/`?` placements remain rejected by the configuration compiler until
their Apache semantics are implemented. Address-specific vhost filtering
remains shared with HTTP.

### 3. A wildcard listener lost the destination-address TLS identity

A single `Listen 0.0.0.0:443` may serve address-specific virtual hosts. The
old listener built one resolver containing all same-port vhosts; Rustls's
certificate resolver receives SNI but not the accepted socket's local address.
HTTP later selected its vhost with the real destination address, so two local
addresses could present one address's certificate and dispatch as the other.
Deriving the handshake vhost from HTTP selection afterward also mislabeled the
certificate that had actually been sent.

Wildcard listeners now prepare a separate complete Rustls generation for every
configured concrete destination address plus a wildcard fallback. The accepted
socket's canonical local address chooses that generation before any handshake
bytes are processed. This also permits different client-auth/protocol/session
policies on different destination IPs while retaining uniform-policy checks
inside each actual TLS listener identity. Configuration testing validates every
generation, and a real two-address handshake test verifies the certificate
presented at each destination.

### 4. Default session lifetime was unbounded until capacity eviction

When `SSLSessionCacheTimeout` was omitted, httpd-rs used Rustls's bounded memory
cache directly. TLS 1.2 entries in that cache do not expire by time, so a
resumed mTLS identity could outlive Apache's default revocation/rotation window.

httpd-rs now always uses a bounded expiring store when session caching is
enabled, with Apache's 300-second default and the configured timeout when
present. The store remains capped at 256 entries, removes expired values on
access/insertion and redacts cached traffic secrets from `Debug`. Real TLS 1.2
and TLS 1.3 full-handshake/resumption integration tests prove that SNI and the
verified client chain survive resumption and yield the identical httpd-rs
connection identity. Reload constructs a new store, so sessions cannot cross
configuration generations.

### 5. `optional_no_ca` was given stronger but different semantics

`SSLVerifyClient optional_no_ca` was accepted with a warning and executed as
Rustls `optional`, which verifies every presented certificate. That is not an
implementation of Apache's unverified-certificate mode and could unexpectedly
deny clients while claiming compatibility. It now fails configuration loading.

Omitted `SSLVerifyClient` and explicit `none` are treated as the same effective
policy, and an unused CA path does not create a false listener-policy mismatch.
Per-location client-auth directives remain rejected because httpd-rs does not
perform TLS renegotiation and must not globalize a request-local policy.

### 6. Connection-wide TLS directives could escape location scope

Several session/stapling compatibility directives were accepted inside a
directory/location and wrote global or vhost state. A nested scope could thus
change session lifetime or cache behavior for an entire listener. These
directives are now limited to represented server/vhost contexts and have a
configuration regression matrix.

### 7. OCSP responder URLs crossed an HTTP serialization boundary unchecked

An AIA URI is certificate-controlled data and `SSLStaplingForceURL` is
administrative data. Both reached an HTTP request line and `Host` field through
a bespoke split. The parser now reuses the verified HTTP-authority boundary,
rejects credentials, invalid ports, fragments and non-visible/request-line
bytes, and renders IPv6 Host fields with brackets. OCSP bodies are still
accepted only after certificate-id, freshness, signer authorization and
signature verification.

### 8. HTTPS proxy verification mishandled bracketed IPv6 identities

Proxy authorities retain IPv6 brackets for HTTP serialization, but Rustls
expects the unbracketed IP literal as its certificate identity. Both synchronous
and asynchronous proxy TLS paths now remove only those brackets before creating
the `ServerName`; hostname/IP certificate verification remains mandatory.

### 9. OCSP cache intervals could outlive an authenticated staple

An OCSP response was checked for freshness when fetched or loaded, but the
live `CertifiedKey` retained the response until the configured cache-refresh
interval. A response with an earlier `nextUpdate` could therefore remain
stapled after httpd-rs's own validator would reject it.

Validation now returns the authenticated response deadline as well as a
boolean verdict. Each TLS generation records that deadline, schedules refresh
before it (including a bounded near-expiry retry schedule), and atomically
removes the staple when the deadline is reached without a valid replacement.
A response is never installed unless both its semantic deadline and a
monotonic in-process deadline can be represented. The cached-startup and live
refresh tests exercise deadline derivation, early scheduling and removal from
the shared certificate key.

### 10. Client-certificate revocation had no usable supported path

httpd-rs correctly rejected unsupported `SSLOCSP*` directives, but it also
treated Apache's CRL configuration as unsupported. Operators could enforce a
trust anchor and certificate lifetime but could not deploy revocation without
placing a different TLS terminator in front of httpd-rs.

`SSLCARevocationFile` and `SSLCARevocationCheck none|leaf|chain` are now typed
configuration fields and part of the listener's immutable handshake policy.
The CRL is a bounded privileged administrative input, is parsed before the TLS
generation commits, and is passed to Rustls/WebPKI with expired CRLs and
unknown revocation status rejected. A revocation mode without a CRL, a CRL
without active checking, revocation configuration without client
authentication, and vhosts with different effective CRL policy all fail
startup. Online client-certificate OCSP remains explicitly unsupported and
fails configuration loading.

## Deliberately closed protocol surface

- Only TLS 1.2 and 1.3 are enabled.
- TLS 0-RTT, half-RTT application data and secret extraction are explicitly
  disabled, rather than relying on dependency defaults.
- All vhosts on a listener must agree on effective client-auth, protocol,
  cipher preference, session-resumption and ALPN policy.
- Unsupported cipher, online client-OCSP, peer-verification and TLS access
  directives fail configuration loading instead of becoming no-ops. Client
  revocation through a bounded PEM CRL supports leaf or complete-chain checks.
- HTTPS proxy connections use WebPKI roots or one bounded, trusted custom CA
  bundle and always verify the configured DNS/IP identity.
- Certificate/key pairs are validated before a generation commits; graceful
  reload retains the complete old generation for its existing connections.

## Formal and test coverage

The verified crate now owns the final decisions for TLS-vhost transition,
SNI-without-authority admission and required-client-identity presence, in
addition to exact client-policy equality and host-pattern matching. Runtime
tests cover first-match resolver parity, exact/catch-all/suffix-wildcard aliases,
destination-address certificate selection, different/equivalent certificate
policies, H1 421 admission, H2 coalescing,
required/optional mTLS, full and resumed mTLS handshakes, default session expiry,
malformed security directives, OCSP URL injection shapes and IPv6 proxy TLS
identity construction. A real negative-handshake matrix rejects wrong server
names, unknown server and client CAs, not-yet-valid and expired server
certificates, a server-only EKU presented for client authentication, a cached
session after the listener's client trust changes, and a revoked client leaf.
An HTTPS health-check integration test proves that a trusted certificate for
the wrong configured IP/DNS identity is still rejected. OCSP tests cover
deadline extraction, early refresh and removal of an expired live staple.

The verified crate additionally owns exact equality of the effective
leaf/chain revocation mode and active CRL identity. The Verus gate reports 665
verified functions and 0 errors.

## Remaining assumptions

Rustls/WebPKI cryptography, X.509 and CRL parsing/path/revocation validation,
handshake transcript binding and persisted-session decoding remain external
trusted dependencies.
The operating system's randomness and time sources are also assumptions.
httpd-rs's formal layer proves the policy joins around those results; it does
not reimplement or claim to prove the cryptographic protocol.
