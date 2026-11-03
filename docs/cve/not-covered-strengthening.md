# Strengthening plan for the not-covered Apache CVEs

This follows the 371-CVE triage in `docs/cve/apache2-cve-matrix.json`.
It groups the current **1** `not_covered` row by the security mechanism
that must become a first-class part of the spec.

The proxy hardening landed in `proxy.rs` moved all 23 proxy rows out of
`not_covered` (to prevented, fail-closed or partial).  What remains is listed
below.

## Current category summary

| category | count | high/critical |
|---|---:|---:|
| TLS client — external Rustls certificate parser | 1 | 0 |

Total: **1 not covered**, **0 high/critical**.

All 12 rewrite rows have left the not-covered set.  The rewrite section below
records the invariants extracted from those CVEs rather than claiming the
entire rewrite language is formally refined.  The TLS policy and OCSP rows
also left the set; their boundaries are recorded below.

## Proxy hardening already landed

- Canonical `ProxyTarget` URL now uses the parsed backend identity and path;
  the same value is used for `<Proxy>` authorization, resource binding,
  `Host`, and outbound target identity.
- Bracketed IPv6 backend authorities are parsed without splitting on the
  wrong colon.
- Proxy responses reject ambiguous `Content-Length` + `Transfer-Encoding`,
  duplicate framing headers, unsupported transfer codings, malformed header
  names/values, interim `1xx` responses, excessive header counts/sizes, and
  unbounded trailers.
- Client-supplied `Forwarded`/`X-Forwarded-*` headers are stripped and
  regenerated from the actual peer.
- Unsupported proxy transports (FTP/UDP/etc.) fail at configuration load;
  `ProxyRequests` and `RequestHeader` remain fail-closed; balancer-manager and
  FTP-proxy interfaces are not implemented.
- Proxy error pages use the escaped error-response path.
- Backend connections are not reused; `Connection`-nominated headers are
  stripped from both requests and responses.
- Caching forward proxy mode is unavailable (`ProxyRequests` fails closed).

## Proxy status

All 23 proxy rows are out of `not_covered`, and none remain partial:

- `CVE-2021-40438` — `ProxyPassMatch` and rewrite `[P]` authority templates
  cannot derive from captures/variables; targets are canonical and
  policy-bound.
- `CVE-2024-38473` — proxy paths are encoded exactly once and target identity
  is canonical.
- `CVE-2024-38476` — all backend response headers, including `Location`, pass
  the verified sanitizer.
- `CVE-2024-38477` — Rust proxy state has no nullable-pointer dereference and
  framing/buffers are bounded.

The response-framing refinement and exact front/upstream path witness are now
executable Verus kernels consumed by the runtime. A full semantic refinement
of every upstream application's path interpretation remains future work.

## HTTP/2

### HTTP/2 hardening landed

The h2 adapter now sets bounded header-list, concurrent-stream, initial
window/connection-window, frame, reset-stream, pending-reset and send-buffer
limits, plus a connection idle timeout.  The adapter calls verified
`h2_settings`, `h2_method_ok`/`h2_head_admit`, `H2HeaderState` and
`H2BodyState`, and advances the verified `H2Budget` and `H2Flow` models.
`H2Budget` is driven by the connection/task loop: accepted tasks consume
active slots, completed tasks release them, resets observed through
`SendResponse::poll_reset`, body errors, timeouts or send failures enter the
pending-reset budget, and a timer matching the h2 reset-stream duration
reclaims them.  The h2 crate still owns wire framing, HPACK, SETTINGS state
and some internal resets.  The adapter-boundary H2 rows (`CVE-2018-11763`,
`CVE-2023-45802`, header limits, methods, timeouts, flow buffering) are
closed by H2Settings, H2HeaderState, H2Flow, H2Budget/stream IDs, the idle
timeout and Rust h2 ownership; proxy HTTP/2 backends are not implemented.
There is no remaining H2 partial.

### CVE-2026-23918 retired from the not-covered set

The Apache 2.4.66 double-free was the only H2 `not_covered` row.  It is now
classified **prevented by construction**: Vapache uses the Rust `h2` crate,
whose stream store is keyed by `StreamId` with an ABA guard, and has no Apache
`spurge` array or `h2_stream_destroy` path.  The adapter additionally tracks
stream IDs and uses verified `h2_purge_contains` / `h2_purge_add_idempotent`,
so duplicate early-reset/close cleanup is a no-op.  The early-reset
conformance test sends HEADERS followed by RST_STREAM and verifies the
listener remains healthy.

This does not remove the remaining H2 proof debt: wire framing and resets
handled internally by the h2 crate are still not a formal refinement.  No H2
CVE row remains partial after the adapter-boundary models and runtime
bounds.

## Rewrite rows retired

The 12 rewrite rows were used as prompts for a narrower spec boundary:

- **CVE-2000-0913** — legacy Apache 1.3 expansion: `not_applicable` to the
  current canonical rewrite/filesystem model.
- **CVE-2001-1072** — duplicate slashes are collapsed by the verified
  `normalize_uri_path` before rule matching; conformance regression added.
- **CVE-2003-0542** — Rust regex captures are dynamically sized; a
  12-capture regression exercises the old fixed-buffer boundary.
- **CVE-2013-1862** — rewrite logging is not implemented, so request bytes
  cannot enter a rewrite log; fail-closed.
- **CVE-2019-10098 / CVE-2020-1927** — verified percent-decoding rejects
  encoded control bytes before rewrite; redirect locations are escaped.
- **CVE-2023-25690 / CVE-2024-38474** — `rewrite_backref_no_qmark` proves the
  default backreference/variable expansion cannot introduce `?`; unsafe
  behavior requires the explicit `UnsafeAllow3F` flag.
- **CVE-2024-38475** — `rewrite_filesystem_admit` proves an absolute rewrite
  file target is below the current document/alias root; `UnsafePrefixStat` is
  parsed for compatibility but never changes the authorization base, and
  target authorization is re-evaluated.
- **CVE-2024-39573** — proxying requires explicit `[P]`; external
  substitutions otherwise redirect, and proxy targets are canonical and
  access-checked.
- **CVE-2025-54090** — Apache 2.4.64-specific regression; the independent
  expression evaluator has a false-expression regression.
- **CVE-2026-56154** — lookahead (`LA-U`/`LA-F`) is rejected at configuration
  load; fail-closed.

The full rewrite AST, regex language and expression truth are still outside
Verus.  These rows are closed only at the stated boundaries, not because the
whole module is proved.

## Cache rows retired

The three cache partials were resolved by construction:

- disk metadata stores response headers, never request headers, and
  Authorization/Proxy-Authorization are excluded;
- the verified parser rejects CL/TE smuggling and the cache accepts only
  GET/HEAD without a request body;
- empty Content-Type is handled as an empty value in safe Rust.

## Path, range and logging rows retired

- Cygwin/encoded-backslash traversal is rejected by verified path bytes.
- suexec CVEs are not applicable because suexec is not implemented.
- All multi-range/repeated/overlapping Range requests are rejected; only one
  bounded single range is served.
- Access and error logs use the verified `escape_log_bytes` primitive for
  terminal controls.
- The Mandrake autoindex default and third-party auction.pl XSS are not
  applicable.

## Auth / `.htaccess` rows retired

The seven auth partials were third-party providers/tools or implemented
policies:

- SMB/auth-mysql/usertrack/RSA-agent classes are not loaded or shipped;
- htpasswd/htdigest utilities are not part of Vapache;
- legacy `Satisfy`/`Order` merging and AuthRequired-vs-Denied policy use the
  verified policy combinators and the single access evaluator.

The two `.htaccess` privilege rows were expression file-read issues.
`file()` and `filesize()` data reads now resolve only beneath
`DOCUMENT_ROOT`; absolute, parent-relative and symlink-escaping reads fail
closed.  `FileTest` remains metadata-only (and supports admin `<IfFile>`
absolute paths).  The broader local privilege-separation model is still not a
formal Verus refinement.

## HTTP parser rows retired

The 11 HTTP parser/framing/response partials were resolved at these
boundaries:

- verified `escape_log_bytes` covers access-log control/quote/backslash
  injection;
- generic error pages do not reflect `Expect` or the request method;
- chunk trailers are parsed and discarded, never merged into request
  headers;
- body read/discard failures return an error and close the connection, so a
  pipelined request is not reused;
- every response header passes the verified `sanitize_header_value` before
  serialization;
- split-logfile, HP Secure OS, reverse-DNS log injection, Hyperguard WAF and
  the RHEL-specific legacy Allow/Deny regression are not applicable.

The parser-to-`Request` translation beyond the verified head/framing subset
is still not a full Verus refinement.

## Generic DoS rows retired

The 13 generic-DoS partials were mostly old APR/C parser or platform
classes.  The resolved boundaries are:

- strict verified HTTP/1 head and chunk framing, exact head-size limits and
  bounded body spooling;
- explicit compression cap (8 MiB) with no post-disconnect worker;
- request decompression filters are unsupported and fail closed;
- APR-only OS/2, big-endian and `fnmatch` classes are not applicable;
- HTTP/2 header/flow/settings models bound the adapter side; the response
  path reserves/polls h2 capacity before every DATA send, so a zero-window
  client cannot queue unbounded response bytes.

The HPACK/zero-window row (`CVE-2026-49975`) is now closed at this boundary;
the h2 crate's internal HPACK state is still an external implementation
assumption, not a Verus refinement.

## CGI / FastCGI rows retired

The 15 CGI/FastCGI partial rows were used as prompts for narrower
boundaries:

- sample scripts (`nph-test-cgi`, `phf`, `test-cgi`, `printenv`) are not
  shipped; `htdigest` and mod_fcgid process management are absent;
- CGI stderr is drained on a separate bounded thread and CGI has an explicit
  timeout/process-group kill;
- FastCGI/CGI response headers are bounded to 64 KiB and parsed in safe Rust;
- configured/rewrite environment entries cannot override reserved calculated
  CGI variables;
- CGI `Location` responses are not followed as internal redirects.

The full CGI environment, FastCGI protocol and handler semantics are still
not a Verus refinement; the rows are closed only at these boundaries.

## TLS client policy

### Per-vhost client-certificate policy — resolved

`CVE-2019-0215` / `CVE-2025-23048` prompted a listener-level policy
invariant.  Rustls has one client-certificate verifier per `ServerConfig`, so
Vapache now rejects a TLS listener whose virtual hosts disagree on
`SSLVerifyClient`, `SSLCACertificateFile`, `SSLCARevocationFile` or
`SSLCARevocationCheck`.  A single uniform policy means
session resumption cannot cross a vhost with a different client-auth policy.
Per-location client-authentication and revocation policy is rejected at
configuration load because Rustls authenticates the connection, not an
individual request.

PEM certificate-revocation lists are supported with Apache's
`SSLCARevocationFile` and `SSLCARevocationCheck leaf|chain` directives. Rustls
checks the configured leaf or complete presented chain, rejects unknown
revocation status, and rejects expired CRLs. Online client-certificate OCSP is
not claimed: `SSLOCSP*` remains a security-sensitive startup error.

The completed handshake now retains immutable SNI, selected TLS-policy and
verified client-certificate identity for both full and resumed sessions.
HTTP/1 keep-alive and HTTP/2 coalescing return 421 when a request authority
would select a different certificate/client-auth policy. TLS and HTTP vhost
selection share first-match wildcard semantics, and the bounded session store
uses Apache's 300-second default expiry.

### OCSP response path — prevented

`CVE-2026-44185` prompted bounded HTTP response parsing for the OCSP fetch:
line, header and body limits are enforced, and the DER TLV parser checks
bounds in safe Rust.  The C buffer over-read primitive is absent; the
external Rustls certificate parser remains the separate dependency row.
Staple lifetime is derived from the authenticated `nextUpdate` value (or the
bounded no-`nextUpdate` lifetime), refresh is scheduled before that deadline,
and an expired response is removed from the live certificate generation
rather than being served until the configured cache interval elapses.

### External certificate parser — the remaining not-covered row

`CVE-2004-0488` is the sole remaining `not_covered` row.  Rustls replaces the
legacy OpenSSL parser, but the external crate is an explicit trusted
dependency, not a Vapache formal proof.  Keeping this row honest is more
useful than calling an external parser “proved”.

**Strengthening:** pin and test the Rustls dependency, track its advisories,
and record the parser as an explicit assumption in the verification ledger.

## Cross-cutting strict profile

To make the remaining dependency boundary less likely to fail while the
formal models are extended, add a strict security profile that rejects:

- forward proxy and unmodeled proxy transports,
- expression conditions outside the verified AST,
- any future request-level use of client-certificate identity unless cache and
  authorization keys bind the immutable connection identity.

Then build a replay corpus for the **0 high/critical** rows, starting with the external Rustls parser assumption.
