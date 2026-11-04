# Shared-cache identity and cache-poisoning review

Date: 2026-11-04

This campaign followed the complete identity of a reusable representation
from request admission through policy evaluation, cache-key construction,
memory and disk lookup, response storage, reload generations, and unsafe-
method invalidation. The threat model is one client, tenant, or backend
causing bytes selected under its request context to be served under another
context.

## Identity contract

A Vapache cache entry is now partitioned by all of the following:

- configuration generation, server root, selected virtual host, listener
  address/port and HTTP versus HTTPS scheme;
- exact Host bytes, canonical request and representation URLs, raw query
  bytes, and the resolved filesystem target;
- the complete effective policy object, request method, HTTP protocol and
  effective client address; CGI/FastCGI/custom-handler entries additionally
  bind the source port they export to the backend;
- every normalized request header field and value, with length-framed fields
  before the SHA-256 policy digest; and
- response `Vary` dimensions, freshness, the exact policy digest and the
  complete persisted base key.

This is deliberately conservative. Vapache already partitions entries by
client address and all request headers. The source port is added only when
handler classification says the response can observe it; static entries
remain reusable across connections, while HTTP protocol identity is retained
for every entry. Further reductions in the tuple should wait until the
configuration compiler can prove that a representation does not observe a
particular input.

## Remediated findings

### C1: backend-visible transport inputs were absent from the cache identity

CGI and FastCGI receive `SERVER_PROTOCOL` and `REMOTE_PORT`, but the cache
fingerprint contained neither. A dynamic response could therefore be stored
under one protocol or source port and replayed for a request whose backend
environment would have produced different bytes.

Every fingerprint now includes a verified transport tuple containing the HTTP
version and a handler-visibility bit. Handler-backed fingerprints also include
the full 16-bit peer port; static fingerprints use a canonical zero port.
Tests mutate both inputs and require distinct dynamic policy fingerprints
while requiring static fingerprints to remain stable across source ports.
Verus proves equality of encoded tuples implies equal protocol and visibility,
and equal ports whenever the backend can observe the port.

### C2: cache admission differed between request paths

The ordinary head pipeline made body-bearing GETs unusual, but lookup and
store did not themselves require an unframed request. A fully read or direct
call path could therefore make a framed, currently empty GET look like the
same request as an ordinary bodyless GET. `Proxy-Authorization` was also not
treated as a shared-cache credential.

Lookup and store now consume common verified admission predicates. Cacheable
requests must be unframed, bodyless, and free of `Authorization`,
`Proxy-Authorization`, and `Cookie`. The checks occur at the cache boundary as
well as in scope selection, so a caller cannot bypass them by entering after
the normal head phase.

### C3: request Cache-Control semantics were incomplete

Request directives were previously found by comma splitting and exact byte
comparison. Legal optional whitespace and leading-zero delta seconds could
change the result, duplicate or malformed numeric directives were not treated
uniformly, `min-fresh` was ignored, and a request `no-store` prevented lookup
but not storage of the resulting response.

Request and response policy now use the same bounded RFC list parser. Invalid
metadata fails closed. `no-cache`, `no-store`, `max-age=0`, and legacy
`Pragma: no-cache` force a miss; request `max-age` and `min-fresh` can only
narrow the origin freshness window; and `no-store` independently forbids
storage. The Verus freshness predicate proves a request constraint can never
make an origin-stale entry admissible.

### C4: unsafe-method invalidation omitted response-selected targets

After a successful unsafe request, Vapache invalidated only the effective
request URI. RFC 9111 also requires invalidating same-origin URIs named by
`Location` and `Content-Location`; leaving them live can replay state that the
successful operation just changed.

Invalidation now covers the request URI plus at most one unambiguous value of
each response field. Each candidate must be valid UTF-8 without controls or
backslashes, use HTTP(S) or a relative reference, have the same canonical
scheme/host/port as the request origin, and canonicalize through the ordinary
request-target path logic. Unsupported schemes, cross-origin authorities,
ambiguous duplicate fields, and malformed paths cannot select a local cache
entry. At most three targeted invalidations are performed per response.

## Boundaries reviewed without a new finding

- Proxy routes are never served from or stored in this cache, so upstream
  target identity cannot collide with local cache identity.
- `Range`, response `Set-Cookie`, `Vary: *`, malformed `Vary`, partial
  metadata, private/no-cache/no-store policy, uncacheable statuses and local
  ErrorDocument responses remain ineligible.
- Complete request headers are bound even when a backend omits `Vary`; the
  explicit `Vary` witness remains checked on lookup as defense in depth.
- Stored entries carry the configuration epoch and exact key. Reload rejects
  old generations, and legacy disk formats cannot become live entries.
- TLS client certificates are not exported to CGI/FastCGI or available as a
  representation-selecting expression input. If that changes, the immutable
  certificate identity must be added to the cache tuple before the feature is
  enabled for cacheable responses.
- SHA-256 collision resistance, the safe-Rust hash invocation, cache-directory
  filesystem integrity, and the full runtime-to-Verus refinement remain
  explicit trusted boundaries.

## Regression and proof coverage

The cache suite covers pairwise transport identity, robust request directive
parsing, freshness restrictions, credential and framing rejection, production
store refusal, canonical same-origin response invalidation, and preservation
of unrelated entries. The Verus crate adds executable specifications and
proofs for exact transport identity, lookup/store request admission, monotone
request freshness, and cross-origin invalidation rejection.
