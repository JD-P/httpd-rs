# Malicious backend response review

Date: 2026-11-03

This campaign followed attacker-controlled response bytes from HTTP proxy,
CGI and FastCGI ingress through response normalization, header policy,
compression, shared-cache admission, disk persistence and the HTTP/1 and
HTTP/2 writers. WebSocket switching responses were reviewed as the separate
raw-protocol transition they are. The threat model includes a compromised or
less-trusted application backend attempting to affect another cache user or
to make httpd-rs and a downstream recipient interpret different metadata.

## Remediated findings

### R1: incomplete cache-policy field-set parsing

Cache admission, compression and the Expires filter inspected only the first
`Cache-Control` field line and split it naively on commas. A backend could put
`public` or a TTL first and a later `private`, `no-store`, `no-cache` or
`no-transform` directive second. Worse, the Expires filter replaced all field
lines with a synthesized first-line value, erasing the later restriction
before cache admission. Qualified forms such as `private="Set-Cookie"` also
did not match the exact-string checks. Malformed or conflicting freshness
metadata could fall through to the default TTL.

One strict parser now owns all `Cache-Control` field lines, quoted strings and
quoted commas. Cache admission fails closed on malformed policy, recognizes
qualified privacy directives, and rejects duplicate or invalid numeric TTL
directives. Directive and `Vary` dimension counts are capped before owned
per-item allocations, preventing a small response head from amplifying into
unaccounted parser memory. Origin `Age` and apparent age from `Date` now
consume the declared freshness lifetime, and the heuristic `CacheMinExpire`
floor cannot revive an explicitly stale response. Compression applies the
same complete policy and preserves the identity representation when policy is
malformed. `Vary` is likewise parsed as one complete field set; an empty,
malformed, wildcard or over-limit dimension set makes the response ineligible
for shared storage. The Expires filter now appends its own directive only
after validating the complete policy and never destroys pre-existing field
lines.

### R2: response-normalization provenance was lost before caching

HTTP and CGI backends may use `Connection` to nominate other fields for
hop-local removal. httpd-rs removed those fields before constructing the
internal response. That made the immediate response safe to forward, but it
also erased the evidence that representation metadata had been removed. The
normalized response could then look eligible for the shared cache.

The verified backend disposition now has three results: reject framing
nominations, forward-only after an end-to-end nomination, or cacheable for
ordinary connection options. `Response` retains the forward-only decision
through filters and dispatch. Cache admission independently rechecks any
still-present `Connection` field, so neither early nor late normalization can
lose the restriction. `Connection: close` remains cacheable; nominations of
`Content-Length`, `Transfer-Encoding` or `Connection` are rejected.

### R3: ambiguous response metadata entered the shared cache

Duplicate singleton metadata (`ETag`, `Expires`, `Last-Modified`, `Location`,
`Age`, `Content-Type`, `Content-Range` and related fields) could be persisted even
though consumers are not required to choose the same instance. A cacheable
full response could also carry partial-response `Content-Range` metadata.

Shared-cache admission now rejects duplicate singleton metadata and rejects
`Content-Range` on the admitted full-response statuses. Invalid dates no
longer select the default freshness path.

### R4: malformed backend fields diverged across HTTP versions

CGI admitted response control bytes that the final HTTP/1 writer rejected.
The HTTP/2 writer silently dropped malformed names or values and still sent
the backend-selected body. Thus the same internal response could fail on
HTTP/1 but become a different successful response on HTTP/2.

CGI now consumes the same verified field-name/value admission predicate as
the proxy parser. Both output adapters consume a common complete response
validation gate. HTTP/1 rejects an invalid response before writing its head;
HTTP/2 emits a canonical local 500 rather than dropping only the offending
fields and forwarding the hostile body.

### R5: FastCGI response records were not bound to the request

The record reader accepted STDOUT, STDERR and END_REQUEST records without
checking their request ID, ignored unexpected application records, accepted a
nonzero reserved header byte, and treated malformed or non-complete
END_REQUEST bodies as success. This weakened the record boundary even though
httpd-rs currently uses one request per backend connection.

Recognized response records must now carry request ID 1. Only management
records may use ID 0 and be ignored; unknown application records fail closed.
The header reserved byte, END_REQUEST length, protocol status and reserved
tail bytes are validated before a response can be constructed. The fuzz entry
point now drives successful record streams through CGI response conversion as
well as the record decoder.

### R6: pre-fix disk entries survived the new admission rules

V6 entries may have been written under the incomplete cache-policy rules.
Serving them after upgrade would bypass the new admission boundary. V7 is the
only disk metadata generation eligible for lookup; older entries remain
decodable for bounded cleanup and diagnostics but cannot provide a live cache
key.

### R7: WebSocket negotiation selections were not bound to the client offer

The WebSocket switching path strictly validated `Upgrade`, `Connection` and
`Sec-WebSocket-Accept`, but treated `Sec-WebSocket-Protocol` and
`Sec-WebSocket-Extensions` as ordinary response fields. A malicious backend
could therefore select an unoffered subprotocol or extension, repeat a
selection, return malformed extension parameters, or use duplicate parameter
names. The raw 101 parser also had a byte ceiling but no independent header
count ceiling.

Client offers now compile into a bounded typed negotiation model before
routing or upstream connection. Subprotocol tokens must be unique and
extension lists must satisfy the RFC 6455 token/quoted-token grammar, with
unique parameter names and explicit item/parameter ceilings. A backend may
select exactly one offered subprotocol and only offered, non-duplicated
extension names. Request-only WebSocket fields are rejected in a 101,
response header count and bytes are jointly bounded, and admitted selections
are serialized into one canonical field per negotiation dimension. Extension-
specific parameter semantics remain correctly owned by the WebSocket client
and application endpoint; the proxy enforces the generic wire grammar and
offer/selection relationship without pretending to implement each extension.
The selection gate is an executable Verus predicate proving that malformed,
unoffered or duplicate selections cannot be admitted.

## Boundaries reviewed without a new finding

- HTTP proxy response lines require strict CRLF, a valid HTTP/1 status and no
  informational response on the normal proxy path.
- Content-Length/Transfer-Encoding selection is a single verified decision;
  duplicate, conflicting and unsupported framing is rejected.
- Chunk sizes, chunk count/framing work, trailer count/bytes and total bodies
  are bounded. Trailers are validated and discarded rather than merged into
  cached metadata.
- httpd-rs does not decompress backend bodies, so a compressed upstream body
  cannot expand inside the server. Locally generated compression remains
  resource-accounted.
- Proxy and FastCGI bodies have explicit output ceilings and aggregate spool
  accounting. Large fixed-length proxy bodies stream with an exact remaining
  length.

## Retained evidence

The primary deterministic regressions are:

- `http::tests::cache_control_parser_owns_all_field_lines_and_quoted_commas`
- `cache::tests::production_store_rejection_and_eviction_edges`
- `compression::tests::ranges_and_no_transform_bypass_compression`
- `compression::tests::conditional_etag_honors_no_transform`
- `expires::tests::apply_covers_inactive_status_invalid_and_cache_control_edges`
- `cgi::tests::parse_cgi_response_edge_cases`
- `proxy::tests::proxy_response_success_and_streaming`
- `proxy::coverage_tests::websocket_negotiation_is_typed_bounded_and_offer_bound`
- `proxy::coverage_tests::websocket_async_binds_backend_negotiation_to_client_offer`
- `proxy::coverage_tests::websocket_async_rejects_unoffered_backend_selection`
- `fastcgi::tests::response_reader_unknown_records_and_output_limit`
- `h2::tests::response_sender_covers_stream_and_every_file_strategy`

The CGI, proxy and FastCGI fuzz targets now continue through the semantic
response/cache-policy boundary after successful wire parsing. A dedicated
WebSocket negotiation target exercises client protocol/extension offers, raw
101 parsing and structured selection responses. Verus proves the three-way
`BackendConnectionDisposition` decision, including that framing nominations
reject and stripped end-to-end metadata never becomes cacheable, plus the
WebSocket selection admission rule.
