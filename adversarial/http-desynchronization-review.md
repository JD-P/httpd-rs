# HTTP desynchronization review

Date: 2026-11-03
Baseline: `28d309e` (`origin/main` before this campaign)

## Scope and threat model

This review treats message boundaries as a property of the complete chain, not
only of Vapache's parser. The relevant boundaries are:

1. client or front proxy to Vapache over HTTP/1;
2. an HTTP/2 request translated into Vapache's internal request and then an
   HTTP/1 backend request;
3. Vapache to a reverse-proxy backend and back;
4. the HTTP/1 to WebSocket protocol transition; and
5. CGI/FastCGI output translated back into an HTTP response.

The fail-closed rule is that a byte stream must select one framing decision
before a body is consumed, and raw framing metadata from one hop must not be
forwarded to another hop. Parse failures close the client connection, so bytes
left after a rejected request cannot become a later request.

## Findings and remediation

### D1: duplicate and hop-specific request metadata was too permissive

The verified request parser already rejected conflicting `Content-Length`,
`Content-Length` plus `Transfer-Encoding`, non-canonical transfer codings,
bare-LF lines, obs-fold and malformed chunks. It nevertheless accepted some
forms that adjacent HTTP implementations do not treat uniformly: identical
duplicate `Content-Length`, duplicate `Transfer-Encoding`, multiple
`Connection` lines, contradictory persistence options, `Proxy-Connection`, a
leading empty line, an un-nominated `TE` field, and unsupported `Expect`
values.

The parser now accepts a deliberately strict intermediary subset:

- exactly one `Content-Length` or one exact `Transfer-Encoding: chunked`;
- no leading empty request line and no `Proxy-Connection`;
- one syntactically valid `Connection` list, with contradictory persistence
  tokens, duplicate options and unimplemented field nominations rejected (only
  `close`, `keep-alive`, `upgrade` and `te` are accepted);
- `TE: trailers` only when `Connection` nominates `TE`; and
- one exact HTTP/1.1 `Expect: 100-continue`, only on a request with a body.

Unsupported expectations return 417. Other ambiguity returns 400. These errors
are produced by the verified head compiler before any body is read.

### D2: WebSocket switching responses crossed a raw protocol boundary

The WebSocket path previously validated selected handshake values and then
forwarded the backend's original 101 head. A backend could therefore attach
duplicate handshake fields or `Content-Length`/`Transfer-Encoding` metadata to
the protocol switch. Also, bytes read in the same socket read after the header
terminator were discarded, potentially dropping the first WebSocket frame.

The path now requires exactly one canonical `Upgrade: websocket`, one
`Connection: Upgrade`, and one exact `Sec-WebSocket-Accept`; rejects all
framing and hop metadata on a 101; reconstructs the 101 response; and forwards
any bytes co-read after its header as the first tunnel bytes. Requests with a
body or expectation cannot enter tunnel mode. A non-101 backend response is
turned into a complete zero-length closing HTTP response instead of forwarding
unconsumed body framing.

### D3: ordinary proxy requests advertised reuse that never happened

Vapache deliberately opens a fresh upstream connection for each ordinary
proxied request, but sent `Connection: keep-alive`. It now sends
`Connection: close`, matching ownership and eliminating any possibility that
unconsumed upstream bytes could poison a later request. Client request heads
are still reconstructed from parsed fields and decoded body length; raw client
framing is never forwarded.

### D4: mixed CGI line endings could move the response boundary

CGI permits CRLF and LF header lines. The in-memory CGI parser and the
file-backed FastCGI path searched for a CRLF terminator before considering an
earlier LF terminator. A script could therefore place an LF boundary first and
a CRLF boundary in its body; the latter was selected and body bytes such as
`Status` or `Location` were promoted into response metadata.

Both paths now share one boundary selector that chooses the earliest delimiter
by byte position. CGI metadata is also singular where its meaning is singular:
duplicate `Status`, `Location`, or `Connection` fields are rejected, the
complete `Connection` list is parsed strictly, and hop-by-hop nominations
cannot erase or reinterpret CGI framing or status fields.

### D5: response Content-Length ownership depended on protocol path

HTTP/1 and HTTP/2 did not apply one status-aware rule to an application-supplied
`Content-Length`. In particular, a 1xx or 204 response could retain a configured
length even though it cannot carry a body, while HEAD and 304 metadata was not
validated consistently.

Both writers now consume the same decision: strip caller framing, never emit a
length for 1xx or 204, compute the actual length for an ordinary response, and
preserve only one strictly parsed, canonically serialized length for HEAD or
304. Duplicate, list-form, signed, or otherwise non-decimal preserved lengths
fail closed.

### D6: HTTP/2 request lengths were normalized differently from HTTP/1

The HTTP/2 adapter formerly accepted equal repeated lengths and Unicode
whitespace through generic string trimming. It also retained the raw spelling
when translating a request to CGI or FastCGI. That created an interpretation
boundary even though the adapter later checked the DATA length.

The adapter now accepts exactly one field, ASCII SP/HTAB around one unsigned
decimal value, and replaces it with its canonical decimal spelling before
routing. Equal duplicates, comma lists, Unicode whitespace, signs, and overflow
are rejected. The declared value must still equal the received DATA length.

### D7: WebSocket switching was not restricted to HTTP/1.1 on both hops

Upgrade is an HTTP/1.1 transition, but an otherwise valid HTTP/1.0 client or an
HTTP/1.0 backend 101 could enter the tunnel path. Vapache now requires HTTP/1.1
on the client request and the backend switching response in addition to the
existing exact handshake checks.

### D8: response connection state was still caller-controlled

The response writers owned `Content-Length` and `Transfer-Encoding`, but the
HTTP/1 path could still forward a handler or `Header` directive's `Connection`,
`Keep-Alive`, `Upgrade`, `TE`, or `Trailer` fields before appending its own
connection decision. That could produce contradictory persistence metadata,
and a `Connection` nomination could leave another hop-specific field in the
outbound message. HTTP/2 removed only part of the same set.

Both writers now parse the complete caller-supplied `Connection` list, reject
malformed or duplicate options, remove every nominated field, and remove the
complete fixed hop-by-hop set before serializing transport-owned metadata.
HTTP/1 emits at most its single `Connection` decision; HTTP/2 emits none.

The bodyless status matrix now also includes 205 across CGI, file-backed
FastCGI, ordinary proxy framing, HTTP/1, HTTP/2, compression and expiration.
An upstream 205 is accepted only without transfer coding and with no declared
length or an exact zero length. Outbound 205 responses discard any body and
emit the transport-owned `Content-Length: 0` needed to delimit a persistent
HTTP/1 response.

### D9: cache storage lost Connection nominations

The live response writers removed both `Connection` and every field it
nominated, but cache storage removed only the fixed hop-by-hop names. A
configured response containing `Connection: X-Hop` and `X-Hop: secret` was
safe on its first response, then persisted `X-Hop` without the nomination. A
cache hit could consequently replay it as an end-to-end field.

Proxy ingestion, cache storage, HTTP/1 and HTTP/2 now share one strict response
header sanitizer. It rejects malformed and duplicate options, uses hash-set
duplicate detection, and caps nominations at 64 options and 4 KiB before
allocation can amplify a response head. Ordinary proxy responses no longer
ignore malformed `Connection` list members, and WebSocket token validation uses
the same bounded parser. Cache storage consumes the sanitized end-to-end field
set, strips transport-owned length metadata, and writes V6 metadata; V5 and
older disk entries are deliberately ineligible after upgrade.

## Preserved invariants

- HTTP/1 body readers consume exactly the selected fixed length or the complete
  strict chunked message and leave subsequent bytes for the next request.
- HTTP/2 forbids connection-specific fields, validates declared length against
  DATA length, and is reserialized rather than downgraded byte-for-byte.
- Normal proxy responses use exact CRLF, reject every informational status,
  make one verified CL/TE/EOF framing decision, decode chunking, and are
  reserialized. Upstream sockets are not pooled.
- CGI and FastCGI response fields are parsed into the internal response model;
  their earliest wire boundary wins and raw framing fields are not sent to the
  client.
- WebSocket is the only raw tunnel and is entered only after the reconstructed
  HTTP/1.1 101 has passed complete handshake validation.
- HTTP/1 and HTTP/2 response writers own framing and share the same
  status-aware `Content-Length` preservation rule.
- Proxy ingestion, cache storage and both writers share one bounded connection
  state parser; fixed or nominated hop-by-hop fields cannot be resurrected by
  an intermediate representation.

## Regression and proof coverage

- Unit matrices cover duplicate/equal CL, duplicate TE/Connection/Expect,
  leading CRLF, `Proxy-Connection`, invalid connection nominations, TE
  nomination, expectation handling, body-bearing upgrades, malicious 101
  fields and co-read first-frame preservation.
- Property tests generate fixed-length and chunked bodies plus a second
  pipelined request under arbitrary 1–127-byte read fragmentation. The first
  body and second request must remain exact and no bytes may remain.
- Live conformance cases exercise the strict rejection behavior and 417
  expectation response, CGI mixed-boundary handling, 204 length stripping,
  and HTTP/1.0 WebSocket rejection.
- The revised request-head compiler verifies under Verus: 648 functions and
  zero errors at the time of this review.

## Remaining boundaries

No parser can guarantee agreement with every possible third-party front end.
Deployments should still configure a front proxy to reject, rather than
normalize, ambiguous HTTP/1 and should avoid rewriting rejected bytes onto a
fresh backend connection. Vapache's strict subset makes disagreement less
likely and ensures its own outbound messages are canonical.

The HTTP/2 wire codec remains dependency-owned, although Vapache independently
checks the semantic header and body invariants at the adapter. Application
protocols behind ordinary HTTP proxying can still assign different meanings to
URI syntax; that is an authorization/normalization issue rather than an HTTP
message-boundary issue and remains covered by the proxy representation witness
and target restrictions.
