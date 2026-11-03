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

## Preserved invariants

- HTTP/1 body readers consume exactly the selected fixed length or the complete
  strict chunked message and leave subsequent bytes for the next request.
- HTTP/2 forbids connection-specific fields, validates declared length against
  DATA length, and is reserialized rather than downgraded byte-for-byte.
- Normal proxy responses use exact CRLF, reject every informational status,
  make one verified CL/TE/EOF framing decision, decode chunking, and are
  reserialized. Upstream sockets are not pooled.
- CGI and FastCGI response fields are parsed into the internal response model;
  their raw framing fields are not sent to the client.
- WebSocket is the only raw tunnel and is entered only after the reconstructed
  101 has passed complete handshake validation.

## Regression and proof coverage

- Unit matrices cover duplicate/equal CL, duplicate TE/Connection/Expect,
  leading CRLF, `Proxy-Connection`, invalid connection nominations, TE
  nomination, expectation handling, body-bearing upgrades, malicious 101
  fields and co-read first-frame preservation.
- Property tests generate fixed-length and chunked bodies plus a second
  pipelined request under arbitrary 1–127-byte read fragmentation. The first
  body and second request must remain exact and no bytes may remain.
- Live conformance cases exercise the strict rejection behavior and 417
  expectation response.
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
