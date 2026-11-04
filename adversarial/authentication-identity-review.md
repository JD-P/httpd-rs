# Authentication providers and identity-lifetime review

Date: 2026-11-04

This campaign followed HTTP Basic credentials from the HTTP/1 and HTTP/2
header views through file-provider lookup, password verification, nested
authorization, internal/canonical target transitions, proxy failover, CGI and
FastCGI export, access logging, reload overlap, and credential-file mutation.
The central invariant is that authentication failure is never an empty or
anonymous success, while a successfully authenticated identity belongs to
exactly one logical request and survives every authorized transition of that
request.

## Remediated findings

### A1: Unicode whitespace changed the Basic authentication grammar

`authenticate` converted the complete `Authorization` field to UTF-8 and used
Rust's Unicode `trim`/`char::is_whitespace`. HTTP field values permit obs-text,
but Apache's authentication grammar is byte-oriented. A UTF-8 em-space after
`Basic` was therefore a separator in Vapache and ordinary data in Apache.
With otherwise valid credentials, the retained raw-wire oracle produced
Apache `401` versus Vapache `200`.

Basic scheme parsing now consumes bytes, recognizes only ASCII SP/HTAB at the
scheme boundary, rejects whitespace inside the token, and sends the resulting
token through the existing bounded Base64/credential parser. Group membership
uses ASCII whitespace as well, and stored hashes are no longer Unicode-
trimmed before verification. `basic_authorization_shape_admit` and its
non-ASCII-separator proof make the runtime admission boundary explicit.

### A2: authenticated identity was owned by an executor thread

The authenticated username lived in a thread-local slot. Ordinary dispatch
reset and consumed it carefully, but this made the lifetime depend on the
current executor rather than the request object. More concretely, a protected
lexical CGI path that resolved through a symlink could authenticate correctly,
then independently authorize an unprotected canonical target and construct a
new grant without the original identity. CGI/FastCGI consequently lost
`REMOTE_USER`; `AUTH_TYPE` was also derived from the canonical scope and was
lost even when the username survived.

The immutable request header object now owns a clone-shared, monotonic identity
cell. Internal request clones share it; unrelated requests never do. Top-level
dispatch resets the cell before authentication and takes a non-destructive
snapshot for access logging; the binding itself remains live until the request
and all internal clones are dropped, including across deferred backend work.
Repeated authentication may confirm the same username but cannot overwrite it
with a different username. Canonical-target grants and proxy failover preserve
an already established identity without using it to satisfy the new target's
independent authorization check. CGI and FastCGI export `AUTH_TYPE=Basic`
whenever their bound grant carries an HTTP-authenticated user, which is exact
because Basic is the only implemented HTTP authenticator.

The conformance suite exercises a Basic-protected symlinked CGI whose canonical
target has no authentication directives and requires Apache-equivalent
`REMOTE_USER=alice` and `AUTH_TYPE=Basic`. Unit coverage interleaves cloned and
unrelated requests and proves that a conflicting identity cannot replace the
first binding. `request_identity_record_admit` is consumed at the mutation
site, with a proof that the conflicting transition is rejected.

### A3: group-provider failure was represented as empty membership

An absent or unreadable `AuthGroupFile` produced an empty group vector. A
positive `Require group` still denied, but a negated group provider could turn
the missing provider into a neutral result and allow a surrounding
`<RequireAll>` containing another positive provider. Vapache now treats this
as an unavailable security provider: a provider that was never configured or
could not be read must not become evidence for a negative authorization claim.
The raw Apache 2.4.69 oracle returns `200` for this exact missing-provider
configuration; Vapache's `403` is therefore recorded as deliberate fail-closed
hardening rather than accidental parity drift.

Identity now carries `None` for unavailable group data and `Some(empty)` for a
successful lookup with no memberships. Only the group provider consumes that
state: `valid-user` and `user` continue to work if an irrelevant group file is
bad, while both positive and negated group checks deny on provider failure.
`group_provider_result` proves that unavailable lookup always returns
`Denied`, independently of membership and negation.

### A4: cache-hit revalidation compared only device and inode

Authentication cache keys already included path, device, inode, size, mtime
and ctime. On a hit, however, path revalidation reopened the file and compared
only device/inode. An in-place credential edit racing after the first metadata
snapshot could therefore authorize once from the old parsed snapshot even
though the file's size/timestamps had changed.

The reopened path must now match the complete cache key before parsed data is
reused. The post-read check retains the same complete comparison. A regression
rewrites the same inode at the same path with a different-sized credential and
requires the old snapshot to be rejected. `auth_cache_snapshot_admit` and its
changed-snapshot proof are consumed by the cache-hit path.

## Boundaries reviewed without another finding

- HTTP/1 and HTTP/2 merge repeated `Authorization` fields into the same
  comma-separated view, which Basic decoding rejects; CGI/proxy sinks cannot
  select a different duplicate value from the authorization provider.
- User lookup is exact and case-sensitive, duplicate usernames fail closed,
  usernames exclude controls/colon, passwords and files are bounded, and
  unsupported or over-cost password formats deny.
- Credential files are strict UTF-8 regular files opened nonblocking and
  without symlink traversal. Operator ownership is the default; the explicit
  mutable-file capability still retains complete snapshot revalidation.
- `Require valid-user`, `user`, and `group`, nested provider containers,
  method limits and `AuthMerging` continue through the common fail-closed
  policy evaluator. Duplicate group records retain Apache's union behavior.
- Cache admission rejects `Authorization` and `Proxy-Authorization`; an
  authenticated representation cannot become a shared anonymous response.
- Graceful reload generations share only bounded parsed credential snapshots
  keyed by complete filesystem identity; request identity remains local to
  the request generation that established it.

The cryptographic implementations of bcrypt, SHA-1, salted SHA-1 and
MD5-crypt remain trusted safe-Rust dependencies. The new Verus obligations
cover admission and state transitions around those implementations rather
than claiming a proof of the hash algorithms themselves.
