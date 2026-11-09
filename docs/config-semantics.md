# Configuration semantics: model and proof plan

This document is the bridge between the implementation and a future
machine-checked model of Apache configuration semantics.  It is deliberately
smaller than the full Apache directive set.  The goal is to define the
security-relevant core precisely enough to prove, and to state exactly which
parts are still implementation detail.

The running implementation now uses `policy_ref::effective_scope_with_layers`
for both configuration phases and access-file interleaving.  The access-file
walker only parses files and builds `AccessLayer` values; it does not merge
them.  This discharges the production equivalence obligation by
construction: there is one evaluator, not two.  The phase plan and the
security-relevant merge decisions are now Verus-checked and consumed by that
evaluator (counts and exact boundaries in §10a).  Container/list merging,
directive disposition and `.htaccess` layer-slot translation use verified
helpers. Configuration quote/escape tokenization, section-tag delimiters,
argument bounds and section-depth transitions now consume executable verified
kernels. Main and access-file configuration are sealed into immutable programs
with exact section mates and semantic directive/section values before effects
are applied. Fallible regex, expression, route, authorization, TLS, listener,
method, expiry, environment and compatibility payload parsing therefore cannot
be hidden in a skipped branch or partially mutate policy before failing.

## Process capability boundary

Compatibility features that expand parsing, filesystem discovery, generated
content, or execution are off by default. `VapacheCapability NAME On` is valid
only in global server context. The supported names are
`AbsoluteRequestTarget`, `AccessFiles`, `AutoIndex`, `Cgi`, `FastCgi`,
`LegacyAuthz`, `MutableAuthFiles`, `RequestTrailers`, `RewriteProgram`,
`ServerStatus`, `Trace`, and `UnstableFastCgiPaths`.

The compiler records every effectful use, evaluates capability declarations
independently of directive order, and refuses startup when the final global
set lacks a required capability. Access-file parsing has no capability
directive and independently rejects gated options, handlers, and legacy
authorization when their global gate is absent. Final TRACE, directory-list,
CGI, FastCGI, and status sinks check the gate again. Thus configuration
acceptance and request dispatch obey the same invariant:

```text
requested(feature) ==> globally_enabled(capability(feature))
```

FastCGI has a second, independent boundary: each configured backend requires
an exact `VapacheFastCGIStablePath On` policy. The historical pathname-only
handoff is available only through the separately reviewable
`UnstableFastCgiPaths` capability. Configuration compilation records that
requirement and the final FastCGI sink consumes the verified capability gate
again, so programmatically constructed or access-file-selected routes cannot
bypass it.

`--audit-capabilities` suppresses only missing-capability errors so an
existing main configuration can report the opt-ins it requires. It does not
enable those capabilities and does not infer trust from access-file contents.
The resulting audit artifact is marked non-runnable and rejected by request
dispatch, so callers cannot use suppressed audit diagnostics as a startup
bypass.

Authentication databases have a separate data-authority boundary. Both
`AuthUserFile` and `AuthGroupFile` must be bounded strict UTF-8 regular files
opened without following symlinks. Their complete parent chain and final file
must be immutable to the service identity by default; file ownership is
treated as mutation authority even when the owner-write bit is currently
clear. `MutableAuthFiles` is an explicit compatibility opt-in for deployments
that intentionally let the service update these databases. Startup, reload,
and every runtime read repeat the check, including files named by access-file
configuration. Parsed-database cache hits revalidate the complete device,
inode, size, mtime and ctime snapshot. An absent or unreadable group provider
is distinct from a successful lookup with no memberships and denies both
positive and negated group requirements.

## 1. Scope of the model

In scope:

- request path canonicalization and vhost selection
- `<Directory>`, `<DirectoryMatch>`, `<Files>`, `<FilesMatch>`,
  `<Location>`, `<LocationMatch>`
- `<If>`, `<ElseIf>`, `<Else>`, `<IfFile>`
- `<Limit>`, `<LimitExcept>`, method scoping, `AllowMethods`
- `AllowOverride`, `AllowOverrideList`, `Nonfatal=...`, `AllowOverride`
  categories, `.htaccess`
- `Require`, `<RequireAll>`, `<RequireAny>`, `<RequireNone>`, `AuthMerging`
- `Satisfy`, legacy `Order`/`Allow`/`Deny`
- `Options` merge algebra and `AllowOverride Options=...`
- cache-enable/disable prefix selection (for the prefilter invariant)

Out of scope for the first proof:

- TLS, HTTP/2 wire framing, CGI, proxy protocol details, rewrite substitution
- authorization backends (file/Digest/LDAP)
- regex implementation correctness (the model assumes a trusted `Regex`
  matcher with a stated language)
- filesystem race semantics beyond the `openat` containment argument
- logging and response formatting

## 2. Domains

Let:

- `Path` be a canonical absolute filesystem path.
- `Url` be a canonical absolute URL path with no `.`/`..` and a preserved
  trailing slash.
- `Method` be an HTTP method token, with the Apache-equivalence
  `HEAD ~ GET`.
- `Request` carry `(method, url, headers, peer, env)`.
- `Config` be the compiled immutable configuration.
- `Scope` be the merged directive state for a directory.
- `Rule` be `(kind, delta, order, condition, branch, chain, nested)`.
- `Phase` be one of `Directory < Files < Location < Condition`.
- `Match` be one of `Always`, `Directory(pattern)`, `DirectoryMatch(regex)`,
  `Files(pattern)`, `FilesGlob(pattern)`, `FilesMatch(regex)`,
  `Location(prefix)`, `LocationGlob(pattern)`, `LocationMatch(regex)`.

The implementation's `RulePhase` and `ScopeRule::phase` are the code-level
counterparts of `Phase`.

## 3. Matching

For a request `(url, fs_path, fname)`:

- `Directory(pattern)` matches a directory ancestor of `fs_path`, or
  `fs_path` itself (including the file's own path when the pattern's
  component count equals the mapped path's, F61-C), using Apache shell-glob
  semantics with `*`, `?`, `[]`, `[!...]` and `[^...]`.  Wildcards do not
  cross `/`.
- `DirectoryMatch(regex)` matches the **full filesystem filename string**
  (observed Apache 2.4 behavior).  A pattern anchored at a directory name
  without allowing for the final filename does not match a file inside it.
- `Files(pattern)` and `FilesMatch(regex)` match the basename `fname`.
  `<Files>` patterns support `*`, `?`, `[]`, `[!...]`, `[^...]` (F62/F62b:
  both markers negate a class); `~ regex` is regex.
- `Location(prefix)`:
  - `/` or empty matches everything.
  - a prefix **not** ending in `/` matches exactly the prefix or a
    slash-boundary child;
  - a prefix ending in `/` matches only strings that begin with that exact
    prefix.  Thus `/admin/` does not match `/admin`.
- `LocationGlob(pattern)` is a `<Location>` argument containing shell
  wildcards (`*`, `?`, `[...]`): the stack-safe iterative fnmatch evaluator
  runs in path mode — component-bounded, anchored, and `*` never crosses `/`.
  Exhaustive small-input refinement tests compare it with the Verus fnmatch
  specification (F61-A/A2/B). A `~` first argument compiles the rest as a regex
  (`LocationMatch`); `<Location ~>` with no expression is a configuration
  error (fail closed).
- `LocationMatch(regex)` matches the canonical URL path.

## 4. Merge order

For one request define:

```
D = apply literal <Directory>/<DirectoryMatch> rules and .htaccess,
    interleaved from the root directory down to the target directory
F = apply <Files>/<FilesMatch> rules
L = apply <Location>/<LocationMatch> rules
C = apply <If>/<ElseIf>/<Else> conditionals
```

The effective scope is:

```
effective = C( L( F( D( base ) ) ) )
```

More precisely:

1. Walk directories root-to-leaf.  At each directory:
   1. apply matching literal/wildcard `<Directory>` rules, in
      least-specific-to-most-specific order;
   2. read that directory's access file if `AllowOverride` permits it and
      the file exists, and merge its **top-level** scope;
   3. defer its `<Files>` rules to phase `F` and its `<If>` rules to phase `C`.
2. Apply `<DirectoryMatch>` rules after all directory/access-file merges.
3. Apply `<Files>` rules from the configuration and from access files.
4. Apply `<Location>` rules.
5. Apply `<If>`/`<ElseIf>`/`<Else>` rules last, evaluating chains in order.

The implementation enforces this ordering with:

- `effective_scope_req_base_deferred` (base + top-level deferred rules)
- `apply_directory_rules_for_dir` (per-directory Directory rules)
- `apply_directory_match_rules`
- `apply_normal_rule_list` (Files then Location)
- `apply_deferred_req` (conditionals)

The fast path when no access file can apply uses
`effective_scope_req_deferred`, which folds Directory, Files and Location in
one pass because there is no access file to interleave.

## 5. Scope merge

`Scope::merge(child)` is a per-field operation, not a textual replacement:

- scalar overrides (`document_root`, `allow_override`, `auth_type`, ...)
  replace when present;
- `Options` is a sequence of `Set`/`Add`/`Remove`, applied left-to-right
  from the built-in default `FollowSymLinks`;
- `Require` is replaced by a child `Require` unless the child sets
  `AuthMerging And|Or`, in which case the child policy is combined with the
  inherited policy;
- every append-only container/list field appends parent then child;
- a child `Header set` replaces an inherited field of the same name instead of
  emitting a duplicate; `Header unset` removes inherited set/add fields;
  `Header always` lists are merged separately and also apply to error
  responses;
- `ErrorDocument` and `RewriteMap` are list-backed; a reverse lookup makes
  child entries win for duplicate keys;
- `RewriteRule`/`RewriteCond` lists append;
- `.htaccess` top-level directives merge in the same way.

The formal model should define `merge : Scope × Scope → Scope` as the
composition of these per-field operations and prove the ordering lemmas used
by the phases above.

## 6. Override gating

`AllowOverride` is valid only in a non-regex `<Directory>` section.  A
`None` mode means access files are not read at all.  For a read access file:

- `All` permits every implemented directive;
- each category permits its directive group;
- `AllowOverrideList` permits individually named commands even when
  `AllowOverride None` would otherwise disable access files; section commands
  use their Apache spelling (for example `"<Files"`) and are gated separately
  from their children;
- `Nonfatal=Override|Unknown|All` suppresses category/unknown errors while a
  genuine syntax error in a valid directive still fails with 500;
- `Options=...` permits an `Options` token only if the corresponding option
  is listed, except that `Options None` is always permitted once any
  `Options` override is enabled;
- the section containers `<If>`, `<IfFile>`, `<Files>`, `<FilesMatch>` and the
  conditional wrappers require some active `AllowOverride` category (Apache's
  `OR_ALL`) or an exact section entry in `AllowOverrideList`; a listed inner
  directive never admits an unlisted wrapper;
- `<RequireAll>`/`<RequireAny>`/`<RequireNone>` require `AuthConfig` or their
  own exact list entry; `<Limit>`/`<LimitExcept>` require `AuthConfig`, `Limit`
  or their own exact list entry. Their inner directives are admitted
  independently.

A disallowed directive is an error (500), not a silent skip.  This is the
fail-closed rule and must be preserved by the model.

Access-file discovery and parsing are descriptor-first. The selected
candidate is opened once with `O_CLOEXEC|O_NONBLOCK`; its identity, cache key
and bytes all come from that descriptor. A bounded read is followed by
`fstat`, and `descriptor_snapshot_admit` requires a regular file, unchanged
device/inode and version metadata, and the size limit. Cache hits perform the
same post-lookup descriptor validation. A pathname rename or in-place policy
change between selection and use therefore fails closed.

## 7. Authorization evaluation

For a scope and method:

- ordinary `Require` directives form an implicit `RequireAny` list;
- an entry whose `MethodSet` does not apply is skipped;
- if every entry is skipped, the list is neutral/granted according to the
  surrounding `parent_and` context (root is granted);
- `<RequireAll>` is conjunction and requires at least one grant;
- `<RequireAny>` is disjunction;
- `<RequireNone>` cannot grant; a granted child becomes denied, a denied
  child is neutral;
- `AuthMerging And/Or` combines a child policy with the inherited policy;
- legacy `Order`/`Allow`/`Deny` is evaluated for the request method, then
  combined with the modern result by `Satisfy All|Any`.

## 8. Security invariants to prove

These are the target theorems.  The implementation should be shaped so they
are stated over pure functions.

### I1 — ACL reachability (non-bypass)

Every response path that serves a file, directory index, CGI, proxy target or
error document either:

- has called `access::check` on the effective scope with the request's
  identity and peer, and obtained `Allowed`; or
- is an explicitly documented pre-auth response (e.g. `401` challenge).

In particular, the cache lookup path may not return a stored response unless
the same check would have allowed the request.

### I1a — Resource-bound grant

The implementation refines I1 with a concrete `ResourceKey`:

```text
grant.resource = (vhost, method, URL, resolved filesystem/script path,
                  proxy/backend target, cache host/path/query,
                  opened dev/ino, policy fingerprint, identity)
cache key     = (listener address/port, scheme, grant.resource, Vary variant)
```

Every body/tunnel sink checks the grant against the resource it is about to
serve. A grant for one URL/path/proxy target/cache entry cannot be reused for
another.  Static file and directory sinks additionally bind the grant to the
opened `dev`/`inode`; if `/proc/self/fd/N` resolves to a different path (a
symlink target), policy is re-evaluated for that target path before the file
is served. Failure to resolve the descriptor path fails the request closed,
and configuration testing/startup require readable `/proc/self/fd`. Proxy,
WebSocket and FastCGI grants are bound to the exact outbound backend/script
target. CGI scripts are bound to the opened script inode and executed via
`/proc/self/fd`; cache grants are policy-key-bound.

### I1b — Opened-object binding

For static files and directories, the grant additionally carries the opened
`(dev, inode)`.  The server resolves `/proc/self/fd/N` for the opened
descriptor; if that path differs from the URL-selected filesystem path, the
target `<Directory>`/`<Files>`/`.htaccess` scope is re-evaluated before the
response is served.  A file replaced between policy evaluation and serving is
therefore either the exact inode that was authorized or causes a 500/403.

CGI scripts are also bound to the opened `(dev, inode)`.  Bound scripts bypass
the path-based worker-pool exchange and execute through `/proc/self/fd`, so a
path replacement cannot swap the script after authorization.  Proxy,
WebSocket and FastCGI grants are additionally bound to the exact outbound
backend/script target.

### I2 — Override gating

If a directive is not permitted by the effective `AllowOverride` mode, it has
no effect on the effective scope.  If it is a security directive, the request
fails closed with 500 rather than ignoring it.

### I3 — Fast-path implication

For every request:

```
htaccess_may_apply(fs_path) == false
  ⇒ no access file in the ancestor chain changes the effective scope
```

and

```
raw path is outside the base-scope CacheEnable prefixes
  ⇒ cache_enabled(effective_scope, raw_path) == false
```

`CacheEnable` and `CacheDisable` are rejected in every rule-producing section,
so only the inherited server/vhost base scope can introduce those prefixes.
This compiler invariant must remain an over-approximation, never an
under-approximation. The `/cache/` trailing-slash bug was a violation of this
shape.

### I4 — Conditional-last

For any scope, a conditional rule cannot be overridden by a later
Directory/Files/Location rule; condition evaluation happens after all normal
merges, including access files.

### I5 — Method limits

`MethodSet::intersect` is exact:

```
intersect(a,b).matches(m) ⇔ a.matches(m) ∧ b.matches(m)
```

and a method-limited requirement cannot apply to a method outside its set.

### I6 — Path-prefix discipline

`Location("/x/")` does not match `/x`; `Directory("/srv/foo")` does not match
`/srv/foobar`; wildcard components do not cross `/`.

### I7 — Fail-closed unsupported constructs

Unsupported access-control directives, malformed `.htaccess` files, invalid
contexts, and unknown `Require` providers deny or error; they never widen
access.

### I8 — Rewrite/proxy authorization

A proxy target reached through a rewrite `[P]` is still subject to the
matching `<Proxy>` authorization section.  `<Proxy>` matching considers both
the configured logical identity (`balancer://cluster`, or the rule URL) and
the concrete selected member, and a balancer failover re-runs that decision
before sending the request to a different member.  Prefix and regex proxy
routes form one configuration-ordered table; the first matching route chooses
HTTP proxy versus FastCGI, so a later `ProxyPassMatch` cannot reorder an
earlier `ProxyPass`.  The complete route/balancer identity rules are in I32.

### I9 — Closed-world configuration acceptance

```text
Accepted(cfg) ==> forall d in directives(cfg): handled(d) or proved_inert(d)
Unhandled(d) ==> reject(cfg)
```

A warning may only mean “proved semantically inert,” never “effectful but
unsupported.”  In particular, `AliasMatch`, `ScriptAliasMatch`,
`RedirectMatch`, `RedirectPermanent`, `RedirectTemp` and `RemoveHandler` are
handled; the remaining mapping/handler directives (`Action`, etc.) fail
closed in every mode; normal mode no longer accepts an unhandled name as a
warning-only no-op.

### I10 — One resolved target

```text
resolve(req) -> Resolved(vhost, listener, url, root, rel, fs_path,
                          script?, path_info?, backend?, cache_target?)
policy and every sink use the same Resolved
sink_grant.target == sink_target == resolve(req).target
```

The dispatcher, cache base-scope gate and authorization walk share `map_path()`.
`AliasMatch`/`ScriptAliasMatch` are part of that mapping, not a separate
lookup.  `map_path()` returns an explicit mapping failure when a regex alias
expands outside its configured base; there is no parent-root fallback.
`ResourceKey` carries the vhost, URL, filesystem target, proxy target, backend
identity, inode, authenticated identity and policy fingerprint; `bind_file`
and `bind_backend` produce the bound grant required by every sink.
`AccessGrant` also carries the executable `TransformCapability` state. Every
protected sink calls `require_sink`, which admits the operation only when the
key is exact, the current target was authorized, and the sink-specific inode,
backend, proxy-representation or cache-policy capability is present. A proxy
endpoint binding alone is insufficient: the representation capability is
minted only after both the authorized front path and serialized upstream path
pass the verified ambiguity gate.

### I11 — Reauthorize every target-changing transform

```text
Resolve -> Authorize -> [Transform -> Reauthorize]* -> Sink
Invariant: sink_grant.target == current_target
Invariant: Transform clears authorization; Sink implies reauthorization
```

PATH_INFO splitting, Alias/ScriptAlias mapping, symlink resolution, internal
rewrites, DirectoryIndex, ErrorDocument and FastCGI script resolution are
transforms.  In particular:

- a CGI handler is selected from the **actual script** basename, not from a
  trailing `PATH_INFO` component;
- after `find_script`, policy is re-evaluated for the script path and the
  grant is bound to its opened inode;
- a FastCGI `ProxyPassMatch` target splits `PATH_INFO` to an existing script
  file and re-authorizes that script; the script filename and the ancestor
  walk are bounded by the configured FastCGI prefix (or the request's
  document/alias root), and symlinks that leave that base are rejected;
- an internal rewrite requires both the original request URL scope
  (`<Location>`/`<LocationMatch>`) and the final target scope to allow; the
  original URL's `Options`/`AllowOverride`/header policy is conjoined with the
  rewritten target policy, and an absolute rewrite target is only admitted
  when its canonical file remains below the current document/alias root, so a
  rewrite cannot name a new root or launder a protected upload into an
  executable directory (I61). The admitted target retains that mapping root
  and its relative path through dispatch; it is never re-rooted at the
  selected file's parent;
- an `.htaccess` walk covers every applicable ancestor of an alias or document
  root target, so parent access files outside `DocumentRoot` cannot be skipped
  (I47); the URL-selected alias root is used only for URL-base derivation
  (I48);
- `SymLinksIfOwnerMatch` compares each symlink owner with the resolved target
  owner unless unconditional `FollowSymLinks` is also enabled. The owner-only
  walk pins every directory, ordinary component and symlink descriptor,
  compares device/inode when an ordinary component is reopened with usable
  flags, reads a link through its descriptor, and resolves its target from the
  pinned parent; a rename cannot make the ownership check and returned file
  refer to different objects. `DirectoryIndex`, autoindex metadata and cache
  admission consume this same policy instead of treating owner-match as
  unconditional following. Relative targets cannot climb above the mapping
  root, symlink depth is capped at 40, and at most 64 directory descriptors are
  retained.

The complete transform inventory and the original/current target gate are
specified in I30.  The CGI/FastCGI execution boundary is closed in I31 and the
proxy route/balancer identity boundary in I32.

The transform-to-sink state is executable rather than ledger-only:
`transform_retarget` clears target authorization and every binding,
`transform_authorize` binds the current target, and bind transitions add inode
or backend identity. `transform_retarget_requires_reauthorization` proves that
no sink admits the post-retarget/pre-authorization state;
`transform_sink_implies_reauthorized` and the sink-specific lemmas prove the
required capabilities. Exact `ResourceKey` equality supplies the runtime target
identity refinement.

### I12 — Cache non-interference

```text
hit(entry, req) ==>
    entry.resource == resolve(req).resource
    && entry.policy == policy(resolve(req))
    && identity compatible
    && entry.vary matches req
```

The cache key binds scheme, listener local address/port, vhost, `Host`, raw
canonical URL (including trailing slash), query, resolved filesystem/alias
target and policy fingerprint.  The fingerprint includes the complete request
header set, because `Require expr`, `SetEnvIf` and rewrite conditions can read
any header, and the complete material of every `Scope` policy slice (I26);
hashing only a selected policy subset would let two tenants share an entry when
their policy branches differ.  For CGI `PATH_INFO` the resolved
target is the script prefix, not the URL-mapped nonexistent path.  Entries
also carry the configuration generation (I20); a reload makes every older
entry inadmissible.  A hit re-runs authorization against the mapped target.
Multiple `Vary` field lines are concatenated before variant selection; disk
entries must satisfy the same `vary_match` predicate as memory entries.
Unsafe methods invalidate persisted entries as well as memory entries.
Credentialed and cookie-bearing requests are not stored in the shared cache.

The per-finding closure matrix is in `docs/adversarial-closure.md`.

### I13 — Descriptor capability isolation

```text
fds(daemon at entry) = {0,1,2}
fds(cgi_worker) = {0,1,2,control_fd}
fds(cgi_child) subseteq {0,1,2,script_fd}
fds(rewrite_helper) subseteq {0,1,2,sealed_program_fd}
fds(tls_broker) = {protocol_fd}
```

The main entrypoint atomically closes every launcher-supplied descriptor above
stderr before it opens configuration, listeners, or logs. Child setup marks
the complete descriptor range close-on-exec, then restores only the one
capability named above. The CGI worker control socket is marked close-on-exec
after the worker's own exec and before any script is spawned. The TLS broker
reports readiness only after retaining fd 3 alone and installing all process
restrictions. Vapache requires Linux `close_range`; it fails closed instead of
guessing an upper descriptor number. Fork/exec tests deliberately inject
non-CLOEXEC sentinels into each boundary and inspect `/proc/<pid>/fd` or the
executed child.

### I14 — Ordered competing mappings

Every request-to-resource table has one explicit order and one deterministic
winner:

```text
Alias | ScriptAlias | AliasMatch | ScriptAliasMatch   : first match wins
Redirect | RedirectMatch | RedirectPermanent/Temp     : first match wins
ProxyPass | ProxyPassMatch                            : first match wins
AddHandler | RemoveHandler                            : last matching op wins
SetHandler                                            : precedence force
```

A later, more-specific mapping does not override an earlier overlapping one;
Apache also treats such overlapping aliases as unreachable.  For handler
operations, `RemoveHandler` must be able to cancel an inherited `AddHandler`
regardless of section depth, while `SetHandler` is a precedence force that
overrides every handler assignment in its scope regardless of order (I62,
F64).  `ProxyPass`/`ProxyPassMatch` exclusion syntax
(`!`) is not implemented and is rejected at startup rather than silently
ignored.  This closes the “multiple competing request-to-resource mappings”
class from the findings.

### I15 — Internal subrequests

```text
DirectoryIndex and local ErrorDocument dispatch go through the normal dispatcher
DirectoryIndex retains method, body, query, headers, peer and authenticated identity
ErrorDocument becomes a bodyless GET using only its configured target query
both retain the original wire method/target/version for THE_REQUEST and reselect the canonical URL
subrequest target policy is evaluated exactly like a client request
ErrorDocument recursion depth follows the request and cannot replace a failed target
```

The original directory access check happens before a `DirectoryIndex`
subrequest, and the subrequest re-checks its target.  An `ErrorDocument` may
intentionally run after a denied or missing original resource, but it still
runs through target authorization, handler selection and `.htaccess` review;
it cannot recursively invoke itself.  Its recovery projection removes entity,
conditional-range and hop-by-hop/upgrade metadata (including fields nominated
by `Connection`) before a local or proxied handler runs.  Cache exclusion is a
property of the returned response rather than executor-thread state.
Until Apache-style arbitrary URI index candidates are implemented,
`DirectoryIndex` values must be literal, unescaped single-component names;
this keeps the file probed during selection identical to the URL dispatched.

### I16 — Trusted input boundary

Security-relevant request context has exactly one source:

```text
scheme / HTTPS       <- listener TLS state, never a forwarding header
peer address         <- socket peer, rewritten only by configured trusted RemoteIP
canonical name       <- ServerName when UseCanonicalName On/DNS
%{SERVER_NAME}       <- dispatcher-selected name, not a raw Host lookup
vhost                <- listener port + Host/SNI selection
authorization identity <- verified Basic/client-certificate authenticator
```

`X-Forwarded-Proto`, `Forwarded`, and similar headers never satisfy `HTTPS`,
never change `REQUEST_SCHEME`, and are not authentication evidence.
Forwarded addresses are honored only for peers inside `RemoteIPInternalProxy`.
`UseCanonicalName DNS` currently maps to the configured `ServerName` rather
than performing reverse DNS; this is a conservative approximation that cannot
be steered by the client Host header.

### I17 — Bounded resource consumption

Every untrusted stream has an explicit limit and a deadline:

```text
request body + chunk framing/trailers: decoded-byte, chunk-count, framing-byte, trailer and deadline bounds
CGI/FastCGI body                : spool above threshold; do not materialize LimitRequestBody
CGI output/stderr               : capped
proxy response head/body/chunk/trailer: decoded-byte, chunk-count, framing-byte and trailer caps
proxy chunk arithmetic          : checked_add and MAX_PROXY_BODY
proxy DNS / TLS CA              : bounded queue/deadline; first address set and CA parsed state are generation-bound
pre-request sockets              : async bounded pool; header/TLS/H2-preface deadline and per-transport cap
client/upstream transport buffers: 128 KiB requested send/receive queues; 512 KiB accounting lease under a shared 256 MiB process parent
TLS handshakes                   : 64 concurrent, 4/source, 128/second and 64/source/second
HTTP/1 blocking workers          : reusable pool; MaxRequestWorkers/effective-client caps; configuration ceiling 512
filesystem/cache lookup phase    : 64 process slots, 8/source; cache stripe/cold-scan contention bypasses instead of queues
slow request bodies              : every keep-alive request enters a one-quarter-worker reserve with a one-quarter per-effective-client share
ready listeners                  : rotating order plus 64-accept batch cap
HTTP/1 response writes          : progress-renewed Timeout stall deadline; non-blocking send/poll; plain/TLS 64 KiB TCP unsent low-water wakeup; effective-client worker quota (no body-read permit while waiting)
HTTP/2 streams/control frames   : preface/initial-head deadline, client-before-process stream quotas, separate 128-process/32-source slow-input and slow-output reserves, anchored output rate/lifetime, and every control frame charged; useful WINDOW_UPDATE is 4096 burst/2048 per second
WebSocket tunnels               : 64 process slots, 8 per effective client, plus idle/write deadline
logs / RewriteMap prg / cache   : 128 KiB lines and non-queuing writers; 8-request/8-concurrent/64-per-second helpers plus 2-concurrent/16-per-second per-client shares; iterative depth/record-bounded cache walks; one 4 GiB/16,384-entry disk parent shared with spools and OCSP, plus a 75%-of-observed-free child (capped at the same maxima) for each target `st_dev`
handlers/descriptors            : only stdio + script fd cross exec
```

Exceeding a bound is an error response or connection close, never an
unbounded allocation or an indefinitely pinned worker.

Plain HTTP/1 socket writes use non-blocking `send`/`sendfile` plus `poll`.
Plain and TLS output share an irreversible general-to-slow ownership transfer,
an average-rate checkpoint anchored at the original response start, and an
absolute sixteen-interval lifetime; partial progress cannot renew either
boundary. Kernel `SO_SNDTIMEO` is defense in depth, not the resource boundary.
On Linux, plain and TLS HTTP/1 transports also set `TCP_NOTSENT_LOWAT` to cap
the queued-unsent region at 64 KiB. Accepted sockets request bounded send and
receive queues, while their conservative kernel/TLS/protocol memory charge is
retained until connection teardown.

Shell-pattern evaluation is iterative and uses `O(subject)` memory. Access-file
logical lines and all configuration-originated glob patterns are capped at
8190 bytes; request-controlled expression globbing additionally consumes the
verified pattern-times-subject work admission. Rewrite outputs are capped at
64 KiB, expression values at 1 MiB with a shared 4 MiB evaluation budget, and
main/access-file section nesting at 64 before recursive compilation begins.
Request-time rule traversal and the executable authority, rewrite-chain,
authorization-combine, string-compare and condition-chain kernels use explicit
iterative worklists, so accepted nesting or input length does not consume one
native stack frame per element.

Resident-byte and compression reservations are made before extending request,
proxy, autoindex or encoded-response buffers. HTTP/1 retains the reservation
through dispatch in the request headers; HTTP/2 does the same through stream
completion. An ambiguous proxy failure, including a configured failed-status
response, can select another member only for an idempotent method. The
`proxy_retry_admit` Verus gate proves unsafe methods cannot cross that seam
after a send may have begun.

### I18 — Response-header policy

`Header set`, `Header add`, `Header unset`, `Header always ...` and
`Header onsuccess ...` are evaluated for every response category (static,
directory, redirect, CGI/FastCGI, proxy and error).  `unset` runs after
set/add; a child `set` replaces an inherited field with the same name; `always`
fields also apply to error responses while plain/`onsuccess` fields do not.
Header names and values still pass the verified token/sanitization checks.
Unsupported `Header` actions (for example `Header edit`) are rejected at
startup rather than warned-and-ignored.

### I19 — Terminal sink gate and monotone authorization

```text
State = (original_request, current_url, current_target,
         original_grant, target_grant, cache_epoch)

forall executions:
    Terminal(state, outcome) && positive(outcome)
    ==> Allowed(original_url)
        && Allowed(current_target)
        && target_grant.target == current_target
```

A transform adds an obligation; it never replaces one.  Static, directory,
CGI, FastCGI, proxy and positive redirect outcomes all consume the gate.
In particular a rewrite chain such as `/admin -> /front -> [P] backend`
still authorizes `/admin` before the proxy sink, and a positive `[R]` after a
rewrite does the same.  The gate uses the original request context and applies
the accumulated rewrite effects, so a query-only rewrite or `[E=...]` change
cannot evade the original URL policy.  The implementation shares one
`authorize_original_request()` helper between the post-loop static path and
the early-return proxy/redirect arms; adding a new terminal outcome must route
through the same gate.  The closed transform inventory is I30.

### I20 — Cache generation and resolved-target identity

```text
CacheEntry = { epoch, resolved_target, policy_fingerprint, vary, identity }
hit(entry, req, cfg) ==>
    entry.epoch == cfg.epoch
    && entry.resolved_target == resolve(req).target
    && entry.policy_fingerprint == policy(resolve(req))
    && VaryMatches(entry, req)

Reload(cfg, cache) -> cfg', cache'
ensures cfg'.epoch = cfg.epoch + 1
        forall e in cache: e.epoch < cfg'.epoch
```

`cache_lookup_admit` takes a `generation_match` conjunct and disk metadata
stores the epoch. Each immutable `Config` generation owns a clone-shared epoch
cell; a request captures that value while compiling its cache policy, and both
lookup and store require equality with the same cell. Final publication takes
the read side of a cache-generation barrier. Reload takes the write side,
retires the old cell, advances the candidate and clears both roots. An old
store therefore either precedes cleanup or is rejected; it can neither adopt
the candidate epoch nor recreate files on an abandoned cache root. Reload
closes the old request-admission gate before this cache transition, preventing
new old-policy stores during cleanup. A CGI
`PATH_INFO` request is resolved to the actual
script target (and that script's policy) for both the fingerprint and the key,
so a later `<Files "script.cgi">` deny cannot leave a usable path-info entry.
Authorization still runs on every hit; the cache is a derived view, never an
authorization shortcut.  A directory URL additionally resolves its
`DirectoryIndex` target before the cache decision; the key, target and policy
fingerprint then describe that selected file/script rather than the directory
(I49).

### Reload trust continuity

```text
Reload(old, candidate) is admitted only if
    candidate.admin_input_trust == old.admin_input_trust
    && every discovered administrative parent is not service-writable
    && !(candidate.has_cgi && !old.has_cgi)
    && candidate.{User, Group, PidFile, ServerRoot,
                  ListenBacklog, Listen}
       == old.{User, Group, PidFile, ServerRoot,
               ListenBacklog, Listen}
```

A privileged startup captures root-owned input trust before dropping uid and
retains it for every later parse. Includes (including empty optional globs or
directories), TLS files, `TypesConfig`, and file-backed rewrite maps are all
part of the generation's administrative-input manifest. A SIGHUP therefore
cannot reinterpret service-owned input as trusted merely because the request
process is now unprivileged. Directives whose effects live in process identity,
the pid guard, path base or kernel listeners require a full restart instead of
creating a configuration/runtime split.

Reload itself uses a prepare/commit boundary. Listener-stop and generation
retirement are separate states: a rejected candidate resumes the same live
generation and does not invalidate its established connections. The candidate logger, listener
clones, complete TLS configuration, initial OCSP state and pending refresh
workers are prepared before any live generation changes. A preparation error
rejects the whole candidate; it cannot combine new policy with old logs or
retire the old generation. Only after every fallible step succeeds are
OCSP/health workers activated, the candidate cache epoch committed and the
old generation retired before listener admission resumes. HTTP/1 closes after
an admitted response, HTTP/2 sends GOAWAY and drains admitted streams, and
WebSocket tunnels close; none can begin new old-policy work. Access-file IR and
the asynchronous protocols share an event-driven retirement broadcast rather
than per-connection polling. H1/H2 policy admission takes a generation-local
read gate, while commit takes the write side before broadcasting retirement;
there is no flag-check/commit race. Access-file IR and proxy active/passive
health state are keyed by immutable configuration ID and
are removed only when the last request-owned `Config` clone drops.

TLS is the one root-only input that must support same-path rotation during a
graceful reload. Before threads and privilege drop, the parent forks a broker
with an exact numeric allowlist of TLS paths compiled from the startup
configuration. The helper accepts no pathname from the request process, closes
unrelated inherited descriptors and standard streams, disables dumps and new
privileges, applies tight rlimits, and installs a seccomp allowlist limited to
bounded file reads, memory management and its existing socket. The parent
requires a bounded readiness handshake after all hardening; failure kills and
reaps the broker before startup continues. It rechecks root ownership, type,
size and stable metadata on every read, and exits when its parent does. A reload may replace
the contents at an already-authorized path; adding a different TLS pathname
requires a full restart.

### I21 — Alias root identity

```text
alias_target(template, captures, server_root) -> (root, rel)
root is non-empty and absolute
mapping_root = root of the alias selected by the request URL
```

Prefix aliases and regex aliases (absolute, relative, fixed or capture-only)
must produce the same mapping root for `map_path()`, `ResourceKey`,
URL-base/`RewriteBase` derivation and the cache.  A relative substitute such
as `private/$1` is anchored at `ServerRoot` when the alias is compiled; it is
never represented as an empty root that the walk silently skips.  Per I47 the
mapping root does not bound the authorization walk.

### I22 — Contextual output encoding

```text
SafeRelativeHref = "./" + percent_encode(name)
forall name: href(autoindex, name).starts_with("./")
forall name: !is_absolute_url(href(autoindex, name))
```

HTML text escaping is not URL-context encoding.  Autoindex links, `Location`
headers, cookie values and log fields each use the encoder for their sink.
The `./` prefix removes `javascript:`, `data:`, `vbscript:` and
protocol-relative targets by construction while HTML escaping remains a
separate text-context operation.

### I23 — Provider operands and directive effects

```text
parse("Require not env A B") -> Env { negate: true, names: [A, B] }
eval(Require env A B)         -> present_ci(A) || present_ci(B)
parse("Require not expr E")  -> Expr { negate: true, expr: E }

Accepted(.htaccess) ==> every directive is modeled or fails closed
```

Negation shifts the operand with the provider; it does not read the literal
`env`/`expr` token. Every `Require env` operand participates in the one
provider result; `NAME=VALUE` comparisons are not implemented and fail
configuration loading. Names use APR table's case-insensitive key semantics.
Environment and autoindex directives are not
"accepted but inert": `SetEnv`, `SetEnvIf`, `UnsetEnv`, `PassEnv` and
`IndexIgnore` populate the same `EnvironmentPolicy`/`ContentPolicy` fields in
the main configuration and `.htaccess` parsers. Only the authorization-phase
environment in I71 feeds `Require env`/`Require expr`; late mod_env directives
remain effectful for CGI/FastCGI without becoming ACL inputs. The exhaustive
disposition registry and effect matrix for every recognized `.htaccess`
directive are specified in I29.

### I24 — Canonical directory URL and autoindex policy

```text
authorize(/dir, DirectorySlash Off) uses policy(/dir/)
IndexIgnore patterns are part of the autoindex scope
```

`/dir` and `/dir/` must share one authorization context for directory
actions.  With `DirectorySlash Off`, the dispatcher reauthorizes the
canonical trailing-slash URL before considering a directory index or
autoindex, so a trailing-slash `<Location>` cannot be bypassed.  `IndexIgnore`
patterns are inherited and filter emitted entries in both main-config and
`.htaccess` form.

### I25 — Configured-base containment

```text
configured_base(alias|rewrite|fastcgi) = the stable root named by the mapping
resolved_target(m) ∈ configured_base(m)
failure_to_prove_containment -> mapping failure (404/403), never a new root
```

An alias capture, rewrite substitution or FastCGI suffix may choose a path
inside the configured base; it may not choose the base.  `map_path()` returns
`None` for a regex alias whose expansion leaves its alias root, an internal
rewrite admits a filesystem target only below the current document/alias root,
and a FastCGI script (including its `PATH_INFO` ancestor walk) is canonicalized
inside the configured prefix or document root.  All three mapping paths consume
the verified component-aware `path_under_base` kernel, so a sibling such as
`/srv/www2` is not treated as a child of `/srv/www`.  In particular,
`UnsafePrefixStat` and compatibility flags never widen the authorization base.

### I26 — Cache authorization input closure

```text
cache_policy_material(scope) =
    canonical(scope.options, scope.override_policy, scope.authorization,
              scope.header_policy, scope.content_policy, scope.mapping_policy,
              scope.error_policy, scope.environment_policy,
              scope.rewrite_policy, scope.compression_policy,
              scope.proxy_policy)

cache_fingerprint(req) = hash(cache_policy_material(scope), peer, method,
                              resolve(req).target, all request headers)
cache_key(req)          = (listener, vhost, scheme, host, URL, query,
                           resolve(req).target, cache_fingerprint(req))
```

Any request input that can select an authorization branch or representation is
part of the key.  Header-driven providers are covered by hashing every request
header, not only the headers named in `Vary`; credentialed and cookie-bearing
requests are additionally excluded from storage.  A cached representation may
never cross a policy branch merely because the branch was selected by a header.

The policy side is closed over **every** `Scope` policy slice, not a hand-picked
subset.  `cache_policy_material` destructures `Scope`, so adding a new policy
slice is a compile-time prompt to include it.  Each policy object is hashed
through its complete `Debug` representation; rewrite maps are canonicalized by
sorting keys because their backing `HashMap` iteration order is unstable.  The
unit matrix mutates every field of every policy object and every request/key
dimension and asserts that the fingerprint or key changes.  A future policy
field is therefore either automatically bound through its policy object or
fails the matrix when someone replaces that object with a manual list.

The current request authorizers are header based (`Authorization`), and
credentialed requests are excluded from cache lookup and storage. TLS client
certificates can gate the whole connection, but are not currently exposed as a
request principal or CGI identity. If that changes, the immutable connection
certificate identity must be added to the fingerprint before it can authorize
a cacheable request.

### I27 — Authenticated identity reaches every script sink

```text
grant.identity = Some(user) -> CGI/FastCGI env contains REMOTE_USER=user
authentication scheme          -> AUTH_TYPE=Basic (for Basic authentication)
```

The first successful authenticator records a monotonic identity on the logical
request. Internal request clones share that binding, unrelated requests do
not, and a later provider cannot replace it with another user. The binding
survives deferred execution, target reauthorization, proxy failover and grant
binding into `CgiContext`; access logging receives a non-destructive snapshot.
Both local CGI and FastCGI use the same `build_env()`, so an application cannot
see an empty user for an authenticated request. Configured/rewrite environment
entries still cannot override `REMOTE_USER`/`AUTH_TYPE`.

### I28 — Proxy serialization boundary

```text
serialized_upstream_head = request_line + headers
forall inserted field value v: no_ctl(v) && header_value_safe(v)
backend authority ∈ DNS/IPv4/IPv6 literal alphabet
```

Backend hosts are validated when the route is parsed, `X-Forwarded-Host` is
validated before insertion, and the complete upstream request head is checked
immediately before `write_all` by the verified `proxy_request_line_admit`
(method token, visible target, exact `HTTP/1.1`) and `proxy_header_admit`
(token name, CTL-free value) kernels.
Configuration- or rewrite-derived text therefore cannot split the request line
or inject an upstream header. Reverse-proxy and WebSocket targets containing a
semicolon path parameter are rejected before connection: generic front-end
policy cannot know whether an upstream strips matrix parameters before routing,
so forwarding that representation would give the two hops different resource
identities. The response boundary is symmetric: the status line and every
field consume `proxy_response_status_line_parse` and
`proxy_response_header_admit` before framing headers are interpreted, while
chunk sizes, extensions and trailers use the same verified grammar as inbound
HTTP/1 bodies.

### I29 — `.htaccess` directive disposition closure

```text
recognized(d) <-> exists spec(d) in DIRECTIVE_SPECS
disposition(d) in {Effectful, Inert, Reject}

Effectful(d) ==> parse(d) changes Scope or adds a rule
Inert(d)     ==> parse(d) leaves Scope unchanged
              && d cannot mutate the request, authorization, mapping,
                 handler, Options or environment state
Reject(d)    ==> parse(d) returns an error
forall recognized d: category(d) is defined
```

`DIRECTIVE_SPECS` is the authoritative registry: `directive_category()` derives
the `AllowOverride` category from it, and `apply_directive()` refuses any name
that is absent.  The exhaustive unit matrix asserts that every registry entry
has exactly one effect case, that the case matches observed behavior under
`AllowOverride All`, and that the directive is denied under `AllowOverride
None`.  Adding a directive therefore requires an explicit disposition and a
category; an accidental “recognized but silently ignored” directive fails the
test.

The reviewed inert set is `AddCharset`, `AddLanguage`, `AddEncoding`,
`RemoveCharset`, `RemoveEncoding`, `AddDescription`, `IndexOptions`,
`ReadmeName` and `HeaderName`, plus the validated no-op
`AuthBasicProvider file`.  These do not select an access or mapping branch.
`RequestHeader` and `AllowMethods` are `Reject`; they are never inert.

### I30 — Transform inventory and reauthorization gate

```text
Transform = (original_request, before_url, before_target,
             after_url, after_target, effects)

forall terminal positive outcomes after a transform:
    Allowed(original_request, original_url, original_target)
    && Allowed(current_request, current_url, current_target)
    && grant.target == current_target
    && grant is bound to the current inode/backend/cache key
    && transform_sink_admit(grant.capability, sink)
```

A transform adds an authorization obligation; it never replaces one.  The
final target policy is likewise a meet with the URL policy, never a
replacement (I61).  The inventory is closed over every request-to-resource
conversion:

| Transform | Target identity | Reauthorization / binding |
|---|---|---|
| prefix alias, `ScriptAlias` | `map_path` root + rel | target scope, alias-root access walk, file grant |
| `AliasMatch`, `ScriptAliasMatch` | capture-expanded target inside stable alias base | mapping failure outside base; target scope, file grant |
| internal URL rewrite | canonical rewritten URL | target scope + original-URL gate with rewrite effects; original and target policy meet (I61) |
| internal filesystem rewrite | opened file plus relative path below the retained mapping root | descriptor-relative containment, target scope + rewritten URL scope meet, original-URL gate, file inode grant |
| CGI `PATH_INFO` | `find_script_checked` actual script | script scope, inode-bound CGI grant |
| FastCGI `ProxyPassMatch`/`PATH_INFO` | opened script inode + `PATH_INFO` | actual descriptor-path scope, inode- and backend-bound FastCGI grant |
| `SetHandler proxy:fcgi` | opened contained handler script | actual descriptor-path scope, inode- and backend-bound FastCGI grant |
| symlink resolution | opened descriptor path | target scope, file inode grant |
| `DirectoryIndex` | index subrequest URL; original method/body/query | normal dispatcher authorization for the index target; selected target decides POST support |
| local `ErrorDocument` | configured error path/query; bodyless GET; immutable original wire method/target/version | normal dispatcher authorization; request-owned recursion bound; response-owned cache exclusion |
| `DirectorySlash Off` | canonical trailing-slash URL | reauthorize before index/autoindex |
| proxy route / balancer failover | concrete member URL + binding | `<Proxy>` reauthorization, backend-bound proxy grant |
| cache `PATH_INFO` | actual CGI script target | cache policy grant bound to script target |
| WebSocket rewrite/proxy | rewritten proxy target | rewrite gate, proxy authorization, backend binding |

The original-URL gate deliberately uses the **original request context** and
applies the accumulated mapping effects before evaluating the original scope.
A rewrite that changes only the query string or only `[E=...]` environment
state therefore still rechecks the original URL policy. Environment effects
are admitted according to I71: server-scope `[E]` is already visible, while
per-directory `[E]` remains fixups-late and cannot influence either ACL gate.
The final target scope uses the current rewritten request context.

### I31 — CGI/FastCGI execution boundary

```text
script = resolve_script(req)
contained(script, configured_base)
authorized(script, target_scope) && identity(grant) == identity(req)
CGI:     grant bound to opened script inode
FastCGI: grant bound to opened script inode and
         (transport, script, SCRIPT_NAME, PATH_INFO)
env = calculated_env(req, script) ∪ admitted(config/rewrite env)
calculated_env ∩ admitted_env = ∅
fds(child) subseteq {0,1,2,script_fd}
FastCGI params contain exactly one SCRIPT_FILENAME, SCRIPT_NAME,
PATH_INFO and PATH_TRANSLATED for the selected target
```

The handler is selected from the **actual script basename**, never from a
trailing `PATH_INFO` component.  Script construction, `PATH_INFO` splitting
and the ancestor walk are bounded by the configured FastCGI prefix or the
document/alias root; symlink escapes are rejected.  The target script is
opened first and reauthorized through its descriptor path. The grant is bound
to its inode (CGI) or to both inode and transport/script identity (FastCGI).
Immediately before FastCGI parameters are emitted, the pathname is reopened
and compared with the authorized `(dev, inode)`. `REMOTE_USER`/`AUTH_TYPE` come from the
authenticated grant, while configured or rewrite-set environment entries
cannot override calculated names.  Request bodies stay on their spool file
above the threshold; stdout/stderr, descriptors and deadlines are bounded.
The isolated pool is created before request/background threads and signals
readiness only after its irreversible uid/gid and supplementary-group drop,
parent-death binding, descriptor limit, core limit and no-new-privileges state.
uid/gid 0 and incomplete group setup fail startup. Production never falls back
to direct daemon-side spawning: exhausted or unavailable pool capacity returns
`503`, and enabling CGI on reload requires a full restart.

The FastCGI protocol has no descriptor-passing primitive: PHP-FPM opens
`SCRIPT_FILENAME` after this final comparison. Vapache therefore requires the
pathname rule to be machine-enforced with repeatable global entries:

```text
VapacheFastCGIStablePath On <unix-endpoint> <backend-uid> <endpoint-owner-uid> <trusted-owner-uid>...
```

`endpoint` is an exact `unix:/path` transport identity. Every backend must
have an exact entry; an unregistered backend is rejected. Unix socket type,
owner and inode are validated before and after connect separately from the
PHP worker UID. Linux `SO_PEERCRED` also binds the connected listener to the
configured backend uid, configured endpoint-owner uid (for a rootless pool
manager), or the operating-system trust root (uid 0); the socket file's uid is
never substituted for that independent process credential. TCP
entries are rejected because a loopback address cannot authenticate the
process that owns it. The lexical and canonical script paths are walked
immediately before parameters are sent.
Every component owner must be listed, group/other write bits and POSIX ACLs
are rejected, and a non-symlink component cannot be owned by the backend (an
owner could otherwise use `chmod` to regain write permission). Root backends
and relative paths fail closed.

`VapacheMaxSpoolBytes`, `VapacheMaxSpoolFiles`,
`VapacheMaxDynamicRequests` and `VapacheMaxFastCGIOutput` provide process-wide
aggregate spool/concurrency budgets plus a per-request FastCGI output bound.
RAII reservations cover request bodies, FastCGI responses and the worker-side
CGI body copy and are shared across graceful reloads.

An absent or `Off` policy is rejected unless the process explicitly enables
`VapacheCapability UnstableFastCgiPaths On`. That escape hatch accepts the
external pathname race and restores the deployment obligation: every FastCGI
script and ancestor directory must remain non-writable by the backend and by
every less-trusted process for the whole request lifetime. Use a read-only
bind mount or immutable release tree, and keep uploads outside every FastCGI
handler mapping. This capability is outside the default verified security
boundary. Local CGI has no equivalent residual because it executes from the
retained descriptor.

### I32 — Proxy route and balancer identity

```text
Route = (order, matcher, logical_identity, concrete_member)
selected = matching route with minimum order
prefix and regex routes share one order space

balancer request has:
    logical_identity  = balancer://name/suffix or rule URL
    concrete_identity = selected member URL + binding_key

authorize(logical_identity) && authorize(concrete_identity)
failover(member') -> (scope', grant', resource') atomically
sink_grant.target == selected_member.binding_key()
```

Prefix and regex `ProxyPass`/`ProxyPassMatch` routes form one
configuration-ordered table; a later overlapping route cannot beat an earlier
one.  `<Proxy>`/`<ProxyMatch>` policy is applied to both the logical balancer
identity and the concrete selected member.  Sticky sessions, health checks and
round-robin only choose a member; they never bypass authorization.  On
failover the dispatcher re-runs proxy authorization, rebuilds the resource key
for the new member and binds a new grant to that member before sending.  The
selected grant/resource pair is replaced together, so a grant for member A
cannot authorize a request sent to member B.

### I33 — Framing and resource-bounds closure

```text
forall untrusted stream s:
    bytes(s) <= bound(s)
    && deadline(s) is finite
    && overflow is checked before resize/allocation
```

The bound is part of the protocol adapter, not an incidental `Vec` limit:

| Stream | Explicit bound |
|---|---|
| HTTP/1 request line/head | `LimitRequestLine`, `LimitRequestFields`, `LimitRequestFieldSize`, total head cap |
| HTTP/1 request body | `LimitRequestBody`, hard absolute body deadline plus configured header/body `MinRate` enforcement that cannot extend it, at most 65,536 chunks and 1 MiB of chunk framing independent of decoded size; fixed bodies no larger than 1 MiB stay resident, known-larger dynamic uploads stream through a resource-accounted four-chunk channel, and chunked bodies provide a 64 KiB actual-byte prefix before an `O_EXCL`, mode-0600 spool file is acquired; the shared quota reserves only bytes actually received or the fixed channel capacity |
| HTTP/1 chunked trailers | trailer count and byte budget within the same hard body deadline |
| Proxy routing/response head | HTTP and FastCGI prefix/regex route scans consume the fail-sticky request-work budget; response line, header-count and total-head caps |
| Proxy response body | fixed-length/chunked/EOF body capped at 64 MiB; chunked responses additionally allow at most 65,536 chunks and 1 MiB of framing; large fixed bodies stream, chunked/EOF bodies spill to the shared unlinked-file tier above 256 KiB, and oversize responses do not trigger balancer failover amplification |
| Proxy trailers | trailer count and byte budget |
| CGI worker protocol | path/env/body field caps, env-count cap, body spool above threshold |
| CGI stdout/stderr | 8 MiB stdout and 64 KiB stderr caps, process-wide resident-byte accounting, watchdog deadline, process-group kill |
| FastCGI path/records | each `PATH_INFO` filesystem prefix consumes the fail-sticky request-work budget; synthesized paths pass the shared 256-component/512-KiB cumulative-prefix gate; fixed record/header sizes, stdout spool cap and stderr cap |
| FastCGI response head | bounded prefix/header scan before body streaming |
| Aggregate dynamic I/O | RAII byte/file reservations across request, response, CGI-worker and FastCGI/proxy spools; each client may retain at most one quarter of configured general spool bytes/files, while downstream-bound output transfers into a separate slow-spool reserve capped at one quarter of the configured pool; 128 MiB general and slow response-resident ceilings under the shared physical-memory parent, with a 32 MiB share per client; shared CGI/FastCGI concurrency slots; 32 response-body descriptor reads and 8 per client, held only for the read syscall and never for dispatch or a downstream socket wait |
| Request phase lifecycle | HTTP/1 and HTTP/2 route and authorize before accepting a body; dynamic routes return explicit Proxy/FastCGI/CGI IR, so rewrites/authentication are not repeated and cannot select a different sink after upload. Successful static routes drain request data under the same body bounds before reusing the connection, while static-only deployments retain their early body-rejection optimization. Request-worker permits cover head/policy compilation, but not backend waits, WebSocket tunnel lifetime, body socket waits or output waits. The verified lifecycle has distinct Body, concurrent BodyBackend, Backend, Output and Closed states, including a proved body-discard transition directly to output. Body errors transition to bounded error output/cancellation, and route-selected CGI descriptors remain exactly charged while the prepared handler waits for its body |
| HTTP/1 response framing | the writer discards caller `Content-Length`/`Transfer-Encoding`, emits the computed length, and treats a short file body as a connection-closing error; the event-driven output pump holds no request-worker lease, uses nonblocking `sendfile(2)` for plain file responses in 256 KiB fairness quanta, falls back to short 64 KiB descriptor-read permits for TLS/unsupported sources, and retains response/descriptor/backend ownership through completion or cancellation. Cumulatively blocked output transfers transactionally from general connection/backend/memory/spool capacity into the shared source-fair slow-output class, uses an anchored minimum rate and absolute 16-interval lifetime, and closes rather than returning to keep-alive. The verified ownership state machines prevent either Slow-to-General reopening or outer cancellation from releasing a lease while a blocking read task still owns it |
| HTTP/2 | verified settings, header-state, flow-control and reset budgets; a refillable connection token bucket bounds SETTINGS, PING, PRIORITY and tiny WINDOW_UPDATE work; at most 32 streams per connection, 64 per validated effective-client quota key and 256 process-wide, acquired client-first so rejection cannot retain a global slot. After routing, a stream awaiting request DATA transactionally transfers out of that general pool into a separate source-fair 128-process/32-per-client slow-input pool, and reacquires general capacity before backend/policy execution or output resumes. The verified `GeneralBeforeBody -> SlowInput -> GeneralAfterBody -> Closed` lifecycle prevents a completed body from re-entering the wait pool; failed reacquisition leaves the stream accounted until reset. Known-length dynamic uploads above 1 MiB stream through the same bounded channel as HTTP/1; unknown-length bodies retain the 64 KiB resident prefix and shared request-spool quota. Both enforce body `MinRate` inside the hard deadline. Backend dispatch uses the bounded blocking pool without retaining request-worker or response-read permits. Response file/stream reads wait for assigned flow-control capacity, use at most 64 KiB per chunk, retain response-resident accounting until h2 releases every queued chunk/byte slice, and hold response-body read permits only during the actual read. Cumulatively blocked outputs transfer out of the general stream pool into the shared source-fair 128-process/32-per-client slow-output pool, preserving one complete advertised H2 connection per slow source; still-live queued byte slices transfer with them. Their minimum average rate and absolute 16-send-interval lifetime are anchored at response start, so a one-byte WINDOW_UPDATE cannot renew either boundary; each interval is `max(Timeout, 5s)`, and connection idle expiry runs only when no stream is active |
| Compression/PCRE/password hashing | fixed input/cost bounds and a shared 32-operation CPU-work admission gate; optional compression falls back to identity under pressure |
| Autoindex | at most 4096 examined directory records (including filtered names), 4096 rendered entries and 4 MiB of generated HTML |
| DNS authorization | eight resolver workers, queue length 64, two-second caller deadline and bounded copied host operands |
| Dynamic backend DNS | the first bounded address set is atomically pinned to one immutable configuration generation and shared by proxy, WebSocket, health, TCP FastCGI and OCSP paths; exact connected peer addresses are rechecked and reload is the only identity transition |
| Expression filesystem functions | `-f`/`-d`/`-e`/`-s`/`-F`/`-U`, `file()` and `filesize()` resolve relative to the retained document/alias-root descriptor with `RESOLVE_BENEATH`; `file()` uses `O_NONBLOCK`/`O_NOFOLLOW`, a stable before/after descriptor snapshot and a 64 KiB read ceiling |
| Administrative inputs | regular descriptors with stable before/after metadata; symlinks are forbidden except for a root-owned final TLS-material link between root-owned non-writable trees (the Certbot `live` → `archive` shape), and a root-controlled RewriteMap program spelling whose canonical executable is separately validated and snapshotted; retained root trust and service-nonwritable parents across reload; proxy CA files consume the same retained trust; authentication databases additionally require strict UTF-8 and service-immutable parents/files unless `MutableAuthFiles` is enabled; 4 MiB per configuration/certificate/TypesConfig/auth file, 1 MiB per key/envvars file, existing RewriteMap limit, and 16 MiB aggregate configuration text |

A malformed or over-limit stream produces an error response or connection
close; request-spool exhaustion specifically produces `503` and releases its
exact RAII lease. Empty and small bodies never consume a spool-file slot. No
attacker-declared length reserves bytes that have not arrived, and no
attacker-byte-derived extension can move the absolute body deadline.
Unsafe-method cache invalidation runs only after a successful 2xx/3xx response
and selects disk victims from a per-generation key index; rejected requests do
not force recursive cache-tree walks. Disk metadata reads are capped at 1 MiB,
large cached bodies remain file-backed on warm hits, and request-policy,
access-file and password-file caches have independent byte and entry ceilings.
Connection admission uses an atomic reserve/release guard, including thread
spawn failure, and descriptor-exhaustion accept errors back off instead of
spinning. Per-client accounting canonicalizes IPv4-mapped addresses, keeps
IPv4 exact, and maps IPv6 to a Verus-verified `/64` key so rotating interface
identifiers cannot evade connection, HTTP/2 or WebSocket ceilings. HTTP/2 and
WebSocket admission use the validated effective RemoteIP identity. A transport
peer explicitly trusted to present many such identities is still bounded by
the process-wide worker ceiling, but is not charged as one ordinary client.

### I34 — Main-configuration directive disposition closure

```text
recognized(d) -> handled(d) | fail_closed(d)
unknown(d) -> fail_closed(d)
warning(d) -> handled_equivalent(d) | deliberately_stricter(d)
```

`fail_closed_directives` and the security-family classifier are the explicit
main-config counterpart of the `.htaccess` registry. Security, filter, audit,
resource-limit, presentation, and module directives that are not implemented
fail startup in every mode. Remaining warnings belong only to handled
compatibility forms whose behavior is equivalent or deliberately stricter
(for example Rustls OS randomness in place of `SSLRandomSeed`). The
disposition matrix asserts closed-world rejection.
Directive context is part of that disposition. A value represented only by a
process-global Vapache field is rejected in Apache per-vhost/per-directory
forms rather than allowing the last scope to overwrite every other scope.
Mapping, cache-route, TLS and logging directives likewise compile only in a
context whose effect is represented exactly. `ServerRoot` is processed at
read time, so it binds subsequent relative `Include` paths as it does in
Apache. Unsupported section arities and virtual-host-local balancer
definitions fail before they can acquire global meaning.
Apache 2.4.69 also accepts the unsupported reverse nesting of a request-time
`<If>` containing `<Files>`, but ordinary direct requests do not evaluate
the nested file policy. Vapache rejects that construct in both main
configuration and `.htaccess`: executing the nested grant would broaden access
relative to Apache, while accepting it as inert would hide operator policy.
TLS compatibility directives are validated at the same boundary: malformed
`SSLProtocol`, `SSLPassPhraseDialog`, session-cache and stapling-cache values
cannot survive until listener construction or disappear behind a warning.

### I35 — Single-file alias target split

```text
prefix_alias(target is file) -> (root = target.parent, rel = target.file_name)
prefix_alias(target is directory) -> (root = target, rel = URL remainder)
```

A file target never produces an empty `rel`.  The basename is what carries the
handler/MIME extension and `SCRIPT_FILENAME`; treating the file as a root hid
the extension and served scripts as static source (F39).  The split obligation
is mechanized as `alias_file_target_split`.

### I36 — Single-file alias access root

```text
mapping_root(alias target) == target             if target is a directory
mapping_root(alias target) == target.parent      otherwise
```

The URL/base root for a file target is its parent directory.  Returning the
file itself broke URL-base derivation and handler identity (F39).  This root
is not an authorization boundary: per I47 the access-file walk covers every
applicable ancestor regardless of the alias target.  `alias_access_root_admit`
states the file case.

### I37 — Handler selection from the resolved target

```text
handler/MIME/FastCGI selection consumes resolve(req).target.file_name
```

The URL remainder or lexical alias name may not reclassify a resolved script
as static.  `handler_name_from_target` is the mechanized predicate; the
dispatcher passes the resolved basename to `effective_handler`,
`cgi::is_cgi`, `mime_type` and FastCGI handler selection.

### I38 — `<Limit>` directive effect

```text
accepted_in_limit(d) && effectful(d) -> applied(d) or rejected(d)
not (accepted_in_limit(d) && effectful(d) && ignored(d))
```

Apache applies `Options`, `Header`, `AddHandler` and `SetHandler` written
inside `<Limit>`; discarding them let `Options -ExecCGI` become a
remote-execution bypass (F40).  Main-configuration directives inside a
method-limited section are now applied to the enclosing scope, and auth/access
directives still consume the method set.  `.htaccess` continues to reject
non-auth directives in `<Limit>`.  `limit_directive_effect` is the verified
disposition predicate.

### I39 — CGI/FastCGI actual-target policy

```text
actual_target != lexical_target ->
    authorize(actual_target) && bind(actual_target) before execute/forward
```

CGI and FastCGI dispatch open the target first, re-authorize its descriptor
path and bind the sink to its inode before execution or before sending
`SCRIPT_FILENAME`. FastCGI sends the lexical split path as `SCRIPT_FILENAME`
so PHP-FPM makes the same extension decision it makes behind Apache, while
binding both that path and the canonical authorized path. It also binds the
exact backend and repeats the lexical-path-to-inode comparison immediately
before parameter emission. This
includes `PATH_INFO`, `SetHandler` and `ProxyPassMatch` routes; a public
symlink cannot inherit the allowed directory's policy (F41).
`cgi_actual_target_admit` is the mechanized implication.

### I40 — Capture-only regex alias base

```text
replacement has leading capture and no stable prefix -> no base
no base -> map_path returns None
```

An `AliasMatch`/`ScriptAliasMatch` replacement such as `"$1"` has no implicit
`ServerRoot` base.  Falling back to `ServerRoot` admitted arbitrary reads of
`.htpasswd`, keys and configuration (F42).  Only an explicit directory prefix
(`/srv/private/$1`, `private/$1`) creates a base;
`capture_only_alias_admit` is the verified decision.

### I41 — Exclusive private temporary files

```text
temp_file_create -> create_new && private_mode && unlink_after_open
```

The FastCGI output spool uses `create_new` (`O_EXCL`), mode `0600`, a bounded
collision retry and immediate unlink.  A pre-created shared-temp symlink can
neither redirect nor truncate a server-writable file (F43).
`temp_file_create_admit` states the exclusive/private conjunction.

### I42 — Expression file-test confinement

```text
expr_file_test(arg) -> !absolute(arg)
                     && !parent_relative(arg)
                     && canonical(arg) under canonical(DocumentRoot)
```

`-f`, `-d`, `-e`, `-s`, `-F` and `-U` use the same confinement as
`file()`/`filesize()`; `<IfFile>` remains the explicit main-configuration
exception because its argument is operator supplied.  Without this, a writable
`.htaccess` could use absolute paths or escaping symlinks as a metadata oracle
(F45).  `expr_file_test_admit` is consumed by `confined_expr_path`.

### I43 — Multi-provider `<RequireNone>`

```text
RequireNone(children) -> deny    if any child is Granted
                      -> neutral if no child is Granted
RequireNone(children) never grants
```

The children are aggregated as an OR of positive hits before the negation is
applied.  Combining the children with AND let a denied sibling neutralize a
granted child, turning a multi-network block list into an allow list (F46).
`combine_or_all`, `require_none_multi` and `require_none_multi_result` are the
mechanized aggregation/negation kernels consumed by `access.rs`.

### I44 — Regex alias file target

```text
regex_alias(target is file) -> (root = target.parent, rel = target.basename)
access_root(alias target) == target.parent if target is not a directory
```

A regex replacement ending in `/` may still name a regular file.  The target
must be split exactly like a prefix file alias, whether or not the replacement
had a trailing slash (F47).  The regex mapping branch consumes
`alias_file_target_split`, and the URL/base root uses the file's parent via
`alias_access_root_admit`.  Ancestor authorization still follows I47, so the
mapping-root choice cannot hide a parent access file.

### I45 — Destination-address virtual-host selection

```text
select_vhost(destination, port, Host):
    address_bound(vhost) && destination != vhost.address -> not a candidate
    exact_address_vhost_present -> wildcard vhost cannot take precedence
```

Apache groups virtual hosts by destination address and port.  A loopback-bound
administrative vhost is therefore not reachable through a public address even
when the client supplies its `Host` name, and an exact-address vhost wins over
a wildcard vhost on that address (F48).  `vhost_address_admit` and
`vhost_address_precedence` are consumed by `Config::select_vhost` and the TLS
vhost filter when a listener has a concrete destination address; HTTP/1.1,
HTTP/2, WebSocket, cache and logging call sites all pass the connection's local
address.

The compiler materializes address/port buckets and exact-name maps at startup.
Request selection is therefore constant-time for exact names and scans only a
configuration-bounded wildcard list while preserving Apache's first-match
precedence (an earlier wildcard still beats a later exact name). More than 256
wildcard `ServerAlias` patterns is a configuration error, preventing remote
Host traffic from multiplying an unbounded administrator-supplied rule set.

### I46 — Canonical peer identity

```text
peer ::ffff:a.b.c.d  ==  peer a.b.c.d
```

IPv4-mapped IPv6 peers on dual-stack listeners are canonicalized before any
authorization, logging, cache or CGI identity decision.  An IPv4
`Require ip`/`Require not ip` network therefore sees the IPv4 client, and
`Require local` treats `::ffff:127.0.0.1` as loopback (F49).
`ipv4_mapped_to_v4` is the verified conversion consumed by
`access::canonical_ip`; the connection boundary and RemoteIP path apply it
before the request context is built.

### I47 — Access walk domain

```text
dir in access_walk(target)  <==>  dir is an ancestor of target
                                  && effective_override(dir) permits access files
DocumentRoot(target) and alias_root(target) are not lower bounds
```

Apache consults `.htaccess` at every ancestor directory for which its
`<Directory>`/`AllowOverride` policy permits overrides.  A `DocumentRoot` or
alias target is a URL-mapping label only; using it as the walk boundary
silently discarded policies in an application root above `public/` or in a
parent of an alias target (F50).  The runtime walk consumes
`access_walk_dir_admit`, and `access_file_layer_read` no longer contains an
`under_root` conjunct.  URL-base/`RewriteBase` derivation still receives the
root selected by `map_path()`, but that root never decides participation.

### I48 — URL-selected alias mapping root

```text
alias_root(req) == root returned by map_path(req.url)
alias_root(req) != first alias target that happens to contain resolve(req)
```

An ordered alias table is selected by URL prefix or regex, not by filesystem
containment.  Overlapping targets can therefore make “the first alias whose
target contains the path” a different alias from the one that mapped the
request.  `map_path()` returns the actual mapping root, and every caller passes
that value to the access walk/cache; `alias_mapping_root_admit` states that a
root inferred from alias-target containment is never admitted (F51).  The
mapping root selects the alias for `ResourceKey` and containment, while
per-directory URL bases follow the URL mount for layers at/below it (I50) and
the rewrite matching subject is filesystem-relative for every layer (I58),
never a path relative to the alias target alone.  Authorization still walks
every ancestor per I47.

### I49 — DirectoryIndex cache target

```text
CacheKey(req for /dir/) binds selected_index(target)
CacheFingerprint(req for /dir/) binds selected_index(target).policy
dynamic(selected_index) && CacheIgnoreQueryString && query != "" -> no cache
```

A directory URL resolves through `DirectoryIndex` to a different file or
script before dispatch.  The cache decision must therefore resolve the index
first and bind the key, target, authorization grant and policy fingerprint to
that selected index.  `CacheIgnoreQueryString` may never merge a dynamic
index/script representation across queries, and a live `<Files>`/`.htaccess`
change affecting the index must change the computed policy before a lookup
(F52).  The runtime consumes `cache_directory_index_bind_admit` and
`cache_ignore_query_admit` before lookup/store.

### I50 — Per-directory rewrite URL base

```text
layer_dir at/below mapping_root
depth(layer_dir, target_dir) == number of filesystem components below layer_dir
match_base(layer) == URL_path(target)[0 .. len - depth] with a trailing slash
match_base(layer) != path(layer_dir) relative to an alias target
```

For a layer at or below the URL-mapping root, Apache's per-directory rewrite
prefix is the URL mount, not the directory's position under the alias target.
Using the target-relative path made `RewriteRule ^private/ - [F]` miss and
served or executed protected files (F53).  `request_plan::layer_url_mount()`
is now the single derivation used by access files and main-configuration
`<Directory>` rules; `RewriteBase` remains the substitution base only.  The
runtime consumes `htaccess_layer_url_base_admit`.  Matching subject identity is
separate and follows I58 for every layer, including layers above the mapping
root.

### I57 — REQUEST_URI identity

```text
every expression/rewrite/environment evaluation of %{REQUEST_URI}
  == dispatcher.canonical_url_path
canonical_url_path is percent-decoded, dot-segment-normalized, and query-free
%{REQUEST_URI} != Request::target (raw request-line bytes)
%{REQUEST_URI} does not include %{QUERY_STRING}
```

`Require expr`, `<If>`, `SetEnvIf Request_URI`, `RewriteCond` and rewrite
substitution expansion all inspect the same canonical URL path that dispatch
uses to select the filesystem target.  Binding any of them to the raw request
target let a query suffix, percent encoding or dot segment make a deny
expression miss or an allow expression match the wrong resource (F57).  The
runtime passes the dispatcher path into `expr::Context`,
`Scope::request_env`, `access::check` and `rewrite::Context`; the CGI
`REQUEST_URI` is likewise the canonical script URL.  `expr::Context::new`
consumes `request_uri_identity_admit`, and no implementation appends the query
string.

### I58 — Access-file rewrite subject above the mapping root

```text
for an access-file layer D:
subject(rule, request) == target_path relative to D
subject(rule, request) == requested filesystem target with D's prefix removed
subject(rule, request) != URL_path with components stripped by filesystem depth
layer above mapping_root -> subject is still filesystem-relative
cannot construct subject -> layer fails closed, never silently non-matching
```

Apache's per-directory `RewriteRule` pattern sees `r->filename` relative to the
access-file directory, not a URL prefix.  Layers above an alias/document-root
mapping root can therefore have a subject such as `wallet/public/.env` even
though the request URL is `/wallet/.env`; layers under a fixed `AliasMatch`
suffix can be deeper than the URL.  The runtime attaches the layer directory to
every parsed access-file rule, computes the subject with the single
`request_plan::layer_subject()` implementation, and consumes
`htaccess_rewrite_subject_admit` before matching.  If the subject cannot be
derived, dispatch fails closed instead of skipping the layer's deny rules
(F58).  `request_plan::layer_url_mount()` is only the relative-substitution
base; for layers above the mapping root it uses Apache's filesystem-directory
form rather than the old unmatchable URL fallback.

### I59 — Single request-plan identity

```text
dispatch(cache lookup/store) and --explain consume one RequestPlan
RequestPlan.canonical_url_path == CanonicalTarget.url_path
RequestPlan.mapping_root/rel/fs_path == map_path(canonical target)
RequestPlan.layers == access-file walk(cfg, fs_path, canonical_url_path)
rewrite Context(plan) uses plan.url_path/fs_path/mapping_root
```

Cache and dispatch previously re-decoded `Request::raw_path` and rebuilt the
mapping independently.  They now receive the same `RequestPlan`, so a cache
decision cannot be based on a different URI spelling, mapping root or
access-file layer set than the request that is eventually served.  Rewrite
rounds build a new plan from the rewritten canonical URL, and that plan is the
input to the next scope evaluation.  `--explain` prints the plan’s canonical
path, mapping, layer directories, URL mounts and filesystem subjects.

### I60 — Explicit-target access-layer binding

```text
for every RequestPlan built from an explicit target T:
  layer_walk_root == T
  for every collected layer L: T == L.dir or T is beneath L.dir
  mapping_root may differ from T only as a URL/RewriteBase label
  nonempty RequestPlan.layers are always consumed by scope evaluation
  mapping_root containing a symlink must not fabricate root.join(file_name)
fail closed if the layer set does not belong to T
```

The initial URL-mapped plan and a later canonical-target plan have two path
identities.  A plan built from an explicit target must derive its access-file
walk, layer identities and scope evaluation from that same target; the
mapping root is allowed to differ because it names the URL mount (and may be a
symlink such as a release `current` link).  A failed `strip_prefix(root, T)`
is not evidence that `T` has no access files: the walk uses `T`'s real
ancestors, inheriting `AllowOverride` policy from the corresponding lexical
mapping directory when the root itself is symlinked.  `from_fs_target`,
`build_with_fs_path`, `evaluate_scope` and the `cache`/`DirectoryIndex`
target paths consume `explicit_target_layer_admit` and
`target_layer_consume_admit`; a nonempty layer set is never silently replaced
by the configuration-only scope (F59).

### I61 — Resolved-target and rewrite scope conjunction

```text
L = URL-mapped lexical path/scope
T = opened/canonical target path/scope (or the rewritten URL target)
L != T  ==>  effective_scope = meet(scope(L), scope(T))
options_effective(L, T)    == options(L) AND options(T)
handler(L, ext) == handler(T, ext)  -> permitted
otherwise                            -> no handler (source/default)
AllowOverride(L) None  ==> no access-file layer of T is read
every transform target (symlink, alias, rewrite, PATH_INFO, FastCGI,
DirectoryIndex, DirectorySlash, cache target) uses the same meet
rewrite changes the URL ==> original URL policy is retained as well
```

The URL identity and the resolved filesystem identity can differ without any
URI normalizer, `openat2` or inode-binding failure: a symlinked `DocumentRoot`
or alias, an in-root symlink created by upload/archive extraction, a
`DirectoryIndex`, or a rewrite-selected target all produce two policy
identities.  Replacing `scope(L)` with `scope(T)` dropped child
`<Directory>` and ancestor `.htaccess` restrictions, so `Options -ExecCGI`,
`Options -Indexes`, `RemoveHandler` and lexical `AllowOverride None` were
bypassed (F60).  `Scope::restrict_with()` now computes the meet:
`options_conjoin`, `handler_conjoin_admit` and
`override_categories_conjoin` are the verified kernels; handler maps are
projected to explicit per-extension grants only when both identities agree,
and an explicit lexical `SetHandler none` materializes as a static
`none` force across the meet (F64b: the resolved target cannot re-arm an
extension handler the lexical identity unforced).
The `AllowOverride` walk consumes `OverridePolicy::conjoined_with()` so an
explicit `None` on either path identity denies the canonical access file,
while an unconfigured canonical directory does not erase an enabled lexical
policy (the F59 shape).  Rewrite-selected filesystem targets and cache targets
use the same meet; the post-rewrite original-URL gate uses
`restrict_policy_with()` so it retains the original `Options`/headers without
forcing the old filename's handler extension onto a legitimately rewritten
target.

### I62 — SetHandler precedence

```text
SetHandler in scope S forces handler H for every request S governs
effective_handler == forced-name            when S forces a name
effective_handler == ext-table resolution   when S forces none
merging/inheritance never re-parses the force into the extension table
the extension table can neither add nor remove execution past a force
```

`SetHandler` is a precedence field (`MappingPolicy.set_handler`), not an
extension-table entry, so directive order and inheritance cannot re-prioritize
it (F64).  `effective_handler` consults the force first; a child `SetHandler
none` clears the parent force and the extension table applies again (the
Apache 2.4.69 probes).  The conjoin across the resolved-target meet keeps
`set_handler_conjoin_admit` and materializes a lexical denial as a static
force, so the attacker `.htaccess` `AddHandler` upload chain (F64b) is dead.
`[H=...]` rewrites write the same field.  `set_handler_precedence_admit` is
the kernel; `set_handler_conjoin_preserves_force` proves the conjoin never
grants.

### I63 — Expression filesystem variables fail closed

```text
%{REQUEST_FILENAME}/%{SCRIPT_FILENAME} == mapped fs_path  when bound
unbound reference -> Err (fail closed), never an empty string
unknown variable -> configuration error at load time
```

The `<If>`/`Require expr`/`RewriteCond expr` idioms that key on the mapped
filesystem path must evaluate against the dispatcher's canonical mapping
(F63/F63b).  `expr::Context::fs_path` is the only binding; without one the
variables fail closed instead of substituting an empty string that would
make a guard silently take the attacker's direction.  `expr_var_known` is the
single source of truth shared by evaluation and the load-time `validate_vars`
walker (which also scans `%{...}` inside `Expr::Str` and transform arguments),
so an unknown variable is a configuration error, never an inert string.

### I66 — CGI execution admission

```text
execute(script) <=> classified && exec_allowed
classified   == handler-bound ? (handler == cgi-script) : script_alias
exec_allowed == script_alias || Options ExecCGI
```

CGI execution requires both a CGI classification and a filesystem grant
(F65/I66).  `cgi::is_cgi` reduces to the single verified kernel
`cgi_exec_admit`, so a `SetHandler default-handler` force inside a
`ScriptAlias` tree serves static source (Apache behavior), while the ScriptAlias
mapping keeps executing scripts with `Options` disabled — the Apache 2.4.69
matrix.  `cgi_exec_requires_cgi_handler` and `cgi_exec_requires_exec_allowed`
prove the fail-closed direction.

### I70 — Lexical handler identity

```text
handler/MIME classification binds to the request-mapped basename
L != T  ==>  the canonical target's basename must not classify the request
```

The handler for a request is derived from the lexical URL-mapped filename,
not from the canonicalized target (F69/P13/I70): an in-root symlink
`link.txt -> secret.cgi` under a global `AddHandler cgi-script .cgi` must
serve static source, exactly as Apache does.  The same identity is consumed by
direct CGI, CGI `PATH_INFO` and FastCGI selection.  Resolved-target scope
evaluation uses one immutable request plan twice: canonical basename for
authorization and lexical basename for handler-producing `<Files>` /
`<FilesMatch>` policy.  Only the handler table and `SetHandler` force come
from the lexical view, so canonical Files access restrictions remain active.
`handler_identity_lexical_admit` guards selection and
`handler_scope_lexical_admit` proves the Files-scope obligation.

### I71 — Configuration and environment phase identity

```text
read-time branch = IfModule/IfDefine/IfFile/IfDirective/IfSection/IfVersion
authz_env = SetEnvIf + server-scope RewriteRule [E]
fixups_env = authz_env + directory/access-file [E] + SetEnv/PassEnv - UnsetEnv
ACL input == authz_env
```

Apache's core conditional sections select their branch while configuration is
read; `<IfFile>` is not a request-time filesystem oracle, and linked modules
exist in the `<IfModule>` registry before any `LoadModule`. Access files use
the compiled configuration's same module/directive/section registry. Unknown
sections and conditional ownership that cannot be represented are rejected
rather than made transparent.

Environment visibility follows hook order. `SetEnvIf` and server-scope
rewrite environment effects exist before authorization. Per-directory and
access-file rewrite effects run during fixups, followed by mod_env's
`SetEnv`/`PassEnv`/`UnsetEnv`, so those values may reach CGI/FastCGI but can
never satisfy `Require env`, change `Require expr`, or select an ACL `<If>`.

### I51 — Cache key byte identity

```text
base_key(req) == base_key(req')
  ==> listener, vhost, host, raw URL path, raw query, resolved target bytes
      and policy fingerprint are identical as byte strings
```

A cache key must be injective over the raw bytes that select an entry.
`String::from_utf8_lossy` and `Path::display()` can map distinct invalid-byte
queries, paths or targets to the same replacement text.  `cache_key_hex`
encodes every byte component as two ASCII hex digits; paths that are not valid
UTF-8 bypass the shared cache, and invalidation uses the same encoding.  The
Verus refinement proves the runtime encoder equals `cache_key_hex_spec`, and
`cache_key_hex_spec_injective` proves the encoding is injective over raw byte
sequences, not merely length-preserving.  This closes the
invalid-query/clean-URL collision (F55) for query, path and target material.
Policy/request identity is a separate 256-bit value: every exact material
field is framed by the verified, injective `cache_fingerprint_field` and
hashed with SHA-256.  The old 64-bit `DefaultHasher` fingerprint was small
enough for a header-varying attacker to target; SHA-256 collision resistance
remains a cryptographic assumption, not a Verus theorem.

### I52 — ErrorDocument cache scope

```text
missing(target) && scope.selects_local_error_document
  -> no cache lookup or store for the missing URL
response.from_local_error_document -> no store under the original URL
```

A local `ErrorDocument` is an internal subrequest selected only after dispatch
fails.  Its effective handler, target, query handling and live `.htaccess`
policy belong to the error target, not the missing URL.  Binding the outer
request to the internal subrequest's response would let a query-dependent or
dynamic error document poison the missing URL's entry (F56).  The runtime
consumes `cache_local_error_document_admit` at lookup for a missing target and
again at store using the subrequest's response-provenance marker; the internal
dispatch itself still runs the normal authorization and handler chain.  Existing
targets keep normal cache behavior even when the scope defines an error
document.

### I53 — Dynamic handler classification

```text
effective_handler(target) != default-handler
  -> dynamic(target)
dynamic(target) && CacheIgnoreQueryString && query != "" -> no cache
```

`CacheIgnoreQueryString` may only merge representations whose target is a
static default handler.  The classifier consumes the effective handler after
`DirectoryIndex` resolution and covers `SetHandler "proxy:…|fcgi://…"`,
`cgi-script`, `server-status` and future non-default handlers, not just
`ProxyPass` routes.  The runtime consumes `cache_dynamic_handler_admit` before
`cache_ignore_query_admit`, closing the FastCGI `SetHandler` query leak (F54).

### I54 — Cache store admission

```text
store(req, resp) ==> req.method == GET && req.body == empty
                    && no Authorization/Cookie
                    && status in {200,203,300,301,308,404,410}
                    && Cache-Control permits storage
                    && no Set-Cookie && Vary != *
                    && min_file_size <= body <= max_file_size
                    && freshness_ttl > 0
```

A representation enters the shared cache only through these gates.  The
runtime consumes `cache_store_request_admit`, `cache_store_status_admit`,
`cache_store_control_admit`, `cache_store_shape_admit` and
`cache_store_ttl_admit` instead of an unverified chain of early returns.
Origin `Age` and apparent age from `Date` pass through the verified
`cache_remaining_freshness` subtraction before storage. Explicit max-age and
Expires lifetimes are capped but never raised by `CacheMinExpire`; that floor
applies only to heuristic freshness and cannot revive a zero remainder.
Heuristic values pass through `cache_ttl_clamp`, which returns zero for a
reversed `CacheMinExpire`/`CacheMaxExpire` pair rather than panicking. Expiry
uses the verified saturating `cache_expiry`, so a positive TTL can never wrap
into the past. Disk accounting consumes `cache_disk_projected` and
`cache_disk_evict`; eviction steps are proven not to increase projected usage.
Policy binding uses `cache_fingerprint_field`, whose length framing is proven
injective. V7 disk metadata stores the complete framed base key; lookup admits
an entry only when that metadata key exactly matches the requested key, while
the SHA-1 filename is treated only as an index. V6 and older metadata are
deliberately ineligible after complete response cache-policy admission changed.
Unsafe-method invalidation uses
the same canonical request/selected-representation identity and removes only
entries admitted by the verified key-prefix predicate.

The disk and resident tiers have independent quotas. `CacheMaxMemorySize`
defaults to 64 MiB and counts the base key, body, response headers, Vary
material and fixed entry overhead. Insertions consume the overflow-free
`cache_memory_admit` kernel and evict the oldest entries until the new total
fits; zero disables the tier. Bodies above 64 KiB stay disk-only, and a hit
clones an `Arc<Entry>` under the mutex rather than copying the body while the
process-wide cache lock is held. `CacheMaxDiskSize` remains the independent
persisted-byte ceiling.

## 9. Formalization boundary

The first Verus model should cover:

1. `merge_scope` and the per-field merge functions
2. `rule_matches` for Directory/Files/Location and glob patterns
3. `apply_phase` / `effective_scope` over an abstract rule list
4. `eval_require` over `AuthPolicy`, `MethodSet`, `AuthMerging`
5. `override_allowed` and the category table
6. `cache_maybe_enabled` and `htaccess_may_apply` prefilter predicates
7. ordered mapping-table resolution (alias/redirect/proxy/handler operations)
8. transform-state reauthorization and sink-grant identity
9. subrequest identity and error-document recursion bounds
10. trusted request-context construction (scheme, peer, canonical name)
11. response-header policy application and merge
12. configured-base containment for alias, rewrite and FastCGI mappings
13. cache-key input closure over policy-relevant request headers
14. `.htaccess` directive disposition closure and override-category coverage
15. transform inventory closure and original/current target reauthorization
16. CGI/FastCGI script, environment, descriptor and identity closure
17. proxy route ordering plus logical/concrete balancer identity binding
18. framing and resource-bound closure over every untrusted stream
19. main-config directive disposition closure and strict-mode rejection

The following remain assumptions or separate proofs:

- the safe-Rust regex automata backend implements its documented regular
  language and capture semantics; the PCRE2 compatibility frontend is checked
  against the test-only PCRE2 10.46 oracle and rejects backtracking constructs;
- the filesystem contents match what the access-file walk sees;
- path canonicalization and `openat` containment (already separately
  verified in `crates/verified`);
- h2 wire framing and TLS/CGI/proxy protocol code;
- configuration parsing itself (the parser must produce a model accepted by
  the proofs; a parser proof can follow).

## 10. Proof obligations / lemmas

Suggested order:

1. `merge_assoc` where fields are associative, and explicit counterexamples
   for fields that are not (e.g. `Options Set`).
2. `phase_order`: folding phases in `Directory < Files < Location <
   Condition` order is equivalent to the reference interpreter.
3. `htaccess_interleave`: the per-directory fold matches the reference
   sequence `Directory, access-file` at each level.
4. `require_eval_sound`: `eval_policy` returns `Allowed` only if the policy
   actually grants under the provider semantics.
5. `require_none_never_grants`: a `<RequireNone>` subtree cannot produce a
   grant by itself.
6. `override_gate` (mechanized): `override_mode_allows` decides category-bit
   admission and `htaccess_gate_admit` returns apply/skip/reject. The theorem
   `htaccess_apply_requires_known_and_allowed` proves that applying a construct
   requires both policy admission and a known directive/section; `Nonfatal`
   can only select skip, never apply.
7. `prefilter_sound`: fast-path predicates imply the authoritative checks.
8. `acl_reachability`: every dispatch branch that returns a file/proxy body
   has a predecessor `check(scope, req) == Allowed`.
9. `configured_base_containment`: alias, rewrite and FastCGI resolution never
   returns a target outside the mapping's stable base, and a failed
   containment check produces no target.
10. `cache_input_closure`: the cache key contains every request input read by
    authorization, environment and rewrite evaluation.
11. `identity_propagation`: an authenticated grant's identity is present in
    the CGI/FastCGI environment at the script sink.
12. `proxy_head_safe`: every serialized upstream request line and header value
    satisfies the token/header predicates before I/O.

## 10a. Mechanized pieces already connected

`crates/server/src/policy_ref.rs` is the single pure evaluator for the
configuration phases **and** for access-file layers.  The walker only parses
`.htaccess` files into `AccessLayer` values; `effective_scope_with_layers`
performs the interleaving.  Production dispatch, cache and websocket paths
call this evaluator, so configuration/access-file ordering equivalence is by
construction: there is no second production interleaver.

`crates/verified` now reports **737 verified functions, 0 errors**.  The following pieces are Verus-checked; items marked model-only await a runtime projection/refinement:

- `PolicyResult`, `combine_and`, `combine_or`, `combine_or_all`,
  `require_none_result`, `require_none_multi`, `require_none_multi_result`.
  `crates/server/src/access.rs` calls these for
  `<RequireAll>`/`<RequireAny>`/`<RequireNone>`; the multi-provider
  `<RequireNone>` path aggregates positive hits with OR before negation.
- `RequestPhase`, `RequestPhaseEvent` and `request_phase_step`, consumed by
  both protocol adapters.  The transition proof makes body acquisition
  reachable only after routing selects a body-consuming sink; early policy
  responses bypass body input, prepared backends have their own phase (plus a
  concurrent body/backend phase for streaming uploads), and output/cancellation
  terminate the request. `OutputOwnershipPhase` proves cancellation transfers
  an active read to a cancelled-read owner rather than releasing its leases;
  `PreparedHandlerKind` proves every typed backend IR kind requires bounded
  dynamic admission.
- `InternalRequestKind`, `internal_request_projection`,
  `error_document_depth_step` and `internal_request_target_admit`, consumed by
  the sole internal dispatcher and configuration compiler. `DirectoryIndex`
  preserves application method/body/query state; local `ErrorDocument`
  projects a bodyless GET with its configured query, while both retain the
  wire method/target/version and client identity. Concrete header mutation
  remains covered by runtime refinement tests. `directory_index_name_admit`
  additionally binds the literal filename probe to the internal URL component.
- `multiview_candidate_spec`, `multiview_authorization_meet_spec` and
  `multiview_cache_binding_spec`, consumed by negotiation, final inode binding
  and cache planning. A selected representation retains the public URL policy,
  authorizes its selected URL and resolved inode, completes selected-name
  rewrite fixups, and cannot enter cache under the missing public identity.
- `ipv4_mapped_to_v4`, consumed by `access::canonical_ip` at the connection
  and RemoteIP boundaries; `vhost_address_admit` and
  `vhost_address_precedence`, consumed by `Config::select_vhost` and the TLS
  vhost filter.
- `AccessStep`, `access_walk_plan`, `access_plan`, `access_plan_exec`.
  `policy_ref::effective_scope_with_layers` iterates the verified plan.  The
  plan emits `DirectoryConfig { depth }` then an optional
  `DirectoryAccess { depth }` at each ancestor, followed by own-path and
  DirectoryMatch rules.  Its Files half likewise emits `FilesConfig { depth }`
  then optional `FilesAccess { depth }`, followed by DirectoryMatch Files,
  Location, config conditions and access conditions.
  `access_plan_interleaves` proves the exact structure and suffix.
- `ConfigRuleKind`, `config_rule_phase`, `config_deferred_slot` and
  `config_rule_precedes`. The runtime exhaustively projects every `MatchKind`
  into this model; phase collection and recursive nested-rule sorting consume
  the executable decisions. `config_rule_order_is_asymmetric` proves the
  comparator cannot order the same pair in both directions.
- `ConditionSource` and `condition_source_plan_exec`. Request evaluation
  consumes the verified `Config, Access` order for deferred conditions and
  resets `<If>/<ElseIf>/<Else>` chain state between the two source streams;
  `condition_source_plan_matches_access_tail` connects it to the phase plan.
- `RewriteExpandToken`, `rewrite_match_action` and `rewrite_advance`. The
  runtime expander and template guard share the verified token alphabet;
  matched/unmatched rule actions and the bounded `[S]`/`[N]`/`[L]`/`[END]`
  program-counter transition are shared by dash and internal substitutions.
- `auth_merge_kind`.  `Scope::merge` uses this three-way verified decision
  (`Replace`/`And`/`Or`) before constructing the authorization tree.
  `auth_merge_kind_properties` proves that `And`/`Or` are impossible without
  an inherited parent policy.
- `option_child_wins` / `option_child_presence`.  Scalar and
  clone-based optional security fields in `Scope::merge` use verified
  child-wins combinators.  Presence is proved exact; the underlying clone is a
  standard-library primitive.
- `append_vec`, `merge_containers`, `container_append_preserves_parent`,
  `container_lookup_pair` and `container_append_child_lookup_wins`.  Every
  append-only container/list field in `Scope::merge` appends through the
  verified `append_vec` helper, including list-backed `ErrorDocument` and
  `RewriteMap` fields.  `Header set` uses ordered child replacement (the
  runtime debug snapshot audit models that replacement separately).  Child values win by reverse lookup.  Debug builds still audit the
  concrete `Scope` containers after every merge against a projected snapshot
  and fail if a field is omitted or reordered.
- `options_apply`.  `Scope::effective_options` uses the verified
  Set/Add/Remove operation instead of an open-coded match.
- `expr_value_truthy`, `expr_compare_ints`, `expr_compare_strs`,
  `expr_glob_spec`, `glob_match_resource_admit` and `cond_chain_eval`.
  Expression values map to booleans through the verified truthiness table;
  integer and UTF-8 byte-string comparisons and rewrite `[OR]` condition
  groups consume verified kernels. `-strmatch`/`-fnmatch` uses a stack-safe
  iterative DP evaluator differentially checked against `expr_glob_spec`, with
  a verified work gate before allocation. `bounded_expansion_append_admit`
  also guards expression and rewrite output growth before vector extension.
  Leaf evaluators that consult regex,
  filesystem, IP or request state remain explicit assumptions.
- `path_under_base`, `rewrite_filesystem_admit`,
  `proxy_representation_witness`, `proxy_request_line_admit`,
  `proxy_header_admit`, `proxy_response_status_line_parse` and
  `proxy_response_header_admit`/`proxy_response_framing`. Alias, rewrite and FastCGI targets use the
  component-aware containment predicate (`/srv/www2` is not below `/srv/www`);
  the proxy boundary retains the exact authorized/upstream path pair, admits
  the outbound method, target, version and every request header immediately
  before `write_all`, then checks the complete upstream status/field set before
  choosing one unambiguous response framing mode.
- `TransformCapability`, `transform_retarget`, `transform_authorize`,
  `transform_bind_inode`, `transform_bind_backend`,
  `transform_bind_representation` and
  `transform_sink_admit`. `AccessGrant` carries this state and every protected
  body/tunnel/cache sink consumes it through `require_sink`. The proofs show
  retargeting cannot sink without reauthorization and that every file,
  backend, proxy representation or cache sink has its required concrete
  binding.
- `parse_chunk_size_hex`, `chunk_extension_admit`,
  `chunk_framing_budget_step` and `http_trailer_field_admit`. Request bodies
  and proxy responses share the exact checked hexadecimal/extension/trailer
  grammar; accepted hexadecimal bytes are tied to their mathematical value,
  framing/routing trailers are excluded, and the count/framing-byte transition
  is overflow-free.
- `h2_header_field_admit` and `h2_control_event_step`. The HTTP/2 adapter
  rechecks connection-specific fields at its downgrade boundary, and the
  vendored codec maps concrete SETTINGS, PING, PRIORITY and WINDOW_UPDATE
  events through one verified event-cost/refill/epoch transition.
- `resource_budget_admit`, `connection_admit`, `h2_process_slot_admit`,
  `minimum_progress_rate_admit` and `response_body_read_lease_admit`.
  Aggregate/per-client counters use overflow-free admission; the H2 order
  gate requires client admission before a process slot; the progress gate
  proves the byte-rate comparison without overflow and does not extend an
  absolute deadline; and the P30 phase classifier permits the response-read
  counter only for `DescriptorRead` while proving `RequestDispatch` and
  `ClientWriteWait` are excluded.
- `escape_log_bytes_bounded`. Request-derived logging consumes the executable
  escaping loop with a caller-supplied complete-line ceiling; the proof keeps
  output within that ceiling and excludes CR, LF and NUL.
- `cache_weak_etag_match`, `cache_if_none_match_matches` and
  `cache_conditional_hit_admit`. Cache validators use RFC weak comparison,
  scan the complete comma list, keep commas inside quoted opaque tags, reject
  empty/trailing/malformed members, and prove
  that `If-None-Match` suppresses `If-Modified-Since` even on a non-match.
- `descriptor_snapshot_admit`. Access-file cache lookup/parsing and
  `RewriteMap prg` executable capture consume opened descriptors and require
  stable regular-file identity, version metadata and bounded size before
  accepting the snapshot. Program bytes are sealed in a memfd; every lookup
  checks the source pathname's original inode/version and executes only that
  immutable descriptor.
- `owner_component_reopen_admit` and
  `rewrite_filesystem_binding_admit`. The owner-match walker rejects an
  ordinary component whose device/inode changes between its no-follow probe
  and usable reopen, and filesystem rewrites reach dispatch only with their
  original mapping root plus a relative-below-root witness. The corresponding
  rejection lemmas exclude component substitution and parent re-rooting.
- `alias_file_target_split`, `alias_access_root_admit`,
  `handler_name_from_target`, `limit_directive_effect`,
  `cgi_actual_target_admit`, `capture_only_alias_admit`,
  `temp_file_create_admit`, `cache_disk_size_admit` and
  `expr_file_test_admit`.  These are the pass-4 disposition predicates for
  single-file aliases, `<Limit>` effects, actual-target handler
  reauthorization, capture-only aliases, exclusive spool creation, disk-cache
  quota and expression file-test confinement (I35–I42).
  `confined_expr_relative` consumes `expr_file_test_admit`, and all file
  observations then use the descriptor-relative root walk; the remaining predicates document and
  mechanize the runtime branches exercised by the F39–F45 replay suite.
- `combine_or_all`, `require_none_multi`, `require_none_multi_result`,
  `vhost_address_admit`, `vhost_address_precedence`,
  `vhost_name_candidate_precedes` and
  `ipv4_mapped_to_v4`.  These are the pass-5 kernels for multi-provider
  `<RequireNone>` (I43), regex alias file targets (I44, sharing the pass-4
  split predicates), destination-address virtual-host eligibility (I45) and
  canonical IPv4-mapped peer identity (I46).  `access::eval_node`,
  the compiled `Config::select_vhost` index, the TLS vhost filter and `access::canonical_ip`
  consume them directly.
- `access_walk_dir_admit`, `alias_mapping_root_admit`,
  `cache_directory_index_bind_admit` and `cache_ignore_query_admit`.  These are
  the pass-6 kernels for the ancestor access-file walk (I47), URL-selected
  alias mapping root (I48) and `DirectoryIndex` cache target/query isolation
  (I49).  `access_file_layer_read` was simplified to remove the mapping-root
  conjunct.  `htaccess::collect_layers_with_root`,
  `cache::request_scope` and the dispatch/`--explain` callers consume these
  predicates; unit plus F50–F52 replays exercise each branch.
- `htaccess_layer_url_base_admit`, `cache_dynamic_handler_admit`,
  `cache_local_error_document_admit` and `cache_key_hex`.  These are the
  pass-7 kernels for URL-mounted rewrite bases (I50), lossless cache-key bytes
  (I51), local `ErrorDocument` cache scoping (I52) and complete dynamic-handler
  classification (I53).  The `.htaccess` walk, cache request scope and key
  builder consume them; unit plus F53–F56 fastcgi-mock/raw-socket replays
  exercise each branch.
- `request_uri_identity_admit` and `htaccess_rewrite_subject_admit`.  These
  are the pass-8 kernels for canonical `%{REQUEST_URI}` identity (I57) and
  filesystem-relative access-file rewrite subjects (I58).  `expr::Context::new`
  consumes the URI predicate, while `rewrite::subject_for` consumes the subject
  predicate and fails closed when an access-file layer cannot produce its
  subject; unit plus F57/F58 replays exercise both.  The `request_plan` module
  now builds one canonical target/mapping/layer set per request or rewrite
  round; dispatch, cache, rewrite contexts and `--explain` consume it (I59),
  and `LayerIdentity` plus the shared subject/URL-mount functions replace the
  duplicate layer arithmetic in `config.rs`, `htaccess.rs` and `rewrite.rs`.
- `explicit_target_layer_admit` and `target_layer_consume_admit`.  These are
  the pass-9 kernels for explicit-target access-layer binding (I60), extended
  by the pass-10 `options_conjoin`/`handler_conjoin_admit`/
  `override_categories_conjoin` meet kernels and the resolved-target/rewrite
  scope invariants (I61).
  `RequestPlan::from_fs_target`/`build_with_fs_path` walk the supplied target
  itself and fail closed if a collected layer is not its ancestor;
  `RequestPlan::evaluate_scope` always consumes a nonempty layer set even
  when the canonical target is outside the lexical `AllowOverride` prefix.
  Unit plus F59/F60 symlinked-document-root/alias, in-root symlink,
  ancestor access-file, `DirectoryIndex`, autoindex, `RemoveHandler` and
  `AllowOverride None`/rewrite-laundering cases
  replays exercise both predicates.
- `cache_key_hex_spec_injective`, `cache_lookup_hit_requires_binding`,
  `cache_lookup_rejects_stale`, `cache_store_request_admit`,
  `cache_store_status_admit`, `cache_store_control_admit`,
  `cache_store_shape_admit`, `cache_store_ttl_admit`, `cache_ttl_clamp`,
  `cache_expiry`, `cache_disk_projected` and `cache_disk_evict`.  These
  mechanize the cache key encoder/refinement, lookup consequences, store
  admission gates, freshness arithmetic and disk projection/eviction steps
  consumed by `cache.rs` (I51, I54).
- `regex_dialect_admit` / `guard_regex` / `compile_regex`. Directive regexes
  backed by Rust `regex` are admitted only after the verified dialect guard.
  Expression regexes compile through the in-tree PCRE2 compatibility frontend
  at configuration load. Regular Apache constructs retain their meaning while
  backreferences, recursion, look-around and other recursive-backtracking
  constructs fail closed. `regex_match_resource_admit` proves the overflow-free
  pattern-times-subject work bound and `expr_regex_result` proves that an
  evaluation error cannot grant even through negation. The Rust automata
  backend still supplies matching semantics for the accepted bytecode.
- `directive_disposition`. The configuration fallback uses a verified
  three-way fail-closed disposition for security-sensitive, known-but-
  unimplemented, and unknown directives. This is the executable form of I9;
  neither normal nor strict mode may accept an effectful no-op.
- `access_layer_slot`.  Parsed `.htaccess` rules are translated into
  conditional, Files or top-level layer slots by a verified decision used by
  `collect_layers`.
- `config_lex_step`, `config_lex_eof`, `config_tag_step`,
  `config_argument_count_step`, `config_argument_arity_admit`,
  `config_argument_nonempty_admit`, `config_line_kind` and
  `config_program_depth_step`. The pure front end consumes the verified
  quote/escape and section-tag transition systems, fails closed at UTF-8 and
  256-argument boundaries, and classifies each resulting line. Main
  configuration is sealed into `ConfigProgram`; access files are sealed into
  `AccessProgram`. Both programs establish exact start/end section mates and
  preclassify directive/section identity before compilation. Skipping a false,
  inactive or disallowed section jumps to its exact mate instead of rescanning
  nested text. `config_section_depth_admit` and
  `access_section_depth_admit` establish the main/access recursive compiler
  depth ceilings during these iterative seal passes.
- `config_section_nesting_allowed`.  The recursive configuration compiler
  checks section transitions through the verified context table. Section
  operands are semantic-sealed too: expressions and variables, regex/glob
  patterns and method sets are compiled before the mutation walk.
- `classify_access_rule`.  `htaccess::collect_layers` uses this verified
  partition: condition/non-normal rules go to the deferred conditional bucket,
  `<Files>` rules to the Files bucket, and everything else to the top-level
  scope.
- `prefilter_sound`.  The I3 fast-path implication is a Verus theorem for both
  cases: `htaccess_may_apply_spec` false admits no access-file layer in the
  walk, while `cache_base_scope_admit` is consumed by the compiler to reject
  `CacheEnable`/`CacheDisable` in every rule-producing context.
  `cache_base_scope_only_sound` proves that a path outside the inherited base
  `CacheEnable` list cannot become cache-enabled, so the request path performs
  no recursive cache-rule scan. The path matcher and parser-to-rule-tree
  refinement remain the stated assumptions.
- `first_match_is_first` / `first_match_none_means_no_match`.  For an ordered
  mapping table encoded as its match-bit vector, the selected entry is the
  first true bit and no true bit means no mapping applies.  This is the I14
  first-match theorem; flattening the runtime alias/redirect/proxy tables into
  the vector remains outside Verus.
- `h2_method_ok`, `h2_field_size_admit`, `h2_head_admit`,
  `H2BodyState`/`h2_body_append`, `H2InputPhase`, and `H2Budget`. The HTTP/2 adapter bounds
  `:authority` before authority parsing, calls the verified method/head decision and
  advances a verified body budget as it consumes DATA frames.  `H2Settings`
  fixes the builder limits; `H2HeaderState` bounds the decoded header list;
  and `H2Flow` models connection/stream windows and send-buffer bounds.  The
  response path uses h2 reserve/poll capacity before each DATA send, so a
  zero/small client window cannot make the adapter queue unbounded response
  bytes.  `H2Budget` is
  now driven by the connection/task loop: `Begin` at accept, `Finish` when
  the task ends, `Reset` for a `SendResponse::poll_reset` event, a
  `RecvStream` reset error, a timeout, or a send failure, and `Reclaim` from a
  timer equal to the h2 reset-stream duration.  A replay
  theorem preserves both counters for any finite event sequence.  The adapter
  also tracks stream IDs and uses a verified idempotent purge set, so a
  duplicate early-reset/close cleanup is a no-op; this is the
  CVE-2026-23918 primitive.  The ledger's begin path now calls
  `h2_stream_admit`, which proves a new stream ID is neither active nor
  awaiting reset cleanup.  `H2StreamPhase`/`h2_stream_phase_step` fix the
  adapter-local lifecycle and prove `Closed` is absorbing, so a closed ID
  cannot be reopened. `H2InputPhase`/`h2_input_phase_step` separately prove
  that a body waiter returns only to post-body general ownership, cannot wait
  twice, and cannot escape the absorbing closed state. The h2 crate still owns wire framing and resets that it
  handles internally without surfacing to the adapter; that external wire
  behavior is now an explicit assumption rather than an unverified adapter
  component.
- `cache_invalidation_status_admit` proves that only a successful unsafe
  request can invalidate cache entries; safe methods and every 1xx/4xx/5xx
  response are inert. `cache_trailing_slash_target_admit` prevents an
  unchanged regular-file representation ending in `/` from reaching lookup.
  `autoindex_append_admit` is consumed before both scan
  count and rendered-byte growth, so checked subtraction establishes the
  configured ceiling before allocation.
- `bcrypt_cost_admit` rejects bcrypt costs outside 4..=17 before invoking the
  password library. SHA/SSHA and MD5-crypt verification compares the complete
  fixed representation in constant time, while bcrypt uses its verifier.
  `expr_regex_size_admit` binds compatibility-pattern and
  subject sizes to 64 KiB; `regex_match_resource_admit` additionally proves
  the overflow-free pattern-times-subject ceiling, while compile/capture
  limits and global expensive-work admission bound memory and concurrency.
- `rewrite_backref_no_qmark`, `rewrite_filesystem_admit`,
  `rewrite_target_external`, `rewrite_internal_path` and
  `rewrite_authority_equal`.  Rewrite backreference/variable expansion uses
  the verified question-mark encoder by default.  External HTTP(S)/scheme-
  relative targets are classified exactly, internal targets are given a
  single leading slash, and same-host internalization compares authority and
  optional decimal port with ASCII case folding.  Absolute rewritten
  filesystem targets are admitted only below the current document/alias root;
  `UnsafePrefixStat` is parsed for compatibility but never changes that base.
- `proxy_target_key`.  Proxy grant binding uses an exact, verified
  length-delimited identity of `(tls, host, port, path)`; host/path NUL
  characters are excluded by the validated inputs.  The runtime converts the
  key to hex for string comparison.
- `cache_lookup_admit`.  Cache hits require matching key, policy fingerprint,
  configuration-generation epoch, `Vary` values and freshness
  (`now < expires`); the runtime uses this verified decision for memory and
  disk entries.
- Cache credential exclusion.  Disk metadata stores response headers, not
  request headers, and explicitly drops Authorization/Proxy-Authorization;
  cache keys include the policy fingerprint, query and a hash of every request
  header, so header-selected authorization branches cannot share an entry.
- Proxy target authority binding.  `ProxyPassMatch` and rewrite `[P]`
  authority templates are rejected when derived from captures or variables;
  targets are canonical and paths are encoded exactly once.  Backend hosts,
  `X-Forwarded-Host`, and the fully serialized upstream request head pass the
  verified token/header predicates before `write_all`.  Backend response
  `Location` values also pass the verified header sanitizer.
- FastCGI script containment.  `script_from_prefix()` cleans the target inside
  the configured FastCGI prefix or document/alias root, while
  `split_path_info()` binds regular-file and symlink containment to one
  `openat2(RESOLVE_BENEATH)` descriptor check. The `PATH_INFO` ancestor walk
  cannot select a file above that base, and execution repeats the
  descriptor-bound check before handoff.
- CGI/FastCGI authentication context.  The grant identity is passed into
  `CgiContext`; `build_env()` emits `REMOTE_USER` and `AUTH_TYPE` for both
  local CGI and FastCGI while keeping configured environment entries unable to
  override them.
- Expression filesystem confinement.  `file()` and `filesize()` data paths
  are confined beneath `DOCUMENT_ROOT`; absolute, parent-relative and
  symlink-escaping reads fail closed.  `FileTest` remains metadata-only (and
  is also used by admin `<IfFile>`), so it does not expose file contents.
- `escape_log_bytes`.  Client-derived access-log fields are escaped by a
  verified primitive, including controls, quotes and backslashes.
- HTTP request/header/body and compression budgets.  The verified HTTP/1
  parser plus `H2Settings`, `H2HeaderState`, `H2Flow` and the fixed compression
  cap cover the generic DoS class; the remaining HPACK/zero-window behavior is
  delegated to the explicit h2 wire-framing assumption.
- `cgi_env_entry_admit`.  Configured/rewrite environment entries pass only
  when their key is valid and not a calculated CGI/`HTTP_*` name.
- CGI calculated-environment reservation.  `cgi::build_env` refuses to let
  configured/rewrite environment entries override request, connection or
  identity variables such as `REQUEST_METHOD`, `SCRIPT_FILENAME`,
  `CONTENT_LENGTH`, `REMOTE_ADDR` and `HTTP_*`; custom variables still pass
  through.  CGI stdout/stderr, timeouts, and FastCGI headers are bounded.
- `tls_client_policy_equal`, `tls_client_revocation_policy_equal` /
  `ensure_uniform_client_policy`.  Every TLS
  listener requires one client-certificate policy across its virtual hosts;
  mixed `SSLVerifyClient`/`SSLCACertificateFile` or
  `SSLCARevocationFile`/`SSLCARevocationCheck` configurations fail startup.
  The runtime compares a verified exact identity of the effective verification
  mode, active CA path bytes, leaf/chain revocation mode and active CRL path;
  omitted and explicit `none` are equivalent, while active CA/CRL identities
  must match. Per-location client authentication is
  rejected because Rustls verifies the connection, not an individual request;
  Rustls chain validation itself remains an external TLS assumption.
- `tls_vhost_transition_admit`, `tls_sni_authority_admit` and
  `tls_client_identity_admit`. A completed TLS handshake records immutable SNI,
  destination, selected TLS-vhost policy and verified client-leaf identity.
  Every HTTP/1 request and HTTP/2 stream must retain that policy (or receive
  421), named SNI cannot lose its HTTP authority, and required mTLS cannot
  reach request dispatch without a peer certificate. Rustls's resumed-session
  peer chain is covered by a full/resumed handshake integration test.
- A wildcard `Listen` prebuilds a TLS generation for every concrete
  destination-address vhost plus a wildcard fallback. The accepted socket's
  canonical local address selects the generation before the handshake, so SNI
  certificate selection and the address-aware HTTP vhost bucket cannot diverge.
- `host_pattern_matches` / `host_suffix_matches`.  `VHost::matches_name`
  and the TLS resolver use exact `ServerName` matching and the same verified
  exact, `*`, or leading `*.suffix` `ServerAlias` matching with ASCII case
  folding. A suffix wildcard requires a preceding label and therefore does not
  match its bare suffix. Values beginning with `~` remain ordinary Apache
  names; Vapache does not invent regex virtual-host matching. Other wildcard
  placements fail at startup until their semantics are implemented. First
  configured match wins at both certificate and HTTP routing boundaries.
- `first_true_index`.  Virtual-host candidate selection uses the verified
  first-match policy.
- `parse_http_authority_endpoint`/`parse_http_ipv6_literal`, `ipv4_in_net` /
  `ipv6_in_net`, `remoteip_next_internal` and
  `remoteip_candidate_admit`. RemoteIP network membership, the internal/trusted
  proxy transition and the external-private-address refusal use verified
  functions. Authority bracket/colon splitting, registered-name normalization,
  ports and compressed or embedded-IPv4 IPv6 literals are parsed in the
  verified crate; runtime only renders the typed result.

`crates/server/src/access.rs` also exposes an `AccessGrant` capability with a
concrete `ResourceKey` (vhost, method, URL, filesystem path, proxy target,
cache key, identity).  A grant for `/public/file` cannot authorize
`/private/file`, a different proxy target, or another cache key; the cache,
static file/directory, CGI, FastCGI, HTTP proxy and WebSocket sinks verify the
key.  This is the resource-binding part of I1.  The WebSocket upgrade path
canonicalizes the raw target, runs the same rewrite gate, evaluates the target
scope, and uses the same method/access helper before taking the connection.  A
rewrite that changes the filesystem target re-evaluates
`<Directory>`/`<Files>`/`.htaccess` policy for that target before dispatch.

Static file/directory/local-CGI grants carry the opened inode and symlink
targets are reauthorized. FastCGI opens its script first, reauthorizes the
descriptor path, binds both inode and backend, and performs a final pathname
inode comparison before emitting parameters. The required stable-path policy
additionally projects `fastcgi_stable_component_admit` over every lexical and
canonical component using the configured backend and trusted-owner UIDs.
Proxy and WebSocket grants are
backend-bound; cache grants are policy-key-bound. Apache-equivalence of the
sealed semantic constructors, the regex engine, expression leaf evaluators
and the standard library's concrete sorting implementation remain outside
Verus. The external backend
must still open `SCRIPT_FILENAME` itself. With `VapacheFastCGIStablePath On`,
the verified component predicate is enforced immediately before that handoff;
without it, FastCGI is rejected unless `UnstableFastCgiPaths` explicitly
accepts the equivalent read-only-tree deployment assumption. Writable trees
must not inherit a FastCGI handler.

Security-sensitive unimplemented directives fail closed in every mode.
The classifier covers the auth/TLS/proxy/filter/DAV/LDAP/cache families by
name prefix, not only an explicit denylist. The general fallback is closed too:
known-but-unimplemented and unknown directives are startup errors rather than
warning-only no-ops.

### Policy-core migration

The first `ScopePolicy` slice now exists in
`crates/server/src/scope_policy.rs`:

- `OptionsPolicy` stores the ordered Set/Add/Remove sequence and evaluates it
  through the verified `options_apply` primitive;
- `OverridePolicy` owns `AllowOverride`, `AllowOverrideList` and
  `Nonfatal=...` inheritance, with child-presence merge semantics;
- `AuthorizationPolicy` owns `requires`, `auth_merging`, `AllowMethods` and
  legacy `Order`/`Allow`/`Deny` state, using the verified `auth_merge_kind`
  decision and child-presence inheritance;
- `HeaderPolicy` owns header add/set/unset lists, expiration state,
  cookies and Vary, with append/child-presence merge rules;
- `EnvironmentPolicy` owns phase-separated server rewrite, per-directory
  rewrite, `SetEnvIf`, and late `SetEnv`/`UnsetEnv`/`PassEnv` state (I71);
- `ContentPolicy` owns directory defaults, MIME add/remove/force types,
  ETag/sendfile/directory-slash and access-file names;
- `MappingPolicy` owns aliases, redirects, handlers and unsupported filters;
- `ErrorDocumentPolicy` owns the ordered status-code document list with
  reverse child-wins lookup;
- `RewriteCachePolicy` owns rewrite engine/maps/base/rules and cache
  enable/disable state; pending rewrite conditions remain section-local;
- `CompressionPolicy` owns compression rules and deflate/brotli settings;
- `ProxyPolicy` owns proxy rules, pass/reverse mappings and the proxy CA file;
- `AuthorizationPolicy` also owns the auth type/name and user/group file
  handles;
- `ContentPolicy` also owns the document root;
- `Scope` now contains only policy objects rather than the old ad-hoc fields;
- parser construction, access checks, `.htaccess` gating and cache policy
  fingerprints read the policy objects directly.

The `ScopePolicy` migration is complete at the runtime-data level: `Scope`
now stores policy objects for all former fields.  The next formal step is the
abstract model/projection proof over these policy objects.

### Verified configuration compiler boundary

`crates/server/src/config_frontend.rs` isolates the pure front-end pieces:

- logical-line accumulation with source line numbers;
- Apache-style quoted/escaped tokenization;
- a small `ConfigLine` IR for directives, section starts and section ends.

Both the main configuration parser and `.htaccess` use the shared tokenizer.
Quote, escape, whitespace, section-tag delimiter, EOF, argument-count,
argument-arity/nonempty and structural-depth decisions are executable Verus
kernels used by production. After includes and execute-on-read conditions are
resolved, main configuration is sealed into an immutable `ConfigProgram` with
a closed section vocabulary, canonical directive identities, typed payload
schemas, directive/section arity checks, context checks, and exact section
mates. Each stable access-file snapshot is likewise sealed into an
`AccessProgram` before it mutates a `Scope`; malformed syntax inside a skipped
wrapper therefore cannot evade validation. The seal owns precompiled Require,
Options, ACL, redirect, rewrite, header, expiry, environment, listener,
RemoteIP, proxy and TLS values. Section expressions, method sets and match
patterns are precompiled as well. Raw tokens remain only for exact string/list
assignments, context-dependent filesystem effects, and directives that are
unconditionally rejected.

The main program is compiled only during startup/reload. An access program is
compiled only for a new descriptor/version snapshot and the resulting parsed
layer is cached; the sealed program is not retained on the request hot path.
The token-to-semantic-IR boundary is now closed in production: no fallible
payload parser is first invoked after `Scope` mutation begins. Apache
compatibility of complex safe-Rust constructors is still a differential
oracle obligation, while regex matching semantics remain the separate engine
assumption. Internally, every schema, sealed value and compiler projection
carries one of 46 closed semantic kinds. Executable Verus certificates prove
argument-count preservation, kind-code injectivity and end-to-end kind
identity; every compiler entry and typed getter consumes those certificates.
On/Off normalization, exact overflow-safe decimal parsing/ranging and
first-keyword selection are executable verified constructors. Capability,
stable FastCGI policy, override policy, proxy/balancer health, server aliases,
log level, TLS session-cache mode and RewriteMap source/program payloads are
compiled once during sealing rather than validated and reparsed during
effects. A cross-table test requires every effectful main/access directive to
select the same semantic domain. AccessLayer slot and directive disposition
boundaries are already verified.

### Remaining refinement boundary

The verified source/depth plan is consumed by the evaluator. Rule-kind phase
classification, deferred-slot selection and the recursive ordering comparator
are executable verified decisions. Configuration/access-file lexical
transitions, argument bounds and sealed section structure are executable
verified decisions too. Schema-to-sealed-IR-to-consumer semantic-kind
refinement, argument preservation, primitive normalization and kind
substitution rejection are executable verified decisions. Semantic payload
construction is encapsulated by the sealed Rust IR and completes before
effects. Exact equivalence of complex constructors to Apache and
standard-library sort correctness remain outside mechanical proof;
container/list field merging and the security disposition/layer-slot
translation use verified helpers.

The authorization decision, access-phase interleaving, Options algebra,
scalar overrides, `.htaccess` rule classification, expression truthiness,
comparison and glob semantics, and rewrite condition-chain folding are
verified kernels. Apache-equivalence of semantic IR construction,
standard-library sorting and regex semantics are explicit assumptions, not
hidden axioms. Filesystem
objects used by protected sinks and access-file parsing are descriptor/inode
bound. Secure path opening requires Linux `openat2` with
`RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`; configuration testing and startup
fail closed if that kernel boundary or readable `/proc/self/fd` descriptor
links are unavailable, with no pathname fallback.
The external FastCGI backend's later open of `SCRIPT_FILENAME` is covered when
the required stable-path check admits both identities. The equivalent
read-only requirement stated in I31 applies only after the explicit
`UnstableFastCgiPaths` escape hatch is enabled.

## 10b. Verification progress ledger

Verification progress is tracked as **security obligations and proof debt**,
not as a count of verified functions. The machine-readable ledger is
`docs/verification-status.json`; the gate is:

```sh
python3 tests/verification_status.py
python3 tests/verification_status.py --run-verus
```

The current ledger (2026-11-04) is:

- weighted obligations: **36.5 / 68.0 (53.7%)** if partial obligations receive
  half credit;
- proof debt: **5 / 6** — 0 named unverified security components, 0 partially
  bound sinks, 5 assumptions and 0 accepted unmodeled security-directive
  classes;
- sinks: **8/8** grant-required, **8/8** path/target-bound, **5/8**
  inode-bound, **3/8** backend-target-bound, **3/8** policy-key-bound;
- unexplained adversarial replay failures: **0** (the CVE replay corpus is
  not yet systematic; the separate finding-replay suite covers F23–P18);
- Verus: **702 functions, 0 errors**, with no `assume` or `external_body`
  proof escapes.

The gate fails when proof debt exceeds its budget, the weighted score drops
below its floor, an inode-bound sink regresses, a proof escape appears, or a
sink stops requiring a grant. Raising a budget is an explicit change to the
ledger, not an implicit effect of adding code.

## 11. Current test oracle

## 11a. Acceptance/rejection obligations

Two finite obligations are checked explicitly:

- **Acceptance:** for every configuration in the supported directive/context
  grammar, if Apache accepts it, vapached accepts it.
- **Rejection:** every malformed/invalid configuration in that same grammar is
  rejected by vapached.

`tests/config_grammar.py` enumerates the grammar and currently reports **0
divergences** against Apache.  This is exhaustive for the listed finite
subset, not a proof over arbitrary Apache syntax.

## 11b. Test oracle

The pre-proof suite is:

- `tests/conformance.py` — 165 fixed Apache differential/conformance tests.
- `tests/config_semantics.py` — 235 fixed systematic cases, plus
  `--random N --seed S` deterministic randomized cases.
- `tests/config_validity.py` — `apache2 -t` vs `vapached -t` context matrix.
- `tests/config_grammar.py` — finite supported directive/context grammar,
  including valid and invalid argument/section forms.
- `tests/adversarial_regressions.py` — end-to-end F23–F38 finding replays
  (authorization transforms, cache identity, alias/rewrite/FastCGI
  containment, request-header effects and CGI identity).
- Rust unit invariants in `config.rs`, `htaccess.rs`, `access.rs`, `cache.rs`,
  `fastcgi.rs`, `proxy.rs`, `rewrite.rs` and `server.rs`.

Until the model is mechanized, any change to merge order or override gating
must be accompanied by a differential case.  The generated suite is the
current definition of “matches Apache” for the covered surface.

### 11c — Unproven security-critical production coverage

Modules that are too complex or protocol-dependent for the current Verus model
are tracked separately from the proof ledger:

```sh
tests/coverage.sh
python3 tests/security_coverage.py --strict
```

The tracker measures **production lines before each file's test module** and
sets a 100% target for every listed server module. The current full-tree
fail-closed floor is 29,460/32,026 lines (91.99%); asynchronous cancellation
tests may cover one or two additional race-dependent lines. The CI `--check` mode enforces a
per-module monotone baseline: the number of covered lines cannot decrease and
the number of missed lines cannot increase. `--strict` remains the absolute
zero-debt check. Security-critical targets include:

- `fastcgi.rs` — record parsing, spooling, script/PATH_INFO containment,
  environment derivation, error paths and process boundary;
- `http.rs` — request-head/body framing, chunk/trailer bounds, spool-file
  creation, response framing headers and short-body failure paths;
- `tls.rs` — certificate/key parsing, SNI selection, OCSP refresh, client-auth
  policy and listener construction.

The remaining debt in high-risk surfaces (`cgi`, `h2`, `proxy`, `server`,
`htaccess`, `config`, `expr`, `rewrite`) remains visible in the report and may
only move downward without an explicit review of
`tests/security_coverage_baseline.json`. A module is not considered closed
merely because its test module is covered; the tracker excludes test-only code
from the denominator. The quality workflow installs Apache and runs the full
grammar/validity/semantic corpus before applying the ratchet.
`docs/coverage-debt.md` records why the remaining lines are not reached and
which deterministic harness boundary is needed to reach them; absence of a
test is not treated as evidence that a branch is unreachable.
Coverage builds disable ThinLTO only for instrumentation and pair every raw
profile with its exact executable build ID before export; this avoids the Rust
1.99 mismatched-profile failure without changing production artifacts.

## 12. Known gaps before formal proof

- Configuration phases and access-file interleaving now run through a verified
  source/depth plan consumed by the single production evaluator. Rule-kind
  phase classification, deferred-slot selection and the recursive ordering
  comparator also consume executable Verus decisions. Lexical transitions,
  argument bounds and immutable section structure are verified and connected.
  The closed schema/sealed-IR/compiler semantic domains, argument preservation,
  primitive normalizers and wrong-domain rejection are mechanically connected;
  complex constructor equivalence to Apache and concrete library sorting
  remain covered by the explicit oracle/refinement assumption. Container/list
  field merging, directive disposition and `.htaccess` layer-slot translation
  use verified helpers.
- Some module-specific merge rules are not modelled.  `AllowOverrideList`,
  `Nonfatal=...`, `Include`/`IncludeOptional` and the covered contexts are now
  implemented or covered by the differential/context matrices.
- Regex semantics are assumed, not proved.
- Vhost/Include precedence is only lightly covered by the generated suite.
- `--explain` now lists matching nested configuration rules with phase,
  order and condition result, and traces access files with their override
  mode, list, nonfatal mode and parsed rule count.  It does not yet show the
  action-by-action merge of every `.htaccess` directive.
- I1 is capability-enforced for cache/file/directory/CGI/FastCGI/proxy and the
  WebSocket tunnel path.  A few explicit pre-auth error paths still construct
  responses before an access check; those are documented separately.
- I3 prefilters are now Verus theorems (`prefilter_sound`,
  `htaccess_prefilter_sound`, `cache_base_scope_only_sound`) over the
  boolean/list model. The path-pattern matcher and the parser-to-flattened-rule-
  list refinement are still explicit assumptions; the cache lookup also
  requires an `AccessGrant` at runtime.
- FastCGI cannot pass its retained script descriptor through the protocol;
  the external backend's open of `SCRIPT_FILENAME` occurs after vapache's
  final pathname-to-inode comparison. Exact `VapacheFastCGIStablePath`
  policies enforce trusted owners and backend write exclusion by default.
  Only `UnstableFastCgiPaths` permits the equivalent read-only release-tree
  invariant to remain a deployment assumption; never map writable content to
  FastCGI.

## 13. CVE root-cause triage

### Apache HTTP Server

The NVD CPE `apache:http_server` snapshot is triaged in
`docs/cve/apache2-cve-matrix.json` (371 CVEs).  The current result is:

- 370 prevented in principle by construction, verified primitives or
  fail-closed rejection,
- 0 partially covered,
- 1 not covered by the formal specification,
- 0 unclassified.

The sole uncovered row is the external Rustls certificate parser
(`CVE-2004-0488`), treated as an explicit dependency assumption.
The complete methodology and limits are in `docs/cve/README.md`; regenerate
and validate with:

```sh
python3 tests/cve_matrix.py
python3 tests/cve_matrix.py --check
```

This is a static per-CVE triage, not a claim that a working PoC replay exists
for every row.

### Other widely deployed servers and proxies

`docs/cve/cross-server-nvd.json` snapshots the NVD histories for nginx,
IIS/HTTP.sys, lighttpd, HAProxy, Tomcat/Coyote, Jetty, Squid, Varnish, Apache
Traffic Server, LiteSpeed/OpenLiteSpeed and Envoy. The **1,047 distinct CVEs**
are compared individually against Vapache's feature inventory, invariants and
implementation evidence in `docs/cve/cross-server-cve-matrix.json`:

- 370 prevented by a concrete design/implementation property,
- 54 rejected at an explicit fail-closed capability boundary,
- 580 not applicable because the affected feature/platform is absent,
- 41 partial and therefore still open, and
- 2 NVD description/CPE conflicts retained as `needs_review`.

The source snapshot preserves dates, CVSS vectors, exact vulnerable CPEs and
advisory links. Each result records whether it came from an explicit
advisory/patch override or a conservative description/feature rule. Validate
the generated JSON, CSV and high-risk report with:

```sh
python3 tests/cross_server_cve_matrix.py --check
```

This matrix is not a proof that Vapache cannot have an independent bug in a
similar subsystem. In particular, `partial` and `needs_review` make no
prevention claim.
