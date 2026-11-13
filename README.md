# httpd-rs

A memory-safe, formally verified, drop-in-compatible Apache HTTP Server
replacement written in Rust.

The [httpd-rs documentation](https://jd-p.github.io/httpd-rs/) covers migration,
intentional Apache differences, security expectations, and executable
documentation contracts. Its [Markdown source](docs/README.md) is maintained
in this repository.

`httpd-rs` reads ordinary Apache 2.4 configuration files, serves static files,
runs CGI programs, and keeps the security-critical parsing kernels in
[Verus](https://github.com/verus-lang/verus) so they can be machine-checked.
The project targets Apache-level compatibility while hardening the historical
CVE hotspots: request smuggling, path traversal, response splitting, range
amplification, CGI environment injection and descriptor leaks.

## Status

Implemented today:

- Apache 2.4 config grammar, `<IfModule>`/`<IfDefine>`, `Include`,
  `${VAR}` expansion, scopes, name-based virtual hosts and stock Debian
  `/etc/apache2/apache2.conf` parsing.
- Static files, `DocumentRoot`, `Alias`, `ScriptAlias`, `AliasMatch`,
  `ScriptAliasMatch`, `Redirect`, `RedirectMatch`, `RedirectPermanent`/
  `RedirectTemp`, `DirectoryIndex`, autoindex, `AddType`/`RemoveType`/
  `ForceType`, `AddHandler`/`RemoveHandler`, `AddDefaultCharset`, MIME types
  and custom error documents. Regex aliases and redirects expand `$1`..`$9`
  captures and are resolved through the same target mapping as prefix aliases.
  A trailing-slash URL never serves a regular file; real CGI/FastCGI handlers
  still dispatch trailing path-info spellings.
- Byte ranges, `If-Range`, `If-Match`, `If-None-Match`,
  `If-Modified-Since`, `If-Unmodified-Since`, ETags and `Last-Modified`.
- Access control (`Require all`, `ip`, `host`, `method`, `local`, legacy
  `Order`/`Allow`/`Deny`, `<Limit>`/`<LimitExcept>` method-scoped rules,
  `AuthMerging Off`/`And`/`Or`, `AllowMethods`, and legacy `Satisfy All`/`Any`
  combining host access with authentication) with fail-closed handling of
  unsupported providers. Nested `<Limit>` sections intersect their method
  sets, and `GET` limits also cover `HEAD`. Directory indexes and local
  `ErrorDocument` files are authorized and dispatched as internal subrequests,
  so they run normal CGI/FastCGI/static handlers and cannot bypass `Require`,
  `AllowMethods` or request-conditional rules.
- Per-directory `.htaccess` overrides with category-specific `AllowOverride`
  (`All`/`None`, `AuthConfig`, `FileInfo`, `Indexes`, `Limit`, `Options`, and
  Apache 2.4 `Options=ExecCGI,Includes,...` forms) for access/auth rules,
  `Options`, `DirectoryIndex`, `ErrorDocument`, MIME/handlers, `Header`
  (`set`/`add`/`unset` and `always`/`onsuccess`), `Redirect`, and rewrite
  rules. Unknown directives, disallowed categories and unsupported sections
  return `500` rather than silently ignoring a possible access rule. Every
  recognized directive has an explicit effectful, inert or rejected
  disposition and an `AllowOverride` category in the authoritative registry;
  an exhaustive test matrix checks all of them.
  `<IfModule>` covers every module whose directives the server implements, so
  wrapping auth, rewrite, IP, CGI or autoindex rules in a module block cannot
  silently disable them. Unknown-only `AllowOverride` values are rejected at
  startup.
- A fail-closed `mod_rewrite` implementation in server/vhost/`<Directory>`
  and `.htaccess` contexts: `RewriteEngine`, `RewriteBase`,
  `RewriteOptions Inherit`, `RewriteCond` (regex, `=`, `!=`, `<`, `>`,
  `-f`, `-d`, `-s`, `-l`, `NC`, `OR`, and `expr`), `RewriteMap`
  (`txt`, `rnd`, `prg`, `int`), and `RewriteRule` with the common flag set
  (`L`, `END`, `R`, `P`, `F`, `G`, `C`, `S`, `N`, `QSA`, `QSD`, `QSL`,
  `B`, `BCTLS`, `BNE`, `BNP`, `CO`, `E`, `H`, `T`, `NE`, `PT`,
  `UnsafeAllow3F`, `UnsafePrefixStat`), including backreferences, common
  `%{...}` variables and loop protection. Internal rewrites reauthorize the
  original URL with the original request context and accumulated rewrite
  effects, retain its `Options`/`AllowOverride`/header policy, and authorize
  the final target as a conjunction with the rewritten URL scope. A rewrite
  cannot launder a protected upload into an executable directory.
  `UnsafePrefixStat` is accepted for
  compatibility but never weakens the document/alias containment base. `dbm`
  maps and exact `DPI` path-info handling remain unsupported; malformed
  patterns are rejected rather than approximated.
- HTTP Basic authentication (`AuthType Basic`, `AuthName`, `AuthUserFile`,
  `AuthGroupFile`, `Require valid-user`, `Require user` and `Require group`)
  with Apache-compatible `$apr1$`, `$1$`, bcrypt, `{SHA}` and `{SSHA}`
  htpasswd hashes. Password/group files are opened nonblocking through the
  no-symlink resolver, must be bounded strict UTF-8 regular files, and are
  accepted only while the pathname still names the inode that was read. By
  default their parent chain and file must be outside the service identity's
  mutation authority; deployments that intentionally update them as the
  service account must opt in with `HttpdRsCapability MutableAuthFiles On`.
  Each `AuthUserFile` must use one uniform hash scheme, work factor, and salt
  shape; malformed, duplicate, or mixed-profile files fail closed. Unknown
  users execute one cached dummy verification of that same profile, avoiding
  username-dependent password-work timing without adding another hash to
  successful requests.
  SHA/SSHA and MD5-crypt outputs are compared in constant time; bcrypt uses
  its verifier. Plaintext and unknown hash formats fail closed.
- TLS 1.2/1.3 via Rustls with `SSLEngine`, certificate chains, SNI virtual-host
  certificate selection, ALPN and `-t` certificate validation on startup.
  `Protocols http/1.1` disables HTTP/2 at the ALPN boundary; TLS virtual hosts
  sharing one listener must use the same `Protocols` policy because ALPN is
  negotiated before the HTTP host is known. Unsupported values, including
  the unimplemented cleartext `h2c`, fail configuration loading. An `h2`-only
  listener closes clients that omit ALPN instead of falling back to HTTP/1.1.
  The completed handshake's SNI-selected certificate policy and verified
  client identity are immutable connection state: HTTP/1 keep-alive and HTTP/2
  coalescing receive 421 if a later authority selects an incompatible TLS
  vhost. TLS and HTTP use the same first-match `ServerAlias` pattern semantics,
  and wildcard listeners choose a prevalidated TLS generation from the
  accepted socket's destination address before starting the handshake.
  A root-started daemon retains a minimal pre-thread TLS file broker whose
  numeric allowlist is fixed by the startup configuration, so SIGHUP can
  rotate root-only keys without restoring arbitrary root pathname access.
  Certbot's standard root-owned `live/<name>/*.pem` final symlinks into its
  root-owned `archive/<name>` tree are supported; parent or chained symlinks
  remain forbidden.
  The broker closes every unrelated descriptor and standard stream, disables
  dumps and privilege acquisition, installs tight core/file/descriptor/CPU/
  address-space limits, and runs under a read-only seccomp syscall allowlist.
  The parent accepts it only after a readiness handshake proves those controls
  are active; an incomplete descriptor sweep or hardening step aborts startup.
- HTTP/2 over TLS (ALPN `h2`, enabled by the default
  `Protocols h2 http/1.1`) with bounded header/stream limits, Apache
  request/body limits, content-length validation, CGI POST, ranges and HEAD.
  Request bodies retain at most a 64 KiB prefix per stream and then use the
  same process-wide spool budget as HTTP/1. Cleartext h2c is not implemented.
- CGI/1.1 executed directly (never through a shell) from a pre-created,
  privilege-dropped worker pool, with a minimal environment,
  `PR_SET_NO_NEW_PRIVS`, rlimits, a new session, a watchdog and bounded output.
  Pool absence or saturation returns `503`; it never downgrades to a spawn from
  the multithreaded daemon. `PATH_INFO` is split against the actual script and
  policy is re-evaluated for that script before execution. Every child-side
  descriptor is close-on-exec except stdio and the inode-bound script; the
  worker control socket cannot reach a script. Request bodies above the spool
  threshold stay on disk through the CGI worker instead of being buffered in
  full. TLS requests set
  `REQUEST_SCHEME=https` and `HTTPS=on`, and authenticated requests export
  `REMOTE_USER`/`AUTH_TYPE`, for both CGI and FastCGI. The selected FastCGI
  target is authoritative for `SCRIPT_FILENAME`, `SCRIPT_NAME`, `PATH_INFO`
  and `PATH_TRANSLATED`; stale base-request values are removed before sending.
- gzip and Brotli response compression with `AddOutputFilterByType`,
  `SetOutputFilter`, `AddOutputFilter`, compression levels, `Vary`,
  encoding-aware ETags, range bypass and `.htaccess` filter support.
- Native FastCGI for PHP-FPM and compatible responders via `ProxyPassMatch`
  and `SetHandler "proxy:fcgi://..."`, over Unix or TCP sockets.
- HTTP/1.1 reverse proxying with `ProxyPass`/`ProxyPassReverse`, including
  prefix and regex routes, `<Proxy>`/`<ProxyMatch>` authorization, request/
  response header forwarding, chunked
  upstream bodies and `Location` rewriting, HTTPS upstreams with system or
  `SSLProxyCACertificateFile` roots, `balancer://` round-robin backends with
  active `hcmethod`/`hcuri` health checks, sticky sessions, `failonstatus`
  retries, same-request member failover and reusable upstream connections,
  and WebSocket tunneling over TCP/TLS (WSS on either side). Prefix and regex
  routes share one configuration-ordered route table, and `<Proxy>` sections
  match both the configured `balancer://` identity and the concrete member;
  failover re-authorizes the next member and atomically replaces the
  grant/resource binding instead of reusing the first member's grant. A
  request is retried after an ambiguous send or `failonstatus` response only
  for an idempotent method; connection failures before a send may still move
  any method to another member. Proxy DNS uses a bounded worker queue and one
  absolute connect deadline. The first bounded DNS answer for a backend is an
  immutable transport identity shared by ordinary proxy requests, health
  checks, WebSockets, TCP FastCGI and OCSP for that configuration generation;
  a reload is required to admit a changed address set. Every connected peer is
  checked against the selected address, while HTTPS/WSS additionally verifies
  the configured DNS name. Custom CA bundles are parsed once per policy
  generation.
- TLS client-certificate authentication (`SSLVerifyClient`,
  `SSLCACertificateFile`) with bounded PEM CRL enforcement through
  `SSLCARevocationFile` and `SSLCARevocationCheck leaf|chain`, and OCSP stapling with AIA or
  `SSLStaplingForceURL` responders, startup warm-start persistence and
  validity-driven refresh. An expiring staple is refreshed before its
  `nextUpdate` boundary and is removed from the live certificate generation
  if no fresh authenticated response is available. Full and
  resumed handshakes retain the same verified peer identity; the bounded
  session store expires after `SSLSessionCacheTimeout` (300 seconds by
  default). Unverified `optional_no_ca` semantics are rejected.
- `mod_remoteip` client-address rewriting for trusted proxy headers.
- `mod_expires` (`ExpiresActive`, `ExpiresDefault`, `ExpiresByType`),
  `SetEnv`/`SetEnvIf`/`PassEnv`/`UnsetEnv`, `Require env`, and a basic
  `/server-status` endpoint.
- `mod_rewrite` covers conditions with regex/comparisons/file tests and
  `RewriteCond expr`, `RewriteOptions Inherit`, `RewriteBase`, server and
  per-directory rules, `RewriteMap` (`txt`, `rnd`, `prg` and `int`), query
  string controls (`QSA`, `QSD`, `QSL`, `UnsafeAllow3F`), escaping (`B`,
  `BCTLS`, `BNE`, `BNP`, `NE`), chaining/skips/restarts (`C`, `S`, `N`,
  `END`), `E`/`CO`/`H`/`T` response effects, `Vary` for header conditions,
  proxy rewrites (`P`), and `UnsafePrefixStat`.
- `mod_cache`/`mod_cache_disk` subset: `CacheEnable`/`CacheDisable` in
  server/vhost/directory scopes, `CacheRoot`, expiration and size limits,
  `CacheMaxDiskSize` (total on-disk quota with oldest-entry eviction and
  expiry cleanup), `CacheMaxMemorySize` (independent resident-byte quota;
  zero disables the memory tier and large bodies remain disk-only),
  `CacheIgnoreCacheControl`, `CacheIgnoreNoLastMod`,
  `CacheStorePrivate`, `CacheStoreNoStore`, `CacheIgnoreQueryString` (dynamic
  query-driven CGI/FastCGI/proxy responses bypass the shared cache), `CacheHeader`, `Age`,
  conditional hits, disk warm-start metadata and invalidation on unsafe
  methods. Keys bind the listener/port, vhost, scheme, canonical URL
  (including its trailing slash), query and resolved filesystem/alias target,
  with CGI `PATH_INFO` keys bound to the script actually executed; entries
  also carry a configuration generation that a reload advances. The policy
  fingerprint covers every `Scope` policy slice and all request headers, with
  a matrix test over every policy field and key dimension. Every hit re-runs
  authorization against that mapped target. Multiple `Vary` field lines are
  combined, disk entries are rechecked against their variant, and
  Authorization-, Proxy-Authorization-, Cookie-, body-framing- or request
  `no-store`-bearing requests never enter the shared cache. Request `max-age`
  and `min-fresh` can only narrow an entry's origin freshness window.
- Apache expression evaluation for `Require expr`, `<If>`, `<ElseIf>`,
  `<Else>` and `<IfFile>`: comparisons, boolean logic, string concatenation,
  regex captures, request headers/environment variables, file tests,
  IP/glob matching and the common string/hash/base64 functions. Request-time
  `file()` reads require a regular confined descriptor and are capped at 64 KiB.
- Keep-alive, pipelining, strict HTTP/1.1 parsing, request-smuggling and
  obs-fold rejection, `Content-Length`/`Transfer-Encoding` conflict rejection.
  Request-line and header parsing plus body framing are Verus-verified.
  `RequestReadTimeout` header/body deadlines and minimum-rate enforcement, configurable
  `MaxRequestWorkers`/`ListenBacklog`, graceful `SIGHUP` reload with listener
  reuse, `SIGUSR1` log reopen, `-k graceful`/`graceful-stop` with connection
  draining, pidfd-based control actions bound to the daemon's boot/start/exe
  identity, exact inherited-descriptor closure, pre-thread daemonization,
  privileged helper creation before permanent uid/gid drop, background-worker
  activation only after that drop, transactional reload preparation for
  logs, TLS and background workers, reload cache isolation, retained
  root-ownership/parent trust for every administrative input, and rejection
  of reload-only changes to process identity, listeners, pid file, server root
  or listen backlog. Hard absolute body deadlines and
  resource-accounted streaming for known-length dynamic uploads above 1 MiB;
  a bounded four-chunk channel propagates backend backpressure to HTTP/1 and
  HTTP/2 clients. Unknown-length/chunked bodies retain the bounded spool path.
- Bounded-memory proxy and FastCGI traffic: large fixed-length upstream
  bodies stream through `Body::Stream`, chunked/EOF proxy responses spill to
  an unlinked file above 256 KiB, large FastCGI stdout is spooled, and large
  known-length request bodies stream to Proxy/CGI/FastCGI sinks. Proxy responses are capped at
  64 MiB and local CGI output at 8 MiB. Request and proxy chunk sizes, trailer
  counts/bytes, proxy head sizes and CGI/FastCGI output are explicitly bounded.
  Chunk framing has an independent 65,536-chunk/1 MiB overhead budget, so a
  tiny-chunk flood cannot evade a decoded-body byte limit. Reverse-proxy and
  WebSocket paths containing semicolon path parameters fail closed rather
  than authorizing one path identity and forwarding another to a servlet-style
  backend.
- Process-wide overload control: at most 256 HTTP/2 streams (64 per source),
  64 WebSocket tunnels (8 per effective client), and a bounded asynchronous
  pre-request pool (8 sockets per transport source, or 32 for a configured
  proxy). HTTP/1 sockets do not receive a blocking worker until their first
  complete, valid request head identifies the effective client; workers are
  then limited to 32 per effective source (or half of a smaller
  `MaxRequestWorkers` budget). HTTP/1 connections run on a reusable blocking
  pool, and `MaxRequestWorkers`/`ServerLimit` are rejected above the 512-worker
  implementation ceiling. Every keep-alive request body enters the slow-body
  reserve, which may occupy at most a quarter of the worker pool; keep-alive is shed before the last quarter is
  consumed. Request workers are released before lazy body socket waits and
  before the asynchronous output pump. Routing and authorization produce typed
  Proxy/FastCGI/CGI handler IR before backend I/O; backend waits and WebSocket
  tunnels then run under their own bounded leases without retaining request
  workers. Large known-length uploads use a resource-accounted bounded channel.
  Plain HTTP file output uses nonblocking `sendfile(2)` in 256 KiB fairness
  quanta, while TLS and unsupported filesystems use short 64 KiB read permits.
  Listener acceptance rotates, pauses once saturated workers have an
  admitted connection queued, and is capped per ready-listener batch,
  so a busy listener cannot starve another. These limits sit alongside 128 MiB
  each of retained request and response bytes, 32 blocking response reads,
  and 32 concurrent CPU-heavy regex/hash/compression/access-file operations.
  TLS handshakes are capped at 64 concurrent (4 per source), 128 per second
  process-wide and 64 per source per second. `RewriteMap prg:` is limited to
  eight calls per request, eight concurrent helpers and 64 starts per second;
  each helper gets an empty environment, one sealed program descriptor, tight
  rlimits and an absolute nonblocking output deadline.
  Access/error lines stop at 128 KiB and log/stderr writers do not queue the
  worker population. Disk-cache administrative walks stop after depth 32 or
  32,768 records and invalidate fail closed by generation. DNS
  authorization and outbound proxy resolution use bounded worker queues and
  deadlines; WebSocket tunnels have an independent idle/write deadline.
  Autoindex scans at most 4096 directory records and renders at most 4 MiB. Request
  policy, access-file, password-file and disk-cache metadata indexes are
  byte/count bounded and evict individual entries rather than clearing or
  rescanning an attacker-amplifiable working set. Per-client identities use
  exact IPv4 addresses and verified IPv6 `/64` keys; HTTP/1 workers, HTTP/2
  streams and WebSocket quotas use the validated `RemoteIPHeader` identity.
  A trusted transport proxy gets a slightly larger pre-header allowance but
  cannot bypass downstream per-client worker accounting. HTTP/1 response writes,
  including zero-copy static-file sends, use a non-blocking stall deadline
  derived from `Timeout` and renew it only after byte progress; a client that
  stops reading cannot pin a connection worker, while a progressing download
  is not truncated merely because its total duration exceeds `Timeout`.
  HTTP/2 additionally requires the client preface, initial SETTINGS, and first
  request head before the request-header deadline, and rate-bounds SETTINGS,
  PING, PRIORITY and every WINDOW_UPDATE with a refillable per-connection
  control-frame budget; the useful-update class has a 4,096-frame burst and
  refills at 2,048 frames per second.
- Privileged startup refuses uid/gid 0 and fails when an unprivileged launch
  does not already match the configured identity. Configuration/includes,
  TLS material, environment files, `TypesConfig`, and file-backed rewrite maps
  are regular administrative inputs with per-file bounds and stable descriptor
  snapshots; their parent chains cannot be writable by the service identity,
  including empty optional-include directories. Administrative inputs do not
  follow symlinks except for the narrowly checked Certbot final-link shape
  described above. Aggregate configuration text is capped at 16 MiB.
- Unsupported security-sensitive directives (`SSLRequire*`,
  `SecRuleEngine On`) fail closed even in
  compatibility mode rather than silently weakening access or TLS policy.
  Unsupported handlers (`mod_php`, `mod_perl`, `mod_wsgi`, ...) and output
  filters (SSI, unknown filters) return `500` instead of serving source.
- Main and access-file configuration are compiled through a sealed semantic
  IR. Section expressions/matchers/method sets and fallible directive values
  (authorization, rewrites, routes, listeners, expiry, environment and TLS)
  are validated or precompiled before any policy object is mutated; an
  inactive or disallowed wrapper cannot hide malformed policy syntax.
- Access/error logging with Apache `LogFormat`, daemonization, pid files,
  privilege dropping, graceful reload/shutdown and log reopening.
- Defence in depth: URI percent-decoding, path canonicalization, and the
  HTTP/1.1 request-head parser/framer are Verus-verified; the server still
  cross-checks the canonical-path invariant at runtime, and all file opens go
  through `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)`, optionally
  `RESOLVE_NO_SYMLINKS`. Linux `openat2` support is mandatory: configuration
  testing and startup fail closed if the syscall or required resolution flags
  are unavailable. A readable `/proc/self/fd` is also mandatory so policy can
  be re-evaluated against an opened symlink's resolved target; there is no
  canonicalize-then-open or lexical-path fallback.

Not yet implemented: online OCSP checking for client certificates (CRLs are
supported), OCSP responder error-cache timeout tuning, rare
expression forms such as `LogMessage` interpolation, `RewriteMap dbm`, exact
`[DPI]` path-info discarding in per-directory contexts, some `[NE]`/`[PT]`
corner cases, `mod_cache_socache`/`mod_file_cache`, Digest/LDAP
authentication, h2c, and the long tail of Apache modules.
Unhandled directives are configuration errors in every mode, including
directives that are recognized as Apache directives but not implemented.
`--strict-config` remains accepted for deployment compatibility, but normal
mode no longer converts an unknown or unimplemented directive into a no-op.
Recognized directives are also rejected when httpd-rs cannot preserve their
Apache scope: a per-directory or per-vhost value is never written into a
process-global field, virtual-host balancers are not exposed globally, and
mapping directives are refused in contexts where Apache refuses them.
Security-sensitive unimplemented directives
(for example `Action`, `ProxyBlock`, `RequestHeader`, `SetEnvIfExpr`,
`BrowserIPMatch`, `AcceptPathInfo`, `RLimit*`, `TransferLog`, `ScriptLog*`,
non-file `AuthBasicProvider` values and filter-provider/input-filter
directives) fail closed at startup, and unimplemented `.htaccess` directives
fail closed with a `500`. Warnings are reserved for explicitly handled forms
whose httpd-rs behavior is equivalent or deliberately stricter, never for a
discarded policy. `[DPI]` and `[NS]` rewrite flags fail at configuration load
until their path-info and internal-subrequest semantics are implemented.

## Build

```sh
export PATH="$HOME/.cargo/bin:$HOME/verus-bin:$PATH"
cargo build --release -p httpd-rs
```

The binary is `target/release/httpd-rs`.

### Prebuilt Linux artifacts

Each push to `main`, version tag, and manual `linux-artifacts` workflow run
uploads five x86-64 artifacts:

- the compiled `httpd-rs` binary;
- a portable tar archive;
- a Debian/Ubuntu `.deb` package;
- an RPM-family `.rpm` package; and
- `SHA256SUMS` covering all four payloads.

The release target is `x86_64-unknown-linux-musl`, producing a static PIE with
no glibc version floor. httpd-rs remains Linux-specific and requires Linux 5.9
or newer for its fail-closed `openat2` path-resolution and `close_range`
descriptor-isolation boundaries.

The packages install the server as `/usr/sbin/httpd-rs` and service as
`httpd-rs.service`, but deliberately leave the existing Apache configuration
and daemon state untouched. `httpd-rsctl` selects `/etc/apache2/apache2.conf`
on Debian-family systems or `/etc/httpd/conf/httpd.conf` on RPM-family
systems. To validate the existing configuration and interactively switch the
active daemon:

```sh
sudo httpd-rs-switch
```

The helper shows which Apache service it found and asks before disabling it.
If httpd-rs fails to start, it restores Apache's previous active/enabled state.
Set `HTTPD_RS_CONFDIR` and `HTTPD_RS_CONFIG` to select a nonstandard Apache
layout. The packaged wrapper materializes enabled-config symlinks and derives
any capability opt-ins already implied by the Apache configuration into a
root-controlled runtime snapshot; it never edits the source configuration.
Set `HTTPD_RS_AUTO_CAPABILITIES=0` to retain the raw binary's explicit opt-in
requirement. See `packaging/README.md` for the installed file layout.

### Certbot

httpd-rs reads the usual `SSLCertificateFile` and `SSLCertificateKeyFile`
paths, including Certbot's `/etc/letsencrypt/live/...` links. A graceful reload
atomically validates and adopts renewed certificate/key pairs while existing
connections finish on the old TLS generation:

```sh
sudo systemctl reload httpd-rs.service
```

The packaged `httpd-rs-switch` detects existing Certbot lineages, installs a
conditional deploy hook, and routes Apache-plugin lineages through a dedicated
control shim without replacing Apache's `apache2ctl`. It records the shim in
Certbot's global configuration, so ordinary Apache-plugin commands work:

```sh
sudo certbot --apache -d example.com
```

The shim retains Apache's read-only configuration discovery, requires both
Apache and httpd-rs syntax checks while httpd-rs is active, and maps Certbot's
reload request to a root-started `httpd-rs.service` restart so a newly added
port 443 listener can bind. Webroot and DNS authenticators remain supported.
If `httpd-rs-switch` has not been run, pass
`--apache-ctl /usr/lib/httpd-rs/certbot-apachectl` explicitly.

For first issuance, start with an HTTP-only virtual host and let
`certbot --apache` add the TLS configuration after the certificate exists.
Like Apache, httpd-rs rejects an enabled TLS virtual host whose certificate is
missing. If that virtual host already points into a nonexistent
`/etc/letsencrypt/live/` lineage, httpd-rs's configuration error prints the
literal `certbot certonly --standalone` command needed to create it before
retrying `sudo httpd-rsctl configtest`; the standalone authenticator requires
port 80 to be free.

## Verify

The security kernels live in `crates/verified` and are checked with Verus:

```sh
cargo verus verify -p httpd-rs-verified
```

Current result: **842 verified functions, 0 errors** (percent-decoding,
URI path canonicalization, request-head parsing and body framing, header-value
sanitization, token validation, proxy request-line/header admission, byte-range
arithmetic, the mmap/CGI protocol bounds, the lazy request-body/dispatch/output
lifecycle, typed DirectoryIndex/ErrorDocument internal-request projection,
HTTP/2 method/head/body admission,
the stream/reset budget model, the stream-ID admission/lifecycle model and the
idempotent early-reset purge model, and the TLS listener client-certificate
policy identity, vhost-transition, SNI/authority and required-client-identity
admission decisions, the append-only container/list merge model, the rewrite
target
classification/internal-join/same-host authority model, component-aware
filesystem containment for alias/rewrite/FastCGI targets, the expression
truthiness/comparison/glob/condition-chain model, the regex dialect admission
guard, directive disposition, access-layer slot translation, config front-end
quote/escape/tag state machines, bounded argument schemas, line-kind IR and
sealed section-context transitions, rewrite backreference encoding
and filesystem-target admission, and the configuration access-plan,
authorization-merge, Options-merge and `.htaccess` rule-classification kernels
used by the dispatcher, plus route-prefix matching, handler-extension/removal
selection and authorization-configuration admission, the pass-6 ancestor
access-walk, URL-selected
alias mapping-root, `DirectoryIndex` cache-target/query-isolation predicates,
and the MultiViews public/selected-URL/resolved-inode authorization meet plus
selected cache binding, and the pass-10 I61 Options/handler/`AllowOverride` meet and
rewrite-scope-retention kernels, plus pass-12 admission proofs for exact
`Require method`/`Require env` operands, HTTP/2 pseudo-header identity, CGI
status/header framing, first-existing `AccessFileName`, `FileETag None`,
bounded and descriptor-snapshotted `RewriteMap prg` execution, exact disk-cache keys, targeted cache
invalidation and `[BNE]` escaping, plus the P13 lexical Files-scope handler
binding proof, the executable `AllowOverride`/`AllowOverrideList`/`Nonfatal`
admission gate, and the P14 per-depth Files phase plan, proxy-template dynamic
marker guard, full rewrite-chain resume and duplicate-header merge selection,
plus the executable rewrite expansion-token/match-action/program-counter state
machine and recursive configuration kind/phase/deferred-slot/order decisions).
The latest kernels also model the universal transform capability carried from
authorization to each protected sink, prove its inode/backend/cache-policy
requirements, and prove that construction of a typed authorized plan retains
one public URL, selected URL, lexical/resolved filesystem pair and exact
grant. Production static, directory, CGI, FastCGI, proxy, WebSocket and cache
entry points consume that move-only plan/outcome artifact; local-file sinks
also compare the descriptor's device/inode at the boundary. The kernels
validate descriptor snapshots used for access-file parsing, and
pin P15's fail-closed expression result, Apache-compatible RemoteIP proxy-class
transition, and dual lexical/canonical FastCGI script identity. P16 adds
executable proofs that directive regexes are byte-oriented with default and
inline Unicode classes disabled, header policy input preserves every raw byte,
normalized path bytes require valid UTF-8 before becoming a routing/ACL
identity, and access-file-origin environment entries can never be admitted to
the FastCGI parameter environment or detached from their origin during scope
merges. The post-P16 hardening adds a verified textual-identity gate for
configuration and filesystem policy paths; request plans, config files,
access files, includes and MIME maps reject invalid UTF-8 instead of applying
replacement-character policy.
P17 and P18 add executable gates for resolved-file FastCGI targets and
access-file section commands: the backend wire path must stay bound to the
lexical request mapping while the canonical target remains independently
contained and authorized, and an allowed child directive cannot admit an
unlisted section wrapper.
The cross-server CVE follow-up adds verified authority host/port admission,
chunk-size/extension/trailer grammar and framing budgets, a mandatory proxy
path-representation capability, strict upstream response status/header gates,
HTTP/2 connection-field and control-token transitions, and weak-ETag plus
conditional-precedence kernels. WebSocket 101 negotiation additionally
consumes a verified selection gate: syntax must be valid, the selected
protocol or extension must have been offered, and the selection must not be
duplicated. These executable gates are consumed directly by the HTTP/1,
HTTP/2, proxy and cache paths.

### Default-off compatibility capabilities

httpd-rs does not inherit Apache's ambient legacy surface. The following
features are individually disabled unless the global server configuration
opts in with `HttpdRsCapability <name> On`:

| Capability | Gated surface |
| --- | --- |
| `Trace` | `TraceEnable On`/`Extended` and the TRACE reflection handler |
| `AccessFiles` | any effective `AllowOverride`/`AllowOverrideList` access-file walk |
| `LegacyAuthz` | `Order`, `Allow`, `Deny`, and `Satisfy`, including access files |
| `MutableAuthFiles` | password/group databases that the service identity can replace or modify |
| `AutoIndex` | generated directory listings from `Options Indexes` |
| `Cgi` | `ScriptAlias`, `cgi-script`, and `Options ExecCGI` execution |
| `FastCgi` | FastCGI `ProxyPassMatch`/`ProxyPass` and handler execution |
| `UnstableFastCgiPaths` | pathname-only FastCGI handoff without a stable-path policy |
| `RewriteProgram` | external `RewriteMap prg` helpers |
| `ServerStatus` | the generated `server-status` handler |
| `AbsoluteRequestTarget` | HTTP/1 absolute-form request targets |
| `RequestTrailers` | non-empty HTTP/1 chunked or HTTP/2 request trailers |

Declarations are process-global, order independent, and final-state checked;
they are rejected in virtual hosts, directory/location sections, and access
files. Enabling `AccessFiles` therefore cannot let an attacker-controlled
`.htaccess` enable CGI, autoindex, legacy authorization, FastCGI, status, or
another global capability. Effectful directives missing their opt-in make
configuration loading fail, and execution/generation sinks check the same
gate again.

For example, an application that only needs CGI declares only:

```apache
HttpdRsCapability Cgi On
```

`httpd-rs --audit-capabilities -f /path/to/httpd.conf` parses an existing main
configuration without auto-enabling anything and prints the declarations it
would require. Access-file contents are intentionally checked only when read,
so they remain unable to change the process capability set. A configuration
loaded in audit mode is also marked non-runnable and the dispatcher refuses
it, preventing the reporting API from becoming a capability bypass.

HTTP/0.9, unknown/lenient methods, multipart byte ranges, SSI, MultiViews,
UserDir, DAV, forward proxying, external filters, LDAP/Digest/DBM auth,
`server-info`, and `balancer-manager` are not implemented and remain
unconditionally unavailable. They do not receive opt-in switches that imply
unsupported behavior is safe.

FastCGI is default-safe at the external-process handoff. Every configured
backend normally needs an exact global stable-path policy:

```apache
# endpoint, PHP worker uid, Unix-socket owner uid, then trusted tree owners
HttpdRsFastCGIStablePath On unix:/run/php/php8.4-fpm.sock 33 0 0 1001
```

The directive is repeatable, once per backend. A FastCGI request whose exact
Unix socket is not registered is denied. The socket is checked before and
after `connect()` for type, owner and inode
stability independently of the configured PHP worker UID. On Linux, the
connected listener's kernel `SO_PEERCRED` uid must be either the configured
backend uid, the configured endpoint-owner uid (for a rootless pool manager),
or uid 0 (the usual privileged PHP-FPM master); socket pathname ownership is
not substituted for this independent kernel credential. TCP is rejected in
strict mode because a loopback address does not authenticate the process that
owns it; use a protected Unix socket for the verified backend-identity
boundary.

Both the lexical `SCRIPT_FILENAME` and the canonical authorized script path
are walked immediately before parameters are sent. Every component must have
a listed owner and no group/other write bit; a non-symlink component cannot be
owned by the backend, because its owner could restore write permission with
`chmod`. POSIX ACLs are rejected rather than assuming the mode bits describe
all writers. Symlink ownership and both sides of the mapping are checked. Root
backends, relative paths and malformed identities are rejected.

Deployments that cannot satisfy this policy—for example, a TCP or unusual
chrooted backend—must separately and explicitly accept the external pathname
race:

```apache
HttpdRsCapability UnstableFastCgiPaths On
```

`HttpdRsFastCGIStablePath Off` or an absent policy is otherwise rejected when
FastCGI is configured, and the runtime sink checks the same condition again.
The unsafe capability restores only the pathname handoff; the deployment must
then keep the complete script tree immutable to the backend and every
less-trusted process for the whole request lifetime.

Aggregate dynamic-I/O limits are global directives and remain shared across a
graceful reload:

```apache
HttpdRsMaxSpoolBytes 1073741824
HttpdRsMaxSpoolFiles 128
HttpdRsMaxDynamicRequests 64
HttpdRsMaxFastCGIOutput 67108864
```

The RAII budget covers request-body spool files, FastCGI response spools and
the CGI worker's duplicate body spool. CGI and FastCGI share the dynamic
request ceiling; exhaustion returns `503` and every error path releases its
reservation. FastCGI output is now bounded to 64 MiB per request by default.

Because FastCGI transports a pathname rather than an open descriptor, the
verified deployment boundary requires FastCGI scripts and every ancestor
directory to be non-writable by the backend and all less-trusted principals
for the complete request lifetime. A read-only release tree satisfies this;
writable uploads must live outside all FastCGI handler mappings.

Function count is not the progress metric. The verification ledger tracks
security obligations and proof debt:

```sh
python3 tests/verification_status.py
python3 tests/verification_status.py --run-verus   # include the Verus gate
```

Current ledger: **59.0% weighted obligations**, **5/6 proof debt**,
**11/11 grant-required sinks**, **11/11 path-target-bound sinks**, **6/11
inode-bound sinks**, **3/11 backend-target-bound sinks**, **3/11
policy-key-bound sinks**, **0 partially bound sinks**, **0 unexplained replay
failures**, **109 adversarial replay cases** covering the findings classes,
and **856 Verus functions with 0 errors** (including the I3 fast-path
prefilter, I14 first-match, the pass-4 I35–I42 alias/limit/CGI/spool/cache/
expression dispositions, the pass-5 I43–I46 RequireNone/vhost/canonical-peer
kernels, the pass-6 I47–I49 access-walk/alias-root/cache-target kernels, the
pass-7 I50–I53 URL-mounted rewrite-base/cache-key-byte/ErrorDocument/
dynamic-handler kernels, the pass-8 I57/I58 canonical-REQUEST_URI and
access-file rewrite-subject kernels, the pass-9 I60 explicit-target
access-layer binding kernels, the pass-10 I61 resolved-target/rewrite
scope-conjunction kernels (`options_conjoin`, `handler_conjoin_admit`,
`override_categories_conjoin`, `rewrite_scope_retained_admit`), the pass-11
F61–F69 kernels (the class-capable `fnmatch_match` glob specification,
`expr_var_known`, `set_handler_precedence_admit`/`set_handler_conjoin_admit`,
`cgi_exec_admit`, `handler_identity_lexical_admit`), the pass-12 configuration,
rewrite, HTTP/2, CGI, access-file, ETag and targeted-invalidation admission
kernels, the pass-13 `handler_scope_lexical_admit` scope-force obligation,
and the strengthened cache-key injectivity, lookup, store-admission,
freshness, disk-accounting and SHA-256 policy-binding proofs for I51/I54).

The ledger lives in `docs/verification-status.json`. It records:

- weighted progress on the seventy-two proof obligations,
- named unverified security components,
- sinks that need stronger resource binding,
- explicit assumptions and unmodeled directive classes,
- the adversarial replay-failure budget.

The gate fails if proof debt exceeds its explicit budget, the weighted
obligation score falls below its floor, the inode-bound sink count regresses,
an `assume`/`external_body` proof escape appears, or a body/tunnel sink stops
requiring a grant. Raising a budget is a deliberate, reviewable change.

## Test

```sh
cargo test --workspace          # Rust unit tests
python3 tests/conformance.py    # 165 local httpd-rs conformance tests
python3 tests/conformance.py --differential  # also compare with Apache
python3 tests/adversarial_regressions.py  # F23-P36 end-to-end replay suite
```

The conformance suite starts a real `httpd-rs` and covers HTTP/1.1, HTTPS,
HTTP/2, CGI, conditional requests, ranges, access control and Basic auth. Use
`--differential` when Apache is installed to start both servers and write
`tests/differential_report.md`, comparing status codes, selected headers and
bodies.  The `adversarial/`
folder holds the numbered findings write-ups (passes 3–18) and the pass-11,
pass-13 through pass-18 exploit harnesses (`adversarial/p11/exploit_p11.py`,
`adversarial/p13/exploit_p13.py`, `adversarial/p14/exploit_p14.py` and
`adversarial/p15/exploit_p15.py` through `adversarial/p18/exploit_p18.py`) with
their Apache-versus-httpd-rs case dossiers, so the exact exploit shapes are
documented rather than re-derived.

Security-sensitive configuration semantics are checked separately:

```sh
python3 tests/config_semantics.py  # 339 fixed differential cases
python3 tests/config_semantics.py --random 300 --seed 7  # deterministic randomized matrix
python3 tests/config_semantics.py --stateful 256 --stateful-seed 1818
python3 tests/vhost_semantics.py  # multi-vhost startup/reload differential matrix
python3 tests/config_validity.py  # context acceptance matrix (Apache -t vs httpd-rs -t)
python3 tests/config_grammar.py   # finite valid/invalid grammar matrix
tests/pre_adversarial.sh         # fail-closed full gate, including real PHP-FPM
```

Coverage-guided parser targets are in `fuzz/` and are compiled and smoke-run by
the pre-adversarial gate. Longer campaigns use cargo-fuzz:

```sh
cargo install cargo-fuzz
rustup toolchain install nightly-2026-10-29 --profile minimal --component llvm-tools-preview
tests/fuzz_smoke.sh                         # bounded run of every target
FUZZ_SECONDS_PER_TARGET=900 tests/fuzz_campaign.sh
tests/long_fuzz.sh --nightly latest --hours 12 --jobs 4 --coverage --strict-semantic
```

The 29 targets cover individual HTTP requests, fragmented/pipelined
connections, configuration tokenization and full compilation, `.htaccess`
walks, physical-line continuation refinement, rewrite expressions,
CGI/FastCGI/proxy responses, WebSocket negotiation,
raw HTTP/2 frames and structured multi-frame HTTP/2 state transitions, cache
metadata plus stateful publication/corruption/reload cleanup, TLS policy plus
handshake-identity/reload transitions, request identity and environment-phase
provenance, OCSP DER, the adversarial PCRE2
differential and PCRE2 resource-policy monotonicity, and stateful hierarchical
resource ownership. The whole-request target executes real proxy, FastCGI and
CGI handlers after both wire decoders, compares exact backend requests and
final responses, runs cache-eligible cases cold and warm, and covers local and
external ErrorDocument plus CGI/FastCGI/proxy DirectoryIndex orchestration.
Its cancellation projection aborts after routing but before sink admission and
requires that no proxy, FastCGI or CGI effect occurs and every lease is returned.
The multi-request target retains connection generation and mutable cache,
access-file and backend-health state across a bounded sequence. It requires H1
and H2 to agree when warm cache entries meet reload, in-flight outcomes cross
retirement, access files are atomically replaced between planning and
execution, balancer health changes, and old connections attempt new work.
The resource campaign mutates reserve/release, attribution, parent exhaustion,
slow-input/output handoffs, cross-ledger rejection and RAII teardown while
checking ledger conservation after every operation. The original PCRE2 fuzzer
implementation is retained with the P23 artifacts; the ordinary cargo-fuzz
entry point now extends it across compile metadata, all public matching APIs,
start offsets, engine tiers, CRLF, malformed UTF and
Unicode modes. An admitted-subset grammar makes unexpected compile rejection a
fuzz failure, while the resource target keeps production limits active. The P24
expression-parser crash and non-ASCII PCRE2 byte-boundary cases are permanent
seeds. The physical-line, expression and both PCRE2 targets receive 16,384
executions in the default smoke gate; the resource state machine receives
1,024. Nightly coverage
corpora are minimized and carried into the next run; dictionaries and committed
bootstrap seeds live beside the targets.

`tests/long_fuzz.sh` is the workstation campaign. Its default `full` profile
touches all 29 targets before repeating any target, then gives a second
weighted slot to the configuration/PCRE2, identity/reload, composed-request,
HTTP/2 and resource state machines. The narrower `adversarial` profile remains
available for focused follow-up. It imports committed
seeds by content hash into `.fuzz-long/`; `--nightly latest` additionally merges
the latest uploaded nightly corpora and artifacts, while `--import DIR` accepts
a manually downloaded artifact tree. It keeps coverage corpora, logs and crash
artifacts across interrupts and later runs without modifying the committed
corpus. Every target has a finite semantic census and generated seed matrix;
these retain declared wire forms, grammar families, identity/reload states,
request route/method pairs, state transitions, H2/resource/policy opcodes,
PCRE modes/flags and continuation classes even after structural minimization.
The initial and final JSON census reports corpus hashes, executions, edge/features,
RSS and missing semantic buckets; `--strict-semantic` makes a missing bucket a
failure. A closure check rejects drift between Cargo's fuzz binaries and the
smoke, sustained, workstation and nightly schedules. `--coverage` replays each
corpus under LLVM line/branch instrumentation
and stores text, profile and JSON reports under `.fuzz-long/coverage/`. The
`continuation` profile concentrates on configuration physical/logical-line
refinement; `--state` can place the persistent campaign on a larger disk.
Property tests, Loom interleaving exploration, deterministic
failure injection, Miri, sanitizers, mutation testing, protocol suites,
supply-chain checks and scheduled soak/performance jobs are described in
[`docs/quality.md`](docs/quality.md).

`config_grammar.py` enumerates the supported directive/context grammar and
checks that Apache and httpd-rs agree on acceptance and rejection.  It is the
finite executable counterpart of the “accept valid / reject invalid” proof
obligations.

`config_semantics.py` generates isolated combinations of `AllowOverride`
categories, `<Limit>`/`<LimitExcept>`, `Require` trees, `AuthMerging`,
`Satisfy`/legacy access, `<If>` chains, `Files`/`Directory` wildcards and
Directory/Files/Location ordering, then compares both servers. Its stateful
mode also drives balanced nested wrappers, mismatched closes, live-stack EOF,
duplicate `AllowOverride` ordering and all four `Nonfatal` behaviors. It caught
several fail-open ordering bugs during development, including conditional
sections being applied before a later grant, `<Location "/x/">` matching the
file `/x`, and access-file merges being ordered after `<Files>`.

`vhost_semantics.py` generates two-tenant configurations and checks the
server/vhost hierarchy independently for authorization sections, filesystem
and redirect maps, prefix/regex proxy routes, rewrite/MIME/error/index policy,
name/address selection, per-vhost error/access logging, includes, and graceful
reload. Apache is the oracle; the retained cases pin the module-specific
distinction between vhost-first Alias/Redirect tables and main-server-first
ProxyPass tables, plus `CustomLog` replacement rather than supplementation.

### Apache CVE triage

The complete NVD CPE `apache:http_server` set is triaged in
`docs/cve/apache2-cve-matrix.json`:

- **371 CVEs** assessed,
- **370** prevented in principle by construction, verified primitives or
  fail-closed rejection,
- **0** partially covered,
- **1** not covered by the formal specification.

The sole not-covered row is the external Rustls certificate parser
(`CVE-2004-0488`), which is an explicit trusted-dependency boundary.
The full matrix is `docs/cve/apache2-cve-matrix.json` (and `.csv`); the
summary and methodology are in `docs/cve/apache2-cve-matrix.md` and
`docs/cve/README.md`. The grouped strengthening plan for the 1 not-covered
row is in `docs/cve/not-covered-strengthening.md`. Regenerate or validate
with:

```sh
python3 tests/cve_matrix.py
python3 tests/cve_matrix.py --check
```

This is a static triage, not a claim that every CVE has a working PoC replay.

### Cross-server CVE root-cause audit

The NVD histories for nginx, IIS/HTTP.sys, lighttpd, HAProxy, Tomcat/Coyote,
Jetty, Squid, Varnish, Apache Traffic Server, LiteSpeed/OpenLiteSpeed and Envoy
are also compared per CVE against httpd-rs's actual feature boundary and
implementation:

- **1,047 distinct CVEs** across the eleven product families,
- **370** mapped to a concrete httpd-rs prevention,
- **54** rejected by an explicit fail-closed capability boundary,
- **580** tied to a feature or platform httpd-rs does not implement,
- **41** deliberately left partial pending an exact trigger/invariant, and
- **2** retained as NVD source-data conflicts with no prevention claim.

Together with the existing 371-row Apache HTTP Server ledger, this covers
**1,412 unique CVE IDs** across twelve server/proxy families (six IDs occur in
both source sets).

The complete machine-readable ledger is
`docs/cve/cross-server-cve-matrix.json` (and `.csv`); the high/critical open
set is in `docs/cve/cross-server-cve-matrix.md`. The normalized NVD snapshot,
including publication/modification dates, CVSS, vulnerable CPEs and advisory
links, is `docs/cve/cross-server-nvd.json`. Validate it with:

```sh
python3 tests/cross_server_cve_matrix.py --check
```

This audit directly produced independent chunk-framing work limits,
constant-time legacy password comparisons, an HTTP/2 control-frame token
bucket and fail-closed semicolon handling at reverse-proxy path boundaries.
`partial` is an open review item, not a safety claim.

For a specific request, the compiled policy can be inspected without starting
the server:

```sh
./target/release/httpd-rs -f /etc/apache2/apache2.conf --explain /private/file \
  --explain-method GET --explain-header 'X-Test: yes'
```

The output shows the selected vhost/docroot, `AllowOverride`, the override
walk gate, matching top-level rules, effective `Options`, `Require`/legacy
policy, auth settings, rewrite/cache state, and whether an access file was
read or skipped.  The reference model and proof obligations for formal
verification are in `docs/config-semantics.md`; the per-finding closure matrix
for the adversarial pass is in `docs/adversarial-closure.md`. The Apache
source-model, binary-differential and future extracted-model refinement process
is in `docs/apache-access-parity.md`.

Combined unit and end-to-end line coverage is measured against instrumented binaries:

```sh
tests/coverage.sh                         # full corpus plus CI ratchet
python3 tests/security_coverage.py --strict  # absolute 100% target
```

`security_coverage.py` reports executable production-line coverage before each
file's test module. Every listed server module retains a 100% target. The CI
`--check` mode is a monotone ratchet: for each module, covered lines may not
decrease and missed lines may not increase from the reviewed baseline.
`--strict` fails while any production line remains uncovered. The list includes
the CLI, cache, file serving, HTTP/2, logging, OCSP, proxying, rewrite execution
and aggregate resource accounting. `tests/coverage.sh` requires Apache and runs
the grammar, validity and fixed/random/stateful semantic differential corpora
before applying the ratchet; it never silently substitutes a partial corpus.
Delimiter-only lines and narrowly documented unreachable invariants, external
failure races and privileged-kernel failures are excluded from that metric.
The instrumented-only release build disables ThinLTO because Rust 1.99 emits
stale coverage hashes after ThinLTO rewriting. Raw profiles are paired with the
exact executable build ID before LCOV export, so release, unit, integration,
property, build-script and proc-macro symbols cannot contaminate one another.

Latest fail-closed floor: **29,460/32,026 executable server production lines
(91.99%)**. Asynchronous cancellation tests can cover an additional line or
two depending on which side of a deliberately exercised race completes first;
the per-module and aggregate baseline records the worst observed result.
The prior 20,020/20,548 snapshot predated roughly 11,500 executable lines of
configuration compilation, protocol and resource-accounting work and was not
being enforced by CI. The reviewed per-module debt is recorded in
`tests/security_coverage_baseline.json`; reducing it tightens the ratchet, while
new debt beyond that scheduling envelope fails the quality workflow. The
current instrumented suite is 691 Rust library tests, 8 CLI unit tests, 31 Rust
integration/property tests, 168 conformance tests and 333 fixed configuration
cases. The module-by-module reason for the remaining debt and the intended test
mechanism for each major module are tracked in `docs/coverage-debt.md`.
The separate Verus gate proves 856 functions with 0 errors; proof-only code is
measured by that gate rather than runtime line coverage.

Real-application integration lives under [`tests/deployments`](tests/deployments/README.md).
The fixed nightly profile deploys Hugo, Gitweb/smart Git CGI, WordPress with
PHP-FPM, and Grafana with a live WebSocket. The Sunday workflow runs the
canonical case for all thirteen applications. Manual runs reproducibly sample
112 application/topology combinations by recorded seed across thirteen
applications, including Gitea, Drupal, Jenkins, JupyterLab, MinIO, Nextcloud,
Wagtail, Bugzilla and Mastodon, or can explicitly request the full Cartesian
set.
Application containers use digest-pinned upstream images or staged builds from
pinned source, private networks, read-only roots and staging-only mounts; a
dedicated harness gate rejects any mount overlapping the source checkout.
Optional workloads compare the same application through Apache and httpd-rs
with alternating samples.

Known, deliberate divergences from Apache (reported by the differential run):

| Area | Apache | httpd-rs | Why |
|---|---|---|---|
| `POST` to a static file | `200` + file body | `405` with `Allow` | Safer; matches common server policy |
| `OPTIONS *` | omits `Allow` | sends `Allow` | RFC 9110 requires advertising methods |
| Unsatisfiable range | omits `Content-Range` | `Content-Range: bytes */N` | RFC 9110 requires it |
| `TraceEnable Off` response | empty `Allow` | populated `Allow` | RFC 9110 requires `Allow` on 405 |
| Proxy auth on `RewriteRule [P]` | not enforced on the rewrite-proxy path | enforced | Prevents bypassing `<Proxy>` authorization via `[P]` |
| Denied implicit MultiViews/CGI target | `403`, revealing candidate discovery | `404`, matching no candidate | Suppresses protected-target existence oracles |
| Unsupported handler/filter | may serve source if the module is absent | `500` | Fail closed instead of exposing source |
| Unimplemented security directive | may enforce a policy we do not implement | refuses to start | Fail closed instead of silently ignoring an access/auth/proxy/filter control |

Run the benchmark against real Apache (ports 8080/8081):

```sh
python3 bench/bench.py --quick   # 1s samples
python3 bench/bench.py           # 3s samples
```

`wrk` is used when available (HTTP/1.1, reliable keep-alive under load) with
`ab` as a fallback. Both servers use identical configurations and access logs
are written to `/dev/null` so the harness does not fill `/tmp`. The default
uses eight connections because `wrk` opens its cohort simultaneously from one
loopback client identity and httpd-rs deliberately limits each client to eight
pending connections. Higher concurrency measures connection-admission overload
rejection rather than successful static serving. Each round alternates which
server runs first so shared-host drift cannot systematically favor one side.
Results are appended to `bench/RESULTS.md`. Latest full run (2026-11-05, 3s
samples, median of three, eight connections, zero failed/non-2xx responses or
socket errors):

| scenario | Apache req/s | httpd-rs req/s | ratio |
|---|---:|---:|---:|
| index.html | 41,663 | 44,075 | 1.06x |
| hello.txt (1.1 KB) | 35,602 | 44,413 | 1.25x |
| 10 KB file | 42,811 | 41,789 | 0.98x |
| 1 MB file | 8,310 | 12,250 | 1.47x |

On that five-vCPU host, httpd-rs is at parity or ahead for the three small-file
cases and leads by 47% for the 1 MB file. Older runs used more simultaneous
connections from one identity, sampled the servers in a fixed order, and the
old `wrk` parser did not record its non-2xx counter. They remain in
`bench/RESULTS.md` as historical measurements, but are not comparable with the
strict run above.
Recent hot-path work caches the `Date` header and document-root descriptors,
coalesces small response bodies, and reduces per-request allocation in MIME
and access-log formatting. The latest policy migration also caches
per-directory scopes, shares parsed `.htaccess` scopes through `Arc`, indexes
literal `<Directory>` rules, and avoids per-request ancestor sorting.

`bench/feature_bench.py` runs the same Apache-versus-httpd-rs comparison
against the richer conformance configuration: static and large-file serving,
conditional/range requests, directory handling, access policies, Basic auth,
rewrites, `.htaccess`, CGI, proxy authorization, internal
`DirectoryIndex`/`ErrorDocument` handler dispatch, HTTPS/1.1 and HTTP/2.
Access-policy scenarios cover `<Limit>`/`<LimitExcept>`, `Satisfy`,
`AllowMethods`, `AuthMerging`, `<ElseIf>`, and `<Proxy>`/`<ProxyMatch>`.
After the access-walk prefilter and per-request metadata memoization,
`.htaccess` rewrite moved from **0.70x** to **0.96x** and `.htaccess` Header to
**1.25x** in the latest 3s/five-sample run.
Bound CGI scripts execute inside the worker pool after reopening and
dev/inode-verifying the authorized script, instead of forking the main server;
the latest quick run measured CGI GET **2.60x**, CGI POST **2.57x**,
DirectoryIndex CGI **3.11x**, ErrorDocument CGI **3.55x**, and HTTP/2 CGI
**4.44–5.16x**. Most access-policy scenarios remain ahead of Apache, and
server rewrite is about **1.14x**. The remaining sub-1.0 cases are proxy
static/ProxyMatch (about 0.82–0.85x), limited by the Python test backend and
backend connection setup, HTTP/2 1 MB (about 0.82x), and `.htaccess` rewrite
near parity. See `bench/FEATURE_RESULTS.md` for the full matrix and
measurement caveats.

`bench/cache_bench.py` isolates the shared-cache hit path. Both servers warm
the same `/cached/` entries and the harness refuses to time a scenario unless
the second request reports `X-Cache: HIT`. It also measures an uncached static
file as the baseline:

```sh
python3 bench/cache_bench.py --quick
python3 bench/cache_bench.py
```

Latest full run (2026-10-27, 3s samples, median of three):

| scenario | Apache req/s | httpd-rs req/s | ratio |
|---|---:|---:|---:|
| cache HIT 1.1 KB | 86,780 | 141,844 | 1.63x |
| cache HIT 10 KB | 80,218 | 136,152 | 1.70x |
| cache HIT 1 MB | 8,158 | 13,140 | 1.61x |
| static 1.1 KB baseline | 88,894 | 207,076 | 2.33x |

The cache-hit path still costs httpd-rs some of its static throughput on small
files, but large cached bodies now use the file-body/sendfile path instead of
copying a heap buffer. Results are appended to `bench/CACHE_RESULTS.md`.

`bench/app_bench.py` exercises the production-shaped dynamic paths with the
same upstreams:

```sh
sudo python3 bench/app_bench.py --quick
sudo python3 bench/app_bench.py --only php
python3 bench/app_bench.py --only gunicorn
```

The fixture starts a private PHP-FPM pool over a Unix socket and eight Gunicorn
sync workers, then benchmarks `/index.php` through FastCGI and `/app/hello`
through the HTTP proxy against both front ends. The secure PHP fixture runs
under root-owned `/run` so the same stable-path policy used in production can
remain enabled. Latest five-sample PHP run:

| scenario | Apache req/s | httpd-rs req/s | ratio |
|---|---:|---:|---:|
| PHP-FPM `/index.php` | 17,424 | 11,258 | 0.65x |

The handlers are intentionally trivial; these numbers isolate the front-end
and upstream hop. httpd-rs's PHP result includes per-request stable-path
ownership/writeability/ACL checks, endpoint inode validation and peer-credential
authentication; Apache does not make an equivalent proof. Real PHP/WSGI
application time will usually dominate. The Gunicorn sync workers close each
upstream connection, and httpd-rs deliberately does not pool backend connections
without strict response-framing checks. See `bench/APP_RESULTS.md` for details.

These are static-file microbenchmark numbers with a minimal Apache module set,
not a general claim about Apache. TLS, HTTP/2, `.htaccess`, CGI/modules and
production tuning are outside this comparison. The 1 MB result is close to
parity because it is bound by kernel file/socket throughput; small-file
throughput is dominated by per-request CPU cost. In sampled runs both servers
used roughly five cores, so the advantage reflects CPU efficiency per request,
not extra parallelism.

## Usage

```sh
# Syntax check a stock Apache configuration
./target/release/httpd-rs -f /etc/apache2/apache2.conf -t

# Run in the foreground
./target/release/httpd-rs -f /etc/apache2/apache2.conf -DFOREGROUND

# Strict mode: reject directives/modules we do not implement
./target/release/httpd-rs -f /etc/apache2/apache2.conf -t --strict-config
```

## Repository layout

```text
crates/verified   Verus specifications and verified pure functions
crates/server     HTTP/TLS/HTTP/2, config + .htaccess, pure config front-end + policy core, auth, file/CGI, daemon
tests             Apache differential conformance suite
bench             Apache-vs-httpd-rs static/feature/cache/app benchmark harness and history
```

## Roadmap

1. Finish the remaining rewrite edges: `dbm` maps and exact per-directory
   `[DPI]` path-info handling, keeping the parser fail closed.
2. Expand authentication to Digest/LDAP providers and per-directory policy.
3. Add h2c and cleartext HTTP/2 upgrade support for parity with mixed
   deployments.
4. Grow the conformance suite toward the full Apache test corpus and track
   Apache-oracle line/branch coverage alongside the source-derived warrant
   ledger. The source-tarball and external `apache-httpd-test` cases are pinned
   and inventoried; their supported-subset semantic triage remains ongoing.
5. Port chunked request-body decoding and response-header serialization into
   Verus, reusing the verified token, header-value and framing predicates.
6. Continue tuning large-file throughput (the 1 MB scenario is sensitive to
   host variance and has ranged from 1.26x to 1.39x Apache in recent runs).
