# Apache 2.4 capabilities httpd-rs does not implement

Snapshot: 2026-10-22, Apache 2.4.69 (Debian) vs. httpd-rs 0.1.0. Based on the
README, the directive dispatch in `crates/server/src/config.rs`, the module
list in `crates/server/src/main.rs`, the installed Apache module set, and a
trial parse of the stock Debian `/etc/apache2/apache2.conf`.

Importance is from the point of view of a sysadmin deciding whether httpd-rs can
replace an existing Apache deployment:

- **Blocker** - a typical deployment cannot switch without redesigning the architecture.
- **High** - common production requirement; a workaround or another component is needed.
- **Medium** - relevant to some deployments, not universal.
- **Low** - niche, legacy, or easily replaced.

## Migration hazard: unsupported security directives

Security-sensitive unsupported directives now fail closed even in compatibility
mode: `SSLRequireSSL`, `SSLRequire`, and `SecRuleEngine On` are rejected rather
than silently dropped. `<Limit>`/`<LimitExcept>`, `Satisfy`, `AuthMerging`,
`AllowMethods`, `<ElseIf>`/`<Else>`, and `<Proxy>`/`<ProxyMatch>` authorization
are implemented. Unsupported in-process handlers (`mod_php`, `mod_perl`,
`mod_wsgi`) and output filters (SSI/unknown filters) return `500` rather than
serving source. Cosmetic or module-specific directives still produce warnings
in compatibility mode, but they cannot silently weaken access or TLS policy.
Use `--strict-config` for migration reviews; `DefaultRuntimeDir` and common
MPM/core tuning directives are now recognised.

## Capability gaps

| Capability | Apache mechanism | httpd-rs status | Importance | Practical workaround |
|---|---|---|---|---|
| Reverse proxy / gateway | `mod_proxy`, `mod_proxy_http`, `mod_proxy_wstunnel`, `mod_proxy_balancer`, `ProxyPass*` | HTTP/HTTPS upstreams, FastCGI, round-robin `balancer://`, active health checks, reusable upstream connections, WebSockets over TCP/TLS, and `<Proxy>`/`<ProxyMatch>` authorization are implemented; advanced balancing policies are not | **Medium** | Use a dedicated load balancer for stickiness/failonstatus |
| Dynamic language runtimes | `mod_php`, `mod_wsgi`, `mod_perl`, `mod_lua`, `mod_jk`/AJP, SCGI/uWSGI | FastCGI/PHP-FPM and direct CGI/1.1 are implemented; in-process language modules are not | **High** for non-PHP runtimes, lower for PHP | PHP-FPM works natively; run other runtimes behind the HTTP proxy |
| Apache module ABI / third-party modules | `LoadModule` for any `.so` (`mod_security`, `mod_pagespeed`, `mod_evasive`, `mod_wsgi`, ...) | `LoadModule` is parsed but ignored; no Apache module ABI. Configured handlers that require an unsupported module fail closed with `500` instead of serving source | **Blocker** in module-dependent environments, **High** generally | Replace each module with an external service or a native httpd-rs feature |
| Balancer health / failover / pooling | `hcheck`, `failonstatus`, connection pools, sticky sessions | Active GET/HEAD health checks with passes/fails, passive dead-member skipping, sticky route cookies, `failonstatus` retry and HTTP/1.1 connection reuse are implemented; advanced health templates/policies are not | **Low** | Use a dedicated load balancer only for exotic policies |
| Apache expression engine | `Require expr`, `<If>`, `<IfFile>` | Implemented for common comparisons, boolean logic, regex captures, variables, file/IP/glob tests and string/hash/base64 functions; rare forms and `LogMessage` interpolation are missing | **Medium** | Rewrite complex expressions as supported `Require`/rewrite rules |
| Full `mod_rewrite` | `RewriteMap` (txt/rnd/prg/dbm/int), all flags including `[B]`/`[BCTLS]`/`[CO]`/`[E]`/`[H]`/`[DPI]`, full inheritance | Core rules, maps (`txt`/`rnd`/`prg`/`int`), `[C]`/`[S]`/`[N]`/`[QSD]`/`[QSL]`, `RewriteCond expr`, `RewriteOptions Inherit`, query escaping, `[B]`/`[BNE]`/`[BCTLS]`/`[BNP]`, `[CO]`/`[E]`/`[H]`/`[T]`, `[P]`, `Vary`, `UnsafeAllow3F`, and `UnsafePrefixStat`; `dbm` maps and exact `[DPI]` path-info handling are missing | **Low** | Most CMS `.htaccess` rules and proxy/cookie rewrites now work; avoid `dbm` maps and per-directory `[DPI]` |
| Full `.htaccess` coverage | Any directive allowed by `AllowOverride`, nested sections, provider aliases | Only the implemented subset; unknown directives and unsupported sections fail closed with 500 | **High** for shared hosting/CMS, **Medium** for controlled single sites | Move rules into the vhost config; test every `.htaccess` before switching |
| Compression | `mod_deflate`, `mod_brotli`, `AddOutputFilterByType`, `Deflate*`, `Brotli*` | Implemented: gzip/Brotli negotiation, levels, Vary/ETag, range bypass and `.htaccess` filters | Closed | — |
| Graceful reload / zero-downtime restart | `SIGHUP`, `apachectl graceful`, graceful restart with old workers draining | `SIGHUP` reloads config, reuses open listener sockets (including privileged ports), reloads TLS/OCSP and drains existing connections; changing `Listen` addresses needs a full restart | **Low** | Use a rolling restart only when changing listener addresses |
| TLS automation and advanced TLS | `mod_md`/ACME, `SSLVerifyClient`, `SSLRequire`/`SSLRequireSSL`, OCSP stapling, CRL, session cache/tickets, cipher-policy directives | mTLS, OCSP stapling from AIA or `SSLStaplingForceURL`, response refresh and warm-start persistence work; CRL, session cache/tickets, `SSLRequire*` and external ACME do not | **Medium** for ACME; **Low** for OCSP | Use external ACME/restart; use strict mode for ignored TLS directives |
| WAF / request inspection | `mod_security` (`SecRuleEngine`, `SecRule`, ...) | Directives are recognised but ignored | **High** in PCI/regulated environments | External WAF/CDN; do not rely on compat mode |
| Real client IP behind a proxy | `mod_remoteip`, `RemoteIPHeader`, `RemoteIPInternalProxy` | Implemented for trusted proxy addresses | Closed | — |
| Per-user CGI | `mod_suexec`, `SuexecUserGroup` | Not implemented; CGI runs as the server user with `PR_SET_NO_NEW_PRIVS` | **High** for shared hosting, **Low** for single-site | Separate httpd-rs instances/users, or an external CGI runner |
| `mod_expires` / cache headers | `ExpiresActive`, `ExpiresByType`, `ExpiresDefault` | Implemented, including access/modification bases and max-age | Closed | — |
| HTTP caching | `mod_cache`, `mod_cache_disk`, `mod_cache_socache`, `mod_file_cache` | Disk/memory cache with `CacheEnable`/`CacheDisable`, expiration, size limits, `CacheHeader`, `Age`, conditional hits, warm-start metadata and invalidation; `socache` and `file_cache` are not implemented | **Low** | Use a CDN for shared cache or `mod_cache_socache` topologies |
| Header and environment manipulation | Full `mod_headers` (`append`, `merge`, `edit`, `echo`), `RequestHeader`, `SetEnv`, `SetEnvIf`, `PassEnv`, `UnsetEnv` | `Header set/add/unset` only; environment directives are ignored | **Medium** | Limited header policy; CGI environment is intentionally minimal |
| Authentication providers | `mod_auth_digest`, `mod_authn_ldap`/`mod_authnz_ldap`, DBM/DBD, `mod_auth_form`/`mod_session`, anonymous auth | Basic + file-backed htpasswd only | **Medium**, **High** in enterprise LDAP environments | Basic auth against htpasswd, or authenticate at an external proxy |
| Access-control expressions | `Require expr`, `Require env`, `<Limit>`/`<LimitExcept>`, `Satisfy`, `AllowMethods`, `AuthMerging`, `<Proxy>` auth | `Require ip/host/method/local/user/group`, `Require expr`, `Require env`, `RequireAll/Any/None`, method-scoped `<Limit>`/`<LimitExcept>`, legacy `Satisfy`, `AuthMerging And/Or`, `AllowMethods`, and `<Proxy>`/`<ProxyMatch>` authorization are supported | Closed | — |
| Monitoring and introspection | `mod_status` (`/server-status`), `mod_info`, scoreboard, `ExtendedStatus` | Basic `/server-status` and `?auto` implemented; `mod_info` and scoreboard are not | **Medium** | External health checks, metrics from logs, and process monitoring |
| MPM and server tuning | `StartServers`, `Min/MaxSpareThreads`, `ThreadsPerChild`, `MaxRequestWorkers`, `ServerLimit`, `MaxConnectionsPerChild`, `ListenBacklog`, `RLimit*` | `MaxRequestWorkers`/`ServerLimit` and `ListenBacklog` are enforced; spare-thread/MPM process tuning is irrelevant to the thread-per-connection model | **Low** | Tune OS/file-descriptor limits and `MaxRequestWorkers` |
| DoS / request controls | `mod_reqtimeout`, `mod_ratelimit`, `mod_buffer` | `RequestReadTimeout` header/body deadlines, header `MinRate`, `MaxRequestWorkers`, header/body size limits and keep-alive limits are enforced; full body `MinRate` shaping and `mod_ratelimit` are not | **Medium** for hostile public edges | Enforce full rate shaping at the load balancer; use request limits in httpd-rs |
| SPA fallback | `FallbackResource` | Recognised but not applied | **Medium** | A supported `RewriteRule` fallback or `ErrorDocument` |
| Mass vhosts / user directories | `mod_vhost_alias`, `mod_userdir` | Not implemented | **Low-Medium** | Generate explicit vhosts; keep user content outside the docroot |
| SSI and content negotiation | `mod_include` (`Options +Includes`), `mod_negotiation` (MultiViews, `LanguagePriority`) | SSI filters (`SetOutputFilter`/`AddOutputFilter* INCLUDES`) fail closed with `500`; `Options +Includes` alone does not process includes; MultiViews/negotiation directives are ignored | **Low-Medium** | Preprocess pages; avoid MultiViews; use a dedicated SSI step |
| WebDAV | `mod_dav`, `mod_dav_fs`, `mod_dav_lock` | Not implemented | **Low-Medium** | Use a dedicated WebDAV server |
| Response transformation | `mod_substitute`, `mod_sed`, `mod_ext_filter`, `mod_filter`, `mod_actions`, `mod_imagemap`, `mod_asis` | Not implemented | **Low-Medium** | Do it in the app/CDN |
| HTTP/2 extras | h2c prior knowledge/upgrade, server push, `H2*` tuning directives | HTTP/2 over TLS only; no push or H2 tuning | **Low** for h2c (RFC 9113 deprecated upgrade), **Medium** for cleartext gRPC backends | Terminate TLS; for gRPC use a proxy that speaks h2c |
| Logging/integration | `syslog:` targets, piped logs, `ErrorLogFormat`, conditional logging, `mod_systemd` notify/socket activation | File logs support `SIGUSR1` reopen/rotation; `syslog:` writes to stderr, piped logs are treated as paths, partial `LogFormat`; no systemd notify | **Medium** | Ship files with a log agent; use `Type=simple` |
| Config macros | `mod_macro` | Not implemented | **Low-Medium** | Generate the config with a template tool |
| Niche/legacy modules | `mod_speling`, `mod_mime_magic`, `mod_cern_meta`, `mod_charset_lite`, `mod_case_filter`, `mod_data`, `mod_dialup`, `mod_echo`, `mod_usertrack`, `mod_unique_id`, `mod_ident`, `mod_authn_anon`, `mod_authnz_fcgi` | Not implemented | **Low** | Usually no replacement needed |
| Core/server directives | `DefaultRuntimeDir`, `ServerLimit`, `MaxConnectionsPerChild`, `GracefulShutdownTimeout`, `Mutex`, `ScoreBoardFile`, ... | `DefaultRuntimeDir`, `ServerLimit`, `ListenBacklog`, and `GracefulShutdownTimeout` are recognised; MPM spare-process tuning is irrelevant; remaining core directives may warn | **Low** | Clean up the config; strict mode is now practical for common configurations |

## What is already strong

The gap list is long, but it is not the whole story. httpd-rs already covers the
following well enough for a static or CGI-backed site:

- gzip/Brotli compression and FastCGI/PHP-FPM, plus HTTP/HTTPS reverse
  proxying with prefix/regex routes, `ProxyPassReverse`, round-robin
  `balancer://` backends and WebSocket tunneling over TCP/TLS.
- Static files, `DocumentRoot`, `Alias`/`ScriptAlias`, `Redirect`, directory
  indexes, autoindex, MIME types, custom error documents and vhosts.
- ETags, `Last-Modified`, `If-*` conditionals, byte ranges and HEAD.
- Basic auth with Apache htpasswd hashes; IP/host/method/local and grouped
  `Require` rules; legacy `Order`/`Allow`/`Deny`.
- A useful `.htaccess` subset (access/auth, Options, DirectoryIndex,
  ErrorDocument, MIME/handlers, `Header`, Redirect and rewrite rules).
- TLS 1.2/1.3 with SNI and ALPN, plus HTTP/2 over TLS (including ranges, auth,
  CGI and vhosts).
- Strict HTTP/1.1 parsing, keep-alive, pipelining, CGI, logging, privilege
  dropping, and a large set of Apache-compatible core directives.

For a static site with simple rewrites and Basic auth, httpd-rs is a credible
faster, lower-memory replacement. It is now also a credible front door for
PHP-FPM, HTTP/HTTPS app servers and round-robin backends, with gzip/Brotli
compression and WebSockets over TCP/TLS. Remaining migration blockers are
mostly module-dependent environments, WAF, ACME automation, shared SOCACHE
and exotic load-balancing features.
