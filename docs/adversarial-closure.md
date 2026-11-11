# Adversarial finding closure

This document records how the `adversarial/findings.md` adversarial pass is reflected in
the implementation and the security model.  The numbered findings are the
source of the regression classes; the invariants (`I9`–`I71` in
`docs/config-semantics.md`) are the properties that prevent the class from
returning through a different directive or dispatch path.

| Finding | Class | Implementation closure | Model obligation |
|---|---|---|---|
| F1 | Hidden-file bypass through ignored `RedirectMatch`; strict mode accepted unimplemented directives | `RedirectMatch` is parsed, regex-matched and expands captures; `RedirectPermanent`/`RedirectTemp` are handled. `directive_disposition` now fails strict mode for every unhandled directive | I9 |
| F2 | `AliasMatch`/`ScriptAliasMatch` ignored; `RemoveHandler` ignored | Regex aliases share `map_path` and capture expansion; handler operations are ordered, so a later `RemoveHandler` removes an `AddHandler`. `Action` fails closed | I9, I10 |
| F3 | CGI `PATH_INFO` selected the handler and authorized the wrong object | Handler selection uses the actual script basename. After `find_script`, policy is re-evaluated for the script path and the grant is bound to the script inode. FastCGI splits `PATH_INFO` to an existing script and re-authorizes it | I10, I11 |
| F4 | Cache authorized a different target than dispatch; trailing-slash `<Location>` missed | Cache and dispatch share `map_path`; the cache URL preserves its trailing slash and authorization runs against the mapped alias/target | I10, I12 |
| F5 | CGI inherited the worker control socket | The worker keeps the socket open for its own loop but marks it `FD_CLOEXEC` before spawning scripts; scripts see only stdio plus the explicit script descriptor | I13 |
| F6 | Duplicate `Vary` field lines collapsed | All `Vary` lines are concatenated and de-duplicated before building the variant key | I12 |
| F7 | Cache key omitted listener/vhost/target | Key includes scheme, listener address/port, vhost, Host, canonical URL, query, resolved target and policy fingerprint | I10, I12 |
| F8 | Disk fallback ignored `Vary` | `cache_lookup_admit` receives the real `vary_match` result on disk reload; a mismatch is neither served nor inserted | I12 |
| F9 | `<Proxy balancer://...>` never matched; failover reused the first grant | Proxy sections match both the logical balancer URL and the concrete member; failover re-runs proxy authorization and rebinds the member target | I8 |
| F10 | `.htaccess` `<IfModule>` allowlist skipped security blocks | Access files now consult the compiled configuration's exact linked/loaded module registry. Positive blocks for missing modules are skipped like Apache, while present modules are parsed normally; the old unconditional-positive behavior could activate a grant Apache never selected | I9, I71 |
| F11 | `SymLinksIfOwnerMatch` followed all links; a later pathname re-walk made the owner check raceable | Owner-only mode walks pinned directory descriptors, opens each link with `O_PATH\|O_NOFOLLOW`, reads that inode through empty-path `readlinkat`, and compares its owner with the descriptor-resolved target before returning the same file; mismatch, escape, excessive depth and descriptor depth fail closed. Unconditional `FollowSymLinks` retains the configured behavior | I11 |
| F12 | Unsafe methods left disk entries stale | Invalidation removes persisted body/meta files as well as memory entries | I12 |
| F13 | `Header always`/`unset` ignored; child `set` duplicated | `always`/`onsuccess` are separate lists, `unset` runs after set/add, and child `set` replaces inherited same-name fields | Scope-merge header rule |
| F14 | TLS CGI/FastCGI claimed `http` | `CgiContext` carries listener TLS state; CGI/FastCGI set `REQUEST_SCHEME` and `HTTPS` correctly | I10 (scheme is request context) |
| F15 | `UseCanonicalName On` ignored in redirects | Canonical server name wins for `server_name_for`, absolute redirects and directory redirects; the Host header cannot override it | I10 |
| F16 | `%{HTTPS}` trusted `X-Forwarded-Proto` | Expression evaluation reads connection TLS state set by the listener; forwarded headers are never treated as TLS evidence. `SERVER_PORT` comes from the listener | I10 |
| F17 | Internal rewrite discarded original `<Location>` auth | Both the original request URL scope and the final target scope must allow after a rewrite | I11 |
| F18 | `ProxyPass`/`ProxyPassMatch` order ignored | Prefix and regex HTTP/FastCGI routes share a configuration-order `route_order`; the earliest matching route selects the handler | I8 |
| F19 | Chunked trailers bypassed the body deadline | Trailer lines check the request deadline and are bounded by count/bytes, matching the proxy reader | I12/I13-adjacent resource bounds |
| F20 | CGI buffered the entire request body | Bodies above the 1 MiB spool threshold remain on disk through the worker protocol and are streamed to stdin; small bodies stay in memory | Descriptor/body resource bound |
| F21 | Proxy chunk-size arithmetic could overflow | Chunk end offsets use `checked_add` and are bounded by `MAX_PROXY_BODY` before resizing | Resource bound |
| F22 | Alias target parent `.htaccess` skipped for subdirectories | Access-file walks use the URL-selected alias root for URL-base derivation and include every applicable ancestor, so every parent `.htaccess` down to the target is read; the later F50/F51 fix removed the alias root as an authorization bound | I10, I11, I47, I48 |
| F23 | Two-stage internal rewrite then `[P]` dropped original-URL authorization | The post-loop original-URL check is a shared gate used by proxy and positive-redirect outcomes as well as static targets | I19 |
| F24 | Disk cache survived reload and a new `<Files>` deny via CGI `PATH_INFO` | Cache entries carry a configuration epoch; reload bumps it and removes persisted files. Cache scope/target resolve `PATH_INFO` to the actual CGI script | I12, I20 |
| F25 | Relative `AliasMatch` target skipped its target-tree `.htaccess` | Relative regex replacement roots are resolved against `ServerRoot` at parse time, matching `map_path()` and the access-file walk | I10, I21 |
| F26 | Autoindex emitted executable `javascript:`/scheme-relative links | Autoindex hrefs are built by `safe_relative_href`, which always prefixes `./` before URL encoding | I22 |
| F27 | `Require not env` parsed the wrong operand; `Require not expr` lost negation | `parse_require` consumes `rest.first()`/`rest.join(" ")`, and `Require::Expr` carries its negation into evaluation | I23 |
| F28 | `.htaccess` `SetEnv`/`SetEnvIf` silently ignored | Both `.htaccess` and main config use one environment-rule parser and populate `EnvironmentPolicy`; `SetEnvIf` is authorization-visible, while per-directory rewrite environment and `SetEnv`/`UnsetEnv`/`PassEnv` retain Apache's later fixups timing | I23, I71 |
| F29 | `IndexIgnore` accepted and ignored | `IndexIgnore` is part of `ContentPolicy` in both parsers and filters autoindex entries | I24 |
| F30 | `DirectorySlash Off` let `/dir` bypass `<Location "/dir/">` | A no-slash directory target is reauthorized as its canonical trailing-slash URL before index or autoindex dispatch | I24 |
| F31 | Regex alias fallback re-rooted a target outside its alias base | `map_path()` returns `None` when a regex expansion leaves `fs_path`; dispatch, WebSocket and cache callers fail closed instead of using `target.parent()` as a new root; admission consumes the verified component-aware `path_under_base` kernel | I25 |
| F32 | `UnsafePrefixStat` rewrite changed the authorization base | `rewrite_filesystem_admit` admits only files below the current document/alias root; its `under_base` input comes from verified `path_under_base`; the flag is compatibility-only and cannot re-root at the target parent, and the parser now logs a load-time `[UnsafePrefixStat]` warning ("... has no effect") for main-config rules while `.htaccess` rules still have no warning surface | I25 |
| F33 | FastCGI script construction and `PATH_INFO` walk could escape the document root | `script_from_prefix` cleans inside the configured prefix or docroot and consumes verified `path_under_base`; `split_path_info` uses a descriptor-bound `openat2(RESOLVE_BENEATH)` regular-file check, the ancestor walk stops at that base, and execution reopens beneath the same base before handoff | I25 |
| F34 | Cache fingerprint omitted header-driven authorization inputs | The policy fingerprint hashes the complete request header set; a tenant/header branch therefore cannot share a cached representation | I26 |
| F35 | Proxy request-line/forwarded-host text was interpolated without a final check | Backend hosts and `X-Forwarded-Host` are validated; `validate_proxy_head` consumes verified `proxy_request_line_admit` and `proxy_header_admit` immediately before `write_all` | I28 |
| F36 | `.htaccess` `RequestHeader` was silently ignored | `RequestHeader` now fails closed with `500` in `.htaccess`, matching the main-config policy instead of pretending to be inert | I23 |
| F38 | Authenticated CGI/FastCGI requests lacked `REMOTE_USER`/`AUTH_TYPE` | The grant identity is carried into `CgiContext`; `build_env` emits both variables for CGI and FastCGI and keeps configured entries from overriding them | I27 |
| F39 | Single-file `Alias`/`ScriptAlias` skipped the target `.htaccess` and served CGI/PHP as source | Prefix file targets map to `(parent, basename)`; the access-file walk root for a file target is its parent; handler/MIME/FastCGI selection uses the resolved target basename (`alias_file_target_split`, `alias_access_root_admit`, `handler_name_from_target`) | I35, I36, I37 |
| F40 | Effectful directives inside `<Limit>` were warn-and-ignored | Main-configuration directives inside `<Limit>` are applied to the enclosing scope (auth directives remain method-scoped); `.htaccess` still rejects non-auth directives in `<Limit>` (`limit_directive_effect`) | I38 |
| F41 | CGI/FastCGI dispatch used lexical symlink policy | Static, PATH_INFO, CGI and FastCGI handlers re-authorize the actual opened/canonicalized target and bind that target before execution/forwarding. FastCGI keeps that authorization identity separate from the lexical `SCRIPT_FILENAME` required by Apache/backend policy (`cgi_actual_target_admit`, `fastcgi_script_identity_admit`) | I39 |
| F42 | Capture-only `AliasMatch` used `ServerRoot` as an implicit base | Empty replacement prefixes produce an empty alias base, so `map_path()` fails closed; relative/explicit-prefix aliases keep their stable base (`capture_only_alias_admit`) | I40 |
| F43 | FastCGI spool used a predictable `/tmp` name with truncate | Spool files use exclusive creation, mode `0600`, bounded collision retries and immediate unlink (`temp_file_create_admit`) | I41 |
| F44 | Disk cache had no total quota or expiry cleanup | Persisted bytes are tracked per cache root; store enforces `CacheMaxDiskSize` and the entry cap by evicting the oldest stems, removes oversized entries, deletes expired/stale generations on load, and caps per-key variants (`cache_disk_size_admit`) | I42-adjacent cache bounds |
| F45 | Expression file tests escaped the document-root confinement | `Expr::FileTest` consumes `confined_expr_path`; absolute, parent-relative and escaping-symlink tests are rejected, while main-config `<IfFile>` keeps its operator-supplied path (`expr_file_test_admit`) | I42 |
| F46 | Multi-provider `<RequireNone>` was combined with AND, turning a deny list into an allow list | Children are aggregated as an OR of positive hits before negation; any granted child makes the group deny (`combine_or_all`, `require_none_multi`, `require_none_multi_result`) | I43 |
| F47 | Regex alias file targets with a trailing slash skipped the target `.htaccess`; protected files were served and CGI executed | Regex targets that resolve to a regular file map to `(parent, basename)`, and the URL/base root uses the parent for every non-directory alias target (`alias_file_target_split`, `alias_access_root_admit`); ancestor authorization follows I47 independently of that root | I44, I47 |
| F48 | Address-specific virtual hosts were selected by port and Host only; a loopback-bound admin vhost was reachable through another address | `select_vhost` takes the destination address, excludes address-bound vhosts on other addresses and gives exact-address vhosts precedence over wildcards; HTTP/1.1, HTTP/2, WebSocket, TLS, cache and logging use the address-aware helper (`vhost_address_admit`, `vhost_address_precedence`) | I45 |
| F49 | IPv4-mapped IPv6 peers bypassed IPv4 `Require not ip` rules on dual-stack listeners | Peers and RemoteIP identities are canonicalized to IPv4 before policy evaluation; `ip_in_net` and `Require local` consume the canonical form (`ipv4_mapped_to_v4`) | I46 |
| F50 | The access-file walk stopped at `DocumentRoot`/the alias target and ignored an effective ancestor `.htaccess` | The walk covers every filesystem ancestor and asks the effective per-directory `AllowOverride` policy whether that layer participates; the mapping root is used only for URL/`RewriteBase` derivation (`access_walk_dir_admit`) | I47 |
| F51 | Overlapping aliases selected the first alias target containing the path instead of the URL-selected alias | `map_path()` returns the actual URL-mapping root and dispatch/cache/explain pass it through to the access walk; alias-target containment is never used to reconstruct the root (`alias_mapping_root_admit`) | I48 |
| F52 | Cache lookup/store used the directory URL instead of the selected `DirectoryIndex` target | `DirectoryIndex` is resolved before the cache decision; the cache key, target, grant and policy fingerprint bind that index. Dynamic index/script responses bypass `CacheIgnoreQueryString`, and a live `<Files>` change is visible in the recomputed index policy (`cache_directory_index_bind_admit`, `cache_ignore_query_admit`) | I49 |
| F53 | `.htaccess` anchored rules under an `Alias`/`AliasMatch`/`ScriptAlias` used the alias target-relative path, not the URL mount, so `[F]`/`[G]` deny rules were skipped | `request_plan::layer_url_mount()` derives every layer's substitution base from the requested URL and the layer's depth below the requested target; prefix/regex aliases, nested access files, `RewriteBase`, static files, CGI and `[F]`/`[G]`/`[E]`/`[R]` effects share the same identity (`htaccess_layer_url_base_admit`) | I50 |
| F54 | The `CacheIgnoreQueryString` dynamic-target classifier missed `SetHandler "proxy:…\|fcgi://…"` and other non-default handlers | The cache classifies the effective handler after `DirectoryIndex` resolution; any non-default handler (FastCGI proxy, `cgi-script`, `server-status`, future handlers) forces a cache bypass for query-bearing requests (`cache_dynamic_handler_admit`) | I49, I53 |
| F55 | Lossy UTF-8 conversion in cache-key material merged invalid-byte queries/paths with the empty or replacement value | Server root, host, path, raw query and resolved target are hex encoded losslessly; non-UTF-8 URL paths bypass the shared cache, invalid index names are rejected, and invalidation uses the same encoding (`cache_key_hex`) | I51 |
| F56 | A local `ErrorDocument` is an internal subrequest selected after the original URL's cache scope was built, so a query-dependent error document could be cached under the missing URL | A missing target whose scope can select a local `ErrorDocument` bypasses lookup, and an error-document response is never stored under the failing URL via a response-provenance marker; existing targets keep normal caching and the internal subrequest still runs normal authorization and handler dispatch (`cache_local_error_document_admit`) | I52 |
| F57 | `%{REQUEST_URI}` used the raw request-line target, including the query, percent escapes and dot segments, so expression/rewrite/environment path policies authorized different bytes than dispatch served | Every `%{REQUEST_URI}` implementation receives the dispatcher's decoded, normalized, query-free URL path: expression variables/functions, `Require expr`, `<If>`, `SetEnvIf Request_URI`, `RewriteCond`/rule expansion and CGI environment. `expr::Context::new` consumes `request_uri_identity_admit`; no path appends the query string | I57 |
| F58 | Access-file rewrite rules above the alias/document-root mapping root had an impossible URL match base, so anchored `[F]`/`[G]` deny rules were silently skipped | Every parsed access-file rule carries its layer directory; `request_plan::layer_subject()` matches the selected filesystem target relative to that directory, exactly Apache's per-directory subject. `htaccess_rewrite_subject_admit` requires a derivable subject or fails closed. `request_plan::layer_url_mount()` is used only for relative substitutions and uses the filesystem-directory form for ancestor layers instead of an unmatchable URL fallback | I58, I59 |
| F59 | A symlinked `DocumentRoot`/`Alias`/`ScriptAlias` root made `RequestPlan::from_fs_target()` walk `root.join(file_name)` instead of the canonical target, discarding every child `.htaccess` layer during target reauthorization; child `Options -ExecCGI`, `DirectoryIndex` CGI and `Options -Indexes` were bypassed | Explicit targets derive the access-file walk, layer identities and scope evaluation from the same target path. Canonical ancestors are walked even when the lexical mapping root contains a symlink, with `AllowOverride` policy inherited from the corresponding lexical directory; nonempty layers are always consumed and a layer set that does not belong to the target fails closed (`explicit_target_layer_admit`, `target_layer_consume_admit`) | I60 |
| F60 / F60-A–E | Canonical-target reauthorization replaced the URL-mapped scope with the canonical target scope. A symlinked document root/alias, an attacker-created in-root symlink, or a rewrite-selected target lost child/ancestor `<Directory>` and `.htaccess` policy, enabling `Options -ExecCGI` bypass, `Options -Indexes` listings, `RemoveHandler` bypass, and uploaded `.htaccess` execution when lexical `AllowOverride None` failed to veto canonical `AllowOverride All` | Every target-changing transform computes `meet(scope(URL), scope(target))`: `Options` permissions meet (`options_conjoin`), handlers are granted only when both identities resolve to the same handler (`handler_conjoin_admit`), and `AllowOverride` categories meet with explicit `None` denying either identity (`override_categories_conjoin`, `OverridePolicy::conjoined_with`). Rewrite-selected filesystem/cache targets use the same meet and retain the original URL's non-handler policy; the verified `rewrite_scope_retained_admit` states the dual-scope obligation | I61 |
| F67 | `[PT]` was parsed but never read, so an absolute rewrite substitution became a filesystem override and executed a host file where Apache passes the substitution through URL mapping | `[PT]` is honoured: `rewrite::process()` skips the filesystem promotion whenever `rule.flags.passthrough` is set, so the substituted URL re-enters URL mapping and cannot execute or leak the referenced file; the case still ends non-200 without the target's content. Covered by `F67PassthroughTargetTests` plus the H2 unit tests in `rewrite.rs` (mechanizing the flags/round state machine is deferred) | I25 |
| F68 | The rewrite filesystem override was sticky across rules and rounds, so an earlier rule's absolute substitution executed after a later `[L]` URL-only rewrite mapped the request elsewhere | The per-rule filesystem override is replaced unconditionally on every rule and the dispatcher consumes the per-round value (`rewrite.rs`/`server.rs` `rewrite_filesystem`), so the last target-selection rule wins: a later URL-only `[L]` rewrite clears the stale file target instead of executing it. Covered by `F68StickyFilesystemOverrideTests` (sticky replacement plus an executable-target capability control) and H2 unit tests (deferred mechanization) | I61, I25 |
| F61-A/A2/B/C | `<Location>` shell-glob (`/admin/*`) and `~` regex arguments were parsed as inert literal strings, so `<Location>` deny/`Options -ExecCGI` guards never woke for any real request | `compile_location_pattern` compiles the argument at load time: wildcard forms to `MatchKind::LocationGlob`, `~` regex forms to `LocationMatch`, and the literal form unchanged. The runtime matcher is iterative, component-bounded and anchored; exhaustive small-input tests refine it against the Verus `fnmatch_spec`, whose slash-bound proof remains the semantic oracle. An unhandleable pattern is a configuration error and the section fails closed | `location_glob_parse_binding`, I57-adjacent |
| F62/F62b | `[^...]` class negation was inverted twice: the glob matcher only recognized `!` and the deleted `files_glob_to_regex` translation escaped `^` as a literal, so `<Directory ".../www/[^a]*">` and `<Files "[^a]*.cgi">` denials never matched | The iterative matcher and verified specification both treat `[^a]` and `[!a]` as negated classes, and the regex translation is gone. Exhaustive refinement also found and closed an older class-body boundary error that let bytes after the closing `]` participate in membership. Apache-oracle and unit matrices cover negation, `?`, escapes and basename containment | `glob_class_negation`, I58-adjacent |
| F63/F63b | `expr::var()` had no `REQUEST_FILENAME`/`SCRIPT_FILENAME` and an unbound reference evaluated to the empty string, so `<If "%{REQUEST_FILENAME} =~ /private/">` and `RewriteCond expr` guards were silently fail-open | `expr::Context` carries `fs_path` (via `with_fs_path`); the filesystem variables are known only when the dispatcher binds the mapped path, so an unbound reference evaluates to `Err` (fail closed). `expr_var_known` is the single source of truth shared by evaluation and the load-time `validate_vars` walker (Var nodes plus `%{...}` inside strings, with transform-arg recursion), wired at `<If>`/`<ElseIf>`, `Require expr` and `RewriteCond expr` in both parsers | `expr_var_single_source` |
| F64/F64b | `SetHandler` was stored as a `*`-extension table entry, so directive order and inheritance let a later `AddHandler` (including an attacker-written `.htaccess` in a writable upload tree) re-arm execution over a `SetHandler default-handler` floor | `SetHandler` is a separate precedence field: `effective_handler` consults it first (child `SetHandler None` unforces to the ext table), `restrict_with` conjoins URL/target forces through the verified kernel and materializes a lexical `SetHandler none` as a static force across the resolved-target conjoin, and `[H=...]` rewrites write the same field. A `SetHandler` force always binds (`set_handler_precedence_admit`) and can neither be removed nor re-armed by the extension table | `set_handler_precedence`, I61 |
| F65 | `cgi::is_cgi` returned true for a `ScriptAlias` tree before consulting Options/handlers, so `SetHandler default-handler` inside a ScriptAlias tree had no effect | `is_cgi` reduces to a single kernel call `cgi_exec_admit(handler_bound, handler_is_cgi, script_alias, exec_allowed)`: execution needs the Options grant or a ScriptAlias mapping AND a handler classification, where a `SetHandler default-handler` force classifies as static. `cgi_exec_requires_cgi_handler`/`cgi_exec_requires_exec_allowed` prove the fail-closed direction | `cgi_exec_admission`, I39-adjacent |
| F66 | `<DirectoryMatch ".../private/$">` was already fixed in pass 10; the pass-11 retest verified the trailing-slash directory URL (autoindex path) stays 403 on both sides | No new code; the F66 replay stays in the battery as a guard (`F61ToF69Pass11Tests::test_f66_directory_match_guard_stays_fixed`) | I11 |
| F69 | Handler and MIME classification used the canonical symlink target basename, so `public/link.txt -> ../secret/secret.cgi` under a global `AddHandler cgi-script .cgi` executed a file Apache serves as static source | The dispatch binds the classification name to the lexical request-mapped basename (`fs_path.file_name()` first); `handler_identity_lexical_admit` is debug-asserted at the bind site. Authorization and containment still bind to the resolved canonical target | `handler_identity_lexical`, I61 |
| P13-A–C | F69's lexical identity was enforced only at one direct extension-table lookup: FastCGI and CGI `PATH_INFO` re-derived the canonical basename, while a canonical-only Files-scoped `SetHandler` force bypassed the name entirely | Direct CGI, PATH_INFO and FastCGI consume the same lexical basename. Canonical authorization and lexical handler Files policy are evaluated from one request plan; only handler fields use the lexical view, preserving canonical access denials. `handler_scope_lexical_admit` guards the force-binding site | `handler_identity_lexical`, I70 |
| P17-A | Resolved-file FastCGI `SetHandler` sent the canonical symlink target as `SCRIPT_FILENAME`, bypassing PHP-FPM's lexical extension gate | `handler_target_for_file` derives the wire path from the lexical mapped path and keeps the opened canonical target separate. `LexicalScriptPath` makes the wire identity explicit, `fastcgi_resolved_target_admit` binds lexical classification plus both containment checks, and the final inode reopen remains mandatory | `fastcgi_script_identity_admit`, `fastcgi_resolved_target_admit` |
| P18-A | `AllowOverrideList Require` implicitly admitted unlisted `<Files>`/`<FilesMatch>` wrappers, allowing a file-scoped grant Apache rejects | Every supported access-file section is admitted through one section-command gate before its children. Category masks and exact `"<Section"` list entries are independent from inner directives; `htaccess_section_admit` proves a permitted child cannot admit an unlisted wrapper | `override_mode_allows`, `htaccess_section_admit`, `htaccess_gate_admit` |
| P21-A | A header-only fixed body no larger than 1 MiB reserved its declared `Content-Length` from the process-wide request-resident budget and denied unrelated traffic | The fixed-body reader reserves each owned chunk only after it is received; the declaration itself allocates and reserves nothing, and every error path releases the actual-byte lease | `resource_budget_admit`, `request_body_memory_admit` |
| P22-A/B | HTTP/2 file responses materialized up to 8 MiB before flow-control capacity, while streamed proxy responses held a global blocking-read lease across the capacity wait | File and stream sends obtain h2 capacity first, then reserve/read at most 64 KiB. Each queued chunk owns its response-resident lease until h2 drops it; blocking-read leases exist only around the corresponding blocking read. A zero-window stream therefore holds no body allocation or read lease | `h2_flow_charge`, `h2_flow_enqueue`, `resource_budget_admit` |
| P24-A | A non-ASCII expression-regex delimiter let the byte parser stop inside a UTF-8 code point; the next string slice panicked and `panic = "abort"` killed the process | Expression regex delimiters must be ASCII and are validated before `Parser::pos` advances. Byte accumulators preserve valid UTF-8 for quoted strings and ASCII-delimited patterns. Unit tests include the exact fuzz artifact; the live access-file/main-config battery requires clean errors with the process alive | `expr_parser_totality` remains a partial obligation; deterministic and fuzz regressions cover the closed counterexample |
| P24-B | Nested optional counted repetitions forced PikeVM active-set work 4–5× above the old structural charge | Variable repetitions charge `max + 1` paths (or the unbounded exit path) and a conservative 4× active-set factor. The original subject is rejected and the admitted boundary is benchmarked | `regex_optional_repeat_charge_bounds_pike_work`, `regex_match_resource_admit` |
| P25-A | A trailing slash was preserved in the URL policy identity but dropped by filesystem mapping, so `/private.txt/` served the regular file while anchored URL guards only covered `/private.txt` | After real CGI/FastCGI handlers have an opportunity to dispatch, the static sink rejects every regular-file target whose canonical URL ends in `/`. Differential tests cover duplicate slashes and dot normalization; trailing path-info handler dispatch remains intact | I10, I11 |
| P25-B | Blocking `sendfile` ignored the intended `Timeout` boundary and let non-reading clients pin every connection worker for roughly five times the configured timeout | Plain sockets use non-blocking `send`/`sendfile` with `poll`; TLS receives the same write deadline. P26 refines this to a deadline renewed only after byte progress, so a fully stalled receiver releases its worker within `Timeout` without imposing a total-transfer cutoff | `resource_bounds` |
| P26-A | The P25 trailing-slash static-file rejection ran after cache lookup, and pre-fix V4 disk entries remained eligible after upgrade | Cache admission rejects an unchanged regular-file representation ending in `/` before lookup. V5 introduced exact-key decoding; current V7 retains it and also invalidates entries predating complete response cache-policy admission. The regression proves legacy metadata is removed rather than served | `cache_trailing_slash_target_admit`, `cache_authorization_inputs` |
| P26-B | P25's absolute response deadline truncated legitimate slow downloads even while every write continued to make progress | The HTTP/1 deadline is now per stall: each successful byte write renews it for plain writes, `sendfile`, TLS/adapted writers and final flush. A deterministic slow writer runs longer than one timeout interval and completes, while the stalled-socket test still times out | `resource_bounds` |
| P27-A/B | Recursive verified fnmatch/expr-glob execution overflowed the connection stack on long star runs and explored failing star patterns exponentially, allowing a request to abort the process or permanently consume workers | Runtime glob execution is iterative bottom-up DP with no input-dependent call stack and polynomial work. Access-file lines and configuration patterns are capped at 8190 bytes; request-controlled expression globs additionally consume `glob_match_resource_admit` and fail authorization evaluation closed above four million cells. A 100,000-star unit case, the original exponential shape and exhaustive spec refinement are retained | `glob_match_resource_spec`, `require_eval_sound`, `resource_bounds` |
| P28-A | Rewrite capture/substitution amplification multiplied its own output across ten dispatcher rounds until allocation abort | Every literal, capture, variable, escaped backreference, query append and joined target consumes `bounded_expansion_append_admit` before allocation; each rewritten path/query is capped at 64 KiB, so a later round cannot amplify an already oversized result | `bounded_expansion_append_spec`, `resource_bounds` |
| P28-B | `Require expr` concatenation could materialize hundreds of megabytes from repeated headers or 64 KiB `file()` results | Expression source is capped at 64 KiB, each value/concatenation at 1 MiB, and all values in one recursive evaluation share a 4 MiB cumulative budget. Append checks happen before vector growth and evaluation errors propagate through list membership and authorization | `bounded_expansion_append_spec`, `require_eval_sound`, `resource_bounds` |
| P28-C | Recursive access-file policy compilation had no section-depth limit, so a modest nested file overflowed the connection stack and aborted the process | The iterative `AccessProgram::seal` pass rejects nesting above 64 through `access_section_depth_admit` before recursive section parsing begins; the test constructs the first rejected depth and an overlong logical line | `access_section_depth_spec`, `resource_bounds` |
| P29-A | Access-plan execution recursed once per filesystem ancestor, and an access-file rewrite could expand a short URL into roughly 20,000 components, overflowing a blocking worker stack and aborting the process | Both verified executable plan builders are iterative with loop invariants proving the exact recursive specification. Every request plan, including rewritten and explicit filesystem targets, passes one shared 256-ancestor/512-KiB cumulative-prefix gate before policy allocation; direct reference evaluation retains the same fail-closed boundary. Oversized client paths receive `414` and the original rewrite exploit remains a live-process regression | `access_plan_interleaves`, `policy_path_work_spec`, `resource_bounds` |
| P29-B | Every missing static target ran CGI `PATH_INFO` prefix discovery, rebuilding and probing all decreasing prefixes for quadratic work even when CGI was impossible | Configuration load computes a conservative CGI/PATH_INFO capability bit across nested rules, vhosts, rewrites and access-file eligibility. Static-only requests skip prefix discovery; CGI-enabled searches mutate one path buffer, enforce the shared component ceiling and debit each kernel probe's prefix length to the fail-sticky request budget. The 4,080-component replay falls from roughly 39 ms to about 0.25 ms CPU/request in the release harness | `policy_path_work_spec`, `resource_bounds` |
| P29 follow-up | Similar input-length recursion and unmetered prefix work remained outside the two reported paths | Verified authority parsing, rewrite-chain skipping, `RequireNone` combination, byte comparison and condition-chain execution are iterative refinements of their recursive specifications. Main configuration nesting is rejected above 64 and request rule traversal uses explicit worklists without repeatedly cloning nested subtrees. Cache admission relies on the compiler-enforced base-scope-only `CacheEnable` grammar instead of recursively rescanning rules. HTTP/FastCGI prefix and regex route scans plus FastCGI filesystem-prefix probes consume the shared request budget and path bound. HTTP/2 rejects an oversized `:authority` before authority parsing | `config_section_depth_spec`, `cache_base_scope_only_sound`, `h2_field_size_spec`, `resource_bounds` |
| P30-A/A′ | A stalled HTTP/1 response over 64 KiB held one of 32 process-wide blocking-I/O permits for its whole socket lifetime; exhausting them replaced every other large HTTP/1 response with 503 and rejected all HTTP/2 dispatch, including tiny files | The permit API is now named and scoped specifically to a short response-body descriptor read. HTTP/1 socket waits never acquire it; HTTP/2 dispatch runs in the already bounded blocking pool under process/per-client stream quotas; HTTP/2 waits for flow-control capacity and holds a permit only around the subsequent file/stream read. Saturation regressions prove unrelated large HTTP/1 and small HTTP/2 responses remain 200 while all descriptor-read permits are occupied | `response_body_read_lease_spec`, `resource_budget_admit`, `connection_admit`, `resource_bounds` |
| P30-B | A client application could read periodically without making the server's already-multi-megabyte unsent queue cross Linux's default writable threshold, so the server observed no write progress and expired at `Timeout` | Plain and TLS HTTP/1 transports apply a 64 KiB `TCP_NOTSENT_LOWAT`: once the peer consumes queued data and advertises receive-window capacity, readiness wakes and the next write renews the deadline. The existing no-reader regression still requires timeout, while a socket-option regression fixes the kernel progress-wakeup boundary. Unsupported transports retain the explicit deadline as a fail-safe | `resource_bounds` |
| P31-A | Eight sources could retain all 256 process-wide HTTP/2 stream slots indefinitely by granting one response byte per `Timeout`, causing every unrelated H2 stream to be refused before dispatch | A cumulatively flow-control-blocked output transfers exactly once from the general stream pool into a 128-process/32-per-client slow-response pool; rejected transfers reset and release their general slot. The per-client share preserves one complete advertised H2 connection for a legitimate slow peer while limiting it to one quarter of the reserve. Slow progress is measured from the original response start against an anchored minimum average rate, and an absolute 16-send-interval ceiling cannot be renewed by WINDOW_UPDATE. The 8×32 lease-handoff regression proves all general slots become available and a fresh source is admitted while holders remain | `slow_output_phase_step_spec`, `minimum_progress_rate_spec`, `resource_budget_admit`, `resource_bounds` |
| P33-A | MultiViews selected a sibling representation after the trailing-slash file check and retained the missing extensionless URL as its policy identity, bypassing exact/extension `Location` and per-directory rewrite guards | Trailing-slash spellings are rejected before negotiation. A selected sibling receives a decoded canonical `/name.ext` policy identity used for `Location`, candidate filesystem/access-file, resolved-inode authorization and per-directory rewrite fixups; only wire outputs such as `Content-Location` are percent-encoded. That policy is conjoined with the public URL scope. Deny/gone/redirect outcomes are honored, sink-changing rewrites fail closed, and the existing dynamic-handler refusal remains after the selected-name bind. Shared-cache planning consumes the same selected scope/rewrite transition and binds lookup/store to the selected URL and resolved target, so a hit cannot retain the missing public identity. Unit and Apache differential regressions cover direct and alias slash cases, extension `Location`, access-file rewrite, `<Files>`, cache binding/live policy, MultiViews-off, redirect, decoded names and handler refusal | I11 transform reauthorization; I57 decoded policy identity; `multiview_candidate_spec`, `multiview_authorization_meet_spec`, `multiview_cache_binding_spec` |
| P34-A | MultiViews and autoindex synthesized authorization paths with wire percent-encoding, so decoded-spelling `Location`/`LocationMatch` guards missed names containing spaces, non-ASCII or literal `%` while direct requests were denied | `CanonicalTarget::from_selected_child` is the single typed constructor for implicitly selected filesystem children. It admits only valid UTF-8, exact canonical decoded paths; MultiViews dispatch, cache planning and per-entry autoindex authorization consume that identity. Invalid names fail implicit selection closed. Percent encoding remains only at `Content-Location` and listing-link serialization. A 12-case Apache differential plus Rust constructor, MultiViews and autoindex tests cover decoded and encoded mirrors, space, non-ASCII, literal `%`, alias, `<Files>` and rewrite controls | I57 decoded policy identity; I11 transform reauthorization |
| P35-A | `.htaccess` dropped a physical comment before applying backslash continuation, so a `#\` line could expose a grant or handler section that Apache comments out or rejects | Main configuration and access files now share one continuation-first logical-line assembler; only complete logical lines are filtered as blank or comments. Sealing therefore sees Apache's exact directive/section stream and rejects a hidden handler's unmatched close. Unit and seven-case live Apache regressions cover hidden/chained grants, a hidden CGI section, plain controls and the main-config control | I7 fail-closed malformed access files; I29 access-file disposition closure |
| P35-B | The PCRE2 translation kept greedy `\S`/`\N` repetitions backtrackable before `\R`/`\v`, while PCRE2 auto-possessified them; an obs-text NEL byte inverted a negated ACL guard and allowed a request Apache denied | The compatibility gate rejects unrepresentable `\S*`/`\S+`/`\N*`/`\N+` sequences immediately followed by `\R`, `\v` or `\h`, including nested/alternative shapes and adjacency hidden by PCRE comments or extended-mode whitespace. Simple line atoms remain supported and oracle-equivalent. Crate tests cover the full fail-closed family; the live differential requires Apache acceptance, Vapache configuration rejection and agreement on the simple `\v` control | `regex_dialect_admit`; `expr_regex_result` |
| P36-A | Main-config and per-directory internal rewrites preserved a trailing slash in the URL but passed that spelling as the slash-free mapping identity; `CanonicalTarget::from_normalized` rejected the pair and request-reachable `expect` calls aborted the release process | Rewrite canonicalization returns one `CanonicalTarget` containing both identities, so callers cannot assemble a mismatched pair. Per-directory URL-translation restarts retain the slash in the synthetic request while mapping with the normalized bytes. WebSocket request identity validation also fails closed rather than unwrapping. Unit dispatch and six-case live regressions cover main config, guarded/missing targets, attacker-written `.htaccess`, root and no-slash controls | I11 transform reauthorization; I57 decoded policy identity |
| Post-P31 slow-output generalization | HTTP/1 partial writes could renew `Timeout` indefinitely while retaining established-connection, dynamic-backend, response-memory and spool capacity; long-lived WebSockets also retained both their dedicated tunnel slot and general HTTP/1 connection admission | HTTP/1 writability and HTTP/2 flow control now use one irreversible general-to-slow ownership transition, common 128-process/32-source pool, anchored minimum rate and absolute lifetime. Dynamic slots and retained response/spool resources transfer to slow sibling pools; slow spools are capped at one quarter of the configured general pool. A classified HTTP/1 connection closes after output. WebSockets acquire their dedicated lease before surrendering general connection capacity. Deterministic saturation, cancellation, byte/file transfer, and live upgrade tests pin the complete handoff | `slow_output_phase_step_spec`, `minimum_progress_rate_spec`, `resource_budget_admit`, `resource_bounds` |
| Post-P30 lease/fairness review | The same client-controlled-wait pattern remained in adjacent pools: an H2 client-limit rejection could retain a process stream slot while sending 503; retained response memory and shared spool files had only global caps; queued H2 responses released resident or stream admission when enqueue returned even though h2 still owned the head, body, or EOS state; an ownership-carrying header could be retained in the HPACK dynamic table; expanding Huffman output and retained scratch were not separately bounded; response reads, slow-body workers and `RewriteMap prg` helpers lacked source fairness; H2 used absolute response/idle lifetimes; parsed `MinRate` values did not constrain bodies | H2 acquires the validated effective-client slot before the process slot and resets immediately on either admission failure. Retained response memory is capped at 32 MiB per client, response reads at 8 per client, and every spool client at one quarter of the configured byte/file pool; dynamic allocations inherit client identity at creation. Compression/CGI/autoindex leases shrink from peak work to retained representation. Every queued response carries resident ownership in a never-indexed head field and transfers its general or slow-output admission into shared head/body/EOS ownership until h2 consumes or discards the final object. HPACK uses raw strings when Huffman is not shorter, drops scratch above 160 KiB, and established H2 transports carry a separate dependency-buffer charge. Reset/drop tests, outbound H2 fuzzing, queued-owner and scratch telemetry cover the release paths. Slow-body and program-map pools reserve three quarters for other sources. P31 subsequently replaced renewable H2 capacity-grant deadlines with an anchored minimum rate, absolute response ceiling and source-fair slow-output pool; connection idle timeout still applies only with no active stream. Header/body and H2-body `MinRate` checks run inside, and never extend, their hard absolute read deadline | `h2_process_slot_spec`, `slow_output_phase_step_spec`, `minimum_progress_rate_spec`, `resource_budget_admit`, `connection_admit`, `resource_bounds` |
| Post-P28 DoS review | Capture expansion, polynomial glob rectangles, many individually cheap policy operations, wide access programs and native response heads still lacked one complete resource model | Request clones share a fail-sticky 16 Mi-unit work/4 MiB expansion meter; capture and dynamic-require output is admitted before allocation; every request-time glob debits its exact DP rectangle; access files have per-file, per-request and layer ceilings; response policy and both protocol writers enforce 256-field/128 KiB head limits and charge heads to the aggregate response-resident budget. The CVE-2011-4415 triage now names the concrete prevention instead of attributing memory consumption to Rust memory safety | `glob_match_resource_spec`, `bounded_expansion_append_spec`, `access_program_budget_spec`, `response_header_budget_spec`, `resource_bounds` |
| Post-P28 connection DoS review | Incomplete H2 prefaces had no deadline; pre-header sockets immediately consumed OS threads; one ready listener could be drained before another; trusted proxies bypassed downstream HTTP/1 worker identity; large WINDOW_UPDATE frames cost no control tokens | TLS and first-head admission now run in a bounded async pre-request pool; H2 preface, initial SETTINGS and first head share the request-header deadline; established HTTP/1 workers are charged to the validated effective client, slow bodies and idle keep-alive leave worker reserves, and stalled writers retain only that client-scoped worker until their write deadline; ready listeners rotate with a 64-accept batch; every WINDOW_UPDATE consumes a verified control token | `h2_control_event_step`, `connection_admit`, `resource_bounds` |
| Exhaustive connection/resource DoS follow-up | Later keep-alive bodies bypassed the slow-body reserve; TLS handshakes, log expansion/writers, `RewriteMap prg:` helpers, per-connection OS threads, the useful WINDOW_UPDATE bucket and recursive disk-cache walks retained independent multipliers | Body admission now runs after every parsed head; TLS has concurrent/per-source/rate ceilings; log lines and non-queuing writers are bounded; program maps have per-request/concurrent/rate gates; H1 uses a reusable pool with a 512-worker implementation ceiling; H2 transfer updates use a 4,096 burst and 2,048/s; cache walks stop at depth 32/32,768 records and invalidate by epoch on an incomplete scan | `escape_log_bytes_bounded`, `connection_admit`, `h2_control_event_step`, `resource_bounds` |
| Systematic vendored-h2 DoS follow-up | Frame families that were discarded or rejected before the semantic connection loop could bypass its event bucket, fixed-shape frames reached payload reservation before rejection, fragmented header blocks and Huffman decoding had separate growth/work paths, signed flow-window updates relied on dependency-local arithmetic, and delayed reset expiry had no executable single-use model | The fork admits every nine-byte frame head before payload reservation; charges all frames, including unknown and CONTINUATION traffic, to one verified work bucket; bounds cumulative encoded blocks and Huffman allocation/work; routes signed window changes through checked verified kernels; and advances reset expiry only `Untracked -> Queued -> Reclaimed`. A structured stateful fuzzer generates valid-preface multi-frame sequences across headers, continuation, settings, flow control, reset, priority, ping, unknown, data and GOAWAY paths | `h2_frame_header_admit`, `h2_frame_work_step`, `h2_header_block_step`, `hpack_huffman_decode_bounds`, `h2_signed_window_increase`, `h2_reset_expiry_step` |
| Additional | `Require not valid-user` dropped negation; non-HTTP control bytes passed header serialization; `close, keep-alive` re-enabled a connection; mmap allowed other-owner write races | Negation is carried into `Require::ValidUser`; header values admit only HTAB/SP/VCHAR/obs-text; `close` is sticky; the HTTP/2 mmap response path is removed in favor of bounded positional reads | I23, I33-adjacent |

## Additional hardening before the next pass

The first closure pass also made the following classes explicit in the model:

- alias and redirect mappings are one ordered table, so a later overlapping
  mapping cannot beat an earlier one (matching Apache's first-match behavior);
- handler operations are ordered, so `RemoveHandler` cancels an inherited
  `AddHandler`;
- response-header policy is applied to directory redirects and rewrite/redirect
  responses as well as static/CGI/proxy/error responses;
- the debug scope-merge audit now covers the separate `Header always` lists and
  child `set` replacement rather than assuming every header list appends;
- `%{SERVER_NAME}` uses the dispatcher-selected canonical name, not a raw Host
  lookup, and `UseCanonicalName DNS` conservatively uses `ServerName`;
- `ProxyPass`/`ProxyPassMatch` exclusions are rejected instead of silently
  ignored;
- trusted request context (scheme, peer, canonical name, identity) is separated
  from attacker-controlled forwarding headers in I16;
- a failed containment proof is a mapping failure, never a fallback to the
  target's parent directory (I25);
- an alias, rewrite or FastCGI mapping cannot change the base used by the
  authorization walk, even when a compatibility flag opts into a wider stat
  check;
- the cache key includes every header an expression or environment rule can
  read and the complete material of every `Scope` policy slice, so neither
  header-selected nor policy-selected branches can share an entry; the
  rewrite-map `HashMap` is canonicalized before hashing (I26);
- authenticated identity is a resolved-context field that follows the request
  into CGI/FastCGI rather than being dropped at the script boundary (I27);
- configuration-derived upstream text passes the same serialization
  predicates as native response headers (I28);
- every recognized `.htaccess` directive has one explicit disposition and an
  `AllowOverride` category in an authoritative registry; an exhaustive test
  matrix proves effectful directives change the scope, inert directives leave
  it unchanged, rejected directives fail, and every entry is gated by
  `AllowOverride None` (I29);
- rewrite-condition file tests (`-f`, `-d`, `-s`, `-l`) canonicalize both the
  document/alias root and the probed path before consuming the verified
  component-aware containment kernel, so an in-root symlink cannot become a
  metadata oracle for an outside file;
- the cache key's hex encoder is refined to a recursive byte-exact spec and
  proved injective; store admission is split into verified request/status/
  Cache-Control/response-shape/TTL predicates, freshness clamps cannot panic on
  reversed bounds, expiry is saturating, disk projection/eviction arithmetic
  is mechanized, and cache-policy binding uses verified length framing plus a
  256-bit SHA-256 digest instead of a 64-bit `DefaultHasher` fingerprint
  (I51, I54);
- the transform inventory is closed and every target-changing operation
  reauthorizes both the original request context and the current target,
  binding the sink grant to that target; query-only rewrites and `[E=...]`
  effects are included in the original-URL recheck (I30);
- CGI/FastCGI execution uses the selected script as the authority for
  containment, authorization, inode/backend binding and environment; the
  FastCGI target overwrites `SCRIPT_FILENAME`, `SCRIPT_NAME`, `PATH_INFO` and
  `PATH_TRANSLATED` exactly once, and authenticated identity is exported
  (I31);
- prefix and regex proxy routes share one order space; balancer authorization
  covers both logical and concrete identities, and failover replaces the
  grant/resource pair atomically before sending to the next member (I32);
- every untrusted stream has an explicit byte/count/deadline bound, with
  chunk arithmetic checked before allocation and trailers bounded on both the
  request and proxy sides (I33);
- main-configuration directives are handled, explicitly warned as inert
  presentation/module-absence, or fail closed; security, filter, audit and
  resource-limit directives can no longer disappear into the compatibility
  warning path, and strict mode rejects every unhandled directive (I34).

## Pass 12 closure

The confirmed cases in `adversarial/findings_p12.md` are closed as follows:

- Proxy and FastCGI prefix routes share a verified component-boundary matcher;
  trailing-slash routes match children, and `/` remains the root catch-all.
- Handler selection tokenizes every real filename extension, rejects dotless
  and all-dot basenames, normalizes exactly one configured leading dot, and
  gives a matching `RemoveHandler` precedence independent of directive order.
- `ScriptAlias` CGI classification after `PATH_INFO` splitting uses the
  effective handler policy, so `SetHandler default-handler` cannot be bypassed
  by appending a suffix.
- HTTP/2 request bodies use one whole-body deadline and explicitly return
  consumed flow-control capacity; responses wait for send capacity, including
  bodies larger than the initial window.
- `AuthType` without an effective `Require` is a fail-closed configuration
  state and produces a server error even under `Satisfy any`.
- Streamed proxy responses pass through the same response-header policy as
  buffered responses before dispatch returns them.
- A standalone `[BNE]`/`[BNE=...]` rewrite flag now activates backreference
  escaping while excluding only the configured bytes.
- The pinned HTTP/2 parser rejects a missing `:path` and fragment-bearing
  pseudo-target before `http::Uri` can normalize either shape; the adapter's
  verified gate additionally requires non-CONNECT scheme, authority and path
  identity.
- CGI rejects informational status responses and strips framing, hop-by-hop
  and `Connection`-nominated response fields before server framing is chosen.
- Unknown expression variables and malformed/lowercase `Require method` or
  comparison-shaped `Require env` operands fail closed at configuration load.
- Multiple `AccessFileName` entries select the first existing candidate, and
  `FileETag None` emits no entity tag while preserving wildcard preconditions.
- `RewriteMap prg` runs in a separate process group with a whole-operation
  deadline and an 8 KiB result limit; timeout, overflow and worker failure
  produce no substitution. Its executable is copied from one stable descriptor
  into a sealed memfd at configuration load; each lookup verifies that the
  configured pathname still names the original inode/version and executes the
  immutable snapshot, so rename and same-inode replacement both fail closed.
- Disk cache metadata carries the complete V4 key, lookup verifies the exact
  key rather than trusting a SHA-1 filename, and unsafe-method invalidation is
  canonical and prefix-targeted rather than flushing unrelated entries.

These decisions are backed by new Verus admission kernels and refinement tests.

## Pass 13 closure

The three handler-identity RCE paths in `adversarial/findings_p13.md` are
closed by making I70 a pipeline-wide invariant rather than a single direct
dispatch assertion:

- FastCGI receives the already-bound lexical basename and sends the lexical
  split path as `SCRIPT_FILENAME`; the canonical opened path is used for
  containment, authorization and inode binding. P15 strengthened this rule
  after showing that sending the canonical name bypassed PHP-FPM's own gate.
- CGI `PATH_INFO` classifies the longest existing lexical prefix, while the
  opened canonical script still supplies the executable inode and access
  identity.
- Resolved-target evaluation derives canonical authorization and lexical
  handler scopes from one immutable `RequestPlan` and access-layer set.  Only
  `handlers` and `set_handler` are copied from the lexical Files phase, so a
  canonical-only `<Files>`/`<FilesMatch>` force cannot arm execution while a
  canonical Files `Require` denial still binds.
- `handler_scope_lexical_admit` mechanizes the scope-force obligation and the
  five P13 regressions cover FastCGI, PATH_INFO, Files-scoped SetHandler,
  canonical Files denial and live Location controls.

The Verus gate now proves 433 functions with zero errors. The `.htaccess`
admission seam is also executable proof code: `override_mode_allows` decides
category bits, while `htaccess_gate_admit` ensures only a known, policy-allowed
directive or section can reach the effectful parser; `Nonfatal` can only turn a
rejection into a skip.

## Pass 14 closure

The five phase, rewrite, expression and request-head findings in
`adversarial/findings_p14.md` are closed as follows:

- The verified Files plan now applies main-config and access-file
  `<Files>`/`<FilesMatch>` layers in root-to-leaf directory-depth order, config
  first at each depth. Deeper operator policy therefore outranks a shallow
  writable `.htaccess`, while same-directory access-file precedence is kept.
- `[P]` template admission consumes `rewrite_template_static`, whose model
  recognizes every spelling accepted by the runtime expander (`$N`, `%N`,
  `\N`, `${...}` and `%{...}`). Request-derived authorities fail at load time.
- Config compilation copies the effective default or explicit DocumentRoot
  into the global scope and inherited vhosts. Expression file tests have no
  `/` fallback; an unbound synthetic scope fails closed.
- HTTP/1 duplicate field lines are merged, in arrival order, only after the
  verified raw framing checks. `header_merge_index` proves that the selected
  slot is the exact canonical name and has no earlier match; duplicate Host
  remains a parse error.
- A failed `[C]` chain uses the verified `rewrite_chain_resume` decision to
  skip every remaining chained rule and its first non-chain action. Three-rule
  unit coverage and live P14 replays pin both failing and passing gates.
- The follow-on refinement makes every Directory and Files plan step name its
  exact depth and provenance (`Config` or `Access`), and the runtime consumes
  those steps directly. Rule kind-to-phase, deferred-slot selection and the
  recursive nested-rule comparator are likewise executable Verus decisions.
- Rewrite evaluation now uses one verified token alphabet for expansion and
  template admission, one staged matched/unmatched action, and one bounded
  program-counter transition for `[S]`, `[N]`, `[L]` and `[END]` after both
  `-` and internal substitutions. This also pins `RewriteRule ... - [END]` as
  a final pass.

The Verus gate proves 433 functions with zero errors. Seven P14 replay cases
cover the deeper Files deny/auth/handler/Options variants, implicit-DocumentRoot
file oracles, duplicate-header guards and full rewrite-chain skipping; parser
and verified-kernel tests cover every dynamic proxy-authority spelling.

## Pass 15 closure

The three component-semantics findings in `adversarial/findings_p15.md` are
closed as follows:

- FastCGI now keeps two script identities. The lexical `PATH_INFO` split path
  is sent to the backend as `SCRIPT_FILENAME`, matching Apache and preserving
  PHP-FPM's `security.limit_extensions` decision. The opened canonical path is
  retained for containment, authorization and inode binding. A final lexical
  reopen must still name that inode before parameters are emitted. When the
  canonical target is under `DocumentRoot`, its canonical URL scope is also
  authorized, so a symlink cannot bypass a target `<Location>` guard.
- `RemoteIPTrustedProxy` and `RemoteIPInternalProxy` retain distinct proxy
  classes. Header processing walks right to left, stops on invalid or empty
  values, permits the one-way internal-to-external transition, and rejects the
  private, loopback and link-local address ranges that Apache refuses once the
  chain is external. IPv4-mapped IPv6 values are canonicalized before this
  decision. VApache deliberately remains stricter than Apache when no trust
  list exists: a header alone never authorizes address rewriting.
- Expression regexes compile through the in-tree PCRE2 compatibility frontend
  when configuration is loaded. Regular P15 constructs retain Apache meaning;
  backreferences and other recursive-backtracking features are rejected at
  load time. Any later resource error is fail closed: `Require expr` denies,
  rewrite evaluation errors stop the rewrite, and conditional configuration
  records a misconfiguration that cannot silently remove an ACL, handler or
  Options guard.

The production code consumes Verus kernels for the expression error result,
RemoteIP proxy transition/candidate admission and dual FastCGI identity. Five
P15 end-to-end regressions cover the exploit shapes, and the Apache differential
suite now includes fixed PCRE and RemoteIP cases plus 128 deterministic
generated ACL cases in the normal coverage gate. The broader parity process and
the import boundary for a future extracted Apache model are documented in
`docs/apache-access-parity.md`.

## Post-P16 pre-pass hardening

The four follow-up hardening items are closed before the next adversarial pass:

- HTTP and WebSocket upstream request heads and response headers remain byte
  vectors through validation and serialization. Raw query and obs-text header
  bytes are forwarded exactly; no proxy boundary uses lossy UTF-8. CGI exports
  the raw query as a Unix byte-string environment value as well.
- Main configuration, included configuration, `TypesConfig`, access-file
  contents and every filesystem identity admitted to a `RequestPlan` must be
  valid UTF-8. Invalid bytes fail configuration loading or request planning;
  access control never operates on a replacement-character projection.
- Canonical/rewrite target scope restriction now carries content and tagged
  environment policies from both the selected target and the URL identity,
  with the URL policy applied last. Symlink differential fixtures pin content
  type and authorization-visible environment behavior.
- SHA-1 and MD5 moved to their maintained 0.11 digest stack, eliminating the
  vulnerable `block-buffer` 0.10 line, and TLS PEM loading moved to
  `rustls-pki-types`, removing the unmaintained `rustls-pemfile` dependency.

The new textual-identity executable gate and rejection lemma are verified by
Verus. Runtime regressions cover invalid UTF-8 config, MIME, access-file and
filesystem identities, byte-exact proxy/WebSocket forwarding, CGI query bytes,
and the cross-identity scope merge.

## Pass 17 and 18 closure

The two post-P16 adversarial findings are closed at their shared identity and
admission boundaries:

- P17's resolved-file `SetHandler` path now constructs `SCRIPT_FILENAME` from
  the lexical request mapping. The canonical descriptor path remains the
  authorization, containment and inode-binding identity and is never reused as
  the backend spelling. A private `LexicalScriptPath` field forces every
  FastCGI target constructor to make that choice explicitly; the pre-send
  lexical reopen still has to resolve to the authorized inode.
- P18's section admission is centralized before section parsing. `<Files>`,
  `<FilesMatch>`, `<If*>`, `<Require*>`, `<Limit*>` and execute-on-read
  conditional wrappers each require their Apache category mask or an exact
  `AllowOverrideList "<Section"` entry. A listed child such as `Require` cannot
  admit its wrapper. `Nonfatal=Override` may skip the whole rejected section,
  but no rejected section reaches the effectful parser.

`fastcgi_resolved_target_admit` and `htaccess_section_admit` add executable
Verus gates plus fail-closed lemmas. Runtime coverage includes the P17 fake
FastCGI parameter oracle, the retained inode-binding controls, exhaustive
section-family unit cases, six Apache differential cases, and the P18 CGI
remediation battery with both exploit and `AuthConfig` parity controls.

## Post-P18 pre-pass hardening

Four additional attack surfaces are closed before the next adversarial pass:

- `VapacheFastCGIStablePath` is repeatable and keyed to one exact Unix socket.
  FastCGI requires an exact policy by default, rejects every unregistered
  backend, authenticates the socket by type, owner and inode before and after
  connect, and rejects TCP because a loopback address does not authenticate
  the process that owns it. `UnstableFastCgiPaths` is the explicit,
  process-global escape hatch for deployments that accept the external
  pathname race and enforce an equivalent immutable-tree invariant.
- Stable script and socket paths reject POSIX ACLs as well as backend-owned or
  group/other-writable components. Concurrent atomic-swap tests exercise both
  the final FastCGI inode binding and the access-file descriptor/pathname
  snapshot check rather than assuming a quiescent filesystem.
- Shared RAII budgets bound spool bytes, spool files and concurrent CGI plus
  FastCGI requests across graceful reloads. Request bodies, FastCGI responses
  and the CGI worker's duplicate body copy reserve and release from the same
  counters; FastCGI output also has a per-request ceiling.
- LibFuzzer entry points cover HTTP request framing and fragmentation, full
  configuration compilation, access-file walks, rewrite expressions, CGI,
  FastCGI and proxy responses, raw and structured-state HTTP/2 traffic, cache
  metadata, TLS policy and OCSP DER. The fail-closed pre-pass compiles and
  smoke-runs all 18 targets;
  scheduled campaigns retain corpora and crash artifacts.

`resource_budget_admit` adds an overflow-safe executable Verus admission gate
with bounded and exhausted proofs. Focused runtime tests cover exact endpoint
registration, socket replacement metadata, ACL rejection, reservation
exhaustion/release and reload-shared accounting.

## Pass 18-B through 20 closure

The remaining Pass 18 configuration differentials and both resource-exhaustion
passes are closed at their shared phase and accounting boundaries:

- P18-B1 access-file `<IfFile>` is now an execute-on-read construct. Relative
  operands resolve against `ServerRoot`, the result is frozen while the access
  file is parsed, and admitted children are spliced with their own phase
  identities. A wrapped directory grant therefore cannot jump past a later
  `<Files>` or `<Location>` denial. `iffile_exec_on_read_admit` pins both the
  absolute path binding and child-phase retention.
- P18-B2 selected proxy and FastCGI routes must first pass a scope rebuilt from
  operator configuration only. The access-file scope is still evaluated and
  may narrow the result, but it cannot supply the grant that authorizes a
  `ProxyPass`/`ProxyPassMatch` sink. `proxy_operator_acl_admit` is consumed at
  that boundary.
- P19 gives the resident cache its own `CacheMaxMemorySize` byte ceiling
  (64 MiB by default). Accounting includes key, body, response headers, Vary
  material and fixed entry overhead; replacement and oldest-entry eviction
  happen under the cache mutex. Bodies above 64 KiB are disk-only, zero
  disables the memory tier, and hits clone an `Arc<Entry>` under the lock
  instead of copying the retained body. `cache_memory_admit` proves each
  insertion fits without overflow.
- P20 makes HTTP/1 and HTTP/2 consume the same incremental body accumulator.
  Fixed HTTP/1 bodies no larger than 1 MiB remain resident; known-larger,
  chunked HTTP/1 and HTTP/2 bodies provide at most a 64 KiB prefix before
  spilling to the shared unlinked-file tier. The lease reserves
  only bytes actually received, is acquired only when a body crosses the
  threshold, and is released exactly on completion or error. Exhaustion emits
  `503` instead of dropping the connection. HTTP/2 concurrency is reduced to
  32 streams and `request_body_memory_admit` proves each resident-prefix
  extension remains within its allowance.

The adjacent DoS review also removed three amplification seams: empty and tiny
chunked requests no longer consume spool-file slots, a large fixed-length
declaration plus token data must cross the 64 KiB actual-byte threshold before
it consumes a file slot, and request headers,
body chunks and trailers are all governed by hard absolute deadlines rather
than deadlines extended by attacker-supplied byte counts. Request-time
expression `file()` reads now reject non-regular descriptors, open
nonblocking/no-follow and stop at 64 KiB, so a FIFO or large attacker-selected
file below DocumentRoot cannot pin a worker or multiply heap by the worker
count. The HTTP framing
fuzzer now varies aggregate byte/file quotas, including zero, and asserts that
fragmentation produces the same result and every lease returns to zero. Unit,
adapter and property regressions cover byte-accurate accounting, release on
failure, HTTP/1 `503`, HTTP/2 spill exhaustion, cache eviction, proxy ACL
provenance and `<IfFile>` phase order. Verus verifies 486 functions with zero
errors.

## Post-P20 denial-of-service hardening

The follow-up resource review closes cross-connection multipliers that a
per-request limit cannot contain:

- one `ResourceBudget` now caps process-wide HTTP/2 streams (256), retained
  request bytes (128 MiB), retained response bytes (128 MiB) and blocking
  response reads (32). HTTP/2 still enforces 32 streams per connection, while
  every accepted stream owns the process lease until its task exits;
- chunked and EOF-delimited proxy responses spill to the shared unlinked spool
  above 256 KiB, fixed-length bodies above that threshold stream, and every
  form is capped at 64 MiB. Spool exhaustion returns `503` without poisoning a
  balancer member; oversize responses return `502` without retrying the full
  body against every member. Local CGI stdout is capped at 8 MiB and charged
  while read and again for the parsed response copy;
- disk cache metadata is capped at 1 MiB, warm large-body hits retain only the
  file length and serve the body descriptor instead of first reading it into
  a `Vec`, and cache-store copies consume the response-byte budget. Unsafe
  invalidation occurs only after a successful 2xx/3xx response and selects
  victims from a once-per-generation key index rather than walking the cache
  tree for every rejected POST;
- autoindex counts every directory record, including filtered dot/backup and
  unreadable entries, before metadata lookup; it admits at most 4096 records
  and 4 MiB of HTML. Compression, regex matching, bcrypt/MD5 and access-file
  parsing share a 32-operation gate. Regex pattern, subject, capture and
  deterministic pattern-times-subject work, bcrypt cost, DNS resolver
  workers/queue/operands and auth, access-file and request-policy cache bytes
  are independently bounded;
- connection admission is a compare/exchange reservation with RAII release.
  Injected thread-spawn failure returns the slot, and `EMFILE`/`ENFILE` accept
  failures back off instead of hot-spinning. Proxy health-check reloads cancel
  the previous worker; active/passive observations and selection counters are
  generation-keyed, so old requests cannot consume candidate state.

The executable Verus gates are `cache_invalidation_status_admit`,
`autoindex_append_admit`, `bcrypt_cost_admit` and
`expr_regex_size_admit`, with proofs for failure and boundary cases. Unit,
fault-injection and property regressions cover process lease release,
invalidation, bounded policy caches, hidden autoindex entries, proxy
spooling/oversize responses, bcrypt extremes and connection spawn failure.

## Pre-adversarial seam hardening

The follow-up seam review closes six additional attack surfaces:

- privileged log, PID, disk-cache and OCSP paths are descriptor-walked with
  `openat2`, `RESOLVE_BENEATH` and no symlinks. OCSP cache objects are bounded
  regular files installed by verified temporary-file identity and atomic
  rename; malformed refresh data preserves the last accepted staple;
- balancer retry admission distinguishes failure before connection/send from
  an ambiguous or completed send. POST/PATCH and other unsafe methods cannot
  be replayed after an upstream attempt or `failonstatus` response, while
  idempotent methods retain failover;
- request, proxy-response, autoindex and compression working sets reserve
  process-wide bytes before allocation. The leases remain attached through
  dispatch/send and release on every error path;
- OCSP refresh workers hold only weak TLS-generation references and poll that
  liveness while waiting, so reload retires old threads within one second;
- proxy DNS is contained by eight workers, a queue of 64, 32 returned
  addresses and one absolute resolve/connect deadline (including the async
  TLS handshake used by WebSocket). Custom CA
  files are regular, no-symlink, 4 MiB-capped snapshots parsed once per policy
  generation;
- WebSocket upgrades consume one of 64 process slots and the bidirectional
  tunnel applies independent 60-second read/write idle deadlines. After a
  `101`, tunnel errors close the transport instead of injecting an HTTP error
  into the upgraded byte stream.

`proxy_retry_admit` and its two proofs pin the retry boundary in Verus. Runtime
regressions cover unsafe-method admission, TLS-policy reuse, literal resolver
bypass, WebSocket slot/idle release, OCSP object types and retired refresh
workers.

## Transform-to-sink and filesystem-race closure

The two pre-review hardening items after Pass 14 are now runtime-enforced
invariants:

- TransformCapability is an executable Verus state machine. Retargeting
  removes authorization and all concrete bindings; authorization, inode and
  backend transitions rebuild them. The proofs show that a retargeted state
  cannot reach a sink, every admitted sink was reauthorized, and file,
  backend and cache sinks carry their required binding.
- AccessGrant::require_sink projects that model at every protected static
  file, directory, local CGI, FastCGI, HTTP proxy, WebSocket and cache sink.
  Exact ResourceKey equality prevents a grant for the pre-transform target
  from being reused even when the capability bits are otherwise sufficient.
- Access-file selection opens one descriptor. Candidate identity, cache key,
  bytes, and the post-read metadata validation all come from that descriptor;
  a changed regular-file bit, device/inode, version, mode or size fails
  closed. Pathname replacement cannot substitute new policy between lookup
  and parsing.
- FastCGI script selection now opens the script below its configured base,
  reauthorizes the actual descriptor path, binds both (dev, inode) and the
  exact backend, and compares a final pathname open against the authorized
  inode after backend connection and immediately before parameters are emitted.
- `RewriteMap prg` program selection is descriptor-first too. The load-time
  source must be a bounded executable regular file and remain unchanged while
  copied into a sealed memfd. Runtime pathname identity/version changes fail
  closed, while execution uses the immutable snapshot rather than reopening
  attacker-replaceable code.

FastCGI itself cannot pass an open file descriptor to PHP-FPM. Consequently,
an external backend still opens SCRIPT_FILENAME after vapache's final
identity check. The verified deployment boundary therefore requires the script
and every ancestor directory to remain non-writable by the backend and all
less-trusted principals for the full request lifetime. Read-only release trees
meet the requirement; writable upload trees must never inherit a FastCGI
handler. A deployment that cannot enforce this is explicitly outside the
verified FastCGI boundary rather than relying on a hidden stable-filesystem
assumption.

## Pass 34 closure

P34-A is closed by separating decoded authorization identity from wire
serialization. `CanonicalTarget::from_selected_child` constructs the exact
decoded canonical path for every implicitly selected filesystem child. Both
MultiViews and `DirectoryIndex` (including cache planning), plus autoindex
entry authorization, now use that typed path; invalid UTF-8, separators and
non-canonical names are not implicitly selected. `url_encode_path` remains at
the `Content-Location` and autoindex `href` output boundaries only. The
`DirectoryIndex` conversion is preventive hardening: configuration validation
already restricted index names to valid single components, but dispatch no
longer depends on duplicate string construction or lossy conversion. The
main-config variable expansion pass also advances on UTF-8 character
boundaries, so non-ASCII directive arguments retain their exact decoded
identity instead of being double-encoded before policy compilation. Section
arguments now consume that same expansion; an undefined variable makes the
section inactive and configuration loading fails instead of silently detaching
its policy. The startup `envvars` expander preserves the identity before values
enter configuration expansion, and custom log time-format literals advance by
UTF-8 characters rather than corrupting audit text. A live matrix binds
literal, `${Define}` and environment-backed Unicode through Directory, Files,
Location and rewrite policy against percent-encoded requests and Unicode
filesystem names.

The retained Apache differential is now a fail-closed regression in the
regular pre-adversarial gate. Its 12 cases cover spaces, non-ASCII and literal
percent signs; decoded `Location` and `LocationMatch`; the encoded-spelling
mirror; alias, `<Files>` and access-file rewrite controls; and autoindex
visibility. Focused Rust tests pin the constructor, selected MultiViews URL
and decoded `LocationMatch` filtering of autoindex entries.

The follow-up hardening makes that representation split a type boundary:
`WireUrlPath`, `DecodedUrlPath` and `FilesystemName` are distinct, and policy
keys/outcomes accept only the decoded form. The decoded value has a private
inner string and descriptor-selected children must pass the single-component
filesystem-name constructor before they can become URL identities. Access
grants also carry the opaque immutable configuration-generation token, which
every authorized plan and terminal sink checks; a grant from a retired reload
generation therefore cannot authorize an otherwise identical representation.

## Pass 35 closure

P35-A is closed at the configuration front end. `logical_lines()` now consumes
`logical_lines_with_numbers()`, so a trailing backslash joins physical lines
before a complete logical line is classified as blank or comment. Main
configuration and `.htaccess` therefore cannot disagree about which directive
tokens or section delimiters exist. The hidden-grant forms remain comments;
the hidden `<Files>` opener is swallowed and its unmatched close makes the
access file fail closed, matching Apache.

P35-B is closed at configuration load. PCRE2's auto-possessification has match
semantics the automata backend cannot reproduce for greedy `\S`/`\N` classes
adjacent to `\R`, `\v` or `\h`. `validate_line_constructs()` rejects that
complete family as unsupported, including occurrences inside groups and
alternatives and adjacency obscured by PCRE comments or extended-mode ignored
text. Standalone line atoms remain accepted and checked against the test-only
C PCRE2 oracle. This deliberately chooses a narrow configuration error over a
request-time ACL truth-value difference.

## Pass 36 closure

P36-A is closed at the rewrite identity boundary. `canonicalize_rewrite_target`
returns a complete `CanonicalTarget`; its decoded URL path retains a meaningful
trailing slash while its mapping bytes use the slash-free normalized form.
Neither URL-translation nor per-directory rewrite dispatch can independently
assemble those values. A per-directory restart serializes the URL identity
back into the synthetic request, so the slash survives the next translation
round without contaminating the mapping key. Every request-derived use of the
validated normalized constructor now returns a client error instead of
unwrapping an invariant under the aborting release profile.

## Regression surface

The closure is exercised by:

- Rust unit tests for regex aliases/redirects, `RemoveHandler`, strict
  disposition, child header replacement, cache-key dimensions, cache
  generations, header-selected cache fingerprints, relative alias roots,
  negated `Require` operands, `.htaccess` environment rules, `IndexIgnore`,
  safe autoindex hrefs, alias/rewrite/FastCGI containment, proxy-head
  serialization, `.htaccess` `RequestHeader` rejection, CGI/FastCGI identity
  variables, the exhaustive `.htaccess` directive effect/category matrix, the
  cache input-closure matrix over every policy field, request header and
  listener/vhost/URL/target dimension, transform-gate replays for query-only
  rewrites and rewrite-set environment effects, CGI/FastCGI exact environment
  and script-containment cases, mixed prefix/regex plus balancer
  logical/concrete proxy identity cases, main-config directive disposition
  cases, framing/trailer/record-limit cases for HTTP, proxy and FastCGI,
  transform sink-binding progression, access-file descriptor/cache mutation,
  FastCGI script inode replacement and missing/non-file script targets;
- `tests/conformance.py`, `tests/config_semantics.py`,
  `tests/config_validity.py` and `tests/config_grammar.py`;
- `tests/adversarial_regressions.py`, which starts fresh servers and replays
  the F23–P18 exploit shapes (rewrite-to-proxy/redirect authorization, cache
  reload plus PATH_INFO, relative and capture-only aliases, autoindex schemes,
  negated/env providers, `IndexIgnore`, `DirectorySlash Off`,
  `UnsafePrefixStat` re-rooting, header-selected cache entries,
  `.htaccess` `RequestHeader`, CGI `REMOTE_USER`/`AUTH_TYPE`, single-file
  aliases, `<Limit>` `Options`, symlinked CGI/FastCGI targets,
  capture-only `AliasMatch`, expression file-test confinement,
  multi-provider `<RequireNone>`, regex alias file targets, address-bound
  vhosts, IPv4-mapped peers, ancestor `.htaccess` above `DocumentRoot`/an alias
  target, overlapping `Alias`/`ScriptAlias`/`AliasMatch` roots,
  `DirectoryIndex` cache-target/query/live-policy changes, canonical
  `REQUEST_URI` query/encoding/dot-segment policies, document-root/ancestor
  rewrite subjects for alias and alias-match targets, explicit-target
  access-layer binding for symlinked document roots and aliases,
  the pass-10 resolved-target/rewrite scope-conjunction cases for plain
  `<Directory>` policy, in-root symlinks, ancestor access files,
  `RemoveHandler`, `AllowOverride None`, and rewrite laundering, and the
  H2 regressions: `[PT]` passthrough targets stay in URL space (F67), the
  sticky per-round filesystem override is replaced by a later URL-only
  `[L]` rewrite (F68), and `[UnsafePrefixStat]` logs its inertness warning
  at load time);
- `tests/config_validity.py` `MALFORMED_CASES` rows (H8: malformed
  `AddType`/`AddHandler`/`Header`/`ExpiresByType`/`ProxyPass` arities,
  unknown `Options` and `RewriteOptions` tokens, and unparsable
  `ProxyPass`/`ProxySet` `failonstatus` lists are refused in every mode when
  Apache rejects them at `-t`);
- `tests/config_validity.py` `HARDENED_CASES` rows record ambiguous legacy
  coercions that Apache 2.4 accepts (`Options` with no operand, nonnumeric
  numeric directives, non-error `ErrorDocument`, malformed expiry text and
  extra `<IfFile>` words, plus `<Files>` nested inside request-time `<If>`
  whose child policy Apache does not evaluate on ordinary direct requests) but both Vapache modes
  deliberately reject; the latter Apache parser/runtime mismatch is documented
  in `adversarial/apache-if-files-nesting.md`;
- operator replay harnesses that reproduce the Apache-versus-vapached
  differentials in `adversarial/findings.md`, plus the repaired P34 synthesized
  identity differential in `adversarial/p34/exploit_p34.py`, the repaired P35
  access-file/PCRE2 gates in `adversarial/p35/`, and the P36 trailing-slash
  rewrite process-survival differential in `adversarial/p36/`.

Any new directive that changes a request-to-resource mapping, cache key,
handler selection, authorization identity or inherited descriptor must state
which of I9–I71 it preserves.  A directive that is recognized but not
implemented is not allowed to pass as “inert” unless that disposition is
explicit and local to the directive (a `Location` pattern that cannot be
represented is a configuration error, never an inert literal scope);
request-mutating directives such as `RequestHeader` are never inert.
