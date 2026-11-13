# Coverage

Snapshot: 2026-10-26, after the pass-8 F57–F58 hardening and 100%
production-line closures for access control, CGI, configuration parsing,
dispatch/server, the expression engine, FastCGI, `.htaccess`, HTTP/1.1, the
HTTP proxy, rewrite execution and TLS:
canonical query-free `%{REQUEST_URI}` identity for expressions, rewrite
conditions, substitution expansion, environment rules and CGI, plus
filesystem-relative access-file rewrite subjects for document-root and
ancestor layers above the mapping root.

```

Filename                          Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
server/src/access.rs                 1832                16    99.13%          74                 1    98.65%        1031                 5    99.52%           0                 0         -
server/src/auth.rs                    445                40    91.01%          20                 3    85.00%         243                20    91.77%           0                 0         -
server/src/cache.rs                  3524               369    89.53%         208                23    88.94%        2366               204    91.38%           0                 0         -
server/src/cgi.rs                    3155               210    93.34%         163                35    78.53%        1837                82    95.54%           0                 0         -
server/src/compression.rs             750                79    89.47%          39                 1    97.44%         418                42    89.95%           0                 0         -
server/src/config.rs                12139               247    97.97%         433                14    96.77%        7953                80    98.99%           0                 0         -
server/src/config_frontend.rs         366                23    93.72%          10                 1    90.00%         218                16    92.66%           0                 0         -
server/src/expires.rs                 257                29    88.72%          20                 0   100.00%         159                19    88.05%           0                 0         -
server/src/expr.rs                   2321                83    96.42%          98                12    87.76%        1144                12    98.95%           0                 0         -
server/src/fastcgi.rs                2437                52    97.87%          89                 6    93.26%        1398                15    98.93%           0                 0         -
server/src/files.rs                  1421               252    82.27%          63                 7    88.89%         837               128    84.71%           0                 0         -
server/src/h2.rs                     1327               258    80.56%          59                14    76.27%         755               139    81.59%           0                 0         -
server/src/htaccess.rs               4153                65    98.43%         113                 9    92.04%        2619                18    99.31%           0                 0         -
server/src/http.rs                   2336               151    93.54%         118                 8    93.22%        1552                93    94.01%           0                 0         -
server/src/log.rs                     768               152    80.21%          41                 8    80.49%         490                75    84.69%           0                 0         -
server/src/main.rs                   1196               339    71.66%          47                11    76.60%         742               260    64.96%           0                 0         -
server/src/ocsp.rs                    744               159    78.63%          28                 4    85.71%         407                78    80.84%           0                 0         -
server/src/policy_ref.rs              336                 4    98.81%          13                 0   100.00%         252                 2    99.21%           0                 0         -
server/src/proxy.rs                  6040               202    96.66%         271                34    87.45%        3838                83    97.84%           0                 0         -
server/src/request_plan.rs            499                 2    99.60%          35                 1    97.14%         391                 2    99.49%           0                 0         -
server/src/rewrite.rs                4494               109    97.57%         121                 6    95.04%        2235                31    98.61%           0                 0         -
server/src/scope_policy.rs            899                25    97.22%          59                 1    98.31%         517                19    96.32%           0                 0         -
server/src/server.rs                 6189               390    93.70%         179                20    88.83%        4010               249    93.79%           0                 0         -
server/src/status.rs                   44                 0   100.00%           3                 0   100.00%          19                 0   100.00%           0                 0         -
server/src/tls.rs                    1086                50    95.40%          53                10    81.13%         660                14    97.88%           0                 0         -
server/src/util.rs                    677                89    86.85%          41                 6    85.37%         339                39    88.50%           0                 0         -
verified/src/lib.rs                  2382               231    90.30%         138                15    89.13%        1765               207    88.27%           0                 0         -
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                               61817              3626    94.13%        2536               250    90.14%       38195              1932    94.94%           0                 0         -
```

`tests/security_coverage.py --check` reports **100% production-line coverage**
for the enforced `access`, `cgi`, `config`, `expr`, `fastcgi`, `htaccess`,
`http`, `proxy`, `rewrite`, `server` and `tls` modules.  The CGI closure adds
worker-protocol, spool, timeout, child-isolation, pool-lifecycle and
response-parser cases; the configuration closure adds directive-matrix,
error-path, rule-phase, glob and section-nesting cases; the proxy closure adds
URL/alias, balancer/sticky, health, websocket, response-framing and
failover-authorization cases; the expression closure adds value-conversion,
variable/expansion, encoding/hash, parser-error and evaluation-branch cases;
the rewrite closure adds cookie/effect, condition and header extraction,
map/backreference, flag/error and process-helper cases; the dispatch/server
closure covers listener setup/rebind, connection limits, rewrite reauthorization,
websocket, CGI/FastCGI/proxy edges, directory policy and failure paths.  The
F39–F49 changes add targeted cases for alias/access-root handling, `<Limit>`
effects, cache generation, expression confinement, vhost address selection and
canonical peers; F50–F52 add ancestor `.htaccess`, overlapping alias roots and
`DirectoryIndex` cache-target/query/live-policy replays; F53–F58 add URL-mounted
rewrite bases, cache classification/key/scoping, canonical `REQUEST_URI`
query/encoding/dot-segment policies and access-file rewrite subjects above the
mapping root in `tests/adversarial_regressions.py`.

## Proxy coverage

`proxy.rs` is at **100% production-line coverage**. The covered surface
includes:

- URL parsing/canonicalization, path joining/encoding and redirect rewriting
- prefix and regex routes, balancers, sticky cookies, health checks and
  member selection
- upstream request/response framing, chunked decoding, body/trailer limits,
  duplicate `Content-Length`/`Transfer-Encoding` rejection and header
  sanitization
- WebSocket upgrade forwarding, including TLS, grant binding, backend
  handshake validation and non-upgrade responses
- failover authorization, `failonstatus` handling and 403/502 error paths

## Configuration coverage

`config.rs` is at **100% production-line coverage**. The covered surface
includes:

- directive parsing and application across server, virtual-host, directory,
  location, files, proxy and conditional sections
- `<Limit>`/`<LimitExcept>`, `<RequireAll>`/`<RequireAny>`/`<RequireNone>`,
  `AuthMerging`, legacy `Order`/`Allow`/`Deny`, and `AllowOverride` categories
- aliases, script aliases, `AliasMatch`, redirects, error documents, handlers,
  MIME types, headers, compression filters and cache limits
- proxy routes, balancer members/health templates, SSL directives, rewrite
  maps, include expansion, and directive fallback disposition
- rule phase collection (`Directory`, `Files`, `Location`, `If`/`Else`) and
  malformed-configuration error paths

## Expression engine coverage

`expr.rs` is at **100% production-line coverage**. The covered surface
includes:

- boolean/int/string comparisons and concatenation
- `&&`, `||`, `!`, `-n`, `-z`
- `-in` lists, regex literals and `$0..$N` captures
- request/header/environment variables and common `TIME_*`/`API_VERSION`
- `req()`, `http()`, `env()`, `toupper`, `tolower`, `escape`, `unescape`,
  `sha1`, `md5`, base64 functions
- `-f`, `-d`, `-e`, `-s`, `-F`, `-U`, `-R`, `-ipmatch`, `-strmatch`,
  `-strcmatch`, `-fnmatch`
- `Require expr`, `.htaccess <If>`, and config `<If>`/`<IfFile>`

File tests (`-f`/`-d`/`-e`/`-s`/`-F`/`-U`) use the canonical document-root
confinement; `<IfFile>` keeps its operator-supplied absolute path through the
separate `Expr::IfFile` variant.

Not covered / not implemented: `LogMessage` expression interpolation, some
rare string/list/function forms, and a few Apache 2.4.68+ file-function
restrictions.

## Rewrite engine coverage

`rewrite.rs` is at **100% production-line coverage**. The covered surface
includes:

- server and per-directory rule matching, chaining, skip, `[N]` loop limits,
  `[L]`/`[END]`, `[QSA]`/`[QSD]`/`[QSL]`, `[B]`/`[BNE]`/`[BCTLS]`/`[BNP]`,
  `[CO]`, `[E]`, `[H]`, `[T]`, and redirect/proxy/forbidden/gone outcomes
- regex, comparison, expression and file-test conditions, including negated
  matches, `[NC]`/`[OR]` and document-root confinement
- `ENV:`, `HTTP_`/`HTTP:`, request/server, query and filesystem variables
- `txt`, `rnd`, `prg` and `int` maps, including closed-pipe and child-failure
  handling for `prg`
- backreference expansion, cookie construction, redirect escaping, host
  comparison, and internal target normalization

Remaining semantic gaps rather than coverage gaps are `dbm` maps and exact
per-directory `[DPI]` path-info handling.

## Still missing from the first-six list

- OCSP responder error-cache timeout policies (`SSLStaplingCache` is still
  treated as local persistence rather than a shared socache).
- Rewrite edge semantics: `dbm` maps and exact per-directory `[DPI]`
  path-info handling.
- Advanced balancer policies beyond route-cookie stickiness, `failonstatus`,
  passive failover and GET/HEAD health checks.
- `mod_cache_socache` and `mod_file_cache` (disk warm-start metadata is
  implemented).
- `mod_info` (basic `mod_status` is implemented).

`llvm-cov` reported 160 functions with mismatched data when merging the release
daemon with the debug unit-test objects; line coverage is unaffected, but
function percentages should be treated as approximate.

Reproduce with `tests/coverage.sh`. The report merges profiles from the real
`httpd-rs` process driving the 165-test conformance suite and 36 adversarial
replays with the Rust unit test binaries (360 library tests plus 4 CLI/daemon
tests).