# Adversarial findings and exploit harness

This folder is the retained adversarial record for vapache: the numbered
finding write-ups from every adversarial pass, plus the retained exploit and
remediation harnesses. Keeping the exact exploit shapes here
prevents re-deriving them from scratch.

## Layout

| Path | Contents |
|---|---|
| `backend-response-review.md` | Malicious HTTP/CGI/FastCGI response campaign: complete cache-policy parsing, normalization provenance, H1/H2 malformed-field behavior, FastCGI record identity, and V7 cache-generation invalidation |
| `http-desynchronization-review.md` | Cross-hop HTTP/1 framing and protocol-transition review: strict verified request metadata, exact fragmented pipeline properties, canonical single-use proxying, and reconstructed WebSocket 101 responses |
| `internal-request-transition-review.md` | Synthetic request campaign: typed DirectoryIndex/ErrorDocument projections, immutable wire identity, body/query/hop-state isolation, request-owned recursion, response-owned cache provenance, and deferred CGI execution regressions |
| `tls-mtls-state-review.md` | TLS/mTLS state campaign: immutable negotiated identity, SNI/Host policy binding, resolver parity, resumed client identity, expiring sessions, CRL-backed revocation, validity-driven OCSP staples, strict responder URLs and HTTPS proxy verification |
| `apache-if-files-nesting.md` | Apache 2.4.69 configuration-validation bug: unsupported `<Files>`/request-time `<If>` nesting passes configtest but its policy is not evaluated on ordinary requests; source analysis, impact, reproduction, and Vapache disposition |
| `findings.md` | Pass 3 write-ups (F31–F36, F38) |
| `findings_p4.md` … `findings_p9.md` | Pass 4–9 write-ups |
| `findings_p10.md` | Pass 10 write-ups (F60–F69) |
| `findings_p11.md` | Pass 11 write-ups (F61–F66, F69, F70; F66 was the only fixed survivor) |
| `findings_p12.md` | Pass 12 write-ups (P12-A–P12-F): trailing-slash `ProxyPass` auth bypass/local RCE, dotless-basename CGI execution, ScriptAlias PATH_INFO gate bypass, HTTP/2 body-window stall, plus secondary findings |
| `findings_p13.md` | Pass 13 write-ups (P13-A–P13-C): F69 closure incomplete — FastCGI and CGI `PATH_INFO` still classify by the canonical symlink-target basename, and a canonical `<Files>`/`<FilesMatch>` `SetHandler` force overrides the lexical name; PHP RCE and `execve` of `<Location>`-denied CGIs through a symlink |
| `findings_p14.md` | Pass 14 write-ups (P14-A–P14-E): `<Files>`/`<FilesMatch>` phase order lets an ancestor `.htaccess` override a deeper config section (RCE/auth bypass), `[P]` authority guard misses `\1`/`%1` (SSRF), `Require expr` file tests fall back to `/` without `DocumentRoot`, duplicate field lines defeat header guards, and `[C]` chain breaks skip one rule instead of the chain |
| `findings_p15.md` | Pass 15 write-ups (P15-A/P15-B/P15-C): FastCGI `PATH_INFO` rebinds `SCRIPT_FILENAME` to the canonical symlink target (PHP-FPM's `security.limit_extensions` gate and `<Location>` guards bypassed, Apache 403 vs vapache PHP RCE); `RemoteIPTrustedProxy`/`RemoteIPInternalProxy` share one list with no private-address rule (private `X-Forwarded-For` rewrite spoofs `REMOTE_ADDR`, Apache 403 vs vapache 200); and expression regexes skip load-time dialect validation, so PCRE-only `<If>`/`Require (not) expr`/`RewriteCond expr` guards silently become inert (protected CGI executed, Apache 403 vs vapache 200) |
| `findings_p16.md` | Pass 16 write-ups (P16-A/P16-B/P16-C/P16-D): `.htaccess` `SetEnv`/`SetEnvIf` values reach FastCGI as PHP-FPM `PHP_VALUE`/`PHP_ADMIN_VALUE`, so an uploaded non-PHP file is executed through `auto_prepend_file` (Apache does not forward access-file env to `mod_proxy_fcgi`; main-config env remains a positive control); directive regexes use Rust `regex` Unicode class semantics, so `\b`/`\W`/`\D`/`\S` deny guards miss non-ASCII input (protected CGI executes) and a positive `SetEnvIf`/`Require env` `^\w+$` gate over-grants it (Apache 403 vs vapache 200); header guards drop invalid UTF-8 (`header_str`), so `SetEnvIf`, `RewriteCond` and `<If>` deny rules miss `\xFFsqlmap`; and `SetEnvIf` action/attribute semantics (valueless `1`, env chaining, `$1` captures) diverge, allowing chained/expression/backreference deny guards to be bypassed |
| `findings_p17.md` | Pass 17 write-up (P17-A): the resolved-file FastCGI `SetHandler` branch builds `SCRIPT_FILENAME` from the canonical symlink target instead of the lexical request-mapped path, so PHP-FPM's `security.limit_extensions` gate sees `.php` where Apache sends `.txt`; a `.txt` symlink to a `.php` target executes as the FPM worker on vapace (Apache `403 Access denied.`), including uploaded content whose direct URL is static under `SetHandler none`/`default-handler` (canonical `<Location>`/`<Directory>` guards still bind) |
| `findings_p18.md` | Pass 18 write-ups: **P18-A** under `AllowOverride None` + `AllowOverrideList Require`, vapache parses attacker-written `<Files>`/`<FilesMatch>` sections that Apache rejects (`500`), and the section-scoped `Require all granted` overrides an outer `<FilesMatch ...> Require all denied`; uploaded PHP-FPM/CGI executes as `www-data`, with AuthConfig parity and no-`.htaccess`/top-level-`Require` controls. **P18-B** (HEAD `07c7879`): `.htaccess` `<IfFile>` is evaluated against DocumentRoot instead of ServerRoot and merged in the if phase instead of the directory phase, so `<IfFile index.html> Require all granted </IfFile>` bypasses file- and URL-scoped upload denies on vapache (Apache `403`, vapache `200` PHPEXEC/`EXEC` as `www-data`); vapache also applies access files to `ProxyPassMatch`-routed requests, letting `<IfFile>`/`<If "true">` grants override a `<Location>` guard that Apache enforces |
| `findings_p19.md` | Pass 19 write-up (**P19-A**): the shared cache retains a complete copy of every cacheable response body in a process-global map bounded only by `MAX_ENTRIES = 4096` keys × `CacheMaxFileSize` (≈4 GiB default, ≈8 GiB under the cache-benchmark policy) and never by `CacheMaxDiskSize`; unique query strings — or, under `CacheIgnoreQueryString On`, any unique request-header value — grow server RSS ≈1 MiB per request, the client can RST after the response headers and the body is retained anyway, and `panic = "abort"` turns the eventual allocation failure into whole-process death (Apache `mod_cache_disk` stays flat with a working `X-Cache: HIT`) |
| `findings_p20.md` | Pass 20 write-ups: **P20-A** HTTP/2 request bodies are buffered in heap up to 32 MiB per stream × 100 concurrent streams per connection (≈3.2 GiB per connection) while HTTP/1 spools bodies above 1 MiB to disk — 20 × 8 MiB streams peak +162 MiB RSS versus Apache `mod_http2` +1.3 MiB, one 32 MiB stream holds +32.9 MiB, and 60 × 8 MiB under a 512 MiB address-space bound aborts the process (`memory allocation of 8388608 bytes failed`); **P20-B** the request spooler reserves the declared `Content-Length` from the process-global `VapacheMaxSpoolBytes` budget before reading any body, so one ~100-byte request declaring 1 GiB denies all large identity and all chunked uploads process-wide (dropped connections, no response) until the body deadline, with recovery on close |
| `findings_p21.md` | Pass 21 write-up (**P21-A**, now remediated): the ≤1 MiB identity-body branch reserved the declared `Content-Length` against the process-wide `MAX_REQUEST_RESIDENT_BYTES` budget before receiving body bytes, so 128 header-only POSTs denied every HTTP/1 and HTTP/2 request. The fixed reader charges only actual received chunks and the retained harness records the original Apache differential |
| `findings_p22.md` | Pass 22 write-ups (**P22-A/B**, now remediated): HTTP/2 zero-window file responses materialized uncharged bodies and streamed proxy responses pinned all blocking-read leases. File/stream sends now wait for capacity, use response-accounted 64 KiB chunks, and scope each blocking lease to one read; the retained harness records the original Apache differentials |
| `findings_p23.md` | Pass 23 write-ups (**P23-A–P23-N**) and remediation dispositions: counted-repetition work charging, final-newline fail-closed contexts, exact byte/POSIX classes and ranges, inline `x`, CRLF atomics, internal `\K` captures, escapes/capture histories, CRLF iteration and linear class parsing |
| `findings_p24.md` | Pass 24 write-ups (**P24-A/B**, now remediated): non-ASCII expression-regex delimiters fail closed before the parser advances, UTF-8 string/pattern bytes are preserved, and optional counted repetitions charge their terminal path plus the PikeVM active-set factor. The retained live battery requires Apache-compatible access-file errors with vapached alive and a clean main-config rejection |
| `p11/exploit_p11.py` | Pass-11 differential exploit battery: 13 micro-apps run against Apache 2.4.69 and vapached, one per finding row |
| `p11/case01-F61-A` … `case13-F61-C` | Captured case dossiers (rendered `apache.conf` / `vp.conf`, fixture tree, server logs, `ap.strace`) |
| `p11/f70_accessfilename.py` | F70 probe (dead finding: Apache rejects the configuration) |
| `p12/exploit_p12.py` | Pass-12 differential battery (P12-A–C/E/F vs Apache 2.4.69 on sibling loopback ports; P12-D single-server h2 body check) |
| `p13/exploit_p13.py` | Pass-13 differential battery (P13-A FastCGI symlink classification, P13-B CGI `PATH_INFO` symlink classification) |
| `p14/exploit_p14.py` | Pass-14 differential battery (P14-A `<Files>` phase order, P14-B `[P]` SSRF, P14-C expr file-test root, P14-D duplicate headers, P14-E `[C]` chain) |
| `p16/exploit_p16.py` | Pass-16 remediation battery: requires Apache/vapache parity for access-file FastCGI environment provenance, ASCII-default directive regexes, raw-byte header guards, and `SetEnvIf` value/chaining/backreference semantics (36 verdicts with A6/B1/B2/C1-C3/D1-D3 controls; A uses a portable built-in FastCGI parameter mock, not PHP-FPM) |
| `p17/exploit_p17.py` | Pass-17 remediation battery (P17-A, 15 verdicts): FastCGI `SetHandler` plus a `.txt` symlink to a `.php` target; cases A (global handler), B (child `SetHandler none` upload tree), C (`<FilesMatch>` plus access-file handlers) and D (`<Location>`/`<Directory>` negative controls). Requires Apache `mod_proxy_fcgi` and a real PHP-FPM; keeps the FPM access log as lexical `SCRIPT_FILENAME` evidence |
| `p18/exploit_p18.py` | Pass-18 remediation battery (P18-A, 14 verdicts): uploaded PHP-FPM (per-directory and parent `FilesMatch` handlers) and CGI scripts under `AllowOverrideList Require`; both servers must reject unlisted `<Files>`/`<FilesMatch>` wrappers, with no-`.htaccess`, top-level-`Require`, scoped-`ok` and `AllowOverride AuthConfig` controls. Requires `mod_proxy_fcgi`/PHP-FPM for group A; group B runs CGI-only |
| `p18/exploit_p18b.py` | Pass-18B differential battery (P18-B): `.htaccess` `<IfFile>` base/phase divergence and `ProxyPassMatch` access-file participation. Default groups E–J (PHP-FPM and CGI upload guards, `<LocationMatch>` guards, `AllowOverrideList "<IfFile" Require`, benchmark `ProxyPassMatch` shape, access-file deny probes); groups A–D retain the earlier DOTALL/handler and conditional-wrapper probes. Requires `mod_proxy_fcgi`/PHP-FPM for the PHP groups; fixtures under `/tmp/opencode/p18b-harness` |
| `p19/exploit_p19.py` | Pass-19 cache memory-exhaustion battery (P19-A, 4 verdicts): query-keyed RSS growth under a 1 MiB `CacheMaxDiskSize` (disk stays empty), header-keyed growth with RST-after-headers under `CacheIgnoreQueryString On`, memory-bounded process death via `RLIMIT_AS` (`memory allocation of N bytes failed`), and the Apache `mod_cache_disk` oracle on the identical fixture and cache policy. Loopback only; fixtures under `/tmp/opencode/p19-harness` |
| `p20/exploit_p20.py` | Pass-20 resource-exhaustion battery (P20-A/B, 4 verdicts): HTTP/1-versus-HTTP/2 request-body memory for concurrent 8 MiB POSTs, a single-stream 32 MiB ceiling probe, memory-bounded HTTP/2 process death via `RLIMIT_AS`, and the declared-`Content-Length` spool-budget starvation with 2 MiB identity, tiny chunked, 1 KiB identity and release controls. Requires `nghttp`/`openssl` for group A; loopback only; fixtures under `/tmp/opencode/p20-harness` |
| `p21/exploit_p21.py` | Pass-21 availability-denial battery (P21-A/B, 4 verdicts): header-only POSTs that declare `2^20 − 2 × head_length` bytes and hold the process-wide 128 MiB request-resident budget; group A runs the identical attack against Apache 2.4.69 (`mpm_event`, `mod_reqtimeout`, 400 workers) side by side, group B re-arms waves below the 30 s body deadline for 60 s, group C1 fills the budget from one client behind `RemoteIPTrustedProxy 127.0.0.1`, and group C2 adds six temporary loopback IPv6 /64s and fills it from one host. Loopback only; fixtures under `/tmp/opencode/p21-harness` |
| `p22/exploit_p22.py` | Pass-22 HTTP/2 zero-window battery (P22-A/B, 3 verdicts): 32 `nghttp -w 0 -W 0` streams holding 8 MiB response bodies for the RSS differential against an Apache `mod_http2`/`mod_ssl` oracle, the same 64 streams under `RLIMIT_AS=550 MiB` for the allocator abort, and a `mod_proxy_http` route used to pin all 32 process-wide blocking-read leases while a concurrent static h2 download, a 128 KiB h2 control and an HTTP/1 control are probed. Loopback only; fixtures under `/tmp/opencode/p22-harness` |
| `p23/exploit_p23.py` | Pass-23 PCRE2 differential battery (9 verdicts): negated-POSIX, character-class range and inline-`(?x)` ACL divergences under `<If … =~ /…/>`, both directions of the inline-`(?x)` mismatch, and the exact counted-repetition CPU amplification (`a{8000}` on an 8,000-byte header) against Apache 2.4.69. Requires only `mpm_event`, `mime`, `dir`, `authz_core` and `authz_host`; loopback only; fixtures under `/tmp/opencode/p23-harness` |
| `p23/probe/` | Retained standalone Rust differential probe (path dependency on `crates/pcre2`; excluded from the product workspace): `repro.rs` exact span/compile cases, deterministic grammar fuzzer `fuzz.rs` (`CLEAN`, `EXPR`, `ONLY_MATCH`, `ONLY_ACCEPT`, `ONLY_REJECT`), and `work2.rs` 64 KiB counted-repetition benchmark, and `work3.rs` 8,190-byte/subject-size sweep |
| `p24/exploit_p24.py` | Pass-24 expression-parser remediation battery (7 verdicts): A1 `<If>` under `AllowOverride AuthConfig`, A2 `Require expr` under AuthConfig, A3 `RewriteCond expr` under `FileInfo`, A4 `<If>` under FileInfo — each must return 500 with vapached alive; A5 ASCII control must stay 200; the identical `.htaccess` served by Apache 2.4.69 must be 500 with the server alive; B1 a main-config `<If>` must make `vapached -t` fail normally, never by signal. Loopback only; fixtures under `/tmp/opencode/p24-harness` |
| `p24/crash-input.bin` | Retained libFuzzer `rewrite_expr` artifact (`%{RUE( 'M(?THO`} =~\xd8\x92#^\`} =~\xd8\x92#^H1`) |
| `p25/exploit_p25.py` | Pass-25 P25-A differential battery (30 verdicts): trailing-slash static-file URLs (`/private.txt/`) are `404` on Apache but `200` with the protected body on vapached while the exact URL stays `403` on both; groups A `<LocationMatch "^/private\.txt$">`, B `.htaccess RewriteRule ^private\.txt$ - [F]`, C `<If "%{REQUEST_URI} == '/private.txt'">`, D slash-tolerant `<LocationMatch "^/private\.txt/?$">` positive control, E basename `<Files>` control. Loopback only; fixtures under a `p25-harness-*` temp tree |
| `p25/exploit_p25_dos.py` | Pass-25 P25-B worker-exhaustion battery (7 verdicts): `MaxRequestWorkers 8` + `Timeout 2` + 64 MiB fixture, 8 stalled downloads from 127.0.0.2/3 make a fresh client receive `503` on vapached (workers survive past `Timeout`), while Apache `mpm_event` serves the fresh client `200`; recovery control after the stalls close. Loopback only; fixtures under a `p25-dos-harness-*` temp tree |
| `findings_p25.md` | Pass-25 write-ups (P25-A/P25-B): trailing-slash URL-identity authorization bypass and stalled-`sendfile` worker pinning (≈5.13–5.16× `Timeout`) |
| `findings_p26.md` | Pass-26 write-ups (P26-A/P26-B): pre-fix persisted-cache eligibility across upgrade and the absolute-response-deadline slow-download regression |
| `p27/exploit_p27.py` | Pass-27 glob-match availability battery (12 verdicts): A1–A3 a long-star `<Files>` pattern under `AllowOverride All`/`AuthConfig` and an `IndexIgnore` pattern under `Indexes` abort the whole process on one request (`SIGABRT`, `thread 'conn' has overflowed its stack`) where Apache refuses the over-long line with `500`; B1–B5 a 12-star exponential `<Files>` pattern wedges workers with no recovery (64/64 exhausted, fresh client `503` after all attacker sockets close) while Apache answers `403` in <1 ms; C1–C3 the same pattern/value pair arrives through `Require expr -strmatch` request headers under `AuthConfig`; D1 the exponential growth ladder. Loopback only; fixtures under `/tmp/opencode/p27-harness` |
| `findings_p27.md` | Pass-27 write-ups (P27-A/P27-B): one-request stack-overflow abort and permanent worker starvation in the verified `fnmatch`/`expr_glob` backtracking kernels |
| `p28/exploit_p28.py` | Pass-28 upload-access evaluator battery (8 verdicts): A1–A3 `RewriteRule $1`-repetition growth to 1.07 GB RSS in 6 s and `memory allocation of N bytes failed` under `RLIMIT_AS` (Apache `403`, 1.9 MB); B1–B3 `Require expr` header/`file()` expansion to >500 MB with allocator abort (Apache `500`, flat); C1–C2 27 KB/90 KB `.htaccess` section nesting stack-overflow aborts (Apache `200`, alive). Loopback only; fixtures under `/tmp/opencode/p28-harness` |
| `findings_p28.md` | Pass-28 write-ups (P28-A/B/C): unbounded rewrite substitution growth, expression value expansion and access-file section nesting |
| `p29/exploit_p29.py` | Pass-29 availability battery (5 verdicts): a 518-byte request plus an attacker-written `.htaccess` rewrite expands to a ~20,000-component internal target and aborts the process in the recursive verified ancestor-plan kernel (Apache `500`, alive); the same kernel is reachable from a static config with `LimitRequestLine ≥ ~38 KiB`; and `find_script_checked` burns ~39 ms of CPU per maximum-length 404 (~260× Apache, saturating 7.7/8 cores from one address). Loopback only; fixtures under `/tmp/opencode/p29-harness` |
| `p30/exploit_p30.py` | Pass-30 remediation battery (8 verdicts): 32 stalled >64 KiB responses from one source must not occupy response-body descriptor-read permits or replace unrelated large/medium responses with `503`; availability is checked before and after a full holder refresh, with small-response, recovery and Apache controls. Loopback only; fixtures under `/tmp/opencode/p30-harness` when `--keep` is given; `P30_TIMEOUT`/`P30_HOLD_SECONDS`/`P30_REFRESH_MARGIN`/`P30_HOLDERS` permit a shorter CI replay |
| `p30/exploit_p30_h2.py` | Pass-30 cross-protocol remediation battery (4 verdicts): while 32 HTTP/1 responses are stalled on the cleartext listener, HTTP/2 on the TLS listener must continue serving both a 3-byte and a large file because socket waits and dispatch cannot consume response-body descriptor-read permits. Needs `nghttp`; fixtures under `/tmp/opencode/p30-h2-harness` |
| `findings_p29.md` | Pass-29 write-ups (P29-A/A′/B): recursive ancestor-plan stack overflow (whole-process abort) and the quadratic 404 PATH_INFO prefix walk (CPU exhaustion at default configuration) |
| `findings_p30.md` | Pass-30 write-up (P30-A/A′): one HTTP/1 client exhausts the 32 process-wide blocking-I/O leases with stalled >64 KiB requests, denying every >64 KiB response process-wide and all HTTP/2 requests through the shared dispatch lease |
| `p31/h2hold.py`, `p31/h2hold404.py`, `p31/h2oracle_apache.py` | Pass-31 differential and remediation harness (P31-A): eight source addresses try to hold all 256 process-wide HTTP/2 stream leases with zero-window bodies and one-byte WINDOW_UPDATE trickles; the victim must remain served, matching the Apache `mod_http2` oracle |
| `findings_p31.md` | Pass-31 write-up (**P31-A**, now remediated): flow-control-progress send-deadline renewal made the 256-stream global lease hold permanent; slow outputs now transfer into a smaller source-fair pool governed by anchored minimum-rate and absolute-lifetime bounds |
| `dos-resource-budget-followup.md` | Post-P28 DoS review: CVE-2011-4415-style `SetEnvIf` amplification, request-wide matcher/policy work and expansion budgets, access-program breadth limits, and generated-response-header admission |
| `dos-connection-admission-followup.md` | Post-P28 connection DoS follow-up: asynchronous first-head admission, H2 preface deadline, worker/source reserves, fair listener batches, and complete control-frame charging |

## Pre-adversarial gate

Run the complete fail-closed pre-pass from the repository root:

```sh
tests/pre_adversarial.sh
```

The gate requires Apache, its proxy/FCGI modules, cargo-verus and a real
PHP-FPM executable. Missing dependencies are failures. It runs the Rust suite,
compiles and smoke-runs all coverage-guided parser fuzz targets, runs the proof
ledger with Verus, grammar/validity checks, fixed plus randomized and stateful
configuration differentials, Apache differential conformance, portable
adversarial regressions, and the real-backend P17/P18 batteries.

## Running the pass-11 battery

```sh
cargo build --release -p vapached
python3 adversarial/p11/exploit_p11.py 1 2 3 4 5 6 7 8 9 10 11 12 13
```

Each case rebuilds its dossier in place and prints the Apache-versus-vapached
verdict.  The oracle is `/usr/sbin/apache2` (Debian Apache 2.4.69); the
harness binds loopback ports only and scopes its cleanup to its own config
paths.  Case index: 1 F61-A, 2 F61-A2, 3 F61-B, 4 F62, 5 F63, 6 F63b, 7 F64,
8 F65, 9 F66, 10 F69, 11 F64b, 12 F62b, 13 F61-C (control).

The dossiers were captured at HEAD `d219efb` (before the pass-11
remediation) and are regenerated in place on each run.  The harness starts
Apache with `-X` (single process) and gives Apache and vapached *separate*
`logs/{apache,vapache}.pid` / `error-{apache,vapache}.log` files: the
original single `logs/httpd.pid` was written by whichever server started
last, so a concurrently starting vapached could make Apache abort with
`httpd (pid ...) already running` and produce an `apache=-1` row.  With the
split pidfiles the full 13-case battery completes without a single retry;
the retry loop and `-1` sentinel are kept as a safety net for the shared
host.

The matching end-to-end regression replays live in
`tests/adversarial_regressions.py` (`F61ToF69Pass11Tests`); the closure status
of every finding is tracked in `docs/adversarial-closure.md`.

## Running the pass-12 battery

```sh
cargo build --release -p vapached
python3 adversarial/p12/exploit_p12.py          # all groups A-F
python3 adversarial/p12/exploit_p12.py A B C    # proxy, extension, ScriptAlias cases
python3 adversarial/p12/exploit_p12.py D --keep # h2 body-window check, keep dossiers
```

Pass-12 cases: **A** trailing-slash/catch-all `ProxyPass` prefix (local
serving, `<Proxy>` authorization bypass, local CGI execution), with the
no-slash control; **B** dotless/hidden basenames (`cgi`, `.cgi`, `..cgi`, `pl`,
`php`) executed by the handler table, including the `<Files "*.cgi">` bypass;
**C** ScriptAlias + `SetHandler default-handler` + PATH_INFO; **D** HTTP/2
request bodies above the 256 KiB stream window (Apache oracle not applicable);
**E** `AuthType` with no applicable `Require` (Apache 500 vs vapache 200);
**F** streamed proxy responses skipping the `Header` policy.
Fixtures are built under `/tmp/opencode/p12-harness` unless `--keep` is given.
Both batteries now use separate per-server pidfiles (`<case>/logs/{apache,vapache}.pid`)
and single-process Apache (`-X`), so neither can trip over the other's
startup.

## Running the pass-13 battery

```sh
cargo build --release -p vapached
python3 adversarial/p13/exploit_p13.py            # all cases
python3 adversarial/p13/exploit_p13.py A          # FastCGI symlink classification
python3 adversarial/p13/exploit_p13.py B          # CGI PATH_INFO symlink classification
python3 adversarial/p13/exploit_p13.py --keep     # keep dossiers
```

Pass-13 cases: **A1** `SetHandler "proxy:…|fcgi://…"` + `pub/link.txt -> secret/app.php`
(Apache source vs vapache PHP-FPM execution); **A2** the same with a
`<Location "/secret/">` Basic-auth guard on the script (anonymous vapache
execution); **B1** `AddHandler cgi-script` + the same symlink requested as
`/pub/link.txt/x` (Apache 404 vs vapache `execve`); **B2** the same with a
`<Location "/secret/">` deny guard; **C1** canonical `<FilesMatch "\.cgi$">
SetHandler cgi-script` + the same symlink requested directly (Apache source vs
vapache `execve`, no global `AddHandler`); **C2** the same with a
`<Location "/secret/">` deny guard.  The Apache oracle runs `-X` on sibling
loopback ports; group A needs `php-fpm8.4`/`php-fpm`, otherwise a private fake
FastCGI responder records the `SCRIPT_FILENAME` vapache sends.  Fixtures are
built under `/tmp/opencode/p13-harness` unless `--keep` is given.

## Running the pass-14 battery

```sh
cargo build --release -p vapached
python3 adversarial/p14/exploit_p14.py            # all cases (8/8 differential verdicts)
python3 adversarial/p14/exploit_p14.py A B        # selected groups
python3 adversarial/p14/exploit_p14.py --keep     # keep dossiers
```

Pass-14 cases: **A1** deeper config `<Files "run.cgi"> Require all denied` /
`<Files "upload.txt"> SetHandler default-handler` vs an ancestor `.htaccess`
grant/force (Apache 403 and static source vs vapache 200 CGI execution);
**A2** the same with a deeper `<Files>` Basic-auth guard (Apache 401,
anonymous vapache execution); **B** `RewriteRule ... "http://\1/" [P]` and
`"%1" [P]` authority/substitution backreferences that the load-time
`proxy_template_authority_safe` guard misses (Apache 400/Apache-compatible
expansions vs attacker-controlled vapache upstream = SSRF); **C**
`Require expr "file('etc/passwd') =~ /^root/"` in `.htaccess` with no
`DocumentRoot` directive (filesystem-root fallback, single-server check);
**D** duplicate `User-Agent` field lines skipping a `RewriteCond ... [F]`
guard (Apache 403 vs vapache 200); **E** a failing `[C]` gate that fails to
skip the whole chain (Apache 404 vs vapache 200 privileged `[PT]` rewrite).
The Apache oracle runs `-X` on sibling loopback ports with a separate pid file
for each server.  Fixtures are built under `/tmp/opencode/p14-harness` unless
`--keep` is given.

## Running the pass-15 battery

```sh
cargo build --release -p vapached
python3 adversarial/p15/exploit_p15.py                    # all groups A1-A4 + B1-B2 + C1 (37 verdicts)
python3 adversarial/p15/exploit_p15.py A1 A3              # FastCGI symlink groups
python3 adversarial/p15/exploit_p15.py B1 B2              # RemoteIP groups (no PHP-FPM needed)
python3 adversarial/p15/exploit_p15.py C1                 # expression dialect group
python3 adversarial/p15/exploit_p15.py --keep --show-fpm-log
```

Pass-15 case **P15-A** — the project's own benchmark FastCGI spelling
(`ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:…|fcgi://localhost<docroot>/"`) with
an in-root symlink whose lexical name is not `.php`
(`pub/link.txt -> ../secret/app.php`).  Apache forwards the lexical path to
PHP-FPM, whose `security.limit_extensions` gate refuses the `.txt` split
script (`403 Access denied.`); vapache resolves the symlink, sends the
canonical `.php` path as `SCRIPT_FILENAME`, and PHP-FPM executes it (`200
PHPEXEC … uid=33`).  **A2** adds a live `<Location "/secret/"> Require all
denied` guard (direct URL 403 on both, symlink route still executes on
vapache); **A3** points the symlink at an uploaded `.php` inside a
`<Location "/uploads/">`-denied tree and executes attacker content; **A4** is
the `<Directory>` control (guard binds on vapache, fail-closed).

Pass-15 case **P15-B** — `mod_remoteip` chain semantics.  **B1**
(`RemoteIPTrustedProxy 127.0.0.1` + `<Directory> Require ip 10.1.2.3`) shows
the same request granting on vapache and denying on Apache for
`X-Forwarded-For: 10.1.2.3` (and for private values after a public entry, as
IPv4-mapped, or before a trailing empty entry): Apache keeps the real peer
and refuses the private presented address, vapache rewrites `REMOTE_ADDR` to
the attacker-supplied value.  **B2** (`RemoteIPInternalProxy`) is the control
that flips both servers to `200`, isolating the missing internal/trusted
distinction plus Apache's private-address rejection.  A CGI oracle prints
`REMOTE_ADDR` on both sides.

Pass-15 case **P15-C** — expression-regex dialect (single group **C1**).
`<If "/…/ =~ /PATTERN/"> Require all denied </If>`, an `<Else>` inversion, a
`<RequireAll>` `Require not expr` deny-list and a `RewriteCond expr` `[F]`
guard are each wrapped around a `.txt` and an executable `.cgi`, with a
plain-pattern control.  Apache evaluates the PCRE patterns
(`\Qsecret\E`, `secret\.txt\Z`, `sec(?#match)ret`, `\Ksecret`,
`(se)cret\1`) and denies/executes accordingly; vapache's lazy regex compile
errors, the error is swallowed as `false`, and the guards disappear
(protected file read, protected CGI `EXEC`, rewrite deny skipped).  The
control denies on both.

`--show-fpm-log` prints PHP-FPM's access log with the Apache/vapache
`SCRIPT_FILENAME` lines paired.  Fixtures and a private PHP-FPM pool are built
under `/tmp/opencode/p15-harness` unless `--keep` is given.

## Running the pass-16 battery

```sh
cargo build --release -p vapached
python3 adversarial/p16/exploit_p16.py            # all groups A1-A6 + B1-B2 + C1-C3 + D1-D3 (36 verdicts)
python3 adversarial/p16/exploit_p16.py A1 A3      # selected FastCGI cases
python3 adversarial/p16/exploit_p16.py B          # directive-regex cases
python3 adversarial/p16/exploit_p16.py C          # invalid-UTF-8 header-guard cases
python3 adversarial/p16/exploit_p16.py D          # SetEnvIf value/chaining/backref cases
python3 adversarial/p16/exploit_p16.py --keep     # keep fixtures
```

Pass-16 case **P16-A** — environment provenance across FastCGI.  The
benchmark `ProxyPassMatch` shape with `AllowOverride All` (or `FileInfo`):
the attacker writes a `.htaccess` containing
`SetEnv PHP_VALUE "auto_prepend_file=<uploads>/avatar.txt"` (also
`PHP_ADMIN_VALUE` and `SetEnvIf` variants, and a nested-directory variant)
and uploads a non-PHP file containing PHP. The retained remediation harness
uses a built-in FastCGI protocol mock that reports `PREPEND` whenever either
dangerous parameter reaches the backend. Access-file cases must report no
parameter on both servers; the main-config `SetEnv PHP_VALUE` positive control
must report it on both. **A6** also covers no `.htaccess`, harmless
`SetEnv APP_ENV`, and `AllowOverride None`.

Pass-16 case **P16-B** — directive-regex dialect.  A `RewriteCond
%{HTTP:X-User} \badmin\b` + `RewriteRule ^ - [F]` deny guard around a CGI is
tested with `éadmin`, `^\W+$`/`é`, `^\D+$`/`١٢٣` and `^\S+$`/U+00A0.
Both Apache and remediated vapache must apply ASCII-class semantics and deny
(`403`, no `EXEC-P16B`). Controls:
ASCII `admin` denied by both, `xadminx` allowed by both, and the `<If>` PCRE
form denied by both.

Pass-16 case **P16-B (B2)** — the over-grant direction at the same compiler.
`SetEnvIf User-Agent ^\w+$ TRUSTED` plus `Require env TRUSTED` admits the CGI
for `User-Agent: é` on neither server (ASCII `\w`). Controls: `abc`
admitted/executing on both, `abc def` denied on both.

Pass-16 case **P16-C** — invalid UTF-8 in a guarded header.  A `SetEnvIf
User-Agent sqlmap BLOCK` + `Require not env BLOCK`, a `RewriteCond
%{HTTP:X-User} sqlmap` + `[F]`, and an `<If "%{HTTP:X-User} =~ /sqlmap/">`
deny are each tested with a raw signature prefix (`User-Agent: \xFFsqlmap`
for C1, `X-User: \xFFsqlmap` for C2/C3).  Apache matches the raw bytes and
denies (`403`, no `EXEC-P16C`); remediated vapache now matches those exact raw
bytes and must return the same result. Controls: ASCII `sqlmap` denied by all
three guards on both, benign `curl/8` allowed on both, `\xFF` alone allowed on
both, and valid UTF-8 `ÿsqlmap` denied on both.

Pass-16 case **P16-D** — `SetEnvIf` action/attribute semantics.  **D1**
`SetEnvIf ... BLOCK` (valueless) plus `Require not expr "%{env:BLOCK} ==
'1'"`, **D2** chained `BAD`/`DENY`, and **D3** `$1` action expansion must all
deny on both servers. Controls covering explicit values, direct rules,
non-matching captures and benign requests keep each guard live.

Each FastCGI case starts and stops its own built-in Unix-socket mock under
`/tmp/opencode/p16-harness/case-*/fpm`; no PHP installation is required. The
Apache oracle runs `-X` on sibling loopback ports with separate pid files;
fixtures are removed unless `--keep` is given.

## Running the pass-17 battery

```sh
cargo build --release -p vapached
python3 adversarial/p17/exploit_p17.py                    # cases A-D (15 verdicts)
python3 adversarial/p17/exploit_p17.py A B                # global handler / uploads controls
python3 adversarial/p17/exploit_p17.py --show-fpm-log     # print paired SCRIPT_FILENAME evidence
python3 adversarial/p17/exploit_p17.py --keep             # accepted; fixture/logs are always kept
```

Pass-17 case **P17-A** — the resolved-file FastCGI `SetHandler` identity. A
global handler (a supported vhost recipe:
`SetHandler "proxy:unix:…|fcgi://localhost"`) serves
`pub/link.txt -> ../secret/app.php` and
`pub/upload-link.txt -> ../uploads/shell.php`.  Apache's `mod_proxy_fcgi`
forwards the lexical request-mapped `.txt` name to PHP-FPM, whose stock
`security.limit_extensions` gate refuses it (`403 Access denied.`). Remediated
vapache must forward the same lexical `.txt` path while retaining the canonical
`.php` target for authorization and inode binding. The same parity requirement
holds with the `fcgi://localhost/` spelling.

**A** is the unguarded global handler and isolates the `SCRIPT_FILENAME` differential; because there is no upload execution hardening in A, the direct `.php` upload is executable on both servers. **B** adds
`<Directory "…/uploads"> SetHandler none</Directory>`, so the direct upload URL
is static source on both servers while the symlink route is refused by both
backends; **C** is the Debian-style `<FilesMatch "\.php$">` main handler plus a
`pub/.htaccess` proxy handler and an `uploads/.htaccess` `default-handler`
override (`AllowOverride All`), which pins the same result through an
access-file handler; **D** is the negative control —
`<Location "/uploads/">` and `<Directory "…/uploads"> Require all denied` both
return `403` on both servers, because vapache still reauthorizes the canonical
target. The retained P17 exploit shape is closed at the backend
policy/extension gate without weakening those guards. The benchmark `ProxyPassMatch` spelling
is fixed by P15 and is not affected by this branch; a bare
`<FilesMatch "\.php$">` handler alone does not match the `.txt` URL and is not
affected either.

The harness starts a private PHP-FPM pool under `/tmp/opencode/p17-harness`
with `php_admin_value[security.limit_extensions] = .php .phar`; the Apache
oracle runs `-X` on sibling loopback ports with separate pid files.  The FPM
access log with `access.format = "%f|%r"` is retained after every run and is
the evidence that Apache and vapache send the same lexical `SCRIPT_FILENAME`
for the request.

## Running the pass-18 battery

```sh
cargo build --release -p vapached
python3 adversarial/p18/exploit_p18.py                    # A PHP-FPM + B CGI (14 verdicts)
python3 adversarial/p18/exploit_p18.py A                  # PHP-FPM chain
python3 adversarial/p18/exploit_p18.py B                  # CGI chain, no PHP-FPM required
python3 adversarial/p18/exploit_p18.py --show-fpm-log     # print retained FPM request evidence
```

Pass-18 case **P18-A** — `AllowOverrideList` section gating.  The upload
directory uses `AllowOverride None` plus `AllowOverrideList Require`, an active
PHP-FPM (or CGI) handler, and an outer file-scoped deny such as
`<FilesMatch "\.php$"> Require all denied`.  An attacker-written `.htaccess`
adds a file-scoped grant:

```apache
<Files "shell.php">
    Require all granted
</Files>
```

Apache 2.4.69 rejects the access file with `500`
(`.htaccess: <Files not allowed here`) because the container section is not
permitted by the directive-only `AllowOverrideList`. Remediated vapache must
reject it with the same `500` before parsing the nested `Require`; no PHP/CGI
execution marker may be created. The `<FilesMatch>` section form and a parent
`FilesMatch` handler exercise the same gate, and the CGI group pins it without
requiring PHP-FPM.

The battery's controls show the outer deny is otherwise live (no `.htaccess`,
both `403`), that a plain top-level `.htaccess Require all granted` cannot
override it (both `403`), that the invalid wrapper makes every request at that
level fail closed, and that `AllowOverride AuthConfig` with the same section is
a parity control (both servers execute). The harness starts a
private PHP-FPM pool under `/tmp/opencode/p18-harness/fpm`
with `security.limit_extensions = .php .phar`, runs Apache `-X` and vapached on
sibling loopback ports with separate pid files, and retains per-case Apache
error logs plus the FPM access log for evidence.

## Running the pass-23 PCRE2 differential battery

```sh
cargo build --release -p vapached
python3 adversarial/p23/exploit_p23.py              # all 9 verdicts
python3 adversarial/p23/exploit_p23.py A B          # omit the C1/C2 controls
cd adversarial/p23/probe
CARGO_TARGET_DIR=/tmp/opencode/p23-probe-target cargo run --release --bin repro
CARGO_TARGET_DIR=/tmp/opencode/p23-probe-target cargo run --release --bin work2
CARGO_TARGET_DIR=/tmp/opencode/p23-probe-target cargo run --release --bin work3
CARGO_TARGET_DIR=/tmp/opencode/p23-probe-target \
  CLEAN=1 ONLY_MATCH=1 cargo run --release --bin fuzz -- 1000000
CARGO_TARGET_DIR=/tmp/opencode/p23-probe-target \
  EXPR=1 CLEAN=1 ONLY_MATCH=1 cargo run --release --bin fuzz -- 2000000
```

The live battery uses a shared `<Directory>` guard on both servers and sends
the same request to Apache 2.4.69 and vapached on sibling loopback ports. The
A1/A2/A3 cases now require status parity, while B1 requires the same
fail-closed status without the former CPU delay; C1/C2 and the A1/A2 controls
must agree. The harness writes
per-case configs, fixtures and server logs under `/tmp/opencode/p23-harness`
and exits non-zero if any verdict fails. The probe crate is standalone and
uses `[workspace]` so it does not join the product workspace.

## Running the pass-24 expression-parser abort battery

```sh
cargo build --release -p vapached
python3 adversarial/p24/exploit_p24.py     # all 7 verdicts
```

A1–A4 each start a fresh vapached with an attacker-written `.htaccess`
(`<If "%{REQUEST_URI} =~ éé">`, `Require expr "… =~ éé"` or
`RewriteCond expr "… =~ éé"`), send one request into the directory and
require the process to die with SIGABRT; A5 is the ASCII `<If>` control that
must answer 200. The Apache oracle serves the identical `.htaccess` and must
return 500 while staying alive; B1 requires `vapached -t` with the
main-config `<If>` to exit with signal 6. Fixtures and server output are
under `/tmp/opencode/p24-harness`; the harness exits non-zero if any verdict
differs.

## Running the pass-25 static-hosting batteries

```sh
cargo build --release -p vapached
python3 adversarial/p25/exploit_p25.py        # P25-A trailing-slash ACL bypass (30 verdicts)
python3 adversarial/p25/exploit_p25_dos.py    # P25-B stalled-download worker exhaustion (7 verdicts)
```

**P25-A** runs five Apache/vapached groups over the same fixture
(`www/private.txt` = `SECRET-CONTENT`, `www/hello.txt` control). The exact
URL `/private.txt` must be `403` on both servers, while remediated vapache
must match Apache's `404` for `/private.txt/` without returning the secret.
Group A is a
main-config `<LocationMatch "^/private\.txt$"> Require all denied`; B is a
`.htaccess` `RewriteRule ^private\.txt$ - [F]` under `AllowOverride All`; C is
`<If "%{REQUEST_URI} == '/private.txt'"> Require all denied`; D is the
slash-tolerant `^/private\.txt/?$` positive control that must deny both
spellings; E is the basename `<Files "private.txt">` control that must deny
both. Apache runs `-X` on sibling loopback ports with separate pid/error
logs; both temp trees are removed unless `--keep` is given.

**P25-B** runs both servers with `MaxRequestWorkers 8` and `Timeout 2` over a
64 MiB file. Eight stalled downloads (127.0.0.2 and 127.0.0.3, four each)
must be aborted by remediated vapache's response-wide deadline, release their
connection workers, and leave a fresh client at `200`; the Apache `mpm_event`
oracle must likewise keep serving the fresh client. Loopback only; fixtures
are removed unless `--keep` is given.

## Running the pass-29 availability battery

```sh
cargo build --release -p vapached
python3 adversarial/p29/exploit_p29.py            # both groups (5 verdicts)
python3 adversarial/p29/exploit_p29.py A          # P29-A stack-overflow abort + Apache oracle
python3 adversarial/p29/exploit_p29.py B          # P29-B 404 prefix-walk CPU burn + Apache oracle
python3 adversarial/p29/exploit_p29.py --keep     # retain fixtures and logs
```

**P29-A** writes the project's conformance/feature access-file shape
(`VapacheCapability AccessFiles On` + `AllowOverride FileInfo`) and an
attacker-written `.htaccess` whose `RewriteRule` repeats `$1` 80 times.  A
518-byte request expands to a ~40 KiB internal target with ~20,000 path
components; the target is outside the override directory, so the
access-file component caps are skipped and
`policy_ref::effective_scope_with_layers_and_file_name` feeds the whole
ancestor vector to the recursive verified kernel
`access_walk_plan_exec_from`.  vapache aborts with
`thread 'vapache-io' has overflowed its stack` / `fatal runtime error:
stack overflow, aborting` (`SIGABRT`); Apache answers `500` in ~1 ms and
stays alive, and the rewrite-removal control is `404` with vapache alive.
The same kernel is reachable from the static `bench.py` shape with
`LimitRequestLine ≥ ~38 KiB`; the bisection and gdb backtraces are recorded
in `findings_p29.md`.

**P29-B** runs both servers on the static `bench.py` shape and sends the
maximum-length 404 (8,175-byte request line, 4,080 components).  vapache
spends ~39 ms of CPU per request (Apache ~0.15 ms) and 16 connections from
127.0.0.1 consume 7.7 of 8 cores at ~190 rps while the Apache oracle serves
the identical traffic at ~10,000 rps using 1.3 cores.  Loopback only;
fixtures and per-server logs are kept under `/tmp/opencode/p29-harness`
when `--keep` is given.

## Running the pass-30 battery

```sh
cargo build --release -p vapached
python3 adversarial/p30/exploit_p30.py            # both groups (8 verdicts)
python3 adversarial/p30/exploit_p30.py A          # vapache stall attack
python3 adversarial/p30/exploit_p30.py B          # Apache mpm_event oracle
python3 adversarial/p30/exploit_p30.py --keep     # retain fixtures and logs
python3 adversarial/p30/exploit_p30_h2.py         # cross-protocol HTTP/1 -> HTTP/2
```

**P30-A** runs both servers on the static `bench/bench.py` shape with the
default `Timeout 60`.  Thirty-two connections from a single source address
(`127.0.0.2`) request `/big.bin` (4 MiB), read only the response head and
never read the body.  All 32 process-wide blocking-read leases stay occupied
for the full `Timeout`, and every victim probe for a >64 KiB object
(`/big.bin`, `/medium.bin` 100 KiB) returns
`503 Response memory capacity is temporarily exhausted`, while `/small.txt`
(3 bytes) still returns `200`.  The holders reissue after ~50 s and the
denial survives the refresh cycle (t≈62 s probe); closing them restores
`200` immediately.  Apache `mpm_event` serves every identical victim probe
`200` with the full body.  `--keep` retains the tree under
`/tmp/opencode/p30-harness`.

**P30-A′** (`exploit_p30_h2.py`) runs a cleartext listener and a TLS/h2
listener in one process.  While the 32 HTTP/1 stalls are held, every HTTP/2
request -- even `small.txt` -- returns `:status: 503`
("request execution capacity exhausted") because `h2::handle_stream` takes
the same lease for request dispatch; HTTP/2 service recovers when the stalls
close.  Needs `nghttp` (`nghttp2-client`); fixtures under
`/tmp/opencode/p30-h2-harness`.
