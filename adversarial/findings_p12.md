# Pass 12 — adversarial break of HEAD `1f5b16e` ("Reach 100% server production coverage")

- **Date:** 2026-10-27
- **Subject:** `target/release/httpd-rs` built at HEAD `1f5b16e` (no repo source edits; the only additions for this pass are `adversarial/p12/exploit_p12.py`, this write-up, and the `adversarial/README.md` index entry)
- **Oracle:** Apache/2.4.69 (Debian), local binary `/usr/sbin/apache2 -X`, loopback only
- **Method:** static audit of the security-critical modules (dispatch, config, handler selection, proxy routing, h2 adapter, access) followed by live differential micro-apps that pair a *typical* httpd-rs deployment — the benchmark/typical CGI posture (`Options +ExecCGI +FollowSymLinks` + `AddHandler cgi-script .cgi`) — with a single common Apache idiom, and compare HTTP responses against Apache on a sibling port.
- **Harness:** `adversarial/p12/exploit_p12.py` (all cases below are reproducible in one command; see §9).

---

## 1. Executive summary

Six new remotely triggerable findings on HEAD: three code-execution class (P12-A–C), one remote availability bug (P12-D) and two verified secondary policy bypasses (P12-E/F). The p11 remediation (F61–F69) is *not* fully closed: the F65 handler gate was added only to the direct path, and the new handler/extension table has an extension-extraction bug that reintroduces upload-to-execution.

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class | Verified |
|---|---------|---------------|--------------|-------|----------|
| **P12-A** | `ProxyPass /app/ …` (trailing slash) never matches any sub-path; catch-all `ProxyPass / …` only matches `/` | proxies; `<Proxy>` deny → 403 | local document root is served; a local CGI under the prefix is **executed as `www-data`** | authentication bypass → local file disclosure / RCE; complete reverse-proxy breakage | live |
| **P12-B** | Dotless / leading-dot basenames are treated as extension tokens (`cgi`, `.cgi`, `..cgi`, `pl`, `php`) | static source, 200 | **CGI executed**, 200 `EXEC-…` | upload→RCE; bypasses `<Files "*.cgi">` deny guards; also source disclosure in the inverse direction (`run.cgi.txt`) | live |
| **P12-C** | `ScriptAlias` + `<Directory> SetHandler default-handler` + `PATH_INFO` suffix | 404 (never executes) | **executed** | F65 hardening bypass → RCE in hardened alias trees | live |
| **P12-D** | HTTP/2 request body larger than the 256 KiB stream window | — (h2 adapter) | **408 after 30 s; the body can never complete**; stream/connection window stays charged | remote availability / connection-occupancy DoS | live |
| **P12-E** | `AuthType Basic` + `AuthUserFile` with no applicable `Require` (and no covering parent `Require`) | 500 — a loud configuration failure | 200 with file contents | fail-open on a broken-but-loud Apache configuration | live |
| **P12-F** | `Header always set …` / `Header unset …` on a proxied location is dropped when the upstream body is streamed (>256 KiB `Content-Length`) | header policy applied | header policy skipped | response-hardening bypass dependent on response size | live |

The strongest chain is **P12-A**: the standard Apache reverse-proxy spelling (`ProxyPass "/app/" "http://backend/"`, per the Apache docs examples) silently falls through to the local filesystem in httpd-rs, so a request that Apache routes to a protected backend — and explicitly `403`s via `<Proxy …> Require all denied` — is answered by the local document root, and any CGI-enabled file reachable under that prefix runs as the worker user.

---

## 2. P12-A — trailing-slash `ProxyPass` prefixes never match; `<Proxy>` authorization is skipped

### 2.1 Root cause

`crates/server/src/proxy.rs:482-494`:

```rust
fn prefix_suffix<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    if path == prefix {
        Some("")
    } else if let Some(rest) = path.strip_prefix(prefix) {
        if rest.starts_with('/') {      // <-- fails when `prefix` already ends in '/'
            Some(rest.trim_start_matches('/'))
        } else {
            None
        }
    } else {
        None
    }
}
```

When the configured prefix already ends in `/`, `strip_prefix` yields the remainder *without* a leading slash, so the boundary test rejects it:

- `prefix_suffix("/app/", "/app/notes.txt")` → `None` (Apache matches);
- `prefix_suffix("/", "/index.html")` → `None` (Apache proxies everything);
- only the exact URLs `/app/` and `/` match.

The helper is the single match predicate for the whole prefix route table — `balancer_unavailable` (`proxy.rs:530`), `matches_route` (`:563`) and `match_target_req` (`:579`) all consume it — so a trailing-slash rule is invisible to backend selection, `<Proxy>`/`<ProxyMatch>` authorization (`apply_proxy_access_urls` runs only after `match_target_req` succeeds, `server.rs:2331-2337`), the cache-disable rule for proxy routes, and the balancer `503` path. Dispatch then falls through to the ordinary local mapping of the URL. The same function is duplicated verbatim at `crates/server/src/fastcgi.rs:262-274` (used by `fastcgi::match_proxy`, `:281`) and has the same defect.

Note the project's own tests only ever use prefix forms without a trailing slash (`tests/conformance.py:1050-1124`, `bench/app_bench.py:194`), which is why this was not caught: `fastcgi.rs` unit tests assert only `prefix_suffix("/x", "/x/y")`.

### 2.2 Exploit chain (observed)

Configuration (a minimal, idiomatic reverse-proxy front end; the CGI posture is the project's own benchmark/typical one):

```apache
DocumentRoot "/srv/app/www"
Options +ExecCGI +FollowSymLinks
AddHandler cgi-script .cgi
<Directory "/srv/app/www">
    Require all granted
</Directory>

ProxyPass        /app/ http://127.0.0.1:9000/
ProxyPassReverse /app/ http://127.0.0.1:9000/
<Proxy "http://127.0.0.1:9000/">
    Require all denied          # or Require valid-user / Require ip …
</Proxy>
```

Fixture: `/srv/app/www/app/secret.txt` (private local file), `/srv/app/www/app/upload.cgi` (executable CGI; in a real deployment: a stale script, an upload, or any file the local tree holds under the prefix).

```
GET /app/secret.txt
  Apache 2.4.69:  403 Forbidden            (<Proxy> deny matched the proxied route)
  httpd-rs HEAD:   200 "LOCAL-SECRET"       (proxy rule skipped; local file served)

GET /app/upload.cgi
  Apache 2.4.69:  403 Forbidden            (never touches the local file)
  httpd-rs HEAD:   200 "EXEC-PROXYBAIL uid=33"   (local CGI executed as www-data)
```

Catch-all form (`ProxyPass / http://127.0.0.1:9000/` — the canonical front-controller spelling of many frameworks), no `<Proxy>`:

```
GET /hello.txt     Apache: 200 "BACKEND-OK path=/hello.txt"   httpd-rs: 200 "LOCAL-HELLO"
GET /nested/x      Apache: 200 "BACKEND-OK path=/nested/x"    httpd-rs: 404 (local)
```

Control (no trailing slash) agrees on both servers:

```
ProxyPass /app http://127.0.0.1:9000/
GET /app/secret.txt    Apache 403 · httpd-rs 403
```

### 2.3 Impact

- **Authorization bypass.** `<Proxy …> Require valid-user|ip|all denied …</Proxy>` — the documented way to protect a proxied path — is evaluated only after `match_target_req` succeeds, so it is never consulted, and the local directory's policy (usually broadly open under `DocumentRoot`) governs instead. Access logs will show a local 200, not the 403 the operator's policy intends.
- **Local disclosure / execution.** Any local file under the prefix is served; any executable handler in the local tree (CGI here, or anything else the local scope enables) runs with the worker identity. In front-controller deployments the application is bypassed entirely: local files win, non-existent paths 404 instead of reaching the app.
- **Secondary breakage.** Because `matches_route` is false, the shared cache is not disabled for these URLs, and a fully-dead `balancer://` route no longer produces its `503` — it falls through to the local tree.

### 2.4 Fix

Treat a trailing-slash prefix as already boundary-matched, e.g.

```rust
if let Some(rest) = path.strip_prefix(prefix) {
    if prefix.ends_with('/') || rest.starts_with('/') {
        Some(rest.trim_start_matches('/'))
    } else {
        None
    }
}
```

(and mirror it in `fastcgi.rs`). Add conformance rows for `ProxyPass "/app/" "http://…/"` and `ProxyPass "/" "http://…/"` with and without `<Proxy>` guards; the existing suite cannot see this class because every fixture uses the no-slash prefix.

---

## 3. P12-B — dotless / hidden basenames are classified as file extensions

### 3.1 Root cause

`crates/server/src/config.rs:780-792`:

```rust
pub(crate) fn effective_handler<'a>(scope: &'a Scope, name: &[u8]) -> Option<&'a str> {
    match &scope.mapping_policy.set_handler { … }
    let base = name.rsplit(|b| *b == b'/').next().unwrap_or(name);
    let ext = base
        .rsplit(|b| *b == b'.')
        .next()                    // <-- returns the WHOLE basename when there is no '.'
        .and_then(|e| std::str::from_utf8(e).ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    effective_handler_for_ext(scope, &ext)
}
```

`rsplit('.')` on `"cgi"` (no dot) yields `"cgi"`, so a *file named* `cgi` is handed to the extension table as if its extension were `cgi`, matching `AddHandler cgi-script .cgi`. The same extraction exists for MIME overrides (`crates/server/src/files.rs:306-312`) and in the `.htaccess` parser; `AddHandler`/`RemoveHandler` also strip *all* leading dots (`config.rs:4061/4069`, `htaccess.rs:1767/1778`) where Apache strips exactly one. Apache's `mod_mime::find_ct` skips leading dots, copies the dot-separated tokens, and a name with no dot has **no** extension.

Two related table defects surfaced in the same audit:

- `handler.ext == "*"` is treated as a wildcard (`config.rs:762`, `conjoin` lookup at `:803`), while Apache keys `AddHandler cgi-script *` on the literal extension `*`. With that config httpd-rs executes **every** file in an ExecCGI tree; Apache executes only `*`-suffixed names.
- `RemoveHandler .cgi` followed by `AddHandler cgi-script .cgi` *in the same scope* executes in httpd-rs: the merged list is scanned in reverse parse order (`config.rs:760-773`). Apache always applies removals after additions when merging the directory config, so the removal wins regardless of line order.

### 3.2 Exploit: upload-to-execution and `<Files "*.cgi">` bypass (observed)

Configuration: global `Options +ExecCGI +FollowSymLinks` + `AddHandler cgi-script .cgi` (server-wide CGI, the p11/benchmark posture). Attacker/application writes an executable file into a writable tree; the file is named without a dot — exactly what an upload filter that blocks strings/endings such as `.cgi` allows, and what `mod_mime` gives no extension.

| file requested | Apache 2.4.69 | httpd-rs HEAD |
|---|---|---|
| `/uploads/cgi` (`cgi`, no dot) | 200, script source (static) | **200, `EXEC-… uid=33`** |
| `/uploads/.cgi` (hidden) | 200, source | **200, executed** |
| `/uploads/..cgi` | 200, source | **200, executed** |
| `/uploads/pl` with `AddHandler … .pl` | 200, source | **200, executed** |
| `/uploads/php` with `AddHandler … .php` | 200, source | **200, executed** |
| `/uploads/cgi` + `<Files "*.cgi"> Require all denied` | 200, source (guard doesn't match, and nothing executes) | **200, executed — the guard pattern has no dot and cannot match the dotless name** |

Prerequisite: the placed file must be executable (`execve` is used directly; a `0644` file returns 500, verified), which a `zip`/`tar`-extraction endpoint, an FTP/SFTP drop, a CMS file manager that chmods, or a local file-write primitive satisfies. The same extraction also feeds FastCGI handler names: with `AddHandler "proxy:…fcgi…" .php`, a dotless file named `php` is routed to the backend where no executable bit exists at all (this FastCGI variant was not run end-to-end this pass; note PHP-FPM's default `security.limit_extensions` accepts only `*.php*`).

**Inverse direction (source disclosure / compatibility):** Apache assigns handlers from *any* dot-separated token, so `run.cgi.txt` and `x.cgi.` are executed by Apache while httpd-rs serves their **source** (last-token extraction only). Observed: `GET /uploads/run.cgi.txt` → Apache 200 `EXEC-DOUBLE`, httpd-rs 200 `#!/bin/sh …`.

Controls: extension case-insensitivity agrees (`run.CGI` with `.cgi` handler executes on both, and `.CGI` handler matches `run.cgi` on both); a normal `run.cgi` executes on both; `<Files "*.cgi">` correctly denies `run.cgi` on both.

### 3.3 Fix

Replace the last-token extraction with the Apache rule: skip leading dots, require a dot, iterate the dot-separated tokens; a basename with none has no extension. Keep `SetHandler` precedence as-is (it is correct), stop treating `*` as a wildcard, and make the same-scope merge apply removals after additions. Add the table of §3.2 as regression rows (the current battery has no dotless/hidden-name case).

---

## 4. P12-C — the F65 handler gate is skipped on the PATH_INFO branch

The p11 fix routes direct requests through the verified admission kernel (`server.rs:2555` → `cgi::is_cgi`, `cgi.rs:1216-1235`, `cgi_exec_admit`), so `<Directory> SetHandler default-handler` correctly suppresses execution for `/cgi-bin/run.cgi`. The PATH_INFO branch never got the same treatment — `server.rs:2785-2815`:

```rust
let path_info_selected_cgi = cgi::is_cgi(cfg, &scope, requested_base, false);
let selected = script_alias || cgi::is_cgi(cfg, &scope, actual_name, false);
if selected {
    …
    if script_alias || cgi::is_cgi(cfg, &target_scope, actual_name, false) {
        return run_cgi(…);          // <-- script_alias short-circuits the F65 gate
    }
}
```

`script_alias ||` means the handler classification and `Options` check added for F65 are bypassed for any request that carries a PATH_INFO suffix:

```
ScriptAlias /cgi-bin/ "/srv/www/cgibin/"
<Directory "/srv/www/cgibin">
    SetHandler default-handler          # operator hardening, the F65 idiom
</Directory>

GET /cgi-bin/run.cgi/anything
  Apache 2.4.69:  404 (mod_alias sets cgi-script, SetHandler keeps default-handler,
                       default_handler rejects the leftover path_info)
  httpd-rs HEAD:   200 "EXEC-CGIBIN uid=33"

GET /cgi-bin/run.cgi/x/y     same divergence
GET /cgi-bin/run.cgi/        Apache 404 · httpd-rs 200 (script source)
GET /cgi-bin/run.cgi         both 200 source (fixed direct path — control)
```

`<Files "run.cgi"> SetHandler default-handler` is bypassed identically. Any operator who used the documented F65 hardening idiom and later exposes a file in the alias tree (migration copy, upload, shared storage) is executing it on demand.

**Fix:** call `cgi::is_cgi(cfg, …)` with the real `script_alias` flag and drop the `script_alias ||` short-circuits at `server.rs:2786` and `:2815` (the kernel already admits the legitimate alias-only case); add the four requests above to the regression battery.

---

## 5. P12-D — HTTP/2 request bodies above 256 KiB can never complete

`crates/server/src/h2.rs:203-240` (`read_body`) reads DATA chunks and copies them into `body`, but never returns flow-control credit:

```rust
loop {
    let next = tokio::time::timeout(timeout, recv.data()).await…  // per-chunk deadline
    …
    body.extend_from_slice(&chunk);
    // no recv.flow_control().release_capacity(chunk.len())
}
```

The h2 settings advertise a 256 KiB stream window and a 1 MiB connection window (`crates/verified/src/lib.rs:5782-5790`: `initial_window: 256*1024`, `initial_connection_window: 1024*1024`, `max_concurrent_streams: 100`). The `h2` crate does not replenish the window when a `Bytes` chunk is dropped; the caller must call `release_capacity`. The only `release_capacity` calls in the file are inside test code (`h2.rs:1076`, `:1214`).

Observed on a local TLS/h2 listener (`curl -k --http2`):

```
POST 300 KiB (Content-Length)   -> 408 after 30.008 s (request_body_timeout)
POST  10 KiB                    -> 405 in 0.006 s (body path completes; static files 405 POST by design)
GET                             -> 200 in 0.007 s
```

Consequences: every h2 upload larger than 256 KiB is impossible regardless of `LimitRequestBody` (the 413 branch is unreachable — the stream times out first); each stuck stream charges the connection window for the full 30 s timeout and up to 100 concurrent streams are admitted, so a handful of large POSTs wedge a connection (and, behind a multiplexing gateway that pools h2 connections, other clients); the per-chunk `tokio::time::timeout` also permits a 1-byte-per-29-s trickle to hold a stream open indefinitely. This is remotely reachable in the project's own HTTP/2 test configuration and in any TLS front end speaking h2 to httpd-rs.

**Fix:** `let _ = recv.flow_control().release_capacity(chunk.len());` after copying each chunk (and consider one deadline for the whole body).

---

## 6. Secondary verified findings

### 6.1 P12-E — `AuthType` without an applicable `Require` fails open

`access.rs:288-290` returns `Access::Allowed` whenever `scope.authorization.requires` is `None`, so:

```apache
<Directory "/srv/www/private">
    AuthType Basic
    AuthName "restricted"
    AuthUserFile "/srv/www/.htpasswd"
</Directory>
```

(with no covering `Require` in any ancestor `<Directory>`):

```
GET /private/data.txt
  Apache 2.4.69:  500 Internal Server Error  (authorize_user_core: auth type set but no authz section)
  httpd-rs HEAD:   200 "private-data"
```

With a parent `Require all granted` covering the directory, both servers return 200 (my first run), so the divergence is specifically the "loudly broken" Apache configuration; even so, a migrated config that Apache refuses to serve silently opens in httpd-rs. Fix: when an `AuthType` is effective and no authorization section applies, fail closed with 500.

### 6.2 P12-F — streamed proxy responses skip the response `Header` policy

`proxy.rs:1509-1528`: when a fixed-length upstream response exceeds `STREAM_THRESHOLD = 256*1024`, the function returns early with `Body::Stream`, running only `compression::finalize`; `scope.header_policy.apply(...)` exists only on the buffered path (`proxy.rs:1558-1560`). Observed with `<Location "/proxy"> Header always unset Set-Cookie` + `Header always set X-Frame-Options DENY` and a backend that answers with `Set-Cookie: leaked=1` on both a 100-byte and a 300 000-byte response:

```
/proxy/small (100 B)      httpd-rs: [x-frame-options: DENY], Set-Cookie stripped
/proxy/big   (300 000 B)  httpd-rs: no X-Frame-Options, set-cookie: leaked=1 forwarded
Apache applies the whole configured policy to both.
```

The entire response-header policy — `set`, `add`, `unset`, `always`/`onsuccess` — is skipped whenever the upstream response crosses the threshold, an attacker-controllable size boundary: hardening headers vanish (`Content-Security-Policy`, `X-Frame-Options`, HSTS, `Cache-Control`), and an operator's `unset Set-Cookie` no longer strips upstream cookies. Fix: hoist `header_policy.apply` above the streaming branch (or apply it for both).

---

## 7. Additional static-audit leads (not all live-verified)

These were found while reviewing the modules for the findings above and are recorded for the next pass; each has a code pointer.

1. **h2 requests without `:path`/`:authority` dispatch as `GET /`** (`h2.rs:539-547`; `http` crate normalizes an empty `PathAndQuery` to `"/"`). h1 rejects the same request (`400 MissingTarget`/`MissingHost`) — a protocol differential for any h2-forwarding front end.
2. **h2 `:path` fragments are truncated before validation** (`http::Uri::path_and_query` cuts at `#`), where h1 rejects `#` in the target — an intermediary routing/authorization differential.
3. **CGI `Status: 101`/`Upgrade:` passthrough** (`cgi.rs:1138-1148` does not filter `upgrade`): a script can emit a switch-protocol response and httpd-rs keeps treating the socket as HTTP.
4. **Any unsafe method flushes the whole shared disk cache** (`server.rs:1297-1299` calls `cache::invalidate` unconditionally; `cache.rs:1428-1460` unlinks every entry under the one global `CacheRoot`), while the in-memory prefix key uses the raw request path instead of the canonical cache key — so `POST` to a 404 endpoint is an unauthenticated cache-stampede amplifier, and a write to a directory URL does not drop its cached index.
5. **`FileETag None` is ignored** (`files.rs:348-350` treats `bits == 0` as "All"), leaking inode/size/mtime despite an explicit hardening directive.
6. **Unknown `%{http*}` expression variables are accepted and evaluate to `""`** (`expr.rs:338-344`); a typo'd guard such as `Require expr %{HTTPX_BLOCK}` is silently inert instead of a load error. Also `Require env NAME=VALUE` compares the value (Apache can never grant on this form), and `Require method get` is uppercased (Apache registers a *new* method and never matches `GET`) — both more permissive than Apache.
7. **`[BNE]` does not imply `[B]`** (`rewrite.rs` flag parsing: `escape_spec` requires `escape_backrefs`), so captures containing `%`, spaces, `;` or `#` stay literal where Apache escapes them — a target-selection divergence.
8. **`RewriteMap prg` forks per lookup with no timeout** (`rewrite.rs:1147-1196`), unlike Apache's long-lived map process; request input reaches it only on stdin (no command injection found), but every lookup can block a worker indefinitely.
9. **Multiple `AccessFileName` candidates are merged**, where Apache reads only the first existing one (`htaccess.rs:215-252`, `:455-480`).

None of these were demonstrated with an end-to-end Apache differential except where noted in §1; they are stated as code-level divergences to be triaged, not confirmed exploits.

---

## 8. Negative results and controls (verified, not assumed)

- `ProxyPass /app` (no trailing slash) + `<Proxy>` deny: **403 on both** — the P12-A bug is specific to the trailing-slash spelling.
- `AddHandler`/extension matching is case-insensitive on both servers (`run.CGI` and `.CGI` handler variants agree).
- Normal `.cgi` files with `Options +ExecCGI` execute on both; `<Files "*.cgi"> Require all denied` denies `run.cgi` on both.
- ScriptAlias direct path (`/cgi-bin/run.cgi`) with `SetHandler default-handler`: 200 static source on both — the p11 F65 fix holds where it was applied.
- **Pass-11 survivor spot check at HEAD:** F61-A (wildcard `<Location>` deny), F61-B (`<Location ~ …>`), F62 (`[^a]*` `<Directory>`), F62b (`<Files "[^a]*.cgi">`), F64 (same-scope `SetHandler` vs `AddHandler`), F64b (attacker `.htaccess` `AddHandler` under `SetHandler` floor) and F69 (in-root symlink handler identity) were re-run with the Apache oracle: all seven **agree** (403/403, or 200 static source/200 static source). The p11 remediation holds for those shapes; P12-B/P12-C are new/remaining gaps in the *extension table* and the *PATH_INFO branch*, not regressions of the `SetHandler`-force model. F67/F68 were not re-run this pass.
- The "missing `Require`" shape with a covering parent `Require all granted` returns 200 on **both** servers, so the fail-open only exists with no covering authz section.
- `[P]`/`[R]` original-URL authorization, proxy head validation, rewrite-map command injection, request parsing/framing, static-serving symlink policy, cache key/policy binding, `.htaccess` category gating and expression fail-closed handling were reviewed and no new bypass was found this pass.

---

## 9. How to reproduce

```sh
cd /root/httpd-rs
cargo build --release -p httpd-rs
python3 adversarial/p12/exploit_p12.py            # A–F, Apache oracle on sibling ports
python3 adversarial/p12/exploit_p12.py A B C      # selected groups
python3 adversarial/p12/exploit_p12.py D --keep   # h2 body check, keep dossiers in /tmp/opencode/p12-harness
```

Each case builds its own fixture tree and starts Apache (`-X`) and httpd-rs on loopback ports, then prints the Apache/httpd-rs verdict side by side. All fixtures and configs are generated by the harness; nothing outside `/tmp/opencode/p12-harness` is touched (Apache is run in single-process mode with per-case config and pid files). The pass-12 dossiers from the original run (`/tmp/opencode/p12/validate2.py` results and `proxycheck*.py`) are summarized in the tables above.

## 10. Suggested remediation order

1. **`prefix_suffix`** (`proxy.rs:482-494` and `fastcgi.rs:262-274`) — one-line boundary fix; add the trailing-slash/catch-all conformance rows. This closes the authorization bypass and the local execution path.
2. **Extension extraction** (`config.rs:780-792`, `files.rs:306-312`, `.htaccess` parser) — implement Apache's `find_ct` token rule; stop the `*` wildcard; apply `RemoveHandler` after `AddHandler` on merge; add dotless/hidden/multi-extension regression rows.
3. **PATH_INFO handler gate** (`server.rs:2786`, `:2815`) — pass `script_alias` into `cgi::is_cgi` instead of short-circuiting.
4. **h2 flow-control credit** (`h2.rs:203-240`) — release capacity per chunk; single body deadline.
5. **Streamed proxy header policy** (`proxy.rs:1509-1528`), **missing-`Require` fail-closed** (`access.rs:288-290`), then the §7 triage queue.
