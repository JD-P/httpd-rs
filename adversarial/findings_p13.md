# Pass 13 — adversarial break of HEAD `cce35eb` ("Harden rewrite and configuration security invariants")

- **Date:** 2026-10-27
- **Subject:** `target/release/httpd-rs` built at HEAD `cce35eb` (no repo source edits; the only additions for this pass are `adversarial/p13/exploit_p13.py`, this write-up and the `adversarial/README.md` index entry)
- **Oracle:** Apache/2.4.69 (Debian), `/usr/sbin/apache2 -X`, loopback only; PHP-FPM 8.4 with both the Debian `security.limit_extensions` default and the (Docker) empty value
- **Method:** static audit of every handler-classification site followed by a differential battery that pairs the project's *own* benchmark/typical postures (global `Options +ExecCGI +FollowSymLinks` + `AddHandler cgi-script .cgi`, per-directory `<FilesMatch "\.cgi$"> SetHandler cgi-script`, and the documented `SetHandler "proxy:unix:…|fcgi://…"` FastCGI form) with one common real-world object: an in-root symlink whose filename does not carry the script extension.
- **Harness:** `adversarial/p13/exploit_p13.py` (all cases below reproduce in one command; see §7).

---

## 1. Executive summary

Three remotely triggerable code-execution findings on HEAD. All are faces of the same root cause: the F69 "handler identity binds to the lexical request-mapped basename" rule was applied only to the **extension-table lookup** of one dispatch path. Two other paths still classify by the **canonical symlink-target basename**, and a third lets a canonical-scoped `<Files>`/`<FilesMatch>` `SetHandler` **force** override the lexical name entirely. Every one of them turns a request Apache serves as static content (or rejects) into an `execve`/PHP-FPM execution.

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P13-A** | `SetHandler "proxy:…|fcgi://…"` (documented FastCGI form) classifies the handler from `actual_path.file_name()` — a symlink `pub/link.txt -> secret/app.php` is executed by PHP-FPM on `GET /pub/link.txt` | serves the symlink target as **static source** (200 `<?php …`) | **runs `app.php` in PHP-FPM as `www-data`** (200 `PHP-EXEC …`); a `<Location "/secret/">` `Require valid-user` guard on the script is skipped, so it runs **anonymously** | remote code execution / authentication bypass |
| **P13-B** | The CGI `PATH_INFO` branch classifies from `fd_path()` (canonical) — `GET /pub/link.txt/x` **execve()s** `secret/run.cgi` | **404** (static file + `PATH_INFO` is rejected for non-CGI handlers) | **200 `PWNED-CGI uid=33`**; a `<Location "/secret/">` `Require all denied` guard on the script is bypassed | remote code execution / authorization bypass |
| **P13-C** | A canonical `<FilesMatch "\.cgi$"> SetHandler cgi-script` force is applied to the *lexical* name — plain `GET /pub/link.txt` **execve()s** `secret/run.cgi` with only `Options +ExecCGI` (no global `AddHandler`) | serves source (200 `#!/bin/sh …`) | **200 `PWNED-CGI uid=33`**; a `<Location "/secret/">` deny guard on the script is bypassed | remote code execution / authorization bypass |

All three violate the invariant the project recorded as closed for F69:

> *"Handler and MIME classification used the canonical symlink target basename … The dispatch binds the classification name to the lexical request-mapped basename (`fs_path.file_name()` first); `handler_identity_lexical_admit` is debug-asserted at the bind site."* — `docs/adversarial-closure.md` (F69)

The bind site shown there is only `server.rs` `Target::File` (line 2506–2524), and it only governs the extension table. The FastCGI selector and the CGI `PATH_INFO` branch still consume the canonical name, and a `<Files>`-scoped `SetHandler` force evaluated against the canonical target overrides the lexical name on the direct path. None of the three sites consumes `handler_identity_lexical_admit`.

Premise (the only attacker-side primitive): a symlink inside the served tree whose target is a script the operator would never expose under that name. In practice that comes from archive upload/extraction that preserves symlinks, application-created links (framework `public/storage`-style links, user files, migrations), or a pre-existing deployment symlink. The execution itself is one unauthenticated GET; no other precondition is needed.

---

## 2. P13-A — FastCGI `SetHandler` classifies the canonical symlink target (PHP RCE + `<Location>` bypass)

### 2.1 Root cause

`crates/server/src/server.rs:2551-2568` (the `Target::File` branch) computes the F69 lexical name at 2512–2524 and then hands the **canonical** opened path to the FastCGI selector:

```rust
if let Some(target) =
    fastcgi::handler_target_for_file(scope, &root, &rel, &url_path, &actual_path)
{
    return run_fastcgi(…);
}
if cgi::is_cgi(cfg, scope, name, script_alias) { … }   // `name` is lexical
```

`crates/server/src/fastcgi.rs:381-414` re-derives the classification name from the canonical path instead of the request basename:

```rust
pub(crate) fn handler_target_for_file(
    scope: &Scope, root: &Path, rel: &Path, url_path: &str, actual_path: &Path,
) -> Option<Target> {
    let name = actual_path
        .file_name()                         // <-- canonical (symlink target) basename
        .or_else(|| rel.file_name())         // lexical only if fd_path() failed
        …
    let handler = crate::config::effective_handler(scope, name)?;
    if !handler.starts_with("proxy:") { return None; }
    let backend = parse_backend(handler)?;
    let base = fastcgi_script_base(&backend, root);
    let script_filename = clean_script_path(actual_path);   // canonical target
    …
}
```

For `GET /pub/link.txt` with `pub/link.txt -> ../secret/app.php`, `actual_path` is `/…/secret/app.php`, so `effective_handler` sees `app.php` and the `proxy:` handler. `run_fastcgi` then re-authorizes `target.script_filename` (the canonical target) and sends `SCRIPT_FILENAME=/…/secret/app.php` to PHP-FPM. Apache classifies by the *filename the request resolved to* (`…/pub/link.txt`) — the `\.php$` handler never matches, and `default_handler` serves the target bytes as text.

The authorization that httpd-rs runs for the target is `scope(fs=/…/secret/app.php) ∧ scope(url=/pub/link.txt)` (`authorize_resolved_target`, `server.rs:1530-1621`). It never evaluates `scope(url=/secret/app.php)`, so **URL-scoped guards on the script's own URL are skipped**:

- `<Location "/secret/"> Require valid-user` → direct `/secret/app.php` is 401 on both servers; `/pub/link.txt` is 200 PHP execution with no credentials on httpd-rs and static source on Apache.
- `<Location "/secret/"> Require all denied` behaves the same way.

`<Directory>`/`<Files>` guards that match the canonical path are still applied (verified negative result, §6), so the bypass is specific to `<Location>`/`<LocationMatch>`/URL-scope policy — which is exactly the policy Apache applies to the URL that the attacker is *not* using.

### 2.2 Exploit chain (observed)

Configuration — the documented FastCGI spelling from the README and Debian's `php-fpm` docs:

```apache
DocumentRoot "/srv/app/www"
Options +FollowSymLinks
<Directory "/srv/app/www">
    Require all granted
</Directory>
<FilesMatch "\.php$">
    SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
</FilesMatch>
<Location "/secret/">
    AuthType Basic
    AuthName "admin"
    AuthUserFile "/srv/app/.htpasswd"
    Require valid-user
</Location>
```

Tree:

```
/srv/app/www/secret/app.php      (the protected application)
/srv/app/www/pub/link.txt   ->   ../secret/app.php
```

Observed against real PHP-FPM 8.4 (harness output, `p13a2`):

```
guard control direct /secret/app.php:            apache=401   httpd-rs=401
GET /pub/link.txt            Apache: 200  "<?php echo 'PHP-EXEC ' . __FILE__ …"
                             httpd-rs: 200  "PHP-EXEC /…/secret/app.php uid=33"
```

Same result for any lexical name (`photo.png`, `download.php.txt`, …); only the canonical basename matters. Without the `<Location>` guard (case `p13a1`) Apache still serves PHP **source** while httpd-rs executes it.

Prerequisite only: the symlink. With an archive-extraction endpoint that preserves entries such as `pub/link.txt -> ../secret/app.php` (the classic zip/tar symlink upload), the entire chain is attacker-supplied.

### 2.3 Impact

- **Remote code execution as the FPM worker user** (`www-data`): the request dispatches a PHP script through PHP-FPM that Apache never dispatches.
- **Authentication/authorization bypass**: `<Location>` is the documented way to scope guards to a URL; the script's own URL guard is not evaluated when the script is reached through the symlink name.
- **Source-disclosure inversion**: routes where Apache leaks PHP source (misconfiguration) are turned into execution on httpd-rs.

### 2.4 Fix

`handler_target_for_file` must classify using the lexical request-mapped basename — the same rule as the `Target::File` CGI path — and only use the canonical path for containment/`SCRIPT_FILENAME`:

```rust
let name = rel.file_name()               // lexical request basename
    .or_else(|| actual_path.file_name())
    …
debug_assert!(httpd_rs_verified::handler_identity_lexical_admit(
    actual_path != fs_path_used_by_caller,
    name == rel.file_name()…,
));
```

The same lexical rule should be asserted wherever a handler is selected from a resolved target. Add the battery cases (`p13a1`, `p13a2`) plus controls to `tests/adversarial_regressions.py`.

---

## 3. P13-B — CGI `PATH_INFO` branch classifies the canonical symlink target (`execve` of a denied script)

### 3.1 Root cause

`crates/server/src/server.rs:2783-2850` (the `Target::NotFound` + PATH_INFO branch) resolves the longest existing prefix and then classifies from `fd_path()`:

```rust
if let Some(st) = cgi::find_script_checked(&root, &rel, follow, owner_match_only) {
    let actual_path = crate::files::fd_path(&st.file)          // canonical
        .unwrap_or_else(|| root.join(&st.rel_script));
    let actual_name = actual_path
        .file_name()                                           // <-- canonical basename
        .or_else(|| st.rel_script.file_name())
        …
    let selected = cgi::is_cgi(cfg, &scope, actual_name, script_alias);
    …
    if cgi::is_cgi(cfg, &target_scope, actual_name, script_alias) {
        return run_cgi(…, &st.path_info, …);
    }
```

For `GET /pub/link.txt/x` with `pub/link.txt -> ../secret/run.cgi`:

- `resolve_target_checked(root, "pub/link.txt/x")` is `NotFound` (the symlink resolves to a regular file, so the remaining component is `ENOTDIR`).
- `find_script_checked` walks back and opens `pub/link.txt`; `st.file` is the `run.cgi` inode.
- `actual_name` is `run.cgi`, so `is_cgi` is true under the project's own posture (`AddHandler cgi-script .cgi` + `Options +ExecCGI`).
- `run_cgi` executes the authorized inode through the worker pool (`execve` of `/proc/self/fd/N`), with `PATH_INFO=/x`.

Apache's `mod_core` resolves the same request to the regular file `…/pub/link.txt` with `PATH_INFO=/x`; because the handler is `default-handler`, the leftover path info is refused and the response is 404. The direct `GET /pub/link.txt` is not executed on either server (the F69 fix holds there).

The target authorization is the same `scope(fs=canonical) ∧ scope(url=lexical)` conjunction as P13-A, so `<Location>` guards on `/secret/` are not evaluated. `<Directory>`/`<Files>` guards on the canonical tree still apply.

### 3.2 Exploit chain (observed)

Configuration — the project's benchmark posture plus a documented URL guard:

```apache
DocumentRoot "/srv/www"
Options +ExecCGI +FollowSymLinks
AddHandler cgi-script .cgi
<Directory "/srv/www">
    Require all granted
</Directory>
<Location "/secret/">
    Require all denied            # or AuthType Basic + Require valid-user
</Location>
```

Tree:

```
/srv/www/secret/run.cgi          (protected, executable CGI)
/srv/www/pub/link.txt   ->       ../secret/run.cgi
```

Observed (harness output, `p13b2`):

```
guard control direct /secret/run.cgi:   apache=403   httpd-rs=403
GET /pub/link.txt/x          Apache: 404
                             httpd-rs: 200 "PWNED-CGI uid=33"
```

The `Location: deny` variant was used above; the Basic-auth variant was also run manually and executes anonymously (`PWNED uid=33`, marker file written). Any non-empty suffix triggers it (`/pub/link.txt/x`, `/pub/link.txt/.cgi`, …). Case `p13b1` shows the unguarded divergence: Apache 404, httpd-rs executes.

### 3.3 Impact

- **Remote code execution as the CGI worker user**: an `execve` of a script that Apache classifies as a non-executable static file.
- **Authorization bypass**: URL-scoped guards (`<Location>`, `<LocationMatch>`, URL-keyed `Require expr`) on the script's own URL are skipped; only path-scoped policy is consulted.

### 3.4 Fix

Use the lexical prefix basename (`st.rel_script.file_name()`) for `actual_name` (classification) while keeping the canonical path for authorization/inode binding — mirroring the `Target::File` branch:

```rust
let actual_name = st.rel_script
    .file_name()
    .or_else(|| actual_path.file_name())
    …
```

Then `GET /pub/link.txt/x` classifies `link.txt`, is not a CGI, and returns 404 exactly like Apache. Add a regression row for the PATH_INFO symlink shape (the existing F69 test asserts only the direct `/public/link.txt` request).

---

## 4. P13-C — a canonical `<Files>`/`<FilesMatch>` `SetHandler` force overrides the lexical name on the direct path

### 4.1 Root cause

This face does not need `PATH_INFO` or FastCGI, and it still works after the F69 lexical-name fix because that fix only governs the **extension table**. `effective_handler` (`crates/server/src/config.rs:810`) consults the scope's forced handler first:

```rust
pub(crate) fn effective_handler<'a>(scope: &'a Scope, name: &[u8]) -> Option<&'a str> {
    match &scope.mapping_policy.set_handler {
        Some(SetHandler::Name(forced)) => return Some(forced.as_str()),   // name ignored
        Some(SetHandler::None_) | None => {}
    }
    … filename_extension_tokens(name) …
}
```

`bind_target_grant` (`server.rs:1410-1524`) notices the symlink (`actual_path != fs_path`) and evaluates the target scope for the **canonical** path (`evaluate_scope_for_path`, line 1451). `<Files>`/`<FilesMatch>` bodies are matched during that evaluation against the evaluated target's basename (`config.rs:5316`, `re.is_match(fname)`), i.e. the canonical `run.cgi` rather than the request's `link.txt`, so a `<FilesMatch "\.cgi$"> SetHandler cgi-script </FilesMatch>` inside the target directory sets `mapping_policy.set_handler` **even though the request URL's basename is `link.txt`**. The subsequent `is_cgi(cfg, scope, name="link.txt", …)` then sees a forced `cgi-script` regardless of the lexical name. Apache, by contrast, matches `<Files>` against the request filename (`…/pub/link.txt`) and never selects the handler.

### 4.2 Exploit chain (observed)

```apache
DocumentRoot "/srv/www"
Options +ExecCGI +FollowSymLinks
<Directory "/srv/www">
    Require all granted
</Directory>
<Directory "/srv/www/secret">
    <FilesMatch "\.cgi$">
        SetHandler cgi-script
    </FilesMatch>
</Directory>
<Location "/secret/">
    Require all denied            # or Basic auth
</Location>
```

Tree: `secret/run.cgi` (executable), `pub/link.txt -> ../secret/run.cgi`.

Observed (harness cases `p13c1`/`p13c2`):

```
GET /secret/run.cgi          Apache: 403        httpd-rs: 403
GET /pub/link.txt            Apache: 200 "#!/bin/sh …"   (source)
                             httpd-rs: 200 "PWNED-CGI uid=33"   (execve)
```

`<Files "run.cgi"> SetHandler cgi-script` behaves identically. The `AddHandler`-free posture matters: an operator who enables CGI with per-directory `<FilesMatch …> SetHandler cgi-script` (the standard way to scope CGI to a tree) is affected without any global `/cgi-bin` configuration.

### 4.3 Impact

- **Remote code execution** as the CGI worker user where only `Options +ExecCGI` and a Files-scoped `SetHandler` are configured, plus the same `<Location>`/URL-scope authorization bypass as P13-B.

### 4.4 Fix

A force produced by a `<Files>`/`<FilesMatch>` section that matched the **canonical target only** must not apply to a request whose lexical basename did not match the section. Concretely, when `bind_target_grant`/`authorize_resolved_target` evaluates an explicit target whose lexical identity differs (`actual_path != fs_path`), Files-scoped `SetHandler` directives must be re-admitted through the lexical match predicate (or the target scope must fail closed when its handler force disagrees with the request-mapped name). Access rules (`Require`/`Allow`/`Deny`) keep the canonical-target evaluation — that direction is stricter and matches the F41/F69 authorization model; only the **handler identity** must stay lexical. Add `handler_identity_lexical_admit`-style checks at the scope-force bind site as well as the two selection sites of P13-A/P13-B.

---

## 5. Why the previous passes missed this

- **F69 closure was applied to one bind site and one decision.** `docs/adversarial-closure.md` and the F69 test (`tests/adversarial_regressions.py::test_f69_symlink_classifies_by_request_basename`) assert only `GET /public/link.txt -> 200 source`. `handler_identity_lexical_admit` is debug-asserted only in the `Target::File` extension-table lookup (`server.rs:2518`); `handler_target_for_file`, the PATH_INFO branch and the scope-force path never consume it.
- **Pass 12 re-ran F69 as a survivor spot check** but only in the direct shape ("in-root symlink handler identity … 200 static source/200 static source"), so all three leaks survived the re-check.
- The FastCGI leak survives the pass-12 "extension extraction" hardening because it is *handler selection on the resolved file*, not `filename_extension_tokens`.
- No existing test combines a symlink with (a) `PATH_INFO`, (b) `SetHandler "proxy:…"`, or (c) a Files-scoped `SetHandler`; the F69 suite only covers `AddHandler` on the direct path.

---

## 6. Negative results and controls (verified, not assumed)

- Control `GET /secret/run.cgi` (CGI cases) executes on **both** servers (200 executed); control `GET /pub/link.txt` serves source on **both** (200 `#!/bin/sh …`). The fixture is viable and the F69 direct-path fix holds for the `AddHandler` posture.
- Control `GET /secret/app.php` (FastCGI case) is 401 anonymous and 200 executed with valid credentials on **both** servers; the `<Location>` guard itself is live.
- `<Files "link.txt"> Require all denied` and `<FilesMatch "^link\.txt$"> Require all denied` on the symlink URL deny on both servers (403) — the divergence is not "any guard bypass".
- `<Directory "/…/secret"> Require all denied` and `<Files "run.cgi"> Require all denied` deny the symlink request on httpd-rs (403, no execution) — *access* rules on the canonical target are still evaluated. Only the Files-scoped *handler force* leaks (P13-C).
- `Options -ExecCGI` on the canonical target directory blocks P13-B/P13-C (no execution) and P13-A (source/static) — the exploit needs the project's benchmark `ExecCGI` posture, which the README/benchmarks use.
- `<Location "/pub/"> Require all denied` on the symlink URL itself denies both servers (403).
- A no-handler control (symlink, `Options +ExecCGI`, no `AddHandler`/`SetHandler`) serves source on both servers — classification alone never executes.
- PHP-FPM `fix_pathinfo` exercises (`/uploads/avatar.txt/x.php` with the Docker-style empty `security.limit_extensions`) execute on **both** Apache and httpd-rs; that is upstream PHP behaviour, not a httpd-rs divergence. The P13-A divergence is handler selection before the backend is involved.
- With PHP-FPM's default `security.limit_extensions`, symlink targets that are not `.php*` are refused by FPM; the demonstrated target is a real `.php` script.

---

## 7. How to reproduce

```sh
cd /root/httpd-rs
cargo build --release -p httpd-rs
python3 adversarial/p13/exploit_p13.py            # A+B, Apache oracle on sibling ports
python3 adversarial/p13/exploit_p13.py A B --keep # keep dossiers in /tmp/opencode/p13-harness
```

Each case builds its own fixture tree and starts Apache (`-X`) and httpd-rs on loopback ports with separate pid/error files. Group A needs `php-fpm8.4`/`php-fpm` for the execution oracle; if neither is installed the harness substitutes a private fake FastCGI responder that echoes the `SCRIPT_FILENAME` httpd-rs sends, which still proves Apache never dispatches the request while httpd-rs does. Group B has no external dependency.

Expected summary:

```
  PASS  P13-A1 FastCGI symlink executes php target
  PASS  P13-A2 Location auth bypass via symlink
  PASS  P13-B1 CGI PATH_INFO symlink executes denied script
  PASS  P13-B2 Location deny bypass via symlink PATH_INFO
  PASS  P13-C1 FilesMatch SetHandler force + symlink direct exec
  PASS  P13-C2 Location deny bypass via FilesMatch force
  PASS  controls
```

---

## 8. Suggested remediation order

1. **`fastcgi::handler_target_for_file`** (`fastcgi.rs:381-414`) — classify by `rel.file_name()` (lexical) and assert `handler_identity_lexical_admit` at the call site in `server.rs:2551`.
2. **CGI PATH_INFO branch** (`server.rs:2783-2850`) — classify by `st.rel_script.file_name()` and re-check `handler_identity_lexical_admit`; keep the canonical path for containment, authorization and inode binding.
3. **Files-scoped `SetHandler` force** (`bind_target_grant`/`evaluate_scope_for_path`) — when the explicit target differs from the lexical request path, re-admit the force through the lexical `<Files>`/`<FilesMatch>` match predicate (fail closed on disagreement); access rules keep the canonical evaluation.
4. **Binding-wide invariant**: make `handler_identity_lexical_admit` (or a successor kernel) a *required* argument of every handler-selection site, and extend the F69 regression to (`/link.txt/x`, FastCGI `SetHandler`, Files-scoped `SetHandler`, each with/without a `<Location>` guard) so one decision site cannot regress without the others.
5. Consider tightening `authorize_resolved_target` so a script selected under a lexical URL also evaluates the canonical target URL's URL-scope policy (defence in depth if a future transform reintroduces a canonical-name fixup).
