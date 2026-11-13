# Pass 17 — adversarial break of HEAD `b8f68b5` ("Harden policy identity and proxy byte handling")

- **Date:** 2026-10-28
- **Subject:** `target/release/httpd-rs` built at HEAD `b8f68b5`. No product source was edited. The only retained additions for this pass are `adversarial/p17/exploit_p17.py`, this write-up and the `adversarial/README.md` index entry.
- **Oracle:** Apache/2.4.69 (Debian), `/usr/sbin/apache2 -X`, with `mod_proxy_fcgi`; PHP-FPM 8.4.27 (`php-fpm8.4`, Unix socket). Loopback only.
- **Harness:** `adversarial/p17/exploit_p17.py` — 15 differential verdicts across four cases (A–D), with index, static-source, plain-`.txt` and canonical-guard controls. The PHP-FPM access log is kept at `/tmp/opencode/p17-harness/fpm/access.log` after every run.
- **Method:** targeted audit of every FastCGI target constructor after the P15 lexical-`SCRIPT_FILENAME` fix, then a live Apache-versus-httpd-rs differential against PHP-FPM's `security.limit_extensions` gate.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P17-A** | The resolved-file `SetHandler "proxy:…\|fcgi://…"` branch builds the wire `SCRIPT_FILENAME` from the **canonical symlink target** instead of the **lexical request-mapped path**. PHP-FPM therefore applies `security.limit_extensions` to a different name than it does under Apache | The request-mapped `.txt` path is forwarded; PHP-FPM's extension gate sees `.txt` and refuses with `403 Access denied.` | The canonical `.php` target is forwarded; PHP-FPM sees `.php` and executes the file as `www-data` (`200 PHPEXEC …`) | remote PHP code execution / backend policy-gate bypass when the direct upload URL is hardened static |

The security-relevant exploit shape is a FastCGI `SetHandler` that covers the lexical non-PHP request (a global/per-directory handler or an access-file handler), plus an in-root symlink into an upload tree where the operator has disabled direct PHP execution:

```apache
<Directory "/srv/app/www">
    SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
</Directory>
<Directory "/srv/app/www/uploads">
    SetHandler none                  # direct uploads are static data
</Directory>
```

```
/srv/app/www/pub/upload-link.txt -> ../uploads/shell.php    (attacker-created in-root link)
/srv/app/www/uploads/shell.php       attacker-uploaded PHP content
```

```
GET /uploads/shell.php
  Apache 2.4.69: 200 static source        httpd-rs HEAD: 200 static source
GET /pub/upload-link.txt
  Apache 2.4.69: 403 Access denied.       httpd-rs HEAD: 200 PHPEXEC uploads-shell uid=33
```

The direct URL is inert on both servers, so the operator's "no PHP in uploads" directive is live. Only the alternate `.txt` URL distinguishes the servers, and only httpd-rs reaches PHP-FPM with a name that satisfies `security.limit_extensions`. The same effect is demonstrated with an access-file handler in case C. A handler scoped to `\.php$` alone does not match the `.txt` URL and is not affected by this specific bypass; the vulnerable forms are the supported global/per-directory and access-file `SetHandler` spellings.

Case A (without the uploads hardening) isolates the same `SCRIPT_FILENAME` differential. In that configuration the direct `.php` upload is already executable on both servers, so case A is the mechanism control rather than the security-relevant advantage; cases B and C are the RCE chains where Apache's hardened upload stays inert and httpd-rs executes it.

---

## 2. Root cause

### 2.1 The documented invariant

`Target.script_filename` is documented as the **lexical** value sent to the backend, with the canonical object kept separately for authorization:

```rust
// crates/server/src/fastcgi.rs:61-65
impl Target {
    /// Exact FastCGI transport plus both script identities used for resource
    /// binding. `script_filename` is the lexical Apache-compatible value sent
    /// to the backend; `authorized_path` is the canonical opened object whose
    /// inode and policy were authorized (P15-A).
```

(`authorized_path` is supplied separately to `binding_key`; it is not a stored field.)

`execute_inner` sends exactly that field:

```rust
// crates/server/src/fastcgi.rs:780-783
env.push((
    OsString::from("SCRIPT_FILENAME"),
    OsString::from(target.script_filename.to_string_lossy().into_owned()),
));
```

After P15, `match_proxy`/`split_path_info` construct `Target.script_filename` from the lexical route path, and `run_fastcgi` resolves that path to a descriptor for authorization without rewriting the wire identity:

```rust
// crates/server/src/server.rs:3248-3259
// Resolve the actual script through an opened descriptor first. The
// canonical object is the authorization identity, but Apache forwards the
// lexical split prefix as SCRIPT_FILENAME and lets PHP-FPM apply
// `security.limit_extensions` to that name. Conflating the two identities
// bypassed the backend's own gate (P15-A).
...
let Some(script_binding) = fastcgi::open_script(&target, mapping_root, ...)
```

### 2.2 The remaining constructor

The direct resolved-file handler is a **separate constructor** and still conflates the two identities:

```rust
// crates/server/src/fastcgi.rs:417-447
/// Handler selection for a resolved file.  `name` is the lexical
/// request-mapped basename used for classification; the actual opened target
/// supplies only `SCRIPT_FILENAME`, containment and authorization (P13/I70).
pub(crate) fn handler_target_for_file(
    scope: &Scope,
    root: &Path,
    url_path: &str,
    actual_path: &Path,
    name: &[u8],
) -> Option<Target> {
    let handler = crate::config::effective_handler(scope, name)?;
    ...
    let script_filename = clean_script_path(actual_path);   // canonical
    ...
    Some(Target {
        backend,
        script_filename,
        script_name: url_path.to_string(),
        ...
    })
}
```

The constructor comment documents the split rather than hiding it: `actual_path` supplies `SCRIPT_FILENAME` (plus containment and authorization), while only classification uses the lexical name. That was the P13 contract — but it conflicts with the `Target.script_filename` invariant and with the P15 closure claim that the canonical object is no longer sent to the backend.

```rust
// crates/server/src/server.rs:2638-2673
let actual_path = crate::files::fd_path(&file).unwrap_or_else(|| fs_path.clone());
...
let name = fs_path
    .file_name()
    .or_else(|| actual_path.file_name())
    ...
    .map(|n| n.as_encoded_bytes())
    .unwrap_or(b"");
...
// crates/server/src/server.rs:2709-2710
if let Some(target) =
    fastcgi::handler_target_for_file(scope, &root, &url_path, &actual_path, name)
{
    return run_fastcgi(...);
}
```

So handler **selection** uses the lexical basename (the P13 fix), but the **backend identity** does not. `run_fastcgi` then reopens `target.script_filename` (`fastcgi.rs:732-760`) and authorizes its canonical path (`server.rs:3286-3301`), which is internally consistent — it is simply the wrong name to hand to a backend that makes its own policy decision.

The result is the same identity split P15 fixed for `ProxyPassMatch`: PHP-FPM's `security.limit_extensions` is evaluated against the canonical `.php` target on httpd-rs and against the requested `.txt` path on Apache. The closure document currently states the invariant globally:

```text
docs/adversarial-closure.md:198-200
- FastCGI receives the already-bound lexical basename and sends the lexical
  split path as `SCRIPT_FILENAME`; the canonical opened path is used for
  containment, authorization and inode binding.
```

That is true for the prefix/regex route constructors but false for `handler_target_for_file`.

### 2.3 Why PHP-FPM's gate matters

Apache's `mod_proxy_fcgi` forwards the request-mapped filename as `SCRIPT_FILENAME`. PHP-FPM applies `security.limit_extensions` (and `cgi.fix_pathinfo`) to that name before executing. On Debian, the stock pool leaves `security.limit_extensions` unset, so PHP-FPM's built-in `.php .phar` default applies and a syntactically perfect PHP file named `.txt` is refused through the FastCGI backend. The harness pins that value explicitly for reproducibility:

```ini
php_admin_value[security.limit_extensions] = .php .phar
```

This is a backend-side defense the operator gets with Apache for free. With httpd-rs's canonical `SCRIPT_FILENAME`, a `.txt` URL resolves to a `.php` canonical target and the gate is satisfied.

---

## 3. Exploit chain (observed)

### 3.1 Deployment

```apache
DocumentRoot "/srv/app/www"

<Directory "/srv/app/www">
    Options +FollowSymLinks
    AllowOverride None
    Require all granted
    SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
</Directory>

DirectoryIndex index.php
```

Both spellings of the documented handler work:

```apache
SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost/"
```

The global/per-directory `SetHandler` form is a supported PHP-FPM vhost recipe; the same bug is reachable from any handler scope that covers the lexical `.txt` name: a per-directory handler or an access-file handler (cases B and C). A `<FilesMatch "\.php$">` handler alone does not route a `.txt` URL to FastCGI, so it is not vulnerable to this exact shape.

Fixture:

```
/www/index.php                      PHP marker (control)
/www/secret/app.php                 PHP marker "secret-app"
/www/uploads/shell.php              PHP marker "uploads-shell"  (attacker content)
/www/uploads/note.txt               static upload
/www/pub/link.txt          -> ../secret/app.php
/www/pub/upload-link.txt   -> ../uploads/shell.php
/www/pub/note.txt                   static public file
/www/plain.txt                      static non-PHP file (backend-gate control)
```

### 3.2 Case A — global `SetHandler`, no guards

| Request | Apache 2.4.69 | httpd-rs HEAD | Evidence |
|---|---|---|---|
| `/index.php` | `200` `PHPEXEC index` | `200` `PHPEXEC index` | handler live on both |
| `/pub/link.txt` | `403 Access denied.` | `200` `PHPEXEC secret-app uid=33` | FPM gate vs canonical `.php` |
| `/pub/upload-link.txt` | `403 Access denied.` | `200` `PHPEXEC uploads-shell uid=33` | uploaded content executed |
| `/plain.txt` | `403 Access denied.` | `403 Access denied.` | no symlink; gate fires on both |

The PHP-FPM access log (`access.format = "%f|%r"`) shows the identity drift directly. Each request is sent to Apache first and httpd-rs second, so the paired lines are Apache then httpd-rs:

```
/tmp/opencode/p17-harness/A/www/pub/link.txt|/pub/link.txt
/tmp/opencode/p17-harness/A/www/secret/app.php|/pub/link.txt
/tmp/opencode/p17-harness/A/www/pub/upload-link.txt|/pub/upload-link.txt
/tmp/opencode/p17-harness/A/www/uploads/shell.php|/pub/upload-link.txt
```

Apache sends the lexical `.txt` name (the line immediately before each canonical line); httpd-rs sends the resolved `.php` name. Only the canonical names pass `security.limit_extensions`.

The response bodies are unambiguous:

```
Apache  /pub/upload-link.txt: 403  "Access denied."
httpd-rs /pub/upload-link.txt: 200  "PHPEXEC uploads-shell uid=33"
```

`uid=33` is the PHP-FPM worker (`www-data`), i.e. code execution in the backend worker context.

Case A isolates the wire-identity differential. Because this fixture does not disable execution under `/uploads`, the direct `/uploads/shell.php` URL is executable on both servers; an attacker who can upload there already has RCE under either server. The security-relevant advantage is cases B and C, where the direct upload URL is static on both and only the alternate symlink URL executes — on httpd-rs.

### 3.3 The benchmark `ProxyPassMatch` branch is not the vulnerable one

The project's benchmark uses a prefix/regex route, not `SetHandler`:

```python
# bench/app_bench.py:193
ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:{php_socket}|fcgi://localhost{docroot}/"
```

That constructor goes through `match_proxy`/`split_path_info`, which P15 converted to the lexical identity. The existing P15 regression `test_p15_a_fastcgi_forwards_lexical_script_identity` passes at this HEAD, and the old P15 exploit URL `/pub/open.txt/x.php` now returns `403` on both servers. P17 is therefore a **remaining** FastCGI identity branch, not a regression of the benchmark spelling: it affects the documented `SetHandler` deployment class, which is supported and occurs in real PHP-FPM vhosts and shared-hosting trees, as advertised in `README.md` ("Native FastCGI for PHP-FPM and compatible responders via `ProxyPassMatch` and `SetHandler "proxy:fcgi://..."`").

### 3.4 Case B — operator disabled PHP execution in the upload tree

```apache
<Directory "/srv/app/www/uploads">
    SetHandler none
</Directory>
```

| Request | Apache 2.4.69 | httpd-rs HEAD |
|---|---|---|
| `/uploads/shell.php` | `200`, body starts `<?php` (static source) | `200`, body starts `<?php` (static source) |
| `/pub/upload-link.txt` | `403 Access denied.` | `200` `PHPEXEC uploads-shell uid=33` |

The direct upload URL is inert on both servers, so the operator's "no PHP in uploads" directive is live. The alternate URL still reaches the global handler in the `pub` scope on both servers; Apache's backend refuses the `.txt` name, while httpd-rs hands the backend the canonical `.php` name and executes the same uploaded content. This is the operational difference that matters: a defense that works on the direct URL is bypassed through an in-root symlink only on httpd-rs.

The case-B FPM log shows the same pair as case A:

```
/tmp/opencode/p17-harness/B/www/pub/upload-link.txt|/pub/upload-link.txt
/tmp/opencode/p17-harness/B/www/uploads/shell.php|/pub/upload-link.txt
```

### 3.5 Case C — Debian-style `<FilesMatch>` plus access-file handlers

```apache
# main configuration
<FilesMatch "\.php$">
    SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
</FilesMatch>

# pub/.htaccess
SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"

# uploads/.htaccess
<FilesMatch "\.php$">
    SetHandler default-handler
</FilesMatch>
```

`AllowOverride All` is required for this case. Observed:

| Request | Apache 2.4.69 | httpd-rs HEAD |
|---|---|---|
| `/index.php` | `200` `PHPEXEC index` | `200` `PHPEXEC index` |
| `/uploads/shell.php` | `200`, `<?php` source | `200`, `<?php` source |
| `/pub/upload-link.txt` | `403 Access denied.` | `200` `PHPEXEC uploads-shell uid=33` |
| `/plain.txt` | `200` `PLAIN` | `200` `PLAIN` |

This is the shared-hosting shape: the application (or an attacker who can write the access file) selects the FastCGI handler for a directory, and the upload tree's access file disables PHP execution for `.php` names. The symlink request gets the proxy handler from `pub/.htaccess` on both servers, but the canonical target name again passes FPM's gate only on httpd-rs. The static and index controls show the fixture is not misconfigured in a way that makes every request dynamic. Case C produces the same FPM pair under `C/`:

```
/tmp/opencode/p17-harness/C/www/pub/upload-link.txt|/pub/upload-link.txt
/tmp/opencode/p17-harness/C/www/uploads/shell.php|/pub/upload-link.txt
```

### 3.6 Case D — negative controls: this is not an access-control bypass

```apache
<Location "/uploads/">
    Require all denied
</Location>
<Directory "/srv/app/www/uploads">
    Require all denied
</Directory>
```

| Request | Apache 2.4.69 | httpd-rs HEAD |
|---|---|---|
| `/uploads/shell.php` | `403` | `403` |
| `/pub/upload-link.txt` | `403` | `403` |
| `/index.php` | `200` `PHPEXEC index` | `200` `PHPEXEC index` |

httpd-rs reauthorizes the canonical target before dispatch (`server.rs:3286-3318`), so both the `<Directory>` filesystem policy and the canonical target URL scope close the symlink route. The FPM log for case D contains only Apache's lexical line for `/pub/upload-link.txt`; httpd-rs denies before opening the backend. Unlike P15-A, P17 is **not** an alternate-route authorization bypass of a live `<Location>`/`<Directory>` guard. The defect is specifically the backend-policy identity.

---

## 4. Impact

- **Remote code execution as the PHP-FPM worker user** in a FastCGI `SetHandler` deployment whose handler scope covers the lexical non-PHP request (global/per-directory handler, or an access-file handler) and whose direct upload URL is hardened static (`SetHandler none` in case B, access-file `default-handler` in case C). The attacker needs the same in-root-symlink primitive prior passes already treat as reachable (archive extraction that preserves symlink entries, application-created links, backup/migration tooling, file-manager features), plus attacker-controlled content in a canonical file whose extension PHP-FPM accepts (`.php`/`.phar` in the stock policy). The **requested symlink name** need not have a PHP extension; that is the lexical name FPM sees under Apache and the reason Apache refuses it.
- **Bypasses PHP-FPM's `security.limit_extensions` defense.** The same configuration and the same backend refuse the request under Apache with `403 Access denied.` and execute it under httpd-rs. The operator gets a weaker gate than Apache from identical configuration.
- **Defeats the operator's upload-execution hardening end-to-end.** `SetHandler none` (case B) and an access-file `SetHandler default-handler` (case C) make the direct upload URL static on both servers. The alternate URL is handled by the global/access-file proxy handler on both servers, but Apache's backend gate is the only thing that keeps it inert; httpd-rs removes that gate and executes the same uploaded content, turning a file the application treats as inert data into PHP code.
- **Case A is isolation, not the exploit claim.** Without the upload-tree hardening, both servers execute the direct `.php` upload, so the `.txt` differential alone does not give httpd-rs an RCE advantage over Apache. The security-relevant deployments are B/C, where Apache keeps the hardened file inert and httpd-rs executes it through the alternate URL.
- **Handler identity is only half-fixed.** P13 made handler **classification** lexical so a `.txt` symlink does not inherit an extension-table `.php` handler. P15 made the `ProxyPassMatch`/`PATH_INFO` **wire identity** lexical. The resolved-file `SetHandler` constructor still uses the canonical target for the wire parameter, so a request whose lexical name is not PHP reaches the backend with a canonical `.php` name and satisfies a gate Apache would fail.
- **No malformed request or parser differential is required.** The trigger is a well-formed GET to a symlink. Apache and httpd-rs agree on the URL, the symlink resolution, the handler selection for the lexical name, and the canonical authorization target; they disagree only on the name handed to the backend.
- **Reachability.** Any scope that applies a FastCGI `SetHandler` to a resolved file is affected when the scope covers the lexical non-PHP name: global `<Directory>`, per-directory, and access-file handlers (cases A–C). Both URL spellings (`fcgi://localhost` and `fcgi://localhost/`) were verified. TCP backends use the same constructor; they were not separately run, but the defect is in the path construction rather than the transport.

### Limitations

- The direct upload URL is not executable in cases B/C; the attacker must route through a symlink (or another path that maps a non-PHP lexical name to the canonical PHP file). P17 does not turn an arbitrary file upload into RCE by itself.
- The symlink must be inside the FastCGI script base (the document root for the no-prefix handler) and must resolve to an existing file under that base; `handler_target_for_file` and `open_script` enforce containment.
- `<Location>`/`<Directory>` denies on the canonical target are still honored (case D), so this is not an authorization bypass of those guards. A deployment whose only protection is such a guard is not affected by this specific finding.
- The backend must have an extension gate that distinguishes the lexical and canonical names (the stock PHP-FPM default does; a pool with `security.limit_extensions` disabled does not rely on this gate in either server).
- The result is code execution as the FPM worker, not privilege escalation beyond that account; the worker's filesystem and database credentials are the blast radius.

---

## 5. Fix

### 5.1 Preferred: send the lexical request-mapped path

Make `handler_target_for_file` honor the `Target.script_filename` invariant already stated in `fastcgi.rs:61-65` and implemented for the other constructors:

1. Pass the lexical request-mapped path (`fs_path`, or the resolved lexical path produced by the same mapping Apache uses) into the constructor alongside `actual_path` and `name`.
2. Use the lexical path for the wire `SCRIPT_FILENAME`, mapped through the configured backend prefix exactly as `handler_target`/`script_from_prefix` do. Keep `actual_path` for `script_under_base`, `contained_after_resolving_symlinks`, canonical authorization, `binding_key` and `ScriptBinding`.
3. Keep the P15 pre-send binding: `retain_script_path_binding` must reopen the **wire** path (`target.script_filename`) and verify it still resolves to the authorized inode, failing closed on mismatch. With a lexical `.txt` path this reopen follows the symlink to the same `.php` inode, so the anti-TOCTOU property is preserved.
4. Add a regression that selects a FastCGI `SetHandler` for a `.txt` symlink and asserts the backend receives the lexical `.txt` name, not the canonical target. The existing P15 test covers only `ProxyPassMatch`; the mock-FastCGI tests in `tests/adversarial_regressions.py` are the natural place to pin the parameter, and the live PHP-FPM case A is the end-to-end proof.

This mirrors Apache exactly and lets PHP-FPM apply the same `security.limit_extensions`/`cgi.fix_pathinfo` decision it applies under Apache.

### 5.2 Defense in depth: fail closed on identity disagreement

If carrying a second identity is too invasive for the immediate fix, refuse the request **with an explicit 403** when the canonical basename/extension differs from the lexical `name`:

```rust
// at the dispatch site, before static/CGI fallthrough
if actual_path.file_name().map(|n| n.as_encoded_bytes()) != Some(name) {
    return error_response(..., 403, ...);
}
```

The explicit error matters: merely returning `None` from `handler_target_for_file` would fall through to the normal static path and serve the canonical target's **source** as static content, which is worse than Apache's `403 Access denied.`. With a 403 at the call site, case A/B/C return the same security outcome as Apache for the `.txt` symlink while leaving legitimate same-name symlinks working.

The check is stricter than Apache for the opposite direction (lexical `.php` -> canonical `.txt`): Apache's backend sees the lexical `.php` name and would execute the target content, whereas the fail-closed check would deny it. The lexical-wire fix in §5.1 is therefore preferred for parity. The check remains useful as a last-resort assertion at the FastCGI boundary.

### 5.3 Do not regress the controls

- Keep case A's `/index.php` and `/plain.txt` rows: normal PHP execution and the plain `.txt` gate must still behave identically.
- Keep case B/C direct-upload rows: `SetHandler none`/`default-handler` must still serve static source on the direct URL.
- Keep case D: canonical `<Location>`/`<Directory>` denies must still close the symlink route. A fix that sends the lexical path must not weaken the existing canonical reauthorization.
- Update `docs/adversarial-closure.md` so the "FastCGI sends the lexical split path" invariant explicitly covers `handler_target_for_file`, and add the new regression to the P13/P15 closure rows.

---

## 6. Reproduction

```sh
# Build the tested HEAD
cargo build --release -p httpd-rs

# Full pass-17 battery (15 verdicts, cases A-D)
python3 adversarial/p17/exploit_p17.py

# Selected cases
python3 adversarial/p17/exploit_p17.py A B
python3 adversarial/p17/exploit_p17.py --show-fpm-log

# Keep the fixture and print paired SCRIPT_FILENAME evidence
python3 adversarial/p17/exploit_p17.py --keep --show-fpm-log
```

Expected final line:

```
15 verdict(s) passed
```

The harness builds the fixture under `/tmp/opencode/p17-harness`, starts Apache and httpd-rs on sibling loopback ports, starts a private PHP-FPM pool with `security.limit_extensions = .php .phar`, and kills only its own process groups. `--show-fpm-log` prints the paired access-log lines that prove the identity drift:

```
/www/pub/link.txt|/pub/link.txt          <- Apache, FPM gate -> 403
/www/secret/app.php|/pub/link.txt        <- httpd-rs, canonical -> 200 exec
```

The harness requires `apache2` with `mod_proxy_fcgi` and a PHP-FPM binary (`php-fpm8.4`, `8.3`, `8.2` or `php-fpm`). The Apache module directory can be overridden with `APACHE_MODDIR`; the Apache binary with `APACHE`.

---

## 7. Scope and limitations

- **Local only.** Every server binds `127.0.0.1`; PHP-FPM uses a Unix socket under the fixture. No external address or backend is contacted.
- **No product source changes.** The evidence is produced by the unmodified `target/release/httpd-rs` built from HEAD `b8f68b5`.
- **Handler deployment.** The finding affects resolved-file FastCGI `SetHandler` targets whose scope covers the lexical non-PHP name: a global/per-directory handler or an access-file handler. A `<FilesMatch "\.php$">` handler alone does not match the `.txt` URL and is not affected by this specific bypass. The benchmark `ProxyPassMatch` route is fixed by P15 and is exercised as a control; a deployment that uses only `ProxyPassMatch` is not affected by this branch. The global/per-directory and access-file `SetHandler` forms are documented, supported, and occur in real vhosts and shared-hosting trees, so this is a typical-deployment finding rather than a benchmark-only parity issue.
- **Symlink precondition.** The attacker needs an in-root symlink in a directory whose handler scope selects FastCGI, pointing to a file under the script base whose lexical extension is not accepted by PHP-FPM and whose canonical extension is. This is the same primitive P13 and P15 already treat as attacker-reachable; the pass does not claim that a plain file upload alone creates the link.
- **Case C access-file precondition.** Case C requires `AllowOverride All` (or the relevant `FileInfo` categories) and a writable access file in the proxied directory; it is the shared-hosting/application-managed deployment class. Case B uses main-configuration directives only.
- **Canonical guards still bind.** Case D shows `<Location>`/`<Directory>` denials on the target are enforced by httpd-rs. The finding is the backend extension-gate bypass, not a bypass of those access controls.
- **Backend posture.** The differential is observable with PHP-FPM's stock `security.limit_extensions`. A pool that explicitly disables the gate is relying on other controls; the canonical-name drift still changes what the backend sees, but the demonstrated `403`-versus-execution difference depends on the gate being enabled.
- **No denial-of-service, memory-safety or privilege-escalation claim.** The harness records status, body markers and the FPM access log only.

---

## 8. Disclosure summary

| ID | Component | Preconditions | Observed effect |
|---|---|---|---|
| P17-A | `server.rs::run_fastcgi` → `fastcgi.rs::handler_target_for_file` (`script_filename = clean_script_path(actual_path)`) → `execute_inner` (`fastcgi.rs:780-783`) → PHP-FPM `security.limit_extensions` | A FastCGI `SetHandler` applies to a resolved file; an in-root symlink has a non-PHP lexical name and a canonical `.php` target; attacker content is reachable through that target | Apache `403 Access denied.` vs httpd-rs `200` PHP execution as `www-data`; uploaded content executes through the alternate URL even when the direct upload URL is static (`SetHandler none`/`default-handler`) |

The exact exploit shapes are retained in `adversarial/p17/exploit_p17.py`; the next pass should re-run the battery after any change to `handler_target_for_file`, `Target.script_filename`, FastCGI authorization/binding, or the `SetHandler` dispatch path.
