# Pass 18 — adversarial break of HEAD `b8f68b5` ("Harden policy identity and proxy byte handling")

- **Date:** 2026-10-28
- **Subject:** `target/release/httpd-rs` built at HEAD `b8f68b5`. No product source was edited. The retained additions for this pass are `adversarial/p18/exploit_p18.py`, this write-up and the `adversarial/README.md` index entry.
- **Oracle:** Apache/2.4.69 (Debian), `/usr/sbin/apache2 -X`, with `mod_proxy_fcgi` and `mod_cgi`; PHP-FPM 8.4.27 for the PHP cases. Loopback only.
- **Harness:** `adversarial/p18/exploit_p18.py` — **14 differential verdicts** across a PHP-FPM chain (A) and a CGI chain (B), with scoped-target, no-access-file, plain-`Require` and `AllowOverride AuthConfig` parity controls.
- **Retained evidence:** `/tmp/opencode/p18-harness` (fixtures, per-case Apache error logs, FPM access log and private FPM pool).
- **Method:** targeted audit of the `AllowOverrideList` admission predicate in `htaccess.rs`, followed by a live Apache-versus-httpd-rs differential against a file-scoped upload-execution guard.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P18-A** | With `AllowOverride None` plus `AllowOverrideList Require`, an attacker-written `.htaccess` can contain a `<Files>` or `<FilesMatch>` section. Apache rejects the section itself (`500`, fail closed); httpd-rs parses it unconditionally, permits the inner listed `Require`, and applies its file-scoped grant over the main `<FilesMatch ...> Require all denied` guard | `500`; `.htaccess: <Files not allowed here` (or `<FilesMatch not allowed here`) | `200`; uploaded PHP executes as the FPM worker (`PHPEXEC … uid=33`) or uploaded CGI executes as `www-data` (`EXEC uid=33`) | remote code execution / access-file section-gating bypass |

The exploit shape is a direct upload; it needs **no symlink**, no path traversal, and no FastCGI `SCRIPT_FILENAME` trick. An attacker who can write `.htaccess` into an upload directory, and can upload a PHP/CGI script there, adds:

```apache
<Files "shell.php">
    Require all granted
</Files>
```

The directory's main configuration is:

```apache
<Directory "/srv/app/www/uploads">
    AllowOverride None
    AllowOverrideList Require
    SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
    <FilesMatch "\.php$">
        Require all denied
    </FilesMatch>
</Directory>
```

Apache treats `AllowOverrideList Require` as permission for the **directive** `Require` only. A container section is not itself one of the listed directives, so Apache aborts the access file with `500` and never reaches the handler. httpd-rs's parser admits the container without consulting the list, then admits the inner `Require` because `Require` is in the list. The section's grant is scoped to `shell.php`, overrides the outer file-scoped deny, and the uploaded PHP/CGI is executed by the already-configured handler.

The scoped `ok.php`/`ok.cgi` control remains `403` on httpd-rs, so the bypass is not a blanket directory grant. Apache returns `500` for both names because the attacker's access file itself is invalid under its configuration.

---

## 2. Observed differential

The harness uses sibling loopback instances of Apache and httpd-rs with the same fixture. The main configuration for **A** uses a per-directory FastCGI handler (`P18-A`), a parent `<FilesMatch>` handler (`P18-A2b`), or the same outer deny with an access-file `<FilesMatch>` instead of `<Files>` (`P18-A2`). **B** uses `AddHandler cgi-script .cgi` plus `Options +ExecCGI`.

### 2.1 PHP-FPM: uploaded PHP becomes `www-data`

Fixture request target: `/uploads/shell.php?who=probe`. The uploaded file writes `PWNED who=probe uid=33` to `uploads/pwned.txt`, reads a file outside the web root (`S3CRET`), and echoes:

```
PHPEXEC who=probe uid=33 marker=S3CRET wrote=yes
```

Observed:

| Case | Apache 2.4.69 | httpd-rs HEAD |
|---|---|---|
| `P18-A` `<Files "shell.php"> Require all granted`, per-directory FastCGI handler | `500`; `PWNED` absent | `200`; `PHPEXEC who=probe uid=33 marker=S3CRET wrote=yes`; `PWNED who=probe uid=33` written |
| `P18-A` same `.htaccess`, `/uploads/ok.php` (outside the `<Files>` grant) | `500`; `PWNED` absent | `403 Forbidden`; `PWNED` absent |
| `P18-A2` `<FilesMatch "^shell\.php$">` grant | `500`; `.htaccess: <FilesMatch not allowed here` | `200`; PHP executed, marker written |
| `P18-A2b` parent `<FilesMatch "\.php$"> SetHandler` plus the same section | `500`; `.htaccess: <Files not allowed here` | `200`; PHP executed, marker written |
| `P18-A3` no access file | `403`; outer deny | `403`; outer deny |
| `P18-A4` top-level `.htaccess` `Require all granted` | `403`; outer deny | `403`; outer deny |
| `P18-A5` `AllowOverride AuthConfig` plus the same `<Files>` section | `200`; `PHPEXEC … uid=33` | `200`; `PHPEXEC … uid=33` |
| `P18-A5` scoped `ok.php` under AuthConfig | `403` | `403` |

The **P18-A5** row is the parity control: when the override policy is `AuthConfig` rather than a directive-only `AllowOverrideList`, Apache accepts the section and both servers execute it. The differential is therefore the section gating specific to `AllowOverrideList`, not the section itself or the PHP handler.

The Apache error log for the exploit case contains:

```text
[core:alert] ... /tmp/opencode/p18-harness/P18-A-php-allowoverridelist/www/uploads/.htaccess: <Files not allowed here
```

The FPM access log records the backend execution on httpd-rs:

```text
/tmp/opencode/p18-harness/P18-A-php-allowoverridelist/www/uploads/shell.php|/uploads/shell.php
```

There is no FPM line for the Apache request because Apache rejects the access file before reaching `mod_proxy_fcgi`.

### 2.2 CGI: arbitrary command execution

The same access-file section against a CGI handler (`AddHandler cgi-script .cgi`, `Options +ExecCGI`, outer `<FilesMatch "\.cgi$"> Require all denied`) produces:

| Case | Apache 2.4.69 | httpd-rs HEAD |
|---|---|---|
| `P18-B` `<Files "shell.cgi"> Require all granted` | `500`; `PWNED` absent | `200`; `EXEC uid=33 who=probe`; `PWNED who=probe uid=33` written |
| `P18-B` `/uploads/ok.cgi` | `500`; `PWNED` absent | `403`; `PWNED` absent |
| `P18-B2` no access file | `403` | `403` |
| `P18-B3` plain top-level `Require all granted` | `403` | `403` |
| `P18-B4` `AllowOverride AuthConfig` plus the section | `200`; `EXEC uid=33` | `200`; `EXEC uid=33` |

The CGI script is a normal uploaded executable script (mode `0755`). Its output and the `pwned.txt` side effect show that httpd-rs's handler path is not merely serving source: it runs the script as the worker user. Apache's `500` is a fail-closed response to the invalid `.htaccess`.

### 2.3 What the controls rule out

- **The outer guard is live without the access file.** `P18-A3`/`P18-B2`: both servers return `403` for the same uploaded script when no `.htaccess` is present.
- **A plain `Require` is not enough.** `P18-A4`/`P18-B3`: a top-level `.htaccess` `Require all granted` is accepted by Apache under the allow-list, but both servers still return `403`; the main `<FilesMatch>` deny is more specific. The attacker needs a file-scoped section.
- **The result is scoped.** The exact-name `<Files>` section grants `shell.php` only; `ok.php` remains `403` on httpd-rs (Apache `500` for both because the access file is invalid).
- **The section is valid under ordinary category overrides.** `P18-A5`/`P18-B4`: `AllowOverride AuthConfig` with the same section returns `200` on both servers. The bug is not “httpd-rs allows `<Files>` sections”; it is “httpd-rs allows the section under `AllowOverrideList` where Apache does not.”
- **The FPM/CGI backend is otherwise functional.** A5/B4 parity demonstrates the handler and script; the exploit difference is the access-file admission, not a broken backend.

---

## 3. Root cause

### 3.1 The documented model

`docs/config-semantics.md:170-181` states:

```text
- `AllowOverrideList` permits individual directive names even when
  `AllowOverride None` would otherwise disable access files; the effective
  permission set is the union of both;
...
- the section containers `<If>`, `<IfFile>`, `<Files>`, `<FilesMatch>` do not
  themselves require a category; the directives **inside** them do;
```

The first sentence is correct for a **directive** admitted by the list. The second sentence is the incorrect generalization: Apache's `AllowOverrideList` does not admit a container section merely because a directive name inside it is listed. In Apache 2.4.69, a `.htaccess` containing `<Files>` or `<FilesMatch>` under `AllowOverrideList Require` is rejected as invalid:

```text
.htaccess: <Files not allowed here
```

Apache's category-based `AllowOverride AuthConfig`/`FileInfo` does allow these containers (our A5/B4 controls), so the model is right for categories and wrong for the directive-only list. The practical consequence is a fail-open policy: Apache returns `500`; httpd-rs applies the file-scoped grant and continues.

### 3.2 The parser branch

`crates/server/src/htaccess.rs:1135-1176` handles the two container forms:

```rust
"files" | "filesmatch" => {
    // The override category applies to the directives inside
    // the section, not to the section itself.
    if require_only {
        return Err(format!("line {}: <{name}> is not allowed here", *i));
    }
    let pat = args.join(" ");
    let kind = ...;
    let mut inner = Scope::default();
    let mut inner_rules = Vec::new();
    parse_block(
        cfg,
        lines,
        i,
        &mut inner,
        &mut inner_rules,
        mode,
        allow_list,
        ...
    )?;
    rules.push(ScopeRule {
        kind,
        delta: inner,
        ...
    });
}
```

`mode` and `allow_list` are passed into the recursive parse, but the branch never checks them for the **container**. It only checks `require_only` (a different nested-section restriction). The comment states the exact invariant that Apache disproves for `AllowOverrideList`.

The inner `Require` is then admitted by `directive_allowed_list`:

```rust
// crates/server/src/htaccess.rs:1811-1822
fn directive_allowed_list(
    mode: OverrideMode,
    allow_list: &[String],
    name: &str,
    args: &[String],
) -> bool {
    if allow_list
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(name))
    {
        return true;
    }
    ...
}
```

With `AllowOverrideList Require`, the inner `Require` passes because its name is in the allow-list. The container never reaches an equivalent gate. The resulting `ScopeRule` is a file-phase rule (`MatchKind::Files`/`FilesMatch`), so it is applied to the request's basename after the main `<FilesMatch ...> Require all denied` of the uploads directory and the section-scoped grant wins for `shell.php`.

In short: the code and documentation model `AllowOverrideList` as a union of individually admitted directives, but Apache also gates the **section wrapper**. httpd-rs applies the wrapper and the inner listed directive, turning a fail-closed Apache configuration into a fail-open httpd-rs one.

### 3.3 Why the file-scoped wrapper matters

The attacker cannot use a top-level `Require all granted` for this bypass: under the same allow-list, Apache and httpd-rs both accept it, but the main `<FilesMatch>` deny is still more specific and both return `403` (A4/B3). The `<Files>`/`<FilesMatch>` section is the mechanism that targets the denied basename; httpd-rs permits it, Apache rejects it. The unit of the bypass is therefore the **container**, not merely the `Require` directive.

---

## 4. Exploit chain

### 4.1 PHP-FPM deployment

A typical hardening posture for an upload directory is:

```apache
<Directory "/srv/app/www/uploads">
    AllowOverride None
    AllowOverrideList Require
    SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
    <FilesMatch "\.php$">
        Require all denied
    </FilesMatch>
</Directory>
```

The `AllowOverrideList Require` is intended to permit small, per-directory authorization adjustments without granting `FileInfo`, `Options` or arbitrary `.htaccess` content. The `<FilesMatch>` deny is the execution guard for uploaded PHP. The handler can instead be placed in a parent:

```apache
<Directory "/srv/app/www">
    <FilesMatch "\.php$">
        SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
    </FilesMatch>
</Directory>
```

Both forms were tested (A and A2b); both execute on httpd-rs and return `500` on Apache after the access-file section is added.

Attacker steps:

1. Upload `shell.php` (arbitrary PHP) and `.htaccess` into `/srv/app/www/uploads/` through an application that allows file writes there.
2. Write the section:
   ```apache
   <Files "shell.php">
       Require all granted
   </Files>
   ```
3. Request `/uploads/shell.php`.

Observed on the harness:

```text
Apache:  500  <Files not allowed here (access file rejected)
httpd-rs: 200  PHPEXEC who=probe uid=33 marker=S3CRET wrote=yes
              pwned.txt: PWNED who=probe uid=33
```

The PHP process is the FPM worker (`uid=33`); the payload reads a file outside the document root and writes a marker. Arbitrary PHP code can call `system`, open sockets, modify application files, or read secrets within the worker's permissions.

### 4.2 CGI deployment

The CGI form uses the same access-file section and a normal handler configuration:

```apache
<Directory "/srv/app/www/uploads">
    AllowOverride None
    AllowOverrideList Require
    Options +ExecCGI
    AddHandler cgi-script .cgi
    <FilesMatch "\.cgi$">
        Require all denied
    </FilesMatch>
</Directory>
```

With an uploaded `shell.cgi` and `.htaccess`:

```apache
<Files "shell.cgi">
    Require all granted
</Files>
```

Apache returns `500` (`<Files not allowed here`); httpd-rs returns `200` and runs the script as `www-data`:

```text
EXEC uid=33 who=probe
pwned.txt: PWNED who=probe uid=33
```

`ok.cgi` remains `403` on httpd-rs, so the grant is scoped to the attacker's filename.

---

## 5. Impact and preconditions

**Impact.** A remote attacker who can write `.htaccess` and a PHP/CGI script into an affected upload directory obtains **remote code execution as the web-worker user** on httpd-rs. The harness demonstrates this with both a PHP-FPM backend and a POSIX CGI backend. The attacker can read files available to the worker (the harness reads a file outside the web root), write files in the upload tree, and run arbitrary commands through the executed script. Apache's response is a fail-closed `500`; the same access file does not execute there.

**Preconditions.**

1. **Write access to an access file and a script** in a directory served by httpd-rs. This is the same upload/`.htaccess` primitive used by the other access-file findings; the application must permit the `.htaccess` name (directly or through a rename/upload path).
2. **A directive-only override policy**: `AllowOverride None` plus a nonempty `AllowOverrideList` containing `Require` (or an equivalent policy that admits the inner `Require` but not the section). The exact hardening posture in the fixture is `AllowOverrideList Require`. This is not the Apache default, but it is a valid least-privilege configuration.
3. **An execution handler for the uploaded script**: a per-directory or parent FastCGI `SetHandler`, or CGI `AddHandler` with `Options +ExecCGI`. The PHP handler can be the documented FastCGI spelling.
4. **A file-scoped authorization guard** on the upload path, e.g. `<FilesMatch "\.php$"> Require all denied` or `<Files "*.cgi"> Require all denied`, which the attacker's section can target. Without such a guard, the uploaded script may already execute on both servers and there is no differential to exploit.
5. **No broader `AllowOverride` that admits the section on Apache.** With the tested `AllowOverride AuthConfig` (A5/B4), Apache accepts the section and both servers execute; ordinary category modes such as `All` likewise admit the section. This finding is specific to the directive-only `AllowOverrideList`.

A `<Location>` guard outside the file-scoped section still binds in the negative probe (both servers deny); the exploit targets the file-scoped authorization gate in the fixture. The no-`.htaccess` controls show that gate is otherwise effective.

**Severity.** Remote code execution, configuration-gated. In a deployment that uses the listed posture, the upload guard is the only barrier between an upload primitive and code execution; the differential is a high-impact fail-open. It is not a default-configuration RCE: `AllowOverrideList` is an opt-in policy, and a deployment with `AllowOverride All` is not affected by this exact section-gating mismatch.

---

## 6. Relationship to P17 and other findings

P18 is separate from P17:

- **P17** is a FastCGI `SCRIPT_FILENAME` canonicalization bug. A symlink named `.txt` points at `.php`; Apache forwards the lexical `.txt` to PHP-FPM and FPM's `security.limit_extensions` refuses it, while httpd-rs forwards the canonical `.php` and executes it. P17's differential is at the **backend script-identity** layer and requires a symlink; its Apache response is `403 Access denied.`
- **P18** has no symlink and no canonical/lexical backend identity. Apache rejects the attacker's `.htaccess` at **access-file parse time** (`500`, `<Files not allowed here`); httpd-rs accepts the container section and applies a file-scoped authorization grant. The upload is requested directly and executes. The two findings should not be merged: fixing P17's `SCRIPT_FILENAME` does not affect P18, and fixing P18's section gating does not affect P17.

P18 also differs from the P14 `<Files>` phase-order and P12/P13 handler-classification findings: those involve conflicting config/access-file scopes or canonical-target classification; P18 is a section-container admission mismatch under `AllowOverrideList`, observed with both PHP-FPM and CGI and with a clean A5/B4 parity control.

---

## 7. Reproduction

```sh
cargo build --release -p httpd-rs
python3 adversarial/p18/exploit_p18.py
# 14 verdict(s) passed
```

Optional evidence modes:

```sh
python3 adversarial/p18/exploit_p18.py A          # PHP-FPM chain
python3 adversarial/p18/exploit_p18.py B          # CGI chain (no PHP-FPM required)
python3 adversarial/p18/exploit_p18.py --show-fpm-log
```

The harness starts its own PHP-FPM pool under `/tmp/opencode/p18-harness/fpm` with
`php_admin_value[security.limit_extensions] = .php .phar`, and starts Apache and
httpd-rs on sibling loopback ports with separate pid files. It retains:

- `/tmp/opencode/p18-harness/<case>/error.log` — Apache's `<Files not allowed here` / `<FilesMatch not allowed here` evidence;
- `/tmp/opencode/p18-harness/fpm/access.log` — the PHP-FPM request for the httpd-rs execution;
- `/tmp/opencode/p18-harness/<case>/www/uploads/pwned.txt` — the code-execution marker path checked per request (removed after each check); the run output records the observed `PWNED who=probe uid=33` content;
- `/tmp/opencode/p18-final-run.txt` — the final 14-verdict harness output;
- rewritten `apache.conf`/`httpd-rs.conf` fixtures for each case.

The final retained run produced **14 PASS** verdicts, including the two exploit paths and all controls. The Apache oracle runs `-X`; the harness binds loopback ports only and keeps its cleanup inside `/tmp/opencode/p18-harness`.

---

## 8. Suggested remediation direction

The product source was not changed for this pass. The required behavior is to match Apache's access-file admission:

- In an `AllowOverrideList` context, a container section must not be admitted solely because a directive inside it appears in the list. `<Files>`/`<FilesMatch>` (and the other containers named in `docs/config-semantics.md`) should be rejected or skipped unless the active `AllowOverride` mode permits the container, matching Apache's `500` fail-closed behavior in the tested configuration.
- Update the invariant at `docs/config-semantics.md:178-179`: container sections do not require a category under category-based `AllowOverride`, but `AllowOverrideList` is not a union that implicitly admits them.
- Add an Apache differential regression with `AllowOverride None` + `AllowOverrideList Require`, an outer `<FilesMatch>` deny, and an access file containing `<Files>`/`<FilesMatch>`; assert the access file is rejected (or otherwise not applied) rather than executing the target.
- Keep the existing A5/B4 `AllowOverride AuthConfig` controls: they ensure the fix does not reject sections where Apache accepts them.

---

# Pass 18-B — adversarial break of HEAD `07c7879` ("Require stable FastCGI paths and openat2")

- **Date:** 2026-10-28
- **Subject:** `target/release/httpd-rs` built at HEAD `07c7879`. No product source was edited. The retained additions for this pass are `adversarial/p18/exploit_p18b.py`, this section and the `adversarial/README.md` index entry.
- **Oracle:** Apache/2.4.69 (Debian), `/usr/sbin/apache2 -X`, with `mod_cgi` and `mod_proxy_fcgi`; PHP-FPM 8.4.27 for the PHP cases. Loopback only.
- **Harness:** `adversarial/p18/exploit_p18b.py` — differential battery over the `.htaccess` `<IfFile>` conditional, the access-file phase order and `ProxyPassMatch` route participation. Default groups **E, F, G, H, I, J**; groups **A–D** retain the pass-18A/P15-adjacent probes.
- **Retained evidence:** `/tmp/opencode/p18b-harness` (fixtures, per-case Apache/httpd-rs configs, error logs, private FPM pool and access log) and `/tmp/opencode/p18b-final-run.txt` (final battery output).
- **Method:** targeted audit of the access-file conditional parser and Apache's `ap_if_walk`/`ap_file_walk`/`ap_location_walk` phase order, followed by a live Apache-versus-httpd-rs differential over the upload-execution guard shapes already used by P18-A and the project's own benchmark (`bench/app_bench.py`).

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P18-B1** | An access-file `<IfFile>` conditional is evaluated against the **DocumentRoot** instead of **ServerRoot**, and its children are applied in the **if phase** (after `<Files>`/`<Location>` sections) instead of the **directory phase**. An attacker-written `.htaccess` can therefore make the condition true on httpd-rs and false on Apache, and the wrapped `Require all granted` then overrides the operator's upload deny | `<IfFile index.html>` resolves to `ServerRoot/index.html` (absent) → the section is skipped and the upload guard holds (`403`); even when the condition is true the wrapped grant is a directory-phase directive and still loses to the file/location deny | `DocumentRoot/index.html` (present) → the condition is true and the wrapped grant is merged in the if phase, after the upload deny → uploaded PHP-FPM/CGI executes as `www-data` (`200 PHPEXEC … uid=33`) | remote code execution / access-file authorization bypass |
| **P18-B2** | httpd-rs applies the mapped directory's access file (and its `<If>`/`<IfFile>` conditional grants) to **`ProxyPassMatch`-routed requests**. Apache does not run the directory/access-file walk for `proxy:` filenames, so the same access file is inert there. The conditional grant merges after the operator's `<Location>` guard | The upload `.htaccess` is not consulted for the proxied request; the `<Location>` guard holds (`403`) | The `.htaccess` is consulted; `<IfFile index.html>` (or even `<If "true">`) grants after the `<Location>` deny and the request reaches PHP-FPM (`200 PHPEXEC … uid=33`) | remote code execution / URL-guard bypass on the benchmark FastCGI route |

Both findings execute **attacker-uploaded content as the PHP-FPM worker or CGI user**. They require an access-file write primitive plus an override policy that admits `<IfFile>` and `Require` (any category, e.g. `AllowOverride AuthConfig`, or the directive-only `AllowOverrideList "<IfFile" Require`). No symlink, path traversal or FastCGI `SCRIPT_FILENAME` trick is involved.

---

## 2. Observed differential

### 2.1 `<IfFile>` base and phase (non-proxied handler)

Fixture: `www/uploads` with `SetHandler "proxy:unix:…|fcgi://localhost"` (or `AddHandler cgi-script .cgi` + `Options +ExecCGI`) and an outer `<FilesMatch "\.php$"> Require all denied </FilesMatch>`; attacker uploads `shell.php`/`shell.cgi` plus `.htaccess`:

```apache
<IfFile index.html>
    Require all granted
</IfFile>
```

| Case | Access-file content | Apache 2.4.69 | httpd-rs HEAD |
|---|---|---|---|
| `F1` PHP-FPM, `AllowOverride AuthConfig`, `<FilesMatch>` deny | `<IfFile index.html> Require all granted </IfFile>` | `403`; no marker | `200` `PHPEXEC who=probe uid=33 wrote=yes`; `pwned.txt` = `PWNED who=probe uid=33` |
| `F4` PHP-FPM, `AllowOverride AuthConfig`, `<LocationMatch "^/uploads/.*\.php$">` deny | same | `403`; no marker | `200` PHPEXEC; marker written |
| `F5` PHP-FPM, `AllowOverride None` + `AllowOverrideList "<IfFile" Require`, `<FilesMatch>` deny | same | `403`; no marker | `200` PHPEXEC; marker written |
| `E1` CGI, `AllowOverride AuthConfig`, `<FilesMatch "\.cgi$">` deny | same | `403` | `200` `EXEC-E uid=33` |
| `E5` CGI, same config, `<IfFile favicon.ico>` | `<IfFile favicon.ico> …` | `403` | `200` `EXEC-E uid=33` |
| `G1` CGI, `<LocationMatch "^/uploads/.*\.cgi$">` deny, `AllowOverride AuthConfig` | `<IfFile index.html> …` | `403` | `200` `EXEC-G uid=33` |
| `H1` CGI, `<FilesMatch>` deny; `www/index.html` **and** `www/www/index.html` exist (condition true under both bases) | `<IfFile www/index.html> …` | `403` (directory-phase grant loses to the file deny) | `200` `EXEC-H uid=33` (if-phase grant wins) |

Controls (all SAME on both servers):

| Control | Content | Result |
|---|---|---|
| `F2`/`E7` | no `.htaccess` / `<IfFile missing.html>` | `403` on both |
| `F3`/`E2`/`G4` | direct top-level `Require all granted` | `403` on both (the file/location deny is applied after the directory phase) |
| `E3`/`G3` | `<If "true"> Require all granted </If>` | `200` on both (Apache's `<If>` children are merged in the if phase too) |
| `F6`/`F7`/`F8` | `AllowOverrideList "<IfFile" Require`: direct `<Files>` grant / direct `Require` / `<If "true">` | `500` / `403` / `500` on **both** — under this policy `<IfFile>` is the only admitted construct that bypasses on httpd-rs |
| `H2` | `<IfFile www/index.html>` wrapping a `<Files>` grant, condition true on both | Apache `200`, httpd-rs `403` (httpd-rs drops non-`Always` rules nested in a conditional; Apache splices them inline and applies them in the file phase) |

`F5` is the clean fail-open case: Apache admits every construct in the access file (`AllowOverrideList` lists `<IfFile` and `Require`), evaluates the condition against `ServerRoot/index.html` (absent), and returns `403`; httpd-rs admits the same constructs, evaluates the condition against `DocumentRoot/index.html` (present) and executes the uploaded script. The direct alternatives are rejected/denied on both servers (`F6`/`F7`/`F8`), so the `<IfFile>` wrapper is the necessary bypass.

### 2.2 Benchmark `ProxyPassMatch` route

Fixture: the project's own benchmark spelling plus an uploads guard:

```apache
<LocationMatch "^/uploads/">
    Require all denied
</LocationMatch>
<Directory "/srv/app/www/uploads">
    AllowOverride AuthConfig
</Directory>
ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:/run/php/php8.4-fpm.sock|fcgi://localhost/srv/app/www/"
```

Attacker uploads `uploads/shell.php` and `uploads/.htaccess`:

```apache
<IfFile index.html>
    Require all granted
</IfFile>
```

| Case | Access-file content | Apache 2.4.69 | httpd-rs HEAD |
|---|---|---|---|
| `I1` | `<IfFile index.html> Require all granted </IfFile>` | `403`; no marker | `200` PHPEXEC `uid=33`; marker written |
| `I2` | none | `403` | `403` |
| `I3` | `Require all granted` | `403` | `403` |
| `I4` | `<If "true"> Require all granted </If>` | `403` (access file not consulted for the proxied request) | `200` PHPEXEC `uid=33`; marker written |
| `J1`/`J2`/`J3` | `Require all denied` / `<Files "shell.php"> Require all denied </Files>` / `<FilesMatch "\.php$"> Require all denied </FilesMatch>` | `200` PHPEXEC (access file ignored; the proxied request is served) | `403` |
| `J4` | `<If "false"> Require all granted </If>` | `200` | `200` |

`I1`/`I4` are the executable direction: the attacker's access file overrides the operator's `<Location>` guard on httpd-rs while Apache never reads the file for the proxied request. `J1`–`J3` are the compatibility divergence in the other direction (httpd-rs enforces access-file denies on proxied requests where Apache does not), and `J4` shows the deny is not a blanket rule.

---

## 3. Root cause

### 3.1 `<IfFile>` is parsed as an if-phase conditional and confined to DocumentRoot

`crates/server/src/htaccess.rs:1105-1191` groups `IfFile` with the request-time conditionals:

```rust
AccessSectionKind::If
| AccessSectionKind::IfFile
| AccessSectionKind::ElseIf
| AccessSectionKind::Else => {
    ...
    let (branch, chain, condition) =
        if matches!(section, AccessSectionKind::If | AccessSectionKind::IfFile) {
            let expression = if section == AccessSectionKind::If {
                ...
            } else {
                let path = args.first().cloned().unwrap_or_default();
                crate::expr::Expr::FileTest("-F".into(), Box::new(crate::expr::Expr::Str(path)))
            };
            ...
        };
    ...
    rules.push(ScopeRule {
        kind: MatchKind::Always,
        delta: inner,
        ...
        condition,
        branch,
        chain,
        nested: inner_rules,
    });
}
```

`Expr::FileTest` evaluates relative paths through `confined_expr_path` (`crates/server/src/expr.rs:672-701`), which joins them to `ctx.docroot`:

```rust
let joined = ctx.docroot.join(path);
...
let root = std::fs::canonicalize(ctx.docroot).ok()?;
let target = std::fs::canonicalize(&joined).ok()?;
```

and the resulting `Always` rule is merged by `apply_scope_conditionals` **after** the file-scoped rules — the same merge slot as `<If>`. A top-level `Require all granted` wrapped in `<IfFile>` therefore overrides a `<FilesMatch>` or `<Location>` deny that an unwrapped top-level `Require` cannot (`E2`/`G4` vs `E1`/`G1`).

Apache does neither:

- `server/core.c:test_iffile_section` resolves the argument with `ap_server_root_relative(cmd->temp_pool, arg)`, i.e. against **ServerRoot** for relative paths (`docs/manual/mod/core.xml`: “If a relative filename is supplied, the check is ServerRoot relative”).
- `<IfFile` is `EXEC_ON_READ`; `start_cond_section` splices the children into the parent directive list with `ap_build_cont_config`. The children are ordinary directives of the enclosing directory scope — they are walked in the **directory phase** (`ap_walk_config`), before `ap_file_walk` (`<Files>`/`<FilesMatch>`) and `ap_location_walk` (`<Location>`/`<LocationMatch>`). A wrapped top-level grant therefore loses to the operator's file/location deny (`H1`, `H2`), and a `<Files>` section nested inside `<IfFile>` is applied in the file phase (`H2`).

`H1` isolates the phase difference with a condition that is true under both bases: the same access file is `403` on Apache and `200` on httpd-rs. `E1`/`E5`/`F1`/`G1` isolate the base difference: the relative path exists below `DocumentRoot` but not below `ServerRoot`.

### 3.2 Access files participate in `ProxyPassMatch` requests

For a `ProxyPassMatch` request Apache translates the URI to `r->filename = "proxy:fcgi://…"`; `ap_directory_walk`/`ap_file_walk` then operate on the proxy URL, so the mapped directory's `.htaccess` (a `<Directory>` construct) is never read. This is why the same upload `.htaccess` is inert on Apache for `I1`–`J3` and why the operator is told to use `<Location>`/`<Proxy>` for proxied content. httpd-rs instead maps the URL to a file, evaluates the mapped directory scope (including access files) and re-authorizes the resolved script in `run_fastcgi`/`authorize_resolved_target`. That is stricter for denies (`J1`–`J3`) but also lets an attacker-written conditional grant (`<IfFile>` in `I1`, or `<If "true">` in `I4`) merge after the operator's `<Location>` deny.

### 3.3 Why the wrapper is the unit of the bypass

The unwrapped top-level `Require all granted` is admitted by the same override policy but is applied in the directory phase, where the operator's `<FilesMatch>`/`<Location>` deny is applied later (`E2`, `G4`, `I3`, `F7`). Wrapping the grant in `<IfFile>` moves it to the if phase on httpd-rs, after those denies. On Apache the same wrapper either is not evaluated (relative path against ServerRoot) or is evaluated in the directory phase and loses. The bypass is therefore not “httpd-rs allows `Require`” but “httpd-rs evaluates and phases `<IfFile>` differently from Apache”.

---

## 4. Exploit chain

1. The operator hardens an upload tree with a file- or URL-scoped deny and an execution handler, e.g.:

   ```apache
   <Directory "/srv/app/www/uploads">
       AllowOverride AuthConfig          # or AllowOverrideList "<IfFile" Require
       SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
       <FilesMatch "\.php$">
           Require all denied
       </FilesMatch>
   </Directory>
   ```

2. The attacker writes `uploads/shell.php` (or `shell.cgi`) and `uploads/.htaccess`:

   ```apache
   <IfFile index.html>
       Require all granted
   </IfFile>
   ```

3. `GET /uploads/shell.php` returns `403` on Apache and executes on httpd-rs:

   ```text
   Apache:  403  (ServerRoot/index.html absent; guard holds)
   httpd-rs: 200  PHPEXEC who=probe uid=33 wrote=yes
                 pwned.txt: PWNED who=probe uid=33
   ```

   With the benchmark `ProxyPassMatch` route plus `<LocationMatch "^/uploads/"> Require all denied`, the same access file (`I1`), or even `<If "true"> Require all granted </If>` (`I4`), executes on httpd-rs while Apache returns `403`.

The executed process is the PHP-FPM worker (`uid=33`); the CGI variant runs as the worker user and writes the same marker. Arbitrary PHP/script code can read files available to the worker, call `system`, or modify application files.

---

## 5. Impact and preconditions

**Impact.** Remote code execution as the web-worker user from an access-file write primitive plus an uploaded script, in the same upload-hardening shapes as P18-A. The differential exists for both FastCGI and CGI, for file-scoped (`<FilesMatch>`) and URL-scoped (`<LocationMatch>`) guards, and on the project's benchmark FastCGI route.

**Preconditions.**

1. **Write access to an access file and a script** in a directory served by httpd-rs (upload/rename/archive-extraction primitive).
2. **An override policy that admits `<IfFile>` and `Require`**: any category (`AllowOverride AuthConfig`, `FileInfo` + AuthConfig, `All`) or the directive-only `AllowOverrideList "<IfFile" Require`. With `AllowOverride AuthConfig` Apache is independently bypassable with `<If "true">` in the non-proxied shape (`E3`/`G3` are parity), so the `AllowOverrideList` case `F5` is the one where Apache has no admitted alternative; the non-proxied AuthConfig rows (`F1`, `E1`, `G1`) demonstrate the divergence on the same access file.
3. **An execution handler** for the uploaded script: a per-directory or parent FastCGI `SetHandler`, or `AddHandler cgi-script` with `Options +ExecCGI`.
4. **A file- or URL-scoped deny** that the wrapped grant must outrank: `<FilesMatch "\.(php|phtml)$"> Require all denied </FilesMatch>` or `<LocationMatch "^/uploads/"> Require all denied </LocationMatch>`. Without a deny there is no differential.
5. **A docroot-relative file that exists below DocumentRoot but not below ServerRoot** for the `<IfFile>` condition (`index.html`, `favicon.ico`, `robots.txt`, `index.php`). `E7`/`G6`/`F2` are the missing-file and no-access-file controls.

**Severity.** Remote code execution, configuration-gated. `AllowOverrideList "<IfFile" Require` is the clean fail-open posture; category-based `AllowOverride AuthConfig` in an upload tree is itself weak on Apache, but the same `.htaccess` still produces `403`/`200` divergence between the two servers, and the benchmark `ProxyPassMatch` shape (`I1`/`I4`) bypasses a `<Location>` guard that Apache enforces.

---

## 6. Relationship to the other findings

- **P18-A** is an *admission* mismatch (`AllowOverrideList Require` admitted unlisted `<Files>`/`<FilesMatch>` wrappers); the fix centralizes section admission. P18-B is an *evaluation* mismatch: `<IfFile>` is admitted on both servers, but its path base and merge phase differ. Fixing one does not affect the other (`F5` still executes after the P18-A fix).
- **P17/P15** concern FastCGI `SCRIPT_FILENAME` identity; P18-B never changes the script name and reproduces with native CGI (`E1`, `G1`, `H1`).
- **P14-A** was a `<Files>` phase-order bug; P18-B is the `<IfFile>`/if-phase analogue and additionally diverges on the condition's path base and on access-file participation for proxied routes.

---

## 7. Reproduction

```sh
cargo build --release -p httpd-rs
python3 adversarial/p18/exploit_p18b.py            # groups E F G H I J
python3 adversarial/p18/exploit_p18b.py F          # PHP-FPM cases incl. F5 AllowOverrideList "<IfFile" Require
python3 adversarial/p18/exploit_p18b.py I          # benchmark ProxyPassMatch shape
python3 adversarial/p18/exploit_p18b.py J          # access-file participation probes
```

The harness starts sibling loopback Apache and httpd-rs instances per case and a private PHP-FPM pool under `/tmp/opencode/p18b-harness`, and retains per-case `apache.conf`/`httpd-rs.conf`, error logs and the FPM access log. The final retained run is `/tmp/opencode/p18b-final-run.txt`.

Key verdicts from that run:

```text
DIFF  F1-php-iffile-docroot-relative shell
      apache=403 pwned='' | httpd-rs=200 PHPEXEC who=probe uid=33 wrote=yes pwned='PWNED who=probe uid=33'
DIFF  F5-php-allowoverridelist-iffile shell
      apache=403 pwned='' | httpd-rs=200 PHPEXEC who=probe uid=33 wrote=yes pwned='PWNED who=probe uid=33'
DIFF  G1-iffile-docroot-relative shell
      apache=403 pwned='' | httpd-rs=200 EXEC-G uid=33 who=probe
DIFF  H1-iffile-true-both shell
      apache=403 pwned='' | httpd-rs=200 EXEC-H uid=33 who=probe
DIFF  I1-bench-iffile-docroot-relative shell
      apache=403 pwned='' | httpd-rs=200 PHPEXEC who=probe uid=33 wrote=yes pwned='PWNED who=probe uid=33'
DIFF  I4-bench-if-true-control shell
      apache=403 pwned='' | httpd-rs=200 PHPEXEC who=probe uid=33 wrote=yes pwned='PWNED who=probe uid=33'
DIFF  J1-top-level-deny shell
      apache=200 PHPEXEC who=probe uid=33 wrote=yes | httpd-rs=403 pwned=''
```

---

## 8. Suggested remediation direction

The product source was not changed for this pass. The required behavior is to match Apache's access-file semantics:

- **Evaluate `.htaccess` `<IfFile>` against ServerRoot**, not DocumentRoot (`ap_server_root_relative`), or reject relative `<IfFile>` arguments in access files as a configuration error. Use `Expr::IfFile` (the existing unconfined variant) rather than `Expr::FileTest("-F", …)` for the access-file section, and do not confine the operator-supplied `<IfFile>` argument to the document root.
- **Apply `<IfFile>` children in the directory phase.** `<IfFile>` is an `EXEC_ON_READ` container on Apache: its children are ordinary directives of the enclosing scope and must be ordered before `<Files>`/`<Location>` rules. Only `<If>`/`<ElseIf>`/`<Else>` belong to the request-time if phase. Keep the existing admission gate (`htaccess_section_admit`) for the wrapper.
- **Do not consult `<Directory>`/access-file policy for proxied requests**, or document and constrain the difference. Apache does not run the directory walk for `proxy:` filenames, so `.htaccess` grants cannot widen a proxied route; today httpd-rs's if-phase grants (`I1`, `I4`) override `<Location>` denies that Apache enforces. If access files are intentionally applied to proxy routes, they must not be able to grant past a `<Location>` deny (order the access-file merge before the location merge and re-check it at the FastCGI/proxy sink).
- Add Apache differential regressions for: relative `<IfFile>` with the file below DocumentRoot only (`F1`/`E1`), `<IfFile>` with the file below both roots (`H1`), `<IfFile>` nested `<Files>` (`H2`), and the `ProxyPassMatch` + `<LocationMatch>` shape with an attacker access file (`I1`/`I4`) plus the access-file deny controls (`J1`–`J3`).
