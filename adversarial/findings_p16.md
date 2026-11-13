# Pass 16 — adversarial break of HEAD `8454631` ("Remove h2 because uh, why?")

> Remediation status (2026-10-28): fixed in the current tree. Access-file
> environment provenance is excluded from FastCGI parameters; directive
> regexes use ASCII-default byte semantics; header guards match raw bytes; and
> the P16-D SetEnvIf semantics are regression-pinned. The retained harness now
> requires Apache/httpd-rs parity instead of reproducing the differentials, and
> its FastCGI cases use a built-in protocol mock so PHP-FPM is not required.

- **Date:** 2026-10-28
- **Subject:** `target/release/httpd-rs` built at HEAD `8454631`. No product source was edited. The only retained additions for this pass are `adversarial/p16/exploit_p16.py`, this write-up and the `adversarial/README.md` index entry.
- **Build note:** `vendor/h2-0.4.20` is an intentional upstream patch: public `h2` 0.4.20 accepts a `:path` containing a `#` fragment and lets `http::uri::PathAndQuery` truncate it before httpd-rs can validate the pseudo-header. HEAD `8454631` deletes that tree but leaves the `[patch.crates-io] h2 = { path = "vendor/h2-0.4.20" }` entry, so a clean checkout cannot build. The directory was restored from the parent commit with `git checkout 6b781ea -- vendor/h2-0.4.20`; this restores the intended patched dependency and does not participate in any finding.
- **Oracle:** Apache/2.4.69 (Debian), `/usr/sbin/apache2 -X`, and PHP-FPM 8.4.27 (`php-fpm8.4`, Debian defaults, Unix socket). Loopback only.
- **Harness:** `adversarial/p16/exploit_p16.py` — 36 differential verdicts across four findings, with twenty Apache/parity controls (§7).
- **Method:** targeted audit of the environment vector into FastCGI, a differential sweep of the Rust `regex` dialect at every directive-regex compiled through `config.rs::compile_regex`, a raw-byte header sweep of the `SetEnvIf`/`RewriteCond`/expression guard paths, and a comparison of Apache's documented `SetEnvIf` value/chaining/capture semantics.

---

## 1. Executive summary

Four new findings, all rooted in a representation httpd-rs sends or interprets differently from Apache:

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P16-A** | `.htaccess` environment entries are forwarded to FastCGI as PHP-FPM per-request configuration. An attacker-writable access file can inject `PHP_VALUE`/`PHP_ADMIN_VALUE`; `auto_prepend_file` then executes an uploaded non-PHP file as PHP | Access-file `SetEnv`/`SetEnvIf` values (including `PHP_VALUE`) are **not** forwarded by `mod_proxy_fcgi`; request returns `200` without execution. A main-config `SetEnv PHP_VALUE` **is** forwarded | The same access-file `PHP_VALUE`/`PHP_ADMIN_VALUE` reaches PHP-FPM; the uploaded file executes (`PREPEND`, marker written) | remote code execution via untrusted configuration/environment provenance |
| **P16-B** | Directive regexes use Rust `regex` Unicode class semantics while Apache uses PCRE's ASCII-by-default classes. `\b`, `\W`, `\D`, `\S` therefore change meaning for non-ASCII input | A `RewriteCond` deny guard such as `\badmin\b` matches `éadmin` and returns `403`; the protected CGI does not execute. A positive `SetEnvIf User-Agent ^\w+$` / `Require env` gate does not match `é` and returns `403` | The same deny guard misses `éadmin` and the protected CGI executes (`200`, `EXEC-P16B`). The positive gate matches `é` (Unicode `\w`) and the protected CGI executes, where Apache denies | fail-open access-control guards and over-grant allow gates |
| **P16-C** | Header values are converted to UTF-8 before guard evaluation (`header_str(...).unwrap_or_default()`), while Apache matches raw field bytes | `SetEnvIf`, `RewriteCond` or `<If>` deny guards match `User-Agent`/`X-User: \xFFsqlmap` and return `403` | The invalid byte makes the header empty for all three guard paths; the deny misses and the protected CGI executes (`200`, `EXEC-P16C`) | fail-open header deny/blocklist guard with no `.htaccess` required |
| **P16-D** | `SetEnvIf` action/attribute semantics diverge: valueless actions set `""` instead of Apache's `"1"`, prior env variables cannot be tested, and `$1` captures are not expanded | `SetEnvIf ... BLOCK` + `Require expr "%{env:BLOCK} == '1'"` denies; `SetEnvIf ... BAD` + `SetEnvIf BAD 1 DENY` + `Require not env DENY` denies; `SetEnvIf ... ID=$1` + a value test denies | The same configurations allow the protected CGI (`200`, `EXEC-P16D`) because the environment value/chain/backreference never matches | fail-open `SetEnvIf` ACL guard with no `.htaccess` required |

P16-A is the primary result: it is a direct PHP-FPM RCE in a deployment that enables per-directory overrides and lets an attacker write `.htaccess` and upload a file. P16-B, P16-C and P16-D are independent guard-parity bugs that survive `AllowOverride None`; each needs a guard/allow rule of the affected shape, but then any attacker-controlled header (or, at the other regex call sites, path component) can bypass it.

The four findings are independent and are demonstrated by the same battery.

---

## 2. P16-A — `.htaccess` environment reaches PHP-FPM as `PHP_VALUE`

### 2.1 Root cause

The `.htaccess` parser intentionally accepts `SetEnv` and `SetEnvIf` and stores them in the same `EnvironmentPolicy` as the main configuration (`crates/server/src/htaccess.rs:2131-2152`):

```rust
"setenv" => {
    let Some(name) = args.first() else {
        return Err("SetEnv requires a variable".into());
    };
    scope.environment_policy.set_env
        .push((name.clone(), args[1..].join(" ")));
}
...
"setenvif" | "setenvifnocase" | "browsermatch" | "browsermatchnocase" => {
    scope.environment_policy.set_env_if
        .push(crate::config::parse_env_rule(name, args)?);
}
```

`Scope::request_env` (`crates/server/src/config.rs:1500-1546`) merges `set_env`, `set_env_if`, `pass_env` and `unset_env` into one name/value vector with **no provenance bit** and **no backend-control-name filter**. The FastCGI dispatcher then places that vector directly in the request context (`crates/server/src/server.rs:3351-3372`):

```rust
let ctx = CgiContext {
    ...
    env: &scope.request_env(req, url_path),
    ...
};
let mut r = fastcgi::execute_bound(&ctx, scope, &target, &script_binding);
```

`cgi::build_env` appends every admitted entry (`crates/server/src/cgi.rs:266-276`). The admission kernel only rejects invalid keys and variables already calculated by httpd-rs (`crates/server/src/cgi.rs:148-174` — the CGI names plus `HTTP_*`); `PHP_VALUE` and `PHP_ADMIN_VALUE` are neither calculated CGI variables nor `HTTP_*`, so they pass:

```rust
for (k, v) in ctx.env {
    let key_valid = !k.is_empty() && !k.contains('=') && !k.as_bytes().contains(&0);
    if !httpd_rs_verified::cgi_env_entry_admit(key_valid, reserved_cgi_env(k)) {
        continue;
    }
    env.retain(|(n, _)| n != k.as_str());
    env.push((OsString::from(k), OsString::from(v)));
}
```

Finally `fastcgi::env_from_base` calls `build_env` and `build_params` serializes every entry into the `FCGI_PARAMS` stream (`crates/server/src/fastcgi.rs:506-520`). PHP-FPM applies `PHP_VALUE` (and `PHP_ADMIN_VALUE`) before running the requested script, so `auto_prepend_file` is the execution primitive.

The existing reservation list is the right idea — it prevents request/configured environment from shadowing `SCRIPT_FILENAME`, `REMOTE_ADDR`, etc. — but it is a list of **CGI protocol variables**, not PHP-FPM control parameters, and it has no notion of whether the value came from operator configuration or from an attacker-writable access file.

### 2.2 Apache oracle

Apache accepts and applies `.htaccess` `SetEnv` for local CGI (a CGI printing `$FOO` sees `FOO=accessfile`). For a `ProxyPassMatch … fcgi://…` request, however, Apache 2.4.69's `mod_proxy_fcgi` does not forward access-file environment values. With `SetEnv PHP_VALUE "auto_prepend_file=…"` in `.htaccess`, Apache returned `200` and PHP did not execute the target. A diagnostic `SetEnv FOO bar` in the same access file was likewise absent from the FastCGI request, while `SetEnv FOO bar` in the **main** configuration was forwarded (`$_SERVER['FOO'] = mainconfig`). The A6-main-config control below uses the main-config form and confirms both servers execute it, so the differential is provenance, not a prohibition on `PHP_VALUE` itself.

### 2.3 Exploit chain (observed)

The deployment is the benchmark FastCGI spelling (`bench/app_bench.py`: `ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:…|fcgi://localhost<docroot>/"`) with per-directory overrides enabled on the writable tree. Apache must have `AllowOverride All` (or at least `FileInfo`) for the access file to be parsed; the harness uses exactly that.

```
/srv/app/www/uploads/avatar.txt      attacker-uploaded non-PHP file containing:
                                     <?php file_put_contents('/tmp/pwned', 'executed'); ?>
/srv/app/www/.htaccess               attacker-written:
                                     SetEnv PHP_VALUE "auto_prepend_file=/srv/app/www/uploads/avatar.txt"
```

Requesting any PHP script in the directory executes `avatar.txt` first:

```
GET /index.php
  Apache 2.4.69: 200  (no prepend, no marker)
  httpd-rs HEAD:  200  (PREPEND, marker written)
```

The battery covers the same primitive through the variants an operator is likely to meet:

| Case | Access-file directive | Override | Apache | httpd-rs |
|---|---|---|---|---|
| **A1** | `SetEnv PHP_VALUE auto_prepend_file=uploads/avatar.txt` | `All` | 200, no exec | 200, **exec** |
| **A2** | `SetEnv PHP_ADMIN_VALUE auto_prepend_file=…` | `All` | 200, no exec | 200, **exec** |
| **A3** | `SetEnvIf User-Agent .* PHP_VALUE=auto_prepend_file=…` | `All` | 200, no exec | 200, **exec** |
| **A4** | `SetEnv PHP_VALUE …` in `app/.htaccess`, request `/app/index.php` | `All` | 200, no exec | 200, **exec** |
| **A5** | `SetEnv PHP_VALUE …` with only `FileInfo` | `FileInfo` | 200, no exec | 200, **exec** |

`PHP_ADMIN_VALUE` is not a weaker variant: PHP-FPM applies it with system-level precedence, so the attacker can override directives that `PHP_VALUE` cannot. `SetEnvIf` is equally useful because it can attach the value to a request header the attacker controls, but it is not required — a plain `SetEnv` in the writable directory is enough.

The upload need not be a PHP-named file. The harness uploads `uploads/avatar.txt`; PHP-FPM executes a file named by `auto_prepend_file` regardless of extension, so upload filters that only reject `.php`/`.phtml` do not help.

### 2.4 Impact

- **Remote code execution as the PHP-FPM worker user** in the common FastCGI deployment, using only an uploaded non-PHP file plus an attacker-writable `.htaccess`. This is the same uploader-writable-access-file primitive as F60/P14-A, but a different mechanism: phase order is not involved; the environment itself is trusted across the CGI boundary.
- **Bypasses extension-based upload defenses.** The executed file can be `.txt`, `.jpg`, or any name the application accepts, because `auto_prepend_file` does not apply `security.limit_extensions` to the prepended file.
- **`PHP_ADMIN_VALUE` widens the blast radius** to system-level PHP settings (including `disable_functions`-adjacent policy and other `PHP_INI_SYSTEM` values), not only per-directory settings.
- **The operator's main-config `SetEnv PHP_VALUE` works on both servers**, so a scanner comparing only "does PHP_VALUE work?" will not see the bug. The difference is whether the value came from an access file.
- Reachable on any FastCGI route that consumes the request scope (benchmark `ProxyPassMatch`, `ProxyPass` with a FastCGI backend, or a FastCGI `SetHandler`), not only the exact benchmark spelling.

### 2.5 Fix

The FastCGI environment needs a provenance boundary, not another flat denylist:

1. **Preferred: mirror Apache for proxied FastCGI.** Keep operator/main-config environment and access-file environment distinct (`Scope`/`EnvironmentPolicy` origin tags, or a separate `access_env` vector). `run_fastcgi` should forward only the operator-origin environment, as Apache's `mod_proxy_fcgi` does; CGI may continue to receive access-file values because Apache's `mod_cgi` does. This removes the entire class, including future PHP-FPM control names and `RewriteRule [E=…]` spellings.
2. **Defense in depth: reserve backend-control names for untrusted provenance.** At the FastCGI boundary, refuse `PHP_VALUE`, `PHP_ADMIN_VALUE` (and any future `PHP_*`/`PHPRC`/`PHP_INI_SCAN_DIR` control parameters) when the entry originated in an access file or request rewrite. Do not add them to the global `reserved_cgi_env` list without provenance: that would also break the legitimate, Apache-compatible main-config `SetEnv PHP_VALUE` control.
3. **Do not rely on `AllowOverride None` alone.** The harness's `A6-override-none` control shows the guard works, but P16-A matters precisely for deployments that enable overrides. The fix must hold when the access file is parsed.
4. Add A1–A5 and the A6 controls to the end-to-end regression suite, including `SetEnvIf`, `PHP_ADMIN_VALUE`, a nested directory, `FileInfo`-only overrides, and a main-config positive control.

---

## 3. P16-B — directive regexes use Unicode classes where Apache uses PCRE ASCII classes

### 3.1 Root cause

`config.rs::compile_regex` validates the dialect and then compiles with the Rust `regex` crate (`crates/server/src/config.rs:5956-5967`):

```rust
pub(crate) fn guard_regex(pattern: &str) -> Result<(), String> {
    if httpd_rs_verified::regex_dialect_admit(pattern.as_bytes()) { Ok(()) }
    else { Err("unsupported regex dialect: backreferences/look-around/control bytes".into()) }
}

pub(crate) fn compile_regex(pattern: &str) -> Result<Regex, String> {
    guard_regex(pattern)?;
    Regex::new(pattern).map_err(|e| e.to_string())
}
```

Rust `regex` is Unicode-aware by default: `\w` includes Unicode letters, `\d` includes Unicode decimal digits, `\s` includes Unicode whitespace, and `\b` recognizes a boundary between a Unicode word character and a non-word character. Apache's configuration regex engine is PCRE without UTF/UCP, so the same escapes are ASCII-only.

The same mismatch is present at the two rewrite compilation sites, which bypass `compile_regex` and build the `regex` crate directly:

- `RewriteCond`: `guard_regex(stripped)` followed by `regex::RegexBuilder::new(stripped).case_insensitive(flags.nocase)` (`crates/server/src/config.rs:6418-6427`).
- `RewriteRule`: `guard_regex(pattern)` followed by `regex::RegexBuilder::new(pattern)` (`crates/server/src/config.rs:6462-6469`).

`compile_regex` also feeds `SetEnvIf` (`config.rs:1255`) and the `FilesMatch`/`LocationMatch`/`DirectoryMatch`/`RedirectMatch`/`AliasMatch` parsers (`config.rs:1886`, `3176`, `3211`, `3238`, `3402`, `4594`, `5994`, `6018`). The demonstrated exploits are `RewriteCond` (B1) and `SetEnvIf` (B2); the semantic bug is shared by every one of these sites.

This is deliberately **not** the P15-C expression-regex finding: `<If>` and `Require expr` were moved to PCRE2 and now agree with Apache. The P16-B control `B1-control-if-pcre` confirms that `<If "%{HTTP:X-User} =~ /\badmin\b/">` still denies `éadmin` on both servers. The gap is the separate directive-regex path.

### 3.2 Exploit chain (observed)

A configuration uses a `RewriteCond` deny guard with an ASCII-class assumption:

```apache
<Directory "/srv/app/www/secret">
    RewriteEngine On
    RewriteCond %{HTTP:X-User} \badmin\b
    RewriteRule ^ - [F]
</Directory>
```

The attacker sends a header value that Apache treats as a boundary-delimited `admin` but Rust does not:

```
GET /secret/run.cgi
X-User: éadmin

  Apache 2.4.69: 403  (PCRE ASCII: é is non-word, \b matches before admin)
  httpd-rs HEAD:  200  EXEC-P16B
```

The other class escapes produce the same differential:

| Case | Pattern | Header | Apache | httpd-rs |
|---|---|---|---|---|
| **B1** | `\badmin\b` | `éadmin` | 403, no exec | 200, **EXEC** |
| **B1** | `^\W+$` | `é` | 403, no exec | 200, **EXEC** |
| **B1** | `^\D+$` | `١٢٣` (Arabic-Indic digits) | 403, no exec | 200, **EXEC** |
| **B1** | `^\S+$` | U+00A0 (NBSP) | 403, no exec | 200, **EXEC** |

Controls:

- ASCII `admin` with `\badmin\b`: both servers `403` (the guard is live on both).
- `xadminx` with `\badmin\b`: both servers `200` (no match on either; the protected CGI executes on both, as intended by this fixture).
- `<If "%{HTTP:X-User} =~ /\badmin\b/"> Require all denied` with `éadmin`: both servers `403` (P15's PCRE2 expression fix holds).

The `\W`, `\D` and `\S` cases show that this is not specific to word boundaries: any negated ASCII class is narrower in Rust than in PCRE when the input contains the corresponding Unicode character class.

The over-grant direction is a second, independent regression at the same compiler. A positive gate can use `SetEnvIf` to set an environment variable and `Require env` to admit only matching requests:

```apache
SetEnvIf User-Agent ^\w+$ TRUSTED

<Directory "/srv/app/www">
    Options +FollowSymLinks +ExecCGI
    AddHandler cgi-script .cgi
    Require env TRUSTED
</Directory>
```

With `User-Agent: é`, Apache's ASCII PCRE does not match `^\w+$`, `TRUSTED` is absent, and the request is `403`; httpd-rs's Unicode-aware `\w` matches `é`, `TRUSTED` is set, and the same CGI executes:

| Case | Pattern | User-Agent | Apache | httpd-rs |
|---|---|---|---|---|
| **B2** | `^\w+$` | `é` | 403, no exec | 200, **EXEC** |
| **B2 control** | `^\w+$` | `abc` | 200, EXEC | 200, EXEC |
| **B2 control** | `^\w+$` | `abc def` | 403, no exec | 403, no exec |

The ASCII and space controls show that the gate is live on both servers; only the Unicode letter is misclassified. The same shape applies when the environment variable is consumed by `Require env`, `SetEnvIf`-driven rewrite conditions, or another later directive that reads the environment.

### 3.3 Impact

- **Fail-open deny guards.** A guard that denies a header/path pattern on Apache can silently stop matching on httpd-rs, exposing the protected resource. The harness's protected resource is an executable CGI; the same shape can protect a `.php` handler, an upload tree, or a rewrite-selected file.
- **Over-grant allow guards (B2).** The opposite direction is demonstrated by the `SetEnvIf`/`Require env` gate: an allow rule written with `^\w+$`, `^\d+$` or `^\s+$` accepts Unicode input on httpd-rs that Apache rejects. Any security decision that uses these classes as a positive gate inherits the bug.
- **No `.htaccess` is required.** P16-B works under `AllowOverride None` and the benchmark config, because `RewriteCond`/`RewriteRule`/`SetEnvIf` in the main configuration use the same compiler. The attacker only needs to control the tested header (or, at the other call sites, a path component).
- **Blast radius beyond rewrite.** `FilesMatch`/`LocationMatch`/`DirectoryMatch`/`AliasMatch`/`RedirectMatch` patterns use `compile_regex` and share the Unicode semantics. A `<FilesMatch "^\W…">`-style deny or allow can differ in the same way; those non-rewrite call sites were not separately differential-tested in this pass, but `SetEnvIf` now is (B2) and the shared compiler is the invariant to fix.
- The impact is configuration-dependent: it requires a guard/allow rule that uses one of the affected class escapes with attacker-controlled non-ASCII input. It is not an unconditional RCE by itself, but it is a complete bypass of a guard that an operator reasonably expects to behave as Apache does.

### 3.4 Fix

1. **Compile directive regexes with Apache-compatible ASCII semantics.** The project already uses `pcre2::bytes` for expression regexes (`crates/server/src/expr.rs:11-44`); using the same engine for `compile_regex`, `RewriteCond` and `RewriteRule` removes the dialect split. If a PCRE2 migration is too large for one change, set `unicode(false)` on the Rust `regex` builder at all three sites (and any direct builder) so `\b`, `\w`, `\d`, `\s` and their negations are ASCII, and keep `.` byte-oriented like PCRE.
2. **Do not leave direct builders behind.** Route `RewriteCond`/`RewriteRule` through the single `compile_regex` helper so a future fix cannot miss them, and add a unit test that compiles the same pattern through every directive parser.
3. **Add non-ASCII regressions** for `\b`, `\W`, `\D`, `\S`, `\w`, `\d`, `\s` at the `RewriteCond`/`RewriteRule` and `SetEnvIf`/`FilesMatch` sites. The four B1 rows and three B1 controls are the minimal fail-open differential; the B2 row and two controls are the minimal over-grant differential. The normal test suite should also pin the ASCII positive and `xadminx` negative cases.
4. **Do not "fix" this by rejecting non-ASCII input.** Apache accepts the header/path and makes a policy decision; httpd-rs must make the same decision, not return a different error. The control `<If>` case shows the project already has the correct PCRE behaviour available.

---

## 4. P16-C — header guards drop invalid UTF-8 instead of matching raw bytes

### 4.1 Root cause

The request policy layer exposes header values as `&str` (`crates/server/src/http.rs:150-155`):

```rust
pub fn header_str(&self, name: &str) -> Option<&str> {
    self.header(name).and_then(|v| std::str::from_utf8(v).ok())
}
```

HTTP/1.1 field values are byte strings; RFC 9110 permits `obs-text` (`%x80-FF`) in them, and Apache's regex engines match those bytes directly. httpd-rs instead converts each value to UTF-8 and silently substitutes an empty string on failure at every guard consumer:

- `Scope::request_env` (`config.rs:1502-1513`) calls `header_str(...).unwrap_or_default()` for `SetEnvIf`;
- `rewrite.rs:1117` does the same for `RewriteCond %{HTTP:...}`;
- `expr.rs:300-321` does the same for `<If>`, `Require expr` and `RewriteCond expr`.

A header value such as `\xFFsqlmap` is therefore the empty string on httpd-rs, while Apache's PCRE still sees the bytes and matches `sqlmap`. Any **negative** guard (deny when the signature matches) disappears: `SetEnvIf` + `Require not env`, `RewriteCond ... [F]`, or `<If>`-wrapped `Require all denied`. Positive allow guards fail closed in the same situation, so the security-relevant direction is a deny/blocklist bypass.

This is independent of P16-B: it needs no special regex class and no non-ASCII Unicode character; one invalid byte anywhere in the field is enough, and the valid UTF-8 controls still match on both servers.

### 4.2 Exploit chain (observed)

Fixture per case: one executable `run.cgi` producing `EXEC-P16C`, one of three main-config guards, and the attacker-controlled header named in the guard (`User-Agent` for C1, `X-User` for C2/C3). The guard is the only thing standing between the request and the CGI.

```apache
# C1
SetEnvIf User-Agent "sqlmap" BLOCK
<Directory "/srv/app/www">
    Options +FollowSymLinks +ExecCGI
    AddHandler cgi-script .cgi
    <RequireAll>
        Require all granted
        Require not env BLOCK
    </RequireAll>
</Directory>

# C2
RewriteEngine On
RewriteCond %{HTTP:X-User} sqlmap
RewriteRule ^ - [F]

# C3
<Directory "/srv/app/www">
    <If "%{HTTP:X-User} =~ /sqlmap/">
        Require all denied
    </If>
    Require all granted
</Directory>
```

| Case | Guard | Header value | Apache | httpd-rs |
|---|---|---|---|---|
| **C1** | `SetEnvIf User-Agent` / `Require not env` | `\xFFsqlmap` | 403, no exec | 200, **EXEC** |
| **C2** | `RewriteCond %{HTTP:X-User}` / `[F]` | `\xFFsqlmap` | 403, no exec | 200, **EXEC** |
| **C3** | `<If>` on `X-User` deny | `\xFFsqlmap` | 403, no exec | 200, **EXEC** |
| C1 control | `SetEnvIf User-Agent` / `Require not env` | `sqlmap` | 403, no exec | 403, no exec |
| C1 control | `SetEnvIf User-Agent` / `Require not env` | `curl/8` | 200, EXEC | 200, EXEC |
| C1 control | `SetEnvIf User-Agent` / `Require not env` | `\xFF` | 200, EXEC | 200, EXEC |
| C1 control | `SetEnvIf User-Agent` / `Require not env` | `ÿsqlmap` (valid UTF-8) | 403, no exec | 403, no exec |
| C2 control | `RewriteCond %{HTTP:X-User}` / `[F]` | `sqlmap` | 403, no exec | 403, no exec |
| C3 control | `<If>` on `X-User` deny | `sqlmap` | 403, no exec | 403, no exec |

The ASCII controls show the guard is live in each directive; the benign and invalid-only controls show the differential is the invalid byte plus the signature, not a blanket rejection; the valid UTF-8 control shows the bug is specifically the failed UTF-8 conversion, not any non-ASCII byte.

### 4.3 Impact

- **Header deny-guard/blocklist bypass with no `.htaccess`.** The benchmark posture uses `AllowOverride None`; all three guards are main-configuration directives. One invalid byte in the tested header defeats the guard and executes the protected CGI.
- **WAF-style and application blacklist rules are affected.** A rule that blocks `sqlmap` by matching `User-Agent`, `Referer`, a custom `X-*` header, or another request field is bypassed by prefixing the signature with `\xFF`; the request reaches the protected handler.
- **The same byte/string boundary affects appliance and application decisions.** Any later directive or expression that reads the header through `header_str` sees the empty string, not the raw value. Positive allow rules tend to fail closed, but the negative rules that are the common shape of a deny/blocklist fail open.
- **Not a malformed-request rejection.** Apache accepts obs-text in a field value, and httpd-rs's verified parser also accepts it; the request is well-formed on both. The servers disagree only after parsing, when httpd-rs converts to UTF-8 for the policy layer.

### 4.4 Fix

1. **Evaluate header-derived regexes on bytes.** Compile the relevant patterns with `regex::bytes` (or PCRE2 bytes) and pass `req.header(name)` or `req.header_str`-free raw accessors into `SetEnvIf`, `RewriteCond %{HTTP:...}` and expression header lookups. This also removes the unnecessary UTF-8 requirement from a layer that is supposed to mirror Apache's byte-oriented PCRE.
2. **Do not use `from_utf8_lossy` as the fix.** Replacing the invalid byte with `U+FFFD` changes the matched substring and still diverges from Apache (for example, a byte-oriented `\xFF` rule and an offset/anchored rule). The raw bytes must reach the matcher.
3. **Unify the three consumers.** `Scope::request_env`, `rewrite.rs` and `expr.rs` currently duplicate the same lossy conversion; introduce one byte-oriented header accessor and use it everywhere a guard or expression consumes a request field.
4. **Add C1–C3 and their controls** to the end-to-end regression suite. The invalid-only, ASCII, benign and valid-UTF-8 controls are the minimum needed to distinguish this from a general parser change.

---

## 5. P16-D — `SetEnvIf` action/attribute semantics diverge from Apache

### 5.1 Root cause

`parse_env_rule` implements the action list, but three documented Apache behaviours are missing (`crates/server/src/config.rs:1255-1268`):

```rust
} else if let Some((k, v)) = action.split_once('=') {
    actions.push((k.to_string(), Some(v.to_string())));
} else {
    actions.push((action.to_string(), Some(String::new())));   // Apache sets "1"
}
```

`Scope::request_env` (`config.rs:1502-1513`) then maps each rule's attribute to a request header or one of five special variables; it never consults an environment variable set by an earlier `SetEnvIf`, and it stores action values literally, without expanding `$1`/`$2` from the regex captures.

Apache 2.4 documents all three:

- `SetEnvIf ... varname` sets the variable to `"1"`, not the empty string;
- a later `SetEnvIf` may test an environment variable defined by an earlier one (when the attribute is not a request header/special variable);
- `$1`..`$9` in an action value are replaced with the corresponding regex captures.

The differences become deny-guard bypasses when the value, the chained variable, or the capture is what the guard checks.

### 5.2 Exploit chain (observed)

Fixture per case: one executable `run.cgi` producing `EXEC-P16D`, a `User-Agent`-controlled rule, and a `<RequireAll>` deny. The three shapes are:

```apache
# D1 - valueless action must be "1"
SetEnvIf User-Agent "sqlmap" BLOCK
<RequireAll>
    Require all granted
    Require not expr "%{env:BLOCK} == '1'"
</RequireAll>

# D2 - later SetEnvIf tests the prior variable
SetEnvIf User-Agent "sqlmap" BAD
SetEnvIf BAD "1" DENY
<RequireAll>
    Require all granted
    Require not env DENY
</RequireAll>

# D3 - action value uses the regex capture
SetEnvIf User-Agent "^([a-z]+)$" ID=$1
<RequireAll>
    Require all granted
    Require not expr "%{env:ID} == 'sqlmap'"
</RequireAll>
```

| Case | Shape | `User-Agent` | Apache | httpd-rs |
|---|---|---|---|---|
| **D1** | valueless `BLOCK` + expression value test | `sqlmap` | 403, no exec | 200, **EXEC** |
| D1 control | `BLOCK=1` + same test | `sqlmap` | 403, no exec | 403, no exec |
| D1 control | valueless `BLOCK` + benign request | `curl/8` | 200, EXEC | 200, EXEC |
| **D2** | `BAD` then `SetEnvIf BAD 1 DENY` + `Require not env` | `sqlmap` | 403, no exec | 200, **EXEC** |
| D2 control | single `DENY=1` + `Require not env` | `sqlmap` | 403, no exec | 403, no exec |
| D2 control | chain + benign request | `curl/8` | 200, EXEC | 200, EXEC |
| **D3** | `ID=$1` + expression value test | `sqlmap` | 403, no exec | 200, **EXEC** |
| D3 control | same rule, non-matching benign value | `curl` | 200, EXEC | 200, EXEC |

The D1 control (`BLOCK=1`) proves the expression syntax and guard are live on both servers; the D2 control (single `DENY=1`) proves the `Require not env` gate is live; the D3 control proves the regex matches on both servers and only the capture value differs. The benign controls show the rule does not deny unrelated requests.

### 5.3 Impact

- **Server-side ACL bypass with no `.htaccess`.** D2 is the strongest shape: `SetEnvIf` chaining plus `Require not env` is entirely main-configuration, and the protected CGI executes on httpd-rs while Apache denies. D1/D3 show the same bypass when an operator checks the value with `Require expr` or uses a capture in an action.
- **The environment contract is wrong for applications too.** A CGI/PHP application that reads `BLOCK`, `ID` or a chained variable sees `""` or the literal `$1` on httpd-rs, and `"1"`/the captured text on Apache. Application-level deny logic that treats a nonempty/truthy value as a block can therefore fail open without any server-side expression.
- **No malformed request is required.** The trigger is a normal `User-Agent` (or other header) value that matches a configured signature; the differential is entirely in how httpd-rs builds the environment.
- **Broader `SetEnvIf` compatibility surface.** The same parser is used for `.htaccess`, `BrowserMatch` and `BrowserMatchNoCase`; the missing special variables (`Remote_Addr`, `Server_Addr`, `Request_Protocol`, …) and header-name regex attributes are adjacent gaps that were not separately differential-tested in this pass, so the fix should close the documented semantics as a unit.

### 5.4 Fix

1. **Set `"1"` for valueless actions** and update the parser unit test that currently pins `Some(String::new())`.
2. **Resolve env-var attributes from the environment built so far.** After the request-header/special-variable lookup fails, look for an earlier environment entry with the attribute name, matching Apache's precedence and ordering.
3. **Expand `$1`..`$9` in action values from the regex captures.** Store the captures at match time and substitute them in the action value; a literal `$1` must never reach `Require expr` or the application.
4. **Add D1–D3 and controls to the regression suite**, plus the adjacent special-variable and header-name-regex forms. The controls must include the explicit-value, single-rule and benign rows so a fix cannot pass by changing the guard rather than the environment.

---

## 6. Why these are reachable in the benchmark/typical posture

- **P16-B** needs no `.htaccess` and no benchmark deviation. `bench/app_bench.py` uses `AllowOverride None`; the main-config `RewriteCond`/`SetEnvIf` in B1/B2 is compiled by the same code and the guard/allow decision is changed with a request header. Only the rule's use of `\b`/`\W`/`\D`/`\S` (fail-open) or `\w`/`\d`/`\s` (over-grant) is required.
- **P16-C** also needs no `.htaccess` and no benchmark deviation. Its three guard shapes (`SetEnvIf` + `Require not env`, `RewriteCond` + `[F]`, `<If>` deny) are main-configuration directives, and the attacker only adds one obs-text byte to a header the guard already inspects. A blocklist/WAF rule that matches a signature in `User-Agent`, `Referer` or a custom header is bypassed while the request stays a valid HTTP field value.
- **P16-D** also needs no `.htaccess` and no benchmark deviation. The strongest shape (D2) uses `SetEnvIf` chaining and `Require not env`, both valid main-configuration directives; the attacker supplies a matching `User-Agent`. D1/D3 require the operator to test the env value or use a capture in the action, which is the documented Apache behavior.
- **P16-A** needs the deployment to enable per-directory overrides (`AllowOverride All` or `FileInfo`), which the benchmark config does not. This is the same precondition as F60/P14-A: a shared-hosting or application-managed tree where `.htaccess` is writable and a non-PHP upload is possible. The finding is still a remotely exploitable RCE in that common deployment class, and it is a direct consequence of httpd-rs's environment handling rather than a misconfiguration of the application.
- The Apache oracle for all four findings is a stock Debian Apache 2.4.69, the same package used by the benchmark and by the previous pass harnesses.

---

## 7. Reproduction

```sh
# Build (restore the deleted vendor directory first on this HEAD)
git checkout 6b781ea -- vendor/h2-0.4.20
cargo build --release -p httpd-rs

# Full battery: P16-A A1-A6 + P16-B B1-B2 + P16-C C1-C3 + P16-D D1-D3 (36 verdicts)
python3 adversarial/p16/exploit_p16.py

# Selected groups
python3 adversarial/p16/exploit_p16.py A1 A3
python3 adversarial/p16/exploit_p16.py B
python3 adversarial/p16/exploit_p16.py C
python3 adversarial/p16/exploit_p16.py D
python3 adversarial/p16/exploit_p16.py --keep
```

Expected final line:

```
36/36 differential verdicts
```

The retained remediation harness builds its fixture under `/tmp/opencode/p16-harness`, binds Apache and httpd-rs to sibling loopback ports, starts a fresh built-in FastCGI Unix-socket mock per A case, and kills only its own process groups. The mock reports whether `PHP_VALUE` or `PHP_ADMIN_VALUE` reached the backend, so PHP-FPM is no longer a test dependency. The B, C and D groups need Apache's `mod_cgi`/`mod_rewrite`/`mod_setenvif` and `mod_authz_core`.

The full observed row set:

```
PASS A1-setenv       apache=200 prepend=False/False  httpd-rs=200 prepend=True/True
PASS A2-admin-value  apache=200 prepend=False/False  httpd-rs=200 prepend=True/True
PASS A3-setenvif     apache=200 prepend=False/False  httpd-rs=200 prepend=True/True
PASS A4-subdir       apache=200 prepend=False/False  httpd-rs=200 prepend=True/True
PASS A5-fileinfo     apache=200 prepend=False/False  httpd-rs=200 prepend=True/True
PASS A6-no-htaccess  apache=200 prepend=False/False  httpd-rs=200 prepend=False/False
PASS A6-safe-env     apache=200 prepend=False/False  httpd-rs=200 prepend=False/False
PASS A6-override-none apache=200 prepend=False/False httpd-rs=200 prepend=False/False
PASS A6-main-config  apache=200 prepend=True/True   httpd-rs=200 prepend=True/True
PASS B1-boundary     apache=403/noexec httpd-rs=200/EXEC
PASS B1-nonword      apache=403/noexec httpd-rs=200/EXEC
PASS B1-nondigit     apache=403/noexec httpd-rs=200/EXEC
PASS B1-nonspace     apache=403/noexec httpd-rs=200/EXEC
PASS B1-control-ascii  apache=403 httpd-rs=403
PASS B1-control-nomatch apache=200 httpd-rs=200
PASS B1-control-if-pcre apache=403 httpd-rs=403
PASS B2-setenvif-grant apache=403/noexec httpd-rs=200/EXEC
PASS B2-control-ascii apache=200/EXEC httpd-rs=200/EXEC
PASS B2-control-space apache=403/noexec httpd-rs=403/noexec
PASS C1-setenvif-invalid apache=403/noexec httpd-rs=200/EXEC
PASS C1-control-ascii apache=403/noexec httpd-rs=403/noexec
PASS C1-control-benign apache=200/EXEC httpd-rs=200/EXEC
PASS C1-control-invalid-only apache=200/EXEC httpd-rs=200/EXEC
PASS C1-control-valid-utf8 apache=403/noexec httpd-rs=403/noexec
PASS C2-rewritecond-invalid apache=403/noexec httpd-rs=200/EXEC
PASS C2-control-ascii apache=403/noexec httpd-rs=403/noexec
PASS C3-if-invalid apache=403/noexec httpd-rs=200/EXEC
PASS C3-control-ascii apache=403/noexec httpd-rs=403/noexec
PASS D1-empty-value apache=403/noexec httpd-rs=200/EXEC
PASS D1-control-explicit apache=403/noexec httpd-rs=403/noexec
PASS D1-control-benign apache=200/EXEC httpd-rs=200/EXEC
PASS D2-chain apache=403/noexec httpd-rs=200/EXEC
PASS D2-control-single apache=403/noexec httpd-rs=403/noexec
PASS D2-control-benign apache=200/EXEC httpd-rs=200/EXEC
PASS D3-backref apache=403/noexec httpd-rs=200/EXEC
PASS D3-control-benign apache=200/EXEC httpd-rs=200/EXEC
```

The A6 controls are deliberately all on the `expect_httpd_rs=False` side except the main-config positive control:

- `A6-no-htaccess` — no access file; neither server executes.
- `A6-safe-env` — `SetEnv APP_ENV production`; a harmless name is not a PHP control parameter, neither executes.
- `A6-override-none` — the same `SetEnv PHP_VALUE` access file with `AllowOverride None`; the parser never sees it, neither executes.
- `A6-main-config` — `SetEnv PHP_VALUE "auto_prepend_file=…"` in the main configuration; both servers execute, proving the differential is source provenance rather than PHP-FPM refusing the parameter.

The B1 controls pin the guard itself: ASCII `admin` is denied by both, `xadminx` is allowed by both, and the `<If>` PCRE form denies `éadmin` on both. Without those rows, a broken fixture could look like a bypass. The B2 controls pin the positive gate: ASCII `abc` is admitted and executes on both, while `abc def` is denied on both; only the Unicode letter `é` differs. The C1 controls pin the byte boundary: ASCII `sqlmap` is denied by both, benign `curl/8` is allowed by both, an invalid byte without the signature (`\xFF`) is allowed by both, and `ÿsqlmap` (valid UTF-8 containing the signature) is denied by both. The C2/C3 ASCII controls repeat the positive signature for the other two guard paths. The D1/D2/D3 controls pin the environment semantics: explicit `BLOCK=1` still denies on both, a single `DENY=1` rule still denies on both, a non-matching catch-all capture still allows on both, and benign requests are allowed by all three shapes.

---

## 8. Scope and limitations

- **Local only.** Apache and httpd-rs bind `127.0.0.1`; PHP-FPM uses a Unix socket under the fixture. No public address or external backend is contacted.
- **P16-A precondition.** The deployment must parse the access file (`AllowOverride All`/`FileInfo`). The benchmark's `AllowOverride None` makes the A group fail closed by construction (`A6-override-none`), which is why the finding is stated for the override-enabled deployment class rather than the default benchmark run. The `.htaccess` and upload are attacker content; no product source is modified.
- **P16-B precondition.** The rule must use an affected class escape on an attacker-influenced value. The battery demonstrates the four fail-open deny forms (B1) and one over-grant allow form (B2); the shared `compile_regex` call sites mean the same class of bug can appear in other directives, but those additional sites were not individually differential-tested here.
- **P16-C precondition.** The guard must read an attacker-influenced header through the current string conversion and must be a negative/deny shape (match means block). The battery demonstrates `SetEnvIf`/`Require not env`, `RewriteCond`/`[F]` and `<If>` deny; a positive `Require env` or positive expression gate fails closed when the header becomes empty, so it is an availability/parity difference rather than an access bypass.
- **P16-D precondition.** The guard must depend on one of the documented `SetEnvIf` semantics that httpd-rs does not implement: a valueless action's value, an earlier env variable as an attribute, or a `$n` capture in an action value. D2 (`Require not env` plus chaining) is the most broadly usable shape; D1/D3 require the operator to test the value or use a capture.
- **Apache version.** The oracle is Apache 2.4.69 (Debian) with `mod_proxy_fcgi` and PHP-FPM 8.4.27. The P16-A recommendation (do not trust access-file environment for FastCGI, or reserve backend-control names) is safe regardless of a particular Apache point release; the P16-B recommendation (ASCII/PCRE parity) follows Apache's documented regex semantics, the P16-C recommendation (match raw field bytes) follows Apache's byte-oriented request handling, and the P16-D recommendation follows mod_setenvif's documented `1`/chaining/`$n` semantics.
- **No denial-of-service or memory-safety finding is claimed.** The harness records only the status/content and marker execution differentials above.

---

## 9. Disclosure summary

| ID | Component | Preconditions | Observed effect |
|---|---|---|---|
| P16-A | `htaccess.rs` environment parser → `config.rs::request_env` → `server.rs::run_fastcgi` → `cgi.rs::build_env` → `fastcgi.rs::build_params` → PHP-FPM | Writable `.htaccess`, `AllowOverride All`/`FileInfo`, any PHP request in scope, one uploaded non-PHP file | PHP code execution as the FPM worker; `PHP_ADMIN_VALUE` system-level override |
| P16-B | `config.rs::compile_regex` (`SetEnvIf`), `RewriteCond`/`RewriteRule` direct builders | A deny/allow rule using `\b`, `\W`, `\D`, `\S` (fail-open) or `\w`, `\d`, `\s` (over-grant) on attacker-controlled non-ASCII input | Deny-guard bypass (B1) or positive-gate over-grant (B2); protected CGI execution, with no `.htaccess` needed |
| P16-C | `http.rs::header_str` → `config.rs::request_env` / `rewrite.rs` / `expr.rs` | A negative guard (`SetEnvIf`+`Require not env`, `RewriteCond`+`[F]`, or `<If>` deny) on an attacker-controlled header, with one obs-text/invalid-UTF-8 byte | Header deny/blocklist bypass; protected CGI execution, with no `.htaccess` needed |
| P16-D | `config.rs::parse_env_rule` / `Scope::request_env` | A guard that depends on valueless-action `1`, env-variable chaining, or `$n` capture expansion; attacker controls the matching header value | `SetEnvIf` deny-guard bypass; protected CGI execution, with no `.htaccess` needed |

The exact exploit shapes are retained in `adversarial/p16/exploit_p16.py`; the next pass should re-run the battery after any environment-provenance, regex-dialect, header-value conversion or `SetEnvIf` environment-semantics change and keep the controls as the regression floor.
