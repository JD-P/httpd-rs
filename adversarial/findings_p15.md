# Pass 15 — adversarial break of HEAD `a3d514f` ("Harden verified transform and filesystem boundaries")

- **Date:** 2026-10-28
- **Subject:** `target/release/httpd-rs` built at HEAD `a3d514f` (no repo source edits; the only additions for this pass are `adversarial/p15/exploit_p15.py`, this write-up and the `adversarial/README.md` index entry)
- **Oracle:** Apache/2.4.69 (Debian) with `mod_proxy_fcgi`, `/usr/sbin/apache2 -X`; PHP-FPM 8.4.27 (Debian defaults, `security.limit_extensions` as compiled). Loopback only.
- **Method:** re-run of the pass-13/14 fixtures plus a targeted audit of every FastCGI script-identity construction site, driven by the one place a backend makes its own security decision from `SCRIPT_FILENAME`: PHP-FPM's `security.limit_extensions`. The battery pairs the project's own benchmark FastCGI posture (`bench/app_bench.py`: `ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:…|fcgi://localhost<docroot>/"`) with an in-root symlink whose lexical name has no PHP extension — the same attacker primitive pass 13 already treats as in scope.
- **Harness:** `adversarial/p15/exploit_p15.py` (37 differential verdicts, see §8).

---

## 1. Executive summary

Three new remotely triggerable findings, all identity/validation drift between httpd-rs and the component that makes the actual security decision:

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P15-A** | The FastCGI `PATH_INFO` split walks to the longest existing **lexical** prefix and then rebinds `SCRIPT_FILENAME` to the **canonical** symlink target, so PHP-FPM's own `security.limit_extensions` gate is bypassed and scripts whose direct URLs are `<Location>`-denied can be executed through an alternate URL, including an **attacker-uploaded `.php` file** reached through an attacker-created symlink whose name is not `.php` | `SCRIPT_FILENAME` is the lexical regex-captured path; FPM splits `PATH_INFO` itself, sees the `.txt` split script, and refuses with `403 Access denied.` | `SCRIPT_FILENAME` is the canonical `/…/secret/app.php`; FPM executes it as `www-data` (`200 PHPEXEC …`) | remote code execution / backend-policy and alternate-route authorization bypass |
| **P15-B** | `mod_remoteip` treats `RemoteIPTrustedProxy` and `RemoteIPInternalProxy` as one list and has no private-address rule, so a trusted proxy presenting a **private/loopback `X-Forwarded-For`** value rewrites `REMOTE_ADDR` where Apache deliberately refuses the value | `REMOTE_ADDR` stays the real peer; `Require ip 10.1.2.3` → `403` | `REMOTE_ADDR` becomes the attacker-supplied `10.1.2.3`; `Require ip 10.1.2.3` → `200` | remote-address authentication bypass (internal-only pages, `Require local`, audits) |
| **P15-C** | Expression regexes (`=~`/`!~` in `<If>`/`<ElseIf>`, `Require expr`, `RewriteCond expr`) skip load-time dialect validation, and evaluation errors are swallowed as `false`, so a PCRE-only pattern silently makes the guard inert | The guard's regex evaluates under PCRE; `Require all denied` / `[F]` / `Options -ExecCGI` applies (`403`) | Evaluation errors → condition false; `<If>`-wrapped denies and rewrite denies are skipped, `Require not expr` grants, and a protected CGI executes (`200`, `EXEC`) | fail-open guard removal (ACL bypass, protected-CGI execution, rewrite-deny bypass) |

The differential is unconditional in the format the project benchmarks: same config, same trees, same requests. For P15-A, Apache refuses (FPM gate), httpd-rs executes. For P15-B, the same `RemoteIPTrustedProxy` config that Apache denies grants on httpd-rs; the `RemoteIPInternalProxy` control flips both servers to `200`. For P15-C, the same PCRE pattern that Apache evaluates denies on httpd-rs is silently ignored; a plain-pattern control denies on both.

The root cause is the same shape in all three: the **decision the other component makes** (PHP-FPM's extension gate, the remote-IP policy, the guard regex) is computed from a representation httpd-rs never validated to match Apache's (canonical path, merged proxy list, lazy unvalidated regex).

---

## 2. P15-A — FastCGI `PATH_INFO` symlink canonicalization bypasses the backend's own script gate

### 2.1 Root cause

`crates/server/src/fastcgi.rs:247-296` (`split_path_info`) walks the URL-mapped path backwards to the longest **existing lexical** prefix and returns that prefix plus the remainder as `PATH_INFO`:

```rust
if candidate.is_file() {
    if !contained_after_resolving_symlinks(&candidate, base) {
        return None;
    }
    ...
    return Some((candidate, name, info));      // lexical prefix, e.g. pub/link.txt
}
```

`server.rs:3220-3239` (`run_fastcgi`) then resolves that prefix through an opened descriptor and **replaces the target's script filename with the canonical target**:

```rust
let Some(script_binding) = fastcgi::open_script(&target, mapping_root, …) else { … };
target.script_filename = script_binding.actual_path.clone();   // canonical: secret/app.php
```

and `fastcgi.rs:762-781` sends that canonical path as the backend's `SCRIPT_FILENAME`, with the freshly split `PATH_INFO` alongside it. The closure for P13 explicitly made this intentional: *“the canonical opened path is used only for containment, authorization and `SCRIPT_FILENAME`.”*

Apache's `mod_proxy_fcgi` does the opposite: for `ProxyPassMatch` it forwards the **lexical regex-captured path** as `SCRIPT_FILENAME` and lets PHP-FPM perform its own `fix_pathinfo` split, after which FPM applies `security.limit_extensions` to the split script. For `/pub/link.txt/x.php`:

- Apache: `SCRIPT_FILENAME=<docroot>/pub/link.txt`, FPM split script `/…/pub/link.txt` → extension `.txt` → **403** (`Access to the script … has been denied (see security.limit_extensions)`).
- httpd-rs: `SCRIPT_FILENAME=<canonical>/secret/app.php` → extension `.php` → **executes**.

The project's own FPM access log makes the drift explicit (harness `--show-fpm-log`, paired lines are Apache/httpd-rs):

```
/tmp/opencode/p15-harness/www//pub/link.txt|/pub/link.txt     <- Apache: lexical path, 403
/tmp/opencode/p15-harness/www/secret/app.php|/pub/link.txt    <- httpd-rs: canonical path, 200 exec
```

### 2.2 Exploit chain (observed)

The deployment is the project's own benchmark configuration (`bench/app_bench.py`), plus one symlink in the served tree:

```apache
DocumentRoot "/srv/app/www"
<Directory "/srv/app/www">
    Options +FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:/run/php/php8.4-fpm.sock|fcgi://localhost/srv/app/www/"
DirectoryIndex index.php
```

```
/srv/app/www/secret/app.php          (application script)
/srv/app/www/pub/link.txt   ->       ../secret/app.php
```

`P15-A1` — no guards:

```
GET /pub/link.txt/x.php
  Apache 2.4.69: 403  "Access denied."                 (FPM security.limit_extensions)
  httpd-rs HEAD:  200  "PHPEXEC secret-app uid=33"      (PHP-FPM executed the script)
```

`P15-A2` — the operator protects the script's directory the documented way:

```apache
<Location "/secret/">
    Require all denied
</Location>
```

```
GET /secret/app.php        Apache 403  httpd-rs 403   (guard live on both)
GET /pub/link.txt/x.php    Apache 403  httpd-rs 200 "PHPEXEC secret-app uid=33"
```

Apache's second-row `403` is PHP-FPM's extension-gate refusal, not the `<Location>` guard (the guard cannot see the `/pub/…` URL on either server); on httpd-rs neither the guard nor the gate stops the request, so the protected script runs through an alternate URL.

`P15-A3` — the symlink points at an **attacker-uploaded** PHP file and the uploads tree is `<Location>`-denied:

```
/srv/app/www/uploads/shell.php       (attacker upload)
/srv/app/www/pub/upload-link.txt ->  ../uploads/shell.php

<Location "/uploads/"> Require all denied </Location>

GET /uploads/shell.php                  Apache 403 (guard)      httpd-rs 403
GET /pub/upload-link.txt/x.php          Apache 403 (FPM gate)   httpd-rs 200 "PHPEXEC uploads-shell uid=33"
```

The second row is the operational effect on an operator who protects the writable tree with `<Location>`: the direct URL is denied on both servers, but httpd-rs executes the same uploaded file by its alternate name, and Apache refuses only because FPM sees the `.txt` split script.

Any suffix that satisfies the route regex works: `/pub/link.txt/x.php`, `/pub/link.txt/x.php/y`, `/pub/link.txt/.php` (all three rows execute on httpd-rs; Apache is 403 on all three).

### 2.3 Impact

- **Remote code execution as the PHP-FPM worker user** in the benchmark FastCGI posture, using only a request plus the same in-root-symlink primitive pass 13 already treats as attacker-reachable (archive extraction preserving symlink entries, application-created links, backups/migrations, file-manager features).
- **Executes scripts the backend is configured to refuse**: PHP-FPM's `security.limit_extensions` is a defense-in-depth gate that Apache cannot bypass with this URL; httpd-rs hands FPM a path that satisfies it. The operator gets *less* security from the same config/backend than with Apache.
- **Alternate-route authorization bypass**: an operator who protects a script or a writable upload tree with `<Location>` (the URL-space guard, and the only one Apache honors for proxied paths) gets a `403` on the protected URL but an execution through `/pub/link.txt/x.php` on httpd-rs. Neither the `<Location>` guard nor FPM's extension gate applies to that route, so the guard's intent is defeated even though the guard itself is live on its own URL (`P15-A2`/`A3`).
- Also reachable through any FastCGI prefix route (`ProxyPass`/`ProxyPassMatch`) that resolves a `PATH_INFO` prefix, not only the benchmark spelling.

### 2.4 Fix

The backend must make the same security decisions Apache's backend would. Two consistent options:

1. **Mirror Apache (preferred).** Carry two script identities on the FastCGI target: the **lexical split prefix** (the path selected by `split_path_info` before canonicalization) as the `SCRIPT_FILENAME` sent to the backend, and the canonical opened path for httpd-rs's own containment/authorization/binding (which `binding_key()` and the `expected.fs_path` sink check consume today). PHP-FPM then applies its own `fix_pathinfo`/`security.limit_extensions` policy to the same path Apache would send. To preserve the pass-13 anti-TOCTOU property, verify immediately before sending that reopening the lexical path still yields the bound dev/ino and fail closed on mismatch.
2. **Keep the canonical path but fail closed on identity disagreement.** If `script_binding.actual_path`'s basename/extension differs from the lexical prefix the URL resolved to, return `403` instead of sending the canonical path, so the backend never sees an extension identity Apache would not produce.

Separately (defense in depth, and the P13 `<Location>` note): evaluating the selected script's own URL scope (`/secret/app.php`, `/uploads/shell.php`) in addition to its canonical filesystem scope would restore URL-space guards — but the FPM gate bypass in `P15-A1` needs fix 1 or 2 regardless.

Add the §7 rows (`link.txt`/`upload-link.txt` × `x.php`/`x.php/y`/`.php`, `<Location>` guards, direct-guard controls, `<Directory>` control) to `tests/adversarial_regressions.py` and the closure matrix.

---

## 3. P15-B — `RemoteIPTrustedProxy` loses Apache's private-address rejection (internal-only auth bypass)

### 3.1 Root cause

`crates/server/src/config.rs:4762-4777` parses both directives into the *same* list and later `Config::client_addr` (`config.rs:11005-11047`) uses that list only as "is the peer allowed to rewrite", then picks the first address in the header that is **not** in the list:

```rust
"remoteipinternalproxy" | "remoteiptrustedproxy" => { … self.cfg.remoteip_internal.push(net) … }
…
let trusted = self.remoteip_internal.iter().any(|(net, bits)| ip_in_net(peer.ip(), *net, *bits));
if !trusted { return peer; }
…
match crate::verified::first_untrusted_index(&trusted_flags) {
    Some(index) => SocketAddr::new(parsed[index].0, peer.port()),
    None => peer,
}
```

Apache's `mod_remoteip` has three rules that list cannot express:

1. `RemoteIPInternalProxy` and `RemoteIPTrustedProxy` are different classes; an address presented by a *trusted* (external) proxy is treated as external (`internal = match[i].internal` only when the presenting proxy was internal).
2. When the chain is external, a presented **private/nonsensical** address (`10/8`, `127/8`, `169.254/16`, `172.16/12`, `192.168/16`, non-global IPv6) is refused and processing stops (`APLOGNO(01569)` "appears to be a private IP or nonsensical. Ignored"); `REMOTE_ADDR` stays the real peer.
3. An unparsable entry or an empty entry stops the walk; httpd-rs skips it and keeps scanning left.

The stated security purpose of rules 1–2 is exactly to stop a trusted external proxy from injecting an internal-looking address; httpd-rs dropped all three. `RemoteIPHeader` alone is not enough to rewrite on httpd-rs either (the peer must be in the list), but once a trusted proxy is configured, any private value it presents is believed.

### 3.2 Exploit chain (observed)

Precondition: the deployment trusts a reverse proxy/CDN for client-address rewriting (`RemoteIPTrustedProxy <proxy>`), the proxy forwards or passes through the client-supplied `X-Forwarded-For` value (or the attacker is positioned to control the rightmost value), and an internal-only area is guarded with `Require ip <private range>` / `Require local` — an ordinary "admin pages are internal-only" posture.

```apache
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy 127.0.0.1          # the proxy; in production, the CDN/LB address

<Directory "/srv/app/www">
    Require all granted
</Directory>
<Directory "/srv/app/www/admin">
    Require ip 10.1.2.3                  # internal-only area
</Directory>
```

Harness `B1` (the proxy is loopback for the loopback-only test; the peer must be trusted for rewriting to happen at all):

| `X-Forwarded-For` | Apache 2.4.69 | httpd-rs HEAD |
|---|---|---|
| *(absent)* | `403`, `REMOTE_ADDR=127.0.0.1` | `403`, `REMOTE_ADDR=127.0.0.1` |
| `8.8.8.8` | `403`, `REMOTE_ADDR=8.8.8.8` | `403`, `REMOTE_ADDR=8.8.8.8` |
| `10.1.2.3` | **`403`**, `REMOTE_ADDR=127.0.0.1` | **`200`**, `REMOTE_ADDR=10.1.2.3` |
| `8.8.8.8, 10.1.2.3` | **`403`**, peer kept | **`200`**, `REMOTE_ADDR=10.1.2.3` |
| `::ffff:10.1.2.3` | **`403`**, peer kept | **`200`**, `REMOTE_ADDR=10.1.2.3` |
| `10.1.2.3,` (trailing empty) | **`403`**, peer kept | **`200`**, `REMOTE_ADDR=10.1.2.3` |

Control `B2` flips the directive to `RemoteIPInternalProxy 127.0.0.1`: both servers accept `10.1.2.3` (`200`/`200`) and compute the same `REMOTE_ADDR`, proving the divergence is the missing trusted/internal distinction plus the private-address rule, not a general `Require ip` difference. The CGI oracle (`/rip.cgi` printing `REMOTE_ADDR`) shows the exact rewritten value on each server.

### 3.3 Impact

- **Authentication/authorization bypass**: internal-only areas (`Require ip 10/8`, `Require ip 192.168/16`, `Require local`, `Require not ip <public>` …) that Apache denies become reachable through the trusted proxy by spoofing the header. Any CGI/executable inside that area becomes reachable too.
- **Audit/log integrity**: `REMOTE_ADDR` used by the application, access logs (`%a`), and downstream `Require env`/expression rules reflects the attacker-supplied value only on httpd-rs; on Apache the spoof is refused.
- The migration hazard is silent: the operator's config is valid on Apache, where these spoofs are *by design* ineffective.

### 3.4 Fix

Mirror Apache's three rules in `client_addr` and the parser:

1. store the proxy class per entry (`internal: bool`) and propagate it while walking the chain: a trusted entry presented by a non-internal chain is external, and an internal address presented by an external chain is refused;
2. after the chain leaves the internal class, refuse (and stop at) private/loopback/link-local/CGNAT IPv4 values and non-global IPv6 values, exactly Apache's `APLOGNO(01569)` list;
3. stop the walk on an entry that does not parse (do not skip and continue left); trailing empty entries keep the previously accepted value, as Apache does.

Add the `B1`/`B2` table and the controls to `tests/adversarial_regressions.py`.

---

## 4. P15-C — expression regexes skip load-time dialect validation; evaluation errors make guards inert

### 4.1 Root cause

Directive-level regexes go through `config.rs::compile_regex` → `guard_regex`, whose doc comment states the contract: *“PCRE-only constructs are rejected at load time rather than silently changing meaning.”* Expression regexes do not:

- `expr.rs:655-663` (`Expr::Regex` evaluation) runs `regex_dialect_admit` and `RegexBuilder::new(pattern).build()` **at request-evaluation time**, on every request;
- the expression parser/validator does not pre-compile regex nodes, so the configuration loads even when the pattern is a PCRE-only construct that the Rust regex crate rejects (`\Q…\E`, `\Z`, `\K`, `(?#…)`, backreferences `\1`…);
- every caller converts an evaluation error to `false`:
  - `config.rs:5401-5404` (`rule_condition_matches`, `<If>`/`<ElseIf>`) → `unwrap_or(false)`;
  - `rewrite.rs:819` (`RewriteCond expr`) → `unwrap_or(false)`;
  - `access.rs:585` (`Require expr`) → `unwrap_or(false)` and then `decide(hit, negate)`, so `Require not expr` **grants** on error.

Apache evaluates the same pattern with PCRE, so the guard applies. In httpd-rs the conditional block, rewrite-deny rule or negated require simply disappears; mixed `<If>/<Else>` chains even take the `<Else>` branch.

### 4.2 Exploit chain (observed)

Fixture per case: `/…/<name>/secret.txt`, `secretse.txt`, `private.txt` and an executable `secret.cgi` (`Options +ExecCGI` + `AddHandler cgi-script` in the server config). Config per case (one `<Directory>` each):

```apache
<If "%{REQUEST_URI} =~ /PATTERN/">
    Require all denied            # or: Options -ExecCGI
</If>
Require all granted
```

Harness `C1` results (`PATTERN` is the only variable):

| case | PATTERN | request | Apache 2.4.69 | httpd-rs HEAD |
|---|---|---|---|---|
| q-literal | `\Qsecret\E` | `/q-literal/secret.txt` | `403` | **`200`** protected file read |
| q-literal-cgi | `\Qsecret\E` | `/q-literal-cgi/secret.cgi` | `403` | **`200 EXEC`** protected CGI executed |
| end-Z | `secret\.txt\Z` | `/end-Z/secret.txt` | `403` | **`200`** |
| pc-comment | `sec(?#match)ret` | `/pc-comment/secret.txt` | `403` | **`200`** |
| K-reset | `\Ksecret` | `/K-reset/secret.txt` | `403` | **`200`** |
| backref | `(se)cret\1` | `/backref/secretse.txt` | `403` | **`200`** |
| if-else | `\Qsecret\E` (`<If> deny ; <Else> grant`) | `/if-else/secret.txt` | `403` | **`200`** branch inverted |
| not-expr | `\Qprivate\E` (`<RequireAll> Require not expr`) | `/not-expr/private.txt` | `403` | **`200`** deny-list bypass |
| rewrite-cond | `\Qsecret\E` (`RewriteCond expr` + `RewriteRule ^ - [F]`) | `/rewrite-cond/secret.txt` | `403` | **`200`** |
| control-plain | `secret` | `/control-plain/secret.txt` | `403` | `403` (guard itself works) |

`Options -ExecCGI` inside the `<If>` fails the same way: Apache answers `403 "Options ExecCGI is off"`, httpd-rs executes the script (the `q-literal-cgi` variant with `Options` instead of `Require` was verified with the standalone `expr_diff.py` harness and is folded into the same root cause).

### 4.3 Impact

- **Advisory/deny guards silently disappear**: the standard `<If "%{REQUEST_URI} =~ /…/"> Require all denied </If>` and `<RequireAll> Require not expr "…" </RequireAll>` idioms fail open for any pattern outside the Rust regex dialect.
- **Protected CGI execution**: `Options -ExecCGI` / `SetHandler default-handler` / `Require` restrictions wrapped in a conditional block are skipped, so files Apache refuses run under httpd-rs.
- **Rewrite deny rules fail open**: `RewriteCond expr` + `[F]`/`[G]`/`[R]` guards are skipped.
- The failure is invisible: configuration load succeeds, `-t` reports `Syntax OK`, and the server behaves as if the guard were never written. The project's own contract says the opposite.

### 4.4 Fix

Validate at load and fail closed at runtime:

1. In the expression validator (the same walk that implements `expr_var_known`), compile every `Expr::Regex` node: run `guard_regex` and `RegexBuilder::new(...).build()`; reject the configuration for unsupported dialects exactly like a directive regex. One walk covers `<If>`/`<ElseIf>`, `Require expr` and `RewriteCond expr`.
2. Make evaluation errors fail closed as defense in depth: an erroring `<If>`/`<ElseIf>` condition should fail the request (or at least never skip a deny); an erroring `Require not expr` must not grant; an erroring `RewriteCond expr` must fail the request.
3. Add the §4.2 table (including the plain-pattern control) to `tests/adversarial_regressions.py`.

---

## 5. Secondary observations (not promoted)

- **`SetHandler "proxy:…"` does not implement `PATH_INFO` at all.** With the same tree and `SetHandler "proxy:unix:…|fcgi://localhost"` scoped by `<FilesMatch "\.php$">`, `GET /index.php/x` executes on Apache (`200 PHPEXEC`, FPM `fix_pathinfo`) but returns `404` on httpd-rs: the `NotFound` branch only considers local CGI, never `fastcgi::match_proxy`/handler targets. This is a *fail-closed* compatibility gap (Apache executes, httpd-rs refuses), not a vulnerability; recorded for the conformance queue.
- **Trailing-slash source disclosure.** `GET /pub/link.txt/` returns `404` on Apache but `200` with the **source** of the symlinked PHP file on httpd-rs (`link.txt` is classified lexically, then the opened canonical target is served statically). The no-slash form `/pub/link.txt` already serves source on both servers, so this only widens an existing disclosure shape; note that the operator's remedy for both is not to expose a non-script symlink name in the tree.
- **`SSLVerifyClient` ignores section scope.** The `sslverifyclient` handler (`config.rs:5152-5181`) writes `verify_client` to the *current vhost/listener* SSL policy regardless of whether the directive appeared in a `<Directory>`/`<Location>` section, and last-write-wins. An Apache config with `SSLVerifyClient require` at vhost level plus a per-directory override either errors at TLS setup (mixed policies) or silently changes the whole listener's mTLS requirement. Operator-only (directives cannot be set in `.htaccess`), so not promoted; worth a future differential pass for the per-directory `require`/`none` shapes.

---

## 6. Negative results and controls (verified, not assumed)

- `/pub/link.txt` (no suffix) is served as **source** by both servers — the pass-13 F69 direct-path fix holds; the divergence needs the `PATH_INFO` route.
- Direct `/secret/app.php` and `/uploads/shell.php` are `403` on both servers while the `<Location>` guards are live, and `/secret/app.php/x` is `403`/`403` in `A2` — the guards themselves are not being skipped for their own URLs.
- A `<Directory "<docroot>/uploads"> Require all denied` guard **does** bind the symlink route on httpd-rs (`403`). The bypass is specific to URL-space `<Location>` policy and the backend's own gate; note Apache serves `/uploads/shell.php` (`200`) under a `<Directory>` guard because proxied dispatch resolves to the proxy filename, so `<Location>` — not `<Directory>` — is the Apache-compatible guard, and httpd-rs's `<Directory>` denial there is fail-closed.
- A reused pass-14 battery and the pass-15 ordering matrix (config vs `.htaccess` `<Files>`/`<Directory>`/`<DirectoryMatch>`, `Options=ExecCGI` gating, top-level `<Files>` vs per-directory forces) show **no** new ordering divergence on HEAD; all probes agree with Apache.
- The FPM `security.limit_extensions` message in Apache's `403` response (`Access denied.`, chunked) confirms the refusal comes from the backend, not from a URL-mapping 404: the request *does* reach FPM on Apache, and FPM refuses it.

---

## 7. Why the previous passes missed this

- Pass 13 fixed the CGI `PATH_INFO` branch to classify by the **lexical** prefix basename (`server.rs:2910-2940`), and fixed FastCGI **direct** dispatch to classify by the lexical request basename. Neither decision applies to `ProxyPassMatch` prefix/regex routes: the route is selected from the **URL** (not the basename), and the script filename is then rebuilt from the filesystem walk.
- The pass-13 closure explicitly sanctions the canonical `SCRIPT_FILENAME` ("…the canonical opened path is used only for containment, authorization and `SCRIPT_FILENAME`"), so the pass-13 retests only checked *classification*, not what identity the backend receives.
- Every existing FastCGI symlink regression uses a lexical name that PHP-FPM would itself accept (`.php`) or a non-PHP target, so the extension-gate differential never appears.
- `mod_remoteip` was audited in pass 5 only for peer canonicalization (F49: IPv4-mapped peers); the *header-chain* semantics — Apache's internal/trusted class propagation and the private-address rejection rule — were never differentially tested. The project's own config suite has no `RemoteIP*` case, and the httpd-rs parser silently merges the two directives into one list.
- Expression regexes were never fuzzed for dialect fidelity: the pass-8/11 `<If>` cases use plain patterns, `guard_regex` is wired only to directive regexes (`<DirectoryMatch>`, `SetEnvIf`, non-expr `RewriteCond`), and the dialect unit tests (`config.rs:7097-7101`) pin `compile_regex` rejection without ever building an `<If>`/`Require expr` pattern. The `regex_dialect_admit` call inside `Expr::Regex` evaluation looked like a guard, but it runs per request and its error is discarded.

---

## 8. How to reproduce

```sh
cd /root/httpd-rs
cargo build --release -p httpd-rs
python3 adversarial/p15/exploit_p15.py                    # A1-A4 + B1-B2 + C1, 37 verdicts
python3 adversarial/p15/exploit_p15.py A1 A3              # selected groups
python3 adversarial/p15/exploit_p15.py B1 B2              # RemoteIP only (PHP-FPM not needed)
python3 adversarial/p15/exploit_p15.py C1                 # expression dialect only
python3 adversarial/p15/exploit_p15.py --keep --show-fpm-log
```

Expected summary (Apache 2.4.69 and PHP-FPM 8.4 installed):

```
  PASS  A1-benchmark symlink-pathinfo-executes /pub/link.txt/x.php   apache=403 httpd-rs=200 PHPEXEC secret-app uid=33
  PASS  A1-benchmark symlink-direct-source /pub/link.txt             apache=200 source httpd-rs=200 source
  PASS  A1-benchmark deep-pathinfo /pub/link.txt/x.php/y             apache=403 httpd-rs=200 PHPEXEC
  PASS  A1-benchmark hidden-suffix /pub/link.txt/.php                apache=403 httpd-rs=200 PHPEXEC
  PASS  A2-location-secret symlink-pathinfo-executes /pub/link.txt/x.php   apache=403 httpd-rs=200 PHPEXEC
  PASS  A2-location-secret location-guard-direct /secret/app.php     apache=403 httpd-rs=403
  PASS  A3-uploaded-target upload-symlink-pathinfo /pub/upload-link.txt/x.php  apache=403 httpd-rs=200 PHPEXEC uploads-shell
  PASS  A3-uploaded-target upload-direct-guard /uploads/shell.php     apache=403 httpd-rs=403
  PASS  A4-directory-control directory-guard-symlink /pub/upload-link.txt/x.php  apache=403 httpd-rs=403
  PASS  B1-trusted-proxy private-xff-spoof        apache=403 httpd-rs=200 apcgi=REMOTE_ADDR=127.0.0.1 vpcgi=REMOTE_ADDR=10.1.2.3
  PASS  B1-trusted-proxy private-xff-after-public apache=403 httpd-rs=200 …
  PASS  B1-trusted-proxy mapped-v4-private-xff    apache=403 httpd-rs=200 …
  PASS  B1-trusted-proxy control-no-xff           apache=403 httpd-rs=403
  PASS  B2-internal-proxy internal-private-xff-both-allow apache=200 httpd-rs=200 REMOTE_ADDR=10.1.2.3
  PASS  C1-expression-dialect q-literal secret.txt        apache=403 httpd-rs=200
  PASS  C1-expression-dialect q-literal-cgi secret.cgi    apache=403 httpd-rs=200 EXEC
  PASS  C1-expression-dialect control-plain secret.txt    apache=403 httpd-rs=403
  … 37/37 differential verdicts
```

The harness builds its fixtures under `/tmp/opencode/p15-harness`, starts Apache (`-X`) and httpd-rs on sibling loopback ports with separate pid files, and kills its own process groups. The `A` groups use a private PHP-FPM pool, the `B` groups use a CGI `REMOTE_ADDR` oracle, and `C1` uses an executable CGI marker and needs neither PHP-FPM nor the `A` fixtures. `--show-fpm-log` prints the PHP-FPM access log (`%f|%r`) with the Apache/httpd-rs `SCRIPT_FILENAME` lines paired.

---

## 9. Suggested remediation order

1. **`run_fastcgi` script identity** — forward the lexical split prefix as `SCRIPT_FILENAME` (Apache parity) or fail closed when canonical and lexical basenames disagree; either way PHP-FPM must not receive an extension identity Apache's backend would never see. Add the §2.2/§2.3 rows as regressions.
2. **Expression regex validation** — compile every `Expr::Regex` node at load; reject unsupported dialects (do not defer to request-time evaluation), and make evaluation errors fail the request closed. Add the §4.2 table as regressions.
3. **`client_addr`/`RemoteIP*` semantics** — store the proxy class per entry, propagate internal/external through the chain, refuse private/nonsensical presented addresses once the chain is external, and stop on unparsable/empty entries (Apache's `mod_remoteip` rules). Add the §3.2 table as regressions.
4. **Canonical target URL scope** — evaluate the selected script's own URL (`/secret/app.php`, `/uploads/shell.php`) as part of target reauthorization so `<Location>` guards on the script's directory are honored even for `ProxyPassMatch` routes (defense in depth for the `P15-A2`/`A3` dimension).
5. **`SetHandler "proxy:…"` `PATH_INFO`** — implement the `NotFound`/`fix_pathinfo` case for handler-selected FastCGI targets so `/index.php/x` matches Apache (compatibility, fail-closed today).
6. Add the A1–A4/B1–B2/C1 rows to `tests/adversarial_regressions.py` and record P15-A/B/C in `docs/adversarial-closure.md` and the trend ledger.
