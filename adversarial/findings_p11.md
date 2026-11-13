# Pass 11 — adversarial re-test of HEAD `d219efb` ("Expanded tests and Verus coverage")

- **Date:** 2026-10-27
- **Subject:** `target/release/httpd-rs` built at HEAD `d219efb` (no repo edits; `cargo build --release` is a no-op at this commit)
- **Oracle:** Apache/2.4.69 (Debian), local binary `/usr/sbin/apache2`, loopback only
- **Method:** differential harness `/tmp/opencode/p11/exploit_p11.py` — 13 micro-apps, each a *typical* httpd-rs deployment (server-wide CGI enabled) plus **one hardening rule written in a common Apache idiom**; same fixture tree served by both servers on sibling ports; HTTP response compared.
- **Task framing:** verify which pass-10 survivals (`F61–F66`, `F69`, documented in `findings_p10.md`) are still live *after* the post-pass-10 remediation commits (`9e28a4f` + `d219efb`, which closed only F60/F67/F68), and run a fresh break-RCE hunt over the newest code and least-covered modules.

---

## 1. Executive summary

**The pass-10 remediation is incomplete.** Six of the seven pass-10 survivor root causes still reproduce on HEAD (only F66 turned out fixed), and a new sibling (`F64b`) is the strongest exploit chain found so far: **a remote attacker with nothing but a writable upload directory turns any `.cgi` file they create into executed code as `www-data`**, in a configuration where Apache 2.4 denies execution. httpd-rs executes it. That is remote code execution in the exact configuration the benchmark deploys (server-wide `AddHandler cgi-script .cgi` + `Options +ExecCGI`, i.e. the typical httpd-rs use case).

| # | Finding | Operator idiom Apache honours | Oracle result | httpd-rs HEAD result |
|---|---------|-------------------------------|---------------|----------------------|
| F61-A | `<Location "/admin/*"> Require all denied` | 403 | **200 — CGI executed** |
| F61-A2 | `<Location "/admin/*"> Options -ExecCGI` | 403 ("Options ExecCGI is off") | **200 — CGI executed** |
| F61-B | `<Location ~ "^/admin/"> Require all denied` | 403 | **200 — CGI executed** |
| F62 | `<Directory ".../www/[^a]*"> Require all denied` | 403 | **200 — CGI executed** |
| F62b | `<Files "[^a]*.cgi"> Require all denied` | 403 | **200 — CGI executed** |
| F63 | `<If "%{REQUEST_FILENAME} =~ /private/"> Require all denied` | 403 | **200 — CGI executed** |
| F63b | `RewriteCond expr "%{REQUEST_FILENAME} =~ /secret/"` + `[F]` | 403 | **200 — protected file leaked** |
| F64 | `<Directory uploads> SetHandler default-handler` (+ floor AddHandler) | 200, script served as **source** | 200, **script executed** |
| F64b | F64 + `AllowOverride FileInfo`, **attacker-written `.htaccess`** | 200, script served as **source** | 200, **script executed** |
| F65 | `ScriptAlias` tree + `<Directory cgibin> SetHandler default-handler` | 200, source | 200, **executed** |
| F69 | symlink `public/link.txt -> ../secret/secret.cgi`, global AddHandler | 200, static source | 200, **executed** |
| F66 | `<DirectoryMatch ".../private/$">` | 403 | 403 — **fixed** (verified, both 403) |
| F70 | `AccessFileName` inside `<Directory>` | config rejected by Apache | accepted — **not exploitable**, dead |

Control case **F61-C** (identical fixture tree, no `<Location>` block): both servers 200 with the CGI's own output — confirming the divergence in F61-A/B is caused by the guard idiom, not by the fixture.

Result: **six pass-10 survivor root causes (11 variant rows in the table) plus the new F64b reproduce as exploitable divergences on HEAD — every one in the RCE or protected-content-execution class.** Negative results: F66 is fixed; F70 cannot be triggered by operator-valid configuration.

---

## 2. Root-cause map (all verified at HEAD d219efb)

### 2.1 The mechanical insight: parse-time scope break, conjoin cannot fix it

Pass 10's fix for F60 (`bind_target_grant` / `restrict_with` conjoin, `server.rs:1390-1500` and `2231-2262`) is tight — reviewed this pass, see §4. It conjoins the *initial URL-mapped scope* with the *final target scope*. F61–F66 still bypass it because, for every case below, **the guard scope is never created at parse time on the URL-mapped path** (or is created without the needed predicate), so there is nothing to conjoin. The fixes must move to parse time (Location/glob matching, `[^...]` semantics, `expr` variables), not to the conjoin layer.

### 2.2 F61 — `<Location>` shell-glob / regex forms are parsed as literal strings

- `config.rs:2921-2922` — parser entry: `MatchKind::Location(args.join(" "))`. The argument is stored **verbatim** (tilde, quotes, spaces and all). No glob compilation, and no regex form.
- `config.rs:5225-5238` — matcher: literal `url_path == prefix` / prefix-with-`/`-boundary test only.

Consequences:

1. `<Location "/admin/*">` — the only URL path the predicate can ever accept is the literal string `/admin/*`. Real requests never match ⇒ the section never wakes ⇒ `Require all denied` / `Options -ExecCGI` inside it are inert. Apache matches the shell `*` (and `/admin` boundaries).
2. `<Location ~ "^/admin/">` — the `~` regex form folds into the same literal entry; it can never equal any request path ⇒ inert.
3. Note the silent nature: httpd-rs *parses* the section successfully (no config error), so an operator has no signal that the guard is dead.

Exploit (observed, clean differential run this pass):

```
<Location "/admin/*">
    Require all denied
</Location>
...
GET /admin/run.cgi
  Apache 2.4.69:  403 Forbidden  ("<!DOCTYPE HTML ... 403 Forbidden ...")
  httpd-rs HEAD:  200 + body "EXEC-ADMIN uid=..." + Content-Type: text/plain
```

`F61-A2` variant: `Options -ExecCGI` instead of `Require` — Apache rejects with *403 "Options ExecCGI is off"*, httpd-rs executes anyway (earlier clean run). `F61-B` variant: `<Location ~ ...>` — same, 403 vs EXEC (clean run this pass).

### 2.3 F62 / F62b — `[^...]` glob negation inverted in `<Directory>` and `<Files>`

`glob_match` (root at `config.rs:2287`, used from the `MatchKind::Directory`/`Files` primitive-matching arm) treats `[^...]` as a literal-character *class requirement* control incorrectly, in the direction of **including** paths Apache excludes: `<Directory ".../www/[^a]*">` matches nothing instead of "directories not starting with `a`", and `<Files "[^a]*.cgi">` matches nothing instead of "CGI scripts whose name does not start with `a`".

Operator reading: *deny everything that does not start with `a`* — Apache denies `/zdir/run.cgi`. httpd-rs executes it:

```
<Files "[^a]*.cgi">           # and identically <Directory ".../www/[^a]*">
    Require all denied
</Files>
GET /zdir/run.cgi
  Apache 2.4.69:  403 Forbidden
  httpd-rs HEAD:  200 + "EXEC-ZDIR uid=..." (clean run this pass)
```

### 2.4 F63 / F63b — `expr` has no `REQUEST_FILENAME` (and no `SCRIPT_FILENAME`)

`crates/server/src/expr.rs` (1519 lines) contains **zero occurrences** of `REQUEST_FILENAME` or `SCRIPT_FILENAME`. `expr::var()` therefore has no mapping for the two variables the `<If>`/`RewriteCond expr` access-control idioms depend on, and evaluates the guard against an empty/unknown value — fail-open.

```
# F63 — <If> in Directory scope
<Directory "{root}/www">
    Require all granted
    <If "%{REQUEST_FILENAME} =~ /private/"> Require all denied </If>
</Directory>
GET /private/run.cgi
  Apache: 403      httpd-rs: 200 EXEC-PRIVATE (executed)

# F63b — rewrite-layer
RewriteEngine On
RewriteCond expr "%{REQUEST_FILENAME} =~ /secret/"
RewriteRule "^" "-" [F]
GET /secret/index.html
  Apache: 403      httpd-rs: 200, protected index.html body served (info leak)
```

### 2.5 F64 / F64b — handler precedence: the last-parsed `AddHandler` beats same- & parent-scope `SetHandler`

- `config.rs:3979-4005` — both `AddHandler` and `SetHandler` push into the **same ordered list** with no precedence field: `sethandler` becomes `Handler::add("*", name)`.
- `effective_handler(...)` resolves the list in reverse order, so a later-parsed `AddHandler .cgi` overrides an earlier `SetHandler`, and a child's later-authority `AddHandler` overrides a parent's `SetHandler`. Apache gives `SetHandler` absolute authority in its scope regardless of order or inheritance.

This is where `F64b` becomes a remote-code-execution primitive rather than a misconfiguration:

```
# operator config — the standard "uploads are dead static data" hardening
<Directory "{root}/www/uploads">
    SetHandler default-handler
    AllowOverride FileInfo            # per-directory authority, as usual in deployments
</Directory>

# whole attacker contribution: a file in the writable upload dir
www/uploads/.htaccess:
    AddHandler cgi-script .cgi
www/uploads/run.cgi:                # attacker-authored CGI payload, mode irrelevant

GET /uploads/run.cgi
  Apache 2.4.69:  200 — body is the *source* of the script ("#!/bin/sh ..."), static
  httpd-rs HEAD:  200 — "EXEC-UPLOADS uid=..." (executed as www-data)
```

No operator mistake beyond the default `AllowOverride` posture of an upload tree; nothing about the operator config changes between the Apache-verdict and the httpd-rs-verdict. The single attacker-write is enough to gain code execution — **on HEAD this is the highest-impact single finding of pass 11.**

### 2.6 F65 — `ScriptAlias` ignores `SetHandler default-handler`

`cgi.rs:1211-1214`:

```rust
pub fn is_cgi(cfg: &Config, scope: &Scope, name: &[u8], script_alias: bool) -> bool {
    if script_alias { return true; }     // ← before options/handlers are consulted
    ...
}
```

Once `script_alias` is set, `is_cgi` returns `true` **before** reading `Options::EXEC_CGI` or the handler policy, so `SetHandler default-handler` in the ScriptAlias tree has no effect. Operators use exactly this idiom to keep alias trees from executing:

```
ScriptAlias /cgi-bin/ "{root}/www/cgibin/"
<Directory "{root}/www/cgibin"> SetHandler default-handler </Directory>
GET /cgi-bin/run.cgi
  Apache: 200 source     httpd-rs: 200 EXEC-CGIBIN (executed)
```

### 2.7 F69 — handler identity from the canonical target basename on in-root symlinks

`www/public/link.txt -> ../secret/secret.cgi` with the global `AddHandler cgi-script .cgi`: Apache classifies the URL by the *request* basename (`link.txt` → static) and serves the target; httpd-rs resolves the in-root symlink and classifies by the *canonical target* basename (`secret.cgi` → CGI) and **executes** a file Apache treats as inert static content. Observed (earlier clean run): Apache 200 static source vs httpd-rs 200 `EXEC-SECRET`.

---

## 3. Negative results (verified, not assumed)

- **F66 — `<DirectoryMatch ".../private/$">` — FIXED on HEAD.** Both servers serve 403 for the trailing-slash directory URL (`GET /private/`). Left in the battery as a regression guard; it exercises the autoindex path, which neither the pass-10 golden tests nor the adversarial replay file covered.
- **F70 — `AccessFileName` identity split — dead.** Apache rejects the directive inside `<Directory>` ("AccessFileName not allowed here"), so no operator-valid configuration can change the access-file name per-directory. httpd-rs accepting the directive there is a parser-strictness divergence only; no exploit shape exists. Kept for the record: `/tmp/opencode/p11/f70_accessfilename.py`.

---

## 4. Verified-clean inventory (reviewed this pass, negative results)

- **F60 conjoin** — `bind_target_grant` / `restrict_with` (`server.rs:1390-1500`, `2231-2262`): the conjoin is tight; the unresolved F61–F66 shapes escape it *upstream* (§2.1), not through it.
- **F67 `[PT]`** (`rewrite.rs:586-650`) and **F68 filesystem-override state machine** (`rewrite.rs:803-936`): reviewed clean at HEAD; the `[L]`-last-wins semantics and per-round replacement are correct.
- **expr.rs regex depth bounds** — bounded, no stack-exhaustion shape found past the pre-existing cap.
- **auth.rs hash verification** (md5crypt / bcrypt / SHA / SSHA paths): all fail closed on malformed input.
- **h2.rs** pseudo-header handling and request-path translation allocation: no new issue in the ≤80%-coverage areas exercised.
- **Verified kernels** `handler_conjoin_admit`, `options_conjoin`: consistent with the conjoin intent.
- **Coverage gaps for a follow-up pass** (not exercised adversarially yet): `files.rs` 82%, `log.rs` 80%, `main.rs` 71% (CLI flag paths), `ocsp.rs` 78%, `h2.rs` 80%, `auth.rs` 91%.

---

## 5. Remediation guidance (ordered)

1. **Parse-time Location matching (F61-A/A2/B).** Compile `<Location>` arguments with the shell-glob semantics Apache uses, honour the `~` regex form, and keep boundary semantics (`"/admin/"` ≠ `/admin`). Sections whose pattern cannot be handled should **fail closed** (config error), not degrade into inert literal scopes.
2. **`[^...]` in glob matching (F62, F62b).** Fix the class-negation branch of `glob_match` so `<Directory>`/`<Files>` patterns compute node sets on at least the reference shapes; add the Apache "deny /zdir, allow /adir" oracle pair as a unit test.
3. **expr variables (F63, F63b).** Register `REQUEST_FILENAME` and `SCRIPT_FILENAME` in `expr::var()` with the *post-mapping filesystem target* value (Apache's definition), and fail the guard **closed** when the variable is unavailable in a given evaluation context, in both `<If>` and `RewriteCond expr`.
4. **Handler precedence (F64, F64b).** Store `SetHandler` in a separate precedence field (Apache semantics: SetHandler overrides every handler assignment in its scope, regardless of parse order and inheritance) and make the merge across `.htaccess` layers respect it. This kills the F64b upload chain — the specific fix is not the same as fixing F61–F63.
5. **ScriptAlias + `default-handler` (F65).** `cgi::is_cgi` must consult `Options::EXEC_CGI` and the effective handler *before* returning true for `script_alias`; a `default-handler` assignment in the tree must suppress execution (Apache's documented behaviour).
6. **Symlink handler identity (F69).** Match Apache: the handler classification for a request must be derived from the *request*-mapped filename (per the URL basename pipeline), not from the canonicalized target basename, unless the resolved target itself is a script alias by definition.
7. **Regression replays (currently missing).** `tests/adversarial_regressions.py` at HEAD contains **no replays for F61–F66/F69** (verified during this pass), which is why none of these shapes were caught by CI after pass 10. Add one replay per row of the table in §1 (F61-A, F61-A2, F61-B, F61-C, F62, F62b, F63, F63b, F64, F64b, F65, F69, and the F66 positive guard), asserting Apache-verdict-equivalence.

---

## 6. How to reproduce

```bash
cd /root/httpd-rs && cargo build --release        # no-op at d219efb once built
python3 /tmp/opencode/p11/exploit_p11.py 1 2 3 4 5 6 7 8 9 10 11 12 13
# or individually, e.g. the upload-RCE chain and its control:
python3 /tmp/opencode/p11/exploit_p11.py 11 13
```

Harness notes (for honesty about noise in individual rows): Debian's `/usr/sbin/apache2 -k start` shares a system pidfile and daemonized Apache rewrites its argv, so path-scoped cleanup misses it; a cron-restarted *system* Apache on this shared host occasionally interfered. The harness therefore runs Apache with `-DFOREGROUND`, bind-tests both ports before start, and retries each case once. Rows in §1 marked "clean" were re-run individually to a stable verdict; the others were confirmed in the earlier clean `-k start` battery at the same HEAD. Per-case dossier trees: `/tmp/opencode/p11/case01-F61-A/` … `case13-F61-C/`, each with the exact fixture, rendered configs (`apache.conf`, `vp.conf`) and server logs.
