# httpd-rs adversarial findings — Pass 6

**Target:** `HEAD 9a7809c` plus the uncommitted pass-5 fixes in the checkout
(the tree used by `target/release/httpd-rs`, rebuilt from the current working
tree). The repository source was not modified for this pass; all fixtures were
created under `/tmp/opencode`.

**Environment:** Linux, loopback only. Apache 2.4.69 (Debian) was used as the
differential oracle. No external network, IP address, or real web server was
involved.

**Status of this pass:** three new issues were reproduced end to end. F50 and
F51 are authorization bypasses: an Apache-valid `.htaccess` policy is silently
ignored and the protected file is served. F51 also executes a protected CGI.
F52 is a cache-target mismatch with two demonstrated consequences, including a
cross-query representation leak and a cached index that survives a new
`<Files>` denial.

---

## Top exploit chains (wallet-shaped deployments)

1. **F50 — `.htaccess` above the document root is ignored.** A very common
   deployment layout puts the application root above `public/` and enables
   `AllowOverride` at the application root:

   ```apache
   DocumentRoot /srv/wallet/public
   <Directory /srv/wallet>
       AllowOverride All
   </Directory>
   ```

   The administrator protects `/srv/wallet/.htaccess` with Basic auth (or
   `Require all denied`). Apache applies it. httpd-rs starts its access-file
   walk at `/srv/wallet/public` and never reads the parent policy. An
   unauthenticated client requests `/wallet.dat` and receives the wallet
   bytes.

2. **F51 — overlapping aliases select the wrong access-file root.** A normal
   static-asset setup has a short alias into a subdirectory and a broader
   alias for the whole tree:

   ```apache
   Alias /assets /srv/site/assets
   Alias /site   /srv/site
   ```

   `.htaccess` in `/srv/site` protects the tree. A request for
   `/site/assets/wallet.dat` maps through the *second* alias, but
   `access_root_for()` sees that `/srv/site/assets` is an earlier alias target
   and starts the walk there. The `/srv/site/.htaccess` policy is skipped.
   Reordering the two aliases makes httpd-rs return `403`, proving the root is
   chosen from the wrong alias. The same bug executes a protected
   `ScriptAlias` CGI.

3. **F52 — the cache is bound to the directory URL, not the selected
   DirectoryIndex target.** With `CacheEnable`, a `DirectoryIndex` script's
   query-specific response is shared across queries when
   `CacheIgnoreQueryString On`. A second variant serves a cached index after
   a live `.htaccess` change adds `<Files "index.html"> Require all denied`;
   Apache rejects both the directory URL and the direct index URL, while
   httpd-rs returns the cached `200` with `X-Cache: HIT`.

---

## Findings at a glance

| ID | Severity | Area | Demonstrated impact | Preconditions |
|---|---|---|---|---|
| F50 | Critical | `.htaccess` ancestor walk | Unauthenticated read of a Basic-auth-protected / `Require all denied` file | `AllowOverride` enabled on an ancestor of `DocumentRoot` with an `.htaccess` there |
| F51 | Critical | Alias access root | Same bypass; protected CGI execution in the ScriptAlias variant | Two aliases whose targets overlap, with the narrower target configured first |
| F52 | High | Cache target / DirectoryIndex | Cross-query representation leak; cached index survives a new `<Files>` deny | Cache enabled and a `DirectoryIndex` target; query variant needs `CacheIgnoreQueryString On`, stale variant needs a live `.htaccess` change |

---

# F50. Critical: the access-file walk stops at DocumentRoot/alias base and ignores an ancestor `.htaccess` that Apache enforces

## Impact

`access_root_for()` returns `DocumentRoot` for every document-root target and
an alias target directory for alias targets. `collect_layers()` then drops
every directory that is not `starts_with(root)`:

```rust
// crates/server/src/htaccess.rs:243-245
let docroot = cfg.documentation_root_for(vhost);
if fs_path == docroot || fs_path.starts_with(&docroot) {
    return docroot;
}
```

```rust
// crates/server/src/htaccess.rs:309-311
for dir in dirs {
    if !dir.is_dir() || !dir.starts_with(&root) {
        continue;
    }
```

Apache does not use `DocumentRoot` as the start of the `.htaccess` search.
For a request whose resolved filename is `/srv/wallet/public/wallet.dat`,
Apache walks the filesystem ancestors and, at each directory where
`AllowOverride` permits it, examines `.htaccess`. This includes
`/srv/wallet` and above. The configuration below is valid (`apache2 -t` says
`Syntax OK`) and Apache enforces the parent policy; httpd-rs serves the file.

This is a pure authorization bypass: no symlink, writable directory, proxy, or
second bug is needed. It applies at least to static files, directory indexes
and CGI targets under the document root, and to both the dispatcher and the
cache authorization path because they share `collect_layers()`.

## Reproduction: Basic auth above DocumentRoot

```sh
D=/tmp/opencode/p6-docparent-auth
rm -rf "$D"; mkdir -p "$D/app/public" "$D/logs" "$D/run"
printf 'WALLET-DOCPARENT-AUTH-SECRET\n' > "$D/app/public/wallet.dat"
printf 'alice:%s\n' "$(htpasswd -nbm alice secret | cut -d: -f2-)" > "$D/htpasswd"

cat > "$D/app/.htaccess" <<EOF
AuthType Basic
AuthName "wallet"
AuthUserFile "$D/htpasswd"
Require valid-user
EOF

cat > "$D/vp.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19278
ServerName localhost
DocumentRoot "$D/app/public"
<Directory "$D/app">
  AllowOverride All
</Directory>
EOF
```

The Apache configuration is the same, with `mod_authz_core`, `mod_authz_host`,
`mod_auth_basic`, `mod_authn_core`, `mod_authn_file`, `mod_authz_user` and
`mod_mpm_event` loaded.

Observed:

```text
Apache, no credentials: 401 Unauthorized
httpd-rs, no credentials: 200 OK
WALLET-DOCPARENT-AUTH-SECRET

Apache, alice:secret:    200 OK
httpd-rs, alice:secret:   200 OK
```

The equivalent `Require all denied` form produces `403` from Apache and
`200` from httpd-rs. The same result is obtained with
`<Directory /> AllowOverride All` and an `.htaccess` in an ancestor.

`--explain` confirms that the policy file is not considered at all:

```text
explain: GET /wallet.dat
  fs_path: /tmp/opencode/p6-docparent1/app/public/wallet.dat
  override_policy: OverridePolicy { mode: Some(All), ... }
  override_enabled: true
  override_prefilter: true
  access_file_trace:
    no access files present in override-enabled path
  htaccess: no access files present
```

`$D/app/.htaccess` exists and is readable; the trace is wrong because the walk
is truncated at `$D/app/public`.

## Variant: alias target below its own ancestor `.htaccess`

```apache
Alias "/site" "$D/srv/site"
<Directory "$D/srv">
    AllowOverride All
</Directory>
```

With `$D/srv/.htaccess` containing `Require all denied` and
`$D/srv/site/assets/wallet.dat` existing, Apache returns `403` and httpd-rs
returns `200 WALLET-PARENTHT-SECRET` for `/site/assets/wallet.dat`.

## Root cause

* `crates/server/src/htaccess.rs:237-273` — `access_root_for()` implements the
  walk bound as `DocumentRoot`/alias root.
* `crates/server/src/htaccess.rs:288-311` — `collect_layers()` filters every
  directory by `starts_with(&root)` before considering `AllowOverride`.
* `crates/server/src/htaccess.rs:117,162` — the older `apply_req_deferred()`
  has the same filter.
* `crates/server/src/htaccess.rs:387,409` — `trace_access_files()` has the same
  filter and therefore hides the problem in `--explain`.

Apache's actual rule is directory-based: an `.htaccess` in an ancestor is
effective when `AllowOverride` is enabled for that ancestor. The main-config
`<Directory>` rule for the ancestor *is* applied by httpd-rs; only the contents
of that ancestor's `.htaccess` are discarded.

The restriction is explicit in the project model: `docs/config-semantics.md`
I21 says `access_walk_root = target.alias_root`, and I36 says the walk "stops
at and includes the target directory". That model boundary is the
vulnerability. If it is retained as a trust boundary, httpd-rs cannot claim
Apache compatibility for `.htaccess`; it would have to reject or warn about
applicable ancestor access files (and ensure directories above the boundary are
not attacker-writable) rather than silently ignore them.

## Remediation

1. Do not use `DocumentRoot`, an alias target, or any other policy boundary as
   the lower bound of the `.htaccess` walk. Walk every ancestor of the resolved
   target and decide participation per directory from
   `effective_scope_cached(...).override_policy`.
2. If a walk cost bound is needed, use the highest ancestor for which the
   compiled configuration enables `AllowOverride` (or the filesystem root),
   not `DocumentRoot`.
3. If the project intentionally refuses to read `.htaccess` above a boundary,
   detect such files at configuration time and fail closed (or document the
   divergence); silently serving content that Apache denies is not safe. The
   repository currently claims Apache-compatible `.htaccess` behavior.
4. Pass the actual URL-mapping root from `map_path()` to the access walk for
   `dir_url_base()`/rewrite-base calculation, but keep the ancestor walk
   independent of it. The alias root is a URL/base label, not an authorization
   boundary.
5. Add regression tests for:
   * `DocumentRoot /app/public` with Basic auth/deny in `/app/.htaccess`;
   * `<Directory /> AllowOverride All` with an ancestor `.htaccess`;
   * an `Alias` target whose parent `.htaccess` requires auth;
   * static, CGI and directory-index targets, plus the cache lookup path.

---

# F51. Critical: overlapping aliases choose the wrong access-file root

## Impact

`access_root_for()` does not know which alias actually mapped the request. It
reconstructs that choice from filesystem containment, taking the first alias in
configuration order whose target contains the resolved path:

```rust
// crates/server/src/htaccess.rs:248-255
for alias in &base.mapping_policy.aliases {
    if alias.fs_path.as_os_str().is_empty() {
        continue;
    }
    if fs_path == alias.fs_path || fs_path.starts_with(&alias.fs_path) {
        ...
        return alias.fs_path.clone();
    }
}
```

The comment immediately above the loop is false: the first alias whose
*target* contains a path is not necessarily the alias whose *URL* matched.
`map_path()` chooses by URL prefix/regex and returns the mapping root, but that
root is not passed to the access-file walk. When an earlier alias target is a
descendant of the later alias target that actually mapped the request, the walk
starts too deep and skips the real alias root's `.htaccess`.

This also contradicts the model's I21 `target.alias_root` identity: the model
implicitly assumes the alias root is unique, but this implementation can select
a different alias's root for the same mapped path.

This is independent of F50: even if the walk were correctly bounded at the
actual alias root, it is bounded at the wrong root. It affects any alias kind
(prefix `Alias`, `ScriptAlias`, `AliasMatch`, `ScriptAliasMatch`). A single-file
alias can do it for that exact file: an earlier
`Alias /logo /srv/site/static/logo.png` makes `/srv/site/static` the walk root
for `/site/static/logo.png` mapped through a later broad `/site -> /srv/site`
alias, skipping `/srv/site/.htaccess` for that request.

## Reproduction A: unauth read through an overlapping alias

```sh
D=/tmp/opencode/p6-aliasroot-auth
rm -rf "$D"; mkdir -p "$D/www" "$D/site/assets" "$D/logs" "$D/run"
printf 'WALLET-AUTH-SECRET\n' > "$D/site/assets/wallet.dat"
printf 'alice:%s\n' "$(htpasswd -nbm alice secret | cut -d: -f2-)" > "$D/htpasswd"

cat > "$D/site/.htaccess" <<EOF
AuthType Basic
AuthName "wallet"
AuthUserFile "$D/htpasswd"
Require valid-user
EOF

cat > "$D/vp.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19270
ServerName localhost
DocumentRoot "$D/www"
<Directory "$D/site">
  AllowOverride All
</Directory>
Alias "/assets" "$D/site/assets"   # earlier; target is a subdirectory
Alias "/site"   "$D/site"          # later; this is the alias that maps /site/...
EOF
```

The Apache configuration uses the same aliases and `.htaccess`, with
`mod_authz_core`, `mod_authz_host`, `mod_auth_basic`, `mod_authn_core`,
`mod_authn_file`, `mod_authz_user` and `mod_mpm_event` loaded. Both
configurations pass their respective syntax checks.

Observed:

```text
Apache, no credentials: 401 Unauthorized
httpd-rs, no credentials: 200 OK
WALLET-AUTH-SECRET

Apache, alice:secret:    200 OK
httpd-rs, alice:secret:   200 OK
```

The request is `GET /site/assets/wallet.dat`. It matches only the second
alias's URL. `access_root_for()` nevertheless picks `/site/assets` because
that earlier alias target is a prefix of the mapped path, and the walk root is
inside the tree; `/site/.htaccess` is never read.

## Proof of causality: reorder the aliases

With the same two aliases swapped:

```apache
Alias "/site"   "$D/site"
Alias "/assets" "$D/site/assets"
```

httpd-rs now returns `403` for the same request. The mapped file and policy are
identical; only the alias order changed, so the wrong-root selection is the
cause.

## Reproduction B: protected CGI execution

```sh
D=/tmp/opencode/p6-aliasroot-cgi
rm -rf "$D"; mkdir -p "$D/www" "$D/site/cgi" "$D/logs" "$D/run"
cat > "$D/site/cgi/run.cgi" <<'EOF'
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf 'WALLET-CGI-SECRET\n'
EOF
chmod 755 "$D/site/cgi/run.cgi"
printf 'Require all denied\n' > "$D/site/.htaccess"

cat > "$D/vp.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19272
ServerName localhost
DocumentRoot "$D/www"
<Directory "$D/site">
  AllowOverride All
</Directory>
ScriptAlias "/cgia" "$D/site/cgi"
ScriptAlias "/site"  "$D/site"
EOF
```

Observed for `GET /site/cgi/run.cgi`:

```text
Apache: 403 Forbidden
httpd-rs: 200 OK
WALLET-CGI-SECRET
```

This is execution of a CGI that the administrator explicitly denied in its
own directory, not merely source disclosure. An `AliasMatch` configured
before a broader `Alias` produces the same bypass:

```apache
AliasMatch "^/assets/(.*)$" "$D/site/assets/$1"
Alias      "/site"          "$D/site"
```

## Root cause

* `crates/server/src/server.rs:2843-2910` — `map_path()` maps by URL prefix
  or regex and returns the actual mapping root. The root is used for the file
  mapping but is not carried into `collect_layers()`.
* `crates/server/src/htaccess.rs:248-270` — `access_root_for()` independently
  re-derives a root from alias `fs_path` containment and configuration order.
  This only works if alias URL order and alias target containment are
  consistent, which is not guaranteed.
* `crates/server/src/htaccess.rs:310` — the walk drops every directory outside
  the incorrectly chosen root.

## Remediation

1. Pass the actual mapping root (or, better, the full ordered mapping record)
   from `map_path()`/`evaluate_scope_for_path()` into `collect_layers()` and
   `apply_req_deferred()`. Do not reconstruct it from the alias table.
2. If the walk must remain alias-bounded, use the alias selected by the URL
   mapping, never the first alias whose target happens to contain the path.
3. Still implement F50: the walk should include ancestor `.htaccess` files that
   Apache reads. The actual alias root is needed for `dir_url_base()` and
   rewrite-base computation, not as a hard authorization boundary.
4. Add a regression with overlapping alias targets in both orders, using
   `Alias`, `ScriptAlias` and `AliasMatch`, and assert that the parent
   `.htaccess` is read in all forms.

---

# F52. High: cache lookup/store is bound to the directory URL, not the DirectoryIndex target

## Impact

`cache::request_scope()` builds the cache context for the URL-mapped target.
For a directory URL such as `/dir/`, that target is the directory itself. Later,
`dispatch_inner()` selects a `DirectoryIndex` file (possibly a CGI/FastCGI
script) and performs an internal subrequest:

```rust
// crates/server/src/server.rs:2656-2664
if let Some(name) = directory_index_name(...) {
    let index_url = format!("{}/{}", auth_url.trim_end_matches('/'), ...);
    return internal_dispatch(cfg, req, &index_url, peer, local_ip, local_port);
}
```

The resulting response is stored by the outer dispatcher under the **directory**
cache key. The cache grant and policy fingerprint describe the directory, not
the selected index. Two security consequences were reproduced.

### F52-A: `CacheIgnoreQueryString On` shares a CGI index response across queries

With cache enabled, `CacheIgnoreQueryString On` and a dynamic `DirectoryIndex`
script, the dynamic-target precheck in `request_scope()` examines only the
mapped directory name:

```rust
// crates/server/src/cache.rs:335-347
if cfg.cache.ignore_query_string && !req.query.is_empty() {
    let name = fs_path.file_name().map(...).unwrap_or(b"");
    let dynamic = script_alias
        || crate::cgi::is_cgi(cfg, &scope, name, false)
        || crate::fastcgi::match_proxy(...).is_some()
        || crate::proxy::matches_route(...);
    if dynamic { return None; }
}
```

For `/dir/`, `name` is `dir`, not `index.cgi`; `dynamic` is false. The cache
key then drops the query (`cache.rs:525-529`), and the internal script
response is shared between different query strings.

Reproduction:

```sh
D=/tmp/opencode/p6-cacheqs2
rm -rf "$D"; mkdir -p "$D/www/dir" "$D/cache"
cat > "$D/www/dir/index.cgi" <<'EOF'
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf 'SECRET-FOR-%s\n' "$QUERY_STRING"
EOF
chmod 755 "$D/www/dir/index.cgi"

cat > "$D/vp.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19294
ServerName localhost
DocumentRoot "$D/www"
<Directory "$D/www">
  Options +ExecCGI
  AllowOverride None
  AddHandler cgi-script .cgi
  DirectoryIndex index.cgi
  CacheEnable disk /
  CacheRoot "$D/cache"
  CacheIgnoreQueryString On
  CacheIgnoreNoLastMod On
  CacheDefaultExpire 3600
  CacheMaxExpire 3600
  CacheHeader On
</Directory>
EOF
```

Observed:

```text
GET /dir/?token=alpha  -> X-Cache: MISS, SECRET-FOR-token=alpha
GET /dir/?token=beta   -> X-Cache: HIT,  SECRET-FOR-token=alpha
GET /dir/?token=gamma  -> X-Cache: HIT,  SECRET-FOR-token=alpha
```

The control without `CacheIgnoreQueryString On` returns `MISS` and the correct
`beta`/`gamma` bodies, confirming the query is the collided dimension. This is
a cross-query representation leak and a cache-poisoning primitive: a victim's
query-specific representation can be served to a later request for a different
query.

### F52-B: a cached `DirectoryIndex` survives a live `.htaccess` `<Files>` deny

With cache enabled (no `CacheIgnoreQueryString` needed), a static index is
cached under `/dir/`. Later, `.htaccess` adds:

```apache
<Files "index.html">
    Require all denied
</Files>
```

The directory cache context does not include the `<Files>` rule: the rule only
matches the selected index filename. The same directory scope, target and
policy fingerprint are recomputed on the next lookup, so the old entry is a
HIT. Apache re-runs authorization for the resolved index and returns `403`.

Reproduction:

```sh
D=/tmp/opencode/p6-cache-ht2
rm -rf "$D"; mkdir -p "$D/www/dir" "$D/cache"
printf 'WALLET-CACHED-INDEX\n' > "$D/www/dir/index.html"
printf '# initially no deny\n' > "$D/www/dir/.htaccess"

cat > "$D/vp.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19296
ServerName localhost
DocumentRoot "$D/www"
CacheRoot "$D/cache"
CacheEnable disk /
CacheDefaultExpire 3600
CacheMaxExpire 3600
CacheHeader On
<Directory "$D/www">
  AllowOverride All
</Directory>
EOF
```

Apache uses the same `DocumentRoot`, index and `.htaccess`, with
`mod_cache`/`mod_cache_disk`, `CacheRoot`, `CacheEnable disk /` and
`CacheHeader On`.

Observed:

```text
GET /dir/ before deny:  200, X-Cache: MISS, WALLET-CACHED-INDEX
add the <Files "index.html"> Require all denied rule to /dir/.htaccess
GET /dir/ after deny:   200, X-Cache: HIT,  WALLET-CACHED-INDEX
GET /dir/index.html:     403 Forbidden
```

Apache 2.4.69 with `mod_cache`/`mod_cache_disk` and the same `DirectoryIndex`
and `.htaccess` change returns `403` for both `/dir/` and `/dir/index.html`;
the cached directory response is not used to bypass the newly effective
authorization rule.

## Root cause

* `crates/server/src/cache.rs:211-388` — `request_scope()` resolves the
  URL-mapped path; for a directory URL this is the directory, not the
  `DirectoryIndex` target.
* `crates/server/src/cache.rs:331-347` — the dynamic-target check uses
  `fs_path.file_name()` and therefore misses `DirectoryIndex` CGI/FastCGI
  scripts.
* `crates/server/src/cache.rs:525-529` — `base_key()` blanks the query when
  `CacheIgnoreQueryString` is enabled.
* `crates/server/src/server.rs:1220-1270` — the outer dispatcher stores the
  internal DirectoryIndex response under the directory's cache key.
* `crates/server/src/cache.rs:606-628,739-746,1150-1157` — the cache policy
  fingerprint and grant cover the directory scope, not the selected index's
  `<Files>`/`<Location>` policy. The internal dispatch reauthorizes the index
  on a miss, but a cache hit bypasses it.

## Remediation

1. Resolve `DirectoryIndex` (and any other internal subrequest target) before
   the cache decision. Bind the cache key and policy fingerprint to the actual
   selected file/script, its inode/backend target, and its full policy scope.
2. Never share a `DirectoryIndex` CGI/FastCGI/proxy representation across
   queries. `CacheIgnoreQueryString` must not apply to dynamic targets; the
   dynamic check must run after index/script resolution.
3. On every cache hit, either re-run authorization for the resolved
   `DirectoryIndex` target or make that target's policy part of the immutable
   cache entry key/fingerprint. Do not rely only on the directory URL's scope.
4. Invalidate entries when an access file that can affect the selected index
   changes. For F52-B, a content/mtime hash of `.htaccess` in the directory
   (and its ancestors per F50) should participate in the fingerprint.
5. Add regressions:
   * `CacheIgnoreQueryString On` + `DirectoryIndex index.cgi`: alpha/beta/gamma
     must not share a cache entry;
   * cache + `DirectoryIndex index.html` + live `.htaccess`
     `<Files "index.html"> Require all denied`: both the directory URL and the
     direct index URL must return `403`;
   * Apache differential for both with `mod_cache`/`mod_cache_disk`.

---

# Model / regression updates

The pass-5 ledger's access-plan and cache obligations should be extended:

* **I47 `access_walk_domain`:** the `.htaccess` walk domain is every ancestor
  of the resolved target for which the effective `AllowOverride` policy
  permits an access file. `DocumentRoot`/alias root is not a lower bound.
* **I48 `alias_mapping_root`:** the alias root used by a request is the root of
  the alias selected by URL mapping, never a root inferred from filesystem
  containment of an arbitrary alias target.
* **I49 `directory_index_cache_target`:** a cache entry produced by
  `DirectoryIndex` is keyed and authorized against the selected index/script
  (plus its query when the handler is dynamic), not only the directory URL.
* Add F50/F51/F52 shapes to the adversarial replay budget and to
  `config_semantics.py`/`adversarial_regressions.py`. The current corpus has
  parent `.htaccess` cases inside an alias tree and a single positive
  `RequireNone` child, but no ancestor-of-docroot policy, no overlapping alias
  targets, and no `DirectoryIndex` cache-target case.

# Notes and non-promoted review targets

* The root cause of F50 and F51 is shared: a policy boundary is being used as a
  filesystem-walk boundary. Fixing only the alias lookup in F51 would leave
  F50 (and vice versa).
* `trace_access_files()` and `--explain` have the same filter and report
  "no access files present" for F50 even when the file exists. This is a
  diagnostics bug that makes the bypass harder to notice, not a separate
  security issue.
* The pass-5 note about `CacheIgnoreQueryString` and a CGI `DirectoryIndex`
  was not reproduced in that pass; it is promoted here as F52-A with a
  concrete `X-Cache: HIT` PoC.
* F52-B is related to F24 (disk cache surviving a new `<Files>` deny), but the
  trigger here is a live `.htaccess` change without a reload. F24's reload
  epoch does not help because no reload occurs; the policy fingerprint still
  describes the directory, not the index.
* The verified request-head, URI canonicalization and range kernels did not
  need to be bypassed for any of these findings; they are all semantic
  authorization/cache-target bugs above the verified layer.
