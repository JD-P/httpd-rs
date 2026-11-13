# httpd-rs adversarial findings — Pass 8

**Target:** the current working tree at `HEAD 1f530df` (`Fix vulnerabilities,
expand Verus coverage and tests, still not ready`), rebuilt from source with
`cargo build --release -p httpd-rs`. The repository source was not modified for
this pass; every fixture lives under `/tmp/opencode/p8-*`.

**Environment:** Linux, loopback only. Apache 2.4.69 (Debian) was used as a
local differential oracle. No external network, real web server, or IP address
was involved.

**Status of this pass:** two new critical authorization bypasses were
reproduced end to end. The current tree's 366 Rust tests and 45 adversarial
replay tests all pass; neither suite covers the two shapes below.

* **F57 (Critical):** `%{REQUEST_URI}` is evaluated from the *raw* request
  target, including the query string, before percent-decoding and path
  canonicalization. A `Require expr`, `<If>`, `SetEnvIf Request_URI`, or
  `RewriteCond %{REQUEST_URI}` path policy can therefore be bypassed with a
  query suffix (`/.env?x=1`), percent-encoding (`/%2eenv`), or dot segments
  (`/api/../secret`). Apache returns `403`; httpd-rs returns the protected file.
* **F58 (Critical):** per-directory rewrite rules in an access file *above the
  alias mapping root* are silently skipped. This includes the ordinary
  `DocumentRoot/.htaccess` when a URL is served through an `Alias` whose target
  is inside the document root, and an ancestor `.htaccess` above
  `DocumentRoot`. A parent `.env` / `.git` / `wallet.dat` denylist is enforced
  by Apache and ignored by httpd-rs.

Both findings were reproduced with a wallet-shaped fixture: a `.env` containing
`WALLET_SEED=correct-horse-battery-staple` and a `wallet.dat` containing a
private balance/seed record. In both cases Apache returned `403` and httpd-rs
returned `200` with the secret body.

---

## Top exploit chains (wallet-shaped deployments)

### 1. F57 — one question mark defeats an expression-based `.env` deny

A deployment protects dotfiles with an expression in the main configuration or
in a directory scope:

```apache
<Location "/">
    Require expr "%{REQUEST_URI} !~ /\.env$/ && %{REQUEST_URI} !~ /wallet\.dat$/"
</Location>
```

Apache sees the normalized URI `/.env` or `/wallet.dat`, the expression is
false, and the request is denied. httpd-rs evaluates `%{REQUEST_URI}` from
`req.target` — the raw request line target, including the query string and
without decoding — so:

```text
GET /.env?x=1          -> raw expression sees "/.env?x=1", does not end in ".env"
GET /%2eenv            -> raw expression sees "/%2eenv", does not contain ".env"
GET /wallet%2edat?dl=1 -> raw expression sees "/wallet%2edat?dl=1"
```

All three are `403` from Apache and `200` from httpd-rs, with the `.env` or
`wallet.dat` body. The attacker only needs one request; no upload, local
account, race, or cache interaction is involved.

The same primitive defeats an allow-list gate:

```apache
<Directory "/srv/wallet/public">
    Require all denied
</Directory>
<If "%{REQUEST_URI} =~ /api/">
    Require all granted
</If>
```

`GET /api/../private/wallet.dat` is normalized by Apache to
`/private/wallet.dat` before the `<If>` runs, so the grant does not apply.
httpd-rs evaluates the raw target, sees `api`, grants access, then normalizes to
`/private/wallet.dat` and serves it.

### 2. F58 — the document-root `.htaccess` denylist is skipped for alias URLs

A normal application layout publishes an app through an alias whose target is
under the document root:

```apache
DocumentRoot "/srv/wallet/public"
<Directory "/srv/wallet/public">
    AllowOverride All
    Require all granted
</Directory>
Alias /wallet "/srv/wallet/public/current"

# /srv/wallet/public/.htaccess
RewriteEngine On
RewriteRule (^|/)\.(env|git)(/|$) - [F,L]
RewriteRule (^|/)wallet\.dat$ - [F,L]
```

Apache applies the document-root `.htaccess` to `/wallet/...` URLs as well,
using subject `wallet/current/.env`. httpd-rs reads the access file (a
`Header set X-Htaccess-Read yes` directive is applied) but computes the rewrite
base as `/wallet/.env/`, so `subject_for()` strips nothing and every
per-directory rewrite rule in that layer is skipped:

```text
GET /wallet/.env       -> Apache 403, httpd-rs 200 "WALLET-...-ENV"
GET /wallet/wallet.dat -> Apache 403, httpd-rs 200 "WALLET-...-DB"
```

The same failure occurs one level higher, with the `.htaccess` above
`DocumentRoot` and an ancestor `AllowOverride All`. That case is documented in
F50 as a supported access-file scenario; F58 shows that rewrite rules in that
layer never participate.

---

## Findings at a glance

| ID | Severity | Area | Demonstrated impact | Preconditions |
|---|---|---|---|---|
| F57 | Critical | expression/rewrite `%{REQUEST_URI}` identity | Path-based allow/deny expressions bypassed with `?`, `%XX`, or `..`; protected `.env` / `wallet.dat` disclosed | Any `Require expr`, `<If>`, `SetEnvIf Request_URI`, or `RewriteCond %{REQUEST_URI}` path policy |
| F58 | Critical | access-file rewrite base above mapping root | Parent/document-root `.htaccess` `[F]` denylist skipped; protected static files and CGI/application files exposed | `AllowOverride` enabled for a directory above the URL mapping root, alias target below it, per-directory rewrite deny |

---

# F57. Critical: `%{REQUEST_URI}` is the raw target, not the normalized decoded URL path

## Impact

httpd-rs exposes several different implementations of `%{REQUEST_URI}`:

```rust
// crates/server/src/expr.rs:269
"request_uri" => String::from_utf8_lossy(&ctx.req.target).into_owned(),

// crates/server/src/config.rs:1184 (SetEnvIf Request_URI)
"request_uri" | "request-uri" => {
    Some(String::from_utf8_lossy(&req.target).into_owned())
}

// crates/server/src/rewrite.rs:891 (RewriteCond %{REQUEST_URI})
"REQUEST_URI" => {
    let mut s = path.to_string();
    if !query.is_empty() {
        s.push('?');
        s.push_str(&String::from_utf8_lossy(query));
    }
    s
}
```

`Request::target` is the exact request-line target. For an HTTP/1.1 origin-form
request it still contains the query, percent escapes, dot segments, and
duplicate slashes. `Request::raw_path` is only the path bytes, also still
percent-encoded. The dispatcher later runs:

```rust
let decoded = percent_decode_path(raw_path, allow_encoded)?;
let norm = normalize_uri_path(&decoded)?;
let url_path = String::from_utf8_lossy(&norm).into_owned();
```

and authorizes/serves the canonical `url_path`. The expression engines are not
given that canonical value. They see a different string from the one used to
select the resource.

Apache's `%{REQUEST_URI}` is `r->uri`: the normalized request path, excluding
the query string. Apache's own ap_expr documentation is explicit that the query
is a separate variable. On a case-sensitive Linux build its `<FilesMatch>` /
`<DirectoryMatch>` regexes are case-sensitive, but `r->uri` is still
percent-decoded and canonicalized before authorization. The local differential
confirms this: `GET /api/%2e%2e/secret.json` is denied by an expression watching
for `api`, because Apache's expression sees `/secret.json`.

This is not a cosmetic logging difference. `Require expr`, `<If>`, and
`RewriteCond` are authorization inputs, and several are explicitly advertised
in the README and benchmarked in `bench/feature_bench.py`.

## Reproduction A: `.env` deny bypassed by a query string

Fixture:

```sh
D=/tmp/opencode/p8-expr2
rm -rf "$D"; mkdir -p "$D/www" "$D/logs"
printf 'WALLET_SEED=correct-horse-battery-staple\n' > "$D/www/.env"
printf 'WALLET-DB=secret\n'                         > "$D/www/wallet.dat"

# Apache and httpd-rs use the same security policy.
cat > "$D/apache.conf" <<EOF
ServerRoot "/etc/apache2"
LoadModule mpm_event_module  /usr/lib/apache2/modules/mod_mpm_event.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule authz_host_module /usr/lib/apache2/modules/mod_authz_host.so
LoadModule dir_module        /usr/lib/apache2/modules/mod_dir.so
LoadModule mime_module       /usr/lib/apache2/modules/mod_mime.so
ServerName localhost
Listen 127.0.0.1:19368
PidFile "$D/logs/apache.pid"
ErrorLog "$D/logs/apache-error.log"
TypesConfig /etc/mime.types
DocumentRoot "$D/www"
<Directory "$D/www">
    AllowOverride None
    Require all granted
</Directory>
<Location "/">
    Require expr "%{REQUEST_URI} !~ /\.env$/ && %{REQUEST_URI} !~ /wallet\.dat$/"
</Location>
EOF
```

Run Apache on `:19368` and httpd-rs on `:19369` with the same file (only the
listener, pid file and log change), then:

```text
GET /.env            -> Apache 403, httpd-rs 403       (control)
GET /.env?x=1        -> Apache 403, httpd-rs 200       WALLET_SEED=...
GET /wallet.dat?dl=1 -> Apache 403, httpd-rs 200       WALLET-DB=...
```

The query string is not part of the resource identity on the resolved path,
but it is enough to make the raw-target regex fail.

## Reproduction B: percent-encoded protected name

With the same fixture:

```text
GET /%2eenv          -> Apache 403, httpd-rs 200       WALLET_SEED=...
GET /wallet%2edat    -> Apache 403, httpd-rs 200       WALLET-DB=...
```

Apache decodes `%2e` before the expression; httpd-rs matches the undecoded
`%2eenv` / `wallet%2edat` spelling and lets dispatch decode it into the
protected file afterward. This bypass works even when the deny pattern is not
`$`-anchored and does not depend on the query string.

## Reproduction C: `<If>` allow-list bypassed with dot segments

```apache
<Directory "/tmp/opencode/p8-if/www">
    AllowOverride None
    Require all denied
</Directory>
<If "%{REQUEST_URI} =~ /api/">
    Require all granted
</If>
```

Fixture files: `/api/public.json` is public, `/secret.json` is the wallet
record.

```text
GET /api/public.json          -> Apache 200, httpd-rs 200
GET /api/../secret.json       -> Apache 403, httpd-rs 200  WALLET-IF-SECRET
GET /api/%2e%2e/secret.json   -> Apache 403, httpd-rs 200  WALLET-IF-SECRET
```

Apache normalizes the URI before evaluating `<If>`; httpd-rs sees `api` in the
raw target, grants the request, then normalizes to `/secret.json` and serves it.
`<If>` is applied last in httpd-rs's merge order, so this also bypasses a
base `Require all denied`.

## Reproduction D: `RewriteCond %{REQUEST_URI}` query-suffix bypass

```apache
# /tmp/opencode/p8-rewritecond/www/.htaccess
RewriteEngine On
RewriteCond %{REQUEST_URI} \.env$
RewriteRule ^ - [F,L]
```

With `.env` present:

```text
GET /.env       -> Apache 403, httpd-rs 403       (both deny)
GET /.env?x=1   -> Apache 403, httpd-rs 200       WALLET-RC-ENV
```

The rewrite implementation appends the query to the condition value. Apache's
`RewriteCond %{REQUEST_URI}` sees only the normalized path, so its condition
matches and the deny rule fires. The same pattern applies to
`SetEnvIf Request_URI` because it also reads `req.target` directly
(`crates/server/src/config.rs:1184`), which can flip `Require env` policies.

## Root cause

The dispatcher computes a trustworthy canonical `url_path` but does not pass it
into expression evaluation:

```rust
// crates/server/src/server.rs (dispatch_inner)
let decoded = percent_decode_path(raw_path, allow_encoded)?;
let norm = normalize_uri_path(&decoded)?;
let mut url_path = String::from_utf8_lossy(&norm).into_owned();
```

`expr::Context` only carries `req`, `env`, `peer` and `docroot`; it has no
canonical URL-path field. `var()` therefore falls back to `ctx.req.target`,
which includes raw query bytes and pre-decoding spelling. The rewrite
`variable_value()` implementation has the same query append at
`crates/server/src/rewrite.rs:891`, and `Scope::request_env()` uses
`req.target` for `SetEnvIf Request_URI`.

The verified request parser is not at fault. The parser intentionally preserves
the raw target and separates `raw_path`/`query`; the bug is that security
expressions consume the raw field instead of the dispatcher's canonical path.

## Remediation

1. Add a canonical, decoded, query-free URL path to the expression context.
   `Context::new()` should receive the dispatcher's `url_path` (and the current
   rewritten path where that is the relevant Apache equivalent), not derive it
   from `Request::target`.
2. Make `%{REQUEST_URI}` return that canonical path for every implementation:
   * `expr::var("REQUEST_URI")`,
   * `expr` function/expand forms,
   * `RewriteCond`/`RewriteRule` variable expansion,
   * `SetEnvIf Request_URI`.
3. Do not append `QUERY_STRING` to any `REQUEST_URI` value. Apache exposes it
   only as `%{QUERY_STRING}`.
4. For internal rewrites, decide and document whether `%{REQUEST_URI}` is the
   original URI or the current rewrite URI, matching Apache rather than the
   current mutable rewrite path.
5. Add differential regressions for at least:
   * `/.env?x=1`, `/%2eenv`, `/wallet%2edat`,
   * `/api/../secret`, `/api/%2e%2e/secret`,
   * the same cases inside `<If>`, `Require expr`, `RewriteCond`, and
     `SetEnvIf Request_URI`,
   * an allow-list where the expression must not match the normalized path,
   * a deny-list where the expression must match the normalized path.
6. If a future expression variable cannot be bound to the canonical path,
   fail the expression closed rather than falling back to request-line bytes.

## Model / regression updates

Add an invariant such as:

```text
I57 — request-URI identity
For every expression evaluation, %{REQUEST_URI} equals the canonical decoded
URL path selected by the dispatcher, with no query string, no percent escapes,
and no dot segments. Evaluating a path authorization expression on the raw
request target is a fail-open bug even when the resolver later canonicalizes
the filesystem target.
```

The existing `config_semantics.py` matrix covers `<If>` branch interaction but
not the URI variable's byte identity, so it did not exercise this class.
`tests/adversarial_regressions.py` should replay F57 against both Apache and
httpd-rs, not only against httpd-rs's expected status.

---

# F58. Critical: access-file rewrite rules above the alias mapping root are skipped

## Impact

F53 fixed the per-directory rewrite base for access files *inside* an alias
tree. It did not cover layers *above* the mapping root. The walk correctly
collects those layers (F50), but `dir_url_base()` derives their rule subject
from the requested URL's depth, while Apache uses the filesystem-relative path
from the access-file directory to the selected target.

The result is a total skip of per-directory rewrite rules in that layer. This
is a pure authorization bypass for `[F]`/`[G]` deny rules and can also skip
`[E]`, `[R]`, `[P]` and other effects. It does not affect top-level `Require`,
`<Files>`, or `Header` directives in the same access file, so an administrator
can see that the access file was read while the rewrite denylist does nothing.

## Reproduction A: alias target under `DocumentRoot`, standard `.htaccess`

This is the ordinary layout where `DocumentRoot` is the public web root and an
application is published below it with `Alias`:

```sh
D=/tmp/opencode/p8-docroot-alias
rm -rf "$D"; mkdir -p "$D/www/wallet/public" "$D/logs"
printf 'WALLET-DOCROOT-ALIAS-ENV\n' > "$D/www/wallet/public/.env"
printf 'WALLET-DOCROOT-ALIAS-DB\n'  > "$D/www/wallet/public/wallet.dat"

cat > "$D/www/.htaccess" <<'EOF'
RewriteEngine On
RewriteRule (^|/)\.(env|git)(/|$) - [F,L]
RewriteRule (^|/)wallet\.dat$ - [F,L]
Header set X-Htaccess-Read yes
EOF

# Apache config; httpd-rs uses the same body on a different loopback port.
cat > "$D/apache.conf" <<EOF
ServerRoot "/etc/apache2"
LoadModule mpm_event_module  /usr/lib/apache2/modules/mod_mpm_event.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule authz_host_module /usr/lib/apache2/modules/mod_authz_host.so
LoadModule alias_module      /usr/lib/apache2/modules/mod_alias.so
LoadModule rewrite_module    /usr/lib/apache2/modules/mod_rewrite.so
LoadModule headers_module    /usr/lib/apache2/modules/mod_headers.so
LoadModule dir_module        /usr/lib/apache2/modules/mod_dir.so
LoadModule mime_module       /usr/lib/apache2/modules/mod_mime.so
ServerName localhost
Listen 127.0.0.1:19372
PidFile "$D/logs/apache.pid"
ErrorLog "$D/logs/apache-error.log"
TypesConfig /etc/mime.types
DocumentRoot "$D/www"
<Directory "$D/www">
    AllowOverride All
    Require all granted
</Directory>
Alias /wallet "$D/www/wallet/public"
EOF
```

Observed:

```text
GET /wallet/.env       -> Apache 403, httpd-rs 200  WALLET-DOCROOT-ALIAS-ENV
GET /wallet/wallet.dat -> Apache 403, httpd-rs 200  WALLET-DOCROOT-ALIAS-DB
```

The httpd-rs response contains `X-Htaccess-Read: yes`, proving that
`/www/.htaccess` was loaded and its `Header` effect applied. Only the
per-directory rewrite subject was wrong.

## Reproduction B: `.htaccess` above `DocumentRoot`

This is the F50 ancestor-access-file scenario without an alias target below
the document root:

```text
D=/tmp/opencode/p8-ancestor
Alias /wallet "$D/storage/current/public"
# $D/storage/.htaccess:
# RewriteEngine On
# RewriteRule ^current/public/private/ - [F,L]

GET /wallet/private/wallet.dat -> Apache 403, httpd-rs 200 WALLET-ANCESTOR-SECRET
```

Apache's per-directory subject for `/storage/.htaccess` is
`current/public/private/wallet.dat`; httpd-rs's base calculation sees three
filesystem components but only two URL components and falls back to the full
URL path, after which `subject_for()` strips nothing.

A probe with one rule at a time against the document-root `.htaccess` in
Reproduction A confirmed Apache's subject is `wallet/public/.env` for the
request `/wallet/.env`:

```text
^wallet/public/\.env$ -> 403
^\.env$                -> 200
^wallet/\.env$         -> 200
^public/\.env$         -> 200
^wallet/public         -> 403
env$                   -> 403
```

httpd-rs never gets far enough to match any of them.

## Root cause

`collect_layers_with_root()` passes the alias mapping root to `dir_url_base()`:

```rust
// crates/server/src/htaccess.rs:675-714
fn dir_url_base(root: &Path, dir: &Path, fs_path: &Path, url_path: &str) -> String {
    let Some(rel) = fs_path.strip_prefix(dir).ok() else { /* ... */ };
    let depth = rel.components().count();
    let trimmed = url_path.trim_end_matches('/');
    // strip `depth` URL components ...
    if !httpd_rs_verified::htaccess_layer_url_base_admit(true, url_depth_sufficient) {
        return normalize_rewrite_base(url_path);
    }
    normalize_rewrite_base(&trimmed[..end])
}
```

For the document-root layer in Reproduction A:

```text
fs_path  = /www/wallet/public/.env
dir      = /www
rel      = wallet/public/.env          (depth 3)
url_path = /wallet/.env                (only 2 components)
fallback = /wallet/.env/               (normalize_rewrite_base(url_path))
subject_for(): "/wallet/.env".strip_prefix("/wallet/.env/") -> None
```

Every rule in the layer is therefore skipped. `subject_for()` is correct for
the layers F53 covered, but the layer base is not. For a directory above the
mapping root, Apache's per-directory rewrite subject is the filesystem-relative
path from that directory (`wallet/public/.env`), not the URL path minus a
prefix. The current code has no representation for that case, and its
"only sound upper bound" fallback is silently fail-open.

## Remediation

1. Distinguish a layer's **mapping state** from its **filesystem depth**:
   * layers at or below the URL mapping root keep the URL-mount base computed
     by the F53 fix;
   * layers above the mapping root must use the filesystem-relative subject
     Apache uses (the path of the selected target from the access-file
     directory), or must be evaluated with an explicit non-match/fail-closed
     policy if that subject cannot be represented.
2. Do not fall back to `normalize_rewrite_base(url_path)` when the URL has too
   few components. That base makes `subject_for()` return `None` for every
   rule. A missing subject is not "no rule matched"; for authorization rules
   it is an unenforced policy.
3. Pass both the requested mapping root and the access-file layer's filesystem
   root into the rewrite subject computation. In particular, for
   `dir` above `root`, compute the subject from `fs_path.strip_prefix(dir)`
   (Apache's behavior) and attach it to the parsed rules, rather than deriving
   a URL base from a URL depth that cannot describe it.
4. Add differential tests for:
   * `DocumentRoot/.htaccess` + `Alias` target under `DocumentRoot`,
   * `DocumentRoot/.htaccess` + `AliasMatch`/`ScriptAlias` target under it,
   * ancestor `.htaccess` above `DocumentRoot` with an outer
     `AllowOverride All`,
   * `[F]`, `[G]`, `[E]`, and `[R]` effects in those layers,
   * static files, directory indexes, CGI and FastCGI targets,
   * both `Alias` orders and an overlapping alias inside the same docroot.
5. Keep the F53 tests; add the parent-layer shapes separately, because the
   existing F53 fixtures only place `.htaccess` inside the alias target tree.

## Model / regression updates

Add an invariant such as:

```text
I58 — access-file rewrite subject above the mapping root
For an access-file layer D above the URL mapping root R, the per-directory
rewrite subject is the requested target path relative to D (Apache's
r->filename-relative subject), not the URL path with components stripped by
filesystem depth. If no sound subject can be constructed, the layer's rewrite
deny/authorization policy must fail closed rather than silently not matching.

subject_for(rule, request) must never be None for a well-formed access-file
layer merely because the alias target is deeper than the URL mount.
```

Extend the verification ledger's path-target-bound sinks and
`tests/adversarial_regressions.py` with the F58 shapes. The current F53 tests
verify only the alias-root case and therefore pass while the document-root
layer remains bypassed.

---

# Cross-cutting observations

* **F57 is independent of filesystem mapping.** It is visible in the main
  configuration's `<Location>` + `Require expr`, so it does not need
  `AllowOverride`, `.htaccess`, an alias, or a cache entry.
* **F58 is a layer identity bug, not a cache bug.** The access-file walk reads
  the file; its top-level `Header` effect is visible. The failure is entirely
  in the per-directory rewrite subject.
* **Both bugs can expose the same wallet files** (`.env`, `wallet.dat`) with a
  single unauthenticated GET, but through different surfaces. F57 is an
  expression-identity bypass; F58 is an access-file-layer-base bypass.
* The verified kernels are not bypassed. The raw/decoded and URL/filesystem
  identities are wrong in the runtime adapters before those kernels are
  called.
* `SetEnvIf Request_URI` should be treated as the same class as F57 until it
  is bound to the canonical path: it reads `req.target` at
  `crates/server/src/config.rs:1184`, including query and percent escapes.

---

# Reproduction notes

* All fixtures are under `/tmp/opencode/p8-*`; repository source was not
  edited.
* `target/release/httpd-rs` was rebuilt from the current working tree
  (`cargo build --release -p httpd-rs`) before the pass.
* Apache 2.4.69 was started with private loopback configs and only the modules
  needed for `Alias`, `mod_rewrite`, `mod_headers`, `mod_authz_core`,
  `mod_authz_host`, `mod_dir`, and `mod_mime`.
* Requests that needed raw dot segments or percent escapes were sent with
  `curl --path-as-is`.
* The Apache differential used the same `DocumentRoot`, `Directory`, `Alias`,
  `.htaccess`, authentication policy, and body files as httpd-rs; only the
  listener ports, pid files and log paths differed.
