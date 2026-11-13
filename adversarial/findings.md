# httpd-rs adversarial findings

**Target:** `HEAD 24e226d` plus the uncommitted hardening changes in the working tree, release build `target/release/httpd-rs`. Repository source was not modified for this pass. All tests are loopback-only.

---

# Pass 3 — alias-base escape and follow-on review

**Status of this pass:** F31, F36 and F38 were reproduced against the current
release binary. F32–F35 and F37 are observations and defence-in-depth
hypotheses; they are retained as review targets but were not all reproduced
end-to-end.

## F31. Critical: regex alias fallback re-roots a target outside the configured alias base

### Impact

`map_path()` in `crates/server/src/server.rs` computes a stable alias base (`a.fs_path`) for every regex alias. If the expanded replacement starts with the base, the request is served relative to that base. If the expanded replacement does **not** start with the base, the function does not reject the mapping: it falls back to `target.parent()` as the new root and `target.file_name()` as the relative path. A capture-only or leading-capture `AliasMatch`/`ScriptAliasMatch` can therefore resolve to an absolute path outside the configured base and still be served.

The authorization walk is also rooted at the intended alias base (the part of the replacement before the first `$`), so `<Directory>`/`<Files>`/`.htaccess` policy attached to that base is not applied to the fallback target. This is a mapping-boundary bypass, not a raw `../` traversal: the verified URI canonicalizer rejects dot-segment and encoded-separator attempts before `map_path()` runs.

### Reproduction

Files:

```text
/tmp/opencode/aliastest/www/          # DocumentRoot
/tmp/opencode/aliastest/secret.txt    # WALLET-ALIAS-SECRET
```

Configuration:

```apache
Listen 127.0.0.1:18099
ServerName localhost
DocumentRoot "/tmp/opencode/aliastest/www"
AliasMatch "^/static(.*)$" "$1"
```

Requests against the current release binary:

```text
GET /static/tmp/opencode/aliastest/secret.txt    -> 200 WALLET-ALIAS-SECRET
GET /static//tmp/opencode/aliastest/secret.txt   -> 200 WALLET-ALIAS-SECRET
GET /static/..%2ftmp%2f.../secret.txt            -> 404
GET /static/%2ftmp%2f.../secret.txt              -> 404
```

The encoded forms are stopped by `percent_decode_path`/`normalize_uri_path`. The unencoded forms succeed because the regex capture begins with `/`, making the replacement an absolute path; the fallback then serves it from its real parent directory. The earlier `/files/..%2f..%2f...` shape described in the first draft is **not** reproducible against this build; normalization resolves the dot segments before alias matching.

### Root cause

```rust
let target = clean_alias_path(&target);
if !a.fs_path.as_os_str().is_empty() && target.starts_with(&a.fs_path) {
    ...
    return (a.fs_path.clone(), rel, a.script);
}
// fallback: target.parent() becomes the new root
let root = target.parent().map(Path::to_path_buf)
    .unwrap_or_else(|| PathBuf::from("/"));
let rel = PathBuf::from(target.file_name()...);
return (root, rel, a.script);
```

The invariant `resolved_target ∈ a.fs_path` is checked only on the successful branch. The fallback is an escape hatch that converts a failed containment check into a valid request for a different root. The fallback also conflicts with the documented `ResolvedTarget`/`alias_root` model and with the `openat2` containment guarantee, because containment is enforced relative to the new root, not the configured alias base.

### Remediation

Remove the fallback for regex aliases. When `target` does not start with the configured base, return a mapping failure (404/403) rather than a parent-rooted target. Change `map_path()` to return `Option<(PathBuf, PathBuf, bool)>` or an explicit error and update the dispatch, WebSocket, cache and unit-test call sites. Add regression cases for capture-only/leading-capture aliases and for absolute replacements outside the alias base, plus an authorization test where the alias base is denied by `<Directory>` but the fallback target would be served.

---

## F32. High: internal-rewrite filesystem targets are admitted outside the document root under `UnsafePrefixStat`

### Impact

The rewrite admission predicate in `crates/verified/src/lib.rs` is:

```rust
pub fn rewrite_filesystem_admit(
    is_file: bool,
    under_docroot: bool,
    under_server_root: bool,
    unsafe_prefix_stat: bool,
) -> bool {
    is_file && (under_docroot || (unsafe_prefix_stat && under_server_root))
}
```

With the default `UnsafePrefixStat` off, an absolute rewrite target is only admitted when it is under the document root. With `UnsafePrefixStat` explicitly enabled on a rule, an absolute target under `ServerRoot` is also admitted. The dispatcher then re-roots the request at `filesystem.parent()`:

```rust
if let Some(filesystem) = rewrite_filesystem {
    root = filesystem.parent().map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));
    rel = PathBuf::from(filesystem.file_name()...);
    ...
}
```

So an absolute target under `ServerRoot` but outside `DocumentRoot` is served from a new virtual root equal to its parent directory. `ServerRoot` is commonly a configuration directory (`/etc/apache2`) or the application tree, so a rewrite that can name a file there reads configuration, keys or source outside the document root. This is a deliberate opt-in escape (`UnsafePrefixStat` exists for this reason), but the fallback makes the escape invisible to `<Directory>`/`<Files>`/`.htaccess` policy attached to the real document root and is not called out as an authorization change in the directive docs. It is also the internal-rewrite analogue of F31 for the `UnsafePrefixStat` case.

### Reproduction

Configuration sketch:

```apache
Listen 127.0.0.1:18100
ServerRoot "/tmp/opencode/rewrite-root"
DocumentRoot "/tmp/opencode/rewrite-root/www"
RewriteEngine On
RewriteRule "^/escape/(.*)$" "/tmp/opencode/rewrite-root/$1" [PT,UnsafePrefixStat]
```

A request for `/escape/secret.txt` causes the rewritten target `/tmp/opencode/rewrite-root/secret.txt` to be split into `root=/tmp/opencode/rewrite-root` and `rel=secret.txt`. The intended document root is `/tmp/opencode/rewrite-root/www`, so the file outside it is served. Without `UnsafePrefixStat` the same request should be rejected; the finding is that the opt-in changes the authorization base as well as the stat target.

### Root cause

The fallback treats "the rewrite named a file" as "the rewrite named a document root." `rewrite_filesystem_admit` enforces the intended base at admission time, but the dispatcher's parent-root fallback then changes the base used for authorization and serving. The policy re-evaluation walks from the new parent root, not from the original root.

### Remediation

Require `filesystem` to remain beneath the original document root/alias base even when `UnsafePrefixStat` admits it for stat purposes; or document explicitly that `UnsafePrefixStat` also changes the authorization base. Add a regression test with `UnsafePrefixStat` on and a target outside `DocumentRoot`, asserting the intended policy and response.

---

## F33. Critical: FastCGI script path construction and `PATH_INFO` split have no document-root containment check

### Impact

`crates/server/src/fastcgi.rs` builds the FastCGI script filename from the configured backend prefix and the request suffix:

```rust
fn script_from_prefix(backend: &Backend, root: &Path, rel: &Path) -> PathBuf {
    let rel_text = rel.to_string_lossy().trim_start_matches('/').to_string();
    if backend.prefix.contains("$1") {
        PathBuf::from(backend.prefix.replace("$1", &rel_text))
    } else if !backend.prefix.is_empty() && backend.prefix != "/" {
        PathBuf::from(format!("{}/{}", backend.prefix.trim_end_matches('/'), rel_text))
    } else {
        root.join(rel)
    }
}
```

The result is passed to `split_path_info()`, which walks up the parent chain and returns the first ancestor that is a regular file:

```rust
while let Some(parent) = candidate.parent() {
    ...
    candidate = parent.to_path_buf();
    if candidate.is_file() { ... return (candidate, name, info); }
}
```

Neither function checks that the final script filename is contained in the document root or the configured FastCGI prefix directory. If a `ProxyPassMatch` replacement or a request suffix produces an absolute path outside the document root (for example `/tmp/opencode/fcgi-root/www/../../bin/sh`), the ancestor walk selects `/bin/sh` as the script to authorize and execute. The authorization and inode binding that follow are performed on that escaped script, so the containment failure is not caught later. This is a direct path-traversal-to-code-execution primitive in the FastCGI route.

### Reproduction

A `ProxyPassMatch` whose replacement is an absolute path containing `$1` or a suffix that reaches `..` segments, combined with an ancestor file that exists. The split loop walks to the ancestor and returns it as `script_filename`; the request then runs that file as the FastCGI script.

### Root cause

The ancestor walk assumes the caller already supplied a contained path. `script_from_prefix` also treats a configured absolute prefix as trusted without validating that the joined result stays beneath it. The final target is authorized as-is, so an escaped script becomes the authorization subject.

### Remediation

Canonicalize and require the constructed script filename to be beneath the document root or the configured FastCGI prefix directory before the ancestor walk. Bound the walk to that base and reject candidates outside it. Add tests for `PATH_INFO` splits with `..` components, for `$1` replacements that expand to absolute paths, and for scripts in ancestor directories of the document root.

---

## F34. Medium: cache policy fingerprint does not include request headers used by authorization

### Impact

`cache_policy_fingerprint()` in `crates/server/src/cache.rs` hashes the compiled `Scope` policy, the peer address, the method and the target path. It does not include request headers, `Vary` dimensions or the authenticated identity. The cache lookup path computes a per-request grant with `identity: None` and only rejects requests that carry an `Authorization` header. A policy that distinguishes access by a non-credential header (for example `Require expr "%{HTTP:X-Tenant} == 'a'"`) therefore produces the same fingerprint for requests that should receive different representations. The cache store excludes `Authorization` and `Cookie` headers, but not arbitrary header-based authorization dimensions.

The practical effect is cross-tenant or cross-policy cache reuse when authorization depends on headers not represented in the fingerprint. The cache's own comment acknowledges the missing identity dimension, but the header dimension is also absent.

### Reproduction

Configuration with a header-dependent policy and caching enabled:

```apache
Listen 127.0.0.1:18101
DocumentRoot "/tmp/opencode/cache-header/www"
CacheRoot "/tmp/opencode/cache-header/cache"
CacheEnable disk "/"
<Location "/tenant/">
    Require expr "%{HTTP:X-Tenant} == 'alpha'"
</Location>
```

A request with `X-Tenant: alpha` is authorized and its response is stored under the computed fingerprint. A later request with `X-Tenant: beta` computes the same fingerprint (the header is not hashed) and, if the grant check for the cached resource succeeds, is served the cached alpha representation. Whether the second request is denied depends on whether the lookup grant is re-evaluated; where it is not, the cached body crosses the policy boundary.

### Root cause

The fingerprint models configuration policy but not the request inputs that select a policy branch. Header-based authorization and `Vary` dimensions are not part of the key or the policy hash.

### Remediation

Include every request input that can affect authorization or representation in the fingerprint/key: authorization-relevant headers named by `Require expr`/`SetEnvIf`, the authenticated identity, and the effective `Vary` set. Alternatively, refuse to cache responses for scopes whose authorization is header-dependent unless the request is identity-partitioned. Add a differential test that fills the cache as tenant alpha and requests the same URL as tenant beta.

---

## F35. Low/Medium: `X-Forwarded-Host` and proxy request-line construction trust configuration-derived host text

### Impact

`crates/server/src/proxy.rs` builds upstream request lines and `X-Forwarded-Host` headers with `format!` string interpolation from backend and request host values. The HTTP/1 parser rejects CRLF in request targets and header values, so direct injection through the request line is blocked at the front door. The risk is in configuration-derived or rewrite-derived host text that is not re-validated at serialization time. If a `ProxyPass`/balancer target or a rewritten host value contains CR/LF or other control bytes, the upstream request can be split or the forwarded host can be spoofed. This is a defence-in-depth gap rather than a demonstrated remote exploit against the current parser.

### Remediation

Validate the final serialized request line and every forwarded header value with the same `valid_token`/`sanitize_header_value` predicates used for native responses immediately before `write_all`, and fail closed on control bytes. Add a unit test that constructs a backend host containing CR/LF and asserts rejection.

---

## F36. Critical: `.htaccess` `RequestHeader` is silently ignored, bypassing header-driven access control

### Impact

`crates/server/src/htaccess.rs` accepts `RequestHeader` in a per-directory access file but explicitly discards it:

```rust
"requestheader" | "addcharset" | ... => {}
```

The comment above the arm says these directives "do not affect access decisions or response framing." That is false for `RequestHeader`. Apache's `mod_headers` runs `RequestHeader` during request processing; the resulting header is visible to `Require expr`, `SetEnvIf`, rewrite conditions and `mod_remoteip`. A `.htaccess` that uses `RequestHeader set` to force a deny trigger (for example a header consumed by a `Require not expr` rule) is therefore bypassed by httpd-rs: the header is never set, the deny condition is false, and the protected resource is served. This is a fail-open in the `.htaccess` parser, not a benign cosmetic omission.

### Reproduction

Files:

```text
/tmp/opencode/reqhead/www/secret.txt          # WALLET-REQHEADER-SECRET
/tmp/opencode/reqhead/www/.htaccess
```

`.htaccess`:

```apache
RequestHeader set X-Block yes
<Files "secret.txt">
    Require expr "%{HTTP:X-Block} != 'yes'"
</Files>
```

Configuration:

```apache
Listen 127.0.0.1:18202
ServerName localhost
DocumentRoot "/tmp/opencode/reqhead/www"
<Directory "/tmp/opencode/reqhead/www">
    AllowOverride All
</Directory>
```

Observed against the current release binary:

```text
GET /secret.txt                       -> 200 WALLET-REQHEADER-SECRET
GET /secret.txt with X-Block: yes     -> 403
```

Apache evaluates `RequestHeader set X-Block yes` first and returns 403 for both requests. httpd-rs only denies when the client supplies the header itself, so a client that omits it receives the protected body. The same primitive applies to `RequestHeader unset` on an allow-list header and to `RequestHeader set` of any header consumed by a `Require expr`, `SetEnvIf`, or rewrite condition.

### Root cause

`apply_directive()` treats `RequestHeader` as inert and drops it. Because `.htaccess` parsing is otherwise fail-closed, the silent acceptance hides the omission: the directive is recognized (so strict/validity checks pass) but has no effect on the request that later reaches authorization.

### Remediation

Implement the `RequestHeader` set/append/unset/echo forms for `.htaccess` scopes and apply them before authorization and rewrite evaluation. If full support is not feasible, reject `RequestHeader` in `.htaccess` unless its effect is proved inert (which it is not when any `Require expr`/`SetEnvIf`/rewrite condition reads request headers). Add differential tests for `set`, `append`, `unset` and `echo` forms against Apache.

---

## F38. High: authenticated CGI/FastCGI requests do not receive `REMOTE_USER` or `AUTH_TYPE`

### Impact

After a successful Basic authentication, `helper_access_response()` records the
identity in the `ResourceKey`, but `cgi::build_env()` never emits
`REMOTE_USER` or `AUTH_TYPE`. Both names are also in `reserved_cgi_env()`, so a
`.htaccess`/rewrite environment entry cannot supply them either. A CGI or
FastCGI application that follows the Apache CGI contract therefore sees an
empty user for an authenticated request. In applications that use
`REMOTE_USER` for per-user authorization or audit, this is either a functional
failure or an application-level authorization bypass (for example a default
"anonymous" branch for an empty user).

The same `build_env()` is used by the FastCGI responder, so PHP-FPM and other
FastCGI applications are affected as well.

### Reproduction

A CGI script in a Basic-auth-protected directory:

```sh
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf 'REMOTE_USER=[%s]\n' "$REMOTE_USER"
printf 'AUTH_TYPE=[%s]\n' "$AUTH_TYPE"
```

Configuration uses the same `AuthType Basic`/`Require valid-user` as the
normal conformance auth fixture, with `AddHandler cgi-script .cgi` and
`Options +ExecCGI`.

Observed against the current release binary:

```text
GET /cgi/who.cgi with alice:secret
REMOTE_USER=[]
AUTH_TYPE=[]
```

Apache reports `REMOTE_USER=alice` and `AUTH_TYPE=Basic` for the same request.

### Root cause

`build_env()` sets the request-derived CGI variables from `CgiContext`, but
`CgiContext` has no authenticated-identity field and `build_env()` has no
`REMOTE_USER`/`AUTH_TYPE` writes. The reserved-name list prevents a
configuration workaround.

### Remediation

Carry the authenticated identity (already available in the access grant) into
`CgiContext` and emit `REMOTE_USER`, `AUTH_TYPE` and, when applicable,
`REMOTE_GROUPS`/`REMOTE_USER` for both CGI and FastCGI. Add differential tests
with Basic auth for CGI and FastCGI.

---

## Pass 3 model changes

The existing invariants I10/I11 already require one resolved target and reauthorization after transforms. F31–F33 show the invariant needs to be stated over the *configured base* as well as the *document root*:

```text
for all alias/rewrite/fastcgi mappings:
    resolved_target ∈ configured_base(scope)
```

and the cache key invariant needs to cover request inputs that select a policy branch, not just compiled policy:

```text
cache_key(req) includes every input that changes authorize(req) or representation(req)
```

Add `alias_base_containment`, `rewrite_filesystem_containment`, `fastcgi_script_containment` and `cache_authorization_inputs` to the ledger. Add replay cases for F31–F34 to `cve_replay_cases`, not just static triage rows.
