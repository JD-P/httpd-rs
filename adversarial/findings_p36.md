# Pass 36 — trailing-slash internal rewrite aborts the whole process

- **Date:** 2026-11-10
- **Subject:** HEAD `3e4ce6cd0e97d8582c58a3729ae47b3e33a29d53`
  (`target/release/httpd-rs`, rebuilt from the checked-out tree; no product
  source was edited).
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` + `mod_rewrite` +
  `mod_authz_core` + `mod_mime` + `mod_dir`, loopback only.
- **Harness:** `adversarial/p36/exploit_p36.py` — six rewrite cases; retained
  output `adversarial/p36/results_p36.txt`.
- **Method:** audit of the newest unreviewed commit `93c834f` ("Make
  authorization identities representation-safe") plus live Apache-versus-
  httpd-rs differentials over trailing-slash internal rewrites in main
  configuration and attacker-writable `.htaccess`.
- **Disposition:** **P36-A confirmed and unfixed at HEAD.** One
  unauthenticated request that reaches an internal rewrite whose result ends
  with `/` aborts the whole process with `SIGABRT`. The retained P33
  remediation battery also fails at HEAD (403 changed to 404, no disclosure);
  recorded as observation O1.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs at HEAD | Class |
|---|---------|---------------|------------------|-------|
| **P36-A** | `CanonicalTarget::from_normalized` (tightened by `93c834f`) now requires its `norm` argument to be the slash-less canonical form, but the two rewrite call sites still pass the slash-suffixed `canonical` string. When a rewrite result ends with `/` (except exactly `/`) the constructor returns `None` and `.expect("canonicalized rewrite path remains canonical")` panics. Release builds use `panic = "abort"`, so the request kills the entire process. | Main config `RewriteRule ^/legacy/$ /newdir/ [L]` and `RewriteRule ^/x$ /does-not-exist/ [L]`: `404`, Apache stays alive. `.htaccess` `RewriteRule ^boom$ /target/ [L]` under `AllowOverride FileInfo`: `200` and the rewritten target is served. | `SIGABRT` (`rc=-6`), connection closed without a response, process gone (`thread 'httpd-rs-request-…' panicked at crates/server/src/server.rs:6333:30` / `:7161:22`). | denial of service — whole-process abort, one unauthenticated request |

P36-A is the strongest class this project records: a single request from any
unauthenticated client destroys the server process (all vhosts, all
connections). It is reachable from an ordinary rewrite idiom
(`RewriteRule … /somewhere/ [L]`) and, in the deployment threat model, from a
one-line attacker-written `.htaccess` in any `AllowOverride FileInfo` upload
directory.

---

## 2. P36-A — `from_normalized` contract mismatch aborts on trailing-slash rewrites

### 2.1 Root cause

`93c834f` replaced the infallible internal-rewrite constructor with a
validating one:

```rust
// crates/server/src/request_plan.rs:200-221
pub fn from_normalized(norm: Vec<u8>, url_path: String) -> Option<Self> {
    let trailing_slash = url_path.len() > 1 && url_path.ends_with('/');
    let checked = normalize_uri_path(url_path.as_bytes())?;
    if checked != norm {
        return None;
    }
    let mut canonical = String::from_utf8(checked).ok()?;
    if trailing_slash && canonical != "/" {
        canonical.push('/');
    }
    (canonical == url_path).then_some(Self {
        url_path: DecodedUrlPath(url_path),
        norm,
    })
}
```

In Apache and in this codebase the internal-rewrite subject keeps a
“meaningful trailing slash” (`rewrite.rs::new_path_from_joined`,
`canonicalize_rewrite_path` re-adds it), and
`normalize_uri_path` is documented to remove trailing slashes —
“absolute, no `.`/`..`/empty segments, no duplicate or trailing slashes”
(`crates/verified/src/lib.rs:517-521`). The pair that satisfies
`from_normalized` is therefore

- `url_path = "/newdir/"` and
- `norm = b"/newdir"` (the slash-less normalized bytes).

Both rewrite call sites instead pass the *same* slash-suffixed string for both
arguments:

```rust
// crates/server/src/server.rs:6331-6333  (URL-translation Internal outcome)
target = CanonicalTarget::from_normalized(canonical.as_bytes().to_vec(), canonical)
    .expect("canonicalized rewrite path remains canonical");
```

```rust
// crates/server/src/server.rs:7159-7161  (per-directory Internal outcome)
url_path = canonical;
norm = url_path.as_bytes().to_vec();
let mut target = CanonicalTarget::from_normalized(norm.clone(), url_path.clone())
    .expect("canonicalized per-directory rewrite path remains canonical");
```

For `canonical = "/newdir/"`:
`checked = normalize_uri_path("/newdir/") = b"/newdir"`, `norm = b"/newdir/"`,
so `checked != norm` and the constructor returns `None`. The `.expect()` turns
that into a panic, and `[profile.release] panic = "abort"` turns the panic into
`SIGABRT` for the whole process. The root `/` case is exempt only because
`canonicalize_rewrite_path` does not append a slash for it
(`if trailing && out != "/"`).

`93c834f` is newer than the last adversarial review (`3310fe3`, Pass 35), so
neither the trailing-slash rewrite shapes nor this constructor/caller
disagreement had been reviewed.

### 2.2 Reachable shapes and live evidence

`adversarial/p36/exploit_p36.py` runs Apache and httpd-rs on sibling loopback
ports over one fixture tree. Retained output
(`adversarial/p36/results_p36.txt`):

```text
## A main-config trailing-slash rewrite aborts the process
   /legacy/       apache=404 (oracle alive=True)
   -> VULNERABLE: httpd-rs aborted (rc=-6) on one unauthenticated request (RemoteDisconnected)

## A2 missing target still aborts (target need not exist)
   /x             apache=404 (oracle alive=True)
   -> VULNERABLE: httpd-rs aborted (rc=-6) on one unauthenticated request (RemoteDisconnected)

## A3 RewriteCond guard still reaches the abort
   /x             apache=404 (oracle alive=True)
   -> VULNERABLE: httpd-rs aborted (rc=-6) on one unauthenticated request (RemoteDisconnected)

## B .htaccess per-directory trailing-slash rewrite aborts (FileInfo)
   /uploads/boom  apache=200 (oracle alive=True)
   -> VULNERABLE: httpd-rs aborted (rc=-6) on one unauthenticated request (RemoteDisconnected)

## C control: no-trailing-slash rewrite survives
   /x             apache=200 (oracle alive=True)
   -> control httpd-rs=200 survived

## C2 control: root rewrite survives
   /x             apache=403 (oracle alive=True)
   -> control httpd-rs=200 survived
```

Retained daemon evidence (`/tmp/opencode/p36-harness/case*/httpd-rs.log`
when `--keep` is used):

```text
thread 'httpd-rs-request-1' (31555) panicked at crates/server/src/server.rs:6333:30:
canonicalized rewrite path remains canonical
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

```text
thread 'httpd-rs-request-1' (32063) panicked at crates/server/src/server.rs:7161:22:
canonicalized per-directory rewrite path remains canonical
```

Confirmed properties:

- **Main configuration.** `RewriteEngine On` plus
  `RewriteRule ^/legacy/$ /newdir/ [L]` aborts on `GET /legacy/`
  (`server.rs:6333`). `RewriteRule ^/x$ /does-not-exist/ [L]` aborts even
  though the rewritten target does not exist; the panic happens before any
  filesystem resolution.
- **`.htaccess` / per-directory.** With `AllowOverride FileInfo` and
  `HttpdRsCapability AccessFiles On`, a one-line access file
  (`RewriteEngine On` + `RewriteRule ^boom$ /target/ [L]`) aborts on
  `GET /uploads/boom` (`server.rs:7161`); Apache rewrites and serves the
  target (`200`).
- **Guarded rewrites still abort.** A `RewriteCond %{REQUEST_METHOD} =GET`
  precondition does not prevent the panic.
- **Conditional/query variants.** `RewriteRule ^/legacy$ /newdir/?x=1 [L]`
  also aborts (query override does not change the path validation).
- **Controls.** A rewrite to a path without a trailing slash
  (`/noslash`) works on both servers, and a rewrite to exactly `/` does not
  abort either.

### 2.3 Preconditions and blast radius

- **Attacker cost:** one unauthenticated `GET`. No body, credentials, or
  pre-existing session.
- **Configuration shapes:** any internal rewrite (main config, `<Directory>`,
  or `.htaccess`) whose substitution canonicalizes to a path that ends in `/`
  other than exactly `/` — a common mod_rewrite idiom for directory targets
  (`RewriteRule ^([a-z]{2})$ /$1/ [L]`, `/app/`-style front controllers, etc.).
  Redirect (`[R]`) and proxy (`[P]`) outcomes are not affected; the abort is
  specific to the internal-rewrite path.
- **Writable-`.htaccess` deployment shape (upload → whole-host DoS):** the
  benchmarked WordPress/PHP-FPM deployment
  (`tests/deployments/scenarios/wordpress-fpm/driver.py:201,204,178`) applies
  `AllowOverride FileInfo` to the whole document root and leaves
  `wp-content/uploads` writable by PHP-FPM (`chown -R 33:33`). `RewriteRule`
  is in the `FileInfo` override category, so any application-level file write
  (media upload, plugin write, symlink target) can plant `.htaccess` and crash
  the server with one request. The same applies to any `AllowOverride FileInfo`
  upload tree.
- **Blast radius:** the process exits (`SIGABRT`); every connection and every
  virtual host served by that process is lost. With `panic = "abort"` there is
  no unwinding or per-request containment.
- **Supervision caveat:** a supervisor (systemd) restarts the daemon, but the
  attacker can repeat the request after each restart; the service is
  effectively permanently down for one request per restart.

### 2.4 Why the `.expect()` is not acceptable as “unreachable”

The `.expect` messages assert an invariant the author believed held:
“canonicalized rewrite path remains canonical”. The constructor’s contract is
narrower than the callers’ assumption — it requires the pair
`(norm_without_slash, url_path_with_slash)` — and `rewrite.rs` deliberately
preserves the trailing slash (`new_path_from_joined` comment: “preserve a
meaningful trailing slash”; `canonicalize_rewrite_path` re-adds it). This is
the same class as the P24/P28/P29 abort findings: an executable invariant
check on attacker-reachable input under `panic = "abort"` is an availability
vulnerability, not a safety net.

### 2.5 Remediation direction (not applied in this pass)

1. At both call sites, pass the slash-less normalized bytes:
   `let Some(norm) = normalize_uri_path(canonical.as_bytes()) else { return 400 }`
   and call `CanonicalTarget::from_normalized(norm, canonical)`; or
2. simplify `from_normalized(url_path)` so the constructor derives `norm`
   itself, making the mismatch unrepresentable; and
3. add differential regressions for both main-config and `.htaccess`
   trailing-slash rewrites (the four `expect_abort` rows in
   `adversarial/p36/exploit_p36.py` convert directly into the regression:
   the server must answer and stay alive).

### 2.6 Relationship to prior passes

- This is a regression introduced by `93c834f` (2026-11-10), the newest
  security-relevant commit and the one that also closed the P34-A decoded
  identity class. The commit’s new `.expect()` calls were not exercised by
  trailing-slash rewrite requests.
- The retained P33/P34/P35 batteries still pass except the stale P33 case B
  expectation described in O1; the new-open batteries (P18/P17) pass, which
  pins P36-A to the rewrite constructor path rather than parser or
  authorization behavior.
- P28-A/P29-A previously demonstrated request-triggered aborts; P36-A is a
  distinct root cause in the rewrite identity constructor and needs no
  memory pressure or deep recursion.

---

## 3. Negative observations

### P36-O1 — retained P33 battery case B now conceals the MultiViews guard as 404

At HEAD, `adversarial/p33/exploit_p33.py` case B
(`MultiViews` + `<LocationMatch "\.txt$"> Require all denied`, request
`/secret`) returns `httpd-rs=404` where the retained remediation output
(`adversarial/p33/results_p33.txt`) records `httpd-rs=403`:

```text
## B extension Location guard
   /secret        apache=404 httpd-rs=404 leaked=False
   -> FAIL: httpd-rs expected 403, got 404 for /secret
```

No protected content is disclosed (`leaked=False`), and 404 is at least as
restrictive as 403. The change postdates the P33 remediation and matches the
later deliberate concealment of implicit target rejections added by
`7209f0e` (“Add information disclosure campaign”): `conceal_implicit_target_rejection`
maps 401/403/404 to 404 for negotiated-target denials
(`crates/server/src/server.rs:5491-5519`). The P33 battery’s expectation was
not updated with that design change and is now stale. Recorded as an
unresolved observation, not a vulnerability claim.

### P36-O2 — rewrite to exactly `/` diverges from Apache

With `<Directory /> Require all denied` + a granted `DocumentRoot`, main-config
`RewriteRule ^/x$ / [L]` returns `403` on Apache 2.4.69 (the oracle log shows
it resolves the substitution as a filesystem path: `client denied by server
configuration: /`) and `200` with the DocumentRoot index on httpd-rs. Only
public DocumentRoot content is served on httpd-rs, and the same request can be
made directly, so no protected content is exposed under either interpretation.
Recorded as an unresolved parity observation.

### Environment notes

- `adversarial/p16/exploit_p16.py` reports `httpd-rs did not listen` for every
  case at HEAD because the harness (`os.chmod(RUN, 0o777)` at
  `exploit_p16.py:875`) makes the configuration tree writable by the service
  account, which the newer administrative-path hardening rejects; this is a
  harness/environment incompatibility, not a product regression. P17 and P18
  pass at HEAD.
- `adversarial/p33/exploit_p33.py` stops at the first failing case, so cases
  C–F were not re-run during this pass; case A agrees with the retained
  output.

---

## 4. Retained files

- `adversarial/p36/exploit_p36.py` — six-case Apache/httpd-rs trailing-slash
  rewrite reproducer; exits 0 while the aborts reproduce and 1 once the server
  survives (convert to a remediation regression at that point).
- `adversarial/p36/results_p36.txt` — retained HEAD run output (four
  `SIGABRT` rows and two surviving controls).
- `/tmp/opencode/p36-harness/` — per-case configs, fixtures and daemon logs
  when `--keep` is used.
