# Pass 33 — MultiViews selects a representation before the trailing-slash rejection and serves it without re-evaluating URL-scoped authorization (P33-A)

- **Date:** 2026-11-09
- **Subject:** HEAD `dc2d5e5` (`target/release/vapached`, rebuilt from the
  checked-out tree; no product source was edited). The feature under review is
  the MultiViews support added by `fb46f2f` ("Support Debian static and
  PHP-FPM defaults"), the newest product commit before this pass.
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` + `mod_negotiation` +
  `mod_rewrite` + `mod_authz_core`, loopback only.
- **Harness:** `adversarial/p33/exploit_p33.py` (six differential cases;
  Apache and vapached on distinct sibling loopback ports with separate
  configs, pid files and fixtures). Retained output:
  `adversarial/p33/results_p33.txt`.
- **Method:** source audit of the new MultiViews branch plus a live
  Apache-versus-vapached differential across exact-`Location`,
  extension-`Location`, `.htaccess` rewrite, stock-Debian alias and control
  shapes.
- **Disposition:** confirmed, live, reproducible; not yet remediated.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | vapache HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P33-A** | `Options MultiViews` content negotiation runs in the `Target::NotFound` branch and maps a missing/extensionless URL to a sibling `name.ext` representation. Two independent identities stay behind: (1) the trailing-slash static-file rejection lives only in the `Target::File` branch, so `/secret/` negotiates and serves `secret.txt`; (2) URL-scoped authorization ( `<Location>`/`<LocationMatch>` and per-directory `RewriteRule` subjects) is still evaluated against the pre-negotiation URL `/secret`, while Apache evaluates it against the negotiated representation `/secret.txt`. | `/secret` under `RewriteRule \.txt$ - [F]` or `<LocationMatch "\.txt$"> Require all denied` → `404`; `/secret/` under `<LocationMatch "^/secret$">` → `404`; stock alias `/js/secret/` → `404`. | `/secret` → `200` with the protected body; `/secret/` → `200` with the protected body; `/js/secret/` → `200` with the protected body. | protected static-file read; authority bypass |

The controls agree on both servers: the same guard with `MultiViews` off
returns `403`/`404`, and a candidate-bound `<Files "secret.txt"> Require all
denied` denies on both. The divergence appears only when negotiation actually
selects the sibling representation.

The attack requires one request and no authentication. `Options MultiViews`
is a documented Apache policy and is enabled by stock Debian configuration
(`/etc/apache2/conf-available/javascript-common.conf` sets
`Alias /javascript /usr/share/javascript/` plus
`Options FollowSymLinks MultiViews`; the `userdir` module does the same for
user directories), which is exactly the Debian static-default surface the
`fb46f2f` commit added.

---

## 2. Root cause

### 2.1 Negotiation runs where the pre-P25 static-file rejection should have happened

`resolve_target_checked()` maps `/secret/` to the same missing filesystem
target as `/secret`: the trailing slash survives in `url_path`, but the
filesystem plan has no component for it. Because the target does not exist,
dispatch enters `Target::NotFound`. The new negotiation branch runs there:

```rust
// crates/server/src/server.rs (HEAD dc2d5e5)
Target::NotFound => {
    ...
    if !script_alias && matches!(req.method.as_str(), "GET" | "HEAD") {
        match multiviews_target(cfg, &scope, req, &root, &rel, follow_symlinks, owner_match_only) {
            MultiViewsResult::Selected(view) => { ... serve_file(...) ... }
```

The P25-A trailing-slash rule — "A trailing slash asserts a directory-like
target ... never serve a regular file through that spelling" — is implemented
later and only inside the `Target::File` branch
(`crates/server/src/server.rs:7452`). `/secret/` never reaches that branch, so
the rejection cannot apply. On Apache, `/secret/` is not a content-negotiation
request at all: mod_negotiation is only reached for a missing *basename*
without the trailing-slash directory assertion, and Apache returns `404`.

### 2.2 The negotiated representation keeps the pre-negotiation URL identity

`multiviews_target()` (`crates/server/src/files.rs:660`) opens the selected
sibling file and `bind_multiview_grant()`
(`crates/server/src/server.rs:4857`) computes:

- a lexical scope for the requested URL `/secret` against the candidate
  filesystem name;
- a resolved scope for the opened candidate and its `.htaccess` ancestors;
- a per-base restriction that conjoins the requested URL scope.

Candidate-bound rules therefore bind — `<Files "secret.txt"> Require all
denied` and candidate `<Directory>` policy are evaluated and do deny — but
URL-bound policy never sees the negotiated name. `<LocationMatch "\.txt$">`,
`<Location "^/secret$">` and per-directory rewrite subjects all run against
`/secret`. Apache instead runs the negotiated variant through the normal
URL/Location/per-directory phases: the `mod_negotiation` error log for a
non-MultiViews server already shows the denial against
`/tmp/.../secret.txt` ("client denied by server configuration:
.../secret.txt"), and its trailing-slash path is `404`.

This is the same class as F60/P13/F69: a transform changes the served object
but policy is bound to the pre-transform identity. MultiViews is the one
transform that was added without extending that invariant.

### 2.3 Content served

`serve_file()` binds the opened inode and the candidate's `Files`/`Directory`
policy, then serves the negotiated bytes with `Content-Location`,
`Vary: Accept, Accept-Language, Accept-Encoding` and `TCN: choice`. It never
consults the requested URL's extension-scoped rules, so a deny that exists
precisely to keep the representation from being downloaded is skipped.

---

## 3. Live evidence

`python3 adversarial/p33/exploit_p33.py` (retained output
`adversarial/p33/results_p33.txt`):

```text
## A exact Location + trailing slash
   /secret        apache=403 vapache=403 leaked=False
   /secret/       apache=404 vapache=200 leaked=True

## B extension Location guard
   /secret        apache=404 vapache=200 leaked=True

## C .htaccess rewrite extension guard
   /secret        apache=404 vapache=200 leaked=True

## D stock-Debian alias shape
   /js/secret     apache=403 vapache=403 leaked=False
   /js/secret/    apache=404 vapache=200 leaked=True

## E control: MultiViews off
   /secret        apache=403 vapache=403 leaked=False
   /secret/       apache=404 vapache=404 leaked=False

## F control: Files deny is candidate-bound
   /secret        apache=404 vapache=403 leaked=False

PASS-33 HARNESS COMPLETE: expected divergences above are the P33-A reproducer
```

Case details:

- **A** — `<LocationMatch "^/secret$"> Require all denied` + `Options
  MultiViews`, file `secret.txt`. The exact-URL guard works on `/secret`; the
  `/secret/` spelling bypasses both it (by URL identity) and Apache's
  directory assertion (by ordering) and returns `P33-SECRET-CONTENT-7f3a`.
- **B** — `<LocationMatch "\.txt$"> Require all denied` + `Options
  MultiViews`. Apache denies the negotiated `.txt` representation (`404`);
  vapache serves it.
- **C** — `.htaccess` `RewriteEngine On` + `RewriteRule \.txt$ - [F]` under
  `AllowOverride FileInfo` + `Options MultiViews`. Apache's per-directory
  rewrite sees the negotiated subject and denies (`404`, and the rewrite is an
  ordinary operator control in the deployment scenarios); vapache returns the
  body.
- **D** — the stock-Debian alias shape: `Alias /js <root>`, `<Directory
  "<root>"> Options FollowSymLinks MultiViews`, plus an exact
  `<LocationMatch "^/js/secret$">` deny. `/js/secret/` leaks on vapache,
  `404` on Apache. This is the configuration shape produced by Debian's
  `javascript-common.conf`.
- **E** — the same exact-`Location` guard with `Options FollowSymLinks`
  (MultiViews off): both servers `403`/`404`.
- **F** — candidate-bound `<Files "secret.txt"> Require all denied` with
  MultiViews on: both servers deny, which isolates the bug to URL-scoped
  policy rather than a general MultiViews bypass.

An additional interop check (not part of the pass) showed that MultiViews
still refuses handler/candidate execution: a negotiated `.php` or `.txt`
file with a `<FilesMatch>`/`<LocationMatch>` `SetHandler cgi-script` returns
`404` on vapache instead of executing, while Apache executes the negotiated
handler. The divergence is therefore disclosure, not code execution, unless a
future negotiation path arms a handler — the handler-refusal check must stay
fail-closed when this fix lands.

### Reviewed without a finding (P33-O observations)

- **P33-O1** — The `fb46f2f` translation of
  `SetEnvIfNoCase ^Authorization$ "(.+)" HTTP_AUTHORIZATION=$1` into
  `scope.environment_policy.cgi_pass_auth = Some(true)` was probed with a CGI
  `HTTP_AUTHORIZATION` oracle. A `<FilesMatch "\.php$">`-scoped rule did not
  leak the header to CGI paths outside the match, and the global-rule and
  no-rule controls matched Apache. No divergence was established.
- **P33-O2** — The new connection-local proxy pooling (`8cec30c`) was
  reviewed statically: `proxy_session_key` binds the backend binding, method,
  query, host, the complete admitted header view and the bounded body, and
  `ProxySession` is created per downstream transport with a five-second idle
  timeout and a four-entry cap. No cross-request/cross-client reuse sequence
  was found; no live reuse attack was attempted. The HTTP-desynchronization
  review's D3 statement ("upstream sockets are not pooled") is now stale and
  should be refreshed.

---

## 4. Preconditions and blast radius

- **Precondition:** `Options MultiViews` is effective for the target
  directory (server/vhost/`<Directory>`/`.htaccess`) and at least one sibling
  `name.ext` representation has a configured MIME type. `.htaccess` can
  enable it wherever `AllowOverride Options`/`All` permits.
- **Guards that fail open:** exact URL `<Location>`/`<LocationMatch>` rules
  (by the trailing-slash spelling), extension-scoped `Location` rules,
  per-directory `RewriteRule` deny/redirect/`[F]` rules, and any other
  URL-subject control that Apache re-evaluates for the negotiated variant.
- **Not affected:** candidate-bound `<Files>`/`<FilesMatch>` rules,
  `<Directory>` rules, resolved-target reauthorization, and handler
  execution — the new `bind_multiview_grant()` conjoin keeps those closed
  (cases E/F and the handler probe).
- **Blast radius:** unauthenticated read of any static representation the
  operator intentionally denied, from any affected MultiViews directory,
  including stock Debian `/javascript` aliases. The content is not staged or
  user-restricted; it is exactly the representation the URL rule protects
  (source, configuration snippets, exported text, internal documents).
- **Attacker cost:** one unauthenticated `GET`; no body, no state, no
  credential. Recovery is only a configuration change (disable MultiViews)
  until the code fix lands.

---

## 5. Relationship to prior passes

- **P25-A** fixed trailing-slash static-file URL identity in the
  `Target::File` branch. P33-A shows the same spelling reaches a different
  branch (`Target::NotFound` → MultiViews) that the fix did not cover. The
  regression shape is `GET /private.txt/` served while the exact URL is
  denied, now generalized to content negotiation.
- **F60 / P13 / F69 / F64** established that a transform changing the
  served object must re-derive both the handler identity and the URL policy
  identity. MultiViews (new in `fb46f2f`) re-derives the opened candidate and
  its `Files`/`Directory` scope but not the URL-scoped rule subject.
- **P14-A** fixed `<Files>`/`<FilesMatch>` phase interleaving; P33-A is the
  complementary case where the rule *kind* is URL-bound (`Location`/rewrite)
  and the served name changed instead.
- **P27/P28/P29** hardened the verified glob/expansion kernels; MultiViews
  itself stays within its directory-entry/candidate/work budgets and did not
  yield an availability finding in this pass (400 randomized hostile
  directory-entry probes, no crash).

---

## 6. Recommended remediation

1. **Reject regular-file negotiation for trailing-slash requests before
   selecting a candidate.** Move/duplicate the P25-A trailing-slash check so
   it applies to the `Target::NotFound` path before `multiviews_target()` can
   select a file. This closes cases A and D-slash and matches Apache's
   directory assertion.
2. **Make the negotiated representation a URL-policy identity.** After a
   candidate is selected, re-run the URL-scoped authorization and
   per-directory rewrite phases with the negotiated URL (`/name.ext`) as the
   subject — or, equivalently, evaluate the candidate against a synthesized
   internal-request identity the way Apache's negotiation phase does — and
   require both the pre-negotiation URL policy and the negotiated-name policy
   to allow it. This closes cases B and C. `bind_multiview_grant()` should keep
   the existing candidate `Files`/`Directory`/resolved-target conjoin and must
   not weaken the handler-refusal check.
3. **Regression coverage:** add the six P33 harness cases (exact-Location
   slash, extension-Location, `.htaccess` rewrite extension, stock alias,
   MultiViews-off control, `<Files>` control) plus a candidate-handler
   refusal control to the conformance/adversarial regression suites, and
   require both the selected-file and selected-URL policy decisions in the
   request plan rather than a post-selection patch.

---

## 7. Reproduction

```sh
cd /root/vapache
cargo build --release -p vapached
python3 adversarial/p33/exploit_p33.py            # six differential cases
python3 adversarial/p33/exploit_p33.py --keep     # retain fixtures and logs
```

The harness writes configs, fixtures and server logs under
`/tmp/opencode/p33-harness` (`--keep` retains them), binds Apache and
vapached to separate loopback ports in the `29100`/`29200` ranges, and uses
the real `/usr/sbin/apache2` 2.4.69 oracle with `mod_negotiation`,
`mod_rewrite` and `mod_authz_core`.

## 8. Retained files

- `adversarial/p33/exploit_p33.py` — six-case Apache/vapached differential
  harness; asserts the vulnerable `LEAK` rows so a remediation flips it.
- `adversarial/p33/results_p33.txt` — retained run output.
- `/tmp/opencode/p33-harness/` — per-case configs, fixture trees and server
  logs when `--keep` is used.
