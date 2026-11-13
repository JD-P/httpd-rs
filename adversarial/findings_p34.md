# Pass 34 — Percent-encoded synthesized representation identities fail decoded-spelling URL policy open (P34-A)

- **Date:** 2026-11-09
- **Subject:** HEAD `755e81a82e4f638019e98e4e96f84f39c5a2f730`
  (`target/release/httpd-rs`, rebuilt from the checked-out tree; no product
  source was edited). The mechanism under review is the P33 remediation's
  synthesized selected-representation identity (`702e042`, `a52eb76`,
  `7209f0e`) and the autoindex entry gate added by `7209f0e`.
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` + `mod_negotiation` +
  `mod_autoindex` + `mod_rewrite` + `mod_authz_core`, loopback only.
- **Harness:** `adversarial/p34/exploit_p34.py` (eleven cases; Apache and
  httpd-rs on distinct sibling loopback ports with separate configs, pid files
  and fixtures). Retained output: `adversarial/p34/results_p34.txt`.
- **Method:** inspection of the P33 synthesized-identity code plus a live
  Apache-versus-httpd-rs differential over representation names that contain
  characters `url_encode_path` percent-encodes (space, non-ASCII, literal
  `%`), crossed with `Location`, `LocationMatch`, `Files`, autoindex and
  access-file rewrite policy.
- **Disposition:** **confirmed and unfixed at HEAD.** Every earlier family
  guard and the candidate-bound `<Files>` control still deny; the defect is
  specific to the encoding of the synthesized authorization identity.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs at HEAD | Class |
|---|---------|---------------|------------------|-------|
| **P34-A** | The synthesized policy identities for implicitly selected objects are built with `url_encode_path` (wire percent-encoding), while the request pipeline and Apache authorize URL-scoped policy against the decoded path. A decoded-spelling `<Location>`/`<LocationMatch>` rule therefore fails open for (1) the MultiViews negotiated representation and (2) autoindex directory entries. | File `name with space.txt` with `<LocationMatch "^/name with space\.txt$"> Require all denied`: `GET /name%20with%20space` → `404`; the same guard around a directory hides `name with space.txt` from the listing; the stock Debian `Alias /javascript`-style shape leaks `/js/name%20with%20space` the same way. Non-ASCII spellings and `<Location>` prefixes behave the same. | `GET /name%20with%20space` → `200` with `P34-SECRET-CONTENT-5e21`; the listing names the denied entry. The direct URL `/name%20with%20space.txt` is `403` on both servers, so a single representation is denied under one spelling and served under the negotiated spelling. | protected static-file read; authority bypass; autoindex metadata disclosure |

The identity mismatch is bidirectional and pinned by controls: putting the
percent-encoded spelling in the rule makes Apache **serve** while httpd-rs
**denies** (`A6`), and a `\.txt$` or `<Files "name with space.txt">` guard
denies on both servers (`A4`, `A5`, `B2`). The defect is the encoding, not
rule semantics.

---

## 2. Root cause

### 2.1 The request pipeline's URL identity is decoded

Every ordinary request authorizes against the decoded, normalized path:
`CanonicalTarget::from_request` (`crates/server/src/request_plan.rs:47`)
runs `percent_decode_path` then `normalize_uri_path`, and dispatch passes the
resulting decoded `url_path` to `evaluate_scope_identities_for_path`,
`helper_access_response` and the `Location`/`LocationMatch` machinery.
A direct `GET /name%20with%20space.txt` under the decoded guard is denied by
both servers (`A1`/`A2` direct rows).

### 2.2 Two synthesized identities use wire encoding instead

`multiview_selected_url()` builds the negotiated representation's policy
identity by appending `url_encode_path(selected_name)` to the decoded parent:

```rust
// crates/server/src/server.rs:5237 (HEAD 755e81a)
pub(crate) fn multiview_selected_url(public_url_path: &str, selected_name: &[u8]) -> String {
    ...
    selected.push_str(&crate::util::url_encode_path(selected_name));
    selected
}
```

`url_encode_path` (`crates/server/src/util.rs:427`) encodes every byte outside
its pchar/sub-delim set, so `name with space.txt` becomes
`name%20with%20space.txt`, `café.txt` becomes `caf%C3%A9.txt`, and a literal
`%20` in the filename becomes `%2520`. That string is what the P33 remediation
feeds to post-negotiation authorization (`multiview_target_scope()` →
`evaluate_scope_identities_for_path(..., selected_url_path, ...)`), to the
replayed per-directory rewrite subject, and to the shared-cache identity; the
dispatch call site is `crates/server/src/server.rs:8118`.

The new autoindex metadata gate makes the same choice per entry:

```rust
// crates/server/src/files.rs:2189 (HEAD 755e81a)
let mut target_url = format!(
    "{}/{}",
    url_path.trim_end_matches('/'),
    crate::util::url_encode_path(&name)
);
... crate::server::autoindex_entry_visible(..., &target_url, ...)
```

`autoindex_entry_visible()` (`crates/server/src/server.rs:5443`) forwards
`target_url` twice into `authorize_resolved_target` as both the selected and
the public URL. A decoded-spelling `<LocationMatch "^/docs/name with
space\.txt$">` never matches the encoded subject, so the entry is exposed.

Apache evaluates URL-scoped policy for the negotiated file and for directory
entries against the decoded path (`A1`/`A3`, `B1`), exactly as httpd-rs itself
does for direct requests. Both synthesized sites are therefore using a wire
serialization as a security identity — the same class of identity mismatch
that F57 fixed for `%{REQUEST_URI}` and that P33-A fixed for the
pre-negotiation URL.

---

## 3. Original live evidence

`adversarial/p34/exploit_p34.py` on HEAD `755e81a` (key lines; the complete
run is retained in `adversarial/p34/results_p34.txt`):

```text
## A1 decoded LocationMatch body
   /name%20with%20space         apache=404 httpd-rs=200 httpd_rs_leak=True
   /name%20with%20space.txt     apache=403 httpd-rs=403
## A2 decoded Location prefix body
   /name%20with%20space         apache=404 httpd-rs=200 httpd_rs_leak=True
   /name%20with%20space.txt     apache=403 httpd-rs=403
## A3 decoded non-ASCII LocationMatch body
   /caf%C3%A9                   apache=404 httpd-rs=200 httpd_rs_leak=True
## A4 control extension guard body
   /name%20with%20space         apache=404 httpd-rs=404 httpd_rs_leak=False
## A5 control Files guard body
   /name%20with%20space         apache=404 httpd-rs=404 httpd_rs_leak=False
## A6 mirror encoded LocationMatch body
   /name%20with%20space         apache=200 httpd-rs=404 httpd_rs_leak=False
## A7 stock-Debian alias body
   /js/name%20with%20space      apache=404 httpd-rs=200 httpd_rs_leak=True
   /js/name%20with%20space.txt  apache=403 httpd-rs=403
## B1 decoded LocationMatch autoindex
   /docs/ listing: apache=200 httpd-rs=200 apache_names_denied=False
   httpd_rs_names_denied=True public_on_both=True direct_apache=403 direct_httpd_rs=403
## B2 control Files autoindex
   /docs/ listing: apache_names_denied=False httpd_rs_names_denied=False
## B3 control no guard autoindex
   /docs/ listing: apache_names_denied=True httpd_rs_names_denied=True
## C1 access-file rewrite decoded spelling
   /name%20with%20space         apache=404 httpd-rs=404
P34-A LIVE AT HEAD: percent-encoded synthesized identities fail decoded-spelling URL policy open
```

Case detail:

- **A1/A2** — `Options MultiViews`, file `name with space.txt`, guard
  `<LocationMatch "^/name with space\.txt$">` or
  `<Location "/name with space.txt">` (`Require all denied`). Apache denies
  the negotiated spelling (`404`); httpd-rs serves the protected body
  (`200`). The exact `.txt` URL stays `403` on both.
- **A3** — `café.txt` with `<LocationMatch "^/café\.txt$">`: Apache `404`,
  httpd-rs `200` with the body. Any name with a character that
  `url_encode_path` encodes is affected.
- **A4/A5** — `\.txt$` `LocationMatch` and `<Files "name with space.txt">`
  controls deny on both servers.
- **A6** — the mirror: `<LocationMatch "^/name%20with%20space\.txt$">`
  matches on httpd-rs (`404`) and is ignored by Apache (`200`). Together with
  A1 this proves the two implementations disagree about the identity, not the
  rule.
- **A7** — the stock-Debian `Alias /js` + `<Directory ... Options MultiViews>`
  shape with a decoded-spelling deny: `/js/name%20with%20space` leaks on
  httpd-rs (`200`) and `404`s on Apache, while the exact `.txt` URL is `403`
  on both. This is the deployment shape of Debian's
  `javascript-common.conf`.
- **B1** — `Options +Indexes` directory `docs/` with `public.txt` and
  `name with space.txt`, guard
  `<LocationMatch "^/docs/name with space\.txt$">`. Apache omits the denied
  entry from the listing; httpd-rs names it. `public.txt` is visible on both,
  and the direct entry URL is `403` on both — the listing is the only oracle.
- **B2/B3** — `<Files>` hides on both; no guard lists on both.
- **C1** — the per-directory rewrite replayed by `multiview_rewrite_outcome`
  was probed separately: `RewriteRule ^name\ with\ space\.txt$ - [F]` denies
  on both servers, so this surface was not promoted (see P34-O1).

---

## 4. Preconditions and blast radius

- **Precondition:** `Options MultiViews` is effective and one sibling
  representation's name contains a character that `url_encode_path`
  percent-encodes (space, non-ASCII, `%`, `"`, `<`, `>`, `\`, `^`, backtick,
  `{`, `|`, `}`, `[`, `]`, `?`, `#`); a URL-scoped `<Location>` or
  `<LocationMatch>` rule spelled with the decoded name guards the file. The
  autoindex vector additionally needs `Indexes` on the directory.
- **Guards that fail open:** decoded-spelling `<Location>` prefixes and
  `<LocationMatch>` patterns (literal or backslash-escaped space, and
  non-ASCII spellings) for negotiated representations and for autoindex
  entries.
- **Not affected:** candidate-bound `<Files>`/`<FilesMatch>` rules,
  `<Directory>` rules, resolved-inode reauthorization, `\.txt$`-style
  patterns without encoded characters, per-directory rewrite re-binding, and
  the dynamic-handler refusal — the P33 candidate conjoin and handler checks
  still bind, and C1/A4/A5/B2 deny on both servers.
- **Blast radius:** unauthenticated read of exactly the representation the
  URL rule protects, plus disclosure of a denied entry's listing metadata.
  The stock Debian `Alias /javascript` and userdir shapes enable MultiViews
  (case A7);
  international or space-bearing content filenames make the guard trigger
  ordinary rather than exotic.
- **Attacker cost:** one unauthenticated `GET` (or one listing request); no
  body, no state, no credential.

---

## 5. Relationship to prior passes

- **P33-A** synthesized a selected-representation URL and evaluated
  `Location`, rewrite and cache identity against it. That fix is the mechanism
  under test here: its unit test freezes the encoded spelling
  (`multiview_selected_url("/name", b"name with space.txt") ==
  "/name%20with%20space.txt"`, `crates/server/src/server.rs:10883`), so the
  encoding choice was deliberate — but it disagrees with the decoded identity
  used everywhere else in the pipeline and with Apache. The
  `docs/adversarial-closure.md` P33-A row records the "URL-encoded
  `/name.ext` identity" as the remediation; this pass shows the encoding must
  not be the policy identity.
- **F57** established that path policy must authorize the dispatcher's
  decoded, normalized URL rather than the raw wire spelling; P34-A is the
  same invariant applied to synthesized identities.
- **P25-A** and its regression suite cover trailing-slash spellings of
  direct files; P34-A is the negotiated-representation counterpart where the
  spelling difference is encoding rather than a slash.
- **The `7209f0e` information-disclosure campaign** crosses
  policy phases with URL spellings, but its fixtures use URL-safe ASCII names
  (`secret.txt`, `index.html`, ...), so it cannot observe this class.

---

## 6. Remediation direction (not applied in this pass)

1. Synthesize policy identities in the pipeline's decoded path form:
   `multiview_selected_url()` should return the decoded selected name, and
   `authorized_autoindex_entries()` should authorize the decoded entry path.
   Keep `url_encode_path` only at wire serialization points
   (`Content-Location` at `crates/server/src/server.rs:8258` and listing
   `href`s at `crates/server/src/files.rs:2192`).
2. Add a regression that negotiates a representation whose name contains a
   space, a non-ASCII character and a literal `%`, with decoded-spelling
   `Location`/`LocationMatch` denies for both the body and the listing, plus
   the encoded-spelling mirror and `<Files>` controls.
3. Optionally assert the identity form at the `AuthorizedPlan` boundary so a
   future transform cannot introduce a wire-encoded policy subject.

---

## 7. Reproduction

```sh
cd /root/httpd-rs
cargo build --release -p httpd-rs
python3 adversarial/p34/exploit_p34.py            # eleven cases; exits 1 if P34-A is fixed
python3 adversarial/p34/exploit_p34.py --keep     # retain fixtures and server logs
```

The harness binds Apache and httpd-rs to separate loopback ports in the
`30600`/`30700` ranges, uses the real `/usr/sbin/apache2` 2.4.69 oracle, and
removes its temp tree unless `--keep` is given.

### Reviewed without a finding (P34-O observations)

- **P34-O1** — the P33 access-file rewrite re-binding
  (`multiview_rewrite_outcome`) was probed with
  `RewriteRule ^name\ with\ space\.txt$ - [F]` under `AllowOverride FileInfo`
  + `HttpdRsCapability AccessFiles On`: both servers return `404`. No
  divergence was established, so the replay path is not affected (case C1).
- **P34-O2** — the WebSocket upgrade authorization added by `a52eb76` was
  probed with `<Location "/ws">` and `<LocationMatch "^/ws$">` denies around
  `ProxyPass /ws http://127.0.0.1:<backend>/`. Both servers return `403`
  with zero backend connections; with no guard both reach the backend. No
  divergence was established.

---

## 8. Retained files

- `adversarial/p34/exploit_p34.py` — eleven-case Apache/httpd-rs reproducer;
  exits non-zero when the divergences are no longer present (future
  regression battery).
- `adversarial/p34/results_p34.txt` — retained HEAD run output.
- `/tmp/opencode/p34-harness/` — per-case configs, fixture trees and server
  logs when `--keep` is used.
