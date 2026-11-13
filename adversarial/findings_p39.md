# Pass 39 — Configured access and authentication files reach the public static-file sink

- **Date:** 2026-11-13
- **Subject:** HEAD `37f9f3f3df11a21e1f0f0613d89d5d5ecaf86b6f`
  (`target/release/httpd-rs`, rebuilt from the clean checked-out tree; no
  product source was edited).
- **Harness:** `adversarial/p39/exploit_p39.py`, loopback only; retained output
  in `adversarial/p39/results_p39.txt`.
- **Method:** recovery-ledger/family review, source audit of underexplored
  administrative-input and terminal-sink identities, then a live deployment
  reproduction in the repository's Hugo/access-file shape.  Side audits of
  CGI/FastCGI environment projection, cache identity, RewriteMap helpers,
  TLS peer identity and proxy serialization did not produce another confirmed
  finding.
- **Disposition:** **P39-A confirmed and unfixed at HEAD.**

---

## 1. Executive summary

| # | Finding | Control | httpd-rs at HEAD | Class |
|---|---|---|---|---|
| **P39-A** | Files already classified as active request policy (`AccessFileName`) or authentication databases (`AuthUserFile`/`AuthGroupFile`) are not excluded from the `StaticFile` terminal sink.  A standalone deployment can therefore publish `.htaccess`, `.htpasswd`, or a custom-named equivalent from its document root. | The protected resource returns `401` without credentials.  Apache's shipped baseline explicitly denies `.ht*`; httpd-rs's standalone deployment helper contains no corresponding guard. | `GET /.htaccess` returns the active policy; `GET /.htpasswd` returns the exact database protecting the `401` resource.  A four-word offline dictionary recovers the project-style `{SHA}` credential and the same client then reads the protected resource with status `200`. | high information disclosure; secondary authority bypass |

This is one root cause and one finding.  The policy file and password database
are two consequences of the same missing administrative-input projection at
the static sink.

---

## 2. P39-A — administrative inputs are also treated as public content

### 2.1 Reachability in a typical repository deployment

The Hugo deployment creates a mode-0644 access file **inside** its document
root and enables `AllowOverride FileInfo`:

```python
# tests/deployments/scenarios/hugo-static/driver.py:109-115,151-168
access_file = document_root / ".htaccess"
access_file.write_text(
    "RewriteEngine On\n"
    "RewriteRule ^legacy$ /posts/hello/ [R=302,L]\n"
    "Header set X-httpd-rs-Deployment hugo\n"
)
...
<Directory "{document_root}">
    AllowOverride FileInfo
    Require all granted
</Directory>
```

Its standalone configuration constructor grants the document root but does
not carry Apache's ordinary `.ht*` denial (`tests/deployments/lib.py:923-964`).
The fixture verifies that `.htaccess` affects responses, but never requests
the file itself.  Against HEAD, the exact shape returns the complete file with
status 200.

The stronger retained case makes `.htpasswd` the exact `AuthUserFile` for a
private directory.  That layout is legacy but realistic: Apache's shipped
configuration contains the following baseline specifically so such files are
not web-visible (`httpd.conf.in:169-175`):

```apache
# The following lines prevent .htaccess and .htpasswd files from being
# viewed by Web clients.
<Files ".ht*">
    Require all denied
</Files>
```

httpd-rs is frequently run from a standalone/minimal configuration rather
than through Apache's complete distro configuration, so that inherited
baseline cannot be assumed.

### 2.2 Root cause

The configuration compiler already owns the relevant identities:

- `Config::access_file_names_for` returns the effective configured policy-file
  names (`config.rs:18507-18513`), and the access walk opens those exact files
  as executable request policy (`htaccess.rs:198-225`).
- `AuthUserFile` and `AuthGroupFile` are canonicalized and retained in
  `cfg.auth_file_targets` (`config.rs:8588-8610`); startup validates them as
  authentication databases.

Those classifications never reach the terminal content decision.  Once the
same pathname is URL-mapped and passes the ordinary directory grant, dispatch
unconditionally mints a `TransformSink::StaticFile` outcome for GET/HEAD and
serves it (`server.rs:8694-8725`).  There is no predicate asking whether the
target is an effective access file or a registered authentication database.

This is not an Apache parser-semantic differential: Apache with an equally
stripped configuration also serves the files.  It is a missing security
baseline/typed-sink invariant in standalone httpd-rs.  The distinction matters
because the migration target does not automatically inherit Apache's shipped
`<Files ".ht*">` rule, while the repository's own deployment constructor
demonstrates that exact standalone posture.

### 2.3 Live result and demonstrated impact

`adversarial/p39/exploit_p39.py` starts the rebuilt release binary on loopback
with:

- an active `.htaccess` in the document root;
- an active `.htpasswd` in the document root;
- `AuthType Basic` and that exact `AuthUserFile` protecting
  `/private/secret.txt`; and
- the explicit `AccessFiles` and `MutableAuthFiles` capabilities.

The retained output is:

```text
public_control=200 body=b'P39 public control\n'
access_file=200 body=b'RewriteEngine On\n...P39-ACCESS-POLICY-SECRET-7b21\n'
auth_file=200 body=b'alice:{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=\n'
protected_without_auth=401
dictionary_recovered_password='secret'
protected_with_recovered_auth=200 body=b'P39-PROTECTED-RESOURCE-7b21\n'
RESULT: VULNERABLE — configured administrative inputs reached StaticFile
```

Thus the public response is not merely a filename oracle.  It returns the
complete live password database; the repository-style unsalted SHA fixture is
cracked offline, and the recovered credential crosses the otherwise working
Basic-auth boundary and returns the protected marker.

Real access files can disclose internal rewrite destinations, filesystem
layout, authorization rules, environment values and application configuration.
Authentication databases disclose usernames and password verifiers even when
the password is strong enough to resist the tiny demonstration dictionary.

### 2.4 Severity and composition

- **Primary family:** `information_disclosure`.
- **Secondary family:** `authority_bypass` (the retained credential-recovery
  chain reaches a resource whose no-credential control is 401).
- **Impact tier:** high.  Exploitation is an unauthenticated GET and the
  disclosed object is live security policy or a credential database.  It is
  not critical because in-tree placement is required and practical credential
  recovery depends on verifier/password strength.
- **Unintended behavior count:** 1.  The one implementation error is that a
  pathname already classified as an administrative input is still admitted to
  `StaticFile`.  A weak demonstration password is an environmental exploit
  precondition, not a second implementation behavior.
- **Remediation component count:** 1.  Project administrative-input identity
  into terminal local-file admission and deny the static sink for effective
  access files and configured auth databases.

### 2.5 Remediation and regression boundary

The robust fix is a sink invariant, not a name blacklist:

1. Bind effective `AccessFileName` candidates plus registered
   `AuthUserFile`/`AuthGroupFile` identities into request planning.
2. Refuse `StaticFile`, DirectoryIndex, local ErrorDocument and cache
   publication when the resolved inode/path is one of those administrative
   inputs.  Preserve the denial through aliases, symlinks, rewrites and
   internal requests.
3. Also add Apache's `.ht*` guard to generated standalone/example
   configurations as defense in depth, but do not rely on it: custom
   `AccessFileName` and auth database names need identity-based protection.
4. Add H1/H2 regressions for `.htaccess`, a custom access filename,
   `AuthUserFile`, `AuthGroupFile`, aliases, cache lookup/store and an explicit
   ordinary dotfile control that remains serveable when it is not an
   administrative input.

---

## 3. Negative observations

The pass began with less-explored cryptographic and composed dynamic paths.
No additional claim is recorded for these observations:

- CGI and FastCGI share a builder that explicitly drops `Proxy`, closing the
  classic `HTTP_PROXY`/httpoxy path.
- Cache lookup/store excludes credential-bearing requests and binds the
  complete request header set plus `Vary` dimensions into its policy identity.
- Proxy TLS validates both trust and destination name; the retained tests
  include a trusted-certificate/wrong-name rejection.
- RewriteMap `prg:` helpers are bounded by time, output, concurrency, process
  isolation and a sealed executable identity.  Request path/query control
  bytes are rejected before they can become a line-protocol key.
- The reviewed TLS/mTLS path keeps listener-wide client-certificate policy,
  negotiated identity and reload generations explicitly bound.  No
  cryptographic trust failure was reproduced.

These are negative observations, not proof that the surfaces are bug-free.
