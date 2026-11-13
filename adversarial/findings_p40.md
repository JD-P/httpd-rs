# Pass 40 — Basic-auth usernames are enumerable through bcrypt response timing

- **Date:** 2026-11-13
- **Subject:** HEAD `3b9620a1bc91713f0f08feb172f72b0de7bbc02b`
  (`target/release/httpd-rs`, rebuilt from the clean checked-out product tree;
  no product source was edited).
- **Harness:** `adversarial/p40/exploit_p40.py`, loopback only; three retained
  release-binary runs in `adversarial/p40/results_p40.txt`.
- **Method:** recovery-ledger/family review followed by source audits of
  HTTP/2 control-frame accounting, internal authentication identity,
  terminal pathname admission, response-policy ordering and the Basic-auth
  verifier. The confirmed candidate was measured with alternating fresh
  connections after warming the parsed authentication-file cache.
- **Disposition:** **P40-A confirmed and unfixed at HEAD.**

---

## 1. Executive summary

| # | Finding | Failure-response control | httpd-rs at HEAD | Class |
|---|---|---|---|---|
| **P40-A** | Basic authentication returns before password verification when a username is absent, but runs the account's full adaptive password verifier when the username exists. An unauthenticated client can enumerate usernames from latency alone. | Missing-user and known-user/wrong-password requests return byte-equivalent stable responses: status `401`, the same non-Date headers and the same 318-byte body. A correct-password control returns the protected marker with status `200`. | With one cost-12 bcrypt account and seven alternating samples per candidate, the missing-user median was 0.956–1.324 ms while the known-user/wrong-password median was 244.043–258.368 ms across three runs: a 192.7×–270.2× signal. The complete retained exploit took 2.169 seconds in the timed run. | low information disclosure (CWE-208 class) |

---

## 2. P40-A — account existence controls whether bcrypt runs

### 2.1 Root cause

The authentication path validates the Basic grammar and then uses an
`Option`-propagating lookup before entering any password-verification path:

```rust
// crates/server/src/auth.rs:59-62
let file = scope.authorization.auth_user_file.as_ref()?;
let stored = lookup_user(file, user, mutable_auth_files)?;
if !verify_password(password, &stored) {
    return None;
}
```

`lookup_user` returns `None` immediately when the parsed file has no matching
key (`auth.rs:376-379`). For a present bcrypt record, `verify_password`
validates the cost, acquires the expensive-operation lease, and calls the
adaptive verifier (`auth.rs:426-445`). Cost 12 deliberately makes each wrong
password expensive; absence avoids that work entirely.

The digest comparisons themselves use constant-time equality where
appropriate. That does not close this oracle because the attacker is
distinguishing *whether a verifier runs*, not two digest values within the
same verifier.

### 2.2 Live reproduction

The retained harness builds a minimal standalone deployment with:

- one `AuthUserFile` entry for `alice`, encoded by Apache `htpasswd -B -C 12`;
- `Require valid-user` on `/private/secret.txt`;
- an authentication database outside the document root, so P39-A is not in
  the exploit path; and
- `MutableAuthFiles` solely because the unprivileged temporary fixture is
  service-owned.

It warms the parsed-file cache, then alternates seven fresh-connection requests
for nonexistent `nobody` and configured `alice`, both with the same wrong
password. The second retained run produced:

```text
missing_user_median_s=0.000956
known_user_wrong_password_median_s=0.258368
median_timing_ratio=270.2x
failure_responses_byte_equivalent=True
failure_status=401 body_len=318
valid_password_status=200 body=b'P40 protected resource\n'
```

The timed third run completed the full 14-failure-probe plus successful-login
sequence in 2.169 seconds and retained a 251.1× median ratio. The alternating
order avoids assigning monotonic host-load drift to one candidate, and the
same result reproduced independently three times.

### 2.3 Impact and severity

- **Primary family:** `information_disclosure`.
- **Impact tier:** low. Account names are authentication metadata and the
  roughly quarter-second local gap is large enough to survive ordinary network
  jitter with repeated samples. Enumeration reduces password guessing and
  credential-stuffing from a username-and-password search to known accounts.
  The reproducer does not recover a password, bypass authentication or read
  the protected resource without the valid credential, so medium or high
  would overstate the demonstrated result.
- **Preconditions:** Basic authentication backed by an `AuthUserFile` with an
  expensive verifier (bcrypt is the retained normal `htpasswd` shape), and
  repeated unauthenticated requests to the protected URL. No malformed request,
  credential or prior authorization is required.
- **Unintended behavior count:** 1. Account absence bypasses the complete
  password-verification work class, making existence observable.
- **Remediation component count:** 1. Make username lookup and password
  verification one non-enumerating credential-check boundary.

### 2.4 Remediation boundary

The robust fix must equalize *work selection*, not merely use constant-time
digest comparison:

1. At authentication-file load, retain a generation-bound dummy verifier for
   the accepted password-hash class and cost.
2. For every syntactically valid Basic credential, select either the real
   verifier or the dummy without returning early, then execute the same
   expensive-operation admission and one comparable verification path.
3. Either require a uniform verifier class/cost within one authentication
   database or pad cheaper records to a declared file-level work class;
   otherwise mixed bcrypt costs or legacy hashes remain account oracles.
4. Keep dummy verification inside the existing process/per-source expensive
   work budget, and make budget exhaustion indistinguishable for present and
   absent users. Closing the oracle must not create an unbounded bcrypt DoS.
5. Add distributional regressions for missing, present-wrong and malformed
   accounts across bcrypt and the supported legacy formats. A unit test that
   compares only returned booleans cannot observe this defect.

---

## 3. Negative observations

The pass rejected several candidates rather than turning hardening debt or
compatibility behavior into findings:

- `RST_STREAM` is absent from the vendored h2 *control-frame* token bucket,
  but it is not unbounded: the universal codec budget charges four units per
  reset against a 131,072-unit burst and 65,536-unit/second refill (32,768
  reset burst, roughly 16,384 resets/second sustained), while pending-accept
  resets have an additional stream limit. A stricter reset bucket is sensible
  hardening, but this pass did not demonstrate availability loss past the
  existing bound and does not duplicate P38-E.
- The authenticated identity carried across a canonical target or balancer
  failover does not authorize that target by itself. The target independently
  passes `access::check`; inherited identity is retained only after that check
  allows the target or requests authentication under the target scope.
- MultiViews appends its negotiation metadata after the ordinary response
  header policy, but a live Apache 2.4.69 control behaved the same: ordinary
  `Header unset Content-Location`/`TCN` did not remove those fields, and
  `Header set Vary Origin` combined with the negotiation `Vary`. No security
  differential was retained.

These observations are not proof that the reviewed surfaces are bug-free.
