# Pass 44 — large SSHA salts escape Basic-auth CPU accounting

- **Date:** 2026-11-15
- **Subject:** release `v0.2.3`, commit
  `35b12a59e9cbceaf4fd5e29dc0ba2acdcd4ec7b6` (`target/release/httpd-rs`
  rebuilt from the clean reviewed product tree before final measurement).
- **Harness:** `adversarial/p44/exploit_p44.py`, release daemon on loopback
  only; retained measurements in `adversarial/p44/results_p44.txt`.
- **Method:** treated closure classifications in the new resource inventory
  as hypotheses, rejected the already-bounded HTTP/2 continuation path, then
  compared each Basic-auth verifier's complete configured input shape with its
  live concurrency/rate owner. The SSHA candidate was measured against an
  eight-byte-salt control while request bytes, source, concurrency, verifier
  family and response behavior remained fixed.
- **Disposition:** **P44-A confirmed at the reviewed release and remediated in
  the product tree on 2026-11-15.**

---

## 1. Executive summary

| # | Finding | Intended bound | httpd-rs v0.2.3 | Class |
|---|---|---|---|---|
| **P44-A** | `{SSHA}` accepts a salt almost as large as the 4 MiB authentication file and hashes it on every Basic-auth attempt without acquiring an expensive/auth CPU concurrency or rate lease. P40's uniform missing-user verifier makes the work reachable with any syntactically valid credential. | Every attacker-triggerable variable-cost request-path operation must have an input/work bound under process/source ownership; adaptive password work already has 32/8 operation and weighted bcrypt/rate ceilings. | One source sent 2,048 exact 110-byte requests at concurrency eight. A 3.1 MB salt consumed 4.05–4.09 daemon CPU-seconds in 1.26–1.32 seconds (about three cores), versus 0.32–0.41 CPU-seconds for an eight-byte salt. All requests returned 401. The verifier hashed 6.35 GB from 225 KB of request input, about 28,182× byte amplification. | low denial of service; unpriced configured-input amplification behind an extraordinarily abnormal operator-supplied record |

---

## 2. P44-A — the auth-file byte bound becomes per-request hash work

### 2.1 SSHA has no cryptographic shape bound

The file reader rejects an `AuthUserFile` above 4 MiB, but the SSHA parser
uses the remainder of one decoded record as a salt without a scheme-specific
limit:

```rust
// crates/server/src/auth.rs:24,185-200
const MAX_PASSWORD_FILE: u64 = 4 * 1024 * 1024;

if let Some(encoded) = stored.strip_prefix("{SSHA}") {
    let decoded = STANDARD.decode(encoded) ...?;
    if decoded.len() < 20 { return None; }
    let digest = <[u8; 20]>::try_from(&decoded[..20]).ok()?;
    let salt = Box::<[u8]>::from(&decoded[20..]);
    ... Self::SaltedSha { digest, salt }
}
```

Base64 expansion still leaves room for about 3.15 MiB of decoded material in
one admitted record. The retained fixture uses a 3,100,000-byte salt and a
4,133,373-byte file. It passes startup validation and the same bounded runtime
reader used for mutable authentication databases.

That file-size ceiling safely bounds retained input memory. It is not a bound
on repeated request work: the cached salt is fed to SHA-1 again for every
credential attempt.

### 2.2 The variable input bypasses password-work admission

The verification branches have materially different resource contracts:

```rust
// crates/server/src/auth.rs:250-279
Self::Sha(expected) => Sha1::digest(password) ...,
Self::SaltedSha { digest, salt } => {
    let mut h = Sha1::new();
    h.update(password);
    h.update(salt);
    ...
}
Self::Md5Crypt { ... } => {
    let Some(_expensive) = crate::resource::try_expensive() else { ... };
    ...
}
Self::Bcrypt { stored, cost } => {
    let Some(_expensive) = crate::resource::try_bcrypt(*cost, password.len() as u64) ...;
    ...
}
```

MD5-crypt first limits its salt to eight bytes and acquires the general
expensive-operation owner. Bcrypt validates its cost and acquires both the
general operation lease and a cost-weighted bcrypt concurrency/rate lease.
SSHA does neither even though its configured salt is the largest variable
input to any branch.

The ordinary request-rate ceilings are deliberately set above same-host
throughput (`500,000` requests per client per second) and are not a CPU-work
bound. By comparison, the expensive-work rate gate permits 64 operations per
source per second. The retained attack completed at roughly 1,550–1,627
requests per second—well below the generic request gate, far above the CPU
gate that the verifier bypasses.

P40's timing fix makes the path available without knowing an account name.
`PasswordDatabase::select` returns the database's uniform dummy verifier for a
missing user (`auth.rs:285-317`), and `authenticate` deliberately executes it
before returning 401 (`auth.rs:59-66`). That behavior is correct for timing
uniformity; the bug is that the selected verifier has no sound work profile.

### 2.3 Live release measurement

The harness starts the released daemon twice with one valid uniform SSHA
database. The control uses an eight-byte salt and the candidate uses
3,100,000 bytes. It warms both servers, then sends 2,048 identical raw HTTP/1
requests from `127.0.0.2` with eight concurrent clients. Every request is
exactly 110 bytes and names a missing user, and every response is 401.

Three independent runs measured:

| Salt | Responses | Daemon CPU | Wall | Candidate/control CPU |
|---:|---:|---:|---:|---:|
| 8 bytes | 2,048 × 401 | 0.32–0.41 s | 0.324–0.393 s | — |
| 3,100,000 bytes | 2,048 × 401 | 4.05–4.09 s | 1.259–1.320 s | 9.90×–12.78× |

The candidate hashes 6,348,800,000 configured bytes in response to 225,280
request bytes: 28,181.8 times as many bytes, before counting response traffic.
CPU divided by wall time is approximately 3.1 cores throughout the wave. The
server remains alive because this is sustained unaccounted work rather than a
panic; repeating the wave maintains the capacity loss.

### 2.4 Reachability, impact and severity

- **Primary family:** `denial_of_service`.
- **Impact tier:** low. Once the configuration exists, an ordinary
  unauthenticated client can consume roughly three cores with eight-way
  concurrency and about 170–179 KiB/s of request traffic. However, the client
  cannot create or select the expensive input. Exploitation first requires an
  operator to install a conspicuous, nonconventional SSHA record with a 3.1 MB
  salt. Conventional SSHA salts and non-SSHA deployments are unaffected, and
  no persistence, crash or security-boundary bypass was demonstrated.
- **Unintended behavior count:** 1. SSHA's complete request-time input/work
  shape is treated as though the 4 MiB file-retention cap were a sufficient
  per-verification CPU bound; no scheme cap or weighted owner constrains it.
- **Remediation component count:** 1. Give SSHA a sound, startup-validated
  salt/work profile before the verifier becomes request-reachable. A strict
  small salt cap proves the operation constant; retaining large salts instead
  requires byte-weighted concurrency and rate ownership.

### 2.5 Remediation and regression boundary

1. **Implemented:** the common parser caps the encoded record before decoding,
   then `ssha_salt_admit` caps the decoded salt at 64 bytes for startup
   validation and mutable-file reloads. A 64-byte salt remains accepted; a
   65-byte salt fails closed before the verifier becomes request-reachable.
   This makes `password + salt` a small proved input and adds no request-path
   throttle or slowdown.
2. If compatibility requires longer salts, derive work units from the complete
   `password.len() + salt.len()` input and acquire a process/source/request
   auth-hash rate and concurrency owner before hashing. Do not charge only the
   request-supplied password.
3. Extend the password-profile uniformity rule to include the bounded work
   profile, so the real and dummy verifier remain timing-equivalent without
   allowing an account record to select unowned work.
4. Add a matrix over `{SHA}`, `{SSHA}` at zero/ordinary/limit/limit+1 salt,
   APR1, Unix MD5 and bcrypt. Assert admitted verifier input/work bounds,
   unknown/known-user response equivalence, the CPU-ledger high-water value,
   rate rejection, and release to zero.

The product regression covers the inclusive 64-byte boundary, startup
rejection, mutable-file fail-closed behavior and the executable Verus
admission predicate. The retained release harness now recognizes rejection of
the oversized record as `RESULT: REMEDIATED`.

---

## 3. Negative observations

- The vendored HTTP/2 decoder already rejects HEADERS/CONTINUATION sequences
  above an encoded-byte ceiling or a derived continuation-frame ceiling, in
  addition to decoded-list and connection frame-work limits. The initial
  pre-dispatch accumulation hypothesis was not retained.
- Plain `{SHA}` has no variable configured suffix. APR1 and Unix MD5 salts are
  capped at eight bytes, while bcrypt cost and password bytes enter weighted
  admission. The demonstrated multi-megabyte request-time input is specific
  to SSHA.
- Auth-file reads, parsed-cache bytes and parsed-cache cardinality are bounded.
  P44-A does not claim retained-memory growth.
- Known and missing usernames both select one uniform verifier and return the
  same 401 behavior. No authentication bypass, password oracle or response
  differential was demonstrated.

These observations are not proof that the remaining authentication or
resource-accounting surfaces are bug-free.
