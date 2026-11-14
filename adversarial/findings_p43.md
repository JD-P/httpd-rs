# Pass 43 — reverse-proxy certificate candidates escape the TLS work budget

- **Date:** 2026-11-14
- **Subject:** HEAD `1c94f127992345d4017fd2d404a4e60a3b45f6c1`
  (`target/release/httpd-rs` rebuilt from the clean reviewed tree before the
  evidence-only Pass-43 files were created).
- **Harness:** `adversarial/p43/exploit_p43.py`, release daemon and HTTPS
  backend on loopback only; retained measurements in
  `adversarial/p43/results_p43.txt`.
- **Method:** reviewed the remaining explicit dependency/kernel assumptions
  after the inbound TLS/mTLS calibration, audited the corresponding outbound
  trust boundary, then varied a backend certificate chain's repeated issuer
  count while holding requests, concurrency, source identity, algorithm and
  response behavior fixed.
- **Disposition:** **P43-A confirmed at the reviewed HEAD and remediated in
  the product tree on 2026-11-14.**

---

## 1. Executive summary

| # | Finding | Intended bound | httpd-rs at HEAD | Class |
|---|---|---|---|---|
| **P43-A** | Reverse-proxy TLS declares every handshake to cost one work unit based only on the configured host name. It neither caps the backend's presented certificate count nor acquires the weighted TLS CPU/rate lease used for inbound TLS. | One source may own at most 8 of 64 dynamic backend operations; variable dependency work is required to have an input/work/workspace bound under a live owner. | A backend repeats one public P-384 intermediate after an invalid leaf. Sixty-four small requests from one source at concurrency 8 consume 5.22–5.80 daemon CPU-seconds in 1.36–1.49 seconds, versus 0.04–0.07 CPU-seconds for a valid one-intermediate control. Every attack request correctly returns 502, but the one source consumes roughly four cores. | medium denial of service; certificate-path work is asserted constant and left outside weighted resource admission |

---

## 2. P43-A — backend certificate multiplicity is priced as one host-name operation

### 2.1 The outbound dependency boundary does not describe its input

The reverse-proxy TLS boundary supplies constants for work and workspace. Its
only variable input is the **configured host-name length**:

```rust
// crates/server/src/proxy.rs:47-56
dependency_call_admit(
    true,
    host.len() as u64,
    MAX_TLS_SERVER_NAME_BYTES,
    1,
    1,
    TRANSPORT_BUFFER_CHARGE,
    TRANSPORT_BUFFER_CHARGE,
)
```

This is a pure predicate. It does not acquire a TLS CPU/rate or dependency-
workspace lease, and no client-side certificate verifier limits the count or
aggregate DER bytes supplied by the upstream. The ordinary dynamic-backend
lease limits live exchanges to 64 process-wide and 8 per client, but prices
each exchange equally regardless of the cryptographic work it performs.

The newest inbound TLS path has the missing shape: it rejects more than eight
presented client certificates or 65,535 aggregate DER bytes before webpki,
selects ordinary versus mTLS work units, and acquires a weighted concurrency,
rate and workspace owner. None of that profile is used by the outbound
`ClientConnection` at `proxy.rs:3129-3146`.

HTTPS upstreams are deliberately not put in the connection-local reuse pool
(`proxy.rs:4202-4215`), so every admitted proxied request performs another
handshake. The configured endpoint and TLS name remain correctly bound; the
failure is resource pricing, not routing identity.

### 2.2 A backend needs no trusted private key

The exploit does not forge a valid certificate and does not need cooperation
from the configured CA. Its backend:

1. creates a P-384 leaf whose issuer name is copied from one ordinary trusted
   intermediate, but signs that leaf with the backend's own leaf key;
2. proves possession of that leaf key in the TLS handshake; and
3. repeats the **public bytes of the same legitimate intermediate** in the
   certificate list.

For each repeated entry, rustls-webpki treats the subject as a potential
issuer, builds the candidate path and performs the expensive signatures before
the invalid leaf signature rejects that path. The dependency iterates the
complete intermediate slice at `verify_cert.rs:120-147`. Its own defensive
budget permits 100 signature checks (`verify_cert.rs:305-347`), so it
eventually fails safely rather than looping forever. That internal ceiling is
nevertheless about two orders of magnitude above httpd-rs's declared one-unit
cost and is independently spendable by every live proxy request.

The 64-entry chain is about 31.5k DER bytes on the wire, below rustls's
handshake-message ceiling. Duplicating a public certificate is sufficient;
the backend does not generate 64 keys or obtain 64 CA certificates.

### 2.3 Live release-daemon measurements

The harness starts a normal `ProxyPass` to a loopback HTTPS backend with
`SSLProxyCACertificateFile`, warms the root store, and sends 64 small GETs
from one effective client with concurrency 8. The control uses the same
P-384 keys, route, request count and concurrency but presents one valid
intermediate and returns `200 P43-OK`.

The candidate-count sweep was:

| Repeated intermediates | Attack status | Daemon CPU | Wall time | CPU/request |
|---:|---:|---:|---:|---:|
| 8 | 64 × 502 | 0.84 s | 0.240 s | 13.12 ms |
| 32 | 64 × 502 | 3.25 s | 0.874 s | 50.78 ms |
| 64 | 64 × 502 | 5.22 s | 1.358 s | 81.56 ms |

The corresponding 64-request one-intermediate control consumed 0.04 CPU-
seconds in 0.053 seconds. An independent finalized run measured 5.80 versus
0.07 CPU-seconds and 1.494 versus 0.057 seconds. RSS high-water growth was
12,584 KiB versus 9,276 KiB; CPU, not retained memory, is the dominant impact.

The runner exposes five cores. Thus one source staying at the intended
eight-operation share consumed approximately 3.8 cores continuously during
the wave. Repeating the wave maintains that load while unrelated clients can
still acquire nominal dynamic slots whose CPU capacity has disappeared. The
invalid chain is correctly rejected and the daemon stays alive; fail-closed
trust behavior does not make the resource escape harmless.

### 2.4 Reachability, impact and severity

- **Primary family:** `denial_of_service`.
- **Impact tier:** medium. A malicious or compromised HTTPS upstream and one
  ordinary downstream client can consume most of a five-core daemon while
  remaining within the source's eight-operation dynamic share. An on-path
  endpoint able to complete TCP and present TLS records can cause the same
  verification work even though certificate validation ultimately rejects
  it. The demonstrated capacity loss is substantial, but high would overstate
  general remote exploitability: an ordinary Internet client cannot select or
  impersonate the configured backend, and the attack additionally needs
  downstream requests to make httpd-rs connect. HTTP-only/static deployments
  and uncompromised, non-intercepted upstreams are unaffected.
- **Unintended behavior count:** 2. The outbound verifier admits unbounded-by-
  application certificate multiplicity under a constant work claim, and the
  claim is not coupled to any weighted TLS concurrency/rate owner.
- **Remediation component count:** 2. Bound the presented server-certificate
  shape before path construction, then acquire a conservative algorithm/shape
  weighted handshake lease for every proxy and health-check TLS path.

### 2.5 Remediation and regression boundary

1. Wrap the default server-certificate verifier exactly as the inbound
   `BoundedClientCertVerifier` wraps client verification. Reject more than a
   small fixed certificate count and reject aggregate DER above the selected
   profile before delegating to webpki. Duplicate entries must count; silently
   deduplicating them is optional defense in depth, not the primary bound.
2. Define an executable outbound TLS dependency profile over certificate
   count/bytes, signature family and the dependency's worst-case path budget.
   Acquire process/source weighted CPU, rate and workspace leases before
   verification. The synchronous `StreamOwned` path must retain the owner
   until its lazy handshake finishes; the async connector must retain it
   through `connect().await`.
3. Cover ordinary proxy, WebSocket-over-TLS and active HTTPS health checks.
   Health checks need a process-owned rate budget even though they have no
   downstream source identity.
4. Add a matrix over 1/8/limit/limit+1 certificates, duplicate and distinct
   candidates, P-256/P-384/RSA, valid and invalid terminal chains, and H1/H2
   downstream requests. Assert rejection occurs before excessive dependency
   work and that every lease returns to zero.
5. Reusing already-validated HTTPS upstream connections under the existing
   exact backend/generation/request identity is useful defense in depth, but
   must not substitute for bounding a first or failed handshake.

### 2.6 Remediation status

The outbound verifier now enforces the same proved shape envelope before
webpki that the inbound mTLS boundary uses: at most eight total certificates
and 65,535 aggregate DER bytes, with duplicates counting independently. An
admitted chain costs one work unit per certificate plus one per 8 KiB of DER,
up to a Verus-proved sixteen-unit maximum. The verifier acquires the shared
process/source TLS concurrency, rate and dependency-workspace owner before
delegating to webpki and retains it through signature verification and
handshake completion.

The owner is scoped to each synchronous proxy/health handshake or asynchronous
WSS task while the verifier itself remains generation-cached. That distinction
preserves rustls session resumption: rustls intentionally disables resumption
when successive connections install different verifier `Arc`s. Active health
checks use a process-only context, so they share the process ceiling without
inventing a downstream source identity.

The original release harness now reports 64/64 successful `200` control
requests in 0.057 seconds and 0.06 daemon CPU-seconds, matching the pre-fix
0.04–0.07 CPU-second range. The 64-candidate attack is rejected 64/64 with
`502` in 0.110 seconds and 0.06 CPU-seconds, down from 5.22–5.80 CPU-seconds.
The largest admitted adversarial shape (seven repeated intermediates plus the
leaf) consumed 0.25 CPU-seconds for the 64-request wave; shape-weighted source
admission allowed only the bounded prefix to enter webpki. Retained output is
in `adversarial/p43/results_p43_remediation.txt`.

---

## 3. Negative observations

- The adversarial chain is not accepted: every attack request returns 502,
  while the valid-chain control returns the exact backend marker. No
  cryptographic trust failure was demonstrated.
- Backend address pinning and TLS server-name validation remain intact; the
  harness does not select a request-derived destination and is not SSRF.
- The recently added inbound client-certificate count/byte cap rejects this
  multiplicity before webpki. P43-A is the separate outbound client-verifier
  path and is not a duplicate of the inbound TLS calibration.
- The retained sweep found linear CPU scaling up to webpki's signature-check
  ceiling, not material retained-memory growth or a process crash.

These observations are not proof that the other TLS and proxy surfaces are
bug-free.
