# TLS/mTLS dependency resource profile

This profile closes the request-reachable rustls/webpki resource shape without
claiming that certificate-chain validation itself is verified.  The local-only
harness is `adversarial/tls_dependency_profile.py`.  It creates valid chains
whose intermediates share one subject, puts the real issuer last, optionally
adds dense name constraints and SANs, and runs fresh TLS 1.3 handshakes against
the release daemon.  It records wall time, daemon CPU, RSS/high-water and
success/failure while varying:

- ordinary TLS versus required mTLS;
- 1, 4, 8, 16 and 32 presented intermediates;
- 0 or 128 name constraints and matching SANs; and
- P-256, P-384, Ed25519, RSA-2048, RSA-4096 and the webpki maximum RSA-8192
  signatures.

The source-derived outer bound is rustls 0.23.46's 65,535-byte handshake
reassembly ceiling.  webpki 0.103.16 additionally has internal budgets of 100
signature checks, 200,000 path-building calls and 250,000 name-constraint
comparisons.  Those dependency budgets are useful backstops, but are too broad
to be httpd-rs's primary admission contract.

## Retained calibration

The November 14, 2026 calibration used the release binary, 8 concurrent
connections and fresh TLS sessions.  The complete retained output is in
`tls_dependency_profile_results.txt`.

| Shape | handshakes | daemon CPU | peak RSS increase | result |
|---|---:|---:|---:|---|
| P-256 ordinary TLS | 64 | 0.11 s | 7,536 KiB | 64/64 |
| P-256 mTLS, 1 intermediate, 128 names | 64 | 0.14 s | 7,668 KiB | 64/64 |
| P-256 mTLS, 8 intermediates, 128 names | 64 | 0.20 s | 8,756 KiB | 64/64 |
| P-256 mTLS, 16 intermediates, 128 names | 64 | 0.27 s | 8,668 KiB | 64/64 |
| P-256 mTLS, 32 intermediates, 128 names | 64 | 0.02 s | 768 KiB | 0/64; rejected by rustls's message bound |
| RSA-2048 ordinary / 8 intermediates | 64 each | 0.09 / 0.10 s | 8,144 / 8,248 KiB | 64/64 each |
| RSA-4096 ordinary / 4 intermediates | 32 each | 0.16 / 0.21 s | 4,340 / 5,508 KiB | 32/32 each |
| P-384 ordinary / 7 intermediates, 128 names | 16 each | 0.03 / 0.26 s | 2,832 / 3,772 KiB | 16/16 each |
| Ed25519 ordinary / 7 intermediates | 16 each | 0.03 / 0.02 s | 3,304 / 3,196 KiB | 16/16 each |
| RSA-8192 P-256 server control / 1 intermediate | 16 each | 0.03 / 0.04 s | 2,480 / 3,136 KiB | 16/16 each |

The full-connection RSS includes the independently charged 512 KiB transport,
task/worker and response-path reservations.  The marginal mTLS peak over its
ordinary control was about 150 KiB per concurrent handshake in the densest
accepted shape.  The runtime reserves 256 KiB of dependency workspace for
mTLS and 128 KiB for ordinary TLS.  These are typed resident-memory leases,
not comments or allocator estimates.

## Enforced contract

`tls_dependency_budget` is the executable Verus-selected profile.  Before
entering rustls, the server acquires the complete profile as one move-only
owner:

- ordinary TLS: 1 work unit and 128 KiB dependency workspace;
- mTLS: 16 work units and 256 KiB dependency workspace;
- 64 process work units and 32 per-source concurrent work units;
- 128 process and 64 per-source work units per second; and
- a 20-second wall-time deadline.

`BoundedClientCertVerifier` rejects more than eight total presented
certificates or more than 65,535 aggregate DER bytes before invoking webpki.
The count cap closes the many-small-candidate/path-ambiguity axis which a byte
limit alone does not dominate.  The byte cap also dominates name-constraint
and SAN material. P-384 issuer ambiguity was the most expensive retained
shape at 8.7x its ordinary control, so the sixteen-unit mTLS envelope keeps
substantial headroom. RSA-8192 is the dependency-exposed maximum and remained
well below that ratio.

A post-enforcement replay at the exact boundary accepted 8/8 chains with one
leaf plus seven intermediates and rejected 8/8 attempts with one leaf plus
eight intermediates. The rejected shape consumed 0.01 seconds of daemon CPU
and never entered webpki path construction.

Run the matrix after a rustls, webpki or ring upgrade:

```sh
cargo build --release -p httpd-rs
python3 adversarial/tls_dependency_profile.py --max-chain 32 --names 128
python3 adversarial/tls_dependency_profile.py --algorithm rsa2048 --max-chain 8
python3 adversarial/tls_dependency_profile.py --algorithm rsa4096 --max-chain 4
python3 adversarial/tls_dependency_profile.py --algorithm p384 --max-chain 8 --names 128
python3 adversarial/tls_dependency_profile.py --algorithm ed25519 --max-chain 8
python3 adversarial/tls_dependency_profile.py --algorithm rsa8192 --max-chain 1
```

The script is diagnostic and intentionally reports rejected cases rather than
treating every non-success as a harness failure.  Unit tests separately pin
the pre-webpki count/byte rejection and weighted lease acquisition/release.
