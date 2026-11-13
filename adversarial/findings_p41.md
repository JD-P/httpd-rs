# Pass 41 — Brotli quality 11 escapes the compression resource budget

- **Date:** 2026-11-13
- **Subject:** HEAD `67f9691ec8a8a44aeaff21cad974fa4781770e77`
  (`target/release/httpd-rs`; the release build check completed at this HEAD,
  whose product source is identical to the release artifact's input).
- **Harness:** `adversarial/p41/compression_probe.py`, loopback only; retained
  measurements in `adversarial/p41/results_p41.txt`.
- **Method:** family-ledger review followed by source audits of TLS/OCSP
  generation binding, request-controlled diagnostics, proxy state and
  response compression. The confirmed candidate was measured from `/proc`
  against the release process with one-source and process-ceiling attacks and
  a lower-quality control.
- **Disposition:** **P41-A confirmed and unfixed at HEAD.**

---

## 1. Executive summary

| # | Finding | Intended bounds | httpd-rs at HEAD | Class |
|---|---|---|---|---|
| **P41-A** | Brotli quality-11 compression is admitted by a flat “expensive operation” slot and a byte lease that covers only about twice the response length. Neither the encoder's quality-dependent workspace nor its CPU work is charged. Compression also finishes before a closed downstream socket is discovered. | 32 expensive operations process-wide, 8 per source; 128 MiB response-resident memory process-wide, 32 MiB per source. | Eight disconnected requests from one source for one 2 MiB JavaScript asset consumed 275,500 KiB extra RSS and 15.75 CPU-seconds in 5.12 s. Thirty-two disconnected request heads consumed 1,406,120 KiB (1.37 GiB) extra RSS and 77.35 CPU-seconds in 20.42 s on a 5-core runner—10.73× the nominal response-resident cap. | high denial of service; resource-accounting/amplification |

---

## 2. P41-A — the admitted response bytes are not the encoder's resource cost

### 2.1 Root cause

The response filter does have several good bounds. It rejects bodies over
8 MiB, takes a per-client/process `ExpensiveCpu` slot, and reserves this byte
estimate before reading and encoding the representation:

```rust
// crates/server/src/compression.rs:458-466
let Some(_expensive) = crate::resource::try_expensive_in(resource_context) else {
    return;
};
let mut compression_lease = budget.map(|budget| {
    let mut lease = budget.try_response_bytes_in(resource_context)?;
    let peak = resp.body_len().saturating_mul(2).saturating_add(64 * 1024);
    lease.reserve(peak).map(|()| lease)
});
```

That estimate accounts for the identity and encoded `Vec`s. It does not
account for the Brotli encoder itself:

```rust
// crates/server/src/compression.rs:340-350
let mut encoder = brotli::CompressorWriter::new(
    &mut out, 4096, quality.min(11), 22
);
encoder.write_all(data)?;
encoder.flush()?;
```

Quality 11 uses a much larger search/workspace and radically more CPU than the
default. Yet `try_expensive_in` charges every operation as one identical slot.
It permits 8 simultaneous operations per source, 32 process-wide, and 64 per
source per second regardless of input bytes or quality (`resource.rs:228-229,
275-276,2658-2685`). The byte ledger separately promises a 128 MiB
process-wide response heap and 32 MiB per source (`resource.rs:256-265`), but
allocator memory owned inside the encoder is invisible to it.

Finally, compression is synchronous and materializes the complete encoded
body before the response writer observes its socket. A client can therefore
send the small request head and immediately close; the full memory and CPU
cost still occurs, while the attacker receives no multi-megabyte response.

### 2.2 Live reproduction

The retained harness creates one syntactically valid, deterministic 2 MiB
JavaScript asset, configures the supported common filter shape

```apache
AddOutputFilterByType BROTLI_COMPRESS text/javascript
BrotliCompressionQuality 11
```

and sends parallel `GET /payload.js` request heads. In exploit mode every
client closes immediately after the head. No request body, malformed framing,
authentication or backend is involved.

The default invocation uses the same source address for all eight requests:

```text
body_bytes=2097152 clients=8 quality=11 abort_after_head=true
baseline_rss_kib=7520 peak_rss_kib=283020 delta_rss_kib=275500
server_cpu_seconds=15.750
wall_seconds=5.117 server_exit=None
```

Thus one network identity stays within the intended eight-operation fairness
limit while consuming about 269 MiB beyond baseline—over eight times the
documented 32 MiB per-source response-resident ceiling—and about three full
cores over the measured interval.

The 32-request process-ceiling invocation produced:

```text
body_bytes=2097152 clients=32 quality=11 abort_after_head=true
baseline_rss_kib=7408 peak_rss_kib=1413528 delta_rss_kib=1406120
server_cpu_seconds=77.350
wall_seconds=20.416 server_exit=None
```

That is 1.37 GiB transient growth, 10.73 times the nominal 128 MiB process
response-resident limit. On the 5-core runner it also represents 77.35 seconds
of CPU work caused by 32 small request heads whose senders had already gone
away. Repeating either wave keeps the compression workers busy. The retained
run did not impose a container memory limit or claim a process kill; the
demonstrated outcome is 1.37 GiB of unaccounted live RSS plus sustained CPU
loss.

The quality-5 control is important. Eight clients receiving the same asset
peaked at 60,424 KiB beyond baseline and every admitted encoded response
completed in 68-135 ms. The finding is not “compression costs resources”; it
is that the supported quality-11 cost is admitted under bounds calibrated only
to response bytes and a unit operation count.

### 2.3 Impact and severity

- **Primary family:** `denial_of_service`.
- **Impact tier:** high. One unauthenticated source can repeatedly consume
  hundreds of MiB and a majority of a 5-core host with eight sub-kilobyte
  request heads; a small multi-source wave reaches 1.37 GiB and about four of
  the runner's five cores. This materially defeats the process/per-source
  resource ceilings. The non-default maximum Brotli
  quality and availability of a suitable public representation are real
  preconditions, so critical would overstate the universal blast radius.
- **Unintended behavior count:** 2. The byte ledger omits quality-dependent
  encoder workspace, and CPU admission prices every compression as one unit
  independent of quality/size/cancellation.
- **Remediation component count:** 2. Add a compression-specific weighted
  admission model for memory/CPU, and make execution cancellation-aware (or
  stream it under output progress) so a dead sink cannot consume the full
  encoding budget.

### 2.4 Remediation boundary

1. Derive a conservative Brotli workspace charge from quality, window and
   input size, and acquire it from a dedicated transient-memory ledger before
   constructing the encoder. The admission must include library-internal
   allocations, not just the two visible vectors.
2. Weight CPU admission by algorithm, quality and input size. At minimum,
   quality 10/11 needs a much smaller per-source/process concurrency than a
   default gzip/Brotli response; a token cost rather than one flat slot is the
   natural model.
3. Move compression into a cancellation-aware path. Check downstream liveness
   before expensive work and periodically while encoding, or stream bounded
   chunks through the existing slow-output/progress machinery.
4. Add regressions that measure the peak ledger/RSS envelope and cancellation
   work for qualities 5, 10 and 11 at multiple input sizes. Functional tests
   that only check `Content-Encoding` cannot observe this defect.

---

## 3. Negative observations

The pass deliberately rejected other candidates:

- TLS resumption state is generation-local, TLS 0-RTT and half-RTT data are
  disabled, listener-sharing requires uniform client-auth/resumption policy,
  and the captured connection identity rejects a different generation.
- OCSP staples are certificate-id, signer, signature and freshness checked;
  cached responses are revalidated against the active chain and live staples
  are removed at their authenticated deadline. No trust bypass was found.
- Request/background diagnostics use the crate's bounded `eprintln!` shadow,
  which escapes controls before writing; configured error and access logs do
  the same. The suspected log-injection path was therefore not retained.
- A short sanitizer build/fuzz attempt for the OCSP target was superseded by
  the source audit and did not produce a crash or memory-safety finding.

These observations are not proof that those surfaces are bug-free.
