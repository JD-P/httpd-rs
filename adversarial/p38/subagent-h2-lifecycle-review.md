# Pass-38 subagent review: HTTP/2 lifecycle commit `1f35e19`

Scope reviewed: `crates/server/src/h2.rs` (ledger + static-only drain),
`crates/verified/src/lib.rs` (H2Budget/H2SettingsSync/H2PeerFrameDecision/
H2ResetExpiry), vendored `h2-0.4.20/src/proto/{settings.rs,streams/{counts,
recv,send,state,streams}.rs}`, `tests/protocol_conformance.py`. Working tree at
HEAD `67ca87b` (h2.rs and vendor byte-identical to `1f35e19`; later commits
touched only `verified/lib.rs` and `http.rs`).

Method: full diff reading; pre-commit source comparison (`git show 1f35e19^:`);
release build (`target/release/httpd-rs`, panic=abort); live TLS+ALPN h2 probes
with a raw frame/hyper-hpack client; `h2spec 2.6.0` (all 36 selected groups,
fresh server per group); libFuzzer `h2_frames`/`h2_stateful` (~7M runs, no
crash); 49 h2 unit tests; a Python stateful random frame tester (4,000
connections, server alive throughout).

## Finding 1 — CONFIRMED (high): empty/small DATA-frame anti-flood budget bypassed on terminal HTTP/2 streams

See `adversarial/p38/h2-data-flood-observation.txt` for the independent
reproduction and the exact source lines. Summary:

- `1f35e19` added decision-table early returns in `Inner::recv_data` that
  bypass the only DATA-frame accounting call (`record_data_frame`), which
  enforces `MAX_RECV_EMPTY_DATA_FRAMES = 100` and the small-frame overhead
  budget. Pre-commit code charged every found stream, and a server-side DATA
  frame on a released stream produced a connection error.
- After one content-length-overflow reset (or any stream-level reset), the
  stream is terminal; empty DATA frames are silently ignored with no GOAWAY,
  bounded only by the unified frame-work budget (~65k frames/s/connection).
- Measured: control GOAWAY after 101 frames; bypass 395,000 frames at
  ~49,351 frames/s over 8 s with no GOAWAY; server CPU ~0.38 µs/frame in the
  cheapest (locally-reset) path. The repository's own CVE matrix records
  CVE-2019-9518/CVE-2020-12603 as prevented by this cap, so the commit
  regresses a documented mitigation.
- Suggested fix: charge `counts.record_data_frame(frame.payload().len())` (or
  at least the empty-frame counter) before returning in all three early-return
  paths; optionally bound the per-frame `send_repeat_reset` path.

## Secondary observations (lower severity / not weaponized)

- HYPOTHESIS (low): static-only body handling now reads/spools the request
  body before rejecting (`crates/server/src/h2.rs:1647-1665`,
  `drain_after_body`). A static-only `400/405` becomes "enter slow-input,
  read up to `limit_request_body` (default 1 GiB) / 30 s timeout / spool
  budget, then respond". Bounded by the shared 128/32 slow-input pool and
  spool budgets; intentional per `docs/adversarial-closure.md`; noted as an
  added resource surface.
- HYPOTHESIS (low): placeholder stream insertion in `Inner::send_reset`'s
  vacant path (`streams.rs:1148-1193`). Traced; bounded by the reset-expiry
  queue and immediate release; not reproducible as a bug.
- Pre-existing, not introduced: the adapter ledger closes the connection with
  ENHANCE_YOUR_CALM after 100 client-observed resets within 10 s
  (`crates/server/src/h2.rs:2787-2794`); self-scoped.

## Negative observations (checked, held)

- No reachable panic found. All `expect`/`assert` sites added by the commit are
  unreachable by construction (SETTINGS phase/payload pairs; request-phase
  machine expects; `path.expect("admitted path")`; `send_repeat_reset`'s
  debug-assert checked by callers). `MAX_FORGOTTEN_STREAMS`/`forgotten_phase`
  are VecDeque-safe.
- h2spec 2.6.0 `--strict --tls` passes every group the repo's conformance
  script selects; 0 failures.
- `h2_stateful` 5M runs and `h2_frames` 5M+ runs: no crash; the added
  `fuzz_h2_lifecycle` invariant held.
- All 49 `h2::tests` pass; 4,000 adversarial stateful connections produced no
  abort and no wrong-response artifacts.
- h2-to-h1 translation rejects connection-specific fields, TE only `trailers`,
  conflicting/invalid CL, pseudo-headers in trailers; proxy strips hop-by-hop.
- Stream-identity protections hold: lower/skipped IDs rejected, no second
  response on a reused ID.
- Static-only behavior: GET+body -> 400, POST+body -> 405 after drain;
  declared-oversize -> 413; client RST mid-body -> no response; server alive.
- Harness note: `whole_request_differential` aborts on a harness
  nondeterminism (round-robin balancer member port differs between the H1 and
  H2 evaluations, `whole_request_fuzz.rs:1381`); the divergent field is a
  fixture port, not a request-path difference (recorded as P38-D).

Artifacts: `/tmp/opencode/h2lab/{repro_data_budget_bypass.py,data_flood*.py,
runner*.py,stateful_random.py,h2raw.py}`; copies under
`adversarial/p38/h2-data-flood/`; h2spec at `/tmp/opencode/h2spec`.
