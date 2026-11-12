# Pass 38 — Backslash continuations are joined with an inserted space, defeating Apache-valid guards and activating Apache-rejected directives

- **Date:** 2026-11-12
- **Subject:** HEAD `67ca87bdccb3932919c2efabb850d7320c2265b2`
  (`target/release/vapached`, rebuilt from the checked-out tree; no product
  source was edited).
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` + `mod_mime` + `mod_dir` +
  `mod_authz_core` + `mod_authz_host` + `mod_cgi` + `mod_rewrite` +
  `mod_alias`, loopback only.
- **Harness:** `adversarial/p38/exploit_p38.py` — one `apache2 -t` join probe
  and eight live Apache-versus-vapached cases; retained output
  `adversarial/p38/results_p38.txt`.
- **Method:** source audit of the newest unreviewed commit window
  (`7ec4fa7..67ca87b`) with a focus on the shared configuration front end,
  followed by a live differential over backslash-continued physical lines in
  `.htaccess` and main configuration.
- **Disposition:** **P38-A and P38-E confirmed and unfixed at HEAD.** P38-B
  and P38-D are deterministic fuzzing-harness crashes recorded `invalid`
  (exchange-queue accounting; round-robin member comparison and an extra
  planning pass that trips the expensive-parse admission). **P38-C** is a
  low-severity, fail-closed URL-policy cache-poisoning hypothesis recorded
  `unresolved` (zero points).

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | vapached at HEAD | Class |
|---|---------|---------------|------------------|-------|
| **P38-A** | `config_frontend::logical_lines_with_numbers` joins a backslash-continued physical line by appending `' '` and trimming the next line's leading whitespace. Apache removes the backslash and the newline and concatenates the next physical line **directly**, so `foo\` + newline + `bar` is one token `foobar` on Apache and two tokens `foo bar` on Vapache. A continuation inside a guard regex therefore silently changes its meaning, and a continuation immediately after a directive name activates a directive Apache rejects for the whole file. | `<FilesMatch "^private\` + `ate\.txt$"> Require all denied` denies (403); `SetHandler\` + `cgi-script` makes the access file invalid (500); `Require\` + `all granted` under a parent deny is invalid (500); the same `<LocationMatch>` split in main configuration denies (403). | The split guard regex becomes `^priv ate\.txt$` and does not match: `200` with the protected body. The split `SetHandler` becomes valid and executes an uploaded `.txt` as CGI. The split grant becomes valid and serves the protected file. | protected static-file read; authority bypass; remote code execution in an Apache-rejected access file |
| **P38-B** | `multi_request_state` fuzzing (added by HEAD `67ca87b`) crashes deterministically on a minimized two-step input with `assertion left == right failed: pre-sink cancellation did not suppress the dynamic effect`. The cause is the harness popping one backend exchange per execution while an idempotent balancer request can legitimately produce two upstream attempts after an ambiguous response. | n/a | n/a (test-only harness accounting) | invalid claim; no product impact |
| **P38-C** | The new `url_policy_cache` stores a partial URL scope when a rule matcher exhausts the request-local policy budget (`conditional_error = true; break`), so later requests for the same `(vhost, fs_path, url_path)` key see `Access::Misconfigured` → 500 until eviction. Requires a configuration with tens of thousands of URL/`Location` rules to charge 16 MiB of matcher work in one request. | n/a | n/a (not reproduced) | unresolved hypothesis; tentative fail-closed DoS, low |
| **P38-D** | `whole_request_differential` aborts on two deterministic inputs. (1) A `/balanced/` route: the fixture balancer is round-robin, so the H1 and H2 evaluations select different members and the compared exchange port differs. (2) `GET /access/guard.cgi`: the harness's extra `plan_snapshot` pass fails with `access-file parse capacity exhausted` from the process-wide expensive-parse admission while the same evaluation's dispatch succeeds and returns 200. | n/a | n/a (test-only harness artifacts) | invalid claims; no product impact |
| **P38-E** | `1f35e19` added decision-table early returns in `Inner::recv_data` (forgotten, `Ignore`, `StreamClosed`) that return before the only `counts.record_data_frame` call, so terminal HTTP/2 streams escape `MAX_RECV_EMPTY_DATA_FRAMES = 100` and the small-frame overhead budget. | n/a | Control GOAWAYs after 101 empty DATA frames; on a locally-reset stream 395,000 empty DATA frames at ~49,351 frames/s over 8 s with **no GOAWAY** and the connection alive (~0.38 µs/frame server CPU). | confirmed denial of service (resource exhaustion), high |

The controls agree on both servers: a plain `<FilesMatch "^private\.txt$">`
denies (403), a plain `SetHandler cgi-script` executes on both, a plain
`Require all granted` grants on both, and the same split `RewriteRule`
continuation fails closed on Vapache (500) while Apache denies (403).

---

## 2. P38-A — continuation lines are re-joined with a separator

### 2.1 Root cause

Both the main configuration (`crates/server/src/config.rs:5099`) and
`.htaccess` (`crates/server/src/htaccess.rs:1069`, through
`config_frontend::logical_lines`) consume the same assembler:

```rust
// crates/server/src/config_frontend.rs:13-30
pub fn logical_lines_with_numbers(text: &str) -> Vec<(usize, String)> {
    ...
        let continued = line.trim_end().ends_with('\\');
        if continued {
            line = line.trim_end().trim_end_matches('\\').to_string();
        }
        match &mut pending {
            Some((start, buf)) => {
                buf.push(' ');                      // inserted separator
                buf.push_str(line.trim_start());    // leading whitespace dropped
                ...
```

Apache's configuration reader instead removes the trailing backslash and the
newline and concatenates the next physical line verbatim; the whitespace that
remains on either side of the join is whatever the file contained. The
`apache2 -t` probe in `results_p38.txt` pins the rule directly:

```apache
Redirect 301 /a\
/dest
```

Apache reports `URL to redirect to is missing` (the joined token is
`/a/dest`); a space-inserting assembler accepts the directive as
`Redirect 301 /a /dest`.

The P35-A remediation replaced the separate `.htaccess` comment path with this
shared assembler and the closure record states: “Main configuration and
`.htaccess` therefore cannot disagree about which directive tokens or section
delimiters exist.” P38-A shows the assembler still disagrees with Apache about
**where tokens end**: every token split across a continuation is re-separated
by a space. P35-A's own unit test pins the divergent join
(`"one  two  three"`), so this was not covered by the P35 remediation.

### 2.2 Demonstrated divergences

All rows are live differentials from `adversarial/p38/results_p38.txt`.

| Case | Access file / configuration | Apache | Vapache |
|---|---|---|---|
| A | `.htaccess`: `<FilesMatch "^priv\` + `ate\.txt$">` `Require all denied` `</FilesMatch>` | `403`, no body | `200` with `P38-SECRET-CONTENT-5a17` |
| A-control | `.htaccess`: `<FilesMatch "^private\.txt$">` `Require all denied` | `403` | `403` |
| B | `.htaccess`: `SetHandler\` + `cgi-script`, `Options +ExecCGI`, executable `run.txt` | `500` for the directory (invalid directive `SetHandlercgi-script`) | `200` with `P38-CGI-EXECUTED-5a17` |
| B-control | `.htaccess`: `SetHandler cgi-script` | `200`, executes | `200`, executes |
| C | `.htaccess`: `Require\` + `all granted` under parent `Require all denied` | `500` (invalid directive `Requireall`) | `200` with `P38-SECRET-CONTENT-5a17` |
| C-control | `.htaccess`: `Require all granted` under parent deny | `200` | `200` |
| E | main configuration: `<LocationMatch "^/sub/private\.txt\` + `$">` `Require all denied` | `403` | `200` with `P38-SECRET-CONTENT-5a17` |
| E-control | main configuration: plain `<LocationMatch "^/sub/private\.txt$">` | `403` | `403` |
| F (observation) | `.htaccess`: `RewriteRule ^priv\` + `ate\.txt$ - [F]` | `403` | `500` (the joined line has the wrong argument count) |

Case A is the strongest form: both servers accept the configuration without
error, and only Vapache fails to apply the operator's deny. Case E shows the
same silent guard loss in a main configuration file with no attacker-writable
`.htaccess` at all. Cases B and C are the P35-A shape (a directive Apache
rejects becomes active policy) through the token-join seam rather than the
comment seam.

### 2.3 Reachability and impact

- The `.htaccess` cases use the project's established writable-access-file
  threat model (`AllowOverride FileInfo`/`AuthConfig`, the same prerequisites
  as P14-A and P35-A). A one-line continuation turns a file Apache rejects
  into an active `SetHandler cgi-script` or `Require all granted`.
- Case E needs no attacker-writable file: any operator configuration that
  wraps a long guard regex across a backslash continuation is silently less
  restrictive on Vapache than on Apache.
- Case B executes an uploaded `.txt` as CGI under `www-data` where Apache
  returns `500`; case A/E return the protected body under a live deny.

### 2.4 Classification and composition

- Primary family `code_execution` (case B executes an uploaded file through
  CGI); secondary families `authority_bypass` and `information_disclosure`
  (cases A/E/C return protected content under an operator deny).
- Attack surfaces: configuration front end, access files, CGI.
- Two unintended behaviors compose: (1) the assembler inserts a separator and
  trims the continuation line instead of concatenating directly; (2) the
  consumers tokenize and apply the resulting logical line without requiring
  Apache-equivalent assembly. One remediation component closes the class:
  join continued physical lines exactly as Apache does.

---

## 3. P38-B — `multi_request_state` fuzz crash (invalid)

The new stateful fuzzer (HEAD `67ca87b`) found a deterministic crash artifact
within minutes:

```text
thread '<unnamed>' panicked at crates/server/src/whole_request_fuzz.rs:1174:5:
assertion `left == right` failed: pre-sink cancellation did not suppress the dynamic effect
  left: true
 right: false
```

The minimized input (24 bytes) is a `PUT /balanced/<token>` against the
fixture balancer followed by a cancelled `OPTIONS /balanced/`. The first
request is idempotent, its backend answers with the ambiguous-framing mode,
and `execute_authorized_with_proxy_base` correctly fails over to the alternate
balancer member. Two upstream attempts are recorded, but
`execute_prepared_snapshot` pops only one exchange; the cancelled second step
then pops the leftover and the harness reports a cancellation failure that did
not occur. The ambiguous-error message appears exactly twice per replay, so
the cancelled step itself did not reach the backend and
`DynamicOutcomeToken::start_backend`'s cancellation check works.

Retained evidence: `adversarial/p38/fuzz-observation.txt`,
`crash-multi-request-state-failover-accounting.bin`,
`minimized-multi-request-state-failover-accounting.bin`. Recorded as
`invalid` in the index so the review's false-positive rate remains
measurable; no product remediation is required for the crash.

The parallel dynamic-backend audit independently reproduced the same crash
with a different 32-byte input (`adversarial/p38/exp.bin`) and added passing
controls that pin the mechanism: a well-formed-then-cancelled pair, a direct
`/proxy` malformed-then-cancelled pair (single exchange, no failover), and a
failover-then-cancelled **CGI** pair whose response would have carried
`X-Backend` if the cancelled CGI had run. The last control proves the
cancellation suppression itself works for a sink that does not share the
proxy exchange queue. Full write-up:
`adversarial/p38/subagent-dynamic-backends-review.md`.

---

## 4. P38-C — budget-exhausted partial URL scope is cached (unresolved)

The parallel audit's second candidate concerns the `url_policy_cache` added
by `a0ac855`:

```rust
// crates/server/src/config.rs:17851-17875
let matched = match rule_kind_matches_req(&rule.kind, fs_path, url_path, &fname, req) {
    Ok(matched) => matched,
    Err(_) => {
        scope.conditional_error = true;
        break;                       // partial scope
    }
};
...
let cached = Arc::new(CachedUrlPolicy { scope: Arc::new(scope), conditionals: ... });
if let Ok(mut guard) = self.url_policy_cache.write() {
    guard.insert(key, Arc::clone(&cached));   // cached process-wide
}
```

A rule matcher returns `Err` only when the *request-local* policy budget is
exhausted (`MAX_POLICY_WORK_UNITS = 16 MiB` at `resource.rs:440`, charged by
`req.charge_policy_work`). The partial scope is still inserted under the
request-independent `(vhost, fs_path, url_path)` key, so later requests that
hit the entry observe `conditional_error`. `access::check` (`access.rs:799`)
maps that to `Access::Misconfigured` → 500 until the bounded cache
(256 entries / 32 MiB) evicts the entry.

Status: **unresolved**. Charging 16 MiB of matcher work in one request needs
a configuration with thousands to tens of thousands of URL/`Location` rules
(each rule charges roughly `1 + pattern length + path length`); the
benchmark deployments and the audit's fixtures cannot reach it, and no live
500 was produced. The impact is tentatively a transient, fail-closed denial
for one URL, not an authorization bypass: every served route passes
`access::check`, which rejects the poisoned scope. Recorded for later
follow-up (a cheap hardening would be to skip the cache insert when
`conditional_error` is set).

---

## 5. P38-D — `whole_request_differential` comparison false positives (invalid)

Two deterministic `whole_request_differential` crashes were reproduced and
diagnosed; both are harness artifacts, not protocol-projection divergences
(full evidence: `adversarial/p38/whole-request-harness-observation.txt`).

1. **Round-robin balancer member.** `PUT /balanced/780a?...` aborts because
   the two compared snapshots differ only in the backend exchange's host port.
   The fixture balancer is round-robin (`next_balancer_member` increments a
   per-generation counter, `proxy.rs:909-916`), so the H1 and H2 evaluations
   legitimately select different members; the fixture's own unit test asserts
   the alternation. The comparison should pin or normalize the member.
2. **Harness extra planning pass.** `GET /access/guard.cgi` aborts with
   `plan: Rejected { status: 500, class: "filesystem" }` (H1) versus
   `plan: Filesystem { ... }` (H2). An instrumented copy of HEAD printed
   `AccessFiles(".../www/access/.htaccess: access-file parse capacity
   exhausted")` for the failing `plan_snapshot` call only; the same
   evaluation's dispatch prepared and executed the CGI and returned 200.
   `htaccess::parse_cached` takes a process-wide expensive-operation lease
   (`resource.rs:2648-2684`), and the harness's extra planning pass can trip
   the fixture client's admission transiently. A standalone server with the
   same fixture config returns 200 for every request, including the first.

Both crashes are recorded as one `invalid` claim (P38-D) so the harness's
false-positive rate stays measurable; no product remediation is required.

## 6. P38-E — HTTP/2 empty-DATA flood bypasses the anti-flood cap (confirmed)

The `1f35e19` HTTP/2 lifecycle hardening moved the only DATA-frame accounting
call onto the `Process` path of `Inner::recv_data`. The new decision-table
early returns for terminal streams never charge the frame:

```rust
// vendor/h2-0.4.20/src/proto/streams/streams.rs
// :697-718  stream not found but in the forgotten tombstones: ignore + return
// :737-741  found stream, decision Ignore (locally reset): ignore + return
// :742-758  found stream, decision StreamClosed: ignore + repeat RST + return
// :779-784  Process path: the only counts.record_data_frame(payload_len) call
```

`record_data_frame` enforces `MAX_RECV_EMPTY_DATA_FRAMES = 100`
(`vendor/h2-0.4.20/src/proto/mod.rs:40`, `counts.rs:161-179`) — the mitigation
the repository's own CVE matrix records for CVE-2019-9518 and CVE-2020-12603.
After the early returns, the only remaining bound is the unified frame-work
budget, which charges one unit per DATA frame and refills 65,536 units/s
(`crates/verified/src/lib.rs:15823-15834`).

Independent reproduction against the HEAD release binary
(`adversarial/p38/h2-data-flood-observation.txt`):

```text
CONTROL: GOAWAY after 101 empty DATA frames: code=11 debug=b'too_many_data_frames'
BYPASS setup RST: [... RST_STREAM ...]          # content-length overflow reset
BYPASS: 395000 frames in 8.0s = 49351 frames/s, NO GOAWAY, connection alive
BYPASS: server CPU 0.15s = 0.38 us/frame
```

Impact: an unauthenticated HTTP/2 client pins server CPU with a sustained
~65k frames/s per connection of 9-byte frames instead of the intended
100-frame lifetime cap per stream; the cost multiplies across the documented
per-client and per-process connection limits. The `StreamClosed` variant also
queues one repeat `RST_STREAM` per input frame (small wire amplification).
No crash, memory-safety or response-integrity result was demonstrated, so the
tier is high rather than critical. One unintended behavior and one remediation
component: charge `record_data_frame` on the three early-return paths.

## 7. Negative observations

- The P35-A comment-continuation shapes (`#\` + grant, `#\` + hidden
  `<Files>` section, chained comments) remain closed at HEAD; the P35
  regression battery still passes.
- Plain (non-continued) guards, grants and handlers agree on both servers in
  every case above.
- The P38-A divergence is one-directional for accepted configurations:
  Vapache always inserts at least as much whitespace as Apache, so the
  fail-closed direction (`RewriteRule` split, case F) errors on Vapache where
  Apache acts. The security-relevant direction is the silent guard loss and
  the Apache-invalid directive activation.
- The four tracked `multi_request_state` corpus seeds pass at HEAD; the
  P38-B crash requires the failover-retry shape.
- The parallel dynamic-backend audit reproduced no bypass in the unreviewed
  proxy/FastCGI/CGI changes: every FastCGI `SCRIPT_FILENAME`/`PATH_INFO`
  spelling it tried (`/uploads/must-not-execute.php[/x.png|/|/.|//…]`,
  `//uploads/…`, `/./uploads/…`, `%2F`/`%2E`/`%00`, out-of-docroot prefixes,
  symlinked scripts) was denied on Vapache, and Apache's `mod_proxy_fcgi`
  actually executed one of those spellings where Vapache denied it; config-time
  capture authority (`$1`/`\1`/`%1`/`%{HTTP_HOST}` in a proxy URL) fails
  configuration loading; a failover member denied by its own `<Proxy>` policy
  is never contacted; a `<Location>` deny survives a per-directory rewrite
  through the `a0ac855` fast path; and no request-reachable panic was found in
  `proxy.rs`/`fastcgi.rs`/`cgi.rs`/dynamic `server.rs`.

- The parallel HTTP/2 audit reproduced no reachable panic and no protocol
  conformance failure in the `1f35e19` changes: `h2spec 2.6.0 --strict --tls`
  passed every selected group, `h2_frames`/`h2_stateful` ran ~7M inputs with
  no crash, all 49 `h2::tests` passed, 4,000 stateful adversarial connections
  produced no abort or wrong response, and h2-to-h1 translation rejected
  connection-specific fields, non-`trailers` TE, conflicting Content-Length
  and pseudo-headers in trailers. The only confirmed result is the empty-DATA
  accounting bypass above.

## 8. Closure recommendation

1. Change `logical_lines_with_numbers` to remove the backslash and newline and
   concatenate the next physical line verbatim (no inserted separator, no
   leading trim), matching Apache's assembler; keep continuation-before-
   comment ordering.
2. Add differential regressions for a split `<FilesMatch>` guard, a split
   `<LocationMatch>` guard, a split `SetHandler`, a split `Require` grant and
   the split `RewriteRule` control, in both `.htaccess` and main
   configuration.
3. Optionally reject or warn on access files whose Apache-equivalent token
   stream differs, as defense in depth.
4. Charge `counts.record_data_frame(frame.payload().len())` (or at least the
   empty-frame counter) before returning on the forgotten, `Ignore` and
   `StreamClosed` early paths in the vendored h2 fork; add a regression that
   floods empty DATA frames on a locally-reset stream and requires GOAWAY
   within the empty-frame cap.

## 9. Evidence

- `adversarial/p38/exploit_p38.py` — the runnable differential (oracle probe,
  cases A/B/C/E and controls, case F observation).
- `adversarial/p38/results_p38.txt` — retained output at HEAD `67ca87b`.
- `adversarial/p38/fuzz-observation.txt` — P38-B decode, replay and the
  two-attempt evidence.
- `adversarial/p38/subagent-dynamic-backends-review.md` — parallel audit
  report (P38-B corroboration, P38-C hypothesis, reproduced negatives).
- `adversarial/p38/subagent-h2-lifecycle-review.md`,
  `adversarial/p38/h2-data-flood-observation.txt` and
  `adversarial/p38/h2-data-flood/` — P38-E source audit, independent
  reproduction and reproducer scripts.
- `adversarial/p38/whole-request-harness-observation.txt` — P38-D
  instrumented diagnosis and product control.
- `adversarial/p38/crash-whole-request-roundrobin-balancer.bin`,
  `adversarial/p38/crash-whole-request-access-plan.bin`,
  `adversarial/p38/minimized-whole-request-access-plan.bin` — P38-D retained
  artifacts.
- `adversarial/p38/crash-multi-request-state-failover-accounting.bin`,
  `adversarial/p38/minimized-multi-request-state-failover-accounting.bin`,
  `adversarial/p38/exp.bin`, `adversarial/p38/ctl.bin`,
  `adversarial/p38/b.bin`, `adversarial/p38/d.bin` — retained fuzz artifacts
  and controls.
- `crates/server/src/config_frontend.rs:13-47` — the shared assembler
  (`buf.push(' ')` and `line.trim_start()` at lines 25-26).
- `crates/server/src/config.rs:5099`, `crates/server/src/htaccess.rs:1069` —
  the two consumers.
