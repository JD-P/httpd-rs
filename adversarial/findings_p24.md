# Pass 24 — adversarial break of HEAD `8198410` (expression-parser abort DoS)

> Remediation status (2026-10-30): **fixed in the current tree**. Expression
> regex delimiters must now be ASCII, so the parser rejects the malicious
> forms before advancing into a UTF-8 code point; string and regex bodies also
> preserve their original UTF-8 bytes. Variable counted repetitions charge
> their terminal path plus a conservative PikeVM active-set factor. The live
> battery now requires four access-file `500` responses with the process still
> alive, an ASCII `200` control, and a normal non-signal `httpd-rs -t` failure.

- **Date:** 2026-10-30
- **Subject:** `target/release/httpd-rs` built at HEAD `8198410`
  (`Retain the PCRE2 fuzzer with P23 artifacts`). No product source was
  edited.
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` + `mime` + `dir` +
  `authz_core` + `authz_host` + `headers`, loopback only.
- **Harness:** `adversarial/p24/exploit_p24.py` — **7 closure verdicts**
  (A1–A4 attacker-written `.htaccess` inputs return 500 while the process
  stays alive, A5 ASCII control stays 200, B1 main-config `-t` fails without
  a signal, Apache oracle 500 + alive).
- **Retained evidence:** `/tmp/opencode/p24-harness` (fixtures, configs,
  per-variant server output), `adversarial/p24/crash-input.bin` (the
  libFuzzer artifact), `/tmp/opencode/p24-fuzz-rewrite_expr.log`.
- **Method:** extended coverage-guided fuzzing of the existing
  `rewrite_expr` target (the checked-in smoke gate runs 64 executions per
  target; this pass ran 1.3 M), followed by a live differential against
  Apache on the project's own `AllowOverride` / `.htaccess` shapes.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P24-A** | `expr::Parser::regex()` takes the byte after `=~`/`!~` as a raw **byte** delimiter and stops the scan with `self.pos` pointing **inside** a multi-byte UTF-8 character whenever that delimiter byte reappears later as the lead byte of another character (`éé`, `éà`, `€€`, …). The next `&str` slice (`Parser::and()`, `crates/server/src/expr.rs:1344`) panics with `start byte index N is not a char boundary`. The release profile is built with `panic = "abort"` (`Cargo.toml`), so the panic kills the **whole httpd-rs process** (SIGABRT, core dumped). Reachable per-request from an attacker-written `.htaccess` in any directory whose effective `AllowOverride` enables **any** category (`<If>`/`<ElseIf>`; `AuthConfig` for `Require expr`; `FileInfo` for `RewriteCond expr`), and at load time from the main configuration (`<If>`, `Require expr`, `RewriteCond expr`). The project's own benchmark/conformance configuration (`HttpdRsCapability AccessFiles On`, `AllowOverride All` on `/www/htaccess`, `.htaccess` rewrite/Header scenarios) is exactly this shape. | `.htaccess: Cannot parse condition clause: syntax error, unexpected T_ERROR, expecting T_REGEX or T_REGEX_I: Parse error near '\xc3'` → **500 for that request, server stays alive**. | First request into the directory kills the process: `thread 'conn' panicked at crates/server/src/expr.rs:1344:26: start byte index 21 is not a char boundary; it is inside 'é' (bytes 20..22 of string)`, `Aborted (core dumped)`. All later requests get connection refused. Re-triggers after every restart (the panicking parse is never cached). `httpd-rs -t` with the main-config form exits with signal 6. | remote whole-process denial of service via the project's attacker-writable-`.htaccess` primitive (panic→abort) |
| **P24-B** (secondary) | The P23 counted-repetition charge uses `max` per repetition, but a nested `{0,m}` expansion contributes `m+1` active paths and forces the PikeVM path: `1(?:[[:^alpha:]]{0,3}){4208}a` on a 1,328-byte subject charges 16.77 M units and costs **262 ms** cold / 292 ms warm on this host, while the flat `[[:^alpha:]]{12624}` with the same charge costs **0.7 ms**. A 30 k-pattern random sweep found admitted evaluations up to **268 ms** (vs. the ~65 ms that a 4 ns/unit reading of the gate implies). 32 concurrent `try_expensive` slots can therefore saturate every core. Requires the operator to configure a nested counted repetition; not attacker-chosen. | PCRE2 executes the same expression shapes in microseconds (auto-possessification) and `mod_reqtimeout`/`LimitRequest*` do not bound match work. | Worst admitted single evaluation 268 ms; nested `{0,m}` under a counted repetition is 4–5× the flat form at identical charge. | CPU-amplification DoS against operator regexes (bounded but miscalibrated work ceiling) |

P24-A is remote, unauthenticated (beyond the file-write primitive), single
file, and persistent. It is the pass-24 breakthrough.

---

## 2. P24-A — the expression parser is not total

### 2.1 Root cause

`crates/server/src/expr.rs:1066-1094`:

```rust
fn regex(&mut self) -> Result<(String, bool), String> {
    let Some(delim) = self.input.as_bytes().get(self.pos).copied() else {
        return Err("expected a regex after =~".into());   // H1 bounds fix
    };
    self.pos += 1;
    let mut out = String::new();
    while self.pos < self.input.len() {
        let b = self.input.as_bytes()[self.pos];
        self.pos += 1;
        if b == delim {                                    // raw byte compare
            let mut nocase = false;
            while self.pos < self.input.len()
                && self.input.as_bytes()[self.pos].is_ascii_alphabetic()
            { ... }
            return Ok((out, nocase));                      // pos may be mid-char
        }
        ...
        out.push(b as char);                               // also mojibake
    }
    Err("unterminated expression regex".into())
}
```

`delim` is always a UTF-8 **lead** byte (≥ 0xC2) when the character after
`=~` is non-ASCII. When that lead byte reappears later as the lead byte of
another character, the loop matches it and returns with `self.pos` one byte
past the lead byte — i.e. on a continuation byte. The caller then slices:

```rust
// expr.rs:1340-1350, Parser::and()
fn and(&mut self) -> Result<Expr, String> {
    let mut items = vec![self.compare()?];
    loop {
        self.skip();
        if self.input[self.pos..].starts_with("&&") {      // <-- panics
```

`Parser::or()` (`:1359`), `Parser::primary_inner()` (`:1158`) and `parse()`'s
trailing check (`:1382`) are the same shape.

Minimal input, `%{X} =~ éé`:

```text
25 7b 58 7d 20 3d 7e 20 c3 a9 c3 a9
                        ^ pos 8: delim = c3, pos -> 9
scan a9 -> pos 10; c3 == delim -> pos 11
bytes 10..12 are 'é'; pos 11 is inside it
and(): self.input[11..] -> panic "start byte index 11 is not a char boundary"
```

The same happens for `!~`, for three-byte characters (`€ = E2 82 AC`), and
for any two accented Latin characters sharing the `C3` lead byte. A single
occurrence (`=~ é`) reaches end-of-input and returns the clean
`unterminated expression regex` error, so the crash needs the delimiter
byte to appear twice — trivially satisfied by real accented text.

The bug was found by the checked-in `rewrite_expr` libFuzzer target after
~1.3 M executions (`fuzz/artifacts/rewrite_expr/crash-3a08443…`,
retained as `adversarial/p24/crash-input.bin`); the CI smoke gate runs only
64 executions per target, which is why it was not caught.

### 2.2 Why it is a whole-server DoS

- The workspace release profile sets `panic = "abort"` (`Cargo.toml`), so
  the panic aborts the entire process from any thread (HTTP/1 `conn`
  threads and the HTTP/2 runtime alike). Observed: `Aborted (core dumped)`
  and `httpd-rs` absent from the process table.
- `.htaccess` files are parsed lazily on the first request that walks into
  their directory (`htaccess.rs::parse_cached`). The panic happens *during*
  parse, before the parse result is cached, so the file remains a permanent
  kill switch: every restart dies on the next request into the tree.
- The attacker does not need a valid expression or any other directive: the
  panic precedes argument validation, `validate_vars`, and any runtime
  policy decision.

### 2.3 Reachability and threat model

| Trigger | Where parsed | `.htaccess` gate | Main config |
|---|---|---|---|
| `<If "… =~ éé">` / `<ElseIf>` | `htaccess.rs:1208/1222`, `config.rs:4186/4221` | section code 2 < 11 ⇒ admitted whenever **any** `AllowOverride` category is enabled (`AllowOverride AuthConfig`, `FileInfo`, `Options`, `Indexes`, `Limit`, `All`); `htaccess_section_category_admit` | abort at load/reload |
| `Require expr "… =~ éé"` | `parse_require` → `config.rs:7838` | `AllowOverride AuthConfig` | abort at load/reload |
| `RewriteCond expr "… =~ éé"` | `parse_rewrite_cond` → `config.rs:8013` | `AllowOverride FileInfo` | abort at load/reload |

This is the project's acknowledged threat model: `docs/agent-handoff.md`
H1 already classified expression-parser panics as reachable "per-request —
from an attacker-writable `.htaccess` (`htaccess.rs:795/813`), which is
inside this project's threat model (F60-D built upload→RCE on
`.htaccess`)", and `docs/verification-status.json` lists
`expr_parser_totality` — "Expression parsing is total: malformed input
errors, never panics" — as *implemented*. The H1 bounds fix
(`get(self.pos)`) landed; the char-boundary case did not. The totality
claim is false at HEAD.

The benchmark/conformance fixture is the vulnerable shape: it enables
`HttpdRsCapability AccessFiles On` and `AllowOverride All` on
`/www/htaccess`, and the feature benchmark drives `.htaccess` rewrite and
`Header` scenarios there. Any real deployment that mirrors the benchmark
(a writable directory under an enabled `AllowOverride`, e.g. an upload
area protected with `AllowOverride AuthConfig`) is exploitable by a
single uploaded `.htaccess`.

### 2.4 Live evidence

`python3 adversarial/p24/exploit_p24.py` (loopback only):

```text
== A1-htaccess-If-AuthConfig: ABORTED; first response b''
    thread 'conn' panicked at crates/server/src/expr.rs:1344:26:
    start byte index 21 is not a char boundary; it is inside 'é' (bytes 20..22 of string)
== A2-htaccess-Require-expr-AuthConfig: ABORTED; first response b''
    thread 'conn' panicked at crates/server/src/expr.rs:1344:26: ...
== A3-htaccess-RewriteCond-expr-FileInfo: ABORTED; first response b''
    thread 'conn' panicked at crates/server/src/expr.rs:1344:26: ...
== A4-htaccess-If-FileInfo: ABORTED; first response b''
    thread 'conn' panicked at crates/server/src/expr.rs:1344:26: ...
== A5-control-plain-If: alive rc=None; first response b'HTTP/1.1 200 OK\r\nDate: F'
== apache oracle: status 500 alive=True; /tmp/.../www/uploads/.htaccess: Cannot parse condition clause:
   syntax error, unexpected T_ERROR, expecting T_REGEX or T_REGEX_I: Parse error near '\xc3'
== B1-main-config-t: returncode -6 (SIGABRT)
    thread 'main' panicked at crates/server/src/expr.rs:1344:26: ...

P24-A exploit battery: PASS
```

The `.htaccess` payload used by A1/A4 (36 bytes):

```text
<If "%{REQUEST_URI} =~ éé">
</If>
```

Fixture: `www/uploads` is group/other-writable (simulating an upload
directory), `AllowOverride AuthConfig` (A1/A2) or `FileInfo` (A3/A4), and
`HttpdRsCapability AccessFiles On`. Apache is given the identical
`.htaccess`; it logs the parse error above, answers 500 for the request and
keeps serving — httpd-rs aborts the process.

### 2.5 Impact

- One small attacker-written file permanently denies service for **every**
  vhost/listener served by the process, not just the upload tree.
- Works with the common `AllowOverride AuthConfig` / `FileInfo` categories
  where `.htaccess` can otherwise only influence authorization, not
  execute code (e.g. `AllowOverrideList Require` rejects `<If>`, but
  `AllowOverride AuthConfig` admits it).
- Also turns an operator typo in the main configuration into a SIGABRT
  (`httpd-rs -t` exits -6) instead of a clean config error, which defeats
  fail-closed reload tooling.

### 2.6 Remediation direction

1. Make `Parser::regex()` (and every other `input[self.pos..]` site)
   char-boundary-safe. The minimal fail-closed fix matching Apache is to
   reject non-ASCII delimiters: if the byte at `self.pos` is ≥ 0x80, return
   `Err("regex delimiter must be ASCII")`; Apache 2.4.69 already rejects
   the same input with a 500. A byte-faithful implementation should scan
   `char_indices`/`&str` boundaries, keep raw bytes, and convert to `String`
   only on a valid boundary (or keep the pattern as `Vec<u8>`).
2. Fix the `out.push(b as char)` mojibake in `regex()`/`string()` while
   there: bytes 0xC3 0xA9 currently become `'Ã','©'` instead of `'é'`.
3. Add regressions: `parse("%{X} =~ éé")`, `parse("%{X} !~ éé")`,
   `parse("%{X} =~ €€")` must return `Err` (or parse identically to Apache)
   and never panic; add `adversarial/p24/crash-input.bin` to the
   `rewrite_expr` corpus; raise the smoke-gate runs for the expression
   target (the bug needs ~10⁴–10⁶ executions, not 64).
4. Move `expr_parser_totality` in `docs/verification-status.json` back to
   open/partial with this counterexample, and mechanize the totality
   obligation or a parser fuzz gate before re-claiming it.

---

## 3. P24-B — admitted regex work is miscalibrated for nested counted repetitions (secondary)

P23-A added `hir_complexity`, which charges a counted repetition as
`sub_complexity × max`. For `(?:X{0,m}){n}` the compiled automaton contains
`m+1` paths per inner repetition (the `{0,m}` expansion) and the engine
falls off the lazy-DFA path to the PikeVM, whose per-byte work is the
active-set size. The charge is therefore low by ~4–5× at `m=3`:

```text
$ /tmp/opencode/p24-probe/target/release/undercharge      # subject '1'×1328
1(?:[[:^alpha:]]{0,3}){4208}a: c=12627 units=16768656 cold=262.5ms warm=292.5ms
[[:^alpha:]]{12624}:           c=12624 units=16764672 cold=  0.0ms warm=  0.7ms
(?:[[:^alpha:]]{0,3}){4208}:   c=12624 units=16764672 cold=127.1ms warm=148.5ms
(?:[[:^alpha:]]){12624}:       c=12624 units=16764672 cold=  0.0ms warm=  0.7ms
```

The random-pattern sweep (`dosweep2`, 30 k patterns × 7 subject families,
full admitted lengths) tops out at:

```text
best=268.13ms c=12627 len=1328 pattern="1(?:[[:^alpha:]]{0,3}){4208}a"
best=155.39ms c=16306 len=1028 pattern="(?:^|\W{2,4}.){2038}[[:digit:]]"
best=148.51ms c=2038  len=8232 pattern="(?:\w{2030}(?:\W|\B)+[\d])"
```

With `MAX_EXPENSIVE_OPS = 32` (`resource.rs`), 32 concurrent admitted
evaluations of the 268 ms shape consume ~8.6 CPU-seconds per 268 ms window;
on the benchmark host (5 cores) six connections saturate every core and
other requests queue behind the `try_expensive` slots. This is a bounded
amplification, not an unbounded one, and it needs an operator pattern with
nested counted repetitions (or an attacker-writable `.htaccess` that is
already inside the P24-A threat model). It is recorded as a calibration
gap, not a standalone breakthrough: either charge `max+1` for `{0,m}` and
include the PikeVM active-set factor, or keep the lazy-DFA-only admission
when the DFA quits, and re-run the P23 benchmark at the gate boundary.

---

## 4. Reproduction

```sh
cd /root/httpd-rs
cargo build --release -p httpd-rs
python3 adversarial/p24/exploit_p24.py     # 7 verdicts, loopback only
```

Direct parser reproduction (no server needed):

```sh
printf '%{X} =~ \xc3\xa9\xc3\xa9' > /tmp/opencode/repro.txt
RUST_BACKTRACE=1 fuzz/target/x86_64-unknown-linux-gnu/release/rewrite_expr \
    /tmp/opencode/repro.txt -runs=1
```

Expected: `panicked at crates/server/src/expr.rs:1344:26: start byte index 11
is not a char boundary`.

Main-config reproduction: `httpd-rs -t` with
`<If "%{REQUEST_URI} =~ éé">` exits with signal 6 (SIGABRT).

P24-B probe (standalone, path dependency on `crates/pcre2`):

```sh
cd /tmp/opencode/p24-probe
cargo run --release --bin undercharge
cargo run --release --bin dosweep2 -- 30000
```

## 5. Retained files

- `adversarial/p24/exploit_p24.py` — 7-verdict live battery (A1–A4 abort,
  A5 control, Apache oracle, main-config `-t` abort).
- `adversarial/p24/crash-input.bin` — libFuzzer `rewrite_expr` artifact
  (`%{RUE( 'M(?THO`} =~\xd8\x92#^\`} =~\xd8\x92#^H1`).
- `/tmp/opencode/p24-harness`, `/tmp/opencode/p24-harness-main` — fixtures,
  configs and per-variant server output.
- `/tmp/opencode/p24-fuzz-rewrite_expr.log` — the crashing fuzz run.
- `/tmp/opencode/p24-probe` — standalone Rust probes for P24-B
  (`undercharge`, `dosweep2`, `dfablow`, `subjfuzz`).
- `/tmp/opencode/p24-dosweep2-big.log` — 30 k-pattern admitted-work sweep.

No product source was modified; `git status` at the end of the pass shows
only the new adversarial files and the `adversarial/README.md` index change.

## 6. Remediation closure

- `Parser::regex()` rejects a non-ASCII delimiter before changing `pos`,
  preserving the parser-wide UTF-8-boundary invariant. Its pattern accumulator
  and the quoted-string accumulator now retain bytes and validate them once,
  eliminating the adjacent mojibake bug.
- The unit regression covers `éé` for `=~` and `!~`, `€€`, the exact retained
  fuzzer artifact, Unicode strings, Unicode patterns and escaped Unicode.
  The minimal crash is also a permanent `rewrite_expr` corpus seed, and that
  target receives 16,384 smoke executions by default.
- Optional bounded repetitions charge `max + 1` paths and a 4× PikeVM
  active-set factor. The original 1,328-byte P24-B subject is rejected by the
  work gate; the admitted 249-byte boundary measures about 49 ms cold/warm on
  the pass host, below the approximately 65 ms policy calibration.
- `regex_optional_repeat_charge_bounds_pike_work` proves that the enlarged
  structural charge and ordinary product ceiling also bound the modeled
  optional-path PikeVM work.
