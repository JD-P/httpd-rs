# Pass 23 — adversarial break of HEAD `a54bcdd` (PCRE2 compatibility engine)

> Remediation status (2026-10-30): remediated in the product tree. Constructs
> with exact regular semantics now match the PCRE2 oracle; constructs whose
> priority requires look-around, atomics or PCRE2 capture history fail closed
> at configuration load. The original evidence below is retained unchanged.

### Remediation disposition

| Finding | Disposition |
|---|---|
| P23-A | Fixed. Runtime work complexity is derived from the parsed HIR, including finite repetition expansion; the final-newline second pass is charged twice. `a{60000}` on 64 KiB now returns `ResourceLimit` in sub-microsecond match time. |
| P23-B | Fixed/fail closed. Terminal `$`/`\Z` cases use bounded dual-position matching with `\z` isolation; non-terminal and lazy-priority forms that a look-around-free DFA cannot represent are rejected. |
| P23-C/D | Fixed. A single-pass PCRE byte-class parser handles negated POSIX classes, leading `]`, literal/range hyphens and out-of-order rejection. |
| P23-E | Fail closed. `\R` remains available in non-splitting contexts; quantified or adjacent split-capable CRLF forms are rejected. |
| P23-F | Fixed. Quoted bytes and class members are emitted as mode-independent byte escapes, including scoped/global inline `x`. |
| P23-G | Fixed. Each compile chooses a collision-free internal `\K` capture namespace. |
| P23-H | Fixed for the reported byte-mode forms: octal fallback, one-digit/braced hex, braced octal and quantification of escaped atoms. |
| P23-I | Fixed/fail closed. Fixed repetitions retain correct last-capture behavior; variable or zero-width-alternative capture histories are rejected precisely. |
| P23-J | Fixed/fail closed. Blanket POSIX/range and empty-alternative guards were removed; duplicate names remain a targeted unsupported feature. |
| P23-K/L | Fixed. CRLF `\N`/final-newline behavior and terminal multiline-empty iteration match the oracle. |
| P23-M | Fail closed. The ungrouped PCRE2 auto-possessification special case is rejected. |
| P23-N | Fixed. Byte classes are scanned once and rendered from a bounded 256-member set. |

Post-remediation validation uses the same fixed fuzzer seed against PCRE2
10.46. A 100,000-pattern run reports `match-diffs=0` and
`rust-accepts-pcre2-rejects=0`; 15,399 PCRE2-accepted cases are deliberately
outside the non-backtracking dialect and fail closed. The Rust port of
`testinput1` checks 1,002 admitted upstream subject cases, and the focused P23
suite contains seven regression groups. Performance results and the
reproducible runner are recorded in [`docs/pcre2-benchmark.md`](../docs/pcre2-benchmark.md).

- **Date:** 2026-10-29
- **Subject:** `target/release/httpd-rs` built at HEAD `a54bcdd`. The binary
  used for the live differential was rebuilt from that tree.
- **Oracle:** PCRE2 10.46 through the `pcre2` 0.2.11 crate (`libpcre2-8`), plus
  Apache/2.4.69 (Debian) for live `<If … =~ /…/>` differentials. All live
  servers bind loopback only.
- **Harness:** `adversarial/p23/exploit_p23.py` — **9 verdicts**: four
  expression-ACL verdicts (A1 negated-POSIX bypass, A2 class-range bypass,
  A3 inline-`(?x)` bypass and A3 overmatch), one CPU-amplification case and
  four controls. The focused probe
  `adversarial/p23/probe/src/bin/repro.rs` prints the exact span differences;
  `work2.rs` measures the counted-repetition cost.
- **Retained evidence:** `/tmp/opencode/p23-harness` (live configs, fixtures,
  logs), `/tmp/opencode/p23-repro.log`, `/tmp/opencode/p23-clean.log`,
  `/tmp/opencode/p23-expr.log`, `/tmp/opencode/p23-accept.log`.
- **Baseline:** `cargo test -p httpd-rs-pcre2 --release` passes 4 unit, 2
  differential and 1 upstream-corpus test. The official differential fuzz
  target has no coverage instrumentation in this environment, so the retained
  deterministic grammar fuzzer was used.

---

## 1. Executive summary

| # | Finding | Oracle / live Apache | httpd-rs HEAD | Class |
|---|---------|----------------------|--------------|-------|
| **P23-A** | Exact counted repetition expands to a large automaton, but the verified pattern×subject work bound charges only **pattern bytes**. `a{60000}` is an 8-byte pattern that the resource kernel admits for a 64 KiB subject (`8 × 65,536 = 524,288 << 16,777,216`). | Apache evaluates the live `a{8000}` guard in **0.4 ms**. | `a{60000}` on 64 KiB takes **15.8 s**; `a{8000}` on 8,190 bytes takes **~350 ms**; the live expression request takes **~363–383 ms** (≈974–1063× Apache). One request holds one of the 32 `MAX_EXPENSIVE_OPS` slots for that whole interval. | CPU denial of service; High when the pattern is attacker-influenced, Medium when only the subject is. |
| **P23-B** | The final-newline fallback in `capture_spans` matches a **trimmed** subject and then chooses the earlier group-0 start, keeping the full-subject result on a tie. It is not equivalent to PCRE2's zero-width `$`/`\Z` positions. | `secret$\n` matches `secret\n` at `(0,7)`; `^\Z\v` matches `\n` at `(0,1)`; `^foo\z$` does **not** match `foo\n`; `\z$` matches `\n` only at `(1,1)`. | `secret$\n` and `^\Z\v` return none; `^foo\z$` falsely returns `(0,3)`; `\z$` returns `(0,0)`; lazy `\D*?$` on `abcdefghij\n` returns `(0,11)` instead of `(0,10)`; `a$|a\n` on `a\n` returns `(0,2)` instead of `(0,1)`. | Anchor/ACL semantics; High. |
| **P23-C** | Negated POSIX classes are silently rewritten into a different class. `[[:^alpha:]]` becomes `[\x5B:^alpha:]]`; the translator does not recognise the leading `^`, escapes the inner `[`, and leaves the final `]` as a literal. | `[[:^alpha:]]` on `1` matches `(0,1)`; on `a]` PCRE2 matches only `(1,2)`. Live header `X: 123` → Apache **403**. | On `1` returns none; on `a]` returns `(0,2)`. Live header `X: 123` → httpd-rs **200** (ACL bypass). | Silent ACL bypass; High. |
| **P23-D** | Class hyphen/range handling escapes every `-` adjacent to another `-`, destroying ranges; the surrounding class grammar also differs for a leading `]`. | `[--1]` on `0` matches `(0,1)`; `[ --]` on `#` matches `(0,1)`; `[]-a]` on `-` does not match; `[a--]` is rejected with `range out of order`. Live header `X: 0` → Apache **403**. | `[--1]` and `[ --]` return none; `[]-a]` matches `(0,1)`; `[a--]` **compiles** and matches. Live header `X: 0` → httpd-rs **200** (ACL bypass). All printed clean-run over-acceptances are this class; the official fuzz target would panic on its `oracle_builder.build(...).expect(...)` assumption. | Class-semantic bypass plus over-acceptance; Medium. |
| **P23-E** | `\R` is lowered to ordinary alternation `(?:\r\n|[\n\v\f\r\x85])`, so CRLF is not atomic. | `\R\R` and `\R\C` on `\r\n` do **not** match; `\R+?$` on `\r\n\n` matches `(0,2)`. | `\R\R` and `\R\C` match `(0,2)`; `\R+?$` matches `(0,3)`. | Line-structure semantics; Medium. |
| **P23-F** | Inline `(?x)` is not reflected in the translator's `extended` flag. Spaces and `#` inside `\Q...\E` and classes are handled using the builder flag, while Rust's inline extended mode applies its own rules. | `(?x)\Qa b\E` on `a b` matches `(0,3)`; on `ab` it does not match; `(?x)[ a#b ]` matches a space. Live `X: a b` → Apache **403**; `X: ab` → Apache **200**. | Same pattern on `a b` returns none; on `ab` matches `(0,2)`; the class pattern fails to compile. Live `X: a b` → httpd-rs **200**; `X: ab` → httpd-rs **403** (bypass in one direction, false deny in the other). | ACL bypass / false deny; Medium. |
| **P23-G** | User capture names share the internal `__httpd_rs_pcre2_keep_` namespace used by `\K`. A user group with that prefix is filtered out of public numbering and its start is applied as the `\K` start. | `a(?P<__httpd_rs_pcre2_keep_0>b)` on `ab`: group 0 `(0,2)`, group 1 `(1,2)`. | Group 0 `(1,2)`, `captures_len() == 1`. | Capture/`$1` corruption; Low (requires pattern control). |
| **P23-H** | Valid PCRE2 escapes and quantified escapes are over-rejected: `\101`, `\10`, `\11`, `\1234`, `\x9`, `\x{0}`, `\o{101}`, `\x{42}{2}`, `\x{42}+`. | All compile and match their PCRE2 meanings (for example `\101` matches `A`, `\x{42}{2}` matches `BB`). | All are rejected as backreference, zero-count repetition, malformed escape or misplaced quantifier. | Config compatibility / availability; Medium. |
| **P23-I** | The `ambiguous_nested_capture_repeat` heuristic rejects any quantified capture whose body contains `* + ? {`, even for a literal `\x{42}` or `\d{2}`, and it misses zero-width alternatives. | `(\x{42})+` matches `BB` with capture `(1,2)`; `(\d{2})+` matches `1234` with capture `(2,4)`; `(\z|\C)+` leaves group 1 at `(5,5)`; `(a|\b)+` leaves it at `(2,2)`. | The first two are rejected; the accepted zero-width cases leave group 1 at `(4,5)` / `(1,2)`. | Wrong captures plus fail-closed rejection; Medium. |
| **P23-J** | Blanket guards reject valid regular patterns: any pattern containing both `[:` and `-`, any empty alternative, and `(?J)` duplicate names. | `[[:alpha:]]-[a-z]`, `[[:space:]]*-`, `a|`, `a||b`, `|a` and `(?J)(?<n>a)(?<n>b)` compile and match. | All are rejected with `POSIX class combined with a range`, `empty alternative`, or an unrecognised flag. | Availability / portability; Low. |
| **P23-K** | CRLF-mode lowering is incomplete: `\N` is always `[^\n]`, and the `$` fallback trims `\r\n` but not a lone `\r`. | With `crlf(true)`, `\N` on `\r` does not match; `a$` on `a\r` matches `(0,1)`. | `\N` matches `(0,1)`; `a$` returns none. | Latent library API; Low (not reached from `expr.rs`). |
| **P23-L** | Multiline empty-match iteration differs. | `(?m)^` on `a\n` iterates `[(0,0)]`; `(?m)^$` on `\n\n` iterates `[(0,0),(1,1)]`. | `[(0,0),(2,2)]`; `[(0,0),(1,1),(2,2)]`. | Iterator-only; Low (`expr.rs` uses `captures`, not the iterator). |
| **P23-M** | PCRE2's auto-possessification of `\N*?` changes a one-byte `\x85` case. | `\N*?\R` on `\x85` does not match; `(?:\N)*?\R` matches. | Both forms match. | Residual differential; Info. |
| **P23-N** | POSIX-class scanning is quadratic in the number of inner `[:` sequences. | A 64,002-byte pattern compiles in about **246 ms**. | Same pattern takes about **246 ms** and expands to 160,002 bytes. | Compile-time amplification; Low. |

The four live cases in `exploit_p23.py` are the strongest evidence: negated
POSIX, class-range and inline-`(?x)` guards deny on Apache but grant on
httpd-rs, and the counted-repetition case is a ~974–1063× CPU amplification with the
same `403` status on both servers.

---

## 2. Observed evidence

### 2.1 Differential fuzz counts

The retained fuzzer is deterministic (seed `0x9E3779B97F4A7C15`) and compares
the complete `captures_iter` span vectors of `httpd_rs_pcre2::bytes` and
`pcre2::bytes`.

```text
CLEAN=1 ONLY_MATCH=1 fuzz -- 1000000
  iterations=1000000 match-diffs=342 rust-accepts-pcre2-rejects=252
  pcre2-accepts-rust-rejects=10260 printed=200

EXPR=1 CLEAN=1 ONLY_MATCH=1 fuzz -- 2000000
  iterations=2000000 match-diffs=103 rust-accepts-pcre2-rejects=517
  pcre2-accepts-rust-rejects=20840 printed=101
```

`CLEAN=1` filters patterns containing `[:`, `(?x`, `\x{0}` or a multi-digit
escape so that the clean run is not dominated by the already-known
translation gaps. The `EXPR` mode uses the production expression flags
(`extended=false`, `multiline=false`, `crlf=false`, optional caseless) and
therefore reaches the negated-POSIX and inline-`(?x)` paths.

All 200 printed clean-run over-acceptances are invalid hyphen-range classes
(`[a--]`, `[^--#]`, `[1--]`, `[a--a]`, …). The first one is enough to violate
the official target's assumption:

```text
pattern "[a--]": rust COMPILES; PCRE2 error at offset 3:
  range out of order in character class
```

The EXPR over-rejection count is dominated by the capture-history heuristic
and by deliberately unsupported backtracking constructs; the unintentional
subset is analysed in P23-H/I/J.

### 2.2 Live Apache/httpd-rs differential

The live battery uses `<If "%{HTTP:X} =~ /PATTERN/"> Require all denied </If>`
with the same configuration on both servers. It needs only `mpm_event`,
`mime`, `dir`, `authz_core` and `authz_host`.

```text
PASS  C1-control-false: apache=200 httpd-rs=200
PASS  C2-control-true:  apache=403 httpd-rs=403
PASS  A1-negated-posix-bypass: apache=403 httpd-rs=200
PASS  A1-negated-posix-control: apache=200 httpd-rs=200
PASS  A2-class-range-bypass: apache=403 httpd-rs=200
PASS  A2-class-range-control: apache=403 httpd-rs=403
PASS  A3-inline-x-bypass: apache=403 httpd-rs=200
PASS  A3-inline-x-overmatch: apache=200 httpd-rs=403
PASS  B1-counted-repeat-dos: apache=403 0.4ms httpd-rs=403 363.0ms
       ratio=973.6x
verdicts: 9/9 reproduced
```

The A1 bypass uses header `X: 123` with `[[:^alpha:]]`; the A2 bypass uses
`X: 0` with `[--1]`; the A3 pair uses `X: a b` and `X: ab` with
`(?x)\Qa b\E`. The B1 case uses header `X:` followed by 8,000 `a` bytes and
the fixed operator pattern `a{8000}`. The statuses are deliberately equal in
B1; the finding is the ~363 ms versus 0.4 ms CPU cost.

### 2.3 Focused library probes

The full output is retained in `/tmp/opencode/p23-repro.log`; the key rows are
reproduced in the finding sections below. The probes build with the default
64 KiB pattern/subject limits, the default 16 MiB work limit and the default
2 MiB compiled-size limit.

---

## 3. Root cause and findings

### P23-A — counted repetition bypasses the verified pattern×subject ceiling

The verified admission kernel is:

```rust
// crates/verified/src/lib.rs:1759-1772
/// The non-backtracking engine has O(pattern * subject) worst-case work.
pub open spec fn regex_match_resource_spec(
    complexity: u64, subject: u64, subject_limit: u64, work_limit: u64,
) -> bool {
    complexity > 0
        && subject <= subject_limit
        && complexity <= work_limit
        && subject <= work_limit / complexity
}
```

`Regex::check_subject` passes `self.complexity` to that kernel:

```rust
// crates/pcre2/src/lib.rs:381-391
fn check_subject(&self, subject_len: usize, start: usize) -> Result<(), Error> {
    assert!(start <= subject_len, "start must be <= subject.len()");
    if !httpd_rs_verified::regex_match_resource_admit(
        self.complexity as u64,
        subject_len.saturating_sub(start) as u64,
        self.config.subject_limit as u64,
        self.config.work_limit,
    ) { … }
}
```

But `complexity` is only the **translated pattern byte length**:

```rust
// crates/pcre2/src/lib.rs:1068-1072
let pattern = String::from_utf8(out).expect("translation preserves UTF-8");
Ok(Translation {
    complexity: pattern.len(),
    pattern,
    final_newline_fallback,
})
```

and it is copied directly into the compiled object at `lib.rs:251`. For
`a{60000}`, `complexity == 8`, so a 64 KiB subject has an admitted product of
`8 × 65,536 = 524,288`, far below the 16,777,216 limit. The automata engine
still expands the exact repetition into roughly 60,000 states; the measured
match cost is:

| Pattern | Subject | Work charge (pattern bytes × subject) | Measured `captures` |
|---|---:|---:|---:|
| `a{25000}` | 64 KiB | 524,288 | 2.78 s |
| `a{30000}` | 64 KiB | 524,288 | 4.07 s |
| `a{40000}` | 64 KiB | 524,288 | 7.21 s |
| `a{50000}` | 64 KiB | 524,288 | 10.94 s |
| `a{60000}` | 64 KiB | 524,288 | **15.80 s** |
| `a{8000}` | 8,190 B | 57,330 | ~350 ms |
| `a{8000}` (live `<If>`) | 8,000 B header | 56,000 | **363.0 ms** |

`a{60000}` is admitted; `a{65535}` fails the separate 2 MiB compiled-size
limit, so the useful range stops somewhere below 65,535. The bounded form
`a{1,8000}` is fast
(about 3.6 ms), which confirms the problem is exact counted repetition
expansion rather than ordinary scanning.

`Expr::Regex` calls `regex.compiled.captures(&text)` under
`crate::resource::try_expensive()` (`crates/server/src/expr.rs:776-790`).
`MAX_EXPENSIVE_OPS = 32` (`crates/server/src/resource.rs:31`), so 32 concurrent
requests can occupy all slots with ~363 ms of CPU each (~11.6 CPU-seconds per
wave at the live 8,000-byte subject), and a 64 KiB subject can hold a slot for
15.8 s. The live battery uses a fixed operator pattern; an attacker who can
influence the pattern text (for example through a writable access file or a
configuration-templating path) can choose the worst case directly. Even
without pattern influence, any operator pattern with a large exact repetition
is remotely triggerable with a matching subject.

**Fix direction:** derive the work complexity from the compiled automaton
state count, or account for the expansion of exact counted repetitions
(`{m}` / `{m,}`) in `complexity`; cap the expanded state count; and account for
the `$`/`\Z` fallback's second match (P23-B). Add a regression that builds
`a{8000}` under the default limits and asserts a bounded cost, not just a
bounded pattern length.

### P23-B — the final-newline fallback is not PCRE2's anchor semantics

The fallback is armed for every `$` and `\Z` (`lib.rs:889-896`, `920-923`).
`capture_spans` runs the full subject and, when the fallback is armed, a copy
with the final newline removed; it then selects the earlier group-0 start and
keeps the full result on a tie:

```rust
// crates/pcre2/src/lib.rs:445-474
let full = self.inner.captures_at(subject, start);
let mut trimmed = None;
if self.final_newline_fallback {
    let trim = if self.config.crlf && subject.ends_with(b"\r\n") { 2 }
               else if subject.ends_with(b"\n") { 1 } else { 0 };
    if trim > 0 && start <= subject.len() - trim {
        trimmed = self.inner.captures_at(&subject[..subject.len() - trim], start);
    }
}
// Select the earlier leftmost match; if starts tie, retain the full-subject
// result and its normal greedy priority.
```

That comment is the core error: PCRE2's `$` and `\Z` are zero-width
assertions, and their priority relative to other tokens is pattern-dependent,
not "full-subject greedy priority." Four independent failure modes follow.

**(a) A token after the anchor cannot consume the newline.**

| Pattern | Subject | httpd-rs | PCRE2 |
|---|---|---|---|
| `secret$\n` | `secret\n` | None | `(0,7)` |
| `^\Z\v` | `\n` | None | `(0,1)` |
| `$\s` | `abcdef\n` | None | `(6,7)` |
| `\Z[^- #]$` | `a-\n` | None | `(2,3)` |

The trimmed subject has already removed the byte that the following token is
supposed to consume.

**(b) A lazy quantifier that can consume the newline returns a longer span.**

| Pattern | Subject | httpd-rs | PCRE2 |
|---|---|---|---|
| `\D*?$` | `abcdefghij\n` | `(0,11)` | `(0,10)` |
| `[^]]+?$` | `abcdefghij\n` | `(0,11)` | `(0,10)` |
| `[^a]??$` | `\n` | `(0,1)` | `(0,0)` |

The full and trimmed matches start at the same position, so the tie-break
keeps the full-subject result, even though the lazy branch preferred the
shorter one.

**(c) `\z` becomes satisfiable at the trimmed end.**

`\z` is an absolute-end assertion, but the fallback is armed whenever the
pattern also contains `$`:

| Pattern | Subject | httpd-rs | PCRE2 |
|---|---|---|---|
| `^foo\z$` | `foo\n` | `(0,3)` | None |
| `^\z$` | `\n` | `(0,0)` | None |
| `\z$` | `\n` | `(0,0)` | `(1,1)` |

This is a false positive for a redundant but perfectly valid `\z$` guard.

**(d) Alternation can consume the newline on the full branch.**

`a$|a\n` on `a\n` returns `(0,2)` because the second branch consumes the
newline, while PCRE2 prefers the first branch and returns `(0,1)`. The
fallback's "earlier start" rule cannot recover PCRE2's branch priority.

**Fix direction:** lower `$` and `\Z` to zero-width assertions that can match
at end-of-subject or immediately before a final newline without changing the
subject, for example `(?:\z|(?=\n\z))` (and the CRLF variant), and lower `\z`
strictly. Do not trim the subject, do not use `\z` in the fallback, and do not
apply the fallback in multiline mode. If the regular engine cannot express
the required assertion, reject the pattern at compile time rather than
returning a different match.

### P23-C — negated POSIX classes are silently rewritten

The translator recognises positive POSIX names only:

```rust
// crates/pcre2/src/lib.rs:797-835 (abridged)
b'[' if in_class => {
    if bytes.get(i + 1) == Some(&b':') {
        if let Some(relative_end) = bytes[i + 2..].windows(2)
            .position(|pair| pair == b":]") {
            let name = &pattern[i + 2..name_end];
            if matches!(name, "alnum" | "alpha" | … | "xdigit") {
                out.extend_from_slice(&bytes[i..end]);
                i = end;
                continue;
            }
        }
        out.extend_from_slice(b"\\x5B");   // inner `[` becomes a literal
    }
    …
}
```

For `[[:^alpha:]]`, `name` is `^alpha`, which is not in the positive list, so
the inner `[` is escaped; the first `]` after `alpha:` closes the Rust class,
and the final `]` is a literal. The translated pattern is
`[\x5B:^alpha:]]`.

| Pattern | Subject | httpd-rs | PCRE2 |
|---|---|---|---|
| `[[:^alpha:]]` | `1` | None | `(0,1)` |
| `[[:^alpha:]]` | `a]` | `(0,2)` | `(1,2)` |
| `[[:^digit:]]` | `x` | None | `(0,1)` |

The live A1 case turns this into an ACL bypass: `X: 123` is non-alpha, so
Apache's negated class matches and denies, while httpd-rs's rewritten class
does not match and grants. `X: abc` is the control (both 200).

**Fix direction:** parse the optional `^` before the POSIX name and emit a
proper negated class (`[^A-Za-z]`, or the equivalent byte set); do not escape
the inner `[`; keep the final `]` as the class terminator. If Rust's POSIX
negation is used, verify its Unicode/ASCII semantics against PCRE2's
non-UCP mode.

### P23-D — hyphen ranges are corrupted and invalid ranges are accepted

The class branch escapes a hyphen whenever either neighbour is another
hyphen:

```rust
// crates/pcre2/src/lib.rs:1046-1055
if in_class
    && (byte == b'&'
        || byte == b'~'
        || (byte == b'-'
            && (bytes.get(i.wrapping_sub(1)) == Some(&b'-')
                || bytes.get(i + 1) == Some(&b'-'))))
{
    out.extend_from_slice(format!("\\x{byte:02X}").as_bytes());
}
```

In PCRE2, `[--1]` is a range from `-` to `1`; in httpd-rs both hyphens become
literal `\x2D`, so the class is only `{-, 1}`. The same loss occurs for
`[ --]` (space through `-`). Conversely, `[a--]` is an invalid out-of-order
range in PCRE2 but becomes `[a\x2D\x2D]` and compiles in httpd-rs.

| Pattern | Subject | httpd-rs | PCRE2 |
|---|---|---|---|
| `[--1]` | `0` / `.` | None | `(0,1)` |
| `[ --]` | `#` | None | `(0,1)` |
| `[]-a]` | `-` | `(0,1)` | None |
| `[a--]` | `a` | `(0,1)` | compile error: `range out of order` |

The live A2 case uses `X: 0` and `[--1]`: Apache 403, httpd-rs 200. `X: -` is
the control (both 403). The clean fuzz run's 252 over-acceptances are this
family; the official target would panic because it asserts that every
Rust-accepted pattern is accepted by PCRE2
(`fuzz/fuzz_targets/pcre2_differential.rs:79-81`).

**Fix direction:** parse character classes with PCRE2's grammar: preserve a
literal leading `]`, recognise ranges only when the hyphen is between two
valid endpoints, reject out-of-order ranges, and escape only hyphens that are
literal members. Add `[a--]`, `[--1]`, `[ --]`, `[]-a]` to the fixed
differential corpus.

### P23-E — `\R` is not atomic across CRLF

`\R` is lowered to a plain alternation:

```rust
// crates/pcre2/src/lib.rs:929-931
b'R' if !in_class => {
    out.extend_from_slice(b"(?:\\r\\n|[\\n\\x0B\\f\\r\\x85])");
    i += 2;
}
```

The first alternative consumes CRLF, but the second can consume CR alone and
leave LF for the next token; PCRE2 treats CRLF as one `\R` unit and does not
allow that split.

| Pattern | Subject | httpd-rs | PCRE2 |
|---|---|---|---|
| `\R\R` | `\r\n` | `(0,2)` | None |
| `\R\C` | `\r\n` | `(0,2)` | None |
| `\R+?$` | `\r\n\n` | `(0,3)` | `(0,2)` |

**Fix direction:** use an atomic/lookahead-capable lowering (`\r\n` as one
alternative with the bare `\r` alternative excluded when followed by `\n`),
or reject `\R` when the following token can consume a newline. Rust's automata
engine has no atomic groups, so a dedicated translation or a fail-closed
context check is needed.

### P23-F — inline `(?x)` is not tracked during translation

`translate` receives only the builder's `extended` flag:

```rust
// crates/pcre2/src/lib.rs:186-191
let translation = translate(
    pattern,
    self.config.multi_line,
    self.config.crlf,
    self.config.extended,
)?;
```

and the Rust builder is configured from the same flag at `lib.rs:198-207`.
An inline `(?x)` is left for Rust's parser. The translator's `\Q...\E`
handler calls `append_quoted_literal(..., extended)` (`lib.rs:910`), and the
class branch escapes whitespace/`#` only when `extended` is true
(`lib.rs:1056`). With inline `(?x)`, PCRE2 treats whitespace and `#` inside
`\Q...\E` and classes as literal, while Rust's inline extended mode ignores
them.

| Pattern | Subject | httpd-rs | PCRE2 |
|---|---|---|---|
| `(?x)\Qa b\E` | `a b` | None | `(0,3)` |
| `(?x)\Qa b\E` | `ab` | `(0,2)` | None |
| `(?x)[ a#b ]` | ` ` | compile error: unclosed class | `(0,1)` |
| `(?x:\Qa b\E)` | `a b` | None | `(0,3)` |

The live A3 pair shows both directions: a guard that should deny `a b`
grants it, while a guard that should allow `ab` denies it.

**Fix direction:** track inline `(?x)`, `(?-x)` and scoped `(?x:...)` state in
the translator and use the effective extended mode for quoted literals and
classes, or reject inline extended mode and require the builder flag. Add
tests for `\Q...\E`, classes and `#` comments under `(?x)`.

### P23-G — user captures collide with internal `\K` names

`\K` is lowered to a named capture with a fixed prefix:

```rust
// crates/pcre2/src/lib.rs:25
const KEEP_PREFIX: &str = "__httpd_rs_pcre2_keep_";

// lib.rs:220-227
for (index, name) in inner_names.iter().enumerate().skip(1) {
    if name.as_deref().is_some_and(|name| name.starts_with(KEEP_PREFIX)) {
        keep_groups.push(index);
        continue;
    }
    …
}
```

A user group named `__httpd_rs_pcre2_keep_0` is therefore filtered out of the
public capture list and treated as an internal `\K` group:

```text
a(?P<__httpd_rs_pcre2_keep_0>b) on "ab"
  httpd-rs: group0 (1,2), captures_len 1
  PCRE2:   group0 (0,2), group1 (1,2)
```

`expr.rs` fills `ctx.captures` from `captures_len()` and `get(i)`, so a
pattern using this name can shift or remove `$1`. The reserved prefix is
attacker-reachable only when the pattern text is attacker-influenced, but it
is also a straightforward collision for a legitimate pattern author.

**Fix direction:** use an internal group name that cannot be expressed in a
PCRE2 pattern, or track the exact inserted group indices separately from
user names. Reject or rename a user group with the reserved prefix.

### P23-H — valid escapes and quantified escapes are over-rejected

The escape parser has several PCRE2-incompatible assumptions:

```rust
// crates/pcre2/src/lib.rs:1006-1030
b'1'..=b'9' | b'g' | b'k' => {
    return Err(Error::unsupported(i, "backreference"));
}
…
b'{' if !in_class
    && (bytes[i..].starts_with(b"{0}") || bytes[i..].starts_with(b"{0,0}")) =>
{
    return Err(Error::unsupported(i, "zero-count repetition"));
}
```

- `\1`–`\9` are always treated as backreferences, but PCRE2 falls back to
  octal when the referenced group does not exist: `\101` is `A`, `\10` is
  backspace, `\11` is tab, `\1234` is octal `\123` followed by `4`.
- `\x` is passed through as one digit, but Rust requires two: `\x9` is a tab
  in PCRE2.
- The zero-count check matches the `{0}` in `\x{0}` / `\o{0}`, not just a
  repetition quantifier.
- `\o{101}` is PCRE2's octal syntax; httpd-rs passes `\o` to Rust and gets an
  unrecognised escape.
- The possessive check at `lib.rs:1022` sees the `}` from `\x{42}` and treats
  a following `+` as a possessive quantifier.
- `invalid_quantifier_placement` skips only two bytes for `\x`
  (`lib.rs:1123-1141`), then parses `{42}` as a repetition at
  `lib.rs:1211-1219`. A valid `\x{42}{2}` is therefore rejected; `\x{42}+`
  is rejected by the possessive check; `\x{42}?` happens to compile, so the
  accepted set is inconsistent as well as incomplete.

| Pattern | Subject | httpd-rs | PCRE2 |
|---|---|---|---|
| `\101` | `A` | compile error: backreference | `(0,1)` |
| `\10` | `\x08` | compile error: backreference | `(0,1)` |
| `\x9` | `\t` | compile error: incomplete escape | `(0,1)` |
| `\x{0}` | NUL | compile error: zero-count repetition | `(0,1)` |
| `\o{101}` | `A` | compile error: unrecognised escape | `(0,1)` |
| `\x{42}{2}` | `BB` | compile error: misplaced quantifier | `(0,2)` |
| `\x{42}+` | `BB` | compile error: possessive quantifier | `(0,2)` |

These are fail-closed, so they do not create an ACL bypass by themselves; they
do make valid Apache configurations fail to load (or, if a config manager
ignores the load error, remove the intended guard). The official corpus does
not cover them.

**Fix direction:** implement PCRE2's escape disambiguation (backreference only
when the group exists, otherwise octal), accept one- and two-digit hex,
implement `\o{...}`, and make the quantifier scanner parse `\x{...}`,
`\o{...}` and `\cX` as single atoms before looking for a following
quantifier. Add the table above to the differential tests.

### P23-I — the capture-history heuristic both over-rejects and misses cases

```rust
// crates/pcre2/src/lib.rs:1286-1293
if !capturing || !matches!(bytes.get(index + 1), Some(b'*' | b'+' | b'?' | b'{')) {
    continue;
}
if bytes[start + 1..index]
    .iter()
    .any(|byte| matches!(byte, b'*' | b'+' | b'?' | b'{'))
{
    return Some(index + 1);
}
```

Any quantified capturing group whose body contains `*`, `+`, `?` or `{` is
rejected. That includes literal braces from `\x{42}` and bounded repetition
inside the group:

| Pattern | Subject | httpd-rs | PCRE2 |
|---|---|---|---|
| `(\x{42})+` | `BB` | compile error: ambiguous capture history | `(0,2),(1,2)` |
| `(\d{2})+` | `1234` | compile error | `(0,4),(2,4)` |
| `(\z|\C)+` | `abcde` | group1 `(4,5)` | group1 `(5,5)` |
| `(a|\b)+` | `aa` | group1 `(1,2)` | group1 `(2,2)` |
| `(a|$)+` | `aa` | group1 `(1,2)` | group1 `(2,2)` |

The heuristic does not inspect alternation or zero-width branches, so it
misses exactly the cases where the automata engine's capture preference
differs from PCRE2's last-participating-iteration rule. When it does accept a
pattern, `expr.rs` uses the captures for `$1`; a wrong group start can change
a rewrite or a follow-up condition.

**Fix direction:** either implement PCRE2's capture history for quantified
groups or reject the whole class uniformly with a precise diagnostic. Do not
use a substring heuristic; at minimum, detect zero-width alternatives (`\z`,
`\b`, `$`, `\Z`, `^`) and reject them as well, and do not treat `{` inside
`\x{...}` as repetition.

### P23-J — blanket guards reject valid regular patterns

Two guards are much broader than their intended hazards:

```rust
// crates/pcre2/src/lib.rs:772-779
if pattern.contains("[:") && pattern.contains('-') {
    return Err(Error::unsupported(0, "POSIX class combined with a range"));
}

// lib.rs:1032-1041
b'|' if !in_class
    && (i == 0
        || matches!(bytes.get(i.wrapping_sub(1)), Some(b'(' | b'|'))
        || matches!(bytes.get(i + 1), None | Some(b')') | Some(b'|'))) =>
{
    return Err(Error::unsupported(i, "empty alternative"));
}
```

| Pattern | httpd-rs | PCRE2 |
|---|---|---|
| `[[:alpha:]]-[a-z]` | compile error: POSIX class combined with a range | compiles, matches `a-b` |
| `[[:space:]]*-` | compile error | compiles, matches ` -` |
| `a|` / `a||b` / `|a` | compile error: empty alternative | compiles; `a|` matches `a`, `|a` matches empty |
| `(?J)(?<n>a)(?<n>b)` | compile error: unrecognised flag | compiles with duplicate names |

The POSIX+range guard fires on a `-` anywhere in the pattern, not just in the
class, and on `[:` inside quoted text. The empty-alternative guard rejects
patterns with no capture ambiguity at all. These are availability and
portability failures; a valid Apache configuration is rejected at load time.
The duplicate-name form is another deliberate-looking over-rejection that
should be documented or implemented.

**Fix direction:** remove the blanket substring checks and let the class
parser decide; allow empty alternatives unless a quantified capturing group
actually needs the capture-history restriction; either implement `(?J)` or
document it as unsupported with a precise message.

---

## 4. Secondary observations

### P23-K — CRLF-mode lowering is incomplete (Low, latent)

`translate` takes `_crlf` but never uses it (`lib.rs:754`), and `\N` is always
`[^\n]` (`lib.rs:933-935`). With `crlf(true)`:

| Pattern | Subject | httpd-rs | PCRE2 |
|---|---|---|---|
| `\N` | `\r` | `(0,1)` | None |
| `a$` | `a\r` | None | `(0,1)` |

The `$` fallback trims only `\r\n` when `crlf` is true (`lib.rs:448-454`), not
a lone `\r`. `ExprRegex::compile` never sets `crlf` (`crates/server/src/expr.rs:52-58`),
so this is a library-API bug rather than a current expression-surface bug.
It should still be fixed because the builder advertises `crlf`.

### P23-L — multiline empty-match iteration differs (Low, iterator-only)

`(?m)^` on `a\n` yields `[(0,0),(2,2)]` in httpd-rs and `[(0,0)]` in PCRE2;
`(?m)^$` on `\n\n` yields an extra `(3,3)`. The first `captures()` result is
the same, and `expr.rs` calls `captures`, not `captures_iter`, so there is no
server impact today. A caller using `captures_iter` sees extra empty matches.

### P23-M — `\N*?\R` auto-possessification differential (Info)

`\N*?\R` on the single byte `\x85` matches in httpd-rs and not in PCRE2;
`(?:\N)*?\R` matches in both. This is a PCRE2 optimizer/auto-possessification
quirk rather than a translation error, but it is a residual differential that
the official corpus should classify explicitly.

### P23-N — quadratic POSIX-class scan at compile time (Low)

The inner-`[` handling calls `windows(2).position(...)` from each `[` at
`lib.rs:799-800`, which is quadratic in the number of `[:` sequences. A
64,002-byte pattern `[` + `[:` × 32,000 + `]` compiles in about **246 ms**
(translated length 160,002). At the 64 KiB expression-pattern limit this is a
config-load amplification, not a request-time attack; it is still worth a
single-pass scan.

---

## 5. Impact and preconditions

- **P23-C, P23-D, P23-F** are the direct ACL findings. They need a guard whose
  pattern uses the affected construct, but that is a normal configuration
  shape (`[[:^alpha:]]`, `[--1]`, `(?x)\Q...\E`). The live battery shows
  Apache denying and httpd-rs granting for A1/A2/A3-bypass; A3-overmatch shows
  the opposite direction (false deny).
- **P23-A** needs a subject large enough to reach the expanded automaton and
  either an operator pattern with a large exact repetition or attacker
  influence over the pattern. The live case deliberately uses the former,
  weaker precondition and still shows ~974×. The 32-slot expensive-work budget
  makes this a process-wide CPU denial, not a per-connection slowdown.
- **P23-B and P23-E** need a subject ending in a newline / containing CRLF.
  Header and URI values cannot carry a raw newline, but `file()` subjects and
  other multi-line variables can; a guard that validates uploaded or generated
  content with `$`, `\Z` or `\R` can therefore be flipped. The library-level
  spans are wrong even when the boolean result happens to agree.
- **P23-G, P23-H, P23-I, P23-J** are primarily correctness/compatibility
  findings. P23-G/P23-I can change captures used by `$1`; P23-H/P23-J reject
  valid configs at load time (fail closed). They are still relevant to a
  drop-in replacement because a valid Apache configuration must not fail to
  load, and because an ignored load error can remove a guard.
- **P23-K, P23-L, P23-M, P23-N** are low-severity or latent. P23-K is not
  reachable from `expr.rs`; P23-L is iterator-only; P23-M is an optimizer
  differential; P23-N is compile-time amplification.

---

## 6. Relationship to prior findings

- **P15-C** established that expression regexes must compile through the
  in-tree PCRE2 frontend and that later resource errors are fail closed. The
  current `ExprRegex::compile` does that (`crates/server/src/expr.rs:40-65`).
  P23-C/P23-D/P23-F are new **semantic** bugs inside that frontend, not a
  regression of the P15-C load-time gate. P23-H/P23-I/P23-J are over-rejection
  that can make a valid Apache configuration fail at load time; they do not
  silently remove a guard unless a caller ignores the load error.
- **P16** covered Rust `regex` Unicode/ASCII class semantics on directive
  regexes. P23 is specifically the PCRE2 compatibility surface used by
  `Require expr`/`<If>`; the two findings sets do not duplicate each other.
- The official differential target
  (`fuzz/fuzz_targets/pcre2_differential.rs:79-81`) assumes
  `rust build succeeds => PCRE2 build succeeds`. P23-D disproves that
  assumption (`[a--]`); the target should either assert only on the intended
  regular subset or turn the over-acceptance into a reported bug rather than a
  panic. The retained fuzzer treats it as a finding and keeps going.

---

## 7. Reproduction

Baseline:

```sh
cd /root/httpd-rs
cargo test -p httpd-rs-pcre2 --release
```

Focused library probes (deterministic, no Apache required):

```sh
cd /root/httpd-rs/adversarial/p23/probe
CARGO_TARGET_DIR=/tmp/opencode/p23-probe-target cargo run --release --bin repro
CARGO_TARGET_DIR=/tmp/opencode/p23-probe-target cargo run --release --bin work2
CARGO_TARGET_DIR=/tmp/opencode/p23-probe-target cargo run --release --bin work3
```

`work2` is the 64 KiB counted-repetition benchmark and takes roughly 40 s at
the largest admitted values. The expected tail is:

```text
n=60000 plen=8 compile=4.036175ms match=15.796734556s result=Ok(Some(1))
n=65535 compile=1.316255ms CERR Compiled regex exceeds size limit of 2097152 bytes.
```

Fuzzing:

```sh
cd /root/httpd-rs/adversarial/p23/probe
CARGO_TARGET_DIR=/tmp/opencode/p23-probe-target \
  CLEAN=1 ONLY_MATCH=1 cargo run --release --bin fuzz -- 1000000
CARGO_TARGET_DIR=/tmp/opencode/p23-probe-target \
  EXPR=1 CLEAN=1 ONLY_MATCH=1 cargo run --release --bin fuzz -- 2000000
```

Live Apache/httpd-rs differential:

```sh
cd /root/httpd-rs
cargo build --release -p httpd-rs
python3 adversarial/p23/exploit_p23.py
```

The harness creates `/tmp/opencode/p23-harness/<case>/{apache,httpd-rs}.conf`,
fixtures and logs, starts both servers on sibling loopback ports with separate
pid files, and prints the 9 verdicts. It needs Apache's `mpm_event`, `mime`,
`dir`, `authz_core` and `authz_host` modules; it does not need PHP or FastCGI.

---

## 8. Suggested remediation direction

1. **P23-A:** replace `complexity = translated_pattern.len()` with a bound that
   reflects the compiled automaton or at least the exact-repetition expansion;
   cap expanded counted repetition and account for the `$`/`\Z` second match.
   Add a regression with `a{8000}` at the default limits that asserts bounded
   work, not merely a bounded pattern string.
2. **P23-B:** implement `$`/`\Z` as zero-width assertions without trimming the
   subject; keep `\z` absolute; handle multiline and CRLF; add all nine table
   cases to the fixed differential corpus.
3. **P23-C/D/F:** replace the ad-hoc class/quote/inline-flag handling with a
   PCRE2-compatible class parser and an inline-flag-aware translator. In
   particular, support negated POSIX names, preserve leading `]`, validate
   ranges, and apply the effective `(?x)` mode to `\Q...\E` and classes.
4. **P23-E:** make `\R` atomic across CRLF or reject the split-capable
   contexts; add `\R\R`, `\R\C` and `\R+?$` regressions.
5. **P23-G:** remove the user-visible `__httpd_rs_pcre2_keep_` namespace
   collision; track inserted `\K` groups separately and reject reserved user
   names.
6. **P23-H/I/J:** parse escapes and quantifiers with PCRE2's atom rules
   (`\x{...}`, `\o{...}`, `\cX`, octal fallback); replace the capture-history
   substring heuristic with a precise implementation or a uniform fail-closed
   rejection; remove the blanket `[:`+`-` and empty-alternative guards.
7. **P23-K/L/M/N:** fix CRLF `\N`/`$`, align iterator empty-match advancement,
   classify the `\N*?` optimizer differential, and make the POSIX scan linear.
8. **Harness:** stop asserting that a Rust-accepted pattern must be accepted by
   PCRE2; add the fixed P23 corpus to the official differential tests and keep
   the live 9-case battery in the adversarial gate.

---

## 9. Retained files

- `adversarial/p23/exploit_p23.py` — 9-verdict live Apache/httpd-rs battery.
- `adversarial/p23/probe/Cargo.toml`, `Cargo.lock` — standalone probe crate
  (excluded from the product workspace with `[workspace]`).
- `adversarial/p23/probe/src/bin/repro.rs` — exact span/compile repros for
  P23-B through P23-M.
- `adversarial/p23/probe/src/bin/fuzz.rs` — deterministic grammar fuzzer
  (`CLEAN`, `EXPR`, `ONLY_MATCH`, `ONLY_ACCEPT`, `ONLY_REJECT` modes).
- `adversarial/p23/probe/src/bin/work2.rs` — 64 KiB counted-repetition
  benchmark.
- `adversarial/p23/probe/src/bin/work3.rs` — 8,190-byte and larger-subject
  counted-repetition sweep.
- `/tmp/opencode/p23-harness` — live configs, fixtures and logs.
- `/tmp/opencode/p23-repro.log`, `/tmp/opencode/p23-clean.log`,
  `/tmp/opencode/p23-expr.log`, `/tmp/opencode/p23-accept.log` — probe and
  fuzz outputs.

No product source was modified; `git status` at the end of the pass showed
only the new adversarial files (`adversarial/findings_p23.md`,
`adversarial/p23/`) and the `adversarial/README.md` index change.
