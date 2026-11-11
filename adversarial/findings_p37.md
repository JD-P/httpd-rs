# Pass 37 — CRLF `\R` and multiline `^` divergences escape the PCRE2 fail-closed gate

- **Date:** 2026-11-11
- **Subject:** HEAD `7ec4fa7ff2a93ee11fb188839781dd7379969e93`
  (`target/release/vapached`, rebuilt from the checked-out tree; no product
  source was edited).
- **Oracle:** PCRE2 10.46 through the pinned `pcre2` 0.2.11 /
  `pcre2-sys` 0.2.10 oracle used by the crate's own `pcre2_differential`
  target. Apache/2.4.69 (Debian) was used for the retained battery replays.
- **Harness:** `adversarial/p37/probe` (standalone crate, path dependency on
  `crates/pcre2`, same oracle binding as the fuzz target) plus the repository's
  `pcre2_differential` fuzzer; retained output
  `adversarial/p37/results_p37.txt`, crash inputs
  `crash-pcre2-crlf-multiline.bin` and
  `crash-pcre2-crlf-multiline-at-offset.bin`.
- **Method:** (1) fuzz the newest unreviewed commit's PCRE2 frontend
  (`pcre2_differential`, both retained runs); (2) build a focused
  offset-0/caseless-only differential restricted to the surfaces the server
  actually consumes (`apache_regex` and `ExprRegex`); (3) test whether the
  accepted divergent patterns compile through the production configuration
  path; (4) enumerate the request channels that can supply a subject and
  decide whether any carries CR/LF.
- **Disposition:** **P37-A and P37-B confirmed at HEAD.** Both are
  engine-contract divergences the P23-E/P35-B fail-closed gate was supposed to
  prevent: the divergent shapes are still *admitted* by the frontend, so a
  configuration using them compiles and can behave differently from Apache.
  No request-reachable channel was found that carries CR/LF into a regex
  subject, so no live server exploit is demonstrated; recorded as
  `unclassified` in line with the earlier P23-K/P23-L library-surface
  findings.

---

## 1. Executive summary

| # | Finding | PCRE2 10.46 | in-tree frontend | Class |
|---|---------|-------------|------------------|-------|
| **P37-A** | `\R` is lowered to a non-atomic alternation and the P23-E/P35-B gate only rejects the enumerated splitting shapes. `\R\s`, `\R\v`, `\R$`, `\R\Z` and `\R(?m:^)` remain admitted and diverge: Rust additionally matches `\r\n\0` with `\R\s`, and its `\R$`/`\R\Z` captures consume only the `\r` of a `\r\n` pair. | `\R\s` on `\r\n\0` does not match; `\R$` on `x\r\n` captures `(1,3)`. | `\R\s` matches; `\R$` captures `(1,2)`. | unclassified — engine compatibility contract; line-structure semantics |
| **P37-B** | Multiline `^` is delegated to the backend anchor semantics, which treat the position after a final newline as a line start where PCRE2 explicitly does not; the offset APIs also diverge in CRLF mode. `\D(?m:^)$` matches `\n`; `(?:[^]a](?m:^))` matches `\r\n`; the repository's own `pcre2_differential` target crashes on two minimized inputs. | `\D(?m:^)$` on `\n` does not match. | `\D(?m:^)$` on `\n` matches; `find_at`/`is_match_at` diverge in CRLF mode (`(?m)^` at start 3; `\r^` at start 2). | unclassified — engine compatibility contract; latent offset-API divergence |

The two findings are separate code paths: fixing the `\R` lowering does not
change the multiline-anchor behavior, and vice versa. Both are in the
compatibility frontend rewritten by the newest unreviewed commit
`881cae7` ("Harden PCRE2 grammar and adversarial handling"). P37-B is caught
directly by the repository's own `pcre2_differential` fuzzer (exit 77, two
retained artifacts); P37-A was found by the focused production-surface
differential.

### Why this matters for the Apache parity contract

The crate exists to be the fail-closed standalone boundary for every
security-relevant directive regex (`apache_regex`, `ExprRegex`). Its contract
in the P23 closure table is: shapes that the non-backtracking engine cannot
reproduce faithfully are *rejected at load* (`P23-E`: "quantified or adjacent
split-capable CRLF forms are rejected"); accepted shapes must match the PCRE2
oracle. P37-A/P37-B are neither rejected nor equal to the oracle. A
configuration such as

```apache
RewriteEngine On
RewriteCond %{REQUEST_URI} !\R\s
RewriteRule ^ - [F]
```

is accepted by `vapached -t` (retained evidence in `results_p37.txt`, `Syntax
OK`, `rc=0`) while the engine's boolean `\R\s` differs from PCRE2 for a
CRLF+non-whitespace subject in the `[F]`-skip direction.

### Why no live exploit is claimed

The server evaluates all regexes at start offset 0 with only `caseless`
enabled (`crates/server/src/apache_regex.rs`,
`crates/server/src/expr.rs`), and the divergent cases require a CR/LF byte in
the *subject*. Every request-controlled subject source rejects those bytes
before evaluation:

- decoded URL paths (`percent_decode_path` → `is_path_byte` requires
  `b >= 0x20`, rejecting `\r`, `\n`, `\0`; `\x85`/obs-text remain allowed and
  were probed without divergence);
- header values (the verified head parser rejects CTLs); and
- the request target/query and CGI environment (no CTLs reach them).

The only remaining channel is a configured expression that reads file
contents (`file('…')`), which an operator must explicitly point at a
CRLF-bearing file. That is not a benchmarked deployment shape and no such
differential was retained, so the findings are recorded without a
demonstrated attacker outcome.

---

## 2. P37-A — `\R` split-capable adjacency is accepted and diverges

### 2.1 Root cause

`\R` is translated to an alternation:

```rust
// crates/pcre2/src/lib.rs:1797-1800
b'R' => {
    out.extend_from_slice(b"(?:\\r\\n|[\\n\\x0B\\f\\r\\x85])");
    i += 2;
}
```

A backtracking engine visits the `\r\n` branch first so CRLF is consumed as
one unit, matching PCRE2. The in-tree engine's priority execution does not
reproduce that atomicity: for `\R$` on `x\r\n` it captures `(1,2)` (the `\r`
alone) where PCRE2 captures `(1,3)`.

The P23-E gate in `validate_line_constructs` deliberately rejects the
enumerated splitting shapes:

```rust
// crates/pcre2/src/lib.rs:2175-2189 (`\R` followed by a quantifier, `\R\C`)
// crates/pcre2/src/lib.rs:2211-2229 (`\S*`/`\N*` auto-possessified prefix)
```

It does not reject a following generic class or anchor. The retained probe
shows the current closure:

```text
"\R\R": rejected (Unsupported)
"\R\C": rejected (Unsupported)
"\R+?$": rejected (Unsupported)
"\N*?\R": rejected (Unsupported)
"\S*\R": rejected (Unsupported)
"\R\s": admitted by the Rust frontend
"\R\v": admitted by the Rust frontend
"\R$": admitted by the Rust frontend
"\R\Z": admitted by the Rust frontend
"\D(?m:^)$": admitted by the Rust frontend
```

### 2.2 Demonstrated divergence

From `adversarial/p37/results_p37.txt`:

| Pattern | Subject | In-tree `is_match`/captures | PCRE2 10.46 |
|---|---|---|---|
| `\R\s` | `[13,10,0]` (`\r\n\0`) | match, `(0,2)` | no match |
| `\R\v` | `[13,10]` (`\r\n`) | match, `(0,2)` | no match |
| `\R$` | `[120,13,10]` (`x\r\n`) | `(1,2)` | `(1,3)` |
| `\R\Z` | `[0,13,10]` (`\0\r\n`) | `(1,2)` | `(1,3)` |

The boolean divergences are the dangerous direction: for a guard whose action
is skipped when the pattern matches, the engine matches where PCRE2 does not
(the `!\R\s` + `[F]` shape above). The capture divergences would change `$N`
substitutions for a CRLF-bearing subject.

### 2.3 Reachability

CR/LF/NUL are rejected by `percent_decode_path` (`is_path_byte`) and by the
header-value grammar, so ordinary requests cannot construct the subject. The
probe's request-byte controls (`\x85`, obs-text, ordinary paths) all agree
with PCRE2. The finding is therefore an engine/config-contract defect, not a
demonstrated request exploit.

---

## 3. P37-B — multiline `^` at a final newline, and the offset APIs

### 3.1 Root cause

`^` is passed through to the backend unchanged:

```rust
// crates/pcre2/src/lib.rs:1737-1741
b'^' => {
    saw_multiline_start |= effective_multiline;
    out.push(b'^');
    i += 1;
}
```

PCRE2's multiline circumflex does not match after a newline that ends the
subject; the backend anchor semantics do. P23-L fixed only the *iterator*
shape (`captures_iter` on `(?m)^`); `is_match`/`captures` and the offset APIs
were left divergent.

### 3.2 Demonstrated divergence

| Case | In-tree | PCRE2 10.46 |
|---|---|---|
| `\D(?m:^)$` on `\n` | match, `(0,1)` | no match |
| `(?:[^]a](?m:^))`, caseless, on `\r\n` | match, `(1,2)` | no match |
| `\R(?m:^)$` on `x\n` | match, `(1,2)` | no match |
| `(?m)^`, crlf, subject `[0,0,13,10,…]`, start 3 | `find_at` = `(4,4)` | `(3,3)` |
| `\r^`, crlf+multiline, subject `\r\r\r`, start 2 | `is_match_at` = true, `find_at` = `(2,3)` | false / no match |

Both artifact inputs are retained and re-read by the probe. The repository's
`pcre2_differential` target fails on them at
`fuzz/fuzz_targets/pcre2_differential.rs:368`/`:377`
(`assertion left == right failed`), so the nightly fuzz campaign now reports
`libFuzzer: deadly signal` at this commit.

---

## 4. Negative observations

- **Extended HTTP/1-versus-HTTP/2 whole-request matrix.** The newest commit's
  `whole_request_fuzz` test was extended (in a disposable worktree, product
  source untouched) with ~350 additional logical requests: encoded dot
  segments and slashes, obs-text and non-ASCII paths, `//`/`/./`/`/..`
  spellings, cache and denied prefixes, duplicate `cookie`/`x-merge` fields,
  ranges, conditional headers, `authorization`, `x-forwarded-*`, `te`,
  `accept`/`accept-language`, and GET/HEAD/POST bodies. All protocols agreed;
  no H1/H2 projection divergence was found. The extension is not retained
  because it was harness-only.
- **Parser fuzzing.** `http_fields` ran 49 million inputs and
  `config_grammars` 2.6 million inputs for their full 1,500-second budgets
  with no artifacts and no crashes.
- **Whole-request fuzzing.** `whole_request_differential` ran its 2,400-second
  budget at HEAD with no artifact.
- **Retained battery replay at HEAD.** `adversarial/p33`, `p34`, `p35`
  (access-file and PCRE2 gates) and `p36` were re-run against the rebuilt
  release binary. All remediated verdicts still pass. The only failing row is
  the already-recorded P36-O1 stale P33 expectation (`/secret` now `404`
  instead of the retained `403`); no protected content is served.
- **Test-isolation observation.** Adding any second test to
  `whole_request_fuzz` makes the module fail under `cargo test`'s default
  parallelism: the tests share one `Config` whose process-global resource
  ledger is asserted to be empty between evaluations. Running with
  `--test-threads=1` passes. This is harness-only and does not affect the
  server.

## 5. Closure recommendation

1. Extend `validate_line_constructs` so admitted `\R`/`\v`/`\h` atoms cannot
   be followed by a generic class, an anchor, or another newline atom whose
   priority depends on CRLF atomicity, or implement an atomic CRLF lowering
   that the backend preserves.
2. Either reproduce PCRE2's multiline `^` semantics (including "no match
   after a final newline") or reject multiline anchors whose subject can end
   with a newline; the offset APIs need the same decision.
3. Add the cases above to `crates/pcre2/tests/p23_regressions.rs` /
   `fuzz_regressions.rs` and re-run `pcre2_differential` for 2,400 seconds
   without artifacts. `adversarial/p37/probe` reduces directly into those
   tests.

## 6. Evidence

- `adversarial/p37/results_p37.txt` — config acceptance, retained artifact
  bytes and the standing probe output.
- `adversarial/p37/probe/src/main.rs` — runnable differential over the exact
  cases and controls.
- `adversarial/p37/crash-pcre2-crlf-multiline.bin` — 37-byte
  `pcre2_differential` artifact (`(?m)^`, crlf, offset 3).
- `adversarial/p37/crash-pcre2-crlf-multiline-at-offset.bin` — 7-byte
  artifact (`\r^`, crlf+multiline, offset 2).
- `fuzz/artifacts/pcre2_differential/` — original artifact directory.
- `crates/pcre2/src/lib.rs` — lowering at `1797-1800`, `^` passthrough at
  `1737-1741`, gate at `2143-2264`.
