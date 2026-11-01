# Agent handoff — remaining hardening items

This document hands the **remaining** review findings to an implementing
agent. The Verus proof generalization and the containment/encoding refactors
from the same review have already landed in this tree (see "Already done"
below); every item below is a well-specified, mostly mechanical runtime fix
that does **not** require writing Verus proofs. Items are ordered by
priority. Work them in order (H1 and H2 first); each item lists the exact
anchors in the *current* tree, the required change, and its acceptance
criteria.

## Environment and commands

Toolchain is pinned by `rust-toolchain.toml`. Verus is not on `PATH` by
default; it lives in `/root/verus-bin`:

```sh
cd /root/vapache
PATH="/root/.cargo/bin:/root/verus-bin:$PATH" cargo verus verify -p vapache-verified   # must end: 0 errors
cargo build --release                                  # python suites run target/release/vapached
cargo test -p vapached
python3 tests/verification_status.py --run-verus       # proof-debt gate: must print "gate: pass"
python3 tests/conformance.py                           # 165 cases vs local Apache
python3 tests/config_semantics.py                      # 235 fixed cases vs local Apache
python3 tests/config_validity.py
python3 tests/config_grammar.py
python3 tests/adversarial_regressions.py              # replays the F23–F60 exploit shapes
```

Apache 2.4.69 is installed at `/usr/sbin/apache2` and is used as the local
differential oracle by the python suites.

## Conventions and guardrails

* **Fail closed.** An unknown directive, flag, variable or malformed value is
  a configuration error, never a silent skip. The `.htaccess` parser already
  follows this; keep it that way.
* **Do not add proof escapes.** `tests/verification_status.py` greps the whole
  verified crate for `assume`/`external_body`; never introduce them.
* **`crates/verified/src/lib.rs` is proof-only surface.** This handoff should
  not need to touch it at all. If a fix genuinely needs a new verified
  kernel, stop and leave it for a Verus-capable pass (see H9).
* **Ledger discipline.** `docs/verification-status.json` is the CI source of
  truth:
  - When you finish an item, move its obligation from `"open"` to
    `"partial"` (or `"mechanized"` if a verified kernel proves it) and
    rewrite the `evidence` string to describe the implementation. The gate
    recomputes the weighted score; it must stay ≥ `minimum_weighted_score`
    (3.5) — moving open→partial only raises it.
  - `verus.verified_functions` (currently 293) only changes when public
  functions are added/removed in `crates/verified`; count with
  `grep -cE '^\s*(pub |)(open |)(spec |)(proof |)fn ' crates/verified/src/lib.rs`
  relative to the current tree (that metric is 312 locally; the ledger
  number 293 is that metric minus the pre-existing 19 private helpers,
  plus this session's additions — keep the same counting intent).
  - Never lower a `sinks.*` count, never add entries to
  `proof_debt.assumptions` (currently 5/6; do not spend the remaining slot
  without documenting a genuinely new external boundary).
  - Add one row per closed finding to `docs/adversarial-closure.md` and the
  matching regression to `tests/adversarial_regressions.py`.
* **Do not run `cargo fmt` on the whole repo** — the tree is not globally
  rustfmt-clean and unrelated reformatting pollutes review. Format only the
  files you edit.
* Line anchors below are exact for the current tree; re-grep before editing
  if your earlier items shifted lines.

## Already done in this tree (do not redo)

* `bits_meet` generalized bit-meet with no-broadening / commutativity /
  associativity / idempotence / narrowing lemmas; `options_conjoin_spec` and
  `override_categories_conjoin` re-pointed to it (`crates/verified/src/lib.rs`).
* `path_under_base_reflexive` / `path_under_base_transitive` composition
  lemmas; `expr.rs::confined_expr_path` now consumes the verified
  `path_under_base` kernel instead of a local `starts_with`.
* Generalized verified percent encoding: `percent_encode_from` spec,
  `percent_encode` exec refinement, identity and `no_masked_raw` lemmas.
  `rewrite.rs` backreference `[B]`-family escaping, redirect-`Location`
  escaping (non-ASCII bytes are now percent-encoded instead of emitting
  Latin-1 mojibake) and the `int:escape` map all call the one loop.
* `rewrite.rs::file_test` closures now receive `(lexical, canonical)` and
  `-f`/`-d`/`-s` probe the canonicalized target (`-l` stays lexical).
* New ledger obligations `percent_encode_family`, `containment_composition`
  (partial) and open obligations for every item below.

---

## H1 (P0) — Expression parser must be total: error, never panic

**Anchor:** `crates/server/src/expr.rs:751-752`

```rust
fn regex(&mut self) -> Result<(String, bool), String> {
    let delim = self.input.as_bytes()[self.pos];   // unguarded index
```

`compare()` advances past `=~`/`!~`, skips whitespace, then calls `regex()`.
An expression that *ends at the operator* (`<If "x =~">`, `Require expr
"'a' !~"`, `RewriteCond expr ... =~`) indexes at `input.len()` and panics.
Reachable from main-config `<If>`/`<ElseIf>` (`config.rs`, `if_expr`
evaluation site), `Require expr` (`config.rs`), `RewriteCond expr`
(`config.rs:5731` area) and — per-request — from an attacker-writable
`.htaccess` (`htaccess.rs:795/813`), which is inside this project's threat
model (F60-D built upload→RCE on `.htaccess`).

**Required change**

1. Bounds-check the delimiter:
   ```rust
   let Some(delim) = self.input.as_bytes().get(self.pos).copied() else {
       return Err("expected a regex after =~".into());
   };
   ```
2. Add a parse-depth cap. `primary()` ↔ `unary()` recurse once per `!`, `-`
   or `(`; `Expr::eval` recurses over tree depth. Add a `depth: usize`
   counter (or field on `Parser`), incremented in `primary()`/`unary()`,
   erroring above e.g. 256; keep `Expr::eval` depth-safe by relying on the
   parse cap (no cap needed at eval if parse is capped).
3. Do not change any accepted-expression semantics; existing tests
   (`crates/server/src/expr.rs` tests, incl. the `=~ /(a)\1/`
   unsupported-dialect case) must stay green.

**Acceptance:** unit tests: `parse` of `"x =~"`, `"'a' !~"`, deep `"!!!!…"`
(> cap) all return `Err` (no panic, no abort); `cargo test -p vapached`
green; `python3 tests/config_validity.py` and `config_grammar.py` still 0
divergence. Then move ledger obligation `expr_parser_totality` to partial.

## H2 (P0) — Rewrite flag/round state machine (F67 + F68 + dead flag)

These are the two still-live findings from `adversarial/findings_p10.md` (its own
remediation list); the F60 half already landed.

### H2a. `[PT]` is parsed but never read (F67)

**Anchors:** `crates/server/src/config.rs:639` (field), `:5626` (parse),
`crates/server/src/rewrite.rs:521-552` (override construction), `:548`.

`rewrite::process()` builds a filesystem override for **any** absolute
substitution; the dispatcher then re-roots at `filesystem.parent()` and
executes the host file. Apache maps a `[PT]` substitution back through URL
space (the F67 repro: Apache 404, vapache RCE).

**Required change:** in the block at `rewrite.rs:521` that computes
`filesystem` (`if !external && Path::new(&joined).is_absolute()`), do not
create the override when `rule.flags.passthrough` is set — the substitution
then flows as an ordinary internal URL and is re-mapped next round
(`RequestPlan::resolve`), which is Apache's pass-through semantics. Keep
`[PT]` accepted (it is Apache-valid). Update the module doc comment at the
top of `rewrite.rs` accordingly.

### H2b. Filesystem override is sticky across rules and rounds (F68)

**Anchors:** `crates/server/src/rewrite.rs:318` (`filesystem_override`
per `process()`), `:548` (`if filesystem.is_some() { … }` — set-only),
`crates/server/src/server.rs:1839` (`rewrite_filesystem`), `:2092`
(set-only).

An earlier rule's file target survives a later `[L]` URL rewrite inside one
`process()` call, and an earlier round's target survives later dispatcher
rounds. Only the final target may be applied.

**Required change:** make each round's assignment unconditional:

* `rewrite.rs`: at the point a rule produces a substitution (after the
  `rule.substitution == "-"` early-continue), assign
  `filesystem_override = filesystem;` (which also clears it when this rule
  selected no file), instead of the `if filesystem.is_some()` guard at
  `:548`. Rules that match nothing (`continue`) must not clear it.
* `server.rs:2092`: `rewrite_filesystem = filesystem;` unconditionally (the
  `Outcome::Internal` filesystem field is per-round `Option`).

### H2c. `[UnsafePrefixStat]` is dead and silent

**Anchor:** `crates/server/src/config.rs:5640`.

It is parsed and read nowhere (deliberate after the F32 remediation — the
flag can no longer re-root). Emit a load-time compatibility **warning**
(the `self.warn` path used by other accepted-inert directives), not an error
(Apache-valid configs must not 500): `"[UnsafePrefixStat] is accepted for
compatibility and has no effect"`.

**Acceptance:** add `tests/adversarial_regressions.py` replays following
the existing F60-style test classes:
* F67 shape: `RewriteRule "^/app/(.*)$" "%{DOCUMENT_ROOT}/$1" [PT,L]` with a
  `<Location "/secret"> Require all denied` and a CGI/php handler — assert
  vapached does **not** execute the host file (expect 403/404, and the same
  as Apache for the same config).
* F68 shape: rule 1 absolute substitution without `[L]`, rule 2
  `"^" "/index.html" [L]` — assert the index document is served (Apache
  agrees).
* `[UnsafePrefixStat]` config logs the warning and still loads.
`cargo test -p vapached`, `conformance.py`, `config_semantics.py`,
`adversarial_regressions.py` all green; move ledger obligation
`rewrite_flag_state_machine` to partial with evidence. The matching Verus
kernels (a spec fn from `RewriteFlags` to a target-action lattice, plus the
10-round loop bound) are deliberately **not** part of this handoff — see H9.

## H3 (P1) — Signless `Options` words must reset the set (Apache semantics)

**Anchors:** `crates/server/src/config.rs:3241-3282` (the `_ =>
scope.options.push_add(o.0)` fall-through), `crates/server/src/htaccess.rs`
`apply_options` (same shape).

vapache treats `Options Indexes` as `+Indexes`. Apache **resets** the set to
exactly the listed options, so a child `<Directory uploads>` saying
`Options Indexes` drops inherited `ExecCGI` — Apache 403s a `.cgi` there
while vapache executes it. This also undercuts the F60 scope conjunction:
the target-side `Options` bits are computed from a scope that failed to drop
the parent bits.

**Required change:** in both parsers, collect the signless words of one
`Options` directive into a fresh mask; if any signless word is present,
`push_set(mask_of_all_signless_words)` once **before** applying the `+`/`-`
words (in argument order); if none, behavior is unchanged. Keep `None`/`All`
handling exactly as now. Unsupported tokens stay warn-only in main config
(strict-mode promotion is H8).

**Acceptance:** add a generated case to `tests/config_semantics.py`
(parent `Options +ExecCGI`, child signless `Options Indexes`, request a
`.cgi`) — must agree with Apache; the suite currently disagrees and will
prove the fix. `config_validity.py` + `conformance.py` green (some existing
cases may assert the old behavior — update expectations **only** after
confirming Apache's answer with the local oracle). Move ledger obligation
`apache_options_reset` to partial.

## H4 (P1) — `RewriteMap` loading is fail-open and unbounded

**Anchor:** `crates/server/src/config.rs:3641-3718`.

* `if args.len() < 2 { return; }` — silently drops a malformed directive.
* `txt`/`rnd`: `read_to_string(path).unwrap_or_default()` — an
  unreadable/missing map file silently becomes an **empty map**, so a
  `${blocklist:…}`-based deny condition evaluates empty and the deny rule
  is skipped. No size cap.
* `prg`: the program string is stored unvalidated (PATH-resolved, no
  existence/executable check); at runtime (`rewrite.rs::run_prg_map`) it
  spawns per lookup with no timeout and silently returns `""` on failure.
* `int`: unknown function names load fine and silently map every key to
  `""` at runtime (`rewrite.rs::int_map` default arm).

**Required change**

* `args.len() < 2` → `ConfigError` (malformed directive, all modes).
* `txt`/`rnd`: on read failure → `ConfigError` (fail closed, matching
  `TypesConfig` at `config.rs:3883-3896`); add an explicit size cap constant
  (e.g. `MAX_REWRITEMAP: u64 = 1024 * 1024`, consistent with
  `MAX_HTACCESS`) enforced after `metadata` before reading.
* `prg`: resolve a relative program against `ServerRoot` at load; require
  the target to exist and be executable (`std::os::unix::fs::MetadataExt`
  mode bits) else `ConfigError`. (Still main-config-only — `.htaccess`
  already rejects `RewriteMap`, keep that.)
* `int`: validate the function name at load against
  `{tolower, toupper, escape, unescape}` else `ConfigError`; leave the
  runtime default arm as a defensive `""`.
* Runtime `prg` timeout is a **stretch goal only** — do not attempt
  thread/timeout machinery in this pass; note it in the ledger evidence if
  skipped.

**Acceptance:** unit tests in `config.rs` tests module: short directive →
error; missing txt file → error; oversized map → error; unknown int
function → error; relative `prg` resolved against ServerRoot. Move ledger
obligation `rewritemap_load_validation` to partial.

## H5 (P2) — `[CO=…]` cookie fields parse under a strict grammar

**Anchor:** `crates/server/src/rewrite.rs::build_cookie` (currently
`:166-225`).

`{name}={value}` is concatenated verbatim; `Domain`/`Path`/`SameSite` text
is copied through; unknown `secure`/`httponly` tokens are silently
tolerated; only control bytes are rejected. A capture containing `:` shifts
every field; one containing `;` injects attributes.

**Required change:** keep the colon-split field layout (Apache semantics)
but validate content: name must be an RFC 6265 token (no `;`, `,`, `=`,
spaces, controls); value must be cookie-octets (allow the current
lenient visible set, reject `;`, `,`, `"` and controls); `secure`/`httponly`
slots accept exactly `secure|true|1` / `httponly|true|1`
(case-insensitive) else `Err`; `SameSite` accepts exactly
`lax|strict|none` case-insensitively else `Err`.

**Acceptance:** extend the existing `build_cookie` unit tests in
`rewrite.rs::tests` (`cookie_escape_and_effect_helpers`): name with `;` →
`Err`; `SameSite=Strict` ok; `SameSite=foo` → `Err`; `secure=yes` → `Err`.
Move ledger obligation `htaccess_cookie_grammar` to partial.

## H6 (P2) — Raw query bytes reach authorization without lossy conflation

**Anchors:** `crates/server/src/access.rs:97`
(`ResourceKey { cache_query: Some(String::from_utf8_lossy(&req.query)) }`),
`crates/server/src/expr.rs` `QUERY_STRING` variable,
`crates/server/src/rewrite.rs:944` (`QUERY_STRING`).

`valid_target` permits obs-text, so `req.query` can be non-UTF-8;
`from_utf8_lossy` conflates distinct raw byte strings (`\xFF` vs `\xFE`
both → U+FFFD). The cache fixed exactly this class with hex-encoded raw
bytes and by rejecting non-UTF-8 index names (`cache.rs:390`).

**Required change (minimum):** at each of the three sites, preserve the
distinction: prefer operating on bytes — for `RewriteCond`/`<If>`
matching, match the regex against raw `&[u8]` (the `regex` crate supports
`&[u8]` patterns); for the access `ResourceKey` field, keep raw bytes (or
hex-encode as the cache key already does) — inspect the type ripple and
choose the smallest correct change. If a site genuinely requires `String`,
fail closed (`Err`) on invalid UTF-8 rather than substituting the
replacement character.

**Acceptance:** unit test: two requests differing only in an invalid-UTF-8
query byte must not compare equal in a `RewriteCond "%{QUERY_STRING} …`
rule or a `<If "%{QUERY_STRING} …"` scope, and must produce distinct cache
identity. `conformance.py` green. Move ledger obligation
`query_byte_identity` to partial. **This item is subtle — flag the diff for
human review.**

## H7 (P2) — `.htaccess <IfFile>` tests the wrong argument

**Anchor:** `crates/server/src/htaccess.rs:798`
(`let path = args.get(1).cloned().unwrap_or_default();`).

`SectionStart.args` excludes the tag token, so the operator-supplied path
is `args[0]`; `args.get(1)` reads the *second* word. A natural
`<IfFile maintenance.flag>` yields `""`, which `confined_expr_path`
resolves to the document root — always true — and silently forces the
section's rules on. Main config reads `args.first()`
(`config.rs:2677` area).

**Required change:** `args.first().cloned().unwrap_or_default()`.
Also decide and test `<IfFile a b>` (two words) behavior: with `first()`
it tests `a`; keep that and document it.

**Acceptance:** unit tests in `htaccess.rs` tests for both arities
(single-arg tests the named file; two-arg tests the first word).
Move ledger obligation `iffile_htaccess_argument` to partial (or fold into
`directive_effect_completeness` evidence).

## H8 (P2) — Strict mode must reject every silent drop

**Anchors (main config, `crates/server/src/config.rs`):**
`:3642` (RewriteMap — covered by H4), `:3763` AddType, `:3778` AddHandler,
`:3846` Header, `:3875` ExpiresByType, `:3976` ProxyPass,
`:4769 parse_status_list` (`filter_map(…ok())` drops unparsable
`failonstatus` entries), `:3261` (unsupported `Options` tokens — warn-only
even in strict mode), `:3758` (`RewriteOptions` unknown tokens silently
become `Some(false)`); `.htaccess` already hard-errors where noted.

**Required change:** follow the existing strict-mode pattern
(`directive_disposition`'s `FailClosedStrict` at `config.rs:4728-4763`):
each under-argument/unparsable drop becomes `self.errors.push(ConfigError …)`
when strict mode is enabled (and stays a warning otherwise, except where the
directive is malformed in any mode — H4 items). Unsupported `Options`
tokens and `RewriteOptions` unknown tokens: strict error, compat warn.

**Acceptance:** `python3 tests/config_validity.py` strict cases (add one
per promoted site); `cargo test`; move ledger obligation
`strict_config_silence` to partial.

## H9 (P2) — Verification follow-ups (NOT for this handoff; Verus-capable pass)

Recorded so the ledger tells the truth about what is still owed. Do not
attempt these without Verus experience:

* `rewrite_flag_state_machine` mechanization (after H2): a spec fn from
  `RewriteFlags` to a `{Url, Filesystem, Proxy, Redirect, Forbidden, Gone}`
  action lattice with a lemma that `process()` implements it (`[PT]` never
  yields `Filesystem`), plus the 10-round dispatcher bound and "only the
  final round's target is applied".
* `int:unescape` roundtrip lemma against the verified `percent_encode`.
* `expr_parser_totality` mechanization (after H1): parser totality as a
  spec (every input yields `Ok` or `Err`, never abort).
* Scope ghost-model meet (continuation of `bits_meet`): `content_policy`
  (ForceType/MIME) and `environment_policy` (`SetEnvIf` feeding
  `Require env`/`expr`) are currently *replaced*, not met, on target
  re-binding; a verified `Scope`-meet would expose both mechanically.

## Definition of done (per item)

1. Code changed only at the listed anchors (+ tests).
2. All commands in "Environment and commands" green; no new warnings in
   edited files.
3. Ledger obligation moved open→partial with rewritten evidence;
   `docs/adversarial-closure.md` row + regression test added for H2/H3.
4. `git diff --stat` shows only intended files.
