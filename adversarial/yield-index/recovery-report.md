# Adversarial yield recovery report

**Derived index under `adversarial/yield-index/`.**
Recovered from the historical OpenCode logs and retained adversarial files on
2026-11-08. This directory is a derived analytical index only: it does not
modify Vapache source, OpenCode logs, or any existing adversarial or findings
file, and it does not compute adversarial yield.

## Deliverables

| File | Contents |
|---|---|
| `searches.jsonl` | 29 engagement rows, 39 logical-search rows, 50 raw segment rows |
| `findings.jsonl` | 186 claim rows: 130 confirmed, 11 duplicate/retest, 1 invalid, 44 unresolved |
| `recovery-report.md` | This document |
| `validate_index.py` | Validation + reporting script (durations, cross-references, ordering, aggregates) |

Every row carries source references; where a fact could not be recovered it is
`null` with an explicit confidence value and an explanation.

## Sources examined

- `~/.local/share/opencode/opencode.db` — 66 sessions (53 top-level, 13 child
  subagent), 312 user messages, 18,303 assistant messages, timestamps, finish
  states, error/idle records, model metadata, and every tool call/output.
- `adversarial/findings.md` (Pass 3), `adversarial/findings_p4.md` …
  `adversarial/findings_p32.md` (Passes 4–32), and the retained `adversarial/p11/`
  … `p32/` exploit harnesses and evidence.
- `adversarial/README.md` — canonical pass/file/finding inventory.
- `docs/adversarial-closure.md` — per-finding implementation closures and
  invariants `I9`–`I71`.
- `docs/vulnerability_trends.md` — the earlier F1–P15 class-level inventory,
  effort/parts/prevalence/impact estimates and caveats; used only as a
  cross-reference for F1–F30 and impact-scale context.
- `/root/vapache` Git history — commit list, messages, dates, and the
  `git log`/`git status`/`git diff` outputs captured inside each session.
- Recovered initial `findings.md` content (F1–F5 write-ups) from the Pass-1
  session transcript (captured at `/tmp/p1_t3_write_0.md` by the recovery work).

## Method

### Logical searches and boundaries

A logical search is one continuous attempt to find vulnerabilities, ending only
when the agent returns a completed result (findings, or a no-finding
conclusion). The 31 top-level sessions that were human-directed vulnerability
searches produced **39 logical searches**; the remaining top-level sessions were
fix, hardening, benchmark, spec, or packaging sessions and are not searches.
Child/subagent sessions (for example the two `Audit …` sessions spawned under
Pass 10) are delegated work inside a search, not searches.

Segment terminals were classified from the session database:

- `completed` — final assistant message with `finish=stop` and a result, or a
  no-finding conclusion.
- `interrupted` — an `aborted`, `provider.free-limit`, or `provider.transport`
  error record; an `idle` outcome of `interrupted`/`failed`; a turn that ended
  with pending tool calls and no completing message; or a `repetition` stop.

Boundary rules applied:

- An interrupted attempt plus a later prompt that resumes the same unfinished
  work is **one** logical search (across sessions too: S14/Pass 9, S32/Pass 25,
  S39/Pass 32 each span two sessions; S16, S22, S25, S30, S33 are same-session
  resumptions).
- A completed result followed by `continue the engagement` (or an equivalent
  request for more searching) is a **new** logical search even when the same
  session, file, model or target commit is reused (S01→S02→S03, S04→S05→S06,
  S07→S08, S20→S21, S23→S24, S26→S27, S28→S29, S34→S35).
- File placement is never used as a boundary: `findings.md` holds Pass 1–3
  searches, and one findings file can span several logical searches.
- Fix/hardening work, spec discussions, write-up bookkeeping and vendor repair
  turns are not search segments. Where they sit between two segments of one
  search they are noted in that search's `boundary_decisions`.

Interrupted searches that were resumed are recorded as **completed with
multiple segments**; no search in this corpus was left interrupted, so there
are **0 censored searches**. Ten of the fifty segments were interrupted; their
error message ids and timestamps are embedded in the segment rows.

### Reviewed commit and worktree state

Each search records the commit checked out when it began, recovered from
in-session `git log`/`git rev-parse`/`git status` outputs and the commit
chronology. 37 of 39 searches have an **exact** commit; 2 are **bounded**:

- **S14 (Pass 9)** — the aborted first segment reviewed `1f530df` plus the
  uncommitted changes that became `469266f`; the resumed segment reviewed clean
  `469266f`. The row records `469266f` with `bounded` confidence and both
  bounds in `worktree_patch_reference`.
- **S32 (Pass 25)** — the aborted first attempt and the resumed run both
  reviewed `fbb26fd`; `bounded` because the first attempt was reconstructed
  from session timing rather than an in-session `git` command.

Worktree state is `clean` for 30 searches and `dirty` for 9. The dirty cases
are the early fix-in-progress trees (Passes 2–7, 9) where a preceding fix
session had left uncommitted hardening changes; each row names the observed
modified files and the commit that later captured them. Two special cases:

- **S15 (Pass 10)** started clean on `ebfd8a7`; a **concurrent** hardening
  session (`ses_e844db4b4`, started 23 minutes into the search) modified the
  shared worktree, visible in the search's own later `git status` output. The
  row records the start state as clean and documents the external diff.
- **S22 (Pass 16)** started clean on `8454631`; turns 4–5 re-vendored `h2`
  (staged), and the resumed segment ran with those staged changes. Committed
  as `53a972a` immediately after.

### Claims, dispositions and duplication

Every claim made by a search is preserved, including negative results. IDs are
canonicalized: `F…` and `Pnn-X` keep their historical identities; Pass-11
re-tests of Pass-10 findings are `F61-A`, `F62.retest`, `F64b`, `F66.retest`,
etc.; Pass-18-B sub-cases are `P18-B1`/`P18-B2`. A search's `finding_ids`
lists every returned claim; `confirmed_finding_ids` lists the confirmed subset.

- Confirmed: 130. F1–F30 come from the retained closure table plus recovered
  detail for F1–F5; F31–P32 from their write-ups.
- Duplicate/retest: 11 Pass-11 rows preserving the survivor set (`F64b` is the
  one new confirmed finding in that pass).
- Invalid: 1 (`F70`, a dead hypothesis Apache rejects).
- Unresolved: 44 observations and static leads (F32–F35; F56; Pass-4/5/7 review
  targets; the nine Pass-12 static-audit leads; Pass-15 secondary observations;
  P23-K–N; Pass-25/26 divergences).

### Families and tiers

Families use the fixed ontology only. Classification follows the
attacker-visible terminal outcome: demonstrated code execution → `code_execution`
(with a bypassed guard as secondary `authority_bypass`); demonstrated
protected-data access → `information_disclosure`; defeats of a guard without a
demonstrated stronger outcome → `authority_bypass`; cache/representation
integrity → `integrity_violation`; availability → `denial_of_service`; SSRF and
wrong-upstream → `server_request_abuse`; interpretation/translation confusion →
`protocol_confusion`. Five confirmed P23 library-semantics findings have no
demonstrated attacker outcome and are `unclassified` with explanations, as
permitted by the handoff.

Impact tiers keep the source label where the write-up states one (Critical →
`critical`, etc.) and quote the `vulnerability_trends.md` access score in the
reason where one exists. For F1–F30 the tier is derived from that score with
the mapping documented per row. No finding is `catastrophic`; the closest are
unauthenticated single-request whole-process aborts (P24-A, P27-A/B, P28-A/B/C,
P29-A/A′) and unauthenticated code execution (F59/F60, P12–P18), which are
`critical`. Ambiguous labels (`High/Medium` F55, `Low/Medium` F35) take the
demonstrated-outcome tier and quote the original label.

### Composition

For every confirmed finding, `unintended_behavior_count` counts distinct
incorrect behaviors that must compose; `remediation_component_count` counts
conceptual mechanisms needed to close the class. For F1–F30 the behavior count
cross-references the trends document's "Parts" (decision layers) estimate and is
marked medium/low confidence. Itemized behavior lists are provided where the
retained record supports them (F1–F5, F31, F36, F39, F50, F57, F59, F60, F64b,
P12-A, P15-A, P16-A, P17-A, P18-A/B, P23-A, P24-A, P27-A/B, P28-A, P29-A,
P30-A, P31-A, P32-A); otherwise the list is the reconstructed root-cause line
with an explicit note. Remediation components are derived from the fix/closure
text; where the source only describes the fix at class level, the component
list quotes it and says so. Defense-in-depth items are recorded separately
(F45, F35).

### Fix-commit mapping

Fix commits are recorded with a confidence value. High-confidence mappings
were recovered from commit chronology plus the fix sessions that produced
them; for several early or low-level findings the per-finding split inside a
commit series is not recoverable and is marked `low`/`medium` with the series
named. Known series include: `76f1a86`+`9a7809c` (Pass 1–4 fixes), `1f530df`
(Pass 5–7), `469266f` (Pass 8), `ebfd8a7` (Pass 9), `9e28a4f`+`d219efb` (Pass
10), `969235c` (Pass 11), `cce35eb`…`b8f68b5`…`b4b9192`…`818d983` (Pass
12–22), `b0613c1`+`fcef21f` (P23), `f195a60` (P24), `5545d7f` (P25),
`6ea02c9`+`b7767cd` (P29), `0ec8194` (P30), `ac58575`/`d2726f2`/`0aa65c3`
(P31), `6ed7070` (P32).

## Search summary

| # | pass | session(s) | reviewed commit | tree | segs | confirmed | claims |
|---|---|---|---|---|---:|---:|---:|
| S01 | Pass 1 | ses_e8f3929b4f… | 24e226d8… | clean | 1 | 5 | 5 |
| S02 | Pass 1 (continuation) | ses_e8f3929b4f… | 24e226d8… | clean | 1 | 16 | 16 |
| S03 | Pass 1 (continuation) | ses_e8f3929b4f… | 24e226d8… | clean | 1 | 1 | 1 |
| S04 | Pass 2 | ses_e8e68f0eaf… | 24e226d8… | dirty | 1 | 1 | 1 |
| S05 | Pass 2 (continuation) | ses_e8e68f0eaf… | 24e226d8… | dirty | 1 | 3 | 3 |
| S06 | Pass 2 (continuation) | ses_e8e68f0eaf… | 24e226d8… | dirty | 1 | 4 | 4 |
| S07 | Pass 3 | ses_e8c1482c9f… | 24e226d8… | dirty | 1 | 1 | 1 |
| S08 | Pass 3 (continuation) | ses_e8c1482c9f… | 24e226d8… | dirty | 1 | 2 | 6 |
| S09 | Pass 4 | ses_e8b1b33cbf… | 24e226d8… | dirty | 1 | 7 | 12 |
| S10 | Pass 5 | ses_e88765bfff… | 9a7809c0… | clean | 1 | 4 | 7 |
| S11 | Pass 6 | ses_e85d69b75f… | 9a7809c0… | dirty | 1 | 3 | 3 |
| S12 | Pass 7 | ses_e858b1e58f… | 9a7809c0… | dirty | 1 | 3 | 8 |
| S13 | Pass 8 | ses_e851191b4f… | 1f530df7… | clean | 1 | 2 | 2 |
| S14 | Pass 9 | ses_e84a0106af…; ses_e84a177edf… | 469266f2… | dirty→clean | 2 | 3 | 3 |
| S15 | Pass 10 | ses_e846361f3f… | ebfd8a7e… | clean | 1 | 15 | 15 |
| S16 | Pass 11 | ses_e83ebc751f… | d219efb8… | clean | 3 | 1 | 13 |
| S17 | Pass 12 | ses_e8060e686f… | 1f5b16ed… | clean | 1 | 6 | 15 |
| S18 | Pass 13 | ses_e7fd1556df… | cce35eb3… | clean | 1 | 3 | 3 |
| S19 | Pass 14 | ses_e7f11c2c5f… | ce8d800e… | clean | 1 | 5 | 5 |
| S20 | Pass 15 | ses_e7e323cbff… | a3d514f5… | clean | 1 | 1 | 3 |
| S21 | Pass 15 (continuation) | ses_e7e323cbff… | a3d514f5… | clean | 1 | 2 | 3 |
| S22 | Pass 16 | ses_e7dc70d47f… | 8454631d… | clean | 2 | 4 | 4 |
| S23 | Pass 17 | ses_e7d217f8df… | b8f68b53… | clean | 1 | 1 | 1 |
| S24 | Pass 18-A | ses_e7d217f8df… | b8f68b53… | clean | 1 | 1 | 1 |
| S25 | Pass 18-B | ses_e79d4c10ff… | 07c78792… | clean | 2 | 2 | 2 |
| S26 | Pass 19 | ses_e798084a5f… | 07c78792… | clean | 1 | 1 | 1 |
| S27 | Pass 20 | ses_e798084a5f… | 07c78792… | clean | 1 | 2 | 2 |
| S28 | Pass 21 | ses_e75c18f26f… | 53984937… | clean | 1 | 1 | 1 |
| S29 | Pass 22 | ses_e75c18f26f… | 53984937… | clean | 1 | 2 | 2 |
| S30 | Pass 23 | ses_e754afcb7f… | a54bcdd8… | clean | 3 | 10 | 14 |
| S31 | Pass 24 | ses_e74e813e9f… | 81984109… | clean | 1 | 2 | 2 |
| S32 | Pass 25 | ses_e73b90beaf…; ses_e73ba4879f… | fbb26fd5… | clean | 2 | 2 | 7 |
| S33 | Pass 26 | ses_e66c17b12f… | 5b5dbb70… | clean | 3 | 2 | 8 |
| S34 | Pass 27 | ses_e66496ba7f… | 5b5dbb70… | clean | 1 | 2 | 2 |
| S35 | Pass 28 | ses_e66496ba7f… | 5b5dbb70… | clean | 1 | 3 | 3 |
| S36 | Pass 29 | ses_e64e50cd2f… | de8853b6… | clean | 1 | 3 | 3 |
| S37 | Pass 30 | ses_e62d43e66f… | b7767cd4… | clean | 1 | 2 | 2 |
| S38 | Pass 31 | ses_e60f99356f… | 9c595e7a… | clean | 1 | 1 | 1 |
| S39 | Pass 32 | ses_e5fd5437bf… | e1251ecc… | clean | 2 | 1 | 1 |

## Boundary decisions needing manual review

All boundary decisions are recorded in each search row with references and a
confidence. The ones worth a human look:

| Search | Decision | Confidence | Why |
|---|---|---|---|
| S16 (Pass 11) | Turn 1 (interrupted with pending tool calls) + status exchange + write-up turn treated as one search | medium | The interruption produced no error record; the user's "what's going on?" is a status query between interrupted and resumed work rather than a new search. If a reviewer decides the write-up is a distinct deliverable, it becomes two units. |
| S22 (Pass 16) | Turn 1 + turn 6 (after vendor repair) treated as one search | high | Turn 1 was interrupted with no result; turns 2–5 are vendor/h2 repair, not search work; turn 6 explicitly resumes the engagement. |
| S25 (Pass 18-B) | `provider.free-limit` abort + "Any luck?" treated as one resumed search | high | Same session, same task. |
| S30 (Pass 23) | Three segments (abort, free-limit, 9-second write-up) as one search | high | The long middle segment did the work; the final turn completed the write-up. |
| S33 (Pass 26) | `free-limit`, `repetition`, then "Continue." as one search | medium | The repetition stop is not a completed result. A stricter reading could call the repetition segment a fresh attempt; the work overlapped. |
| S39 (Pass 32) | Identical prompt repeated ~2 h later as one resumed search | high | Verbatim retry of the same task after an interruption. |
| S32 (Pass 25) | Rewritten (not verbatim) static-host prompt after a 6-second abort as one search | medium | Same task and tail of the same interrupted attempt; a reviewer could treat the new session as a new search. |
| S15 (Pass 10) | Internal mid-turn abort auto-resumed by the framework stays one search | high | No new user prompt; the handoff's rule covers interruptions resumed in place. |
| S17 (Pass 12) | Turns 2–3 (harness placement) excluded from the search | high | Housekeeping, not searching. |

## Missing information and low-confidence areas

- **F1–F30 write-ups are lost.** `findings.md` was overwritten by Pass 3.
  F1–F5 were recovered from the Pass-1 transcript; F6–F30 survive only as the
  one-line classes in `docs/adversarial-closure.md` and the trends tables.
  Composition behavior lists and counts for those 30 claims are class-level
  (confidence low/medium), not replay-verified measurements.
- **F37 is a numbering gap** — it is mentioned once as a Pass-3
  defence-in-depth hypothesis, but has no section, no closure row and no
  reproducible behavior. It is excluded (no claim row), consistent with
  `docs/vulnerability_trends.md`.
- **F56** (Pass-7 cache/ErrorDocument follow-on) is retained as an unresolved
  observation, later formalized in the closure doc; no live reproduction
  survives.
- **Per-finding discovery/confirmation timestamps are not separately logged.**
  They are `null` with whole-segment bounds; do not read bounds as discovery
  times.
- **Dirty-tree patch identities**: early fix-in-progress trees are described by
  in-session diffstat and commit provenance, not by a stored patch. Exact
  reviewed content is bounded by the named commits.
- **Fix-commit splits** are approximate for: F1–F38 per-finding split inside
  `76f1a86`/`9a7809c`; P16-A–D within the 2026-10-28 `bc8b710`/`a3f04f9`/
  `b8f68b5` series; P26-A/B (recorded as closed in the closure doc but the
  commit mapping is unresolved); P27/P28 per-finding split inside
  `167eee4`/`76138dc`/`5f8fe61`/`f56f598`/`de8853b`; P31 within
  `ac58575`/`d2726f2`/`0aa65c3`; P32's coverage commit `a2f6381b`.
- **The P30-B write-progress deadline observation is excluded from S37's
  returned claims** (it is a later closure observation per the checkpoint and
  closure row; the pass file itself marks it "(observation)").
- **The nine Pass-12 static leads are unresolved** and excluded from the
  confirmed counts, matching the trends doc's own exclusion.
- **Model checkpoints**: early searches ran `deepseek/deepseek-v4.1-flash-1017`
  (checkpoint `1017`); later runs used `deepseek/deepseek-v4.1-flash` or the
  `-free` tier with no explicit checkpoint (`null`). Pass 11 ran
  `glm-5.3-flash-free`. Mixed-model searches (S16, S30, S33, S39 and S25's
  resumed session) list every model in `models_observed`; the search-level
  `attacking_model` is the first segment's model. Any per-model yield must be
  computed from segments, not search-level fields.

## Final report statistics

- Logs/sessions examined: **65 historical OpenCode sessions** (52 top-level +
  13 child/subagent) in the project database; **29 engagements** and
  **39 logical searches** reconstructed; remaining top-level sessions were
  non-search work.
- Logical searches: **39**. Completed: **39** (31 single-segment; **8 resumed**
  after an interruption). Censored (interrupted, never resumed): **0**.
  Unclear: **0**. Interrupted segments: **10** of 50.
- Findings: **130 confirmed**, **11 duplicate/retest**, **1 invalid**,
  **44 unresolved** — **186 claims total**.
- Reviewed commit: **100% exact-or-bounded** (37 exact, 2 bounded, 0 unknown).
  Worktree: 30 clean, 9 dirty, 0 unknown.
- Confirmed findings by primary family:
  `code_execution` 41 · `denial_of_service` 28 · `information_disclosure` 23 ·
  `authority_bypass` 19 · `integrity_violation` 10 · `unclassified` 5 ·
  `server_request_abuse` 3 · `protocol_confusion` 1 ·
  (`cryptographic_trust_failure`, `memory_safety`, `catastrophic` tier: 0).
- Derived search duration (sum of segment intervals, outage gaps excluded):
  **14 h 15 m** total, median 15 m 09 s, longest S38/Pass 31 at 1 h 37 m 42 s.
- Fields not reliably recovered: per-finding discovery/confirmation
  timestamps; F6–F30 behavior itemizations; several fix-commit splits (listed
  above); exact dirty-tree patches; P26 fix mapping; per-segment checkpoint
  identities for some `-free` runs.

## Questions that block later adversarial-yield computation

1. **Denominator and units**: should yield be per logical search, per pass, or
   per engagement? Passes 1–3 each contain multiple searches; Pass 11 contains
   one search whose only new confirmed finding is `F64b` while re-testing six
   survivors. The index supports any of these but the choice changes the curve.
2. **What counts in the numerator**: confirmed only, or confirmed plus
   unresolved observations? Duplicates/retests are preserved precisely so
   re-discovery can be measured; state whether they count as yield, as quality
   signal, or not at all. The 44 unresolved claims include both plausible
   leads and pure negative-review rows.
3. **Model attribution for resumed/mixed-model searches**: S16, S25, S30, S33,
   S39 changed models between segments. Yield-per-model needs a segment-level
   attribution rule.
4. **Composition weighting**: are `unintended_behavior_count` and
   `remediation_component_count` intended as severity weights, difficulty
   proxies, or descriptive fields? F1–F30 counts are class-level estimates and
   must not be mixed with replay-verified counts without a confidence filter.
5. **Impact normalization**: the index keeps historical labels in reasons but
   normalizes tiers; if yield weights by tier, the mapping policy recorded in
   the report must be accepted or replaced, not silently reinterpreted.
6. **Review-target scope**: the searches reviewed a moving mixture of
   committed commits and fix-in-progress worktrees (9 dirty states). Yield by
   "commit period" needs a rule for whether a dirty-tree search belongs to its
   base commit, its eventual fix commit, or both.
7. **Negative-search base rate**: no logical search returned zero claims; every
   search produced at least one observation. The historical pass structure
   (human-directed, RCE/DoS-focused in later passes) is a selection process,
   not a random sample. Any yield curve inherits that bias; the index cannot
   correct it.
8. **Adversarial intent drift**: prompts narrowed from "any exploit" (Passes
   1–14) to RCE (9–18) to DoS (19–32). Comparing raw yields across those
   scopes without a scope normalizer will mostly measure the prompt.

## Pass 33 extension (appended after the initial recovery)

This index was extended on 2026-11-09 with the Pass 33 logical search
`S40` (`eng-ses_e4253e249ffet2sc5faL9luct2`) and its claims, appended without
modifying any earlier row:

- **S40 / Pass 33** — reviewed clean HEAD `dc2d5e5cb9a00a650ebe8ca4e2506784659f6cbe`;
  multi-family yield review that confirmed
  **P33-A** (MultiViews negotiated representation bypasses the P25-A
  trailing-slash rejection and URL-scoped authorization; primary
  `information_disclosure`, secondary `authority_bypass`, high, two
  unintended behaviors) and preserved two negative observations
  (`P33-O1`, `P33-O2`).
- Updated aggregate counts after the append: 30 engagements, 40 logical
  searches (51 segments), 189 claims — 131 confirmed, 11 duplicate, 1 invalid,
  46 unresolved. Confirmed `information_disclosure` findings: 24.

The recovery report's earlier Passes 1–32 counts above remain a description of
the initial reconstruction. The yield CSV/report were **not** recomputed in
this extension; run `compute_yield.py` to regenerate them from the extended
JSONL index.

## Validation

Run:

```sh
cd adversarial/yield-index
python3 validate_index.py
```

The script derives durations from the raw segment timestamps, checks
identifiers and all cross-references (including that `finding_ids` and
`confirmed_finding_ids` agree with `findings.jsonl`), detects impossible
timestamp ordering, and prints the aggregate counts. It never modifies the
JSONL files. Current status: **VALIDATION OK (no errors)**.
