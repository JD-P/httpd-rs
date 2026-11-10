# vapache PCRE2 compatibility engine

This crate replaces vapache's production dependency on the PCRE2 C library.
Its `bytes` module deliberately follows the Rust `pcre2::bytes` API used by
vapache (`RegexBuilder`, `Regex`, `Match`, `Captures`, reusable capture
locations, and match/capture iterators).

The frontend follows the PCRE2 10.46 pattern documentation and source:

- <https://www.pcre.org/current/doc/html/pcre2pattern.html>
- <https://github.com/PCRE2Project/pcre2/tree/pcre2-10.46>

The executable backend uses `regex-automata` directly: a bounded Pike VM keeps
cold starts small, and a shared lazy DFA is compiled after the first search
for steady-state speed. Bounded backtracking is explicitly disabled in both
tiers. The engine uses no recursive matcher, native code, executable memory,
or unsafe Rust.
PCRE-only regular constructs are lowered before compilation, including
`\Q...\E`, `\Z`, `\K`, comment groups, control/octal escapes, byte classes,
and PCRE extended-mode class rules. Numbered and named captures are projected
back to the PCRE-visible numbering after internal `\K` markers are removed.

Backreferences, recursion/subroutines, look-around, conditionals, atomic or
branch-reset groups, possessive quantifiers, backtracking verbs, and capture
histories whose preference differs between engines are rejected at compile
time. There is a `RegexBuilder::backtracking` compatibility knob so callers
cannot accidentally assume that enabling it worked; requesting it returns a
compile error because no fallback engine ships in production.
UTF/UCP class and escape forms whose semantics would be narrowed by the
byte-class lowering (including Unicode-sensitive POSIX classes, raw
non-ASCII classes, `\C`, `\R`, `\h` and `\v`) likewise fail closed.
Malformed UTF and UCP subjects fail closed in full. PCRE2's strict validation
window varies with offsets, anchors and word boundaries, while
`MATCH_INVALID_UTF` treats invalid sequences as barriers between valid
fragments. Rejecting the complete malformed subject is deliberately stronger
than those context-dependent behaviors and avoids a false-positive match.

Resource policy is part of the API, not a timeout:

- patterns and translated expansion are byte-capped;
- compiled automata and parser nesting are capped;
- subjects and capture slots are capped;
- every match must satisfy an overflow-free `automaton_complexity × subject`
  work ceiling before execution; finite repetition expansion and additional
  compatibility passes are included in that structural charge. Variable
  repetitions also charge their exit path and a conservative PikeVM
  active-set factor, including when a hot lazy-DFA search falls back.

The corresponding admission predicates and product-bound proof are in
`vapache-verified`: `regex_compile_resource_admit`,
`regex_capture_resource_admit`, `regex_match_resource_admit`, and
`regex_match_work_is_bounded`. The counted-repetition, optional-path/PikeVM and
multipass dominance lemmas close P23-A's and P24-B's undercharges.
`regex_engine_mode_admit` proves that the shipping mode excludes both
backtracking and executable-memory JIT.

## Conformance and fuzzing

`cargo test -p vapache-pcre2` checks a committed PCRE2-derived corpus and an
exhaustive finite grammar against the actual PCRE2 10.46 C library. The latter
enumerates 244 pattern forms against all 781 subjects of length at most four
over its alphabet (roughly 190,000 capture-vector comparisons).

The upstream public-domain `pcre2test` data can be imported directly:

```sh
PCRE2_TESTDATA=/path/to/pcre2-10.46/testdata \
  cargo test -p vapache-pcre2 --test upstream_testdata -- --nocapture
```

The current importer checks 1,005 supported subject/capture records from
`testinput1`; records using the deliberately unsupported dialect or complex
`pcre2test` control commands are skipped. Nightly CI downloads that corpus from
the checksummed 10.46 tag and requires the importer to complete. Cargo forces
the oracle C binding to build its bundled 10.46 source rather than selecting
a runner-dependent system library through `pkg-config`.

The unbounded complement is covered by `cargo fuzz run pcre2_differential` in
the repository's `fuzz` package and by the default smoke and nightly campaigns.
It feeds the same pattern, seven builder flags, raw byte subject, and several
start offsets to this crate and the C oracle. It compares compile metadata,
single-shot matches/captures, reusable capture locations, iterators, and cold
versus hot engine tiers. Raw syntax mutation is paired with a generated grammar
of the admitted subset, so an unexpected Rust rejection is itself a failure.
Valid UTF behavior is differential; malformed UTF/UCP subjects exercise the
documented whole-subject fail-closed boundary. `pcre2_resource` independently
keeps production limits active and checks compile/match limit monotonicity. The
nightly coverage corpus is minimized and carried forward between runs. The C
crate is a dev/fuzz dependency only and is absent from vapached's normal Cargo
graph and release binary.

The reproducible C interpreter/JIT comparison and latest measurements are in
[`docs/pcre2-benchmark.md`](../../docs/pcre2-benchmark.md).
