# httpd-rs PCRE2 compatibility engine

This crate replaces httpd-rs's production dependency on the PCRE2 C library.
Its `bytes` module deliberately follows the Rust `pcre2::bytes` API used by
httpd-rs (`RegexBuilder`, `Regex`, `Match`, `Captures`, reusable capture
locations, and match/capture iterators).

The frontend follows the PCRE2 10.46 pattern documentation and source:

- <https://www.pcre.org/current/doc/html/pcre2pattern.html>
- <https://github.com/PCRE2Project/pcre2/tree/pcre2-10.46>

Admission is a positive grammar, not a blacklist. A deterministic,
stack-bounded parser must consume the complete pattern as literals, byte
classes, a fixed set of escapes, ordinary/named/noncapturing groups, the
`imsUx` option grammar, alternation, anchors and bounded regular quantifiers.
It returns an unforgeable admitted-pattern witness; only that type can enter
translation. Unknown special-group and alphanumeric-escape namespaces are
therefore rejected even if a future backend assigns them a meaning. All
httpd-rs directive and expression regex surfaces enter through this frontend;
none parse configuration patterns with Rust `regex` directly.

The parser's security-relevant option state is an executable Verus state
machine. Scoped groups save and restore the exact parent `x`/`m` state, while
atomic `\R` and multiline `^` have no admitted transition. A complete,
balanced parse produces a verified certificate bound to the exact source
length; translation rejects a missing, malformed or source-mismatched
certificate before lowering the pattern.

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
Consequently Rust-regex-only inline options are rejected by construction: `u`
has no PCRE2 inline spelling, and Rust's `R` flag conflicts with PCRE2's
`(?R)` recursion syntax. The option production covers only global, scoped,
combined and disabled forms composed from `imsUx`.
PCRE2's literal `\<`/`\>` escapes are lowered before the Rust backend can
reinterpret them as word-boundary assertions, and Rust-only extended boundary
forms such as `\b{start}` are rejected.
UTF/UCP class and escape forms whose semantics would be narrowed by the
byte-class lowering (including Unicode-sensitive POSIX classes, raw
non-ASCII classes, `\C`, `\h` and `\v`) likewise fail closed.
Malformed UTF and UCP subjects fail closed in full. PCRE2's strict validation
window varies with offsets, anchors and word boundaries, while
`MATCH_INVALID_UTF` treats invalid sequences as barriers between valid
fragments. Rejecting the complete malformed subject is deliberately stronger
than those context-dependent behaviors and avoids a false-positive match.
UCP `\b`/`\B` also fail closed because the upstream byte iterator can advance
into a UTF-8 scalar after an empty match and expose a fragment-barrier boundary
that a scalar-aware automata iterator cannot reproduce. Under ANYCRLF, generic
classes that can start on the LF half of CRLF and lone-CR extended-comment
terminators are rejected; explicit `\n`, positive byte classes, LF comments,
and CRLF comments remain admitted.

PCRE2's atomic `\R` line-sequence escape is excluded in every mode: preserving
the indivisibility of CRLF changes match and capture priority according to the
following atom, which the automata backend cannot express uniformly. A `^`
anchor is likewise excluded whenever multiline mode is effective because
PCRE2 and the backend disagree at a final newline and at CRLF start offsets.
Quoted `\R`, literal carets, ordinary non-multiline `^`, and scopes that
explicitly disable multiline mode remain in the admitted grammar.

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
`httpd-rs-verified`: `regex_compile_resource_admit`,
`regex_capture_resource_admit`, `regex_match_resource_admit`, and
`regex_match_work_is_bounded`. The counted-repetition, optional-path/PikeVM and
multipass dominance lemmas close P23-A's and P24-B's undercharges.
`regex_engine_mode_admit` proves that the shipping mode excludes both
backtracking and executable-memory JIT.

## Conformance and fuzzing

`cargo test -p httpd-rs-pcre2` checks a committed PCRE2-derived corpus and an
exhaustive finite grammar against the actual PCRE2 10.46 C library. The latter
enumerates 244 pattern forms against all 781 subjects of length at most four
over its alphabet (roughly 190,000 capture-vector comparisons).

The upstream public-domain `pcre2test` data can be imported directly:

```sh
PCRE2_TESTDATA=/path/to/pcre2-10.46/testdata \
  cargo test -p httpd-rs-pcre2 --test upstream_testdata -- --nocapture
```

The current importer checks 1,005 supported subject/capture records from
`testinput1`; records using the deliberately unsupported dialect or complex
`pcre2test` control commands are skipped. Nightly CI downloads that corpus from
the checksummed 10.46 tag and requires the importer to complete. Cargo forces
the oracle C binding to build its bundled 10.46 source rather than selecting
a runner-dependent system library through `pkg-config`.

The unbounded complement is covered by `cargo fuzz run pcre2_differential` and
`cargo fuzz run pcre2_grammar` in the repository's `fuzz` package and by the
default smoke and nightly campaigns. The full differential feeds the same
pattern, seven builder flags, raw byte subject, and several start offsets to
this crate and the C oracle. It compares compile metadata, single-shot
matches/captures, reusable capture locations, iterators, and cold versus hot
engine tiers. The admission-focused grammar target independently generates
valid whitelist productions, deliberately excluded PCRE2 and Rust-regex forms,
and lexical controls where syntax-looking text is quoted, escaped, commented,
or inside a class. Every admitted raw pattern must compile in PCRE2, while
generated admitted patterns also compare capture metadata and results. Valid
UTF behavior is differential; malformed UTF/UCP subjects exercise the
documented whole-subject fail-closed boundary. `pcre2_resource` independently
keeps production limits active and checks compile/match limit monotonicity. The
nightly coverage corpora are minimized and carried forward between runs. The C
crate is a dev/fuzz dependency only and is absent from httpd-rs's normal Cargo
graph and release binary.

The reproducible C interpreter/JIT comparison and latest measurements are in
[`docs/pcre2-benchmark.md`](../../docs/pcre2-benchmark.md).
