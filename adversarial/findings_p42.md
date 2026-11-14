# Pass 42 — capture-state cache pools escape the verified regex budget

- **Date:** 2026-11-14
- **Subject:** HEAD `c73ec3b652b01696f8bb87a9abebaf0d1f49e5ea`
  (`target/release/httpd-rs` rebuilt from the clean reviewed tree).
- **Harnesses:** `adversarial/p42/exploit_p42.py` (release daemon, loopback
  only) and `adversarial/p42/regex_pool_probe/` (the public in-tree wrapper);
  retained output in `adversarial/p42/results_p42.txt`.
- **Method:** used the new resource-effect inventory as a map of dependency
  assumptions, then audited bounded-input calls whose dependency workspace
  varies along more than one data-shape axis. Source analysis of
  `regex-automata`'s PikeVM slot table and non-contracting cache pool was
  followed by wrapper-level scaling and a release-server access-file test.
- **Disposition:** **P42-A confirmed and unfixed at HEAD.**

---

## 1. Executive summary

| # | Finding | Intended bounds | httpd-rs at HEAD | Class |
|---|---|---|---|---|
| **P42-A** | The PCRE2 wrapper prices a search cache as `2 * automata_limit + 256 KiB` and capture metadata as a small linear addend. The dependency actually allocates two PikeVM active-state tables whose size is `NFA states * capture slots`, and its high-level API retains a non-contracting pool of those caches. | 32 MiB dependency workspace per request, 64 MiB per source, 256 MiB process-wide; wrapper claim 4.25 MiB per match. | A legal 509-byte `Require expr` with 120 captures plus a 32-byte header retains about 98 MiB per cache. One warm request plus four more denied requests left 496,564 KiB above baseline. Eight sequential connections reached the same ~500 MiB plateau. Under a bounded process the next request failed a 49,824,896-byte allocation and the release daemon aborted (`SIGABRT`). | high denial of service; multiplicative dependency-workspace undercount and retained-pool amplification |

---

## 2. P42-A — capture slots multiply states, then the pool multiplies caches

### 2.1 The verified claim omits the dependency's dominant term

The wrapper describes `dependency_workspace_bound()` as a conservative
retained/per-search ceiling, but it adds independent terms:

```rust
// crates/pcre2/src/lib.rs:409-428
size_limit * 2
    + HYBRID_CACHE_CAPACITY
    + pattern_limit * DEPENDENCY_PATTERN_EXPANSION_FACTOR
    + capture_limit * DEPENDENCY_CAPTURE_OVERHEAD
    + DEPENDENCY_FIXED_OVERHEAD
```

At match time the verified dependency boundary is even narrower: two 2 MiB
automata plus a 256 KiB hybrid cache, or 4.25 MiB
(`crates/pcre2/src/lib.rs:535-548`). This is a declared number supplied to a
pure admission predicate, not a measurement or allocation lease.

For a regex with captures, the wrapper takes the full-capture path and asks
the high-level engine for every slot (`lib.rs:613-624,734-741`). The pinned
dependency's PikeVM cache contains two active-state sets. Each set's slot
table is explicitly sized as:

```rust
// regex-automata 0.4.18, nfa/thompson/pikevm.rs:2087-2119
slots_per_state = nfa.group_info().slot_len();
len = nfa.states().len() * slots_per_state + scratch_slots;
table.resize(len, None);
```

Each capture contributes two slots and every slot is an eight-byte optional
offset on this target. The dominant workspace is therefore a **product** of
automaton states and captures, duplicated for the current and next active
sets. A fixed 128-byte addend per configured capture cannot bound it.

The retained wrapper probe holds the pattern's state count near its admitted
limit while varying only captures. One additional cache grows from 1,272 KiB
at zero captures to 26,672 KiB at 32 and 97,820 KiB at 120. The last value is
about 22.5 times the 4.25 MiB match-time claim. All patterns and 32-byte
subjects pass the structural, capture, subject and deterministic-work gates.

### 2.2 The high-level API retains more than one underpriced cache

`build_automata` configures the lazy-DFA cache capacity, but it does not bound
the high-level `meta::Regex` cache-pool cardinality
(`crates/pcre2/src/lib.rs:432-449`). The dependency documents the behavior
directly:

```text
Currently, a pool never contracts in size. Its size is proportional to the
maximum number of simultaneous uses.
```

The wrapper's comment says request matching cannot unexpectedly allocate a
per-pattern cache (`lib.rs:468-471`), but the convenient `search` and
`search_slots` calls obtain mutable caches from exactly that pool. A peak of
several search users becomes persistent process memory owned by the compiled
expression. The bound accounts for one undersized cache and no pool
cardinality at all.

This is also outside the access-file dependency lease. Access-file parsing
temporarily reserves 32 MiB and shrinks it to the bytes reported by the
compile-budget hook (`crates/server/src/htaccess.rs:1117-1129`), but
`ExprRegex::compile` constructs the PCRE2 wrapper directly
(`crates/server/src/expr.rs:42-67`). Its later request-time cache allocations
neither acquire nor remain represented by that lease.

### 2.3 Live reproduction

The release harness enables the repository's explicit access-file capability
and uses only `AllowOverride AuthConfig`. The complete attack rule is one
509-byte line:

```apache
Require expr "%{HTTP:X-P42} =~ /(x?)(x?)...(120 groups)...1(?:[[:^alpha:]]{0,3}){4208}a/"
```

This is a normal supported expression, not malformed syntax or a construct
outside the whitelist. The request sends a 32-byte `X-P42` value of `1`s. It
does not match, so every completed request returns 403; authorization remains
fail-closed while availability fails.

With no process ceiling, one warm request and four further connections give:

```text
pattern_bytes=509 captures=120 subject_bytes=32
single_statuses=[403]
concurrent_status_counts={403: 4, other: 0}
baseline_rss_kib=7100
after_one_rss_kib=111952
after_concurrent_rss_kib=503664
retained_growth_kib=391712
server_exit=None
```

The total retained increase is 496,564 KiB. It exceeds the intended 32 MiB
per-request, 64 MiB per-source and 256 MiB process dependency-workspace
ceilings. Eight sequential connections from one client reached essentially
the same plateau (503,896 KiB after the first wave), so an attacker does not
need to keep sockets slow or sustain a large simultaneous connection set.

The capture-free control uses the same `{4208}` state-heavy expression and
the same requests. Four requests retain only 5,444 KiB after warm-up. With 32
captures, the retained increment is already 107,056 KiB. This pins the
unaccounted `states * capture slots` term instead of merely observing that a
large regex consumes memory.

Finally, the harness can put the child under `RLIMIT_AS` to make allocation
failure deterministic. The daemon needs large virtual-address headroom for
its worker stacks, so the limit is not presented as an RSS measurement; the
`/proc` values above are the resource measurements. After one 403 had retained
its cache, the next ordinary request produced:

```text
client_errors=['RemoteDisconnected: Remote end closed connection without response']
server_exit=-6
server_output=memory allocation of 49824896 bytes failed
```

The workspace escape therefore becomes a whole-process abort under a bounded
deployment rather than a 503 or a fail-closed regex error.

### 2.4 Reachability, impact and severity

- **Primary family:** `denial_of_service`.
- **Impact tier:** high. An unauthenticated request supplies only a 32-byte
  header, yet a legal access-file expression makes a handful of requests
  retain roughly 500 MiB and allocation failure aborts the release process.
  The same expression is reachable from main configuration. High rather than
  critical reflects the precondition: an operator or an application-managed
  access file must contain the state-heavy, capture-heavy pattern. The
  repository nevertheless treats enabled access files and their regexes as
  request-path input requiring hard resource bounds; the pattern passes every
  one of those bounds.
- **Unintended behavior count:** 2. The per-cache formula omits the
  state-by-capture product, and the wrapper ignores the retained cache-pool
  multiplicity.
- **Remediation component count:** 2. Give every actual search cache a sound
  bound/lease, and place a hard cardinality/contraction policy on retained
  per-regex caches (or replace the hidden pool with explicitly owned caches).

### 2.5 Remediation boundary

1. Stop using a guessed fixed cache term. Either expose/derive the exact
   PikeVM cache footprint from the compiled NFA and capture-slot count, or use
   a metered/fallible allocation boundary whose measured high-water mark is
   charged before the search becomes request-reachable.
2. Avoid the dependency's hidden non-contracting high-level pool. The safest
   design is an explicit bounded set of `Cache` objects owned by httpd-rs,
   with each live/retained cache represented by a process and source-aware
   dependency-workspace lease. A mutex-serialized fallback is acceptable
   only if its wait occupancy is itself bounded and cancellation-aware.
3. Count expression regexes in the access-file retained dependency lease;
   `ExprRegex::compile` must not bypass the compile-budget accounting used by
   directive regexes.
4. Add a matrix over NFA states, capture slots and concurrent searches. Assert
   both the measured allocator high-water mark and ledger occupancy, then
   assert all request leases release while any intentionally retained cache
   remains charged to its owning configuration generation.

---

## 3. Negative observations

- The vendored HTTP/2 continuation path has explicit header-block byte,
  continuation-count and frame-work limits; the initial continuation-flood
  hypothesis did not yield a new defect.
- The resource inventory's remaining dependency/kernel assumptions were
  reviewed as hypotheses, not treated as proof of safety. No second
  reproducible high-impact candidate was retained in this pass.
- This is distinct from P24's regex CPU/work-bound finding and P41's Brotli
  workspace escape. P42's subject is only 32 bytes, deterministic match work
  passes its gate, and the missing term is the dependency's capture-state
  cache memory plus persistent pool cardinality.

These observations are not proof that those surfaces are bug-free.
