# Post-P28 denial-of-service resource-budget review

- **Date:** 2026-11-02
- **Scope:** request-time configuration matching and expansion, access-file
  breadth, generated response heads, and the Apache CVE-2011-4415 analogue.
- **Method:** call-graph review from attacker-controlled request bytes through
  every policy matcher/expander, followed by deterministic boundary tests. No
  open-ended fuzzing was used.

## Findings

Four resource gaps remained after the P26-P28 fixes:

1. `SetEnvIf` capture replacement called `Captures::expand` before any output
   bound. A short replacement containing many `$1` references could amplify an
   admitted request header, recreating the memory-consumption half of
   CVE-2011-4415 even though Rust removed its NULL-dereference half.
2. The new iterative shell matcher removed exponential backtracking and stack
   exhaustion, but its `O(pattern * subject)` rectangle was not charged outside
   expression globs. `<Files>`, `<Location>`, `<Directory>`, `<Proxy>` and
   `IndexIgnore` could therefore multiply large configured patterns by request
   paths or every autoindex entry.
3. Policy work was bounded inside individual regex/glob evaluators but not
   across the complete request. Many individually cheap directory, rewrite,
   expression, environment and authorization operations could evade those
   local ceilings. Access files also had depth and byte caps but no explicit
   per-file/per-request instruction or layer ceiling.
4. Generated response header vectors had parser-specific limits for CGI,
   FastCGI and proxy responses, but native/configuration-generated headers had
   no final count/serialized-byte admission or process resident-byte charge.

## Remediation

Every request now owns an `Arc<RequestPolicyBudget>` shared by request clones,
request-plan construction, internal rewrites and the HTTP/2 adapter. It is
monotonic and fail-sticky: exceeding a limit poisons the request so a later
authorization phase cannot turn an incomplete evaluation into a grant.

| Resource | Limit | Admission point |
|---|---:|---|
| aggregate policy work | 16 Mi work units | before glob DP, regex evaluation, directory/rule matching, rewrite conditions, expression values and authorization nodes |
| aggregate policy expansion | 4 MiB | before `SetEnvIf`, dynamic `Require` and expression-owned allocations |
| one policy value | 1 MiB | before materializing the value |
| access-file instructions | 8,192/file; 16,384/request | sealed access IR and ancestor-layer collection |
| access-file layers | 64/request | before merging another parsed layer |
| generated response headers | 256 fields; 128 KiB serialized | policy merge/application and final HTTP/1/HTTP/2 serialization |

`SetEnvIf` computes and charges a conservative capture-expansion upper bound
before `Captures::expand` can reserve memory. Runtime shell matching charges
the exact `(pattern_len + 1) * (subject_len + 1)` DP rectangle through the
shared request budget before allocating either row. Autoindex uses the same
budget across all entries, rather than resetting it per match.

The `.htaccess` applicability prefilter, ancestor policy walk and uncached
directory-scope compiler also consume that request meter. They run while the
immutable request plan is being constructed, so leaving them outside the
budget would still permit configured wildcard/rule breadth to amplify an
attacker-selected path before normal policy evaluation began.

Response byte-body admission is now performed at the protocol boundary and
includes the serialized head estimate. HTTP/1 and HTTP/2 therefore use the
same aggregate response-resident budget, while zero-window HTTP/2 responses
retain only the bounded header reservation before DATA capacity exists.

The parallel boundary suite also exposed Linux `openat2(RESOLVE_BENEATH)`'s
documented transient `EAGAIN` result during concurrent rename activity. The
single secure-open wrapper now retries `EAGAIN`/`EINTR` at most eight times;
persistent path races still fail closed instead of becoming an unbounded retry
loop.

The arithmetic gates for glob rectangles, response heads and aggregate
access-file programs are executable Verus specifications with preservation
proofs. Runtime tests pin rejection at each boundary and verify that rejected
operations do not partially mutate policy or write response bytes.

## Residual availability boundary

These changes bound attacker-controlled work that is amplified by Vapache's
configuration engine. They do not claim that one admitted request has zero
cost: TLS handshakes, bounded compression, filesystem latency and upstream
service latency remain volumetric resources. Those paths retain their existing
process concurrency, byte and timeout limits; none exposed another unbounded
allocation or non-terminating loop in this review.
