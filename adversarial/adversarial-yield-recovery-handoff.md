# Reconstruct the Vapache adversarial-review dataset

Read the OpenCode logs stored on this computer and reconstruct the factual
dataset needed to measure how Vapache's adversarial vulnerability yield changed
over the project's development.

Identify every distinct vulnerability search and every vulnerability claim
produced by those searches. Recover:

- when each search began and ended;
- which model performed it;
- the full Git commit ID and worktree state examined by each search;
- which findings each search produced;
- the demonstrated impact and vulnerability family of each finding;
- how many unintended behaviors composed into each confirmed vulnerability;
- how many conceptual parts of Vapache required remediation; and
- the original logs, messages, adversarial files, code changes, and tests that
  support each recovered fact.

Write this information as a separate derived index under `adversarial/`. The
index will later be used to calculate and graph adversarial yield by
vulnerability family and development period.

Do not calculate adversarial yield during this task. Do not modify Vapache
source code, the OpenCode logs, or any existing adversarial-pass or findings
file. The historical records are the source material. The new JSONL files are
only an index reconstructed from them.

Preserve uncertainty. When a fact cannot be recovered exactly, record what is
known, how it was inferred, the source references, and the confidence level.
Do not invent precision.

Record `operator: "JDP"` for every recovered search. Do not attempt to infer
the human operator from the logs. This field exists so future searches
performed by other operators can use their own identifier.

The attacking model and model checkpoint are separate fields. Recover them for
each search when they are available.

## Identify logical searches

A candidate search normally begins with a user prompt that directs an agent to
find vulnerabilities.

A logical search is one continuous attempt by an agent to find
vulnerabilities. It ends when the agent returns a completed result containing:

- one or more findings; or
- an explicit conclusion that the search found nothing.

A single logical search can return multiple findings. Do not create one search
per finding.

A logical search can contain more than one user prompt only when an earlier
segment was interrupted before the agent completed its work and a later prompt
resumed that unfinished work.

If the agent is interrupted before returning a completed result, and the next
turn resumes and completes the same work, treat all segments as one logical
search. An interruption includes a network failure, framework error, timeout,
truncated response, or abrupt stop in the middle of the agent's work. The
segments remain one search even if the user had to say `continue` to restart
the agent.

If the agent returns completed findings or a completed no-finding result, and
the user then says `continue the engagement`, treat the continuation as a new
logical search. It remains a new search even when:

- the user tells the agent to append the new findings to the same
  adversarial-pass file;
- both searches ultimately appear in one findings file; or
- the searches use the same model, context, target revision, or engagement.

Earlier in the project, multiple completed searches were often appended to the
same pass or findings file. Later, separate prompts were more often written to
separate files. Do not interpret that historical file-layout difference as a
difference in search boundaries.

Determine logical search boundaries from completed agent work, not from the
number or names of findings files. The same source pass file can contain:

- several logical searches;
- findings from several searches; and
- interrupted and resumed segments belonging to one search.

Preserve the original adversarial files exactly as they are. Do not split,
rename, rewrite, or normalize them. The recovered dataset is a separate
analytical index that maps logical searches and findings back to the unchanged
source files.

For every search-boundary decision, record:

- whether the preceding agent turn returned completed findings, a completed
  no-finding result, partial work, or an interruption;
- whether the next prompt resumed unfinished work or requested additional
  searching;
- the supporting message or event references; and
- confidence: `high`, `medium`, or `low`.

If the source material does not establish whether the prior work was complete,
mark the boundary `unclear` for manual review. Do not use file placement as a
proxy.

## Record search segments

For every search segment, record:

- engagement ID;
- logical search ID;
- segment number;
- exact prompt timestamp;
- exact response or interruption timestamp;
- termination status: `completed`, `interrupted`, or `unclear`;
- relationship to the next segment: `resume_same_search`, `new_search`,
  `none`, or `unclear`;
- model and provider exactly as recorded in the log;
- user prompt;
- source log;
- message and event identifiers; and
- short supporting quotations.

Do not store active duration as an asserted raw fact. Duration is derived from
segment start and end timestamps.

For a logical search containing resumed segments, total search duration is the
sum of the segment intervals. Do not count the outage or idle period between
segments. Provide a script or generated report that performs this calculation
from the raw timestamps.

## Record logical searches

For every logical search, record:

- engagement ID;
- logical search ID;
- `operator: "JDP"`;
- ordered segment IDs;
- model and model checkpoint, when available;
- the reviewed commit ID and worktree state;
- search scope or vulnerability families requested;
- whether the search completed;
- finding IDs returned by the search;
- whether the completed search returned no confirmed finding; and
- boundary source references and confidence.

A continuation after a completed result is a new logical search but can remain
under the same engagement ID. This records that the attacker carried forward
context and familiarity without falsely describing it as an independent
review.

Record interrupted searches that were never resumed, but mark them `censored`.
Do not treat them as completed searches that found nothing.

## Recover the reviewed commit and source state

For every logical search, record `reviewed_commit_id`: the complete Git commit
ID checked out when the vulnerability search began. Do not substitute the
later fix commit for the reviewed commit.

Record:

- `reviewed_commit_id`: the full 40-character Git SHA, when recoverable;
- `reviewed_commit_confidence`: `exact`, `bounded`, `inferred`, or `unknown`;
- `worktree_state`: `clean`, `dirty`, or `unknown`;
- `worktree_patch_reference`: a patch, tree identifier, or description of
  uncommitted changes when the reviewed worktree was dirty; and
- source references that explain how the commit ID and worktree state were
  recovered.

The reviewed source state is the commit plus any uncommitted changes present
when the search began. Use repository history, commands in the logs, session
timestamps, patches, test changes, and fix commits where appropriate.

If the exact commit cannot be recovered, set `reviewed_commit_id` to `null`.
Record the nearest known earlier and later commits or other available bounds.
Do not invent an exact SHA.

## Record every vulnerability claim

For every vulnerability claim made during a search, record:

- stable claim or finding ID;
- search ID;
- concise title;
- disposition: `confirmed`, `duplicate`, `invalid`, or `unresolved`;
- duplicate target, when applicable;
- timestamp at which the agent first identified the candidate;
- timestamp at which the candidate was confirmed or reproduced, when
  available;
- primary and secondary vulnerability families;
- attack surface;
- root-cause class;
- demonstrated impact;
- impact tier: `low`, `medium`, `high`, `critical`, or `catastrophic`;
- reason for that impact tier;
- reproducer, test, or exploit reference;
- exploit execution time, if the source material actually demonstrates one;
- fix commit or patch, when known;
- regression test, proof, or invariant added by the remediation;
- source references; and
- confidence.

Exploit execution time is separate from discovery time. An exploit that
requires 50 minutes to execute does not mean the reviewer required 50 minutes
to discover it.

Do not accept an agent's original claim as confirmed merely because it sounds
plausible. Use the surrounding discussion, reproducer, tests, code changes,
and later disposition.

Preserve invalid, duplicate, and unresolved claims. They are necessary for
measuring false-positive rates and review quality.

## Classify vulnerability families

Classify by the attacker-visible result, not the implementation surface or
root cause. Use the following fixed ontology:

| ID | Vulnerability family | Includes |
|---|---|---|
| `code_execution` | Server-side code execution | Command injection, unsafe CGI or FastCGI execution, executable upload, interpreter injection, and native-code execution |
| `authority_bypass` | Authentication, authorization, and isolation bypass | Missing authentication, ACL bypass, cross-tenant or cross-vhost access, session confusion, and privilege-boundary or privilege-drop failures |
| `information_disclosure` | Unauthorized disclosure | Protected-file reads, source disclosure, path-traversal reads, cross-user cache leaks, and credential or metadata exposure |
| `integrity_violation` | Content or state manipulation | Cache poisoning, arbitrary modification or deletion, response or header injection, XSS, CSRF, open redirect, and attacker-controlled content presented as trusted |
| `server_request_abuse` | Server-side request and routing abuse | SSRF, open-proxy behavior, unintended upstream selection, internal-service access, and outbound requests across a network boundary |
| `protocol_confusion` | Message-boundary and interpretation confusion | Request smuggling, HTTP desynchronization, CL/TE disagreement, HTTP/2-to-HTTP/1 translation errors, response splitting, and parser differentials without a stronger demonstrated result |
| `cryptographic_trust_failure` | Cryptographic identity or channel failure | Certificate-validation failure, weak or broken cryptography, predictable randomness, signature failure, replay, and TLS session or key-handling defects |
| `denial_of_service` | Availability loss | Crash, panic, deadlock, infinite loop, resource exhaustion, amplification, slow-client slot retention, and algorithmic-complexity attacks |
| `memory_safety` | Memory-safety violation without a stronger demonstrated result | Use-after-free, out-of-bounds access, double-free, uninitialized memory, type confusion, and other native-memory failures |

For every finding, record:

- `primary_family`: exactly one family representing the strongest demonstrated
  terminal outcome;
- `secondary_families`: zero or more other demonstrated security failures in
  the same chain;
- `attack_surface`: the part of Vapache involved, such as HTTP/2, rewrite,
  CGI, TLS, or cache; and
- `root_cause_class`: the underlying defect pattern.

Use only `primary_family` for non-overlapping totals and graphs. Secondary
families preserve the complete exploit chain and support explicitly
non-additive analysis.

Apply these examples:

- A rewrite authorization bypass that executes CGI has primary family
  `code_execution`, secondary family `authority_bypass`, and attack surfaces
  `rewrite` and `cgi`.
- A rewrite defect that only defeats a deny rule has primary family
  `authority_bypass`.
- A path traversal that returns a secret has primary family
  `information_disclosure`.
- A malformed HTTP request that creates desynchronization without a stronger
  demonstrated exploit has primary family `protocol_confusion`.
- Request smuggling that demonstrably bypasses authentication has primary
  family `authority_bypass` and secondary family `protocol_confusion`.
- A use-after-free that only demonstrably crashes has primary family
  `denial_of_service` and secondary family `memory_safety`.
- A native out-of-bounds write with no demonstrated result beyond memory
  corruption has primary family `memory_safety`.
- SSRF that reads an internal metadata endpoint has primary family
  `server_request_abuse` and secondary family `information_disclosure`.
- SSRF that reaches a demonstrated command-execution endpoint has primary
  family `code_execution` and secondary family `server_request_abuse`.

If a finding does not fit this ontology, set `primary_family` to
`unclassified` and explain why. Do not create another family without manual
approval.

## Measure vulnerability composition

For every confirmed finding, record two related measures:

- `unintended_behavior_count`: how many distinct incorrect or insufficiently
  constrained behaviors must compose for the vulnerability to exist; and
- `remediation_component_count`: how many conceptually distinct parts of the
  codebase must be changed or constrained to prevent that vulnerability class
  from recurring.

Also record:

- `unintended_behaviors`: each security-relevant behavior that differed from
  the intended design;
- the expected behavior and actual behavior for each item;
- `remediation_components`: the distinct conceptual parts of Vapache that had
  to be changed, constrained, or given a new invariant;
- `composition_explanation`: how the unintended behaviors combined; and
- `composition_confidence`: `high`, `medium`, or `low`.

Do not count a subsystem merely because exploit data passes through it. Count
it only when its behavior is itself incorrect, violates an intended invariant,
relies on an incompatible assumption, or must be remediated to close the
vulnerability.

Count conceptual mechanisms, not files, functions, crates, lines changed, or
patches. Multiple edits that implement one validation rule count as one
remediation component. Tests, logging, and documentation do not count as
remediation components unless changing them directly prevents the
vulnerability.

Distinguish root-cause remediation from optional defense-in-depth changes.
Record defense-in-depth changes separately.

Apply these examples:

- A parser accepts one malformed length and downstream code behaves correctly
  with the value it receives: one unintended behavior and one remediation
  component.
- Path normalization and access control independently use incompatible path
  identities, and both require changes: two unintended behaviors and two
  remediation components.
- A rewrite defect produces an executable path, while TLS transports the
  request correctly and CGI correctly executes the path it is given: TLS and
  CGI are not defective components. Count only the faulty rewrite behavior
  unless CGI also lacked an intended authorization boundary.
- A central boundary check prevents an exploit but leaves two inconsistent
  underlying behaviors unchanged: record the boundary check as one immediate
  remediation component, retain the two underlying unintended behaviors, and
  explain the residual inconsistency.
- A fix that changes five files can still remediate a one-component
  vulnerability.

These fields measure how many independently wrong things had to align and how
broadly Vapache had to change to prevent recurrence. They are not counts of
every subsystem on the request path.

## Produce the recovered index

Produce:

1. `searches.jsonl`, containing engagements, logical searches, and their raw
   segments.
2. `findings.jsonl`, containing every vulnerability claim and its disposition.
3. `recovery-report.md`, explaining the sources examined, ambiguous cases,
   missing information, and coverage.
4. A small validation and reporting script that:
   - derives search durations;
   - checks identifiers and cross-references;
   - detects impossible timestamp ordering;
   - detects findings that reference missing searches; and
   - produces aggregate counts without modifying the recovered JSONL.

Every JSONL row must contain source references sufficient for another person
or agent to locate the original event. Do not silently fill missing values.
Use `null`, an explicit confidence value, and a short explanation.

## Final report

Finish by reporting:

- number of logs and engagements examined;
- number of logical searches reconstructed;
- number of completed, resumed, censored, and unclear searches;
- number of confirmed, duplicate, invalid, and unresolved findings;
- percentage of searches with an exact or bounded reviewed commit;
- findings by primary vulnerability family;
- fields that could not be recovered reliably;
- search-boundary decisions requiring manual review; and
- questions that block later computation of adversarial yield.

Do not compute adversarial yield yet. This pass exists to create a durable,
derived index of the existing historical record. Different scoring formulas
can later be evaluated from that index without modifying or reinterpreting the
original logs and adversarial files.
