---
doc_type: explanation
audience: contributor, coding-agent
status: draft
prose_style: discursive
---

# How Vapache builds a security argument

Vapache uses safe Rust, formal verification, differential testing, adversarial
regressions, real-application deployments, and CVE analysis. None of those is
the security argument by itself. The argument is the connection between a
specific property, the mechanism intended to enforce it, the evidence that the
mechanism works, and the assumptions outside the evidence.

This matters for contributors because security language is unusually easy to
inflate. A proof can be described as though it covered the daemon. A passing
integration test can be described as though it excluded all variants. A Rust
type can be described as though it established an authorization property. The
project's evidence structure is meant to make those category errors visible.

## Start with a property, not a technique

“Use Verus here” and “add a regression test” are implementation actions. They
do not yet say what must be true.

A useful property has a subject and a boundary. For example: a transformed
filesystem target cannot be executed outside the authorized root; an old
configuration generation cannot admit new work after retirement; a resource
counter cannot be released before the object it accounts for is gone. Once the
property is precise, contributors can decide which parts are suitable for a
proof and which parts require system evidence.

The [verification ledger](../verification-status.json) records these
obligations, their current strength, and their remaining assumptions. Its
purpose is not to produce a large proof count. It is to prevent the project
from forgetting where a persuasive-sounding claim crosses an unproved
refinement boundary.

## Proof kernels establish narrow, reusable facts

Verus is strongest where the inputs and state transitions can be stated
without pretending to model Linux, Rustls, a filesystem, or an application.
Vapache therefore concentrates proofs around parsers, bounded arithmetic,
policy combinators, admission rules, and monotonic state machines.

The runtime must still consume the proved decision correctly. That connection
is a refinement obligation, and it often remains partly tested rather than
fully mechanized. Contributors should resist both extremes: treating a proved
helper as irrelevant because the whole server is not proved, or treating the
helper's theorem as though every caller and external effect were included.

Proofs provide unusually strong answers to questions such as “can this state
transition reopen authority?” or “does this accepted arithmetic step stay
within the bound?” They provide no automatic answer to “did the kernel report
the file identity we thought it did?”

## Tests cover different kinds of uncertainty

The test suites are deliberately heterogeneous because they answer different
questions.

Unit and property tests explore local implementation behavior and algebraic
relationships. Apache differential tests check claimed compatibility semantics
against a concrete oracle. Adversarial regressions preserve exploit shapes and
known failure modes. Fault and chaos tests ask whether partial I/O, process
death, resource pressure, or failed preparation turns into a policy violation.
Real-application deployments test the seams between Vapache and software whose
behavior is too rich to model faithfully in a small fixture.

These layers are not interchangeable. A WordPress deployment can show that an
upload workflow survives an immutable release layout; it cannot prove that all
writable-path substitutions are safe. A verified path predicate can establish
a containment relation; it cannot show that a particular application remains
usable. Differential agreement with Apache can establish compatibility while
also demonstrating that both servers share an unsafe semantic.

## CVE matrices are structured comparison, not replay results

The CVE matrices ask whether the root cause described by an advisory exists in
Vapache, fails closed, is absent, or remains outside the formal model. This is
valuable because it turns a vague “independent implementation” claim into a
row-by-row comparison of causes.

It is not equivalent to replaying every proof of concept, and a `prevented`
classification does not exclude an independent Vapache defect in the same
subsystem. The [CVE methodology](../cve/README.md) says this explicitly.
Contributors updating a row must preserve the distinction between preventing
the advisory's stated cause and proving that the complete feature is safe.

## Assumptions belong inside the claim

Every security argument eventually reaches something the project does not
prove: kernel path resolution, process credentials, Rustls parsing, scheduler
behavior, filesystem ownership enforcement, administrator integrity, or
application semantics. Calling these assumptions “trusted” does not make them
small; it makes their location explicit.

The strongest Vapache claims therefore state their scope. “The verified
parser rejects conflicting framing” is stronger than “request smuggling is
impossible,” because the former identifies the property and leaves room to
review proxy translation, HTTP/2 adaptation, and backend interpretation as
separate boundaries.

## Ledgers keep evidence from drifting away from code

Several repository files are intentionally bureaucratic. The verification
ledger, resource inventory, unsafe inventory, adversarial closure record, and
documentation contracts require a contributor to update the explanation of a
boundary when the implementation changes.

This friction is useful. Security work often fails through local optimization:
a new cache, queue, state flag, unsafe block, or compatibility exception solves
the immediate task but bypasses the place where the system accounts for that
kind of authority. An executable inventory turns “remember to think about
this” into a reviewable failure.

The [resource ownership inventory](../resource-inventory.md) and
[adversarial closure record](../adversarial-closure.md) are examples of this
pattern. They are not polished user documentation. They are continuity devices
for a codebase that will be changed by many short-lived contexts, including AI
agents.

## How to extend the argument

For a security-relevant change, write down this chain:

1. the operator-visible property;
2. the invariant or authority boundary that should establish it;
3. the code that consumes the invariant;
4. the proof, unit, differential, adversarial, fault, or deployment evidence;
5. the external assumptions and unresolved refinement work;
6. the documentation consequence if the behavior differs from Apache or
   changes a deployment responsibility.

If a link in that chain is missing, describe it as missing. An honest partial
argument is more useful than a complete-sounding label. It tells the next
contributor where reasoning must continue.
