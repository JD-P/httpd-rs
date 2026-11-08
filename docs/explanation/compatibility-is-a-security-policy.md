---
doc_type: explanation
audience: contributor, coding-agent
status: draft
prose_style: discursive
---

# Compatibility is a security policy

“Apache-compatible” sounds like a feature claim, but for Vapache it is also a
security policy. Every compatibility decision determines which operator
intentions survive the move from Apache and which pieces of Apache's attack
surface enter the new process.

The project therefore cannot maximize compatibility by counting accepted
directives. A server that accepts a configuration while discarding its
security effect is less compatible in the dimension that matters most.

## Syntax, semantics, and availability are different questions

For any Apache feature, three questions must be answered separately:

1. Can Vapache recognize the syntax?
2. Can Vapache preserve the relevant Apache semantics?
3. Should that behavior be available in this deployment?

The first question belongs to the grammar and directive registry. The second
belongs to compilation, merge order, request evaluation, and differential
testing. The third belongs to the capability and deployment model.

Conflating these questions creates two recurring errors. One is to reject a
safe, well-understood semantic merely because its original Apache module does
not exist. The other is to accept a familiar spelling even though Vapache
cannot reproduce its policy effect. The directive registry exists partly to
force an explicit disposition instead of letting parser control flow make that
decision by accident.

## An accepted no-op is not neutral

Some directives are observational or advisory, and an accepted inert form can
be reasonable when Vapache emits a clear warning. Policy directives are
different. If an Apache configuration says that a request must use TLS, that a
client certificate must satisfy a condition, or that a handler must pass
through a filter, silently accepting the words without the effect changes the
meaning of the deployment.

This is the reason unknown directives and unimplemented policy are rejected.
It is also why an unsupported directive inside `.htaccess` becomes a request
failure: access files are discovered at request time, but their late discovery
does not make their policy optional.

The distinction is recorded for operators in [Apache compatibility and
intentional differences](../reference/apache-compatibility.md). Contributors
should treat that reference as an output of the implementation decision, not
as a substitute for making the decision explicitly.

## Capabilities are authority, not feature toggles

Some behaviors are implemented accurately but increase the ambient attack
surface: CGI execution, access-file discovery, autoindex generation, legacy
authorization, or program-backed rewrite maps. Vapache places selected
surfaces behind process-global capabilities that are off by default.

The important idea is that a capability grants authority to reach a class of
sinks. It is not a preference bit. That is why a `.htaccess` file cannot enable
one, why the compiler records effectful uses independent of directive order,
and why the final execution sink checks the gate again. A local configuration
fragment should not be able to enlarge the process's global authority merely
because it was discovered later.

This gives compatibility a two-part test: the semantics must be implemented,
and the deployment must explicitly admit the resulting authority.

## Apache remains the semantic oracle, not the architecture template

Where Vapache claims compatible behavior, differential tests compare it with
a named Apache version and module set. Apache answers questions about ordering,
context, default values, rewrite behavior, and other externally visible
semantics that are easy to misremember.

That does not mean Vapache should reproduce Apache's internal architecture.
Apache's pools, module hooks, mutable request structures, and extension model
are not the compatibility target. Reusing those shapes would import assumptions
that Vapache is specifically trying to remove. The target is the documented
and observed behavior at the public boundary, subject to intentional
differences that are made visible to the operator.

The practical consequence is a kind of architectural freedom with a strict
accounting requirement. Internals can be radically different, but every
difference in observable behavior needs a classification, evidence, and a
migration consequence.

## Compatibility modes must not become policy amnesties

Compatibility code tends to accumulate exceptions. Each exception can look
small: coerce an odd value, tolerate an unknown token, preserve a historical
default, or accept an ignored flag. Over time, these exceptions can create a
second, less-audited policy language.

Vapache's preferred pattern is narrower. Leniency may preserve an Apache
coercion when the resulting semantic is known and tested. It must not turn an
unknown security effect into a successful parse. Audit mode may report missing
capabilities, but the resulting configuration is marked non-runnable. An
unsafe opt-in may expose a compatibility boundary, but it must be named as an
accepted risk rather than smuggled in as a fallback.

## A useful test for new directives

When adding or reviewing a directive, do not begin with “Can the parser accept
this?” Begin with these questions:

- What state does the directive change?
- In which Apache contexts is that change meaningful?
- How does it merge with inherited, virtual-host, directory, file, location,
  conditional, and access-file state?
- Can failure or absence weaken a policy?
- Does the behavior add filesystem discovery, parsing, execution, generated
  content, or mutable administrative data?
- Which public-interface test demonstrates the claimed semantics?
- What must the migration documentation tell an Apache operator?

The answer can be “unsupported.” That answer is not a compatibility failure if
it is explicit, fail closed, and documented. The more dangerous failure is to
claim compatibility without carrying the policy across the boundary.
