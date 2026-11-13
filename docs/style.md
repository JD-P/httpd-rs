---
doc_type: project
audience: documentation-contributor
status: normative
---

# Documentation style

Use this guide for httpd-rs documentation. Operator-facing procedures and
reference pages use a controlled technical-English style that is similar to
ASD-STE100. The project does not claim formal ASD-STE100 conformance.

Contributor-facing explanation uses ordinary technical prose. Architectural
intuition, alternatives, and tradeoffs lose important information when every
sentence is forced into a procedural vocabulary.

## Select a prose mode

Use the controlled mode for tutorials, how-to guides, reference pages, and
operator-facing security explanation. Controlled mode is the default.

Use `prose_style: discursive` in the metadata of a contributor-facing
explanation page. Discursive prose can use analogy, varied sentence structure,
historical context, and a sustained argument. It must still name exact code or
evidence when it makes a concrete implementation claim. Do not use the
discursive mode to make an operator procedure less precise.

The documentation test permits the discursive mode only when `doc_type` is
`explanation` and the audience includes `contributor`.

## Select one documentation type

Each user-facing page must have one primary type.

| Type | Purpose | Required form |
|---|---|---|
| Tutorial | Help a learner complete a specific example | One named system, a defined start state, numbered steps, verification, and cleanup or rollback |
| How-to | Help an experienced user complete one task | Prerequisites, direct steps, verification, and failure recovery |
| Reference | State exact facts | Stable headings, complete values, defaults, contexts, limits, and errors |
| Explanation | Explain reasons and relationships | Defined scope, explicit assumptions, design reasons, consequences, and links to procedures |

Do not put a general survey in a tutorial. Do not put a long design argument in
a reference entry. Link to a page of the correct type.

## Use controlled language for operator documentation

- Use one approved term for one concept.
- Use the active voice when the actor is important.
- Put one principal action in each numbered step.
- Put a prerequisite before the action that requires it.
- Put a warning before the hazardous action.
- State the expected result after an important command.
- Use `must` for a requirement.
- Use `can` for a capability.
- Use `may` only for permission.
- Use `might` for possibility.
- Do not use `may` to mean possibility.
- Do not use `easy`, `obvious`, `obviously`, `just`, or `simply`.
- Do not use a pronoun when its referent can be unclear.
- Do not use different words only to add variety.
- Preserve the spelling and capitalization of command, directive, protocol, and
  product names.

Keep most sentences below 25 words. A sentence can be longer when a command or
an exact technical name makes the limit impractical.

These vocabulary and sentence-length rules do not apply to contributor
explanations in discursive mode. The rules about factual accuracy, evidence,
stable terminology, and explicit assumptions still apply.

## Use approved terms

| Term | Meaning | Do not use as a synonym |
|---|---|---|
| Apache | Apache HTTP Server 2.4 | httpd, Apache2, upstream server |
| httpd-rs | The project or installed product | httpd-rs server |
| `httpd-rs` | The server executable | httpd-rs binary when the executable is meant |
| service identity | The operating-system user and group that run request processing | worker user, web user |
| administrative input | Configuration, key, certificate, map, or other operator-controlled input | trusted file without a definition |
| backend | A CGI, FastCGI, HTTP, or WebSocket service that receives a dispatched request | upstream, origin, application server unless protocol context requires it |
| capability | A named, default-off httpd-rs compatibility gate | feature flag |
| configuration generation | One immutable configuration used by a set of accepted requests | config version |
| fail closed | Reject configuration or a request when httpd-rs cannot apply the required policy | ignore safely |

Use *Apache directive* for a configuration command that Apache defines. Use
*httpd-rs directive* for a command whose name starts with `httpd-rs`.

## Write procedures

Use an imperative verb at the start of each numbered step. Put commands after
the action statement. State the important expected output after the command.

Use this order:

1. State the goal and concrete example.
2. State the start condition.
3. List prerequisites.
4. State hazards and irreversible effects.
5. Give the actions.
6. Verify the result through the public interface.
7. Give cleanup or rollback actions.

Never use a successful process start as the only verification for a network
service. Test the documented user workflow.

## Write security claims

Classify each concrete security claim with one of these evidence types:

- machine-checked property;
- httpd-rs runtime test;
- Apache differential test;
- real-application deployment test;
- fail-closed exclusion;
- external dependency assumption;
- deployment responsibility;
- not covered.

State the property before the evidence. Do not use *verified* without naming
what was verified and how it was verified.

## Make behavior executable

Each concrete behavior claim, command, configuration example, default, and
compatibility claim must meet one of these conditions:

- A documentation contract tests the claim through a public httpd-rs interface.
- Authoritative implementation metadata generates the value.
- The page links to an existing executable test and names the exact case.
- The page identifies the statement as an assumption, rationale, or non-goal.

Use a stable contract ID in the form `DOC-AREA-NNN`. See
[Executable documentation contracts](reference/documentation-contracts.md).
