---
doc_type: landing
audience: contributor, security-reviewer
status: draft
---

# Contributor architecture

These pages are for human contributors, coding agents, and security reviewers.
They explain the design that the source code is intended to implement. They use
implementation terminology and assume that the reader wants to understand the
server internals.

Apache administrators do not need these pages to evaluate a migration. Start
with [Decide whether to replace Apache with
Vapache](../how-to/evaluate-security-driven-migration.md) instead.

The administrator explanation [Security properties and
limits](security-expectations.md) is written for deployment decisions and does
not require the contributor material below.

## Start here

[The shape of Vapache](the-shape-of-vapache.md) gives the high-level map. Read
it before changing request processing, access checks, configuration loading,
reload behavior, or a backend handoff.

## Design explanations

| Page | What it explains |
|---|---|
| [The shape of Vapache](the-shape-of-vapache.md) | How configuration becomes runtime policy and where the server repeats access checks |
| [Compatibility is a security policy](compatibility-is-a-security-policy.md) | Why accepting Apache syntax is not enough to preserve Apache behavior safely |
| [How Vapache builds a security argument](building-a-security-argument.md) | How proofs, tests, application deployments, and stated assumptions support a claim |
| [Configuration generations make time explicit](configuration-generations.md) | How a reload keeps requests on one complete configuration |
| [Delegation is an authority handoff](delegation-is-an-authority-handoff.md) | What Vapache gives to CGI, FastCGI, and proxied backends |

## Evidence and contributor procedures

- [Executable documentation contracts](../reference/documentation-contracts.md)
- [Add a new Apache CVE to the project
  review](../how-to/evaluate-apache-cve.md)
