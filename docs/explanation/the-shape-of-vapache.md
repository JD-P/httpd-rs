---
doc_type: explanation
audience: contributor, coding-agent
status: draft
prose_style: discursive
---

# The shape of Vapache

Vapache can look like a long list of independent hardening decisions: strict
HTTP parsing, immutable configuration, capability gates, descriptor-contained
filesystem access, typed dispatch, resource accounting, and explicit backend
identity. That is a useful inventory, but it hides the more important fact that
these decisions are related. Most of them follow from a small number of design
intuitions.

This essay describes those intuitions. It is not a claim that every part of the
implementation realizes them perfectly. The verification ledger and tests say
where the architecture is mechanized, where it is tested, and where it remains
an aspiration.

## An Apache configuration is a program

The first intuition is that compatibility is not a parsing problem. An Apache
configuration is a program whose meaning depends on context, ordering,
inheritance, filesystem discovery, request state, and the modules that happen
to exist. Recognizing a directive name is therefore much less important than
preserving the effect that the operator intended.

That observation explains why Vapache compiles configuration into an immutable
typed representation before it serves requests. Parsing produces structure;
sealing establishes that sections are matched and effectful payloads are
well-formed; compilation turns those values into a policy generation. A
failure in any of those phases rejects the candidate rather than leaving a
partly interpreted configuration behind.

The detailed semantics live in the [configuration semantics implementation
record](../config-semantics.md). The architectural point is broader: configuration
is executable policy, so its compiler deserves the same suspicion as the HTTP
parser.

## The narrow waist is a chain of typed decisions

Vapache tries to turn a large compatibility surface into a small number of
security-relevant transitions:

```text
configuration text
        ↓
sealed configuration generation
        ↓
canonical request and effective policy
        ↓
authorized target and transformation authority
        ↓
typed static, CGI, FastCGI, proxy, or WebSocket handler
        ↓
resource-accounted execution sink
```

The point of this shape is not aesthetic purity. It gives the implementation a
place to ask a finite set of questions before an irreversible effect occurs.
Is this path canonical and still beneath its authorized root? Did a rewrite
change the resource being authorized? Is this handler allowed by the effective
scope? Does the request still own the resource leases needed by the selected
sink? Is this configuration generation still allowed to admit new work?

The [request planner](../../crates/server/src/request_plan.rs) and the typed
`PreparedHandler` variants in the [server](../../crates/server/src/server.rs)
are manifestations of this intuition. A contributor should be wary whenever a
new code path reaches execution without passing through the same decision
chain.

## A transformation spends authority

URL mapping, aliases, rewrites, internal redirects, content negotiation, error
documents, and proxy failover all transform one name into another. A common
source of web-server vulnerabilities is to authorize the name before the
transformation and then execute the result as though the authorization still
applied.

Vapache treats a transformation as an authority transition. The result must be
rebound to the correct policy and target identity. This is why apparently
minor implementation details—whether a rewrite produces a URL or a filesystem
path, whether an internal redirect preserves the original method, whether a
proxy route can derive its authority from a capture—receive disproportionate
attention.

The useful contributor heuristic is: if a value can change *what* will be
read, executed, contacted, cached, or logged, find the point where authority is
re-established after the change. If there is no such point, the change is
probably bypassing the architecture.

## Authority belongs to identities, not names

A pathname, process ID, hostname, or configuration filename is only a name.
Security decisions need an identity that cannot be silently substituted after
the decision.

This intuition produces several different mechanisms because the available
kernel objects differ. Static content can be opened and carried as a file
descriptor. A daemon control action can bind a PID file to boot ID, process
start time, executable identity, and service user. A FastCGI handoff cannot
send an already-open script descriptor through the protocol, so it needs a
protected Unix socket, peer credentials, and a release tree that the backend
cannot rewrite. Administrative inputs need ownership, parent-chain, file-type,
size, and stability checks.

These mechanisms should not be copied mechanically from one subsystem to
another. They are answers to the same question: what stable identity is
available at this boundary, and who has the authority to replace it?

## Failure must compose

Fail-closed behavior is often described as a local error-handling rule. In
Vapache it is also a compositional strategy. An unsupported policy directive,
an ambiguous request framing, an unavailable group provider, a missing
capability, or a stale configuration generation must remain a denial when it
passes through negation, merging, caching, rewriting, and error handling.

This is why “parse and ignore” is so dangerous. A no-op can look harmless in
the parser while becoming a policy deletion in a parent scope or a permission
grant under negation. The architecture prefers a visible incompatibility to an
apparently compatible server that has forgotten part of the operator's policy.

## Proof is concentrated where composition is hardest

Vapache does not attempt to prove the whole daemon. It uses machine-checked
kernels for bounded arithmetic, parsing transitions, policy combinators,
resource state machines, and other decisions whose local shape can be made
precise. The surrounding Rust implementation consumes those decisions, while
tests check the refinement boundary and the system behavior.

That division is deliberate. A small proof about a state transition can be
strong and reusable. A sweeping claim about an HTTP server is likely to hide
filesystem, scheduler, dependency, or integration assumptions. The companion
essay [How Vapache builds a security argument](building-a-security-argument.md)
explains this evidence structure in more detail.

## The architecture has costs

These intuitions make some Apache deployments harder to migrate. They reject
configurations that another compatibility layer might accept. They require
more bookkeeping around generations, identities, and resource ownership. They
also create a risk of elaborate internal machinery whose connection to an
operator-visible property becomes hard to see.

Contributor explanation is one countermeasure to that last risk. When adding
a mechanism, document the intuition it serves, the authority it carries, the
failure state it preserves, and the evidence that tests it. If those answers
are unclear, the mechanism may be accidental complexity rather than part of
the design.

## Questions to carry into a change

Before changing a security-relevant path, ask:

- What operator policy is this code interpreting?
- What identity is stable at this point, and who can replace it?
- Does the code transform the resource after it was authorized?
- Can an error become a grant through merging, negation, fallback, or caching?
- Is mutable state policy-bearing, resource-bearing, or process infrastructure?
- Which part belongs in a proof kernel, which part needs a runtime test, and
  which part remains an external assumption?

Those questions are more durable than any current module layout. They are the
shape Vapache is trying to preserve.
