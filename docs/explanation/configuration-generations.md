---
doc_type: explanation
audience: contributor, coding-agent
status: draft
prose_style: discursive
---

# Configuration generations make time explicit

A configuration reload is often described as “read the files again.” That
description omits the hard part. At the moment of reload, old requests may
still be running, long-lived connections may still exist, caches may contain
policy-dependent results, and background workers may be acting on the old
world. The server must decide which world owns every new action.

httpd-rs models reload as a transition between immutable configuration
generations. This makes time part of the policy model rather than an incidental
property of mutable global state.

## Prepare before changing the active world

The intended transition is transactional:

```text
old generation active
        ↓
parse, seal, compile, and prepare candidate
        ↓
commit candidate and retire old admission
        ↓
new generation active; admitted old work drains
```

If candidate parsing, administrative-input validation, log preparation, TLS
preparation, background preparation, or the final pre-commit check fails, the
old generation remains active. Preparation must not leave half-started
background work or retire the only valid policy.

The reload path in [main](../../crates/server/src/main.rs), generation state in
[configuration](../../crates/server/src/config.rs), and retirement gates in the
[server](../../crates/server/src/server.rs) implement this model.

## Retirement means “no new work,” not “destroy immediately”

Requests admitted under the old policy may hold file descriptors, resource
leases, backend work, or response state that cannot disappear at commit. The
old generation therefore drains rather than vanishing.

Retirement closes the door behind it. An old HTTP/1 keep-alive connection
cannot begin an unlimited sequence of new requests. HTTP/2 receives a graceful
shutdown signal and drains admitted streams. WebSocket and other long-lived
work cannot use their old transport to create fresh policy decisions after the
generation is retired.

This distinction prevents two bad models. Killing every old request would make
graceful reload unreliable. Allowing an old connection to admit arbitrary new
work would make the operator's policy change indefinitely postponable.

## Share quantities, isolate meanings

One of the less obvious design decisions is that some state must cross a
generation boundary and some state must not.

Resource budgets are process-wide quantities. If a reload created fresh
request, memory, backend, or spool capacity while old requests retained their
leases, an attacker could multiply the process limit by forcing reloads. The
old and new generations therefore share the accounting pool.

Policy-bearing state has the opposite requirement. Cache epochs, parsed
access-file programs, proxy health and failure state, backend identity
registries, and similar values can carry meanings that depend on the compiled
configuration. They are namespaced, invalidated, or rebound to a generation so
that an observation made under one policy does not silently become a fact
under another.

The short version is: share conserved resources; isolate interpreted meaning.
The [resource ownership implementation record](../resource-inventory.md)
develops this distinction in implementation detail.

## Administrative trust also has a time dimension

Configuration is not the only input to a generation. Certificates, keys,
authentication files, rewrite maps, MIME data, included files, and proxy trust
roots can affect policy. A path that was safe at startup may be replaced before
reload, or a service-owned parent may let the worker substitute the next
candidate.

httpd-rs records and revalidates the authority around administrative inputs.
Where a reload needs privileged file access after the service has dropped
privilege, the design uses a narrowly constrained process-owned broker instead
of restoring ambient privilege to the request-serving process.

The intuition is that trust is not a property permanently bestowed on a
pathname. It is a relationship among an object identity, its parent chain, the
principal allowed to replace it, and the moment at which the server consumes
it.

## Some changes really require a restart

An immutable generation can replace in-memory policy, logs, TLS configuration,
and generation-owned workers. It cannot truthfully claim to have changed
startup effects that remain embodied in the process or kernel. Process
identity, listener identity, PID control state, `ServerRoot`, listen backlog,
and newly enabled CGI execution policy are rejected as reload-only changes.

This is not a limitation to hide behind compatibility syntax. Reporting the
new value while continuing to run with the old effect would split the server's
claimed configuration from reality.

## A state-classification heuristic

When adding mutable or cached state, ask which class it belongs to:

- **Generation policy:** its meaning depends on compiled configuration, so it
  must be namespaced, retired, or invalidated with that generation.
- **Conserved resource:** it represents process, client, descriptor, memory,
  task, or disk capacity, so old and new work must share its ceiling.
- **Process substrate:** it exists across generations but must have a bounded
  role and a protocol that prevents it from granting request authority on its
  own.
- **Request ownership:** it belongs to one admitted request or stream and must
  remain alive until the underlying object or effect is finished.

Misclassifying state is a common route to reload vulnerabilities. Generation
boundaries make the question visible; they do not answer it automatically.
