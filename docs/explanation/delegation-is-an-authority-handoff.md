---
doc_type: explanation
audience: contributor, coding-agent
status: draft
prose_style: discursive
---

# Delegation is an authority handoff

Static-file serving can keep a strong connection between authorization and the
opened object: resolve a canonical target, authorize it, open it beneath the
approved root, and carry the descriptor to the response sink. Dynamic systems
are harder because Vapache eventually asks another process to act.

CGI, FastCGI, reverse proxying, and WebSockets are therefore not merely handler
types. Each is an authority handoff across a protocol boundary. The receiving
process has its own parser, filesystem view, identity model, configuration, and
bugs.

## A backend receives a description, not Vapache's decision

When Vapache sends a path, method, header, or authority to a backend, the
backend interprets the bytes again. It does not receive the proof or policy
state that led Vapache to produce them. If the two processes disagree about
normalization, framing, host identity, or executable path, a request can cross
the boundary with more authority than Vapache intended.

This explains the strictness around backend request construction. Ambiguous
framing is rejected before translation. Hop-by-hop and client-supplied
forwarding fields are removed. Backend authorities are compiled from
configuration rather than assembled from attacker-controlled captures.
Reserved CGI environment variables cannot be overwritten by general
configuration expansion.

The goal is not to make the backend trustworthy. It is to make the delegated
request a narrow, canonical statement of what Vapache intends the backend to
do.

## FastCGI exposes the pathname gap

FastCGI demonstrates the problem in its sharpest form. The protocol sends a
`SCRIPT_FILENAME`; it does not provide a portable way to pass Vapache's
already-authorized executable descriptor as the script identity. PHP-FPM will
resolve the pathname in its own process after Vapache has completed its policy
work.

If the PHP identity can replace the script or one of its ancestors, it can
change what is executed between those two moments. Mode bits alone do not solve
the problem when the backend owns the file, because an owner can restore write
permission. A loopback TCP port does not identify which process accepted the
connection.

The stable FastCGI boundary follows from those facts: use an exact protected
Unix socket, validate its stable identity, authenticate the connected peer with
kernel credentials, and require the script tree to be owned by a trusted
release identity rather than the backend. Writable uploads and generated data
must live outside executable handler mappings.

The operator procedures [Configure a protected PHP-FPM Unix
socket](../how-to/configure-php-fpm-unix-socket.md) and [Replace an unsafe
writable PHP layout](../how-to/replace-writable-php-layout.md) are operational
consequences of this architectural gap.

## Reverse proxying has two authorities

A reverse proxy request has a private transport destination and a public
application identity. The backend connection might go to
`127.0.0.1:8000`, while the application believes it is serving
`https://app.example.test`.

Confusing those authorities breaks redirects, origin checks, signed URLs,
cookies, and virtual-host policy. Blindly trusting client-supplied forwarded
headers creates the opposite problem: the attacker gets to choose the public
identity seen by the application.

Vapache therefore derives forwarding fields from the validated client peer,
actual TLS state, and validated public request authority. It strips competing
client fields first. `ProxyPreserveHost` is an explicit choice about whether
the backend `Host` field carries the public authority or the private endpoint
identity; it is not evidence that either value should be trusted from an
arbitrary network peer.

The backend must complete the boundary by trusting these fields only from the
Vapache address and by having an explicit public-URL configuration where the
application supports one.

## CGI trades protocol ambiguity for process authority

CGI avoids a long-lived network backend, but it creates a child process with
an environment, standard streams, inherited resource limits, credentials, and
filesystem access. Descriptor inheritance and environment construction are
therefore part of authorization, not process-launch trivia.

Vapache's CGI boundary closes unrelated descriptors, constructs reserved
request variables separately from configurable environment values, drops to
the intended identity, applies limits, and accounts for the child until its
output and lifecycle are finished. A contributor adding a new convenience
descriptor or environment path should assume it is an authority grant until
proved otherwise.

## Resource ownership must cross the handoff too

Delegating work does not mean the request has stopped consuming Vapache
resources. A backend slot, spool file, retained response buffer, pipe,
descriptor, or blocking read must stay charged until the underlying object is
actually released. Releasing a request-worker slot can be correct; releasing
the physical resource it was accounting for is not.

This is why typed prepared handlers and resource leases travel together into
backend execution. The handoff is both a policy transition and an ownership
transition.

## Questions for a new delegation path

Before adding a handler, protocol feature, or backend optimization, ask:

- What exact identity does Vapache authorize, and what identity can the
  receiver actually authenticate?
- Which bytes will the receiver parse again under different rules?
- Can attacker-controlled input select the transport destination or public
  authority?
- Can the receiver replace a file or object after Vapache checks it?
- Which descriptors, credentials, environment variables, and resource leases
  cross the boundary?
- What does failure mean after part of the request has been delegated?

The answers define the real feature. The configuration directive is only its
surface spelling.
