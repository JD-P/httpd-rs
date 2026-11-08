---
doc_type: explanation
audience: apache-operator
status: draft
---

# Security properties and limits

Vapache is an independent reimplementation of the core features of Apache HTTP
Server 2.4 in Rust. It can reduce risks that depend on Apache's C implementation
or on an Apache feature that Vapache does not provide. It cannot make the
complete host or web application secure.

Use [Decide whether to replace Apache with
Vapache](../how-to/evaluate-security-driven-migration.md) when a new Apache
incident prompts an evaluation. This page explains the limits that apply to any
Vapache deployment.

## Vapache does not contain the Apache server implementation

Vapache does not use Apache's request parser, configuration evaluator, or
request-processing code. A defect in those exact code paths is not carried into
Vapache.

Independent implementations can still make the same logical mistake. Both
servers implement HTTP, access checks, rewrites, TLS, CGI, FastCGI, and reverse
proxying. A defect in the protocol or in the intended behavior can therefore
affect both products.

## Safe Rust prevents classic C memory corruption

More than 99% of the Vapache server source is safe Rust. Safe Rust prevents
classic C memory-corruption bugs such as use-after-free, double-free,
uninitialized-memory access, and out-of-bounds memory access.

Rust does not prevent:

- an incorrect access decision;
- an ambiguous HTTP interpretation;
- an unsafe configuration default;
- a memory leak or excessive memory use;
- resource exhaustion;
- incorrect use of cryptography;
- a defect in an external library;
- a defect in a web application or backend.

The project checks the small unsafe Rust inventory and prevents unreviewed
growth. Native dependencies, the Rust compiler, and the unsafe boundary remain
separate assumptions. Safe Rust removes a large class of memory-corruption
defects; it does not make every security decision correct.

## Vapache checks some properties with machine proofs

The project uses machine-checked proofs for selected parsers, state changes,
resource counters, and access-policy operations. Each proof applies to a named
piece of the implementation and a stated set of assumptions.

The proofs do not cover the complete daemon, Linux, Rustls, the network, or the
application. A deployment decision must also use runtime tests and application
tests.

## Unsupported policy stops loading or fails the request

Vapache does not silently ignore an access, authentication, proxy, TLS,
handler, or filter rule that it recognizes but cannot implement.

- An unsupported rule in the main configuration stops configuration loading.
- An unsupported rule in an `.htaccess` file returns `500` for the request.
- An unsupported content handler returns `500` instead of serving source code.

This behavior prevents one unsafe migration failure: accepting a configuration
after discarding part of its security policy. It can also prevent an emergency
switch until you change the deployment. Do not delete a security rule only to
make the configuration load.

## Risky compatibility features are off by default

Some supported Apache features can discover files, execute programs, generate
content, or accept older protocol forms. Vapache requires an explicit
`VapacheCapability` setting before it enables these features.

The configuration test reports the capabilities that a site needs. Enabling a
capability permits the feature; it does not prove that the deployment uses the
feature safely.

## Applications and backends remain separate security concerns

Vapache can correctly authorize a request that then exploits WordPress, PHP, a
CGI program, a proxied service, or a database. Replacing Apache does not patch
those components.

For PHP-FPM and other FastCGI deployments, keep executable application code
read-only to the backend. Put uploads and generated data in a separate writable
directory. Do not enable script execution in that directory.

For reverse proxies, configure the application with its public URL and trust
forwarded headers only from Vapache.

## The operating system and dependencies remain trusted

Vapache depends on Linux to enforce file permissions, process identities, and
filesystem containment. An administrator or privileged process can replace
the executable, change trusted configuration, or alter the operating system.

Vapache uses Rustls for TLS and uses other Rust libraries. The project tests and
audits these dependencies, but does not prove their complete behavior. A new
defect in a shared dependency can affect Vapache.

## Resource limits reduce damage but do not guarantee availability

Vapache limits connections, requests, memory, file descriptors, tasks, and
other resources. When a limit is reached, Vapache can reject a connection,
return `503`, or close a tunnel.

These limits protect the server process. They do not guarantee that the site
stays available during an attack or an operating-system failure.

## Vapache is pre-release software

Vapache has a smaller deployment history and support community than Apache. A
new implementation can avoid old Apache defects while introducing new defects
that production use has not found.

Use an evaluation host, test important application operations, keep a rollback
procedure, and decide whether your organization can operate pre-release server
software.

## Detail for contributors and security reviewers

The operator guidance above states what can be claimed about a deployment.
Contributors and security reviewers can continue with [The shape of
Vapache](the-shape-of-vapache.md) for the architecture and [How Vapache builds a
security argument](building-a-security-argument.md) for the evidence model.
