---
doc_type: landing
audience: apache-operator
status: draft
---

# httpd-rs documentation

httpd-rs is an independent reimplementation of the core features of Apache HTTP
Server 2.4 in Rust. It reads existing Apache configuration for the features
that it supports. It does not implement every Apache module or reproduce every
Apache behavior.

Use the Apache manual for Apache configuration syntax and standard Apache
behavior. Use these pages to decide whether httpd-rs fits a site, find the
intentional differences, test an existing configuration, migrate, and operate
the service.

httpd-rs is pre-release software. Evaluate it on a test host and keep an Apache
rollback procedure.

## For Apache administrators

Follow these pages in order when a new Apache incident or security review
prompts an evaluation:

1. [Decide whether to replace Apache with
   httpd-rs](how-to/evaluate-security-driven-migration.md).
2. [Assess the complete Apache
   configuration](how-to/assess-apache-configuration.md) without stopping
   Apache.
3. [Check Apache compatibility and intentional
   differences](reference/apache-compatibility.md).
4. Run the [Debian static-site migration
   tutorial](tutorials/migrate-debian-static-site.md) to learn the switch and
   rollback procedure.
5. Use the [deployment tutorial](tutorials/README.md) for the application or
   connection type.

[Security properties and limits](explanation/security-expectations.md) explains
which risks an independent Rust implementation can reduce and which risks
remain.

## For application and service operators

- [Deployment tutorials](tutorials/README.md)
- [Operational how-to guides](how-to/README.md)
- [Reload, reopen logs, stop, and diagnose
  httpd-rs](how-to/operate-httpd-rs-service.md)
- [Migrate TLS and Certbot](how-to/migrate-tls-and-certbot.md)
- [Roll back to Apache](how-to/roll-back-to-apache.md)

## For contributors and security reviewers

These pages describe the architecture, its assumptions, and the evidence used
for security claims. They use implementation terminology and are not part of
the administrator migration path.

- [Contributor architecture](explanation/README.md)
- [Executable documentation contracts](reference/documentation-contracts.md)

## Project working records

Historical audits, coverage records, generated review material, and other
project working records remain available in the complete documentation index.
They are project evidence, not administrator instructions.
