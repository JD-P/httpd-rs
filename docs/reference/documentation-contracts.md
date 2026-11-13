---
doc_type: reference
audience: documentation-contributor
status: normative
---

# Executable documentation contracts

A documentation contract connects a concrete documentation claim to observable
httpd-rs behavior.

## Contract types

A local executable contract checks a small example through a public httpd-rs
interface. It must have:

- a stable ID in the form `DOC-AREA-NNN`;
- a documentation page that uses the claim;
- a canonical example or generated fixture;
- an invocation through a public httpd-rs interface;
- an exact expected result;
- an evidence type;
- cleanup that does not change the operator's system state.

The contract must use the built `httpd-rs` executable for configuration and
HTTP behavior. An internal Rust function test can provide additional evidence,
but it cannot replace the public-interface check.

An evidence binding connects a how-to procedure to an existing repository
test, package test, or canonical deployment scenario. It must have:

- a stable ID;
- one how-to page;
- a link from the page to each named evidence file;
- stable markers for the relevant test cases or implementation checks;
- a deployment contract for each named scenario.

The documentation test checks the paths and relationships. The owning quality
gate executes the bound test or scenario. Use an evidence binding when the
behavior needs systemd, Certbot, PHP-FPM, a real application, or another
boundary that a small local fixture cannot reproduce.

## Canonical examples

Store a canonical example below `docs/examples`. A page can embed the example
with this marker immediately before a fenced block:

```markdown
<!-- tested-example: path/to/example.conf -->
```

`tests/docs.py` requires the fenced block to equal the canonical file. The
runtime contract then uses the canonical file.

## Contract inventory

Contracts are defined in `docs/contracts.toml`.

| Contract | Claim | Public interface |
|---|---|---|
| `DOC-MIGRATE-STATIC-001` | The tutorial virtual host serves its index, uses its custom 404, and rejects static `POST` with `405` | `httpd-rs -t`, foreground server, HTTP |
| `DOC-CAPABILITY-AUDIT-001` | CGI configuration reports the missing `Cgi` capability and audit mode does not enable it | `httpd-rs --audit-capabilities` and `httpd-rs -t` |
| `DOC-UNSUPPORTED-POLICY-001` | An unimplemented security policy is rejected | `httpd-rs -t` |

Each application tutorial also has a `DOC-DEPLOY-...` contract. The local
documentation test requires exactly one tutorial for every deployment scenario,
checks its canonical dimensions and operating modes against `scenario.toml`,
and checks its catalog entry. The scheduled canonical application workflow then
runs the application and its semantic workflow through httpd-rs.

Each operational how-to has a `DOC-HOWTO-...` evidence binding. The local
documentation test requires the page to link each evidence file and requires
each named application scenario to have a deployment contract. It also fails
if a named evidence case is removed or renamed. Package, conformance,
configuration, and CVE quality gates execute the file evidence.

## Run the contracts

Build httpd-rs and run:

```console
$ cargo build -p httpd-rs
$ python3 tests/docs.py
```

Set `HTTPD_RS` to test another binary.
