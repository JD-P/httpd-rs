---
doc_type: how-to
audience: security-reviewer, contributor
status: draft
contracts: DOC-HOWTO-CVE-001
---

# Add a new Apache CVE to the project review

This procedure is for project maintainers and security reviewers. Use it to add
a newly disclosed Apache HTTP Server CVE to the checked-in project review. It
is not the operator procedure for deciding whether to migrate a site.

Apache operators should use [Decide whether to replace Apache with
httpd-rs](evaluate-security-driven-migration.md).

## Prerequisites

Use a repository checkout for the httpd-rs version that you are reviewing.
Obtain the vendor advisory, affected-version statement, patch when available,
and a configuration that reaches the affected Apache feature.

## 1. Define the exact advisory

Record the CVE ID, affected Apache versions, required module, configuration,
protocol, platform, and attack preconditions. Prefer the vendor advisory and
patch over a summary headline.

Do not infer httpd-rs exposure from an Apache version string. httpd-rs has an
independent implementation, but it can still contain the same type of flaw or
process the same input in an unsafe way.

## 2. Find the matrix row

Search the machine-readable Apache matrix:

```console
$ rg -n 'CVE-2021-41773' docs/cve/apache2-cve-matrix.json
```

Read the row's status, affected httpd-rs feature (the `surface` field),
confidence, rationale, and implementation evidence. Use these meanings:

| Status | Incident meaning |
|---|---|
| `prevented` | The implementation structure or a checked property prevents the cause described by the advisory |
| `fail_closed` | httpd-rs rejects the required feature, directive, or configuration |
| `not_applicable` | The affected feature or platform is absent |
| `partial` | The evidence covers some affected behavior, but not all of it |
| `not_covered` | The affected production code is not included in the formal model |
| `needs_review` | Available source information does not support a decision |

Treat `partial`, `not_covered`, and `needs_review` as open incident work. A
`prevented` row is not a claim that the subsystem has no independent httpd-rs
bugs.

## 3. Check the httpd-rs implementation and test configuration

Confirm which httpd-rs code and configuration correspond to the advisory. Check
enabled capabilities, proxy direction, HTTP version, TLS client-certificate
policy, CGI or FastCGI use, rewrite rules, and platform.

If the deployment enables behavior marked as unsafe, or uses an external
component that the row does not cover, record a separate exposure decision for
that behavior or component.

## 4. Reproduce the checked-in classification

Run:

```console
$ python3 tests/cve_matrix.py --check
```

This command validates the checked-in Apache snapshot and generated matrix. It
does not execute a proof of concept for each CVE.

If the CVE also affects other server implementations, run:

```console
$ python3 tests/cross_server_cve_matrix.py --check
```

Do not use `--fetch` during an incident unless you intend to update the NVD
snapshot and review all resulting classification changes.

## 5. Record the project classification

Record one of these outcomes:

- the cause described by the advisory is prevented and the deployment matches
  the evidence;
- the feature fails closed or is absent in this deployment;
- exposure remains open and needs a mitigation, patch, test, or server change.

For an open outcome, apply a temporary mitigation. When a safe proof of concept
is available, add an automated regression test that sends the triggering
request. Do not convert an open row to `prevented` from design intent alone.

## Evidence

The [Apache CVE review working record](../cve/README.md) defines the snapshot, status
meanings, and limits. The [Apache matrix generator](../../tests/cve_matrix.py)
and [cross-server matrix generator](../../tests/cross_server_cve_matrix.py)
reproduce the checked-in classifications.
