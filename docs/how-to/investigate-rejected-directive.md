---
doc_type: how-to
audience: apache-operator
status: draft
contracts: DOC-HOWTO-REJECTION-001, DOC-UNSUPPORTED-POLICY-001
---

# Investigate a rejected directive

Use this procedure when `vapachectl configtest` rejects an Apache directive or
value.

## Prerequisites

Keep the complete Apache configuration and the matching Vapache binary. Obtain
access to run both configuration tests. Do not change the active service while
you classify the error.

## 1. Preserve the diagnostic

Run:

```console
$ sudo vapachectl configtest 2>&1 | tee /tmp/vapache-configtest.txt
```

Record the directive, file, line, context, and complete error. Do not remove
the directive before you know its effect.

## 2. Confirm the Apache baseline

Run the matching Apache test:

```console
$ sudo apache2ctl configtest
$ sudo apache2ctl -t -D DUMP_INCLUDES
```

On an RPM-family system, use `httpd -t` and `httpd -t -D DUMP_INCLUDES`.

If Apache also rejects the configuration, correct the Apache configuration
first. If Apache accepts it, continue with the Vapache classification.

## 3. Classify the rejection

| Diagnostic class | Meaning | Response |
|---|---|---|
| Missing `VapacheCapability` | The feature is supported but default-off | Check what the capability enables and add it only if the deployment needs that feature |
| Not implemented or unsupported | Vapache cannot preserve the Apache effect | Redesign the deployment or continue to use Apache |
| Unknown directive | The directive is not in the accepted registry | Check the spelling and which Apache module provides it |
| Invalid context or value | Vapache cannot preserve that placement or value | Move or change it only when Apache semantics remain equal |
| Unsafe input | An ownership, file-type, symlink, size, or path-stability check failed | Correct the reported file or directory property |

For example, `SSLRequireSSL` is not a formatting issue. It is a transport
policy. Vapache rejects it because the directive effect is not implemented.
Removing it would weaken policy.

## 4. Trace the effective source

Use the include dump and the reported line to locate the active occurrence.
Check generated distribution files, enabled-site links, module configuration,
and access files. A directive in an inactive example file is not the same as a
directive in the active include graph.

Use `vapached --audit-capabilities` only to discover missing capability
declarations. Audit mode does not convert unsupported directives into
supported behavior.

## 5. Ask your agent to preserve the directive's effect

When the correct replacement is not clear, give your coding agent the error,
the directive and its enclosing blocks, the Apache module list, the Vapache
source revision, and the Apache documentation for the directive.

Ask the agent to state:

- what Apache does with the directive in that exact location;
- whether Vapache provides the same behavior;
- the configuration or deployment change that preserves the behavior;
- the requests that prove both allowed and denied behavior;
- whether the site must remain on Apache.

Reject an answer that only removes the directive or turns a failed security
check into an accepted request.

## 6. Verify the resolution

Run both tests again:

```console
$ sudo apache2ctl configtest
$ sudo vapachectl configtest
```

Then test the workflow that the directive controlled. Include a negative test.
For an authorization rule, test both permitted and denied requests. For a
rewrite, test the original target and a target that must not match.

<!--
Behavior contract evidence:
[Configuration validity](../../tests/config_validity.py)
-->
