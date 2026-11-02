# Apache httpd accepts an unsupported Files-inside-If section that ordinary requests do not execute

## Summary

Apache HTTP Server 2.4.69 accepts request-time conditional sections containing
`<Files>` or `<FilesMatch>`:

```apache
<If "%{HTTP:X-Grant} == 'yes'">
    <Files "secret.txt">
        Require all granted
    </Files>
</If>
```

This nesting is not among the combinations documented as supported. On an
ordinary direct request, the nested file policy is not evaluated. A nested deny
therefore fails to protect the file, while a nested grant fails to relax an
outer denial.

The safest classification is an Apache configuration-validation bug with
security consequences for misconfigured deployments. It is not a demonstrated
remote vulnerability: exploiting it requires the ability to write server or
`.htaccess` configuration, and the unsupported nesting is outside Apache's
documented grammar.

No upstream issue identifier was assigned during this investigation.

## Affected version and test environment

- Apache HTTP Server 2.4.69 (Debian build)
- Linux x86-64
- Main-server configuration and `.htaccess`
- Ordinary direct HTTP/1.1 requests

The 2.4.69 source paths responsible for the behavior are identified below.
Older releases and internal redirect/subrequest behavior were not exhaustively
tested.

## Documented nesting model

Apache's [configuration sections documentation][sections] describes these
supported relationships:

- `<Files>` may be nested inside `<Directory>`.
- `<If>` may be nested inside `<Directory>`, `<Location>`, or `<Files>`.
- `<If>` may not be nested inside another request-time `<If>`.

It does not list `<Files>` inside `<If>`. The same document's
[merge-order section][merging] places Files matching in phase 3 and
request-time If evaluation in phase 5.

The accepted configuration is therefore not evidence of an intended reverse
nesting rule. It conflicts with both the documented nesting direction and the
documented merge order.

## Minimal reproductions

Create a document root containing `secret.txt`, then use one of the following
policy pairs.

### Nested grant is ignored

```apache
DocumentRoot "/srv/repro/www"

<Directory "/srv/repro/www">
    Require all denied
</Directory>

<If "%{HTTP:X-Grant} == 'yes'">
    <Files "secret.txt">
        Require all granted
    </Files>
</If>
```

```sh
apache2 -t -f /srv/repro/httpd.conf
curl -i -H 'X-Grant: yes' http://127.0.0.1:8080/secret.txt
```

Observed on 2.4.69:

```text
Syntax OK
HTTP/1.1 403 Forbidden
```

If the nested Files policy were executed, the matching request would be
granted. The 403 shows that the outer directory denial remains effective.

### Nested deny is ignored

```apache
DocumentRoot "/srv/repro/www"

<Directory "/srv/repro/www">
    Require all granted
</Directory>

<If "true">
    <Files "secret.txt">
        Require all denied
    </Files>
</If>
```

Observed on 2.4.69:

```text
Syntax OK
HTTP/1.1 200 OK
```

The same unsupported nesting is accepted in an otherwise permitted
`.htaccess` file. An enclosed deny was likewise not applied to an ordinary
direct request.

## Root cause

Apache's context flags already group `<If>` with file contexts for exclusion:
`NOT_IN_FILES` is documented as “Forbidden in `<Files>` or `<If>`” in
[`include/http_config.h`][http-config].

However, [`filesection()`][filesection] checks only
`NOT_IN_LOCATION | NOT_IN_LIMIT`. It does not include `NOT_IN_FILES`, so a
`<Files>` child is admitted beneath `<If>`, `<ElseIf>`, `<Else>`, or
another file section. The parser creates a file configuration and attaches it
to the current conditional configuration with `ap_add_file_conf()`.

[`ifsection()`][ifsection] then attaches that conditional configuration to
the enclosing scope with `ap_add_if_conf()`.

At request time, the ordinary file walk has already happened before the If
phase. [`ap_if_walk_sub()`][if-walk] evaluates and merges the selected
conditional configuration. Afterward it recursively walks only nested
`sec_if` entries; it does not perform another `sec_file` walk. The file
configuration stored beneath the conditional is consequently not evaluated on
the direct request path tested here.

This is a parser/runtime phase mismatch:

```text
configuration parser:
    If -> accepts Files child -> stores child in conditional sec_file

ordinary request:
    file walk -> location walk -> If walk -> recursively revisit sec_if only
                                          -> nested sec_file not evaluated
```

## Security impact

The behavior is security-relevant because `apache2 -t` reports `Syntax OK`
for a policy that is not enforced:

- An administrator can place `Require all denied`, authentication,
  handler restrictions, or other file policy in the nested section and
  incorrectly believe it protects matching files.
- Generated configuration can pass deployment validation while silently
  omitting the intended file-specific restriction.
- The surviving nested `sec_file` configuration may interact differently
  with internal redirects or subrequests that repeat configuration walks.
  This investigation did not characterize those paths, so applications must
  not rely on the direct-request no-op being stable.

The prerequisite is configuration write access. This report does not
demonstrate an unauthenticated remote attacker creating the affected nesting,
and therefore does not claim a directly exploitable Apache CVE.

## Recommended Apache remediation

Reject the unsupported nesting at configuration load. The narrow change is for
`filesection()` to include `NOT_IN_FILES` in its context check:

```c
ap_check_cmd_context(cmd,
    NOT_IN_LOCATION | NOT_IN_LIMIT | NOT_IN_FILES);
```

Because Apache's `NOT_IN_FILES` check includes Files, FilesMatch, If, ElseIf,
and Else parents, this preserves the documented `<Directory><Files>` form
while rejecting the unsupported reverse and same-type nestings.

Regression coverage should include:

1. Main-config `<If><Files>` and `<If><FilesMatch>` rejection.
2. The same shapes in `.htaccess`.
3. ElseIf/Else parents.
4. Nested deny and nested grant payloads, demonstrating that neither policy can
   pass configtest and then disappear.
5. A positive `<Directory><Files>` control.

Implementing a second file walk after the If phase would instead create a new
merge order and could change the meaning of existing directives. Parse-time
rejection is smaller and matches the documented grammar.

## Vapache disposition

Vapache rejects non-conditional Directory/Files/Location children inside a
request-time `<If>`, `<ElseIf>`, or `<Else>` in both main configuration
and `.htaccess`.

It does not copy Apache's accepted no-op. It also does not attempt to execute
the nested policy: doing so would create the opposite incompatibility, where a
nested grant could change Apache's 403 into a Vapache 200.

The regression is represented in:

- `tests/config_validity.py` as deliberate fail-closed hardening.
- Main-config and `.htaccess` unit tests.
- `docs/config-semantics.md` and `docs/verification-status.json`.

## References

- [Apache 2.4 configuration sections: nesting and merge order][sections]
- [Apache 2.4 configuration merge order][merging]
- [Apache httpd 2.4.69 `filesection()`][filesection]
- [Apache httpd 2.4.69 `ifsection()`][ifsection]
- [Apache httpd 2.4.69 `ap_if_walk_sub()`][if-walk]
- [Apache httpd 2.4.69 context flags][http-config]

[sections]: https://httpd.apache.org/docs/2.4/sections.html#nesting
[merging]: https://httpd.apache.org/docs/2.4/sections.html#merging
[filesection]: https://github.com/apache/httpd/blob/2.4.69/server/core.c#L2630-L2706
[ifsection]: https://github.com/apache/httpd/blob/2.4.69/server/core.c#L2723-L2794
[if-walk]: https://github.com/apache/httpd/blob/2.4.69/server/request.c#L1868-L2005
[http-config]: https://github.com/apache/httpd/blob/2.4.69/include/http_config.h#L955-L970
