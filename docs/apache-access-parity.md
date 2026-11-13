# Apache access-control parity

httpd-rs treats Apache as an executable compatibility oracle for the supported
configuration surface.  This is stronger than waiting for an adversarial pass
to discover a semantic mismatch: every security-sensitive compatibility change
should add both a source-derived model and a differential case that runs the
same configuration and request against Apache and httpd-rs.

## The refinement rule

For every supported configuration and request, httpd-rs must not reach a
protected sink when Apache denies, challenges, or rejects that request.  Exact
status and selected identity parity is the default test.  A deliberate httpd-rs
divergence is allowed only when it is documented and is a security refinement,
such as refusing to trust `RemoteIPHeader` when no proxy trust list exists.

The protected sinks are static-file reads, directory listings, CGI and FastCGI
execution, HTTP/WebSocket proxying, and cache reads and writes.  The compared
identity includes the original URL, effective client address, selected
filesystem object, handler, FastCGI lexical script name, backend, and relevant
authorization scope.

## Current gate

`tests/config_semantics.py` is the live oracle.  It starts Apache and httpd-rs
with paired configurations, sends the same requests, and compares outcomes.
`tests/coverage.sh` runs its fixed corpus plus 128 deterministic generated ACL
cases. P15 adds PCRE expression and `mod_remoteip` chain cases; P18 adds the
independent section-command gates for `AllowOverrideList`. The end-to-end
P15/P17 cases in `tests/adversarial_regressions.py` independently pin
FastCGI lexical/canonical identity, canonical-target authorization, trusted
proxy address handling, and fail-closed expression behavior.

The corresponding production decisions are small Verus kernels:

- `expr_regex_result` makes an expression evaluation error incapable of
  becoming a grant, including through negation.
- `remoteip_next_internal` and `remoteip_candidate_admit` model Apache's
  internal/trusted proxy class transition and its rejection of private
  addresses presented by an external chain.
- `fastcgi_script_identity_admit` requires the backend identity to bind both
  the lexical path sent as `SCRIPT_FILENAME` and the canonical path used for
  containment and authorization.
- `fastcgi_resolved_target_admit` requires the `SetHandler` resolved-file
  constructor to bind its lexical basename and wire path independently from
  the canonical authorized target.
- `htaccess_section_admit` makes a section command's category or exact
  `AllowOverrideList "<Section"` entry independent from any listed child.

The RemoteIP model was derived from Apache 2.4.69
[`mod_remoteip.c`](https://github.com/apache/httpd/blob/2.4.69/modules/metadata/mod_remoteip.c).
The FastCGI behavior is pinned to Apache 2.4.69
[`mod_proxy_fcgi.c`](https://github.com/apache/httpd/blob/2.4.69/modules/proxy/mod_proxy_fcgi.c).
Expression parity is checked against Apache's PCRE implementation rather than
approximating PCRE with Rust's regular-expression dialect.

## Apache 2.4.69 configuration and authorization source audit

The post-P15 audit was performed against the checksum-verified Apache 2.4.69
source and the matching Debian binary oracle. It followed the configuration
from parse-time condition selection through directory/location/file walks,
authorization provider evaluation, rewrite phases and environment hooks. The
reviewed implementation surface was:

- `server/config.c`, `server/core.c` and `server/request.c` for configuration
  parsing, execute-on-read containers and request-scope merge order;
- `modules/aaa/mod_authz_core.c`, `mod_authz_host.c`, `mod_authz_user.c`,
  `mod_authz_groupfile.c`, `mod_auth_basic.c` and `mod_access_compat.c` for
  provider parsing, negation and authorization combination;
- `modules/metadata/mod_env.c`, `mod_setenvif.c`, `mod_remoteip.c` and
  `mod_version.c` for hook timing and conditional configuration;
- `modules/mappers/mod_rewrite.c`, `mod_alias.c` and `mod_dir.c` for
  configuration that changes the resource or environment seen by ACLs.

That audit closed these additional refinement failures:

- `<IfModule>`, `<IfFile>`, `<IfDirective>`, `<IfSection>` and numeric
  `<IfVersion>` now select their branch while configuration is read. Linked-in
  modules are seeded before `LoadModule`, conditions use the loaded-module
  registry, and access files use the same registry instead of activating every
  positive `<IfModule>`. Unknown sections are configuration errors rather than
  transparent containers.
- Environment state is split by Apache hook phase. `SetEnvIf` and server-scope
  rewrite `[E]` are authorization-visible; directory/access-file rewrite
  `[E]`, followed by `SetEnv`/`PassEnv`/`UnsetEnv`, is visible only in fixups
  and CGI/FastCGI. A late variable can no longer grant `Require env`.
- `SetEnvIf` implements the `Remote_Addr`, `Request_URI`, `Request_Method` and
  `Request_Protocol` attributes, prior-environment fallback, capture expansion
  and Apache's default value `1`. Unsupported `Remote_Host`, `Server_Addr` and
  regex header-name modes are rejected at load time instead of being modeled
  as an empty header.
- `Require env` evaluates every operand with APR table's case-insensitive key
  semantics; host operands use Apache's exact label-boundary suffix rule and
  supported string-result expansions; malformed
  `Require all`, negative providers in OR contexts and authorization sections
  containing only negative providers are rejected like Apache.

`tests/config_semantics.py` contains 339 fixed paired cases after this audit,
including 127 source-derived additions. The newest 96-case matrix exercises
every supported access-file wrapper under child-only and exact command lists,
`Nonfatal=Override`, and the AuthConfig/FileInfo/Limit masks. It also pins
execute-on-read nonfatal behavior, nested authorization-container admission,
and `<IfVersion >= ...>` tokenization to the Apache binary oracle.
`tests/config_validity.py` pins the corresponding load-time rejection rules.
Unsupported expression forms or directive ownership that cannot be
represented exactly fail configuration loading; they are not converted into
a false condition that negation could turn into access.

## Extracted Apache models

`tests/apache_warrant.py` now produces a checksum-pinned inventory of Apache
directive registrations, hooks, providers, filters, configuration callbacks,
source tests, and the external `apache-httpd-test` corpus. The inventory is
deliberately conservative: registrations in conditional source are observed
whether or not this particular oracle build enables them. The separately
instrumented Apache build records which source branches the differential
corpus actually reaches.

This is an evidence and coverage model, not an extracted Apache transition
system. `docs/apache-warrant-policy.json` is the only place that may make a
narrow compatibility claim, every such claim requires repository evidence,
and the default classification is `outside-claimed-surface`. Therefore a newly
observed Apache feature can create a review or test obligation but cannot make
httpd-rs accept that feature.

A future source-derived transition system, SMT model, or Lean embedding could
cover combinations that the registration inventory and hand-maintained
differential corpus miss. Such an artifact must still be pinned, validated
against the Apache binary, restricted to the explicitly supported subset, and
checked against httpd-rs's request-to-sink state. Unsupported Apache states must
reject at configuration load rather than disappear from the model. The live
differential gate remains an independent check of any semantic extractor and
of httpd-rs's runtime wiring.
