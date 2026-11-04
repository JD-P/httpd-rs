# Virtual-host configuration isolation and Apache-equivalence review

Date: 2026-11-04

## Scope

This campaign treated selection of a virtual host and compilation of its
effective policy as a cross-tenant security boundary.  A request must not gain
or lose authorization, select another tenant's filesystem mapping, or reach a
different backend merely because a main-server directive occurs before or
after a `<VirtualHost>` block in the source text.

`tests/vhost_semantics.py` builds equivalent Apache and Vapache
configurations, starts both servers, and compares two named tenants plus
wildcard-name and exact-address buckets.  Its matrix covers:

- main-server versus vhost `Directory`, `Files`, and `Location` policy;
- `Alias`, `Redirect`, `ProxyPass`, and `ProxyPassMatch` first-match order;
- inherited and vhost `RewriteRule`, MIME, `DirectoryIndex`, `ErrorDocument`,
  response-header, and included-file policy;
- exact/wildcard host-name selection, destination-address buckets, Host case
  and trailing-dot normalization; and
- a graceful reload that replaces an authorization generation while retaining
  the selected tenant.

## Findings

### VHOST-1: lexical order crossed the server/vhost policy boundary

Vapache cloned the main-server rule vector, appended vhost rules, and then
sorted the combined vector using each rule's original source position.  If a
main-server section appeared after a `<VirtualHost>` block, equal-path
`<Directory>` and `<Location>` rules ran after the vhost rule.  Apache instead
constructs the main-server layer before the selected vhost layer regardless of
their lexical placement.

Both security directions were observed:

- Apache `200`, Vapache `403` when a vhost grant was followed lexically by a
  global deny; and
- Apache `403`, Vapache `200` when a vhost deny was followed lexically by a
  global grant.

The second form is a cross-tenant authorization bypass for configurations
whose vhost deliberately narrows an inherited main-server policy.

The compiler now rebases vhost rule order after the complete main-server rule
generation before canonical phase/specificity sorting.  The executable Verus
kernel `configuration_child_merge_order` uses checked arithmetic and proves
that every successful child order is strictly after its parent maximum while
preserving local order.

### VHOST-2: inherited first-match mappings shadowed vhost mappings

`Scope::merge` appended vhost `Alias` and `Redirect` entries after inherited
entries, while both dispatchers select the first match.  Apache gives a
vhost's alias/redirect table priority over the main-server table.  An identical
vhost path therefore served the global filesystem object or global redirect
target on Vapache.

The server-to-vhost merge now rotates only these first-match tables to
`vhost -> main`.  Handler extensions remain `main -> vhost` because their
lookup is intentionally last-match; applying one generic list rule to both
was the architectural error.

### VHOST-3: proxy precedence depended on lexical placement

Apache's proxy table has the opposite hierarchy from Alias/Redirect: global
`ProxyPass`/`ProxyPassMatch` entries precede vhost entries.  Vapache stored a
single parser-wide `route_order`, so a vhost route won if its block appeared
first and lost if it appeared second.  Moving an otherwise identical global
directive across the block changed the upstream selected by Vapache but not
Apache.

The compiler now rebases vhost proxy routes after the maximum global route
order across both prefix and regex tables.  Their shared relative order is
preserved, and the same checked verified kernel prevents wraparound from
turning a child route into an early route.

### VHOST-4: audit and CGI metadata escaped the selected vhost

The final field inventory found three values parsed into a vhost but consumed
from the global configuration. A vhost `LogLevel` changed the process-global
level, its `ErrorLog` path was never opened, and CGI/FastCGI `SERVER_ADMIN`
always exposed the main-server administrator. The first two could suppress or
misroute another tenant's diagnostics; the third disclosed the wrong tenant's
metadata to dynamic applications.

`LogLevel` is now retained per vhost. Error-log writers are opened once per
unique path, selected by the same immutable vhost index as the access log,
honor the selected vhost's level, participate in permission preparation,
rotation and reload comparison, and receive request failures without crossing
tenant files. `SERVER_ADMIN` now selects the vhost value with an explicit
main-server fallback. Unit tests and the live matrix pin both error-log
separation and the CGI environment value.

### VHOST-5: a vhost CustomLog supplemented instead of replacing global logs

Apache inherits main-server `CustomLog` directives only into virtual hosts
that have no `CustomLog` of their own. Vapache treated the main-server entries
as unconditional and wrote a vhost with a local access log to both files. That
can disclose one tenant's request targets into a log with different ownership,
retention, or audit consumers.

The logger now compiles an explicit per-vhost override bit alongside its
immutable log table. A selected vhost with any local `CustomLog` skips every
main-server access-log entry and writes only its local set; a vhost without a
local entry inherits the main-server set. Reload comparison includes this
selection policy. The live Apache oracle checks both the overriding tenant and
an inheriting tenant.

## Result and retained coverage

The fixed differential matrix has 32 startup/reload checks and reports full
Apache agreement.  Rust regressions separately pin the rule-generation,
Alias/Redirect, ProxyPass, error-log and access-log hierarchy laws. The Verus
suite reports 706 verified functions and zero errors.

The matrix is part of both the coverage run and the full pre-adversarial gate.
It retains the surprising Apache behaviors too: an earlier wildcard
`ServerAlias` wins over a later exact name in the same address bucket, while an
exact destination-address bucket wins before name matching.

## Remaining boundary

The campaign reduces the server/vhost merge boundary to explicit per-table
laws, but it is not a proof of Apache itself.  Exact semantic construction of
all directive payloads, standard-library sorting, module-specific directives
not implemented by Vapache, and filesystem contents remain outside the Verus
model.  New ordered directive families must declare whether they are
first-match or last-match and whether their server/vhost hierarchy is
`main -> vhost` or `vhost -> main`; they must not inherit a generic vector
append policy by default.
