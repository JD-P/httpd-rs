# Configuration semantic-refinement review

Date: 2026-11-04

## Question

This campaign examined whether configuration text accepted by the shared
front end can acquire a different meaning while it is converted into the
immutable main-configuration or `.htaccess` IR and then projected into the
effectful compiler.

The former boundary was not an unbounded parser: lexical transitions,
argument schemas, section structure and many primitive decisions were already
executable Verus kernels, and every payload was sealed before effects. The
remaining risk was that the safe-Rust sealing constructor and a later compiler
arm could independently interpret the same token vector. A validation/apply
disagreement at that seam can turn a rejected value into an effect, or apply a
validated value under the wrong directive semantics.

## Implemented refinement

Every payload schema now selects one of 46 closed `ConfigSemanticKind`
domains. Sealing records that domain and must consume the executable Verus
certificate that:

1. the schema and constructed IR have the same semantic kind; and
2. source argument cardinality was preserved while the owning Rust object
   moves the original vector into the sealed payload unchanged.

Every main-config and access-file compiler entry checks the same certificate
before any scope mutation. Typed projections additionally name the one domain
they accept and return `None` for every different domain. Verus proves that
the closed kind encoding is injective, that a successful schema-to-seal and
seal-to-consumer chain implies actual kind equality across all three stages,
and that kind substitution is rejected.

The shared primitive constructors are executable verified implementations:

- `On`/`Off` is exact and ASCII-case-insensitive;
- unsigned decimal parsing denotes the exact mathematical base-10 value and
  rejects empty, signed and overflowing forms;
- bounded unsigned values preserve that value and enforce both endpoints;
- keyword selection returns the first matching member and cannot invent or
  skip a match.

The effect-sensitive constructors that previously validated and then reparsed
tokens now compile exactly once into typed values. These include process-wide
capabilities, stable FastCGI identity policy, `AllowOverride` and
`AllowOverrideList`, proxy balancer members and health policy, `ServerAlias`,
`LogLevel`, `SSLSessionCache`, and `RewriteMap`. In particular, `RewriteMap`
now seals its map kind, source, program pathname and helper arguments before
the compiler performs a file open or binds a helper executable.
Compatibility-only TLS directives are validated during sealing and are not
reparsed by the effect phase.

Main configuration and `.htaccess` use separately scoped directive tables for
Apache compatibility. A cross-table regression test enumerates every
effectful access-file directive and requires the same semantic kind in both
tables, preventing schema drift between the two compilers.

## Security consequences

- A payload cannot be projected through a getter for another directive
  domain.
- The compiler cannot silently project the payload through another semantic
  domain, and sealing retains the original token vector alongside its typed
  value.
- Security-sensitive normalization does not run for the first time after
  configuration effects have begun.
- Validation and application no longer maintain separate parsers for the
  high-impact policy, route, process and TLS values listed above.
- Main/access table drift for effectful directives is detected by the normal
  parallel unit suite.

## Evidence

- `cargo verus verify -p httpd-rs-verified`: 711 verified functions, 0 errors.
- `tests/verification_status.py --run-verus`: proof gate passes with no proof
  escapes.
- Unit tests cover all 46 kind tags, wrong-domain projections, malformed and
  overflowing primitives, typed effectful constructors, and main/access
  semantic-domain parity.
- The normal server-library suite exercises construction and application of
  the resulting immutable programs.
- Apache remains the differential oracle for complex compatibility behavior.

## Remaining external boundary

This is an internal refinement proof, not a formal specification of the
Apache C implementation. It proves that httpd-rs preserves its selected
semantic domain from schema through typed IR to compiler consumption and
mechanizes the primitive normalizers above. Complex safe-Rust constructors
such as regular expressions, authorization expressions and rewrite syntax are
still checked by typed construction, unit/property tests and Apache
differential oracles; the regex engine's documented language and capture
semantics remain an explicit external assumption.

Filesystem reads, process binding and other operating-system effects are also
outside this theorem. Their existing descriptor/inode, trust-chain and
resource-admission checks begin only after the relevant configuration payload
has successfully crossed the proved semantic boundary.
