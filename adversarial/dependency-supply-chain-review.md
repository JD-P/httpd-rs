# Dependency and build-supply-chain review

Date: 2026-11-05

## Result

Vapache's dependency policy now distinguishes audit evidence from temporary
trust explicitly. The initial `cargo vet init` state contained 146 blanket
exemptions and no imported or project-authored audit evidence. Trusted audit
ledgers from nine established Rust projects reduce that to 105 exemptions;
five additional crates have project-authored reviews. At the current lockfile,
`cargo vet` reports 41 fully audited dependency versions and 105 exempted
versions.

An exemption means only that the dependency is currently allowed so the build
can proceed. It is not evidence that Vapache reviewed that code. The CI policy
therefore caps exemptions at 105 and fails if local audit evidence or trusted
imports disappear. Removing an exemption remains monotonic progress; adding
one requires an explicit policy change and review.

## Evidence incorporated

The imported ledgers are Actix, Ariel OS, Bytecode Alliance, Embark Studios,
Fermyon, Google, ISRG, Mozilla, and Zcash. Their URLs use HTTPS and cargo-vet
locks the fetched evidence in `supply-chain/imports.lock`.

The Vapache project additionally reviewed:

- `rustix 1.1.6`, including the Linux event, filesystem, and network syscall
  surfaces used by the server and its build-time compiler probes;
- `linux-raw-sys 0.12.1`, the generated Linux UAPI bindings below `rustix`;
- `smallvec 1.15.2 -> 1.16.4`, including the unsafe inline/heap storage and
  drop paths exercised by `vapache-pcre2`;
- `bitflags 2.11.1 -> 2.13.2`, including its generated flag API and changes to
  unsafe implementations;
- `webpki-roots 1.0.11`, whose published-crate delta removes two distrusted
  eMudhra trust anchors without adding code or roots.

The exact scope and reviewer notes live in `supply-chain/audits.toml`.

## Important residual trust

The 105 exemptions are a concrete audit backlog, not a claim of completion.
The highest-impact remaining items include:

- `ring`, because it implements cryptography and contains assembly and unsafe
  native boundaries;
- `mimalloc` and `libmimalloc-sys`, because the allocator is process-wide C
  code beneath most request handling;
- Verus runtime and procedural-macro crates, because they participate in the
  formal-verification build boundary;
- `tokio-macros`, because generated async control flow is used broadly;
- `cc`, `find-msvc-tools`, and `jobserver`, because build scripts can execute
  tools and influence native compilation.

These should receive source review or additional trusted audit evidence before
the exemption ceiling is lowered. Vulnerability databases and `cargo deny`
remain complementary controls: neither establishes that non-vulnerable code is
non-malicious or correctly implemented.

## Build and release controls

Release workflows pin GitHub Actions by commit, Rust and auxiliary Cargo tools
by version, container images by digest, downloaded Verus and h2spec archives by
SHA-256, and Debian packaging tools by exact package version. Release
compilation occurs in a digest-pinned builder and the actual two-build
reproducibility check runs without network access. GitHub release artifacts
receive an OIDC-backed build-provenance attestation.

The package mirror is deliberately not treated as an immutable archive. If an
exact Debian package version disappears, the builder fails rather than silently
substituting another toolchain. Long-term archival of the referenced `.deb`
files would remove that availability dependency as well.
