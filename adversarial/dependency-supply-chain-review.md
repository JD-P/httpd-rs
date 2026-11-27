# Dependency and build-supply-chain review

Date: 2026-11-27

Status: complete first-pass triage, with targeted follow-up on `ring`, mimalloc,
Brotli, and `smallvec`. This review is intended to identify where a deeper
source or stewardship review will buy the most assurance. It is not a claim
that every dependency has received a line-by-line audit.

## Result

No evidence of malicious dependency content was found. The strongest initial
xz-shaped signal, `ring`'s pregenerated cryptographic artifacts, was resolved
substantially in this follow-up: all 86 generated assembly files reproduce
byte-for-byte from the published generators, and all 50 loadable sections plus
the disassembly and runtime relocations in the 17 Windows object files match an
independent NASM 2.13.03 rebuild. The objects are not selected by Linux builds.
The remaining `ring` concerns are release-tool pinning and concentrated
publication authority, not an unexplained binary payload.

The deeper pass found one latent code defect worth tracking. The locked
`brotli-decompressor@5.0.3` predates an upstream validation fix for malformed
block switches related to CVE-2026-111497. In the enabled safe configuration,
the old streaming path can progress toward an out-of-bounds indexing panic
while trying to fill its fixed eight-byte input buffer. The server's shipping
path only encodes responses; its decoder calls are confined to tests and the
`fuzzing` feature, so no request-reachable path was found.

The musl allocator remains the highest-impact native review target, but its
packaged mimalloc v3.3.2 source is byte-identical to Microsoft's tag and its
Rust wrapper is small and conventional. Later upstream fixes justify a scoped
delta review, not an inference that this is a suspicious fork. `smallvec`'s
maintainer expansion was open and retained established owners; the crate is
now development-only in this workspace. The local `httpd-rs-h2` work is
project-authored first-party code and is outside the dependency stewardship
assessment.

Large generated binding crates and the Verus fork/procedural-macro boundary
remain secondary review priorities. These are review priorities, not
allegations of compromise.

The existing `cargo vet` position remains important context. Nine external
audit ledgers and five local audits provide positive evidence, while 104 exact
versions remain exemptions. An exemption permits a build; it is not positive
review evidence. The manual triage below covers every locked third-party Cargo
package/version, including the separately resolved fuzz lock, but it does not
convert those exemptions into full audits.

## Snapshot and scope

The reviewed snapshot is:

- `Cargo.lock` SHA-256
  `6b99e623e77ad9ad66a81ba3a2d1324a7f404225afebc54b443518b16e0e0af4`;
- `fuzz/Cargo.lock` SHA-256
  `87937e2009583f4f6e08ce6fd644386c76bf87bbb891d8bb863750c390d5a097`;
- 143 crates.io package/version entries in the root lock;
- 100 crates.io entries in the fuzz lock, with 22 exact versions absent from
  the root lock: `arbitrary`, `libfuzzer-sys`, and 20 newer resolutions of
  package families also represented in the root lock; and
- the project-owned `vendor/httpd-rs-h2-0.4.20` path dependency.

The union is therefore 165 third-party Cargo package/version entries, all from
the registry, plus the project-owned `httpd-rs-h2` component. The checked-in
unsafe baseline identifies 76 entries in the x86_64 GNU/Linux production
graph. The review also includes musl-only production dependencies, other-target
dependencies, development/build/proof dependencies, and fuzz-only dependencies
because they execute in developer or CI environments.

The workspace's four first-party crates are not treated as third-party
dependencies. The project-owned `httpd-rs-h2` fork is likewise classified as
first-party vendored code; it remains in the code inventory for completeness,
but upstream maintainer trust is not used as evidence for the local changes.
Pinned documentation and Wagtail deployment-fixture Python environments are
separate, non-shipping ecosystems and are not included in this Cargo pass;
they need their own review. CI actions and test images are covered by the
repository's existing commit/digest pinning controls.

## Method and rating scale

The code pass checked archives for lockfile integrity, VCS provenance,
build/procedural-macro behavior, native and binary content, archive tricks,
unusually large or dense files, direct network/download behavior, and obvious
unsafe or parser/state-machine hotspots. Security-sensitive and unusual
sections received a shallow manual read. Existing adversarial findings and the
production unsafe inventory were used to avoid treating a low token count as
a security proof.

The stewardship pass used crates.io publisher ownership, repository history
and governance, public maintainer identities, ecosystem exposure, public
handoff or capacity discussions, organizational backing, sponsorship links,
and project funding statements. Project financial health is reported only
from visible project or organizational support. “No funding located” means
the funding picture is unknown, not adverse. Unless a row says otherwise, no
public campaign to displace or pressure the current maintainers was located in
this pass.

Supply-chain ratings mean:

- **Low:** active team or institution, multiple accountable control paths, and
  substantial reputational or organizational cost to a malicious release.
- **Low-moderate:** strong identity and reputation, with some publisher-key,
  bus-factor, or volunteer-funding concentration.
- **Moderate:** identifiable stewardship and no adverse evidence, but control
  is concentrated or project-level continuity funding is not visible.
- **Moderate-high:** concentrated control plus a concrete continuity,
  provenance, or upstream-lag signal that merits monitoring.

Ratings describe relative review priority. They are not probabilities that a
maintainer will act maliciously.

## Verification and xz-style anomaly checks

- All 165 registry archives matched their lockfile SHA-256 checksums.
- All 165 archives contain `.cargo_vcs_info.json`. Only `http@1.5.0` and
  `ring@0.17.14` set its `dirty` flag.
- The Rust source published in `http@1.5.0` matches recorded commit
  `e559023f67e3fad6ecc3ee91307be178e0f13626`; its differences are package
  normalization/exclusions. This resolves the code-content concern, although
  the release is not derivable from a clean checkout by tag alone.
- The ordinary Rust/C source in `ring@0.17.14` matches recorded commit
  `2723abbca9e83347d82b056d5b239c6604f786df`. Packaging deliberately adds a
  generated `pregenerated/` tree before `cargo package --allow-dirty`.
- All 86 pregenerated `.S`/`.asm` files match independent reruns of their
  bundled PerlAsm generators. All 17 PE/COFF objects were independently rebuilt
  with NASM 2.13.03: 50 `.text`, `.rdata`, `.pdata`, and `.xdata` sections,
  disassembly, and runtime relocations match. Whole object files differ only in
  CodeView debug paths and consequent layout offsets. The three remaining
  generated files are legible symbol prefix headers emitted directly from
  `build.rs`.
- `ring` selects those NASM objects only for Windows x86/x86_64; the reviewed
  Linux targets select textual ELF assembly. The release helper that obtains
  NASM still clones a mutable `ring-toolchain` branch despite an in-file TODO
  to pin it. The branch currently resolves to a long-standing 2021 commit whose
  NASM executable is separately checksum-pinned, but the indirection should be
  immutable at the `ring` release layer too.
- No archive contained a path traversal entry, symlink, or hardlink. Expected
  release-helper scripts were the only unexpected executable files. The only
  files above 5 MiB were Microsoft target import libraries.
- Twenty-eight exact registry package versions have build scripts. No direct
  network API, downloader, `git clone`, `curl`, or `wget` invocation was found
  in those scripts. Compiler/configuration probes, local code generation,
  C/C++ compilation, and tool discovery remain powerful build-time behavior
  and are called out below.
- The six procedural-macro crates did not contain direct downloader or network
  behavior. They still execute compiler-side code and should remain part of
  the trusted build boundary.
- Exact-version OSV queries returned no advisory match for the 165 registry
  entries or the upstream `h2@0.4.20` coordinate as of the review date. OSV
  cannot describe local `httpd-rs-h2` changes. It also did not associate the
  C-decoder CVE-2026-111497 with `brotli-decompressor@5.0.3`; source comparison
  still found the analogous stale Rust validation path described below. A
  no-match result is not a source audit.

The Rust toolchain was not present in the review environment, so `cargo deny`,
`cargo vet`, feature-expanded `cargo tree`, and the Rust test suite were not
rerun. The checked-in lockfiles, manifests, cargo-vet ledger, unsafe baseline,
and Python dependency-policy test were inspected; the latter passes with five
local audits, nine imports, and 104 exemptions. The Brotli decoder result is a
source-path finding corroborated by the upstream fix and regression test; a
local runtime reproducer could not be compiled in this environment.

## Priority findings

### DEP-SC-01 — `httpd-rs-h2` is project-owned code, not an external stewardship risk

**Dependency follow-up priority: none. Classification: first-party.**

The changes in `vendor/httpd-rs-h2-0.4.20` are intentional httpd-rs work. They
remain protocol-critical code and should receive the same security review as
the rest of the server, but upstream Hyperium's publisher posture is not the
relevant trust boundary for those changes. This component is therefore kept in
the code inventory for completeness and removed from the dependency
supply-chain priority order.

### DEP-SC-02 — `ring` artifacts reconstruct; release-tool pinning remains

**Code-review priority: high. Supply-chain risk: moderate.**

`ring@0.17.14` contains a 1,044-line build script, C and assembly sources, and
106 files (3,816,220 bytes) under `pregenerated/`: 86 textual assembly files,
17 PE/COFF object files, and three generated symbol-prefix headers. Ordinary
source matches recorded commit `2723abbca9e83347d82b056d5b239c6604f786df`.
Every textual assembly file reproduced byte-for-byte from the bundled PerlAsm
sources. Reassembling the 17 `.asm` files with the release toolchain's NASM
2.13.03 produced identical code, read-only data, Windows unwind data,
disassembly, and runtime relocations. The remaining whole-file differences are
CodeView records containing the build path and consequent file-layout offsets,
not executable content. Linux x86/x86_64 builds consume the reproduced ELF
`.S` files, not the objects.

The shallow implementation pass found no downloader, hidden secondary build
stage, binary patching step, or unexpected import/string in these artifacts.
Packaged builds invoke local compilers and use the already-pregenerated files;
release generation invokes PerlAsm and the locally installed NASM. The C/Rust/
assembly cryptographic and unsafe-FFI surface remains a high-value specialist
code-audit target, but it did not present an unexplained or deliberately
illegible execution path in this pass.

The residual release-engineering issue is concrete but smaller: the upstream
Windows setup script clones the mutable `windows` branch of `ring-toolchain`
and even contains a TODO to pin a commit. That branch currently resolves to
`65116b2c43a86962d0bc135e8ce2740689c50776`, where the NASM download and
executable are checksum-pinned, and it has not shown a suspicious burst of
changes. `ring` should nevertheless pin that commit directly and automate the
artifact comparison so a future branch movement cannot silently change a
release.

Brian Smith is publicly identifiable and is the sole crates.io publisher for
both `ring` and `untrusted`. Their enormous ecosystem use and his long public
security-engineering record create exceptional reputation at stake. The 2025
maintenance-hiatus advisory was withdrawn after Rustls received security
repository access and normal maintenance resumed; current development is
active. This was a public continuity repair, not evidence of pressure to cede
control. No dedicated project funding source was located, and crates.io
publication remains a key-person boundary even though Rustls now provides a
source/security continuity path.

### DEP-SC-03 — exact upstream mimalloc source, with a meaningful update delta

**Code-review priority: high on musl. Supply-chain risk: moderate.**

On musl, `mimalloc@0.1.52` installs `libmimalloc-sys@0.1.49` as the process-wide
global allocator. The enabled wrapper is limited to aligned allocate,
zero-allocate, reallocate, and free calls. Its 137-line build script locally
compiles `static.c`; it has no downloader. The bundled default v3 tree is
byte-identical to Microsoft mimalloc v3.3.2 apart from files excluded when the
crate was packaged. This resolves the fork/provenance question.

The configuration still merits deliberate review. The `secure`, `override`,
`extended`, and v2 features are off. Microsoft subsequently described
bug/security fixes from an audit in v3.4.1 and v3.4.4 and has since reached
v3.7.1. One v3.4.4 fix validates `realloc_aligned` alignment; Rust `Layout`
already guarantees the value passed by this wrapper is a nonzero power of two.
Other later fixes affect configurations or versions not enabled here, and the
newer line includes large refactors plus its own regressions. No defect was
demonstrated in the locked Linux-musl/default API path, so a blind jump to the
newest tag would not be a substitute for reviewing the relevant delta.

Octavian Oncescu is publicly identifiable and is the sole publisher of both
Rust crates. The wrapper is active and widely used, while exact upstream C
provenance and Microsoft's well-supported core project materially limit what a
wrapper compromise can hide. The wrapper project has no visible funding
channel or backup publisher, and no public pressure to transfer control was
found. Follow-up should add a checked upstream-version assertion, review the
v3.3.2-to-selected-tag changes against this exact feature/API path, and
benchmark the `secure` feature before deciding whether to enable or upgrade it.

### DEP-SC-04 — Brotli tables are explained; stale decoder validation remains

**Code-review priority: medium-high. Supply-chain risk: low-moderate.**

The apparent size is less opaque than the raw line counts suggest. Of roughly
238,000 encoder lines, about 200,000 are two generated lookup/data tables. The
122,784-byte dictionary, 704-entry command table, and encoder static-dictionary
tables match Google's reference Brotli data; the 65,536-entry log table matches
its mathematical formula. Both crate source trees match their recorded commits,
and neither has a build script or binary payload. The default feature set is
only `std`: FFI, SIMD, seccomp, and the decompressor's `unsafe` feature are off.
The decompressor compile-time-forbids unsafe in this configuration.

There is still a concrete correctness issue. Upstream commit
`cc7ee0edae39870daa7f0d7c1456e113b759e752`, released in decompressor 6.2.0,
changed a block switch in a category having only one block type from
`NEEDS_MORE_INPUT` to a format error. Upstream tied this input shape to
CVE-2026-111497 in Google's C decoder and explained that the old Rust streaming
loop would buffer input that can never complete the read. In 5.0.3 that buffer
is eight bytes and the refill writes by `buffer_length` without a pre-index
bound check. With httpd-rs's enabled safe feature set, the resulting concern is
a panic/denial of service, not an unchecked memory write. The Rust crate is not
named by the CVE or the exact-version OSV result.

The server only invokes Brotli compression in production. Direct decompressor
calls are under `#[cfg(test)]` or `#[cfg(feature = "fuzzing")]` and decode the
server's own output, so the malformed-input path is not request-reachable in
the reviewed application. Preserve that boundary, and either backport the
small validation fix or account for it explicitly before exposing decoder
input. The 6.x line also carries an explicit AI-authorship policy; upgrading
across that boundary is a new source/process decision rather than a routine
patch bump.

Daniel Reiter Horn is publicly identifiable; Simon Sapin and a Servo publisher
team also own the encoder. The repositories are active under Dropbox and the
crates have very high use. The decompressor's publication authority is more
concentrated, but the encoder's shared ownership and institutional history put
substantial reputation at stake. No project funding channel or coercive
control-transfer activity was located.

### DEP-SC-05 — `smallvec` transition was transparent and retained backups

**Code-review priority: low while development-only. Supply-chain risk: moderate.**

`smallvec@1.16.4` has concentrated unsafe inline/heap storage and drop logic,
but the production PCRE2 wrapper no longer uses it. The remaining lock entry is
development-only through `tracing-subscriber`, with default features rather
than the `union`, `may_dangle`, or experimental drain surfaces. The exact
1.15.2-to-1.16.4 delta has a local cargo-vet audit, including the substantive
`retain` panic-safety rewrite. The locked commit contains CI definitions for
default/all-feature tests, Miri, and fuzzing; this review did not independently
verify historical CI results.

In 2025 the primary maintainer publicly asked for help because of limited
bandwidth and committed to continue until a handoff. The discussion was open,
Servo remained a fallback, and it closed on 2026-11-13 after the publisher set
expanded. The active publisher of the locked version has a shorter public
track record than the established owners, but Simon Sapin, Ms2ger, and Servo's
publishing team retained control. No pressure campaign or hostile displacement
pattern was found. The project has no visible dedicated funding, offset by
Servo organizational continuity and multiple publishers.

The lock is already behind 1.16.6. That later delta removes the prior fuzz
workflow while also doing a broad refactor, so it should not inherit the local
audit automatically. Keep 1.16.4 until a normal source/publisher delta review
extends the existing evidence.

### DEP-SC-06 — additional opaque or high-impact code surfaces

**Follow-up priority: medium.**

- Production `zlib-rs@0.6.8` is approximately 18,000 lines with extensive
  unsafe SIMD and pointer manipulation; the fuzz lock independently resolves
  0.6.9. Trifecta Foundation stewardship, public funding, and an independent
  audit lower supply risk, not implementation risk. The 0.6.8-to-0.6.9 delta
  received only the shallow fuzz-version review in this pass.
- `base64@0.23.1`, reached through `bcrypt`, enables its default
  `simd-unsafe` implementation. The unsafe is localized and tested. The prior
  safe 0.22 dependency was removed when the server standardized on 0.23, so
  feature monitoring matters more than duplicate-version drift.
- `regex-automata` and `regex-syntax` are large parser/automata engines. The
  prior PikeVM capture-cache resource finding is mitigated in the application
  wrapper but justifies continued adversarial testing.
- `linux-raw-sys`, `libc`, both `windows-sys` versions, and the Windows target
  crates contain very large generated bindings or prebuilt import libraries.
  Their provenance is plausible and institutionally backed; meaningful review
  should reproduce generation rather than read generated output line by line.
- The six Verus crates include large forks of `syn`/`prettyplease`, procedural
  macros, build scripts, and proof/runtime cfg boundaries. The named research
  team and institutional affiliations are strong stewardship signals, but the
  boundary is large enough to deserve a dedicated proof-toolchain review.
- `pcre2-sys` bundles PCRE2 C/JIT code, and `libfuzzer-sys` bundles LLVM
  libFuzzer C++. They are oracle/fuzz-only and absent from the release binary;
  they still execute in CI and developer environments.
- `generator` contains context-switch assembly and extensive unsafe Rust, but
  is dev-only through Loom. Windows target crates contain expected prebuilt
  `.a`/`.lib` import libraries. These are the other notable binary/assembly
  surfaces.
- MD5, SHA-1, Blowfish/bcrypt, and related crates are present for htpasswd and
  protocol compatibility. Their cryptographic limitations are an application
  policy concern rather than a supply-chain anomaly; existing configuration
  policy must continue to prevent them from being mistaken for modern general
  cryptography.

## Stewardship profiles

The profile IDs are referenced by the complete dependency inventory in the
next section. “Reputation” is based on public ecosystem use, visible technical
work, and organizational accountability, not popularity alone.

| ID | Stewardship, identity, and reputation at stake | Continuity and project financial health | Risk |
| --- | --- | --- | --- |
| M01 | `vendor/httpd-rs-h2-0.4.20` is project-authored httpd-rs code. External package-maintainer identity and reputation are not the trust boundary for the local changes. | Govern it with the project's first-party review and release controls, not a third-party stewardship rating. | **First-party** |
| M02 | Rust Project teams and the `rust-lang-owner` publisher control these foundational crates. Named team governance and billion-scale aggregate use create very high reputational and institutional cost. | Rust Foundation and corporate ecosystem support are visible. No abnormal control transfer was found. | **Low** |
| M03 | Carl Lerche, Alice Ryhl, Eliza Weisman, David Barsky, and Tokio team publishers are public, established maintainers. These crates are foundational to Rust networking. | Tokio has publicly identified paid contributors and sponsors, including infrastructure companies; control is shared across teams. | **Low** |
| M04 | Joe Birr-Pixton, Dirkjan Ochtman, and Rustls publisher teams are publicly identified and widely trusted for security work. | Rustls joined the Rust Foundation Innovation Lab while maintainers retained control; ISRG/Prossimo and Sovereign Tech Agency support are public. | **Low** |
| M05 | Artyom Pavlov, Tony Arcieri, and RustCrypto teams are publicly known and steward heavily used crypto interfaces and implementations. | RustCrypto describes security response as volunteer, reasonable-effort work. No central durable funding source was located, although individual/community support exists. | **Low-moderate** |
| M06 | David Tolnay and the Serde publishing team have exceptionally high ecosystem exposure and a long public track record. | GitHub Sponsors support is visible. Several crates remain strongly centered on one maintainer, but Serde has a team publisher. | **Low-moderate** |
| M07 | Andrew Gallant (`BurntSushi`) is a publicly known maintainer of core Rust text-search crates with very high reputation at stake. | Individual sponsorship is visible; publisher control is still concentrated. No transfer pressure was found. | **Low-moderate** |
| M08 | Diggory Hardy and the rust-random maintainer team are public, established ecosystem contributors. | A team publisher and sponsor link are visible; no control dispute or forced handoff was found. | **Low-moderate** |
| M09 | Dan Gohman, Chris Wong, and Bytecode Alliance stewardship are public. `rustix` and WASI sit under an accountable nonprofit technical organization. | Bytecode Alliance organizational support and oversight are visible; `errno` has named co-owners. | **Low** |
| M10 | Microsoft and Kenny Kerr control `windows-rs`. Corporate identity, signed organizational history, and enormous downstream use create high accountability. | Corporate funding and multiple internal continuity paths are evident. | **Low** |
| M11 | Bryan Parno, Chris Hawblitzel, Andrea Lattuada, and the Verus team have public Microsoft Research/CMU and academic identities. Reputation is strong, though crate adoption is smaller than the core ecosystem. | Institutional research backing is visible; crates.io publishing is concentrated in a small research team. No control pressure was found. | **Low-moderate** |
| M12 | Daniel Reiter Horn is publicly named; Simon Sapin and Servo also own the encoder crate. Dropbox/Servo association and very high use create significant reputation at stake. | Repositories are active under Dropbox. No repository funding channel was located; decompressor publication is concentrated, while shared encoder ownership provides continuity. No transfer pressure was found. | **Low-moderate** |
| M13 | Taiki Endo and smol-rs administrators are public, high-volume maintainers; `pin-project-lite` is individually published. | Individual sponsorship is visible and smol has team control, but some publisher-key concentration remains. | **Low-moderate** |
| M14 | Josh Stone, bluss, and Alex Kladov are publicly known maintainers of widely used core utilities. | No single pooled project fund was located; multiple maintainers and individual sponsorship/reputation reduce continuity risk. | **Low-moderate** |
| M15 | Carl Lerche and Sean McArthur are public Hyperium maintainers; `http` has extremely broad ecosystem use. | Individual/project sponsorship is visible and control is shared. The dirty publication marker is explained by matching source. | **Low-moderate** |
| M16 | Ashley Mannix and the bitflags organization maintain one of Rust's most widely used crates. | Organizational ownership exists; no dedicated funding or control-pressure concern was located. | **Low-moderate** |
| M17 | Aria Desires, Peter Blackson, and contain-rs owners are publicly attributable and the crates have a long history. | The project is mature and relatively quiet, with no visible dedicated funding. These entries are dev-only here. | **Moderate** |
| M18 | Mazdak Farrokhzad, Jason Lingle, Cameron Mcloughlin, and the proptest publisher team are public contributors with substantial testing-tool reputation. | No project-level funding source was located. Exposure is limited to development/testing in this workspace. | **Moderate** |
| M19 | NEAR's CI publisher controls Borsh; organizational identity and a large production ecosystem create high accountability. | Corporate/open-source project support and multiple organizational continuity paths are visible. | **Low** |
| M20 | Octavian Oncescu is publicly named and is the sole publisher of both Rust mimalloc crates. The crates are widely used, and their bundled C source is exactly attributable to Microsoft mimalloc. | No wrapper-level funding channel or backup publisher was located. Active wrapper maintenance and Microsoft's well-supported upstream reduce continuity and hidden-fork risk; no transfer pressure was found. | **Moderate** |
| M21 | Brian Smith is publicly known and the sole publisher of `ring`/`untrusted`; almost a billion historical downloads and a long security-engineering record create exceptional reputation at stake. | No dedicated funding source was located. The public 2025 continuity repair gave Rustls security access and normal development is active, but crates.io publication remains concentrated. No coercive handoff activity was found. | **Moderate** |
| M22 | Simon Sapin, Ms2ger, Alejandro Vaz, and Servo publishing control are public. `smallvec` has extremely broad ecosystem exposure; the newest publisher has a shorter independent public track record. | The 2025–2026 maintainer expansion was openly requested and completed, with established owners and Servo retained as backups. No dedicated smallvec funding or pressure campaign was located. | **Moderate** |
| M23 | Ruben Nijveld, Folkert de Vries, and Trifecta Tech Foundation are public and accountable; zlib replacement work has substantial security reputation at stake. | Prossimo, Tweede golf, and Sovereign Tech Agency support and an independent audit are public. | **Low** |
| M24 | Ed Page, ordian, and TOML/winnow maintainer teams are public and maintain billion-download parser infrastructure. | Team publishers and individual sponsorship are visible; no handoff concern was found. | **Low-moderate** |
| M25 | The rust-fuzz project and named publishers including Nick Fitzgerald, Manish Goregaokar, Simonas Kazlauskas, and Corey Farwell have established public identities. | Team infrastructure exists; no dedicated project funding was located. These crates execute only in fuzz builds here. | **Low-moderate** |
| M26 | Marshall Pierce and Alice Maz are publicly named and `base64` has exceptionally broad use. | Two owners reduce key-person risk; no project-level funding channel was located. | **Low-moderate** |
| M27 | Vincent Prouillet (`Keats`) is publicly named with an established Rust project record; `bcrypt` has meaningful but not foundational exposure. | No project-level funding source or backup publisher was located. | **Moderate** |
| M28 | `oyvindln` and `Frommi` have long-lived public project handles and hundreds of millions of downloads, but limited formal governance is visible. | No dedicated funding or team publisher was located. | **Moderate** |
| M29 | Sam (`srijs`) is a long-standing public Rust contributor and `crc32fast` is extremely widely used. | Publisher control is concentrated and no project funding channel was located. | **Moderate** |
| M30 | Marvin Countryman is publicly named and `simd-adler32` has very broad use. | Single-publisher control and no visible project funding keep continuity risk above low. | **Moderate** |
| M31 | Xudong Huang is publicly named and `generator` has substantial use in concurrency testing. | Single-publisher control and no project funding were located; this crate is dev-only here. | **Moderate** |
| M32 | Zicklag and a Katharos Tech publishing team are public organizational handles; the crate is broadly transitive. | An organizational publisher exists, but no dedicated project funding source was located. | **Moderate** |
| M33 | `rutrum` is a persistent public maintainer identity and `convert_case` has high ecosystem use; less real-world identity/governance evidence was located than for core-team crates. | Single-publisher control and no project funding were located. | **Moderate** |
| M34 | Thom Chiovoloni is a publicly known Rust systems contributor. | `core_detect` is mature and quiet, with no project funding located; it is dev-only here. | **Moderate** |
| M35 | Sophia Turner, Stefan Holderbach, and the Nushell publishing organization are public and accountable community maintainers. | Community/organizational continuity is visible; no pressure signal was found. | **Low-moderate** |
| M36 | Isis Lovecruft and the Dalek subtle-maintainers team are publicly known cryptography contributors with high reputation at stake. | Team ownership exists; no durable project-specific funding source was located. | **Low-moderate** |
| M37 | Eliza Weisman is a publicly known Tokio contributor and both crates have very broad ecosystem exposure. | Reputation and adjacent Tokio sponsorship are strong, though these repositories have concentrated implementation ownership. | **Low-moderate** |
| M38 | Alex Crichton and Jason Lingle are publicly known long-time Rust contributors. These are small, mature utility crates. | Repositories are quiet and no current project funding was located; both entries are dev-only here. | **Low-moderate** |
| M39 | Simon Sapin and Servo's publishing team are public and have substantial browser/Rust ecosystem reputation. | Servo organizational continuity is visible; the crate itself is mature and quiet. | **Low-moderate** |
| M40 | Paul Colomiets (`tailhook`) is a public long-time Rust contributor; `quick-error` is mature and widely used. | The project is quiet, single-publisher, and has no funding channel located; it is dev-only here. | **Moderate** |
| M41 | David Rheinsberg is a publicly known Linux/system-software contributor and `r-efi` has very broad target-support use. | No project funding channel was located, but public standards/community review and target-only exposure reduce effective risk. | **Low-moderate** |
| M42 | `comex` and Fenhl are long-standing public contributor identities; `shlex` is extremely widely used in build tooling. | Control is limited to two owners and no project funding channel was located. | **Moderate** |
| M43 | Steven Allen is publicly named and `tempfile` has very broad ecosystem use. | Single-publisher control and no project-level funding were located; this is dev-only here. | **Moderate** |
| M44 | Amanieu d'Antras is a publicly known Rust systems/cryptography contributor with extensive reputation at stake. | Single-publisher control remains, with no project-level funding located. | **Low-moderate** |
| M45 | Paho Lurie-Gregg is publicly named and `typenum` is foundational to many numeric/crypto crates. | Single-publisher control and no project funding channel were located. | **Moderate** |
| M46 | Bastian Köcher is a publicly known Rust/Substrate contributor and the crate has broad proc-macro ecosystem use. | Single-person ownership and no project funding were located; exposure here is development-only. | **Moderate** |
| M47 | Nika Layzell is a publicly known Mozilla/Rust contributor and `synstructure` has very high ecosystem use. | Single-publisher control and no dedicated funding were located, offset by substantial public reputation. | **Low-moderate** |
| M48 | Alex Kladov and Michal Vaner are publicly known Rust maintainers and `once_cell` has foundational ecosystem exposure. | Two-owner continuity and substantial reputation are visible; no dedicated project funding was located. | **Low-moderate** |

## Complete dependency-by-dependency code triage

Every exact third-party Cargo package/version in both locks appears below,
along with the project-owned `h2` path component for code-inventory continuity.
Exposure codes are `P` (GNU/Linux production runtime or release build), `M`
(musl-only production), `T` (other target), `D` (development/test), `F`
(fuzz-only), and `B` (executes or influences build time). A family can span
several codes. “High” means deeper review priority, not a known vulnerability.
The 20 newer versions resolved only in `fuzz/Cargo.lock` were checksum-verified,
checked for archive/VCS/build anomalies, queried in OSV, and diff-triaged
against their root-lock counterparts. Only `crc32fast@1.5.6` adds a build
script, which invokes the Cargo-selected compiler for a capability probe; no
new downloader, binary payload, archive trick, or advisory match was found.

| Profile | Exact locked package/version entries | Exposure | First-pass code-quality assessment |
| --- | --- | --- | --- |
| M01 | `httpd-rs-h2@0.4.20` (project-owned path component) | P | **First-party, high-impact.** No meaningful unsafe surface; changes span frame admission, HPACK, settings, stream lifecycle, flow control, and work budgets. Formal methods and fuzzing support its ordinary first-party security review. The upstream diff is expected project work, not a dependency anomaly. |
| M02 | `cc@1.9.0`, `cc@1.11.3`, `cfg-if@1.0.5`, `find-msvc-tools@0.1.15`, `flate2@1.1.10`, `flate2@1.1.11`, `futures-core@0.3.34`, `futures-sink@0.3.34`, `hashbrown@0.17.1`, `hashbrown@0.17.2`, `jobserver@0.1.35`, `lazy_static@1.5.1`, `libc@0.2.191`, `log@0.4.34`, `log@0.4.35`, `pkg-config@0.3.34`, `regex-automata@0.4.18`, `regex-automata@0.4.19`, `regex-syntax@0.8.11`, `regex-syntax@0.8.12`, `socket2@0.6.5` | P/B, D, F | Mixed. `cc`, `find-msvc-tools`, `jobserver`, and `pkg-config` intentionally discover/execute local tools; no downloader was found. `libc` is about 134k lines of generated FFI, `hashbrown` has dense unsafe table/storage code, `socket2` is an unsafe OS boundary, and the regex crates are large parsers/automata. `flate2` is a relatively small facade over separately reviewed compression backends; the remaining macro/trait/log crates are small and conventional. The second version of each duplicated family in this row is fuzz-only; `cc@1.9.0` is in the release build graph. |
| M03 | `bytes@1.12.1`, `bytes@1.12.2`, `loom@0.7.2`, `mio@1.2.4`, `mio@1.2.5`, `slab@0.4.12`, `tokio@1.54.1`, `tokio-macros@2.7.2`, `tokio-util@0.7.20`, `tracing@0.1.44`, `tracing-core@0.1.36`, `tracing-log@0.2.0`, `tracing-subscriber@0.3.23`, `valuable@0.1.1` | P, D/B, F | **High for concurrency internals.** Tokio is roughly 149k Rust lines with substantial cfg, unsafe, scheduler, I/O, and synchronization complexity; `mio`, `bytes`, and `slab` contain important unsafe storage/OS boundaries. `tokio-macros` is compiler-executed. Tracing is large but mostly instrumentation plumbing. Loom, tracing-subscriber/log, and valuable are non-production here; the newer bytes/mio versions are fuzz-only. No illegible generated payload or unexpected I/O was found. |
| M04 | `rustls@0.23.46`, `rustls-pki-types@1.15.1`, `rustls-pki-types@1.16.0`, `rustls-webpki@0.103.16`, `rustls-webpki@0.103.17`, `tokio-rustls@0.26.6`, `webpki-roots@1.0.11`, `webpki-roots@1.0.12` | P/B, F | **High impact, good first-pass quality.** These crates implement TLS state machines, certificate/name validation, and trust-anchor data, but are mostly safe Rust with clear module boundaries and extensive tests. Rustls has a small build script, not a downloader. `webpki-roots@1.0.11` has a local audit of its trust-anchor removal delta; the newer pki/webpki/roots versions are fuzz-only and received delta triage. Protocol/parser correctness still warrants upstream audit reliance and application fuzzing. |
| M05 | `block-buffer@0.12.1`, `blowfish@0.10.0`, `chacha20@0.10.2`, `cipher@0.5.2`, `const-oid@0.10.2`, `const-oid@0.10.3`, `cpufeatures@0.3.1`, `crypto-common@0.2.2`, `digest@0.11.3`, `hybrid-array@0.4.15`, `inout@0.2.5`, `inout@0.2.6`, `md-5@0.11.0`, `zeroize@1.9.1`, `zeroize@1.9.2` | P, D, F | **High impact.** Trait crates are small, but `block-buffer`, `hybrid-array`, `inout`, `zeroize`, CPU feature detection, and ChaCha SIMD use unsafe storage/pointer/volatile operations. The implementation style is structured and recognizable, with no build-time anomaly. The newer const-oid/inout/zeroize versions are fuzz-only; their changes include correctness and memory-model fixes and received shallow delta review. MD5 and Blowfish are legacy primitives deliberately used only for compatibility; policy restrictions are essential. |
| M06 | `itoa@1.0.18`, `itoa@1.0.19`, `proc-macro2@1.0.107`, `quote@1.0.47`, `rustversion@1.0.23`, `serde@1.0.229`, `serde_core@1.0.229`, `serde_derive@1.0.229`, `syn@2.0.119`, `syn@3.0.9`, `syn@3.0.10`, `unicode-ident@1.0.27` | P/B, D, F | Mature but build-sensitive. `syn` is a large token parser and two major versions increase review surface; `serde_derive` and `rustversion` execute as procedural macros, while proc-macro2/quote/serde build scripts probe compiler capabilities. The newer itoa/syn versions are fuzz-only. No network or external downloader behavior was found. Small unsafe fast paths in itoa/syn/proc-macro2 are localized. |
| M07 | `aho-corasick@1.1.5`, `byteorder@1.5.0`, `memchr@2.8.3`, `pcre2@0.2.11`, `pcre2-sys@0.2.10` | P, D/F/B | `aho-corasick` and `memchr` are mature but have substantial unsafe SIMD/search code; `byteorder` has localized bulk-read unsafe paths. `pcre2-sys` bundles 76 native/header files and a build script around PCRE2/JIT, while `pcre2` wraps its FFI. The PCRE2 pair is only a test/fuzz oracle and is excluded from the release binary, materially reducing production exposure. |
| M08 | `getrandom@0.2.17`, `getrandom@0.4.3`, `rand@0.10.3`, `rand_core@0.10.1`, `rand_xorshift@0.5.0` | P, D/T/B | OS entropy selection and FFI in both `getrandom` versions are security-sensitive and cfg-dense; 0.4 also has a small cfg build script. The code is structured by target and no suspicious fallback was noticed. `rand`/`rand_xorshift` are development transitive entries here; `rand_core` is production. Duplicate getrandom versions enlarge target review surface. |
| M09 | `errno@0.3.14`, `errno@0.3.15`, `linux-raw-sys@0.12.1`, `rustix@1.1.6`, `wasi@0.11.1+wasi-snapshot-preview1` | P/B, T, F | **High impact OS boundary.** `linux-raw-sys` is roughly 480k lines of generated UAPI bindings; `rustix` is about 73k lines with extensive syscall/unsafe code and compiler probes. Both exact versions have local audits. The newer errno is fuzz-only; errno and WASI are smaller FFI layers. Generated output is hard to review directly; generator/upstream-header reproducibility is the relevant assurance. |
| M10 | `windows-link@0.2.1`, `windows-result@0.4.1`, `windows-sys@0.52.0`, `windows-sys@0.61.2`, `windows-targets@0.52.6`, `windows_aarch64_gnullvm@0.52.6`, `windows_aarch64_msvc@0.52.6`, `windows_i686_gnu@0.52.6`, `windows_i686_gnullvm@0.52.6`, `windows_i686_msvc@0.52.6`, `windows_x86_64_gnu@0.52.6`, `windows_x86_64_gnullvm@0.52.6`, `windows_x86_64_msvc@0.52.6` | T/B | Opaque but expected target support. The two `windows-sys` generations total hundreds of thousands of generated binding lines; architecture packages carry prebuilt import libraries and tiny link build scripts. No unexpected executable or archive trick was found. They do not enter the reviewed Linux release, but Windows support should reproduce these libraries from Microsoft's generator/toolchain. |
| M11 | `verus_builtin@0.0.0-2026-10-11-0230`, `verus_builtin_macros@0.0.0-2026-10-18-0147`, `verus_prettyplease@0.0.0-2026-09-06-0133`, `verus_state_machines_macros@0.0.0-2026-10-18-0147`, `verus_syn@0.0.0-2026-09-06-0133`, `vstd@0.0.0-2026-10-18-0147` | P/B | **High.** This boundary includes about 82k lines in the syn fork, 57k in `vstd`, procedural macros, generated/state-machine code, build scripts, and `cfg(verus_only)` differences between proof and Rust compilation. No downloader was found and the code has recognizable upstream ancestry, but size and dual semantics make shallow review weak evidence. Audit the exact Verus toolchain, macro expansion, proof erasure, and fork deltas together. |
| M12 | `alloc-no-stdlib@2.0.4`, `alloc-stdlib@0.2.4`, `brotli@8.0.4`, `brotli-decompressor@5.0.3` | P | **Medium-high.** About 200k encoder lines are attributable reference tables, both source trees match their commits, and the default library/decompressor path has no enabled unsafe or FFI. Human-written code remains C-shaped and allocator/resource-sensitive. Decompressor 5.0.3 lacks the later malformed block-switch rejection and can drive its safe streaming buffer toward an indexing panic, but httpd-rs invokes the decoder only in tests/fuzzing on its own output. Keep the resource limits and treat any decoder exposure or 6.x upgrade as a fresh review. |
| M13 | `atomic-waker@1.1.2`, `fastrand@2.5.0`, `pin-project-lite@0.2.17`, `pin-project-lite@0.2.18` | P, D, F | `atomic-waker` has small but delicate atomic/unsafe state transitions; `pin-project-lite` is macro-dense and generates pin-projection unsafe code; its newer fuzz-only version fixes an always-unsized `Drop` check. `fastrand` is a small safe non-cryptographic PRNG and dev-only here. Implementations are compact and conventional, with focused tests and no build scripts. |
| M14 | `autocfg@1.5.1`, `equivalent@1.0.3`, `indexmap@2.14.2`, `num-traits@0.2.19` | P, D/B | `equivalent` and `autocfg` are tiny; autocfg is intentionally invoked by dependent build scripts to compile probes. `indexmap` is a substantial data structure with limited unsafe and invariant-sensitive indexing, while `num-traits` has a feature/probe build script. No unusual generated or native payload was found. |
| M15 | `http@1.5.0` | P | Security-relevant parsing/container types with about 16k lines and unsafe HeaderMap/storage optimizations. The crate marks its VCS tree dirty, but all included Rust source matches the recorded commit. Review should focus on URI/header parsing and unsafe map invariants, not unexplained release content. |
| M16 | `bitflags@2.13.2` | P | Macro-heavy but compact and mature. The 2.11.1-to-2.13.2 change, including generated API and unsafe implementations, has a local cargo-vet audit. No build script or opaque payload exists. |
| M17 | `bit-set@0.11.1`, `bit-vec@0.10.1` | D | Straightforward bit-vector/set implementations with some indexing/storage unsafe and older macro style. No native/build behavior was found; development-only exposure lowers impact. A deeper review is low priority unless they move into production. |
| M18 | `proptest@1.12.0`, `rusty-fork@0.3.1`, `unarray@0.1.4` | D | Test-only. `proptest` is large and input/generator-complex but mostly safe; `rusty-fork` intentionally controls subprocesses and signals; `unarray` uses unsafe array initialization/conversion. No anomaly was found, though compromised test tooling could affect CI. |
| M19 | `borsh@1.8.1`, `borsh-derive@1.8.1` | D/B | Borsh has a small build script and a roughly 5k-line procedural macro. Serialization parsing and macro generation are conventional, with no external tool/network behavior. Non-production exposure here makes it a secondary review target. |
| M20 | `libmimalloc-sys@0.1.49`, `mimalloc@0.1.52` | M/B | **High impact, explained provenance.** A thin unsafe wrapper locally compiles 78 bundled C/header files and becomes the musl global allocator. The enabled v3 tree matches Microsoft mimalloc 3.3.2 byte-for-byte, and the Rust FFI surface is four conventional allocation operations. Later audit fixes require a feature/API-scoped delta review, but no defect was demonstrated in the locked default path. |
| M21 | `ring@0.17.14`, `untrusted@0.9.0` | P/B | **High impact, artifacts reconstructed.** `untrusted` is a small safe input cursor; `ring` is cryptographic C/Rust/assembly with extensive unsafe FFI. All 86 assembly outputs reproduce exactly, and all loadable sections, disassembly, and runtime relocations in the 17 Windows objects match a NASM 2.13.03 rebuild. The remaining review surface is the cryptographic implementation and an unpinned release-tool branch, not opaque executable content. |
| M22 | `smallvec@1.16.4` | D | **Low while development-only.** About 4k lines have concentrated unsafe storage/capacity/drop invariants. The production PCRE2 wrapper no longer uses it; the remaining default-feature path is through tracing test infrastructure. The exact delta has a local audit and the locked source includes Miri/fuzz CI definitions. Extend the audit before upgrading past 1.16.4. |
| M23 | `zlib-rs@0.6.8`, `zlib-rs@0.6.9` | P, F | **High for the production 0.6.8.** Roughly 18k Rust lines contain hundreds of unsafe/intrinsic/pointer operations in a performance-critical decompressor. Code is organized and externally audited, with no build script or blob, but malformed-stream and memory-model review remains warranted. The 0.6.9 delta is fuzz-only and received a shallow unsafe/delta scan. |
| M24 | `toml_datetime@1.1.2+spec-1.1.0`, `toml_edit@0.25.17+spec-1.1.0`, `toml_parser@1.1.5+spec-1.1.0`, `winnow@1.0.4` | D | Parser-heavy development transitive code. `winnow` is about 46k lines and `toml_parser` contains optimized unsafe scanning; the edit/datetime layers are more conventional. No build/native payload was found. Low production priority, but relevant to compromised build/config tooling. |
| M25 | `arbitrary@1.5.0`, `libfuzzer-sys@0.4.13` | F/B | Fuzz-only. `arbitrary` is a readable safe input-decoding library. `libfuzzer-sys` has a 46-line build script and bundles 53 LLVM libFuzzer C/C++/header files plus an unsafe Rust bridge. It performs local compilation, not downloading, but should remain isolated from release builds. |
| M26 | `base64@0.23.1` | P | The default `simd-unsafe` engine uses localized architecture intrinsics with scalar fallback tests. This parser/encoder code is exposed to untrusted data, so the enabled feature deserves explicit monitoring. The former safe 0.22 dependency has been removed. |
| M27 | `bcrypt@0.19.3` | P | Small, readable safe Rust composition around Blowfish, base64, and random generation. Main risks are password-cost/resource policy, legacy-format semantics, and its transitive `base64@0.23.1` unsafe SIMD, not suspicious code structure. |
| M28 | `adler2@2.0.1`, `miniz_oxide@0.9.1` | P | `adler2` is tiny checksum code; `miniz_oxide` is a moderate pure-Rust DEFLATE implementation with little enabled unsafe. Compression parsers still need malformed-input/resource testing, but no build script, native code, or opaque section was found. |
| M29 | `crc32fast@1.5.3`, `crc32fast@1.5.6` | P/B, F/B | Compact CRC code with localized SIMD/unsafe and a rustc capability probe. Both build scripts execute the local compiler only; no external download behavior was found. The newer version is fuzz-only and narrows unsafe-code allowances around its SIMD backends. |
| M30 | `simd-adler32@0.3.10` | P | About 2k lines with architecture-specific unsafe SIMD and scalar fallback. This is legible, bounded checksum code, but target-specific paths deserve differential tests. No build script or blob exists. |
| M31 | `generator@0.8.11` | D/B | **High if promoted.** It contains extensive unsafe stack/context manipulation, a build script, and 12 assembly/native files. It is dev-only through Loom, so production impact is low; CI compromise and platform-specific UB remain reasons not to broaden its use casually. |
| M32 | `cfg_aliases@0.2.2` | D | Small, readable cfg-expression/build-helper library with no unsafe, native code, or build script of its own. It influences dependent build configuration but showed no unusual behavior. |
| M33 | `convert_case@0.4.0` | P | Small safe string case-conversion code. The locked old major is pulled through proof/macro infrastructure; no unsafe or build behavior was found. Unicode/identifier semantics, not opacity, are the main correctness concern. |
| M34 | `core_detect@1.0.0` | D | Small CPU-feature detection crate with architecture-specific unsafe and inline assembly patterns. It is quiet and dev-only here; no build script or opaque binary exists. |
| M35 | `nu-ansi-term@0.50.3` | D | Conventional terminal formatting/ANSI parsing with almost no unsafe. No build/native behavior or code smell beyond output-escaping correctness; development-only. |
| M36 | `subtle@2.6.1` | P | Compact constant-time choice/equality primitives with very little unsafe. Code quality appears high, but compiler optimization and constant-time claims require specialized testing/audit rather than ordinary review. |
| M37 | `matchers@0.2.0`, `sharded-slab@0.1.7` | D | `matchers` is a small regex/tracing helper. `sharded-slab` has substantial atomic/unsafe concurrent storage code and deserves Loom/Miri scrutiny, but both are development/tracing transitive entries rather than release dependencies here. |
| M38 | `scoped-tls@1.0.1`, `wait-timeout@0.2.1` | D | Small mature OS/thread utilities with localized unsafe TLS and process-wait FFI. Repositories are quiet but code is compact and development-only; no build script or odd payload was found. |
| M39 | `fnv@1.0.7` | D | Tiny, safe hash implementation with no build behavior. It is not collision-resistant and must not be used for adversarial hash-table DoS contexts; here it is a development transitive entry. |
| M40 | `quick-error@1.2.3` | D | Small declarative error macro with no unsafe, build script, or native code. Old style and low activity are maintenance signals, not suspicious implementation signals; dev-only here. |
| M41 | `r-efi@6.0.0` | T | About 9k lines of generated/translated UEFI ABI definitions with extensive FFI unsafe declarations. Target-only and no build/native blob; generator/spec reproducibility matters more than manual line review. |
| M42 | `shlex@2.0.1` | P | Small shell-word quoting/splitting helper used by build/native tooling. Code is compact, with no build script; command-line quoting edge cases are security-relevant even though no anomalous section was found. |
| M43 | `tempfile@3.27.0` | D | Moderate filesystem/security utility with platform-specific cleanup and small unsafe boundaries. Design addresses race-resistant creation, but permissions, persistence, and cleanup deserve review when used with secrets. Development-only here. |
| M44 | `thread_local@1.1.10` | D | Compact but unsafe lifetime/drop/thread-local storage implementation. No native/build payload exists. Development-only exposure reduces priority; Miri and destructor-order testing are the appropriate deeper checks. |
| M45 | `typenum@1.20.1` | P | Roughly 40k lines of highly repetitive generated/type-level arithmetic. It is hard to read but contains no unsafe or build script in the locked archive; opacity is compile-time complexity rather than a hidden execution path. |
| M46 | `proc-macro-crate@3.5.0` | D | Small TOML/crate-name resolution helper used by procedural macros. No unsafe/build/native code, but it parses build metadata and affects generated paths. Development-only here. |
| M47 | `synstructure@0.13.2` | P | Medium-size proc-macro helper built over syn; some unsafe text occurs in generated/test contexts, with no native code or build script. Review generated impl bounds and hygiene when auditing its consumer macros. |
| M48 | `once_cell@1.21.4` | P | Mature lazy-initialization implementation with concentrated unsafe synchronization and platform backends. Code is well structured and heavily exercised, with no build script or opaque payload; memory-order/drop invariants are the deeper-review focus. |

## Existing controls that materially reduce risk

- Cargo locks exact versions and registry checksums. `deny.toml` rejects
  unknown registries and git sources, denies wildcard dependencies, checks
  RustSec/yanked status, and constrains licenses.
- `cargo vet` imports nine established audit ledgers, records five local
  audits, and treats the remaining 104 entries as explicit exemptions. The
  dependency policy test prevents the exemption ceiling or audit evidence from
  silently regressing.
- The production unsafe baseline records the exact x86_64 GNU/Linux graph and
  counts unsafe/build/native surfaces. Separate policy prevents the PCRE2 C
  oracle from entering the release graph.
- GitHub Actions are commit-pinned; Rust and auxiliary Cargo tools are version
  pinned; containers are digest-pinned; downloaded Verus/h2spec archives have
  SHA-256 pins; and Debian tooling is exact-version pinned.
- Release builds run a two-build reproducibility check without network access,
  and GitHub artifacts receive OIDC-backed build-provenance attestations.
- The independent `ring` reconstruction performed for this review ties the
  locked generated assembly and every loadable object section to published
  source. Retaining that check as automation would turn one-time evidence into
  an update gate.
- Application-level bounds and adversarial tests reduce the exploitability of
  compression, regex, protocol, and password-hashing resource behavior even
  when an upstream implementation is complex.

These controls constrain substitution and detect known problems. They do not
make a maintainer key, build script, generated object, or exempted source
intrinsically trustworthy.

## Recommended follow-up order

1. Review the mimalloc v3.3.2-to-selected-supported-tag delta against the
   enabled Linux-musl API/configuration. Add a CI assertion for the embedded
   upstream version and benchmark the `secure` feature before choosing an
   upgrade, replacement, or explicit acceptance.
2. Pin `ring-toolchain` commit
   `65116b2c43a86962d0bc135e8ce2740689c50776` (or a reviewed successor) in the
   release tooling. Automate exact assembly comparison and normalized
   PE/COFF loadable-section/relocation comparison with a pinned NASM; raw
   whole-file equality is not useful until CodeView build paths are normalized.
3. Keep untrusted Brotli decompression outside production. Backport or otherwise
   account for the malformed single-block-type switch validation before that
   boundary changes, and continue the existing metered encoder/resource
   fuzzing. Treat a decompressor 6.x upgrade as a new authorship and
   source-review decision.
4. Perform a focused source audit of `zlib-rs@0.6.8`, whose unsafe decompressor
   remains a higher code-risk surface than the now-reconstructed `ring` blobs.
5. Snapshot crates.io publisher sets in CI for at least `ring`, `untrusted`,
   `mimalloc`, `libmimalloc-sys`, `smallvec`, `brotli`, and
   `brotli-decompressor`; require review when owners change.
6. Extend the local `smallvec` cargo-vet audit before upgrading past 1.16.4,
   including the later workflow removal and broad refactor. The current
   expanded maintainer arrangement does not itself require remediation.
7. Obtain or author cargo-vet evidence for the build-executing and proc-macro
   crates before lowering the exemption ceiling, prioritizing `ring`, the
   Verus macros, `tokio-macros`, `cc`, and native sys crates.
8. Reproduce Microsoft import libraries and generated Linux/Windows bindings
   when those targets become release commitments. Keep native oracle/fuzzer
   crates isolated from production dependency resolution.
9. Audit the separately pinned documentation and Wagtail deployment-fixture
   Python ecosystems in their own threat model; they were deliberately not
   counted as shipping Cargo dependencies in this pass.

## Evidence sources

Primary evidence for exact code content is the two lockfiles, the corresponding
crates.io archives, their `.cargo_vcs_info.json` records, upstream commit
archives for the two dirty publications, and the local files
[`supply-chain/config.toml`](../supply-chain/config.toml),
[`supply-chain/audits.toml`](../supply-chain/audits.toml),
[`docs/dependency-unsafe.json`](../docs/dependency-unsafe.json), and
[`deny.toml`](../deny.toml).

The `ring` reconstruction reran every packaged PerlAsm generator from recorded
commit `2723abbca9e83347d82b056d5b239c6604f786df`. The 17 objects were rebuilt
from the resulting `.asm` using NASM 2.13.03 source archive SHA-256
`812ecfb0dcbc5bd409aaa8f61c7de94c5b8752a7b00c632883d15b2ed6452573`.
Comparison covered all `.text`, `.rdata`, `.pdata`, and `.xdata` sections plus
disassembly and runtime relocations; raw-file differences were traced to
CodeView source paths and consequent layout offsets.

Public stewardship and vulnerability evidence consulted includes:

- crates.io package metadata and owner lists for every registry package;
- the [OSV query API](https://osv.dev/) for exact-version advisory matching;
- [OpenSSF Scorecard](https://scorecard.dev/) results as a supporting signal,
  not a substitute for source or governance review;
- Rustls's [Rust Foundation governance
  announcement](https://rustls.dev/blog/2025-09-03-rustls-and-rust-foundation/)
  and [ten-year project
  retrospective](https://rustls.dev/blog/2026-09-08-a-decade-of-rustls/);
- the withdrawn [ring maintenance advisory
  RUSTSEC-2025-0007](https://rustsec.org/advisories/RUSTSEC-2025-0007.html);
- `ring`'s recorded [source
  commit](https://github.com/briansmith/ring/commit/2723abbca9e83347d82b056d5b239c6604f786df),
  the [ring-toolchain
  commit](https://github.com/briansmith/ring-toolchain/commit/65116b2c43a86962d0bc135e8ce2740689c50776),
  and the [NASM 2.13.03 source
  release](https://www.nasm.us/pub/nasm/releasebuilds/2.13.03/);
- smallvec's public [maintainer-expansion
  discussion](https://github.com/smallvec/smallvec/issues/395);
- Tokio's description of [paid contributor and sponsor
  support](https://tokio.rs/blog/2021-04-welcome-alice);
- RustCrypto's [security policy and volunteer-maintenance
  statement](https://github.com/RustCrypto/traits/blob/master/SECURITY.md);
- the Rust Foundation [maintainer-fund
  RFC](https://github.com/rust-lang/rfcs/blob/master/text/3931-rfmf-rust-foundation-maintainer-fund.md);
- the Bytecode Alliance [project roster](https://bytecodealliance.org/projects),
  Trifecta Foundation's [zlib-rs project
  description](https://trifectatech.org/projects/zlib-rs/), and the Verus
  team's [SOSP artifact page](https://verus-lang.github.io/paper-sosp24-artifact/);
- Google's [Brotli 1.1.0 reference
  source](https://github.com/google/brotli/tree/v1.1.0), the Rust decoder's
  [CVE-related validation
  fix](https://github.com/dropbox/rust-brotli-decompressor/commit/cc7ee0edae39870daa7f0d7c1456e113b759e752),
  [CVE-2026-111497](https://www.cve.org/CVERecord?id=CVE-2026-111497), and the
  rust-brotli-decompressor [6.x policy
  statement](https://github.com/dropbox/rust-brotli-decompressor/blob/6.4.0/README.md);
- the Rust mimalloc [wrapper repository](https://github.com/purpleprotocol/mimalloc_rust)
  and Microsoft mimalloc [3.3.2 source](https://github.com/microsoft/mimalloc/tree/v3.3.2),
  [3.4.1](https://github.com/microsoft/mimalloc/releases/tag/v3.4.1),
  [3.4.4](https://github.com/microsoft/mimalloc/releases/tag/v3.4.4), and
  [3.7.1](https://github.com/microsoft/mimalloc/releases/tag/v3.7.1) releases.

Repository funding files and project sponsor pages were checked where present.
Missing funding metadata was treated as unknown rather than proof of weak
project health.

## Limits and review trigger

This pass did not inspect every historical maintainer interaction, private
security report, signing key, organization role, or line of dependency code.
crates.io owners establish publication authority but do not reveal all source
hosting permissions. Public silence cannot prove that maintainers are not
under pressure. Download counts and Scorecards can show exposure and process,
but neither establishes intent.

Repeat this review whenever a lockfile changes, a publisher set changes, a
listed governance/maintenance event occurs, the musl allocator changes, or a
new release target begins shipping. A dependency update is new evidence; the
ratings above do not automatically transfer to a new version.
