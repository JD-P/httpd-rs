# Apache-derived fuzzing warrants

The Apache source inventory is an evidence source, not a product roadmap.
Finding a directive, hook, provider, filter, configuration callback, or test in
Apache does not authorize implementing it in Vapache.

## The three artifacts

`apache-source-manifest.json` is a mechanically generated observation of the
checksum-pinned Apache 2.4.69 source release. It records balanced `AP_INIT_*`
directive registrations, `ap_hook_*` registrations, providers, filters,
configuration create/merge callbacks, every runtime source file under
`include/`, `server/`, `modules/`, and `os/`, and every test file shipped in
the source tarball. Apache's separate `support/` programs and independently
versioned `srclib/` dependencies are not treated as httpd request-path source.
The manifest also inventories every file in a
commit-pinned `apache-httpd-test` repository and its pinned `Apache-Test`
submodule.

The source registration scan is intentionally build-conservative: it may
observe registrations inside preprocessor branches that the selected binary
does not enable. That is useful evidence, not a compatibility claim. The
instrumented build described below supplies the exact-build reachability view.

`apache-warrant-policy.json` is the human-reviewed boundary. It contains the
exact source and binary oracle pin, the modules loaded by the differential
harnesses, the Apache-derived state-space families, deliberately unsupported
families, non-Apache warrants for every fuzz target, and the only directives
for which this ledger makes a compatibility claim.

`apache-warrant-ledger.json` is generated from those two inputs. Every source
item receives one of these dispositions:

- `supported-subset`: an explicit, evidence-bearing compatibility claim;
- `deliberately-stricter`: an explicit security refinement;
- `deliberately-unsupported`: part of a reviewed exclusion such as WebDAV,
  Digest/LDAP/DBM authentication, SSI, or an unsupported proxy protocol;
- `warrant-source-only`: relevant source that can warrant tests but makes no
  support claim;
- `outside-claimed-surface`: observed Apache code outside Vapache's claimed
  compatibility surface.

The default is always `outside-claimed-surface`. There is no default-supported
category.

Even an explicit directive claim covers only that directive's entry point.
Its accepted syntax, contexts, phase behavior, and semantics remain bounded by
the cited repository evidence; naming `RewriteRule`, for example, is not a
claim to every Apache rewrite feature or flag.

For directives, the ledger also records the relationship with Vapache's sealed
registry: explicit compatibility claim, explicit fail-closed entry, recognized
without a support claim, or unknown/fail-closed. Recognition is not support.
This makes the default-deny boundary measurable: in the current pin, 331 of
Apache's 673 unique source directives are absent from Vapache's registry and
therefore reject as unknown; only the separately listed claims assert any
compatible subset.

## Drift and support-expansion gates

The generated manifest has a content digest. The policy separately records the
digest it has reviewed. Any source change or extractor change therefore fails
the normal quality gate until its diff is examined and the new digest is
explicitly acknowledged. Acknowledging an inventory digest does not change any
compatibility claim.

Adding a compatibility claim requires a named family and repository evidence.
The validator rejects claims for directives absent from the pinned Apache
source, missing evidence, claims that overlap a deliberately unsupported
directive, fuzz targets without a warrant or semantic census, in-scope
state-space families without a fuzz target, drift in the differential module
set, and stale generated ledgers.

The Vapache server is not modified by the extractor or generator. Unsupported
Apache states must continue to reject at configuration load or at the typed
sink boundary. This inventory must never be used to generate permissive parser
arms, no-op directive handling, or module-loading behavior.

## Reproduce the inventory

Run:

```sh
tests/apache_source_inventory.sh
```

The script downloads the pinned archive, verifies its SHA-256 digest, extracts
it into a temporary directory, reruns the extractor, and compares the result
with the checked-in manifest.

To inspect a new Apache release or extractor result, run:

```sh
tests/apache_source_inventory.sh --update
```

That mode writes only the observational manifest. It deliberately does not
update the policy's acknowledged digest or add compatibility claims. Review
the source-item, component, directive, hook, and upstream-test differences;
then edit the policy explicitly and regenerate the ledger:

```sh
python3 tests/apache_warrant.py --write-ledger
python3 tests/apache_warrant.py --summary
```

## What the ledger establishes

The checked-in ledger establishes closure over the extracted registrations and
over the repository's fuzz-target list. It answers which authority warrants
each target and which named state dimensions that target is intended to
explore. It also establishes that the Apache binary oracle has the pinned
version and all modules required by the differential harnesses when
`--check-binary` runs in the pre-adversarial gate.

It does not prove that all value equivalence classes, hook interactions, or
source branches have been exercised. The weekly
`tests/apache_source_coverage.sh` job builds the pinned Apache source with GCC
coverage, drives the existing configuration and end-to-end differential corpus
through that binary, and groups covered and uncovered branches by warrant
family. Each family has a checked-in minimum covered-branch ratchet. A family
with no instrumented file, covered line/branch, or a count below its ratchet
fails the job; the detailed uncovered-branch sample is retained as a CI
artifact and is the queue for new semantic families.

The external `apache-httpd-test` suite is inventoried, not automatically
adopted as a VApache compatibility suite. Mapping its cases to supported,
deliberately stricter, and deliberately unsupported behavior remains an
independent triage queue. A test's presence cannot be converted into a support
claim or waived by increasing libFuzzer execution time.
