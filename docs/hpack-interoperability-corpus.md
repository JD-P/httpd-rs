---
doc_type: reference
audience: contributor
status: stable
---

# HPACK interoperability corpus

httpd-rs tests its vendored h2 fork against the HPACK interoperability corpus
that accompanied h2 0.4.20. The corpus is downloaded during the quality job
rather than committed: its archive is about 5.9 MB, while its extracted JSON is
about 60 MB.

The download is not trusted by location. `tests/h2_hpack_fixtures.py` limits
its size, verifies the pinned archive SHA-256 before opening it, rejects links
and unsafe archive paths, and verifies a second canonical digest over all 418
extracted files. Generated data stays below `target/` and `fixtures/**` remains
excluded from the published h2 crate.

## What the files mean

The 32 files under `raw-data/` are ordered request or response header stories.
Cases in one story share a compression context. The other 382 JSON files are
the same stories encoded by twelve encoder families produced by five
independent implementations:

| Family | Tables | Huffman | Reconstruction role |
| --- | --- | --- | --- |
| `go-hpack` | neither | yes | literal-only independent Go output |
| `haskell-http2-naive*` | neither | no/yes | literal controls for Huffman off/on |
| `haskell-http2-static*` | static only | no/yes | static-index controls |
| `haskell-http2-linear*` | static and dynamic | no/yes | stateful dynamic-table controls |
| `nghttp2` | static and dynamic | conditional | independent production implementation |
| `nghttp2-16384-4096` | static and dynamic | conditional | non-default 16,384-byte table event |
| `nghttp2-change-table-size` | static and dynamic | conditional | in-context 1,365/2,730-byte size changes |
| `node-http2-hpack` | static and dynamic | implementation default | independent Node.js output |
| `python-hpack` | static and dynamic | implementation default | Python hpack 2.3.0 output |

Every encoded record identifies its corresponding raw story. The committed
manifest requires the ordered header values to have the same semantic digest,
so a wire fixture cannot be silently paired with different expected headers.
The four remaining files are the original README, historical CI recipe, and
two compression-ratio utilities; they are described individually too.

## Reconstruction and substitution

[`tests/h2_hpack_fixture_manifest.json`](https://github.com/JD-P/httpd-rs/blob/main/tests/h2_hpack_fixture_manifest.json)
is the authoritative inventory. It records, for every downloaded file, its
path, byte length, SHA-256, purpose, family, story/context, case and field
counts, wire size, table-size events, and semantic header digest. It also
records the h2 import commit/tree, closest original `hpack-test-case` revision,
license, and upstream source relationships.

If the h2 archive disappears, an exact copy can be accepted by matching the
per-file and canonical tree hashes. If no exact copy survives, a substitute
corpus can be generated from the raw stories with independent RFC 7541
encoders. A substitute should preserve all table/Huffman combinations above,
shared compression context, explicit table-size changes, and the rule that
every encoded block decodes to the source story's ordered headers. New hashes
must then be reviewed and committed; the fetcher never accepts a substitute
implicitly.

Generate or verify the inventory with:

```sh
python3 tests/h2_hpack_fixtures.py --fetch-only
python3 tests/h2_hpack_manifest.py
```

`python3 tests/h2_hpack_fixtures.py` additionally runs all 382 interoperability
tests. The quality workflow performs this complete operation.
