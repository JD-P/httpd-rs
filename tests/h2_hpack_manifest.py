#!/usr/bin/env python3
"""Describe and verify every file in the downloaded HPACK test corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
H2_VERSION = "0.4.20"
ARCHIVE_URL = (
    "https://codeload.github.com/hyperium/h2/"
    f"tar.gz/refs/tags/v{H2_VERSION}"
)
ARCHIVE_SHA256 = "5ac48fb14ff4f87fcb923a1ffc05436189ac4d9a660bcc788c3956b6edcc9fa2"
ARCHIVE_MAX_BYTES = 8 * 1024 * 1024
ARCHIVE_PREFIX = f"h2-{H2_VERSION}/fixtures/hpack/"
TREE_SHA256 = "44bfb809ee1941a929f86b22c002a5a171594c2e3217619ad98f59440d726bab"
TREE_FILES = 418
TREE_BYTES = 60_014_073
MANIFEST_PATH = ROOT / "tests/h2_hpack_fixture_manifest.json"


FAMILIES: dict[str, dict[str, object]] = {
    "raw-data": {
        "role": "source_headers",
        "implementation": "http2/http_samples converted to ordered JSON stories",
        "static_table": None,
        "dynamic_table": None,
        "huffman": None,
        "strategy": "Unencoded request/response header sequences shared by every encoder family.",
        "substitute": "Provide ordered request and response header sets with shared compression context, repeated values, realistic large stories, and both pseudo-headers and ordinary fields.",
    },
    "go-hpack": {
        "role": "encoded_headers",
        "implementation": "github.com/Jxck/hpack (Go)",
        "static_table": False,
        "dynamic_table": False,
        "huffman": True,
        "strategy": "Literal fields with Huffman strings, no static/dynamic lookup, and an emptied reference set.",
    },
    "haskell-http2-linear": {
        "role": "encoded_headers",
        "implementation": "Haskell http2 Linear encoder",
        "static_table": True,
        "dynamic_table": True,
        "huffman": False,
        "strategy": "Static and dynamic table lookup without Huffman strings.",
    },
    "haskell-http2-linear-huffman": {
        "role": "encoded_headers",
        "implementation": "Haskell http2 LinearH encoder",
        "static_table": True,
        "dynamic_table": True,
        "huffman": True,
        "strategy": "Static and dynamic table lookup with Huffman strings.",
    },
    "haskell-http2-naive": {
        "role": "encoded_headers",
        "implementation": "Haskell http2 Naive encoder",
        "static_table": False,
        "dynamic_table": False,
        "huffman": False,
        "strategy": "Literal fields without tables or Huffman strings.",
    },
    "haskell-http2-naive-huffman": {
        "role": "encoded_headers",
        "implementation": "Haskell http2 NaiveH encoder",
        "static_table": False,
        "dynamic_table": False,
        "huffman": True,
        "strategy": "Literal fields without tables, with Huffman strings.",
    },
    "haskell-http2-static": {
        "role": "encoded_headers",
        "implementation": "Haskell http2 Static encoder",
        "static_table": True,
        "dynamic_table": False,
        "huffman": False,
        "strategy": "Static table lookup without a dynamic table or Huffman strings.",
    },
    "haskell-http2-static-huffman": {
        "role": "encoded_headers",
        "implementation": "Haskell http2 StaticH encoder",
        "static_table": True,
        "dynamic_table": False,
        "huffman": True,
        "strategy": "Static table lookup and Huffman strings without a dynamic table.",
    },
    "nghttp2": {
        "role": "encoded_headers",
        "implementation": "nghttp2",
        "static_table": True,
        "dynamic_table": True,
        "huffman": "conditional",
        "strategy": "nghttp2 default strategy; Huffman is used only when shorter and selected fields are never indexed.",
    },
    "nghttp2-16384-4096": {
        "role": "encoded_headers",
        "implementation": "nghttp2",
        "static_table": True,
        "dynamic_table": True,
        "huffman": "conditional",
        "strategy": "nghttp2 encoding with an explicit 16,384-byte table-size event; exercises a non-default dynamic-table bound.",
    },
    "nghttp2-change-table-size": {
        "role": "encoded_headers",
        "implementation": "nghttp2",
        "static_table": True,
        "dynamic_table": True,
        "huffman": "conditional",
        "strategy": "nghttp2 encoding with explicit 1,365- and 2,730-byte table-size changes inside each story.",
    },
    "node-http2-hpack": {
        "role": "encoded_headers",
        "implementation": "node-http2-hpack",
        "static_table": True,
        "dynamic_table": True,
        "huffman": "implementation-default",
        "strategy": "Independent Node.js HPACK encoder output with an explicit initial 4,096-byte table size.",
    },
    "python-hpack": {
        "role": "encoded_headers",
        "implementation": "Python hpack 2.3.0",
        "static_table": True,
        "dynamic_table": True,
        "huffman": "implementation-default",
        "strategy": "Independent output from Python hpack version 2.3.0.",
    },
}


SUPPORT_FILES = {
    ".travis.yml": "Historical CI recipe for the original hpack-test-case repository; not consumed by httpd-rs tests.",
    "README.md": "Original corpus format, provenance, interoperability procedure, contributors, and MIT license declaration.",
    "genratiotbl.py": "Python utility that compares compressed wire bytes with uncompressed header bytes and emits an RST table.",
    "util/gen_ratio.py": "Python utility that computes the same per-family compression ratios and emits a Markdown table.",
}


class ManifestError(RuntimeError):
    pass


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def header_identity(cases: list[dict[str, object]]) -> str:
    headers = [case.get("headers") for case in cases]
    encoded = json.dumps(
        headers,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return digest_bytes(encoded)


def json_record(
    path: Path,
    relative: str,
    document: dict[str, object],
    raw_contexts: dict[str, str | None],
) -> dict[str, object]:
    family = relative.split("/", 1)[0]
    story_name = path.name
    cases = document.get("cases")
    if not isinstance(cases, list) or not all(isinstance(case, dict) for case in cases):
        raise ManifestError(f"{relative}: cases is not an object array")
    typed_cases: list[dict[str, object]] = cases
    story = int(path.stem.removeprefix("story_"))
    context = document.get("context") if family == "raw-data" else raw_contexts.get(story_name)
    fields = 0
    header_bytes = 0
    wire_bytes = 0
    table_sizes: set[int] = set()
    for case in typed_cases:
        headers = case.get("headers")
        if not isinstance(headers, list):
            raise ManifestError(f"{relative}: headers is not an array")
        fields += len(headers)
        for field in headers:
            if not isinstance(field, dict) or len(field) != 1:
                raise ManifestError(f"{relative}: malformed header field")
            name, value = next(iter(field.items()))
            if not isinstance(name, str) or not isinstance(value, str):
                raise ManifestError(f"{relative}: non-string header field")
            header_bytes += len(name.encode()) + len(value.encode())
        wire = case.get("wire")
        if wire is not None:
            if not isinstance(wire, str) or len(wire) % 2:
                raise ManifestError(f"{relative}: malformed wire hex")
            wire_bytes += len(wire) // 2
        table_size = case.get("header_table_size")
        if table_size is not None:
            if not isinstance(table_size, int):
                raise ManifestError(f"{relative}: invalid table size")
            table_sizes.add(table_size)
    role = "source_header_story" if family == "raw-data" else "encoded_header_story"
    description = (
        f"Raw {context or 'unspecified-context'} header story {story:02d}; source input for corresponding encoder-family stories."
        if family == "raw-data"
        else f"Story {story:02d} encoded by the {family} family from raw-data/{story_name}; cases share one HPACK compression context."
    )
    data = path.read_bytes()
    record: dict[str, object] = {
        "path": relative,
        "bytes": len(data),
        "sha256": digest_bytes(data),
        "media_type": "application/json",
        "role": role,
        "description": description,
        "family": family,
        "story": story,
        "context": context,
        "cases": len(typed_cases),
        "header_fields": fields,
        "header_bytes": header_bytes,
        "wire_bytes": wire_bytes,
        "explicit_header_table_sizes": sorted(table_sizes),
        "semantic_headers_sha256": header_identity(typed_cases),
        "used_by_fixture_tests": family != "raw-data",
    }
    if family != "raw-data":
        record["source_story"] = f"raw-data/{story_name}"
        upstream_description = document.get("description")
        if isinstance(upstream_description, str):
            record["upstream_description"] = upstream_description
    return record


def build_manifest(root: Path) -> dict[str, object]:
    raw_contexts: dict[str, str | None] = {}
    for path in sorted((root / "raw-data").glob("story_*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        context = document.get("context")
        raw_contexts[path.name] = context if isinstance(context, str) else None

    records: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix()):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if path.suffix == ".json" and path.name.startswith("story_"):
            document = json.loads(path.read_text(encoding="utf-8"))
            record = json_record(path, relative, document, raw_contexts)
        else:
            data = path.read_bytes()
            description = SUPPORT_FILES.get(relative)
            if description is None:
                raise ManifestError(f"{relative}: downloaded support file lacks a description")
            record = {
                "path": relative,
                "bytes": len(data),
                "sha256": digest_bytes(data),
                "media_type": "text/markdown"
                if path.suffix == ".md"
                else "text/x-python"
                if path.suffix == ".py"
                else "text/yaml",
                "role": "corpus_documentation"
                if path.name == "README.md"
                else "corpus_utility",
                "description": description,
                "used_by_fixture_tests": False,
            }
        records.append(record)

    by_path = {record["path"]: record for record in records}
    for record in records:
        source = record.get("source_story")
        if not isinstance(source, str):
            continue
        raw = by_path.get(source)
        if raw is None or record["semantic_headers_sha256"] != raw["semantic_headers_sha256"]:
            raise ManifestError(f"{record['path']}: encoded headers differ from {source}")

    family_records: dict[str, dict[str, object]] = {}
    for name, metadata in FAMILIES.items():
        members = [record for record in records if record.get("family") == name]
        family_records[name] = {
            **metadata,
            "files": len(members),
            "bytes": sum(int(record["bytes"]) for record in members),
            "cases": sum(int(record["cases"]) for record in members),
            "wire_bytes": sum(int(record["wire_bytes"]) for record in members),
        }
        if name != "raw-data":
            family_records[name]["substitute"] = (
                "Encode the corresponding raw-data stories with an independent RFC 7541 implementation preserving this family's table, Huffman, and table-size-event strategy; require every resulting block to decode to the recorded semantic header digest."
            )

    return {
        "schema": 1,
        "purpose": "Reconstruct or replace the HPACK interoperability evidence without trusting availability of the original download host.",
        "source": {
            "archive_url": ARCHIVE_URL,
            "archive_sha256": ARCHIVE_SHA256,
            "archive_prefix": ARCHIVE_PREFIX,
            "h2_version": H2_VERSION,
            "h2_import_commit": "d3e4e036e3b97af3caa80423cea0a227c61e53de",
            "h2_fixture_git_tree": "a015651742269d2749a97d52499797c434c20abe",
            "original_repository": "https://github.com/http2jp/hpack-test-case",
            "closest_original_commit": "b2a1664b43dc520a4bbff2e7db1b7e7af4fb43f4",
            "closest_original_note": "The h2 import matches this original corpus revision except for a one-byte correction in go-hpack/story_06.json; the per-file hashes below are authoritative.",
            "original_header_source": "https://github.com/http2/http_samples",
            "license": "MIT",
            "tree_sha256": TREE_SHA256,
            "tree_files": TREE_FILES,
            "tree_bytes": TREE_BYTES,
        },
        "reconstruction": {
            "exact": "Retrieve any copy of the h2 v0.4.20 fixture subtree and require every per-file digest plus the canonical tree digest to match.",
            "raw_story_substitute": "Create ordered request/response header stories with the recorded case counts and contexts. Preserve each story's compression context across its cases and record a new semantic_headers_sha256.",
            "encoded_story_substitute": "For every raw story, generate RFC 7541 blocks with several independent encoders spanning literal/static/dynamic indexing, Huffman on/off, and table-size changes. Decoder acceptance is valid only when every block yields the source story's ordered headers.",
            "minimum_diversity": "Retain at least one family for each table/Huffman combination represented below plus an independent implementation exercising dynamic-table size updates.",
            "nonessential_files": "README.md and the ratio utilities document provenance and analysis; .travis.yml is historical. They may be replaced by equivalent documentation/tooling without weakening decoder interoperability coverage.",
        },
        "families": family_records,
        "files": records,
    }


def load_committed_manifest() -> dict[str, object]:
    try:
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ManifestError(f"cannot read {MANIFEST_PATH}: {error}") from error


def check_manifest(root: Path) -> None:
    actual = build_manifest(root)
    expected = load_committed_manifest()
    if actual != expected:
        raise ManifestError(
            "downloaded HPACK inventory differs from the committed reconstruction manifest; "
            "review it and run tests/h2_hpack_manifest.py --write"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT / f"target/test-fixtures/h2-v{H2_VERSION}/hpack",
    )
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        manifest = build_manifest(args.root)
        if args.write:
            MANIFEST_PATH.write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(f"wrote {MANIFEST_PATH.relative_to(ROOT)} ({len(manifest['files'])} files)")
        else:
            check_manifest(args.root)
            print(f"HPACK reconstruction manifest OK ({len(manifest['files'])} files)")
    except (ManifestError, OSError, json.JSONDecodeError, ValueError) as error:
        print(f"h2-hpack-manifest: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
