#!/usr/bin/env python3
"""Enforce the exact, contract-annotated Rust unsafe boundary.

Production `httpd-rs` builds forbid unsafe code. The sole exception is the
`httpd-rs-os` crate, where every unsafe block has a unique SAFETY[OSnnn]
contract. Test-only probes in the server are also hashed exactly so they
cannot grow or change under the old line-count budget.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs/unsafe-baseline.json"
CONTRACT = re.compile(r"SAFETY\[(OS\d{3})\]")
UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
UNSAFE_TOKEN = re.compile(r"\bunsafe\b")
RAW_STRING = re.compile(r"(?:br|r)(?P<hashes>#{0,255})\"")


def mask_non_code(source: str) -> str:
    """Replace comments and literals with spaces while preserving offsets."""
    out = list(source)
    length = len(source)
    index = 0
    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = length if end < 0 else end
            for offset in range(index, end):
                out[offset] = " "
            index = end
            continue
        if source.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            for offset in range(start, index):
                if out[offset] != "\n":
                    out[offset] = " "
            continue

        raw = None
        if source[index] in {"b", "r"}:
            raw = RAW_STRING.match(source, index)
        if raw:
            start = index
            hashes = raw.group("hashes")
            index = raw.end()
            end_marker = '"' + hashes
            end = source.find(end_marker, index)
            index = length if end < 0 else end + len(end_marker)
            for offset in range(start, index):
                if out[offset] != "\n":
                    out[offset] = " "
            continue

        quote_index = index + 1 if source.startswith('b"', index) else index
        if quote_index < length and source[quote_index] == '"':
            start = index
            index = quote_index + 1
            while index < length:
                if source[index] == "\\":
                    index += 2
                elif source[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            for offset in range(start, min(index, length)):
                if out[offset] != "\n":
                    out[offset] = " "
            continue

        # A Rust character/byte-character literal has a closing quote close
        # by; a lifetime such as 'a does not and must remain code.
        char_start = index + 1 if source.startswith("b'", index) else index
        if char_start < length and source[char_start] == "'":
            cursor = char_start + 1
            if cursor < length and source[cursor] == "\\":
                cursor += 2
                while cursor < min(length, char_start + 12) and source[cursor] != "'":
                    cursor += 1
            else:
                cursor += 1
            if cursor < length and source[cursor] == "'":
                end = cursor + 1
                for offset in range(index, end):
                    out[offset] = " "
                index = end
                continue
        index += 1
    return "".join(out)


def unsafe_blocks(path: Path) -> list[tuple[int, str, str]]:
    source = path.read_text(encoding="utf-8")
    masked = mask_non_code(source)
    blocks: list[tuple[int, str, str]] = []
    covered_tokens: set[int] = set()
    for match in UNSAFE_BLOCK.finditer(masked):
        covered_tokens.add(match.start())
        opening = masked.find("{", match.start(), match.end())
        depth = 0
        end = -1
        for index in range(opening, len(masked)):
            if masked[index] == "{":
                depth += 1
            elif masked[index] == "}":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        if end < 0:
            raise SystemExit(f"unsafe-inventory: unclosed block in {path}")
        line = source.count("\n", 0, match.start()) + 1
        blocks.append((line, source[match.start():end], source[:match.start()]))

    unclassified = [
        source.count("\n", 0, match.start()) + 1
        for match in UNSAFE_TOKEN.finditer(masked)
        if match.start() not in covered_tokens
    ]
    if unclassified:
        relative = path.relative_to(ROOT)
        raise SystemExit(
            f"unsafe-inventory: non-block unsafe construct in {relative}: {unclassified}"
        )
    return blocks


def block_hash(block: str) -> str:
    return hashlib.sha256(block.encode("utf-8")).hexdigest()


def inventory() -> dict[str, object]:
    contracts: dict[str, dict[str, object]] = {}
    for path in sorted((ROOT / "crates/os/src").rglob("*.rs")):
        relative = str(path.relative_to(ROOT))
        for line, block, prefix in unsafe_blocks(path):
            nearby = "\n".join(prefix.splitlines()[-4:])
            matches = CONTRACT.findall(nearby)
            if len(matches) != 1:
                raise SystemExit(
                    f"unsafe-inventory: {relative}:{line} needs one nearby SAFETY[OSnnn] contract"
                )
            contract = matches[0]
            if contract in contracts:
                raise SystemExit(f"unsafe-inventory: duplicate contract {contract}")
            contract_text = nearby[nearby.rfind("// SAFETY["):].strip()
            contracts[contract] = {
                "path": relative,
                "line": line,
                "contract_sha256": hashlib.sha256(
                    contract_text.encode("utf-8")
                ).hexdigest(),
                "block_sha256": block_hash(block),
            }

    test_blocks: dict[str, list[dict[str, object]]] = {}
    server_paths = list((ROOT / "crates/server/src").rglob("*.rs"))
    server_paths.extend((ROOT / "crates/server/tests").rglob("*.rs"))
    for path in sorted(server_paths):
        blocks = unsafe_blocks(path)
        if not blocks:
            continue
        counter = Counter(block_hash(block) for _, block, _ in blocks)
        test_blocks[str(path.relative_to(ROOT))] = [
            {"sha256": digest, "count": count}
            for digest, count in sorted(counter.items())
        ]

    return {
        "schema": 2,
        "production_boundary": "crates/os",
        "contracts": dict(sorted(contracts.items())),
        "server_test_blocks": test_blocks,
    }


def verify_compile_guards() -> None:
    server_lib = (ROOT / "crates/server/src/lib.rs").read_text(encoding="utf-8")
    server_main = (ROOT / "crates/server/src/main.rs").read_text(encoding="utf-8")
    if "#![cfg_attr(not(test), forbid(unsafe_code))]" not in server_lib:
        raise SystemExit("unsafe-inventory: production server unsafe forbid is missing")
    if "#![forbid(unsafe_code)]" not in server_main:
        raise SystemExit("unsafe-inventory: server binary unsafe forbid is missing")
    for manifest in (
        ROOT / "crates/pcre2/Cargo.toml",
        ROOT / "crates/verified/Cargo.toml",
        ROOT / "vendor/h2-0.4.20/Cargo.toml",
    ):
        text = manifest.read_text(encoding="utf-8")
        if "unsafe_code" not in text or "forbid" not in text:
            raise SystemExit(
                f"unsafe-inventory: {manifest.relative_to(ROOT)} must forbid unsafe code"
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="replace the reviewed baseline")
    args = parser.parse_args()
    verify_compile_guards()
    current = inventory()
    if args.write:
        BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        print(
            "unsafe-inventory: wrote "
            f"{len(current['contracts'])} production contracts"
        )
        return
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    if current != baseline:
        raise SystemExit(
            "unsafe-inventory: FAIL: exact contract/hash inventory changed; "
            "review the boundary and run tests/unsafe_inventory.py --write"
        )
    test_count = sum(
        item["count"]
        for values in current["server_test_blocks"].values()
        for item in values
    )
    print(
        "unsafe-inventory: pass "
        f"({len(current['contracts'])} audited production contracts, "
        f"{test_count} exact test-only blocks)"
    )


if __name__ == "__main__":
    main()
