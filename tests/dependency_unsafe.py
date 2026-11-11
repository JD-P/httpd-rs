#!/usr/bin/env python3
"""Ratchet unsafe and native-code exposure in the production dependency graph."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs/dependency-unsafe.json"
UNSAFE = re.compile(r"\bunsafe\b")
UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
UNSAFE_DECL = re.compile(r"\bunsafe\s+(?:fn|impl|trait)\b")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
NATIVE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".s", ".asm"}
SKIP_PARTS = {"target", "tests", "test", "examples", "benches", "fuzz"}


def metadata() -> dict[str, object]:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--filter-platform",
            "x86_64-unknown-linux-gnu",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return json.loads(result.stdout)


def production_ids(data: dict[str, object]) -> set[str]:
    packages = {package["name"]: package["id"] for package in data["packages"]}
    root = packages.get("vapached")
    if root is None:
        raise SystemExit("dependency-unsafe: vapached package is missing")
    nodes = {node["id"]: node for node in data["resolve"]["nodes"]}
    found: set[str] = set()
    pending = [root]
    while pending:
        package_id = pending.pop()
        if package_id in found:
            continue
        found.add(package_id)
        for dependency in nodes[package_id]["deps"]:
            kinds = dependency.get("dep_kinds", [])
            if any(kind.get("kind") != "dev" for kind in kinds):
                pending.append(dependency["pkg"])
    return found


def source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    source = root / "src"
    if source.is_dir():
        files.extend(source.rglob("*.rs"))
    build = root / "build.rs"
    if build.is_file():
        files.append(build)
    return sorted(set(files))


def native_files(root: Path) -> list[str]:
    found = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in NATIVE_SUFFIXES:
            continue
        relative = path.relative_to(root)
        if SKIP_PARTS.isdisjoint(relative.parts):
            found.append(str(relative))
    return sorted(found)


def inspect(package: dict[str, object]) -> dict[str, object]:
    manifest = Path(package["manifest_path"])
    root = manifest.parent
    unsafe_tokens = 0
    unsafe_blocks = 0
    unsafe_declarations = 0
    rust_files = source_files(root)
    for path in rust_files:
        source = path.read_text(encoding="utf-8", errors="replace")
        # This is a deliberately conservative syntactic exposure metric, not
        # a semantic Rust parser. Remove ordinary comments cheaply; strings
        # may over-count a mention but can never hide a changed package from
        # the exact baseline review.
        code = BLOCK_COMMENT.sub("", source)
        code = "\n".join(line.split("//", 1)[0] for line in code.splitlines())
        unsafe_tokens += len(UNSAFE.findall(code))
        unsafe_blocks += len(UNSAFE_BLOCK.findall(code))
        unsafe_declarations += len(UNSAFE_DECL.findall(code))
    native = native_files(root)
    return {
        "unsafe_tokens": unsafe_tokens,
        "unsafe_blocks": unsafe_blocks,
        "unsafe_declarations": unsafe_declarations,
        "rust_files": len(rust_files),
        "build_script": (root / "build.rs").is_file(),
        "native_files": len(native),
    }


def inventory() -> dict[str, object]:
    data = metadata()
    production = production_ids(data)
    workspace = set(data["workspace_members"])
    packages: dict[str, dict[str, object]] = {}
    for package in data["packages"]:
        if package["id"] not in production or package["id"] in workspace:
            continue
        key = f"{package['name']}@{package['version']}"
        packages[key] = inspect(package)
    packages = dict(sorted(packages.items()))
    return {
        "schema": 1,
        "scope": "locked non-workspace x86_64-unknown-linux-gnu production dependency graph",
        "package_count": len(packages),
        "packages_with_unsafe": sum(
            values["unsafe_tokens"] > 0 for values in packages.values()
        ),
        "packages_with_build_scripts": sum(
            values["build_script"] for values in packages.values()
        ),
        "packages_with_native_code": sum(
            values["native_files"] > 0 for values in packages.values()
        ),
        "packages": packages,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="replace the reviewed baseline")
    args = parser.parse_args()
    current = inventory()
    if args.write:
        BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        print(
            "dependency-unsafe: wrote baseline for "
            f"{current['package_count']} production dependencies"
        )
        return
    expected = json.loads(BASELINE.read_text(encoding="utf-8"))
    if current != expected:
        raise SystemExit(
            "dependency-unsafe: FAIL: locked unsafe/native exposure changed; "
            "review it and run tests/dependency_unsafe.py --write"
        )
    print(
        "dependency-unsafe: pass "
        f"({current['package_count']} packages, "
        f"{current['packages_with_unsafe']} with unsafe Rust, "
        f"{current['packages_with_native_code']} with native code)"
    )


if __name__ == "__main__":
    main()
