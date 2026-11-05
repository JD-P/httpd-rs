#!/usr/bin/env python3
"""Reject stale version requirements on repository-local Rust crates."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import Any, Iterator


ROOT = Path(__file__).resolve().parents[1]


def read_manifest(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def dependency_tables(value: Any) -> Iterator[dict[str, Any]]:
    if not isinstance(value, dict):
        return
    for key, child in value.items():
        if key in {"dependencies", "dev-dependencies", "build-dependencies"}:
            if isinstance(child, dict):
                yield child
        elif isinstance(child, dict):
            yield from dependency_tables(child)


def package_version(manifest: dict[str, Any], workspace_version: str) -> str | None:
    package = manifest.get("package")
    if not isinstance(package, dict):
        return None
    version = package.get("version")
    if isinstance(version, str):
        return version
    if isinstance(version, dict) and version.get("workspace") is True:
        return workspace_version
    return None


def main() -> int:
    root_manifest = read_manifest(ROOT / "Cargo.toml")
    workspace_version = root_manifest["workspace"]["package"]["version"]
    errors: list[str] = []

    for manifest_path in sorted(ROOT.rglob("Cargo.toml")):
        if "target" in manifest_path.parts:
            continue
        manifest = read_manifest(manifest_path)
        for table in dependency_tables(manifest):
            for dependency, spec in table.items():
                if not isinstance(spec, dict) or not isinstance(spec.get("path"), str):
                    continue
                dependency_manifest_path = (
                    manifest_path.parent / spec["path"] / "Cargo.toml"
                ).resolve()
                try:
                    dependency_manifest_path.relative_to(ROOT)
                except ValueError:
                    continue
                if not dependency_manifest_path.is_file():
                    errors.append(
                        f"{manifest_path.relative_to(ROOT)}: {dependency} path has no Cargo.toml"
                    )
                    continue
                dependency_manifest = read_manifest(dependency_manifest_path)
                actual = package_version(dependency_manifest, workspace_version)
                required = spec.get("version")
                if actual is not None and isinstance(required, str) and required != actual:
                    errors.append(
                        f"{manifest_path.relative_to(ROOT)}: {dependency} requires "
                        f"{required}, but {dependency_manifest_path.relative_to(ROOT)} is {actual}"
                    )

    if errors:
        print("release version consistency errors:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"release version consistency: {workspace_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
