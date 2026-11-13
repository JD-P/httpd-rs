#!/usr/bin/env python3
"""Enforce removal of PCRE2 C code from the production dependency graph."""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def fail(message: str) -> None:
    raise SystemExit(f"native dependency policy: {message}")


def check_source_policy() -> None:
    manifest = (ROOT / "crates" / "server" / "Cargo.toml").read_text()
    if '\npcre2 = ' in manifest or 'package = "pcre2"' in manifest:
        fail("httpd-rs must not have a production dependency on the C-backed pcre2 crate")
    engine = (ROOT / "crates" / "pcre2" / "src" / "lib.rs").read_text()
    if "unsafe {" in engine or "unsafe fn" in engine:
        fail("the in-tree regex engine must remain free of unsafe Rust")
    if "backtracking: false" not in engine:
        fail("the in-tree regex engine must default backtracking to false")


def check_binary(binary: Path) -> None:
    if not binary.is_file():
        fail(f"binary does not exist: {binary}")
    if platform.system() != "Linux":
        return
    result = subprocess.run(
        ["ldd", str(binary)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        fail(f"ldd failed for {binary}: {result.stdout.strip()}")
    if "libpcre2" in result.stdout.lower():
        fail(f"{binary} dynamically links an ambient PCRE2 library")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    check_source_policy()
    if args.binary is not None:
        check_binary(args.binary)
    print("native dependency policy: production PCRE2 C boundary removed")


if __name__ == "__main__":
    try:
        main()
    except OSError as error:
        print(f"native dependency policy: {error}", file=sys.stderr)
        raise SystemExit(1) from error
