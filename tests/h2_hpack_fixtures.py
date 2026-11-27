#!/usr/bin/env python3
"""Fetch and run the pinned upstream HPACK interoperability corpus.

The corpus remains outside the repository and the published h2 fork.  Both the
GitHub archive and the canonical extracted tree are authenticated before any
fixture is passed to the test process.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request

from h2_hpack_manifest import (
    ARCHIVE_MAX_BYTES,
    ARCHIVE_PREFIX,
    ARCHIVE_SHA256,
    ARCHIVE_URL,
    H2_VERSION,
    TREE_BYTES,
    TREE_FILES,
    TREE_SHA256,
    check_manifest,
)

ROOT = Path(__file__).resolve().parents[1]


class FixtureError(RuntimeError):
    pass


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def download_archive(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and file_sha256(path) == ARCHIVE_SHA256:
        return
    if path.exists():
        path.unlink()
    request = urllib.request.Request(
        ARCHIVE_URL,
        headers={"User-Agent": "httpd-rs-hpack-fixture-fetch/1"},
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(descriptor, "wb") as output:
            with urllib.request.urlopen(request, timeout=60) as response:
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > ARCHIVE_MAX_BYTES:
                        raise FixtureError(
                            f"HPACK archive exceeds {ARCHIVE_MAX_BYTES} bytes"
                        )
                    digest.update(chunk)
                    output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        actual = digest.hexdigest()
        if actual != ARCHIVE_SHA256:
            raise FixtureError(
                f"HPACK archive SHA-256 mismatch: {actual} != {ARCHIVE_SHA256}"
            )
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def safe_relative(member: tarfile.TarInfo) -> Path | None:
    if not member.name.startswith(ARCHIVE_PREFIX):
        return None
    suffix = member.name[len(ARCHIVE_PREFIX) :]
    if not suffix:
        return None
    relative = PurePosixPath(suffix)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise FixtureError(f"unsafe HPACK archive path: {member.name!r}")
    if member.issym() or member.islnk() or member.isdev():
        raise FixtureError(f"non-regular HPACK archive member: {member.name!r}")
    if not member.isfile() and not member.isdir():
        raise FixtureError(f"unknown HPACK archive member: {member.name!r}")
    return Path(*relative.parts)


def tree_identity(root: Path) -> tuple[int, int, str]:
    rows: list[tuple[str, bytes]] = []
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise FixtureError(f"HPACK fixture tree contains a link: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        total += len(data)
        rows.append((relative, hashlib.sha256(data).digest()))
    rows.sort(key=lambda row: row[0])
    digest = hashlib.sha256()
    for relative, content_digest in rows:
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content_digest)
    return len(rows), total, digest.hexdigest()


def validate_tree(root: Path) -> None:
    identity = tree_identity(root)
    expected = (TREE_FILES, TREE_BYTES, TREE_SHA256)
    if identity != expected:
        raise FixtureError(f"HPACK fixture tree mismatch: {identity!r} != {expected!r}")


def extract_archive(archive: Path, destination: Path) -> None:
    if destination.is_dir():
        try:
            validate_tree(destination)
            return
        except FixtureError:
            pass
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_parent = Path(
        tempfile.mkdtemp(prefix=".hpack-extract-", dir=destination.parent)
    )
    temporary = temporary_parent / "hpack"
    temporary.mkdir()
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle:
                relative = safe_relative(member)
                if relative is None:
                    continue
                target = temporary / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                source = bundle.extractfile(member)
                if source is None:
                    raise FixtureError(f"cannot read HPACK member {member.name!r}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
        validate_tree(temporary)
        if destination.exists():
            shutil.rmtree(destination)
        temporary.replace(destination)
    finally:
        shutil.rmtree(temporary_parent, ignore_errors=True)


def run_tests(fixtures: Path) -> None:
    manifest = ROOT / "vendor/httpd-rs-h2-0.4.20/Cargo.toml"
    generated_lock = manifest.with_name("Cargo.lock")
    lock_existed = generated_lock.exists()
    environment = os.environ.copy()
    environment["HTTPD_RS_HPACK_FIXTURES"] = str(fixtures.resolve())
    environment.setdefault(
        "CARGO_TARGET_DIR", str(ROOT / "target/h2-fixture-tests")
    )
    try:
        subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(manifest),
                "--locked",
                "--lib",
                "hpack::test::fixture::",
                "--",
                "--test-threads=1",
            ],
            cwd=ROOT,
            env=environment,
            check=True,
        )
    finally:
        if not lock_existed:
            generated_lock.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--archive",
        type=Path,
        default=ROOT / f"target/test-fixtures/h2-v{H2_VERSION}.tar.gz",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / f"target/test-fixtures/h2-v{H2_VERSION}/hpack",
    )
    parser.add_argument(
        "--fetch-only",
        action="store_true",
        help="verify and extract the corpus without running the h2 fixture tests",
    )
    args = parser.parse_args()
    try:
        download_archive(args.archive)
        extract_archive(args.archive, args.output)
        check_manifest(args.output)
        print(
            f"verified HPACK corpus: {TREE_FILES} files, {TREE_BYTES} bytes, "
            f"tree sha256 {TREE_SHA256}"
        )
        if not args.fetch_only:
            run_tests(args.output)
    except (
        FixtureError,
        OSError,
        subprocess.CalledProcessError,
        tarfile.TarError,
        urllib.error.URLError,
    ) as error:
        print(f"h2-hpack-fixtures: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
