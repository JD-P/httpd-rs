#!/usr/bin/env python3
"""Reconstruct ring's generated assembly and security-relevant object content."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO


ROOT = Path(__file__).resolve().parents[1]
PINS_PATH = ROOT / "supply-chain" / "ring-reproducibility.toml"
LOCK_PATH = ROOT / "Cargo.lock"
GENERATED_HEADERS = {
    "ring_core_generated/prefix_symbols.h",
    "ring_core_generated/prefix_symbols_asm.h",
    "ring_core_generated/prefix_symbols_nasm.inc",
}
LOADABLE_SECTION_NAMES = {".text", ".rdata", ".pdata", ".xdata"}
DEBUG_SECTION_NAMES = {".debug$S", ".debug$T"}
LINUX_SUFFIXES = ("-elf.S", "-linux32.S", "-linux64.S")
HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
SECTION_LINE = re.compile(r"^\s+\d+\s+(\S+)\s+[0-9a-fA-F]+\s+")
FILE_FORMAT_LINE = re.compile(r"^.*:\s+file format (\S+)\s*$")
RELOCATION_HEADER = re.compile(r"^RELOCATION RECORDS FOR \[(.+)]:$")


class VerificationError(RuntimeError):
    """A pinned input or reconstructed artifact did not match."""


def require_table(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{name} must be a TOML table")
    return value


def require_string(table: dict[str, Any], key: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise VerificationError(f"pin {key!r} must be a non-empty string")
    return value


def require_int(table: dict[str, Any], key: str) -> int:
    value = table.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise VerificationError(f"pin {key!r} must be a non-negative integer")
    return value


def load_pins() -> tuple[dict[str, Any], dict[str, Any]]:
    with PINS_PATH.open("rb") as handle:
        pins = tomllib.load(handle)
    ring = require_table(pins.get("ring"), "ring")
    toolchain = require_table(pins.get("release_toolchain"), "release_toolchain")

    for key in (
        "name",
        "version",
        "source",
        "crate_url",
        "crate_sha256",
        "source_commit",
    ):
        require_string(ring, key)
    for key in (
        "crate_size",
        "expected_pregenerated_files",
        "expected_text_assembly",
        "expected_linux_assembly",
        "expected_windows_objects",
        "expected_loadable_sections",
        "expected_loadable_relocation_tables",
    ):
        require_int(ring, key)
    if not isinstance(ring.get("source_dirty"), bool):
        raise VerificationError("pin 'source_dirty' must be a boolean")

    for key in (
        "ring_toolchain_commit",
        "nasm_version",
        "nasm_source_url",
        "nasm_source_sha256",
        "nasm_windows_executable_sha256",
    ):
        require_string(toolchain, key)
    require_int(toolchain, "nasm_source_size")

    for value, label, pattern in (
        (ring["crate_sha256"], "ring crate SHA-256", HEX_64),
        (ring["source_commit"], "ring source commit", HEX_40),
        (toolchain["ring_toolchain_commit"], "ring-toolchain commit", HEX_40),
        (toolchain["nasm_source_sha256"], "NASM source SHA-256", HEX_64),
        (
            toolchain["nasm_windows_executable_sha256"],
            "NASM Windows executable SHA-256",
            HEX_64,
        ),
    ):
        if not pattern.fullmatch(value):
            raise VerificationError(f"invalid {label}: {value!r}")
    for key in ("crate_url",):
        if not ring[key].startswith("https://"):
            raise VerificationError(f"{key} must use HTTPS")
    if not toolchain["nasm_source_url"].startswith("https://"):
        raise VerificationError("nasm_source_url must use HTTPS")
    return ring, toolchain


def read_lock(stream: BinaryIO) -> dict[str, Any]:
    data = tomllib.load(stream)
    packages = data.get("package")
    if not isinstance(packages, list):
        raise VerificationError("Cargo.lock has no package array")
    matches = [package for package in packages if package.get("name") == "ring"]
    if len(matches) != 1:
        raise VerificationError(
            f"Cargo.lock must contain exactly one ring package; found {len(matches)}"
        )
    package = matches[0]
    record = {key: package.get(key) for key in ("name", "version", "source", "checksum")}
    if not all(isinstance(value, str) and value for value in record.values()):
        raise VerificationError(f"ring lock record is incomplete: {record}")
    return record


def lock_record(path: str | Path) -> dict[str, Any]:
    if str(path) == "-":
        return read_lock(sys.stdin.buffer)
    with Path(path).open("rb") as handle:
        return read_lock(handle)


def check_lock(ring: dict[str, Any], path: str | Path = LOCK_PATH) -> dict[str, Any]:
    record = lock_record(path)
    expected = {
        "name": ring["name"],
        "version": ring["version"],
        "source": ring["source"],
        "checksum": ring["crate_sha256"],
    }
    if record != expected:
        raise VerificationError(
            "the locked ring package changed without a reviewed pin update: "
            f"expected {expected}, found {record}"
        )
    return record


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_verified(
    url: str, expected_hash: str, expected_size: int, destination: Path
) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file():
        if destination.stat().st_size == expected_size and sha256(destination) == expected_hash:
            return destination
        destination.unlink()

    request = urllib.request.Request(url, headers={"User-Agent": "httpd-rs-ring-audit/1"})
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{destination.name}.", dir=destination.parent, delete=False
        ) as output:
            temporary = Path(output.name)
            with urllib.request.urlopen(request, timeout=60) as response:
                length = response.headers.get("Content-Length")
                if length is not None and int(length) != expected_size:
                    raise VerificationError(
                        f"unexpected download size for {url}: {length}, expected {expected_size}"
                    )
                size = 0
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > expected_size:
                        raise VerificationError(f"download exceeded pinned size for {url}")
                    output.write(chunk)
        if temporary.stat().st_size != expected_size:
            raise VerificationError(
                f"unexpected download size for {url}: {temporary.stat().st_size}, "
                f"expected {expected_size}"
            )
        actual_hash = sha256(temporary)
        if actual_hash != expected_hash:
            raise VerificationError(
                f"SHA-256 mismatch for {url}: {actual_hash}, expected {expected_hash}"
            )
        os.replace(temporary, destination)
        temporary = None
        return destination
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def safe_extract(archive: Path, destination: Path, expected_root: str) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    top_levels: set[str] = set()
    with tarfile.open(archive, mode="r:*") as bundle:
        for member in bundle:
            path = PurePosixPath(member.name)
            if (
                not member.name
                or path.is_absolute()
                or ".." in path.parts
                or path.parts[0] in {"", "."}
            ):
                raise VerificationError(f"unsafe archive path in {archive.name}: {member.name!r}")
            if member.name in seen:
                raise VerificationError(f"duplicate archive path in {archive.name}: {member.name}")
            seen.add(member.name)
            top_levels.add(path.parts[0])
            if not (member.isdir() or member.isfile()):
                raise VerificationError(
                    f"archive link or special file rejected in {archive.name}: {member.name}"
                )

            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(member.mode & 0o777)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise VerificationError(f"could not read {member.name} from {archive.name}")
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(member.mode & 0o777)

    if top_levels != {expected_root}:
        raise VerificationError(
            f"unexpected roots in {archive.name}: {sorted(top_levels)}, expected {expected_root!r}"
        )
    root = destination / expected_root
    if not root.is_dir():
        raise VerificationError(f"archive root is not a directory: {root}")
    return root


def run_checked(
    command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None
) -> str:
    environment = os.environ.copy() if env is None else env.copy()
    environment["LC_ALL"] = "C"
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        output = result.stdout[-8000:]
        raise VerificationError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{output}"
        )
    return result.stdout


def require_program(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise VerificationError(f"required program is not installed: {name}")
    return path


def verify_source_identity(source: Path, ring: dict[str, Any]) -> None:
    vcs_path = source / ".cargo_vcs_info.json"
    try:
        vcs = json.loads(vcs_path.read_text(encoding="utf-8"))
        git = vcs["git"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid {vcs_path.name}: {error}") from error
    if git.get("sha1") != ring["source_commit"] or git.get("dirty") is not ring["source_dirty"]:
        raise VerificationError(
            "ring package provenance changed: "
            f"expected commit={ring['source_commit']} dirty={ring['source_dirty']}, found {git}"
        )


def generated_inventory(
    source: Path, ring: dict[str, Any]
) -> tuple[list[Path], list[Path], list[Path]]:
    pregenerated = source / "pregenerated"
    files = sorted(path for path in pregenerated.rglob("*") if path.is_file())
    if len(files) != ring["expected_pregenerated_files"]:
        raise VerificationError(
            f"pregenerated file count changed: {len(files)}, "
            f"expected {ring['expected_pregenerated_files']}"
        )
    text = sorted(path for path in files if path.suffix in {".S", ".asm"})
    objects = sorted(path for path in files if path.suffix == ".o")
    other = {path.relative_to(pregenerated).as_posix() for path in files} - {
        path.relative_to(pregenerated).as_posix() for path in text + objects
    }
    if len(text) != ring["expected_text_assembly"]:
        raise VerificationError(
            f"text assembly count changed: {len(text)}, expected {ring['expected_text_assembly']}"
        )
    if len(objects) != ring["expected_windows_objects"]:
        raise VerificationError(
            f"Windows object count changed: {len(objects)}, "
            f"expected {ring['expected_windows_objects']}"
        )
    if other != GENERATED_HEADERS:
        raise VerificationError(
            f"unexpected non-assembly pregenerated files: {sorted(other)}"
        )
    assembly_stems = {path.stem for path in text if path.suffix == ".asm"}
    object_stems = {path.stem for path in objects}
    if assembly_stems != object_stems:
        raise VerificationError(
            "packaged NASM source/object pairs changed: "
            f"asm-only={sorted(assembly_stems - object_stems)}, "
            f"object-only={sorted(object_stems - assembly_stems)}"
        )
    return files, text, objects


def perl_source_for(source: Path, generated: Path) -> tuple[Path, str, str]:
    stem = generated.stem
    source_stem, separator, output_format = stem.rpartition("-")
    if not separator:
        raise VerificationError(f"cannot derive PerlAsm format from {generated.name}")
    aliases = {
        "sha256-x86_64": "sha512-x86_64",
        "sha256-armv8": "sha512-armv8",
    }
    source_stem = aliases.get(source_stem, source_stem)
    candidates: list[Path] = []
    for directory in (source / "crypto", source / "third_party"):
        candidates.extend(directory.rglob(f"{source_stem}.pl"))
    if len(candidates) != 1:
        raise VerificationError(
            f"expected one generator for {generated.name}, found {len(candidates)}: {candidates}"
        )
    return candidates[0], source_stem, output_format


def first_difference(expected: bytes, actual: bytes) -> str:
    for offset, (left, right) in enumerate(zip(expected, actual)):
        if left != right:
            return f"first byte differs at offset {offset}: {left:#04x} != {right:#04x}"
    return f"length differs: {len(expected)} != {len(actual)}"


def verify_text_assembly(
    source: Path, text_files: list[Path], scope: str, ring: dict[str, Any]
) -> int:
    perl = require_program("perl")
    environment = os.environ.copy()
    for variable in ("PERL5LIB", "PERLLIB", "PERL5OPT"):
        environment.pop(variable, None)
    selected = text_files
    if scope == "linux":
        selected = [path for path in text_files if path.name.endswith(LINUX_SUFFIXES)]
        if len(selected) != ring["expected_linux_assembly"]:
            raise VerificationError(
                f"Linux assembly count changed: {len(selected)}, "
                f"expected {ring['expected_linux_assembly']}"
            )

    with tempfile.TemporaryDirectory(prefix="httpd-rs-ring-asm-") as temporary:
        output_dir = Path(temporary)
        for expected in selected:
            generator, source_stem, output_format = perl_source_for(source, expected)
            output = output_dir / expected.name
            command = [perl, str(generator), output_format]
            if source_stem.endswith("-x86") or source_stem == "x86-mont":
                command.append("-fPIC")
            command.append(str(output))
            run_checked(command, cwd=source, env=environment)
            expected_bytes = expected.read_bytes()
            actual_bytes = output.read_bytes()
            if expected_bytes != actual_bytes:
                raise VerificationError(
                    f"PerlAsm output differs for {expected.name}: "
                    f"{first_difference(expected_bytes, actual_bytes)}"
                )
    return len(selected)


def valid_cached_nasm(path: Path, marker: Path, toolchain: dict[str, Any]) -> bool:
    if not path.is_file() or not marker.is_file():
        return False
    try:
        metadata = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    expected = {
        "source_sha256": toolchain["nasm_source_sha256"],
        "version": toolchain["nasm_version"],
    }
    if metadata != expected:
        return False
    result = subprocess.run(
        [str(path), "-v"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return result.returncode == 0 and result.stdout.startswith(
        f"NASM version {toolchain['nasm_version']} "
    )


def build_nasm(cache: Path, toolchain: dict[str, Any], *, rebuild: bool) -> Path:
    for program in ("gcc", "make", "ar", "ranlib"):
        require_program(program)

    version = toolchain["nasm_version"]
    archive = download_verified(
        toolchain["nasm_source_url"],
        toolchain["nasm_source_sha256"],
        toolchain["nasm_source_size"],
        cache / f"nasm-{version}.tar.xz",
    )
    cache_name = f"nasm-{version}-{toolchain['nasm_source_sha256'][:16]}"
    installation = cache / cache_name
    binary = installation / "bin" / "nasm"
    marker = installation / ".httpd-rs-pin.json"
    if not rebuild and valid_cached_nasm(binary, marker, toolchain):
        print(f"ring reproducibility: using cached NASM {version}")
        return binary

    print(f"ring reproducibility: building pinned NASM {version}")
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nasm-build-", dir=cache) as temporary:
        workspace = Path(temporary)
        source = safe_extract(archive, workspace / "source", f"nasm-{version}")
        staged = workspace / "install"
        environment = os.environ.copy()
        environment["CC"] = require_program("gcc")
        environment["CFLAGS"] = "-O2"
        run_checked(["./configure", f"--prefix={staged}"], cwd=source, env=environment)
        makefile = (source / "Makefile").read_text(encoding="utf-8")
        configured_flags = re.search(r"^CFLAGS\s*=\s*(.*)$", makefile, re.MULTILINE)
        if configured_flags is None:
            raise VerificationError("could not recover configured NASM compiler flags")
        # NASM 2.13.03 predates GCC's warning for a pure void function. Keep
        # its configured flags, but make that one new warning non-fatal.
        make_flags = f"CFLAGS={configured_flags.group(1)} -Wno-error=attributes"
        jobs = max(1, min(4, os.cpu_count() or 1))
        run_checked(["make", f"-j{jobs}", make_flags], cwd=source, env=environment)
        run_checked(["make", "install", make_flags], cwd=source, env=environment)
        staged_binary = staged / "bin" / "nasm"
        if not staged_binary.is_file():
            raise VerificationError("NASM build did not install a nasm executable")
        marker_data = {
            "source_sha256": toolchain["nasm_source_sha256"],
            "version": version,
        }
        (staged / ".httpd-rs-pin.json").write_text(
            json.dumps(marker_data, sort_keys=True) + "\n", encoding="utf-8"
        )
        if installation.exists():
            shutil.rmtree(installation)
        os.replace(staged, installation)

    if not valid_cached_nasm(binary, marker, toolchain):
        raise VerificationError("newly built NASM failed its version/pin check")
    return binary


def object_sections(objdump: str, path: Path) -> tuple[set[str], set[str]]:
    output = run_checked([objdump, "-h", str(path)])
    lines = output.splitlines()
    all_sections: set[str] = set()
    loadable_sections: set[str] = set()
    for index, line in enumerate(lines[:-1]):
        match = SECTION_LINE.match(line)
        if match is None:
            continue
        name = match.group(1)
        all_sections.add(name)
        flags = {flag.strip() for flag in lines[index + 1].split(",")}
        if {"CONTENTS", "ALLOC", "LOAD"}.issubset(flags):
            loadable_sections.add(name)
    return all_sections, loadable_sections


def normalized_disassembly(objdump: str, path: Path) -> tuple[str, str]:
    output = run_checked([objdump, "-dr", str(path)])
    normalized: list[str] = []
    formats: list[str] = []
    for line in output.splitlines():
        match = FILE_FORMAT_LINE.match(line)
        if match is not None:
            formats.append(match.group(1))
            continue
        normalized.append(line)
    if len(formats) != 1:
        raise VerificationError(f"could not identify one object format in {path}")
    result = "\n".join(normalized)
    if "Disassembly of section .text:" not in result:
        raise VerificationError(f"could not identify .text disassembly in {path}")
    return formats[0], result


def loadable_relocations(objdump: str, path: Path, sections: set[str]) -> tuple[str, int]:
    output = run_checked([objdump, "-r", str(path)])
    selected: list[str] = []
    keep = False
    table_count = 0
    for line in output.splitlines():
        match = RELOCATION_HEADER.match(line)
        if match is not None:
            keep = match.group(1) in sections
            if keep:
                table_count += 1
        if keep:
            selected.append(line)
    return "\n".join(selected), table_count


def normalized_symbols(objdump: str, path: Path) -> str:
    """Drop only CodeView path/debug-size records from a COFF symbol table."""
    output = run_checked([objdump, "-t", str(path)])
    selected: list[str] = []
    skip_auxiliary = False
    for line in output.splitlines():
        if line.startswith("["):
            name = line.rsplit(None, 1)[-1]
            skip_auxiliary = "(scl 103)" in line or name in DEBUG_SECTION_NAMES
            if not skip_auxiliary:
                selected.append(line)
        elif line.startswith("AUX"):
            if not skip_auxiliary:
                selected.append(line)
            skip_auxiliary = False
        elif line.strip() == "File":
            skip_auxiliary = False
        elif line == "SYMBOL TABLE:":
            selected.append(line)
    if len(selected) < 2:
        raise VerificationError(f"could not identify link symbols in {path}")
    return "\n".join(selected)


def dump_section(objcopy: str, source: Path, section: str, destination: Path) -> bytes:
    run_checked([objcopy, "--dump-section", f"{section}={destination}", str(source)])
    return destination.read_bytes()


def verify_windows_objects(
    source: Path,
    objects: list[Path],
    nasm: Path,
    ring: dict[str, Any],
) -> tuple[int, int]:
    objdump = require_program("objdump")
    objcopy = require_program("objcopy")
    pregenerated = source / "pregenerated"
    section_count = 0
    relocation_table_count = 0
    nasm_environment = os.environ.copy()
    nasm_environment["NASMENV"] = ""

    with tempfile.TemporaryDirectory(prefix="httpd-rs-ring-objects-") as temporary:
        output_dir = Path(temporary)
        for expected in objects:
            assembly = pregenerated / f"{expected.stem}.asm"
            rebuilt = output_dir / expected.name
            output_format = "win32" if expected.stem.endswith("-win32n") else "win64"
            run_checked(
                [
                    str(nasm),
                    "-o",
                    str(rebuilt),
                    "-f",
                    output_format,
                    "-i",
                    f"{source / 'include'}/",
                    "-i",
                    f"{pregenerated}/",
                    "-Xgnu",
                    "-gcv8",
                    str(assembly),
                ],
                cwd=source,
                env=nasm_environment,
            )

            expected_all_sections, expected_sections = object_sections(objdump, expected)
            rebuilt_all_sections, rebuilt_sections = object_sections(objdump, rebuilt)
            if expected_all_sections != rebuilt_all_sections:
                raise VerificationError(
                    f"complete section set differs for {expected.name}: "
                    f"expected {sorted(expected_all_sections)}, "
                    f"found {sorted(rebuilt_all_sections)}"
                )
            unexpected_all = expected_all_sections - (
                LOADABLE_SECTION_NAMES | DEBUG_SECTION_NAMES
            )
            if unexpected_all:
                raise VerificationError(
                    f"unexpected object sections in {expected.name}: {sorted(unexpected_all)}"
                )
            if expected_sections != rebuilt_sections:
                raise VerificationError(
                    f"loadable section set differs for {expected.name}: "
                    f"expected {sorted(expected_sections)}, found {sorted(rebuilt_sections)}"
                )
            unexpected = expected_sections - LOADABLE_SECTION_NAMES
            if unexpected:
                raise VerificationError(
                    f"unexpected loadable sections in {expected.name}: {sorted(unexpected)}"
                )
            section_count += len(expected_sections)
            for section in sorted(expected_sections):
                expected_bytes = dump_section(
                    objcopy,
                    expected,
                    section,
                    output_dir / f"{expected.name}.{section}.expected",
                )
                rebuilt_bytes = dump_section(
                    objcopy,
                    rebuilt,
                    section,
                    output_dir / f"{expected.name}.{section}.rebuilt",
                )
                if expected_bytes != rebuilt_bytes:
                    raise VerificationError(
                        f"{section} differs for {expected.name}: "
                        f"{first_difference(expected_bytes, rebuilt_bytes)}"
                    )

            expected_format, expected_disassembly = normalized_disassembly(objdump, expected)
            rebuilt_format, rebuilt_disassembly = normalized_disassembly(objdump, rebuilt)
            if expected_format != rebuilt_format or expected_disassembly != rebuilt_disassembly:
                raise VerificationError(f"normalized disassembly differs for {expected.name}")
            expected_relocations, expected_relocation_tables = loadable_relocations(
                objdump, expected, expected_sections
            )
            rebuilt_relocations, rebuilt_relocation_tables = loadable_relocations(
                objdump, rebuilt, rebuilt_sections
            )
            if (
                expected_relocations != rebuilt_relocations
                or expected_relocation_tables != rebuilt_relocation_tables
            ):
                raise VerificationError(f"loadable relocations differ for {expected.name}")
            relocation_table_count += expected_relocation_tables
            if normalized_symbols(objdump, expected) != normalized_symbols(objdump, rebuilt):
                raise VerificationError(f"link-visible symbols differ for {expected.name}")

    if section_count != ring["expected_loadable_sections"]:
        raise VerificationError(
            f"loadable section count changed: {section_count}, "
            f"expected {ring['expected_loadable_sections']}"
        )
    if relocation_table_count != ring["expected_loadable_relocation_tables"]:
        raise VerificationError(
            f"loadable relocation-table count changed: {relocation_table_count}, "
            f"expected {ring['expected_loadable_relocation_tables']}"
        )
    return section_count, relocation_table_count


def verify(scope: str, cache: Path, *, rebuild_nasm: bool) -> None:
    ring, toolchain = load_pins()
    check_lock(ring)
    cache.mkdir(parents=True, exist_ok=True)
    crate = download_verified(
        ring["crate_url"],
        ring["crate_sha256"],
        ring["crate_size"],
        cache / f"{ring['name']}-{ring['version']}.crate",
    )

    with tempfile.TemporaryDirectory(prefix="httpd-rs-ring-source-") as temporary:
        source = safe_extract(
            crate,
            Path(temporary),
            f"{ring['name']}-{ring['version']}",
        )
        verify_source_identity(source, ring)
        _, text_files, objects = generated_inventory(source, ring)
        text_count = verify_text_assembly(source, text_files, scope, ring)
        if scope == "linux":
            print(
                "ring reproducibility: "
                f"{text_count} Linux assembly files match source "
                f"(ring {ring['version']} at {ring['source_commit']})"
            )
            return

        nasm = build_nasm(cache, toolchain, rebuild=rebuild_nasm)
        section_count, relocation_count = verify_windows_objects(source, objects, nasm, ring)
        print(
            "ring reproducibility: "
            f"{text_count} assembly files and {section_count} loadable PE/COFF sections "
            f"with {relocation_count} relocation tables match source "
            f"(NASM {toolchain['nasm_version']}, "
            f"ring-toolchain {toolchain['ring_toolchain_commit']})"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check-lock", help="validate Cargo.lock against reviewed pins")
    check.add_argument("lockfile", nargs="?", default=LOCK_PATH)

    record = commands.add_parser("lock-record", help="print ring's lock record as stable JSON")
    record.add_argument("lockfile", nargs="?", default=LOCK_PATH)

    verify_parser = commands.add_parser("verify", help="reconstruct generated ring artifacts")
    verify_parser.add_argument("--scope", choices=("linux", "full"), required=True)
    verify_parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(tempfile.gettempdir()) / "httpd-rs-ring-reproducibility",
    )
    verify_parser.add_argument(
        "--rebuild-nasm",
        action="store_true",
        help="ignore a cached NASM binary and rebuild the pinned source",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "lock-record":
        print(json.dumps(lock_record(args.lockfile), sort_keys=True, separators=(",", ":")))
        return 0

    ring, toolchain = load_pins()
    if args.command == "check-lock":
        record = check_lock(ring, args.lockfile)
        print(
            "ring reproducibility pins: "
            f"{record['name']} {record['version']} {record['checksum']}, "
            f"NASM {toolchain['nasm_version']}"
        )
        return 0

    verify(args.scope, args.cache_dir.resolve(), rebuild_nasm=args.rebuild_nasm)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, VerificationError, urllib.error.URLError) as error:
        print(f"ring reproducibility: {error}", file=sys.stderr)
        raise SystemExit(1) from error
