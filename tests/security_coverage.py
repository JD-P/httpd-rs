#!/usr/bin/env python3
"""Track production-line coverage for every server production module.

`tests/coverage.sh` produces whole-program coverage, including `#[cfg(test)]`
test modules.  For release tracking we care about the production lines before
the file's test module.  This script reads the same coverage artifacts and
reports those numbers.

`--check` is the CI ratchet: covered production lines may not decrease and
uncovered production lines may not increase relative to the reviewed baseline.
`--strict` retains the absolute 100% target and fails on any uncovered line.

Usage:
    sh tests/coverage.sh
    python3 tests/security_coverage.py
    python3 tests/security_coverage.py --check
    python3 tests/security_coverage.py --strict
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROFILE = Path(os.environ.get("SECURITY_COVERAGE_PROFILE", "/tmp/vapcov/all.profdata"))
COV_TARGET = Path(os.environ.get("COVERAGE_TARGET_DIR", ROOT / "target" / "cov"))
if not COV_TARGET.is_absolute():
    COV_TARGET = ROOT / COV_TARGET
BASELINE = Path(
    os.environ.get(
        "SECURITY_COVERAGE_BASELINE",
        ROOT / "tests" / "security_coverage_baseline.json",
    )
)

# (name, source path, required percentage).
MODULES = [
    ("access", "crates/server/src/access.rs", 100.0),
    ("auth", "crates/server/src/auth.rs", 100.0),
    ("cache", "crates/server/src/cache.rs", 100.0),
    ("cgi", "crates/server/src/cgi.rs", 100.0),
    ("compression", "crates/server/src/compression.rs", 100.0),
    ("config", "crates/server/src/config.rs", 100.0),
    ("config_frontend", "crates/server/src/config_frontend.rs", 100.0),
    ("expires", "crates/server/src/expires.rs", 100.0),
    ("expr", "crates/server/src/expr.rs", 100.0),
    ("fastcgi", "crates/server/src/fastcgi.rs", 100.0),
    ("files", "crates/server/src/files.rs", 100.0),
    ("h2", "crates/server/src/h2.rs", 100.0),
    ("htaccess", "crates/server/src/htaccess.rs", 100.0),
    ("http", "crates/server/src/http.rs", 100.0),
    ("log", "crates/server/src/log.rs", 100.0),
    ("main", "crates/server/src/main.rs", 100.0),
    ("ocsp", "crates/server/src/ocsp.rs", 100.0),
    ("policy_ref", "crates/server/src/policy_ref.rs", 100.0),
    ("process", "crates/server/src/process.rs", 100.0),
    ("proxy", "crates/server/src/proxy.rs", 100.0),
    ("request_plan", "crates/server/src/request_plan.rs", 100.0),
    ("resource", "crates/server/src/resource.rs", 100.0),
    ("rewrite", "crates/server/src/rewrite.rs", 100.0),
    ("scope_policy", "crates/server/src/scope_policy.rs", 100.0),
    ("server", "crates/server/src/server.rs", 100.0),
    ("status", "crates/server/src/status.rs", 100.0),
    ("tls", "crates/server/src/tls.rs", 100.0),
    ("util", "crates/server/src/util.rs", 100.0),
]

ENFORCED = {name for name, _, _ in MODULES}


def load_baseline() -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    try:
        document = json.loads(BASELINE.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read coverage baseline {BASELINE}: {error}") from error
    if (
        document.get("schema") != 1
        or not isinstance(document.get("modules"), dict)
        or not isinstance(document.get("total"), dict)
    ):
        raise SystemExit(f"invalid coverage baseline schema in {BASELINE}")
    modules = document["modules"]
    missing = ENFORCED - modules.keys()
    extra = modules.keys() - ENFORCED
    if missing or extra:
        raise SystemExit(
            f"coverage baseline/module mismatch: missing={sorted(missing)}, "
            f"extra={sorted(extra)}"
        )
    for name, limits in modules.items():
        if (
            not isinstance(limits, dict)
            or not isinstance(limits.get("minimum_covered"), int)
            or not isinstance(limits.get("maximum_missed"), int)
            or limits["minimum_covered"] < 0
            or limits["maximum_missed"] < 0
        ):
            raise SystemExit(f"invalid coverage baseline limits for {name}")
    total = document["total"]
    if (
        not isinstance(total.get("minimum_covered"), int)
        or not isinstance(total.get("maximum_missed"), int)
        or total["minimum_covered"] < 0
        or total["maximum_missed"] < 0
    ):
        raise SystemExit("invalid aggregate coverage baseline limits")
    return modules, total


def llvm_bin() -> Path:
    sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip()
    host = subprocess.check_output(["rustc", "-vV"], text=True)
    host = next(line.split(":", 1)[1].strip() for line in host.splitlines() if line.startswith("host:"))
    return Path(sysroot) / "lib" / "rustlib" / host / "bin"


def coverage_objects() -> list[Path]:
    objects = [COV_TARGET / "release" / "httpd-rs"]
    debug_daemon = COV_TARGET / "debug" / "httpd-rs"
    if debug_daemon.is_file() and os.access(debug_daemon, os.X_OK):
        objects.append(debug_daemon)
    for path in sorted((COV_TARGET / "debug" / "deps").iterdir()):
        # Cargo gives Rust test harnesses executable, extensionless names.
        # Include integration/property/fault binaries as well as the library
        # and CLI tests, but not executable-mode proc-macro shared objects.
        if path.is_file() and not path.suffix and os.access(path, os.X_OK):
            objects.append(path)
    return objects


def object_binary_id(path: Path) -> str | None:
    result = subprocess.run(
        ["readelf", "-n", path],
        text=True,
        capture_output=True,
        check=True,
    )
    match = re.search(r"Build ID:\s*([0-9a-f]+)", result.stdout)
    return match.group(1) if match else None


def profile_binary_id(path: Path) -> str | None:
    result = subprocess.run(
        [str(llvm_bin() / "llvm-profdata"), "show", "--binary-ids", path],
        text=True,
        capture_output=True,
        check=True,
    )
    match = re.search(r"^([0-9a-f]{16,})$", result.stdout, re.MULTILINE)
    return match.group(1) if match else None


def object_profiles(objects: list[Path]) -> list[tuple[Path, Path]]:
    """Pair each retained executable with profiles from that exact build.

    A Cargo test command also executes instrumented build scripts and proc
    macros. Merging all of those profiles and passing every test executable to
    one llvm-cov process makes equal Rust symbol names from different binaries
    collide, producing misleading "mismatched data" warnings. `%m` gives each
    loaded binary a stable filename signature; one binary-id lookup per
    signature lets us merge and export each executable independently.
    """
    raw_profiles = sorted(PROFILE.parent.glob("*.profraw"))
    if not raw_profiles:
        return []

    by_signature: dict[str, list[Path]] = {}
    for path in raw_profiles:
        match = re.match(r"(?:unit|httpd-rs)-\d+-(.+)_\d+\.profraw$", path.name)
        if match:
            by_signature.setdefault(match.group(1), []).append(path)

    by_id: dict[str, list[Path]] = {}
    for paths in by_signature.values():
        binary_id = profile_binary_id(paths[0])
        if binary_id:
            by_id.setdefault(binary_id, []).extend(paths)

    object_by_id: dict[str, Path] = {}
    for path in objects:
        if not path.exists():
            continue
        binary_id = object_binary_id(path)
        if binary_id:
            # target/debug/httpd-rs and its deps/ hardlink have one build id.
            object_by_id.setdefault(binary_id, path)

    pairs = []
    for binary_id, paths in by_id.items():
        obj = object_by_id.get(binary_id)
        if obj is None:
            # Compiler build scripts and proc macros are not server production
            # objects and intentionally have no retained test executable.
            continue
        merged = PROFILE.parent / f"object-{binary_id}.profdata"
        subprocess.run(
            [
                str(llvm_bin() / "llvm-profdata"),
                "merge",
                "-sparse",
                "-failure-mode=all",
                *paths,
                "-o",
                merged,
            ],
            check=True,
        )
        pairs.append((obj, merged))
    if not any(obj == objects[0] for obj, _ in pairs):
        raise SystemExit("release httpd-rs profile is missing from the coverage corpus")
    return pairs


def export_one_lcov(obj: Path, profile: Path) -> str:
    cmd = [
        str(llvm_bin() / "llvm-cov"),
        "export",
        obj,
        f"-instr-profile={profile}",
        r"--ignore-filename-regex=(\.cargo|rustc|/root/\.rustup)",
        "-format=lcov",
    ]
    return subprocess.check_output(cmd, text=True)


def export_lcov() -> str:
    objects = coverage_objects()
    if not objects[0].exists():
        raise SystemExit(f"missing {objects[0]}; run tests/coverage.sh first")
    pairs = object_profiles(objects)
    if pairs:
        return "".join(export_one_lcov(obj, profile) for obj, profile in pairs)
    if not PROFILE.exists():
        raise SystemExit(f"missing profiles under {PROFILE.parent}; run tests/coverage.sh first")
    # Compatibility path for a caller that retained only the historical
    # aggregate profile. New coverage runs use exact binary/profile pairs.
    cmd = [
        str(llvm_bin() / "llvm-cov"),
        "export",
        objects[0],
    ]
    for obj in objects[1:]:
        cmd.extend(["-object", obj])
    cmd.extend(
        [
            f"-instr-profile={PROFILE}",
            r"--ignore-filename-regex=(\.cargo|rustc|/root/\.rustup)",
            "-format=lcov",
        ]
    )
    return subprocess.check_output(cmd, text=True)


def structural_line(line: str) -> bool:
    """Delimiter-only lines carry no independent production behavior.

    LLVM's source coverage assigns them regions even when the preceding
    statement is a terminating branch, so counting them as separate
    executable lines makes a 100% statement metric unreachable.
    """
    stripped = line.strip()
    return stripped in {"}", "};", "});", "),", ");", "]", "};"} or stripped.startswith("//")


def production_lines(source: Path, records: dict[int, int]) -> tuple[int, int]:
    text = source.read_text().splitlines()
    # Files such as htaccess.rs contain `#[cfg(test)]` helpers before the real
    # test module; the module itself starts at a top-level `mod tests`.
    test_start = next(
        (i for i, line in enumerate(text, 1) if line.strip().startswith("mod tests")),
        len(text) + 1,
    )
    ignored: set[int] = set()
    in_ignore = False
    for i, line in enumerate(text, 1):
        if "coverage:ignore-start" in line:
            in_ignore = True
            ignored.add(i)
        elif "coverage:ignore-stop" in line:
            ignored.add(i)
            in_ignore = False
        elif in_ignore or "coverage:ignore-line" in line:
            ignored.add(i)
    executable = [
        (n, c)
        for n, c in records.items()
        if n < test_start
        and n not in ignored
        and not structural_line(text[n - 1])
    ]
    missed = sum(1 for _, count in executable if count == 0)
    return len(executable), missed


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="fail if production coverage regresses from the reviewed baseline",
    )
    mode.add_argument(
        "--strict",
        action="store_true",
        help="fail unless every enforced production module is at 100%",
    )
    args = parser.parse_args()
    baseline, aggregate_baseline = load_baseline()

    data: dict[str, dict[int, int]] = {}
    current = None
    for line in export_lcov().splitlines():
        if line.startswith("SF:"):
            current = line[3:]
            # llvm-cov may emit the same source once per instrumented object
            # (library tests, daemon tests, and release daemon). Preserve and
            # add every object's counters instead of letting the last object
            # silently replace the higher-coverage unit-test record.
            data.setdefault(current, {})
        elif line.startswith("DA:") and current:
            number, count = line[3:].split(",", 2)[:2]
            line_number = int(number)
            data[current][line_number] = data[current].get(line_number, 0) + int(count)

    print("production-line coverage for server modules")
    print(f"{'module':12} {'lines':>7} {'missed':>7} {'cover':>8}   status")
    failed = False
    total_lines = 0
    total_missed = 0
    for name, rel, required in MODULES:
        source = ROOT / rel
        suffix = "/" + rel
        record = next((v for k, v in data.items() if k.endswith(suffix)), None)
        if record is None:
            print(f"{name:12} {'-':>7} {'-':>7} {'-':>8}   missing from profile")
            failed = failed or name in ENFORCED
            continue
        total, missed = production_lines(source, record)
        covered = total - missed
        total_lines += total
        total_missed += missed
        cover = 100.0 if total == 0 else 100.0 * (total - missed) / total
        limits = baseline[name]
        regressed = (
            missed > limits["maximum_missed"]
            or covered < limits["minimum_covered"]
        )
        improved = (
            missed < limits["maximum_missed"]
            or covered > limits["minimum_covered"]
        )
        if args.strict and cover < required:
            status = "FAIL strict"
            failed = True
        elif args.check and regressed:
            missed_delta = missed - limits["maximum_missed"]
            covered_delta = covered - limits["minimum_covered"]
            status = f"FAIL debt {missed_delta:+d}, covered {covered_delta:+d}"
            failed = True
        elif improved:
            status = "improved"
        elif missed == 0:
            status = "100%"
        else:
            status = f"ratchet <= {limits['maximum_missed']} missed"
        print(f"{name:12} {total:7d} {missed:7d} {cover:7.2f}%   {status}")

    total_covered = total_lines - total_missed
    total_cover = 100.0 if total_lines == 0 else 100.0 * total_covered / total_lines
    total_regressed = (
        total_missed > aggregate_baseline["maximum_missed"]
        or total_covered < aggregate_baseline["minimum_covered"]
    )
    if args.strict and total_missed:
        total_status = "FAIL strict"
    elif args.check and total_regressed:
        missed_delta = total_missed - aggregate_baseline["maximum_missed"]
        covered_delta = total_covered - aggregate_baseline["minimum_covered"]
        total_status = f"FAIL debt {missed_delta:+d}, covered {covered_delta:+d}"
        failed = True
    elif (
        total_missed < aggregate_baseline["maximum_missed"]
        or total_covered > aggregate_baseline["minimum_covered"]
    ):
        total_status = "improved"
    else:
        total_status = f"ratchet <= {aggregate_baseline['maximum_missed']} missed"
    print(
        f"total        {total_lines:7d} {total_missed:7d} {total_cover:7.2f}%   "
        f"{total_status}; {total_covered} covered"
    )

    if (args.check or args.strict) and failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
