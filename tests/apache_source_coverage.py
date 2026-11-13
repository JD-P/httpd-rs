#!/usr/bin/env python3
"""Map instrumented Apache coverage back to source-derived warrant families."""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "docs" / "apache-warrant-policy.json"


def relative_source(filename: str, source: Path) -> str | None:
    path = Path(filename)
    if not path.is_absolute() and path.parts and path.parts[0] in {"server", "modules"}:
        return path.as_posix()
    try:
        return path.resolve().relative_to(source.resolve()).as_posix()
    except (OSError, ValueError):
        marker = f"httpd-{json.loads(POLICY.read_text())['source_pin']['release']}/"
        normalized = filename.replace("\\", "/")
        if marker in normalized:
            return normalized.split(marker, 1)[1]
        return None


def covered(count: Any) -> bool:
    if isinstance(count, (int, float)):
        return count > 0
    if isinstance(count, str):
        try:
            return float(count) > 0
        except ValueError:
            return False
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("coverage", type=Path, help="gcovr --json report")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    raw = json.loads(args.coverage.read_text(encoding="utf-8"))
    files: dict[str, dict[str, Any]] = {}
    for entry in raw.get("files", []):
        relative = relative_source(str(entry.get("file", entry.get("filename", ""))), args.source)
        if relative is not None:
            files[relative] = entry

    family_reports = []
    failed = []
    for family in policy["families"]:
        matched = {
            name: entry
            for name, entry in files.items()
            if any(fnmatch.fnmatchcase(name, pattern) for pattern in family["source_globs"])
        }
        lines_total = lines_covered = branches_total = branches_covered = 0
        uncovered_branches: list[str] = []
        for name, entry in sorted(matched.items()):
            for line in entry.get("lines", []):
                lines_total += 1
                if covered(line.get("count", 0)):
                    lines_covered += 1
                for branch_index, branch in enumerate(line.get("branches", [])):
                    branches_total += 1
                    if covered(branch.get("count", 0)):
                        branches_covered += 1
                    elif len(uncovered_branches) < 100:
                        uncovered_branches.append(
                            f"{name}:{line.get('line_number', line.get('line', '?'))}:branch-{branch_index}"
                        )
        report = {
            "family": family["id"],
            "files": sorted(matched),
            "lines": {"covered": lines_covered, "total": lines_total},
            "branches": {"covered": branches_covered, "total": branches_total},
            "minimum_covered_branches": family["minimum_covered_apache_branches"],
            "uncovered_branch_sample": uncovered_branches,
        }
        family_reports.append(report)
        if not matched:
            failed.append(f"{family['id']}: no instrumented Apache source file")
        elif lines_covered == 0:
            failed.append(f"{family['id']}: no covered Apache source line")
        elif branches_total == 0:
            failed.append(f"{family['id']}: no instrumented Apache source branch")
        elif branches_covered == 0:
            failed.append(f"{family['id']}: no covered Apache source branch")
        elif branches_covered < family["minimum_covered_apache_branches"]:
            failed.append(
                f"{family['id']}: covered Apache branches regressed "
                f"({branches_covered} < {family['minimum_covered_apache_branches']})"
            )

    result = {
        "schema": 1,
        "source_release": policy["source_pin"]["release"],
        "measurement": "Apache gcov branch coverage grouped by warrant family",
        "families": family_reports,
        "failures": failed,
    }
    if args.output:
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    if failed:
        print("apache-source-coverage: " + "; ".join(failed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
