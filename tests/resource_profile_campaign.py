#!/usr/bin/env python3
"""Run benchmark/deployment workloads under the resource profiler and reconcile them."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PROFILER = ROOT / "tests" / "resource_profile.py"
WARRANT = ROOT / "tests" / "resource_warrant.py"
BENCHMARKS = {
    "core": [sys.executable, "bench/bench.py"],
    "features": [sys.executable, "bench/feature_bench.py"],
    "cache": [sys.executable, "bench/cache_bench.py"],
    "applications": [sys.executable, "bench/app_bench.py"],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/resource-warrant")
    parser.add_argument(
        "--benchmarks",
        default="core,features,cache,applications",
        help="comma-separated core,features,cache,applications or none",
    )
    parser.add_argument(
        "--deployments",
        choices=("none", "nightly", "canonical", "sample", "full"),
        default="canonical",
    )
    parser.add_argument("--sample-count", type=int, default=10)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0x52534F55524345)
    parser.add_argument("--quick", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--perf", choices=("none", "stat", "record"), default="none")
    parser.add_argument("--keep-going", action="store_true")
    return parser.parse_args()


def run_profile(label: str, workload: list[str], output: Path, perf: str) -> int:
    profile = output / "profiles" / f"{label}.json"
    command = [
        sys.executable,
        str(PROFILER),
        "run",
        "--label",
        label,
        "--output",
        str(profile),
        "--perf",
        perf,
        "--",
        *workload,
    ]
    print("+ " + " ".join(command), flush=True)
    return subprocess.run(command, cwd=ROOT, check=False).returncode


def main() -> int:
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    selected = [] if args.benchmarks == "none" else [item for item in args.benchmarks.split(",") if item]
    unknown = set(selected) - BENCHMARKS.keys()
    if unknown:
        raise SystemExit(f"resource-profile-campaign: unknown benchmarks: {sorted(unknown)}")

    results = []
    for name in selected:
        workload = list(BENCHMARKS[name])
        if args.quick:
            workload.append("--quick")
        returncode = run_profile(f"benchmark-{name}", workload, args.output, args.perf)
        results.append({"label": f"benchmark-{name}", "returncode": returncode})
        if returncode and not args.keep_going:
            break

    if args.deployments != "none" and (args.keep_going or not any(item["returncode"] for item in results)):
        workload = [
            sys.executable,
            "tests/deployments/harness.py",
            "--profile",
            args.deployments,
            "--benchmark",
            "--sample-count",
            str(args.sample_count),
            "--seed",
            str(args.seed),
            "--artifacts",
            str(args.output / "deployments"),
        ]
        returncode = run_profile(
            f"deployments-{args.deployments}", workload, args.output, args.perf
        )
        results.append({"label": f"deployments-{args.deployments}", "returncode": returncode})

    report = args.output / "request-resource-warrant.json"
    reconcile = [
        sys.executable,
        str(WARRANT),
        "--report",
        "--profile",
        str(args.output / "profiles" / "*.json"),
        "--output",
        str(report),
    ]
    print("+ " + " ".join(reconcile), flush=True)
    reconcile_result = subprocess.run(reconcile, cwd=ROOT, check=False).returncode
    summary = {
        "schema": 1,
        "workloads": results,
        "reconciliation_returncode": reconcile_result,
        "report": str(report),
    }
    (args.output / "campaign-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    failed = [item for item in results if item["returncode"]]
    if failed:
        print(
            "resource-profile-campaign: failed workload(s): "
            + ", ".join(str(item["label"]) for item in failed),
            file=sys.stderr,
        )
    return 1 if failed or reconcile_result else 0


if __name__ == "__main__":
    raise SystemExit(main())
