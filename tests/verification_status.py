#!/usr/bin/env python3
"""Report the verification ledger and fail if assurance regresses.

This is the CI gate for *proof debt*, not for test coverage.  The editable
source of truth is docs/verification-status.json.  The script checks that:

  * every obligation has a known status and positive weight;
  * the weighted obligation score has not fallen below its recorded floor;
  * measured proof debt has not exceeded its explicit budget;
  * every body/tunnel sink is grant-required and path/target bound;
  * the inode-bound sink count has not fallen;
  * Verus reports no error-level assumptions in the verified crate;
  * unexplained adversarial replay failures stay at zero.

Use --run-verus to also run the Verus verifier as part of the gate.
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
LEDGER = ROOT / "docs" / "verification-status.json"
CVE_MATRIX = ROOT / "docs" / "cve" / "apache2-cve-matrix.json"
VERIFIED_SRC = ROOT / "crates" / "verified" / "src"
STATUS_WEIGHTS = {"mechanized": 1.0, "partial": 0.5, "open": 0.0}
FORBIDDEN_VERUS = re.compile(r"\bassume(?:_specification)?\b|\bexternal_body\b")


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def load_ledger(errors: list[str]) -> dict:
    try:
        data = json.loads(LEDGER.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(errors, f"{LEDGER.relative_to(ROOT)}: {exc}")
        return {}
    if data.get("schema") != 1:
        fail(errors, "schema must be 1")
    return data


def weighted_score(obligations: list[dict], errors: list[str]) -> tuple[float, float]:
    total = 0.0
    achieved = 0.0
    seen: set[str] = set()
    for index, obligation in enumerate(obligations):
        where = f"obligations[{index}]"
        if not isinstance(obligation, dict):
            fail(errors, f"{where}: must be an object")
            continue
        ident = obligation.get("id")
        status = obligation.get("status")
        weight = obligation.get("weight")
        if not isinstance(ident, str) or not ident:
            fail(errors, f"{where}: missing id")
        elif ident in seen:
            fail(errors, f"{where}: duplicate id {ident!r}")
        else:
            seen.add(ident)
        if status not in STATUS_WEIGHTS:
            fail(errors, f"{where}: invalid status {status!r}")
            continue
        if not isinstance(weight, (int, float)) or weight <= 0:
            fail(errors, f"{where}: weight must be positive")
            continue
        total += float(weight)
        achieved += float(weight) * STATUS_WEIGHTS[status]
    if total <= 0:
        fail(errors, "obligation weights must sum to a positive value")
        return 0.0, 0.0
    return achieved, total


def proof_debt(data: dict, errors: list[str]) -> tuple[int, int]:
    debt = data.get("proof_debt")
    if not isinstance(debt, dict):
        fail(errors, "proof_debt must be an object")
        return 0, 0
    groups = [
        "unverified_security_components",
        "partially_bound_sinks",
        "assumptions",
        "unmodeled_security_directive_classes",
    ]
    values: list[int] = []
    seen: set[str] = set()
    for group in groups:
        items = debt.get(group)
        if not isinstance(items, list):
            fail(errors, f"proof_debt.{group} must be a list")
            values.append(0)
            continue
        for index, item in enumerate(items):
            if not isinstance(item, str) or not item.strip():
                fail(errors, f"proof_debt.{group}[{index}] must be a non-empty string")
            elif item in seen:
                fail(errors, f"proof_debt.{group}[{index}]: duplicate debt item {item!r}")
            else:
                seen.add(item)
        values.append(len(items))
    total = sum(values)
    budget = debt.get("max_total")
    if not isinstance(budget, int) or budget < 0:
        fail(errors, "proof_debt.max_total must be a non-negative integer")
        budget = 0
    if total > budget:
        fail(
            errors,
            f"proof debt increased to {total}, above explicit budget {budget}; "
            "document the new debt and raise max_total deliberately, or remove it",
        )
    category_budgets = {
        "unverified_security_components": "max_unverified_security_components",
        "partially_bound_sinks": "max_partially_bound_sinks",
        "assumptions": "max_assumptions",
        "unmodeled_security_directive_classes": "max_unmodeled_security_directive_classes",
    }
    for group, budget_field in category_budgets.items():
        items = debt.get(group, [])
        group_budget = debt.get(budget_field)
        if not isinstance(group_budget, int) or group_budget < 0:
            fail(errors, f"proof_debt.{budget_field} must be a non-negative integer")
            continue
        if len(items) > group_budget:
            fail(
                errors,
                f"proof_debt.{group} increased to {len(items)}, above category budget "
                f"{group_budget}",
            )
    return total, budget


def check_sinks(data: dict, errors: list[str]) -> dict:
    sinks = data.get("sinks")
    if not isinstance(sinks, dict):
        fail(errors, "sinks must be an object")
        return {}
    fields = [
        "total",
        "grant_required",
        "path_target_bound",
        "inode_bound",
        "backend_target_bound",
        "policy_key_bound",
        "minimum_inode_bound",
        "minimum_backend_target_bound",
        "minimum_policy_key_bound",
    ]
    for field in fields:
        value = sinks.get(field)
        if not isinstance(value, int) or value < 0:
            fail(errors, f"sinks.{field} must be a non-negative integer")
            return sinks
    if sinks["grant_required"] != sinks["total"]:
        fail(errors, "every body/tunnel sink must be grant-required")
    if sinks["path_target_bound"] > sinks["total"]:
        fail(errors, "path_target_bound cannot exceed total sinks")
    if sinks["inode_bound"] > sinks["total"]:
        fail(errors, "inode_bound cannot exceed total sinks")
    if sinks["inode_bound"] < sinks["minimum_inode_bound"]:
        fail(errors, "inode-bound sink count regressed below its floor")
    if sinks["backend_target_bound"] < sinks["minimum_backend_target_bound"]:
        fail(errors, "backend-target-bound sink count regressed below its floor")
    if sinks["backend_target_bound"] > sinks["total"]:
        fail(errors, "backend_target_bound cannot exceed total sinks")
    if sinks["policy_key_bound"] > sinks["total"]:
        fail(errors, "policy_key_bound cannot exceed total sinks")
    if sinks["policy_key_bound"] < sinks["minimum_policy_key_bound"]:
        fail(errors, "policy-key-bound sink count regressed below its floor")
    return sinks


def check_verus_source(errors: list[str]) -> int:
    count = 0
    if not VERIFIED_SRC.exists():
        fail(errors, f"missing verified source directory: {VERIFIED_SRC}")
        return count
    for path in sorted(VERIFIED_SRC.rglob("*.rs")):
        try:
            text = path.read_text()
        except OSError as exc:
            fail(errors, f"{path.relative_to(ROOT)}: {exc}")
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if FORBIDDEN_VERUS.search(line):
                count += 1
                fail(
                    errors,
                    f"{path.relative_to(ROOT)}:{lineno}: unapproved proof escape "
                    f"(assume/external_body): {line.strip()}",
                )
    return count


def check_replay(data: dict, errors: list[str]) -> int:
    replay = data.get("adversarial")
    if not isinstance(replay, dict):
        fail(errors, "adversarial must be an object")
        return 0
    triage = replay.get("cve_triage_cases")
    uncovered = replay.get("cve_not_covered")
    uncovered_max = replay.get("max_cve_not_covered")
    partial = replay.get("cve_partial")
    uncovered_hc = replay.get("cve_not_covered_high_critical")
    uncovered_hc_max = replay.get("max_cve_not_covered_high_critical")
    for name, value in (
        ("cve_triage_cases", triage),
        ("cve_not_covered", uncovered),
        ("max_cve_not_covered", uncovered_max),
        ("cve_partial", partial),
        ("cve_not_covered_high_critical", uncovered_hc),
        ("max_cve_not_covered_high_critical", uncovered_hc_max),
    ):
        if not isinstance(value, int) or value < 0:
            fail(errors, f"adversarial.{name} must be a non-negative integer")
    if isinstance(uncovered, int) and isinstance(uncovered_max, int) and uncovered > uncovered_max:
        fail(
            errors,
            f"not-covered CVE count increased to {uncovered}, above budget {uncovered_max}",
        )
    if (
        isinstance(uncovered_hc, int)
        and isinstance(uncovered_hc_max, int)
        and uncovered_hc > uncovered_hc_max
    ):
        fail(
            errors,
            f"high/critical not-covered CVE count increased to {uncovered_hc}, "
            f"above budget {uncovered_hc_max}",
        )
    if CVE_MATRIX.exists():
        try:
            matrix = json.loads(CVE_MATRIX.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            fail(errors, f"{CVE_MATRIX.relative_to(ROOT)}: {exc}")
        else:
            actual_cases = len(matrix)
            actual_uncovered = sum(1 for row in matrix if row.get("status") == "not_covered")
            actual_partial = sum(1 for row in matrix if row.get("status") == "partial")
            actual_uncovered_hc = sum(
                1
                for row in matrix
                if row.get("status") == "not_covered"
                and row.get("severity") in ("critical", "high")
            )
            for name, actual, expected in (
                ("cve_triage_cases", actual_cases, triage),
                ("cve_not_covered", actual_uncovered, uncovered),
                ("cve_partial", actual_partial, partial),
                ("cve_not_covered_high_critical", actual_uncovered_hc, uncovered_hc),
            ):
                if actual != expected:
                    fail(
                        errors,
                        f"adversarial.{name} is {expected} in the ledger but {actual} in the CVE matrix",
                    )
    else:
        fail(errors, f"missing CVE matrix: {CVE_MATRIX.relative_to(ROOT)}")
    failures = replay.get("unexplained_replay_failures")
    maximum = replay.get("max_unexplained_replay_failures")
    if not isinstance(failures, int) or failures < 0:
        fail(errors, "adversarial.unexplained_replay_failures must be a non-negative integer")
        return 0
    if not isinstance(maximum, int) or maximum < 0:
        fail(errors, "adversarial.max_unexplained_replay_failures must be a non-negative integer")
        return 0
    if failures > maximum:
        fail(
            errors,
            f"unexplained replay failures increased to {failures}, above budget {maximum}",
        )
    return failures


def run_verus(errors: list[str]) -> None:
    env = os.environ.copy()
    home = Path.home()
    env["PATH"] = (
        f"{home / '.cargo' / 'bin'}:{home / 'verus-bin'}:"
        + env.get("PATH", "")
    )
    proc = subprocess.run(
        ["cargo", "verus", "verify", "-p", "httpd-rs-verified"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        fail(errors, "cargo verus verify failed:\n" + (proc.stdout + proc.stderr)[-3000:])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-verus", action="store_true", help="run cargo verus verify as part of the gate")
    parser.add_argument("--json", action="store_true", help="emit the computed report as JSON")
    args = parser.parse_args()

    errors: list[str] = []
    data = load_ledger(errors)
    if not data:
        print("\n".join(errors), file=sys.stderr)
        return 1

    achieved, total = weighted_score(data.get("obligations", []), errors)
    if total and achieved < float(data.get("minimum_weighted_score", 0)):
        fail(
            errors,
            f"weighted obligation score {achieved:.2f}/{total:.2f} fell below floor "
            f"{data.get('minimum_weighted_score')}",
        )

    debt_total, debt_budget = proof_debt(data, errors)
    sinks = check_sinks(data, errors)
    escapes = check_verus_source(errors)
    replay_failures = check_replay(data, errors)
    verus = data.get("verus", {})
    if verus.get("errors") != 0:
        fail(errors, "verus.errors must be 0")
    if args.run_verus:
        run_verus(errors)

    report = {
        "weighted_obligations": round(achieved, 3),
        "obligation_weight": round(total, 3),
        "weighted_percent": round(100.0 * achieved / total, 1) if total else 0.0,
        "proof_debt": debt_total,
        "proof_debt_budget": debt_budget,
        "sinks": sinks,
        "proof_escapes": escapes,
        "unexplained_replay_failures": replay_failures,
        "verus": verus,
        "errors": errors,
    }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("verification status")
        print(f"  weighted obligations: {achieved:.2f}/{total:.2f} ({report['weighted_percent']:.1f}%)")
        print(f"  proof debt: {debt_total}/{debt_budget}")
        if sinks:
            print(
                "  sinks: "
                f"{sinks.get('grant_required')}/{sinks.get('total')} grant-required, "
                f"{sinks.get('path_target_bound')}/{sinks.get('total')} path-target-bound, "
                f"{sinks.get('inode_bound')}/{sinks.get('total')} inode-bound, "
                f"{sinks.get('backend_target_bound')}/{sinks.get('total')} backend-target-bound, "
                f"{sinks.get('policy_key_bound')}/{sinks.get('total')} policy-key-bound"
            )
        print(f"  proof escapes: {escapes}")
        print(f"  unexplained replay failures: {replay_failures}")
        if isinstance(data.get("adversarial"), dict):
            print(
                "  CVE triage: "
                f"{data['adversarial'].get('cve_triage_cases')} cases, "
                f"{data['adversarial'].get('cve_not_covered')} not covered "
                f"({data['adversarial'].get('cve_not_covered_high_critical')} high/critical), "
                f"{data['adversarial'].get('cve_partial')} partial"
            )
        if verus:
            print(f"  verus: {verus.get('verified_functions')} functions, {verus.get('errors')} errors")
        if errors:
            print("\nerrors:", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
        else:
            print("  gate: pass")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
