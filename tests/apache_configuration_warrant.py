#!/usr/bin/env python3
"""Validate configuration-layer security warrants without expanding support.

The source-code warrant inventories Apache implementation entry points. This
parallel ledger records controls that Apache, distributions, service managers,
and benchmark applications supply as configuration. Observing a control can
only create one of four explicit product obligations; it can never turn an
unsupported Apache feature into a compatibility claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "docs" / "apache-configuration-warrant.json"
APACHE_POLICY = ROOT / "docs" / "apache-warrant-policy.json"
SCHEMA = 1
CLASS_TO_ACTION = {
    "intrinsic": "implemented-invariant",
    "generated-baseline": "generated-default",
    "operator-owned": "operator-check",
    "irrelevant-unsupported": "reject-unsupported",
}


class WarrantError(RuntimeError):
    pass


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise WarrantError(f"cannot read {path.relative_to(ROOT)}: {error}") from error


def require_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise WarrantError(f"{where} must be a nonempty string")
    return value


def require_string_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise WarrantError(f"{where} must be a nonempty list")
    return [require_string(item, f"{where}[]") for item in value]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def check_contains(path: Path, needles: list[str], where: str) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise WarrantError(f"cannot read {where}: {error}") from error
    for needle in needles:
        if needle not in text:
            raise WarrantError(f"{where} no longer contains {needle!r}")


def git_head(path: Path) -> str | None:
    if not (path / ".git").exists():
        return None
    process = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.returncode != 0:
        raise WarrantError(f"cannot determine source commit for {path}: {process.stderr.strip()}")
    return process.stdout.strip()


def validate_source_evidence(
    evidence: dict[str, Any],
    pins: dict[str, Any],
    roots: dict[str, Path | None],
    where: str,
) -> str:
    pin_name = require_string(evidence.get("pin"), f"{where}.pin")
    if pin_name not in pins:
        raise WarrantError(f"{where}.pin names unknown source {pin_name!r}")
    relative = Path(require_string(evidence.get("path"), f"{where}.path"))
    if relative.is_absolute() or ".." in relative.parts:
        raise WarrantError(f"{where}.path must be repository-relative within its source")
    expected = require_string(evidence.get("sha256"), f"{where}.sha256")
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        raise WarrantError(f"{where}.sha256 is not a lowercase SHA-256 digest")
    needles = require_string_list(evidence.get("contains"), f"{where}.contains")
    source_root = roots.get(pin_name)
    if source_root is not None:
        path = source_root / relative
        if not path.is_file():
            raise WarrantError(f"{where} source file is missing: {path}")
        actual = sha256(path)
        if actual != expected:
            raise WarrantError(
                f"{where} source hash changed: expected {expected}, observed {actual}"
            )
        check_contains(path, needles, str(path))
    return require_string(pins[pin_name].get("layer"), f"source_pins.{pin_name}.layer")


def validate_local_evidence(evidence: dict[str, Any], where: str) -> str | None:
    relative = Path(require_string(evidence.get("path"), f"{where}.path"))
    if relative.is_absolute() or ".." in relative.parts:
        raise WarrantError(f"{where}.path must be repository-relative")
    path = ROOT / relative
    if not path.is_file():
        raise WarrantError(f"{where} local evidence is missing: {relative}")
    needles = require_string_list(evidence.get("contains"), f"{where}.contains")
    check_contains(path, needles, str(relative))
    layer = evidence.get("layer")
    if layer is None:
        return None
    return require_string(layer, f"{where}.layer")


def validate(ledger: dict[str, Any], roots: dict[str, Path | None]) -> None:
    if ledger.get("schema") != SCHEMA:
        raise WarrantError(f"unsupported schema {ledger.get('schema')!r}")
    if ledger.get("support_effect") != "observation-only":
        raise WarrantError("support_effect must remain exactly 'observation-only'")
    require_string(ledger.get("policy"), "policy")

    classifications = ledger.get("classifications")
    if not isinstance(classifications, dict) or set(classifications) != set(CLASS_TO_ACTION):
        raise WarrantError("classifications must define exactly the four closed dispositions")
    for name, description in classifications.items():
        require_string(description, f"classifications.{name}")

    pins = ledger.get("source_pins")
    if not isinstance(pins, dict) or set(pins) != {"apache", "debian", "ubuntu"}:
        raise WarrantError("source_pins must contain exactly apache, debian, and ubuntu")
    for name, pin in pins.items():
        if not isinstance(pin, dict):
            raise WarrantError(f"source_pins.{name} must be an object")
        require_string(pin.get("layer"), f"source_pins.{name}.layer")

    upstream_policy = read_json(APACHE_POLICY).get("source_pin", {})
    apache_pin = pins["apache"]
    expected_apache = {
        "release": upstream_policy.get("release"),
        "url": upstream_policy.get("archive_url"),
        "sha256": upstream_policy.get("archive_sha256"),
    }
    observed_apache = {key: apache_pin.get(key) for key in expected_apache}
    if observed_apache != expected_apache:
        raise WarrantError(
            "Apache configuration source pin must match docs/apache-warrant-policy.json"
        )

    for name in ("debian", "ubuntu"):
        commit = require_string(pins[name].get("commit"), f"source_pins.{name}.commit")
        if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
            raise WarrantError(f"source_pins.{name}.commit is not a full Git object ID")
        require_string(pins[name].get("repository"), f"source_pins.{name}.repository")
        root = roots.get(name)
        if root is not None:
            observed = git_head(root)
            if observed is not None and observed != commit:
                raise WarrantError(
                    f"{name} source is at {observed}, but the ledger pins {commit}"
                )

    required_layers = set(require_string_list(ledger.get("required_layers"), "required_layers"))
    required_families = set(
        require_string_list(ledger.get("required_families"), "required_families")
    )
    guards = ledger.get("guards")
    if not isinstance(guards, list) or not guards:
        raise WarrantError("guards must be a nonempty list")

    ids: set[str] = set()
    covered_layers: set[str] = set()
    covered_families: set[str] = set()
    source_hashes: dict[tuple[str, str], str] = {}
    for index, guard in enumerate(guards):
        where = f"guards[{index}]"
        if not isinstance(guard, dict):
            raise WarrantError(f"{where} must be an object")
        guard_id = require_string(guard.get("id"), f"{where}.id")
        if guard_id in ids:
            raise WarrantError(f"duplicate guard id {guard_id!r}")
        ids.add(guard_id)
        family = require_string(guard.get("family"), f"{where}.family")
        if family not in required_families:
            raise WarrantError(f"{where}.family is not declared in required_families")
        covered_families.add(family)
        classification = require_string(guard.get("classification"), f"{where}.classification")
        if classification not in CLASS_TO_ACTION:
            raise WarrantError(f"{where}.classification is not a closed disposition")
        action = require_string(guard.get("product_action"), f"{where}.product_action")
        if action != CLASS_TO_ACTION[classification]:
            raise WarrantError(
                f"{where} maps {classification!r} to {action!r}; expected "
                f"{CLASS_TO_ACTION[classification]!r}"
            )
        require_string(guard.get("rationale"), f"{where}.rationale")

        sources = guard.get("sources")
        local = guard.get("local_evidence")
        if not isinstance(sources, list) or not isinstance(local, list) or not local:
            raise WarrantError(f"{where} needs a sources list and nonempty local_evidence")
        for source_index, evidence in enumerate(sources):
            if not isinstance(evidence, dict):
                raise WarrantError(f"{where}.sources[{source_index}] must be an object")
            evidence_where = f"{where}.sources[{source_index}]"
            covered_layers.add(validate_source_evidence(evidence, pins, roots, evidence_where))
            key = (str(evidence["pin"]), str(evidence["path"]))
            previous = source_hashes.setdefault(key, str(evidence["sha256"]))
            if previous != evidence["sha256"]:
                raise WarrantError(f"conflicting hashes for source evidence {key}")
        for local_index, evidence in enumerate(local):
            if not isinstance(evidence, dict):
                raise WarrantError(f"{where}.local_evidence[{local_index}] must be an object")
            layer = validate_local_evidence(
                evidence, f"{where}.local_evidence[{local_index}]"
            )
            if layer is not None:
                covered_layers.add(layer)

    missing_layers = sorted(required_layers - covered_layers)
    if missing_layers:
        raise WarrantError(f"configuration warrant has no evidence for layers: {missing_layers}")
    missing_families = sorted(required_families - covered_families)
    if missing_families:
        raise WarrantError(f"configuration warrant has no guards for families: {missing_families}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apache-source", type=Path)
    parser.add_argument("--debian-source", type=Path)
    parser.add_argument("--ubuntu-source", type=Path)
    args = parser.parse_args()
    roots = {
        "apache": args.apache_source,
        "debian": args.debian_source,
        "ubuntu": args.ubuntu_source,
    }
    try:
        ledger = read_json(LEDGER)
        if not isinstance(ledger, dict):
            raise WarrantError("configuration warrant must be a JSON object")
        validate(ledger, roots)
    except WarrantError as error:
        print(f"apache-configuration-warrant: {error}", file=sys.stderr)
        return 1
    checked = ", ".join(name for name, root in roots.items() if root is not None)
    suffix = f"; pinned sources checked: {checked}" if checked else ""
    print(f"apache-configuration-warrant: PASS{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
