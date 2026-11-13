#!/usr/bin/env python3
"""Extract and validate the Apache-derived fuzzing warrant inventory.

This tool deliberately separates observation from support policy:

* the source manifest records what exists in one pinned Apache source release;
* the policy records the narrow httpd-rs compatibility surface and its evidence;
* the ledger classifies every observed source item without changing httpd-rs.

An Apache item that is not named by an explicit compatibility claim remains
outside the claimed surface.  Regenerating the source manifest changes its
digest, so the policy must be consciously re-acknowledged before CI passes.
Discovery can therefore create a review obligation, never a support claim.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import json
import re
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "docs" / "apache-source-manifest.json"
POLICY = ROOT / "docs" / "apache-warrant-policy.json"
LEDGER = ROOT / "docs" / "apache-warrant-ledger.json"
SCHEMA = 1
EXTRACTOR = "apache-warrant-v1"

SOURCE_SUFFIXES = {".c", ".h"}
# Runtime server source. `support/` contains separate command-line programs and
# `srclib/` contains independently versioned libraries rather than httpd's
# request/configuration implementation.
SOURCE_ROOTS = ("include", "server", "modules", "os")
TEST_ROOTS = ("test",)
CALL_KINDS = {
    "hook": re.compile(r"\b(ap_hook_[A-Za-z0-9_]+)\s*\("),
    "provider": re.compile(r"\b(ap_register_provider)\s*\("),
    "input_filter": re.compile(r"\b(ap_register_input_filter(?:_protocol)?)\s*\("),
    "output_filter": re.compile(r"\b(ap_register_output_filter(?:_protocol)?)\s*\("),
}
DIRECTIVE_CALL = re.compile(r"\b(AP_INIT_[A-Z0-9_]+)\s*\(")
CONFIG_CALLBACK = re.compile(
    r"(?m)^\s*(?:static\s+)?(?:AP_DECLARE\([^)]*\)\s*)?"
    r"(?:const\s+)?(?:void|char)\s*\*\s*"
    r"([A-Za-z_][A-Za-z0-9_]*(?:create|merge)[A-Za-z0-9_]*config[A-Za-z0-9_]*)\s*\("
)


class WarrantError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise WarrantError(f"cannot read {path.relative_to(ROOT)}: {error}") from error


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def strip_comments(text: str) -> str:
    """Blank C comments while preserving strings, newlines, and byte offsets."""

    output = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char in {'"', "'"}:
                state = "string"
                quote = char
            elif char == "/" and following == "*":
                output[index] = output[index + 1] = " "
                state = "block"
                index += 1
            elif char == "/" and following == "/":
                output[index] = output[index + 1] = " "
                state = "line"
                index += 1
        elif state == "string":
            if char == "\\":
                index += 1
            elif char == quote:
                state = "code"
        elif state == "block":
            if char == "*" and following == "/":
                output[index] = output[index + 1] = " "
                state = "code"
                index += 1
            elif char != "\n":
                output[index] = " "
        elif state == "line":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        index += 1
    return "".join(output)


def call_body(text: str, opening: int) -> tuple[str, int] | None:
    depth = 1
    index = opening + 1
    state = "code"
    quote = ""
    while index < len(text):
        char = text[index]
        if state == "code":
            if char in {'"', "'"}:
                state = "string"
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return text[opening + 1 : index], index + 1
        else:
            if char == "\\":
                index += 1
            elif char == quote:
                state = "code"
        index += 1
    return None


def split_arguments(body: str) -> list[str]:
    arguments: list[str] = []
    start = 0
    depth = 0
    state = "code"
    quote = ""
    index = 0
    while index < len(body):
        char = body[index]
        if state == "code":
            if char in {'"', "'"}:
                state = "string"
                quote = char
            elif char in "({[":
                depth += 1
            elif char in ")}]":
                depth = max(0, depth - 1)
            elif char == "," and depth == 0:
                arguments.append(" ".join(body[start:index].split()))
                start = index + 1
        else:
            if char == "\\":
                index += 1
            elif char == quote:
                state = "code"
        index += 1
    arguments.append(" ".join(body[start:].split()))
    return arguments


def string_value(expression: str) -> str | None:
    literals = re.findall(r'"((?:\\.|[^"\\])*)"', expression)
    remainder = re.sub(r'"(?:\\.|[^"\\])*"', "", expression).strip()
    if not literals or remainder:
        return None
    try:
        return "".join(ast.literal_eval(f'"{value}"') for value in literals)
    except (SyntaxError, ValueError):
        return None


def component_for(relative: str) -> str:
    path = Path(relative)
    if relative.startswith("include/"):
        return "include"
    if relative.startswith("server/"):
        return "server"
    stem = path.stem
    if stem.startswith("mod_"):
        return stem
    parts = path.parts
    return "/".join(parts[:2]) if len(parts) > 1 else stem


def calls(text: str, pattern: re.Pattern[str]) -> Iterable[tuple[re.Match[str], list[str]]]:
    for match in pattern.finditer(text):
        opening = text.find("(", match.start(), match.end() + 1)
        if opening < 0:
            continue
        parsed = call_body(text, opening)
        if parsed is None:
            continue
        body, _ = parsed
        yield match, split_arguments(body)


def source_files(source: Path) -> Iterable[Path]:
    for root_name in SOURCE_ROOTS:
        root = source / root_name
        if not root.is_dir():
            raise WarrantError(f"Apache source is missing {root_name}/")
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix in SOURCE_SUFFIXES:
                yield path


def external_test_category(relative: str) -> str:
    if relative.startswith("t/") and relative.endswith(".t"):
        return "perl-test"
    if relative.startswith("t/conf/"):
        return "fixture-or-config"
    if relative.startswith("c-modules/"):
        return "test-module"
    if relative.startswith("scripts/"):
        return "test-helper"
    if relative.startswith("Apache-Test/"):
        return "test-framework"
    return "repository-support"


def extract_external_tests(source: Path, pin: dict[str, Any]) -> tuple[list[dict[str, str]], dict[str, Any]]:
    if not (source / "t").is_dir() or not (source / "Apache-Test").exists():
        raise WarrantError("apache-httpd-test source is missing t/ or Apache-Test")
    files: list[dict[str, str]] = []
    for path in sorted(source.rglob("*")):
        if not path.is_file() or ".git" in path.relative_to(source).parts:
            continue
        relative = path.relative_to(source).as_posix()
        files.append(
            {
                "id": f"external_upstream_test:{relative}",
                "source": relative,
                "category": external_test_category(relative),
            }
        )
    suite = {
        "name": "apache-httpd-test",
        "status": "pinned-inventory",
        "pin": pin,
        "files": len(files),
        "warrant": (
            "Inventory only: every file is evidence to triage, never an implied httpd-rs "
            "support claim. Execution and semantic mapping remain separate work."
        ),
    }
    return files, suite


def extract_source(
    source: Path,
    source_pin: dict[str, Any],
    external_tests_source: Path | None = None,
    external_tests_pin: dict[str, Any] | None = None,
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    apache_source_paths = list(source_files(source))
    observed_source_files: list[dict[str, str]] = []
    for path in apache_source_paths:
        relative = path.relative_to(source).as_posix()
        observed_source_files.append(
            {"source": relative, "component": component_for(relative)}
        )
        original = path.read_text(encoding="utf-8", errors="replace")
        text = strip_comments(original)
        component = component_for(relative)
        public_header = relative.startswith("include/")

        for match, arguments in calls(text, DIRECTIVE_CALL):
            if not arguments:
                continue
            name = string_value(arguments[0])
            # Public headers define the AP_INIT_* macros themselves. Preserve
            # literal command-table fragments such as LISTEN_COMMANDS, but do
            # not mistake the macro definitions for dynamic registrations.
            if public_header and name is None:
                continue
            if name is None:
                name = f"<dynamic:{arguments[0][:80]}>"
            line = text.count("\n", 0, match.start()) + 1
            items.append(
                {
                    "id": f"directive:{relative}:{line}:{name.lower()}",
                    "kind": "directive",
                    "name": name,
                    "component": component,
                    "source": relative,
                    "line": line,
                    "macro": match.group(1),
                    "handler": arguments[1] if len(arguments) > 1 else "",
                    "context": arguments[3] if len(arguments) > 3 else "",
                }
            )

        for kind, pattern in CALL_KINDS.items():
            if public_header:
                continue
            for match, arguments in calls(text, pattern):
                call = match.group(1)
                line = text.count("\n", 0, match.start()) + 1
                if kind == "hook":
                    name = call.removeprefix("ap_hook_")
                    detail = arguments[0] if arguments else ""
                else:
                    name = string_value(arguments[0]) if arguments else None
                    name = name or (arguments[0][:80] if arguments else "<missing>")
                    detail = ", ".join(arguments[1:3])
                items.append(
                    {
                        "id": f"{kind}:{relative}:{line}:{name}",
                        "kind": kind,
                        "name": name,
                        "component": component,
                        "source": relative,
                        "line": line,
                        "call": call,
                        "detail": detail,
                    }
                )

        for match in CONFIG_CALLBACK.finditer(text):
            name = match.group(1)
            line = text.count("\n", 0, match.start()) + 1
            items.append(
                {
                    "id": f"config_callback:{relative}:{line}:{name}",
                    "kind": "config_callback",
                    "name": name,
                    "component": component,
                    "source": relative,
                    "line": line,
                }
            )

    upstream_tests: list[dict[str, str]] = []
    test_candidates: set[Path] = set()
    for root_name in TEST_ROOTS:
        root = source / root_name
        if root.is_dir():
            test_candidates.update(path for path in root.rglob("*") if path.is_file())
    modules = source / "modules"
    test_candidates.update(path for path in modules.glob("**/test/**/*") if path.is_file())
    for path in sorted(test_candidates):
        relative = path.relative_to(source).as_posix()
        upstream_tests.append({"id": f"upstream_test:{relative}", "source": relative})

    items.sort(key=lambda item: (item["source"], item["line"], item["kind"], item["id"]))
    components = sorted({item["component"] for item in observed_source_files})
    if external_tests_source is None or external_tests_pin is None:
        external_upstream_tests: list[dict[str, str]] = []
        external_suite = {
            "name": "apache-httpd-test",
            "status": "not-inventoried",
            "warrant": "A pinned external test source was not supplied to the extractor.",
        }
    else:
        external_upstream_tests, external_suite = extract_external_tests(
            external_tests_source, external_tests_pin
        )

    body = {
        "schema": SCHEMA,
        "extractor": EXTRACTOR,
        "source_pin": source_pin,
        "components": components,
        "source_files": observed_source_files,
        "items": items,
        "upstream_tests": upstream_tests,
        "external_upstream_tests": external_upstream_tests,
        "external_test_suites": [external_suite],
    }
    body["inventory_sha256"] = digest(body)
    return body


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def evidence_exists(reference: str) -> bool:
    path_text = reference.split("::", 1)[0]
    return (ROOT / path_text).exists()


def python_string_list(path: Path, variable: str) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == variable for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                break
            return value
    raise WarrantError(f"cannot find literal {variable} in {path.relative_to(ROOT)}")


def differential_module_literals() -> set[str]:
    modules: set[str] = set()
    load_module = re.compile(r"LoadModule\s+([A-Za-z0-9_]+_module)\b")
    for base in (ROOT / "tests", ROOT / "adversarial"):
        for path in base.rglob("*.py"):
            modules.update(load_module.findall(path.read_text(encoding="utf-8", errors="replace")))
    # Invalid LoadModule syntax is itself a parser test, not an oracle module.
    modules.discard("dummy_module")
    return modules


def rust_array_strings(function: str) -> set[str]:
    text = (ROOT / "crates" / "server" / "src" / "config.rs").read_text(encoding="utf-8")
    match = re.search(rf"\bfn\s+{re.escape(function)}\s*\(", text)
    if match is None:
        raise WarrantError(f"cannot locate Rust directive registry function {function}")
    opening = text.find("[", match.end())
    if opening < 0:
        raise WarrantError(f"cannot locate array in Rust directive registry function {function}")
    depth = 0
    quote = False
    escaped = False
    for index in range(opening, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
        elif char == '"':
            quote = True
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return {value.lower() for value in re.findall(r'"([^"]+)"', text[opening : index + 1])}
    raise WarrantError(f"unterminated array in Rust directive registry function {function}")


def validate_inputs(manifest: dict[str, Any], policy: dict[str, Any]) -> None:
    errors: list[str] = []
    if manifest.get("schema") != SCHEMA or policy.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    stored_hash = manifest.get("inventory_sha256")
    unhashed = dict(manifest)
    unhashed.pop("inventory_sha256", None)
    actual_hash = digest(unhashed)
    if stored_hash != actual_hash:
        errors.append("apache-source-manifest.json inventory_sha256 is stale")
    if policy.get("acknowledged_inventory_sha256") != stored_hash:
        errors.append(
            "Apache inventory changed without policy review; inspect the diff and update "
            "acknowledged_inventory_sha256 (this does not add support)"
        )
    if policy.get("source_pin") != manifest.get("source_pin"):
        errors.append("policy and source manifest pins differ")
    external_suites = manifest.get("external_test_suites", [])
    if len(external_suites) != 1:
        errors.append("source manifest must contain exactly one apache-httpd-test suite")
    else:
        external_suite = external_suites[0]
        if external_suite.get("name") != "apache-httpd-test":
            errors.append("external test suite must be apache-httpd-test")
        if external_suite.get("status") != "pinned-inventory":
            errors.append("apache-httpd-test must have a pinned inventory")
        if external_suite.get("pin") != policy.get("upstream_test_pin"):
            errors.append("policy and apache-httpd-test inventory pins differ")
        if external_suite.get("files") != len(manifest.get("external_upstream_tests", [])):
            errors.append("apache-httpd-test inventory file count is stale")
    external_ids = [item.get("id") for item in manifest.get("external_upstream_tests", [])]
    if not external_ids:
        errors.append("apache-httpd-test inventory is empty")
    if len(external_ids) != len(set(external_ids)):
        errors.append("apache-httpd-test inventory has duplicate ids")
    if policy.get("default_disposition") != "outside-claimed-surface":
        errors.append("default_disposition must remain outside-claimed-surface")
    if policy.get("support_expansion") != "explicit-claim-with-evidence-only":
        errors.append("support_expansion guardrail was weakened")
    if policy.get("compatibility_claim_semantics") != (
        "directive-entry-point-only; syntax-context-and-semantics-remain-evidence-bounded"
    ):
        errors.append("compatibility claim semantics were broadened")

    items = manifest.get("items", [])
    item_ids = [item.get("id") for item in items]
    if len(item_ids) != len(set(item_ids)):
        errors.append("source manifest has duplicate item ids")
    observed_source_files = [item.get("source") for item in manifest.get("source_files", [])]
    if not observed_source_files:
        errors.append("source manifest has no runtime source-file inventory")
    if len(observed_source_files) != len(set(observed_source_files)):
        errors.append("source manifest has duplicate runtime source files")
    directive_names = {
        item["name"].lower() for item in items if item.get("kind") == "directive"
    }

    family_ids: set[str] = set()
    matched_in_scope: set[str] = set()
    for family in policy.get("families", []):
        family_id = family.get("id")
        if not family_id or family_id in family_ids:
            errors.append(f"missing or duplicate family id: {family_id!r}")
            continue
        family_ids.add(family_id)
        patterns = family.get("source_globs", [])
        if not patterns:
            errors.append(f"family {family_id} has no source_globs")
        matches = [item for item in items if matches_any(item["source"], patterns)]
        if not matches:
            errors.append(f"family {family_id} matches no Apache source items")
        matched_in_scope.update(item["id"] for item in matches)
        evidence = family.get("evidence", [])
        if not evidence:
            errors.append(f"family {family_id} has no httpd-rs evidence")
        for reference in evidence:
            if not evidence_exists(reference):
                errors.append(f"family {family_id} evidence does not exist: {reference}")
        if family.get("compatibility") not in {
            "explicit-subset-only",
            "security-refinement",
            "protocol-oracle",
        }:
            errors.append(f"family {family_id} has invalid compatibility disposition")
        minimum = family.get("minimum_covered_apache_branches")
        if not isinstance(minimum, int) or minimum <= 0:
            errors.append(f"family {family_id} has no positive Apache branch-coverage ratchet")

    excluded_ids: set[str] = set()
    for exclusion in policy.get("deliberately_unsupported", []):
        exclusion_id = exclusion.get("id")
        if not exclusion_id or exclusion_id in excluded_ids:
            errors.append(f"missing or duplicate exclusion id: {exclusion_id!r}")
            continue
        excluded_ids.add(exclusion_id)
        patterns = exclusion.get("source_globs", [])
        names = {name.lower() for name in exclusion.get("directives", [])}
        if not patterns and not names:
            errors.append(f"exclusion {exclusion_id} has no source or directive selector")
        if names - directive_names:
            errors.append(
                f"exclusion {exclusion_id} names absent Apache directives: "
                + ", ".join(sorted(names - directive_names))
            )
        for reference in exclusion.get("evidence", []):
            if not evidence_exists(reference):
                errors.append(f"exclusion {exclusion_id} evidence does not exist: {reference}")

    claimed: set[str] = set()
    for claim in policy.get("compatibility_claims", []):
        name = str(claim.get("directive", "")).lower()
        if not name or name in claimed:
            errors.append(f"missing or duplicate compatibility directive claim: {name!r}")
            continue
        claimed.add(name)
        if name not in directive_names:
            errors.append(f"compatibility claim is absent from Apache source: {name}")
        if claim.get("family") not in family_ids:
            errors.append(f"compatibility claim {name} names unknown family")
        evidence = claim.get("evidence", [])
        if not evidence:
            errors.append(f"compatibility claim {name} has no evidence")
        for reference in evidence:
            if not evidence_exists(reference):
                errors.append(f"compatibility claim {name} evidence does not exist: {reference}")
        if claim.get("disposition") not in {"supported-subset", "deliberately-stricter"}:
            errors.append(f"compatibility claim {name} has invalid disposition")

    overlap = claimed & {
        name.lower()
        for exclusion in policy.get("deliberately_unsupported", [])
        for name in exclusion.get("directives", [])
    }
    if overlap:
        errors.append("directives cannot be both claimed and unsupported: " + ", ".join(sorted(overlap)))

    with (ROOT / "fuzz" / "Cargo.toml").open("rb") as stream:
        fuzz_toml = tomllib.load(stream)
    fuzz_targets = {entry["name"] for entry in fuzz_toml.get("bin", [])}
    warranted_targets: set[str] = set()
    families_with_targets: set[str] = set()
    allowed_authorities = {
        "apache-source-and-binary",
        "historical-adversarial-finding",
        "internal-security-invariant",
        "protocol-specification",
        "upstream-reference-oracle",
    }
    for warrant in policy.get("fuzz_warrants", []):
        warrant_id = warrant.get("id", "<missing>")
        authorities = set(warrant.get("authorities", []))
        if not authorities or authorities - allowed_authorities:
            errors.append(f"fuzz warrant {warrant_id} has invalid authorities")
        targets = set(warrant.get("targets", []))
        if not targets:
            errors.append(f"fuzz warrant {warrant_id} has no targets")
        if targets - fuzz_targets:
            errors.append(
                f"fuzz warrant {warrant_id} names unknown targets: "
                + ", ".join(sorted(targets - fuzz_targets))
            )
        warranted_targets.update(targets)
        if not warrant.get("state_dimensions"):
            errors.append(f"fuzz warrant {warrant_id} has no state_dimensions")
        for family_id in warrant.get("families", []):
            if family_id not in family_ids:
                errors.append(f"fuzz warrant {warrant_id} names unknown family {family_id}")
            elif targets:
                families_with_targets.add(family_id)
        evidence = warrant.get("evidence", [])
        if not evidence:
            errors.append(f"fuzz warrant {warrant_id} has no evidence")
        for reference in evidence:
            if not evidence_exists(reference):
                errors.append(f"fuzz warrant {warrant_id} evidence does not exist: {reference}")
    if warranted_targets != fuzz_targets:
        errors.append(
            "fuzz target warrant closure failed: "
            f"missing={sorted(fuzz_targets - warranted_targets)} "
            f"extra={sorted(warranted_targets - fuzz_targets)}"
        )
    if families_with_targets != family_ids:
        errors.append(
            "Apache warrant family closure failed: every in-scope family must map to at "
            f"least one fuzz target; missing={sorted(family_ids - families_with_targets)}"
        )
    semantic = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "fuzz_report.py"), "--check-specs"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if semantic.returncode != 0:
        errors.append(
            "fuzz semantic census closure failed: "
            + (semantic.stderr or semantic.stdout).strip()
        )

    expected_modules = set(policy.get("oracle_modules", []))
    actual_modules = set(
        python_string_list(ROOT / "tests" / "config_validity.py", "MODULES")
        + python_string_list(ROOT / "tests" / "config_semantics.py", "APACHE_MODULES")
    )
    actual_modules.update(differential_module_literals())
    if expected_modules != actual_modules:
        errors.append(
            "oracle_modules drift from the configuration differential harnesses: "
            f"missing={sorted(actual_modules - expected_modules)} "
            f"extra={sorted(expected_modules - actual_modules)}"
        )

    if not matched_in_scope:
        errors.append("policy has no Apache-derived in-scope source items")
    if errors:
        raise WarrantError("\n".join(f"- {error}" for error in errors))


def render_ledger(manifest: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    families = policy["families"]
    claims = {claim["directive"].lower(): claim for claim in policy["compatibility_claims"]}
    exclusions = policy["deliberately_unsupported"]
    known_directives = rust_array_strings("known_directives")
    forced_reject = rust_array_strings("fail_closed_directives")
    apache_directives = {
        item["name"].lower()
        for item in manifest["items"]
        if item["kind"] == "directive" and not item["name"].startswith("<dynamic:")
    }
    source_file_ledger: list[dict[str, Any]] = []
    source_file_counts: dict[str, int] = {}
    for source_file in manifest["source_files"]:
        source = source_file["source"]
        family_ids = [
            family["id"] for family in families if matches_any(source, family["source_globs"])
        ]
        exclusion_ids = [
            exclusion["id"]
            for exclusion in exclusions
            if matches_any(source, exclusion.get("source_globs", []))
        ]
        if exclusion_ids:
            disposition = "deliberately-unsupported"
        elif family_ids:
            disposition = "warrant-source-only"
        else:
            disposition = policy["default_disposition"]
        source_file_counts[disposition] = source_file_counts.get(disposition, 0) + 1
        source_file_ledger.append(
            {
                **source_file,
                "disposition": disposition,
                "families": sorted(family_ids),
                "exclusions": sorted(exclusion_ids),
            }
        )
    ledger_items: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for item in manifest["items"]:
        family_ids = [
            family["id"]
            for family in families
            if matches_any(item["source"], family["source_globs"])
        ]
        exclusion_ids = [
            exclusion["id"]
            for exclusion in exclusions
            if matches_any(item["source"], exclusion.get("source_globs", []))
            or (
                item["kind"] == "directive"
                and item["name"].lower()
                in {name.lower() for name in exclusion.get("directives", [])}
            )
        ]
        claim = claims.get(item["name"].lower()) if item["kind"] == "directive" else None
        if claim is not None:
            disposition = claim["disposition"]
            family_ids = sorted(set([*family_ids, claim["family"]]))
        elif exclusion_ids:
            disposition = "deliberately-unsupported"
        elif family_ids:
            disposition = "warrant-source-only"
        else:
            disposition = policy["default_disposition"]
        counts[disposition] = counts.get(disposition, 0) + 1
        ledger_item = {
                "id": item["id"],
                "kind": item["kind"],
                "name": item["name"],
                "source": item["source"],
                "line": item["line"],
                "component": item["component"],
                "disposition": disposition,
                "families": sorted(set(family_ids)),
                "exclusions": sorted(set(exclusion_ids)),
            }
        if item["kind"] == "directive":
            directive = item["name"].lower()
            if claim is not None:
                parser_relation = "explicit-compatibility-claim"
            elif directive in forced_reject:
                parser_relation = "explicit-fail-closed"
            elif directive in known_directives:
                parser_relation = "recognized-without-support-claim"
            else:
                parser_relation = "unknown-fail-closed"
            ledger_item["httpd_rs_parser_relation"] = parser_relation
        ledger_items.append(ledger_item)
    ledger = {
        "schema": SCHEMA,
        "source_inventory_sha256": manifest["inventory_sha256"],
        "policy_sha256": digest(policy),
        "guardrail": (
            "Source discovery is evidence only. Only compatibility_claims can assert support; "
            "all other items remain unsupported, warrant-only, or outside the claimed surface."
        ),
        "summary": {
            "source_items": len(ledger_items),
            "runtime_source_files": len(manifest["source_files"]),
            "source_components": len(manifest["components"]),
            "source_tarball_tests": len(manifest["upstream_tests"]),
            "external_httpd_test_files": len(manifest["external_upstream_tests"]),
            "apache_unique_directives": len(apache_directives),
            "apache_directives_recognized_by_httpd_rs": len(apache_directives & known_directives),
            "apache_directives_unknown_and_fail_closed": len(apache_directives - known_directives),
            "httpd_rs_registry_names_absent_from_pinned_apache": len(known_directives - apache_directives),
            "families": len(families),
            "explicit_compatibility_claims": len(claims),
            "fuzz_targets_with_warrants": len(
                {
                    target
                    for warrant in policy.get("fuzz_warrants", [])
                    for target in warrant.get("targets", [])
                }
            ),
            "dispositions": dict(sorted(counts.items())),
            "source_file_dispositions": dict(sorted(source_file_counts.items())),
            "external_httpd_test_status": manifest["external_test_suites"][0]["status"],
        },
        "families": families,
        "fuzz_warrants": policy.get("fuzz_warrants", []),
        "source_files": source_file_ledger,
        "items": ledger_items,
    }
    ledger["ledger_sha256"] = digest(ledger)
    return ledger


def validate_checked_files() -> dict[str, Any]:
    manifest = read_json(MANIFEST)
    policy = read_json(POLICY)
    validate_inputs(manifest, policy)
    expected = render_ledger(manifest, policy)
    actual = read_json(LEDGER)
    if actual != expected:
        raise WarrantError(
            "docs/apache-warrant-ledger.json is stale; run "
            "python3 tests/apache_warrant.py --write-ledger"
        )
    return expected


def source_pin_from_policy(policy: dict[str, Any]) -> dict[str, Any]:
    pin = policy.get("source_pin")
    if not isinstance(pin, dict):
        raise WarrantError("policy source_pin is missing")
    return pin


def upstream_test_pin_from_policy(policy: dict[str, Any]) -> dict[str, Any]:
    pin = policy.get("upstream_test_pin")
    if not isinstance(pin, dict):
        raise WarrantError("policy upstream_test_pin is missing")
    return pin


def check_binary(policy: dict[str, Any]) -> None:
    executable = Path(os.environ.get("APACHE", "/usr/sbin/apache2"))
    module_dir = Path(os.environ.get("APACHE_MODDIR", "/usr/lib/apache2/modules"))
    if not executable.is_file():
        raise WarrantError(f"Apache oracle is missing: {executable}")
    result = subprocess.run(
        [str(executable), "-v"], capture_output=True, text=True, timeout=30, check=False
    )
    output = result.stdout + result.stderr
    release = policy["source_pin"]["release"]
    if result.returncode != 0 or f"Apache/{release}" not in output:
        raise WarrantError(
            f"Apache oracle is not pinned {release}: return={result.returncode} output={output.strip()!r}"
        )
    missing_modules = []
    for module in policy["oracle_modules"]:
        if module == "mpm_event_module":
            filename = "mod_mpm_event.so"
        else:
            filename = f"mod_{module.removesuffix('_module')}.so"
        if not (module_dir / filename).is_file():
            missing_modules.append(filename)
    if missing_modules:
        raise WarrantError(
            f"Apache oracle module directory {module_dir} is missing: " + ", ".join(missing_modules)
        )
    print(
        f"Apache binary oracle OK: {release}, {len(policy['oracle_modules'])} differential modules available"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, help="extracted pinned Apache source tree")
    parser.add_argument(
        "--httpd-tests-source", type=Path, help="extracted pinned apache-httpd-test tree"
    )
    parser.add_argument("--write-manifest", action="store_true")
    parser.add_argument("--write-ledger", action="store_true")
    parser.add_argument("--check-source", action="store_true")
    parser.add_argument("--check-binary", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    try:
        policy = read_json(POLICY)
        if args.write_manifest or args.check_source:
            if args.source is None or args.httpd_tests_source is None:
                raise WarrantError(
                    "--source and --httpd-tests-source are required with "
                    "--write-manifest/--check-source"
                )
            extracted = extract_source(
                args.source.resolve(),
                source_pin_from_policy(policy),
                args.httpd_tests_source.resolve(),
                upstream_test_pin_from_policy(policy),
            )
            if args.write_manifest:
                write_json(MANIFEST, extracted)
                print(f"wrote {MANIFEST.relative_to(ROOT)} ({len(extracted['items'])} source items)")
            else:
                checked = read_json(MANIFEST)
                if extracted != checked:
                    raise WarrantError("checked-in Apache source manifest differs from pinned source")
                print("Apache source extraction matches the checked-in manifest")
        if args.write_ledger:
            manifest = read_json(MANIFEST)
            validate_inputs(manifest, policy)
            ledger = render_ledger(manifest, policy)
            write_json(LEDGER, ledger)
            print(f"wrote {LEDGER.relative_to(ROOT)} ({len(ledger['items'])} classified items)")
        if args.check_binary:
            check_binary(policy)
        if not (args.write_manifest or args.write_ledger or args.check_source or args.check_binary):
            ledger = validate_checked_files()
            print(
                "Apache warrant ledger OK: "
                f"{ledger['summary']['source_items']} source items, "
                f"{ledger['summary']['families']} families, "
                f"{ledger['summary']['explicit_compatibility_claims']} explicit claims"
            )
            if args.summary:
                print(json.dumps(ledger["summary"], indent=2, sort_keys=True))
    except WarrantError as error:
        print(f"apache-warrant: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
