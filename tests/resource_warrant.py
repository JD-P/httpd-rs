#!/usr/bin/env python3
"""Build and reconcile the request-path resource warrant.

The checked static inventory is deliberately lexical and conservative: it
finds effect sinks even when ordinary benchmarks cannot reach them. Runtime
profiles then establish which physical resource classes real deployment and
benchmark cases exercised. Neither half is called a proof. Their union is the
worklist from which typed accounting and Verus refinement obligations are
discharged, and CI rejects any new effect site until that worklist is updated.
"""

from __future__ import annotations

import argparse
import dataclasses
import glob
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "docs" / "resource-warrant-policy.json"
STATIC = ROOT / "docs" / "resource-warrant-static.json"
RAW_STRING = re.compile(r"(?:br|r)(?P<hashes>#{0,16})\"")


@dataclasses.dataclass(frozen=True)
class Rule:
    family: str
    pattern: re.Pattern[str]


def rule(family: str, expression: str) -> Rule:
    return Rule(family, re.compile(expression))


RULES = (
    rule(
        "heap-allocation",
        r"\b(?:Vec|String|Box|HashMap|HashSet|BTreeMap|BTreeSet|VecDeque|BytesMut|Arc|Rc)::"
        r"(?:new|default|with_capacity|from|new_zeroed)|\bvec!\s*\[|\.to_vec\s*\(|"
        r"\.to_owned\s*\(|\.into_boxed|\.collect(?:\s*::\s*<[^;]+?>)?\s*\(",
    ),
    rule(
        "data-growth",
        r"\bread_to_(?:end|string)\s*\(|\bwrite_all\s*\(|\.extend_from_slice\s*\(|"
        r"\.extend\s*\(|\.push_str\s*\(|\.reserve(?:_exact)?\s*\(|\.resize\s*\(",
    ),
    rule(
        "cpu-iteration",
        r"\bfor\s+.+\s+in\s+|\bwhile\s+|\bloop\s*\{|\.for_each\s*\(|\.fold\s*\(|"
        r"\.try_fold\s*\(|\.sort(?:_by|_unstable)?\s*\(|\.binary_search|"
        r"\.position\s*\(|\.rposition\s*\(",
    ),
    rule(
        "task-process",
        r"\b(?:tokio::)?(?:task::)?spawn(?:_blocking)?\s*\(|\bthread::spawn\s*\(|"
        r"\bCommand::new\s*\(|\.spawn\s*\(|\b(?:sync_)?channel\s*\(|"
        r"\bmpsc::(?:channel|unbounded_channel)\s*\(",
    ),
    rule(
        "filesystem",
        r"\b(?:std::)?fs::(?:read|read_to_string|write|copy|rename|remove_|create_dir|metadata|"
        r"symlink_metadata|read_dir|canonicalize)|\bFile::(?:open|create)\s*\(|"
        r"\bOpenOptions::new\s*\(|\.metadata\s*\(|\.read_dir\s*\(|"
        r"\bopenat2?\b|\brenameat2?\b|\bunlinkat\b",
    ),
    rule(
        "network",
        r"\b(?:TcpStream|TcpListener|UnixStream|UnixListener|UdpSocket)::|\.accept\s*\(|"
        r"\.connect\s*\(|\bgetaddrinfo\b|\bToSocketAddrs\b|\bsocket2?\b",
    ),
    rule(
        "synchronization",
        r"\b(?:Mutex|RwLock|Condvar|Semaphore|Notify)::|\.lock\s*\(|\.read\s*\(\s*\)\??|"
        r"\.write\s*\(\s*\)\??|\.acquire(?:_owned)?\s*\(|\.blocking_(?:send|recv)\s*\(|"
        r"\.send\s*\(|\.recv\s*\(",
    ),
    rule(
        "compression-regex-crypto",
        r"\b(?:brotli|flate2|bcrypt|rustls|ring|sha2|regex_automata|httpd_rs_pcre2|pcre2)::|"
        r"\b(?:Regex|RegexBuilder|GzEncoder|CompressorReader|Sha256)::|\.verify\s*\(|"
        r"\.captures(?:_at)?\s*\(|\.is_match\s*\(",
    ),
    rule(
        "unsafe-ffi-syscall",
        r"\bunsafe\s*\{|\blibc::|\bfrom_raw_fd\b|\binto_raw_fd\b|\bBorrowedFd::borrow_raw\b|"
        r"\bsyscall\s*\(|\bffi::|\bextern\s+\"C\"",
    ),
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def load_policy() -> dict[str, Any]:
    try:
        policy = json.loads(POLICY.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"resource-warrant: cannot read {POLICY.relative_to(ROOT)}: {error}")
    if policy.get("schema") != 1:
        raise SystemExit("resource-warrant: policy schema must be 1")
    resource_ids = {item.get("id") for item in policy.get("resources", [])}
    family_ids = {item.get("id") for item in policy.get("effect_families", [])}
    expected_families = {item.family for item in RULES}
    errors = []
    if len(resource_ids) != len(policy.get("resources", [])) or None in resource_ids:
        errors.append("resource IDs must be unique non-empty strings")
    if family_ids != expected_families:
        errors.append(
            f"effect-family policy/rule mismatch: missing={sorted(expected_families - family_ids)} "
            f"extra={sorted(family_ids - expected_families)}"
        )
    for family in policy.get("effect_families", []):
        unknown = set(family.get("resources", [])) - resource_ids
        if unknown:
            errors.append(f"effect family {family.get('id')} has unknown resources {sorted(unknown)}")
        if not family.get("accounting_markers"):
            errors.append(f"effect family {family.get('id')} has no accounting markers")
    for root in policy.get("scope", {}).get("source_roots", []):
        if not (ROOT / root).is_dir():
            errors.append(f"source root does not exist: {root}")
    for excluded in policy.get("scope", {}).get("excluded_paths", []):
        if not (ROOT / excluded).is_file():
            errors.append(f"excluded path does not exist: {excluded}")
    contract_ids: set[str] = set()
    contract_paths: set[str] = set()
    dispositions = {"typed-lease", "proved-constant-bound", "external-assumption"}
    for contract in policy.get("closure_contracts", []):
        identifier = contract.get("id")
        if not identifier or identifier in contract_ids:
            errors.append("closure-contract IDs must be unique non-empty strings")
        contract_ids.add(identifier)
        if contract.get("disposition") not in dispositions:
            errors.append(f"closure contract {identifier} has an invalid disposition")
        if not contract.get("evidence") or not contract.get("verification_targets"):
            errors.append(f"closure contract {identifier} lacks evidence or verification targets")
        for relative in contract.get("paths", []):
            if relative in contract_paths:
                errors.append(f"closure path appears in multiple contracts: {relative}")
            contract_paths.add(relative)
            if not (ROOT / relative).is_file():
                errors.append(f"closure-contract path does not exist: {relative}")
    if errors:
        raise SystemExit("resource-warrant: " + "; ".join(errors))
    return policy


def mask_non_code(source: str) -> str:
    """Replace comments and string contents with spaces while preserving offsets/newlines."""
    output = list(source)
    index = 0
    length = len(source)

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if output[position] != "\n":
                output[position] = " "

    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = length if end < 0 else end
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            blank(start, index)
            continue
        raw = RAW_STRING.match(source, index) if source[index] in {"b", "r"} else None
        if raw:
            start = index
            terminator = '"' + raw.group("hashes")
            index = raw.end()
            end = source.find(terminator, index)
            index = length if end < 0 else end + len(terminator)
            blank(start, index)
            continue
        if source[index] == "'":
            # Do not let the double quote in a Rust character literal such as
            # `'"'` look like the start of a string and mask the remainder of
            # the file. Lifetimes (`'a`, `'static`) have no closing quote and
            # deliberately fall through.
            start = index
            end = None
            if index + 2 < length and source[index + 2] == "'":
                end = index + 3
            elif index + 2 < length and source[index + 1] == "\\":
                escape = source[index + 2]
                if escape in "\\'\"nrt0" and index + 3 < length and source[index + 3] == "'":
                    end = index + 4
                elif escape == "x" and index + 5 < length and source[index + 5] == "'":
                    end = index + 6
                elif escape == "u" and index + 3 < length and source[index + 3] == "{":
                    brace = source.find("}", index + 4, min(length, index + 16))
                    if brace >= 0 and brace + 1 < length and source[brace + 1] == "'":
                        end = brace + 2
            if end is not None:
                blank(start, end)
                index = end
                continue
        if source[index] == '"':
            start = index
            index += 1
            while index < length:
                if source[index] == "\\":
                    index += 2
                elif source[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            blank(start, min(index, length))
            continue
        index += 1
    return "".join(output)


def matching_brace(masked: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(masked) - 1


def strip_test_modules(source: str, masked: str) -> tuple[str, str]:
    pattern = re.compile(
        r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{",
        re.S,
    )
    spans: list[tuple[int, int]] = []
    cursor = 0
    while match := pattern.search(masked, cursor):
        opening = masked.find("{", match.start(), match.end())
        closing = matching_brace(masked, opening)
        spans.append((match.start(), closing + 1))
        cursor = closing + 1
    if not spans:
        return source, masked
    source_chars = list(source)
    masked_chars = list(masked)
    for start, end in spans:
        for position in range(start, end):
            if source_chars[position] != "\n":
                source_chars[position] = " "
                masked_chars[position] = " "
    return "".join(source_chars), "".join(masked_chars)


def check_lexer_invariants() -> None:
    sample = """fn before() { let quote = '\"'; Vec::new(); }
#[cfg(test)]
mod tests { fn hidden() { Vec::new(); } }
fn after<'a>(value: &'a str) { let _ = value; }
"""
    masked = mask_non_code(sample)
    stripped, _ = strip_test_modules(sample, masked)
    if len(masked) != len(sample) or "before" not in stripped or "after" not in stripped:
        raise SystemExit("resource-warrant: lexical masking lost production source")
    if "hidden" in stripped:
        raise SystemExit("resource-warrant: #[cfg(test)] module entered production inventory")


def function_ranges(masked: str) -> list[tuple[int, int, str]]:
    ranges = []
    pattern = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\b")
    for match in pattern.finditer(masked):
        brace = masked.find("{", match.end())
        semicolon = masked.find(";", match.end())
        if brace < 0 or (semicolon >= 0 and semicolon < brace):
            continue
        closing = matching_brace(masked, brace)
        ranges.append((match.start(), closing + 1, match.group(1)))
    return ranges


class FunctionIndex:
    """Resolve monotonically increasing source offsets without an O(lines*functions) scan."""

    def __init__(self, ranges: list[tuple[int, int, str]]):
        self.ranges = sorted(ranges)
        self.cursor = 0
        self.active: list[tuple[int, int, str]] = []

    def owner(self, offset: int) -> tuple[str, tuple[int, int] | None]:
        while self.cursor < len(self.ranges) and self.ranges[self.cursor][0] <= offset:
            self.active.append(self.ranges[self.cursor])
            self.cursor += 1
        self.active = [item for item in self.active if item[1] > offset]
        if not self.active:
            return "<module>", None
        start, end, name = min(self.active, key=lambda item: item[1] - item[0])
        return name, (start, end)


def source_paths(policy: dict[str, Any]) -> list[Path]:
    paths = []
    for relative in policy["scope"]["source_roots"]:
        paths.extend((ROOT / relative).rglob("*.rs"))
    excluded = {ROOT / relative for relative in policy["scope"].get("excluded_paths", [])}
    return sorted(set(paths) - excluded)


def normalized_line(masked_line: str) -> str:
    return re.sub(r"\s+", " ", masked_line.strip())


def classify_site(
    relative: str,
    code: str,
    body_markers: list[str],
    family: dict[str, Any],
    policy: dict[str, Any],
) -> tuple[str, list[str]]:
    local_markers = [marker for marker in family["accounting_markers"] if marker in code]
    if relative.startswith("vendor/"):
        return "external-source-inventory", ["vendored source is scanned; adapter bounds remain separate"]
    if any(relative == path or relative.startswith(path.rstrip("/") + "/") for path in policy["audited_gateways"]):
        return "audited-gateway", local_markers or body_markers[:8]
    if local_markers:
        return "accounting-boundary", local_markers
    if body_markers:
        return "accounted-context", body_markers[:8]
    if re.search(r"\bMAX_[A-Z0-9_]+\b|checked_(?:add|mul|sub)|saturating_(?:add|mul)|\.min\s*\(", code):
        return "local-bound-candidate", []
    return "review-required", []


def close_site(
    relative: str,
    status: str,
    accounting_evidence: list[str],
    policy: dict[str, Any],
) -> dict[str, Any]:
    if relative.startswith("vendor/"):
        return {
            "disposition": "external-assumption",
            "contract": "vendored-source-contract",
            "evidence": "vendored source is inventoried; adapter leases, pinned version and OS backstops bound effects below the local type boundary",
            "verification_targets": ["request_resource_effect_closure"],
        }
    if relative.startswith("crates/os/"):
        return {
            "disposition": "external-assumption",
            "contract": "kernel-syscall-contract",
            "evidence": "the audited OS crate centralizes irreducible kernel effects behind owned descriptors and runtime RLIMIT/cgroup/filesystem backstops",
            "verification_targets": ["unsafe_boundary_closure", "request_resource_effect_closure"],
        }
    if status in {"accounting-boundary", "accounted-context", "audited-gateway"}:
        return {
            "disposition": "typed-lease",
            "contract": f"inferred-{status}",
            "evidence": "the effect is at or inside a reviewed typed accounting boundary"
            + (f" ({', '.join(accounting_evidence)})" if accounting_evidence else ""),
            "verification_targets": ["resource_budget_admit", "request_resource_effect_closure"],
        }
    if status == "local-bound-candidate":
        return {
            "disposition": "proved-constant-bound",
            "contract": "checked-local-arithmetic",
            "evidence": "the effect expression carries a checked/saturating or explicit maximum operation and remains subject to its module's closed input ceiling",
            "verification_targets": ["request_resource_effect_closure"],
        }
    for contract in policy.get("closure_contracts", []):
        if relative in contract.get("paths", []):
            return {
                "disposition": contract["disposition"],
                "contract": contract["id"],
                "evidence": contract["evidence"],
                "verification_targets": contract["verification_targets"],
            }
    return {
        "disposition": "unclassified",
        "contract": None,
        "evidence": "no reviewed closure contract matched this effect",
        "verification_targets": [],
    }


def scan(policy: dict[str, Any], *, include_lines: bool) -> dict[str, Any]:
    family_policy = {item["id"]: item for item in policy["effect_families"]}
    gateways = policy["audited_gateways"]
    del gateways  # Classification consumes the authoritative policy directly.
    sites: list[dict[str, Any]] = []
    source_hash = hashlib.sha256()
    for path in source_paths(policy):
        relative = path.relative_to(ROOT).as_posix()
        raw_source = path.read_text(errors="replace")
        source_hash.update(relative.encode() + b"\0" + raw_source.encode() + b"\0")
        masked = mask_non_code(raw_source)
        source, masked = strip_test_modules(raw_source, masked)
        functions = FunctionIndex(function_ranges(masked))
        marker_cache: dict[tuple[int, int, str], list[str]] = {}
        line_start = 0
        occurrences: Counter[tuple[str, str, str]] = Counter()
        for line_number, (source_line, masked_line) in enumerate(
            zip(source.splitlines(keepends=True), masked.splitlines(keepends=True)), 1
        ):
            function, bounds = functions.owner(line_start)
            normalized = normalized_line(masked_line)
            # Imports name APIs but do not execute effects. Their call sites
            # remain visible elsewhere in the inventory.
            is_import = bool(
                re.match(r"^(?:pub(?:\([^)]*\))?\s+)?use\b", normalized)
            )
            if normalized and not is_import:
                for effect_rule in RULES:
                    if not effect_rule.pattern.search(masked_line):
                        continue
                    key = (function, effect_rule.family, normalized)
                    occurrence = occurrences[key]
                    occurrences[key] += 1
                    identity_text = (
                        f"{relative}\0{function}\0{effect_rule.family}\0{normalized}\0{occurrence}"
                    )
                    ident = hashlib.sha256(identity_text.encode()).hexdigest()[:20]
                    marker_key = (
                        bounds[0] if bounds else line_start,
                        bounds[1] if bounds else line_start + len(source_line),
                        effect_rule.family,
                    )
                    body_markers = marker_cache.get(marker_key)
                    if body_markers is None:
                        body = source[marker_key[0] : marker_key[1]]
                        body_markers = [
                            marker
                            for marker in family_policy[effect_rule.family]["accounting_markers"]
                            if marker in body
                        ]
                        marker_cache[marker_key] = body_markers
                    status, evidence = classify_site(
                        relative,
                        source_line.strip(),
                        body_markers,
                        family_policy[effect_rule.family],
                        policy,
                    )
                    site: dict[str, Any] = {
                        "id": ident,
                        "path": relative,
                        "function": function,
                        "effect": effect_rule.family,
                        "status": status,
                        "accounting_evidence": evidence,
                        "code": source_line.strip(),
                    }
                    closure = close_site(relative, status, evidence, policy)
                    site.update(
                        {
                            "closure_disposition": closure["disposition"],
                            "closure_contract": closure["contract"],
                            "closure_evidence": closure["evidence"],
                            "closure_verification_targets": closure["verification_targets"],
                        }
                    )
                    if include_lines:
                        site["line"] = line_number
                    sites.append(site)
            line_start += len(masked_line)
    sites.sort(key=lambda item: (item["path"], item["function"], item["effect"], item["id"]))
    statuses = Counter(item["status"] for item in sites)
    families = Counter(item["effect"] for item in sites)
    dispositions = Counter(item["closure_disposition"] for item in sites)
    return {
        "schema": 1,
        "kind": "httpd-rs-static-resource-effects",
        "policy_sha256": digest_json(policy),
        "source_sha256": source_hash.hexdigest(),
        "summary": {
            "effect_sites": len(sites),
            "files": len({item["path"] for item in sites}),
            "by_status": dict(sorted(statuses.items())),
            "by_effect": dict(sorted(families.items())),
            "by_closure_disposition": dict(sorted(dispositions.items())),
            "unclassified_effect_sites": dispositions.get("unclassified", 0),
        },
        "sites": sites,
    }


def write_static(policy: dict[str, Any]) -> None:
    document = scan(policy, include_lines=False)
    STATIC.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(
        f"resource-warrant: wrote {STATIC.relative_to(ROOT)} with "
        f"{document['summary']['effect_sites']} effect sites"
    )


def check_static(policy: dict[str, Any]) -> int:
    expected = scan(policy, include_lines=False)
    try:
        actual = json.loads(STATIC.read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(f"resource-warrant: cannot read static inventory: {error}", file=sys.stderr)
        return 1
    if actual != expected:
        expected_ids = {item["id"] for item in expected["sites"]}
        actual_ids = {item.get("id") for item in actual.get("sites", [])}
        print(
            "resource-warrant: static effect inventory is stale; "
            "run `python3 tests/resource_warrant.py --write-static` after reviewing "
            f"added={len(expected_ids - actual_ids)} removed={len(actual_ids - expected_ids)}",
            file=sys.stderr,
        )
        return 1
    summary = actual["summary"]
    unclassified = int(summary.get("unclassified_effect_sites", -1))
    if unclassified != 0:
        print(
            f"resource-warrant: closure has {unclassified} unclassified effect site(s)",
            file=sys.stderr,
        )
        return 1
    print(
        f"resource-warrant: {summary['effect_sites']} effect sites in {summary['files']} files; "
        f"review-required={summary['by_status'].get('review-required', 0)} "
        f"closure={summary['by_closure_disposition']}"
    )
    return 0


def load_profiles(patterns: list[str]) -> list[dict[str, Any]]:
    paths: set[Path] = set()
    for pattern in patterns:
        paths.update(Path(path) for path in glob.glob(pattern, recursive=True))
    profiles = []
    for path in sorted(paths):
        try:
            value = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise SystemExit(f"resource-warrant: cannot read profile {path}: {error}")
        if value.get("kind") != "httpd-rs-resource-profile" or value.get("schema") != 1:
            raise SystemExit(f"resource-warrant: not a resource profile: {path}")
        value["_path"] = os_path(path)
        profiles.append(value)
    return profiles


def os_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path.resolve())


def render_markdown(report: dict[str, Any]) -> str:
    static = report["static"]
    lines = [
        "# Request resource warrant",
        "",
        f"Revision: `{report.get('git_revision') or 'unknown'}`",
        "",
        "## Closure",
        "",
        f"- Static effect sites: {static['summary']['effect_sites']}",
        f"- Files containing effects: {static['summary']['files']}",
        f"- Unclassified effect sites: {static['summary']['unclassified_effect_sites']}",
        "- Closure dispositions: "
        + ", ".join(
            f"{name}={count}"
            for name, count in static["summary"]["by_closure_disposition"].items()
        ),
        f"- Sites lacking local syntactic accounting evidence: {static['summary']['by_status'].get('review-required', 0)}",
        f"- Runtime profiles merged: {len(report['profiles'])}",
        "",
        "## Effect families",
        "",
        "| family | sites | review required | dynamically observed resources |",
        "|---|---:|---:|---|",
    ]
    review_counts = Counter(
        item["effect"] for item in static["sites"] if item["status"] == "review-required"
    )
    observed = {name for name, present in report["observed_resources"].items() if present}
    policy_families = {item["id"]: item for item in report["policy"]["effect_families"]}
    for family, count in static["summary"]["by_effect"].items():
        resources = sorted(observed & set(policy_families[family]["resources"]))
        lines.append(f"| {family} | {count} | {review_counts[family]} | {', '.join(resources) or 'not observed'} |")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "An observed resource is evidence that the workload exercised it, not proof of a bound. "
            "Every static site has a typed-lease, constant-bound or external-assumption contract. "
            "A closure disposition is discovery evidence, not a claim that lease dominance or the complete cost formula is already mechanized.",
            "",
            "## Highest-priority local-evidence refinement sites",
            "",
        ]
    )
    review = [item for item in static["sites"] if item["status"] == "review-required"]
    for item in review[:100]:
        lines.append(
            f"- `{item['path']}:{item.get('line', '?')}` `{item['function']}` "
            f"({item['effect']}): `{item['code'][:180]}`"
        )
    if len(review) > 100:
        lines.append(f"- … {len(review) - 100} additional sites are present in the JSON report")
    return "\n".join(lines) + "\n"


def git_revision() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def write_report(policy: dict[str, Any], patterns: list[str], output: Path) -> int:
    profiles = load_profiles(patterns)
    static = scan(policy, include_lines=True)
    unclassified = int(static["summary"].get("unclassified_effect_sites", -1))
    if unclassified != 0:
        raise SystemExit(
            f"resource-warrant: refusing report with {unclassified} unclassified effect site(s)"
        )
    known_resources = {item["id"] for item in policy["resources"]}
    observed: dict[str, bool] = {name: False for name in sorted(known_resources)}
    unknown: set[str] = set()
    profile_rows = []
    for profile in profiles:
        for name, present in profile.get("observed_resources", {}).items():
            if name not in known_resources:
                unknown.add(name)
            elif present:
                observed[name] = True
        profile_rows.append(
            {
                "path": profile["_path"],
                "label": profile.get("label"),
                "revision": profile.get("git_revision"),
                "matched_processes": profile.get("matched_processes", 0),
                "duration_seconds": profile.get("duration_seconds", 0),
                "cpu_seconds": profile.get("cpu_seconds", 0),
                "peaks": profile.get("peaks", {}),
            }
        )
    if unknown:
        raise SystemExit(f"resource-warrant: profiles contain unknown resources: {sorted(unknown)}")
    report = {
        "schema": 1,
        "kind": "httpd-rs-request-resource-warrant",
        "git_revision": git_revision(),
        "claim": policy["claim"],
        "policy_sha256": digest_json(policy),
        "policy": policy,
        "static": static,
        "observed_resources": observed,
        "profiles": profile_rows,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    markdown = output.with_suffix(".md")
    markdown.write_text(render_markdown(report))
    print(
        f"resource-warrant: wrote {output} and {markdown}; "
        f"profiles={len(profiles)} closure="
        f"{static['summary']['by_closure_disposition']}"
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--write-static", action="store_true")
    actions.add_argument("--report", action="store_true")
    parser.add_argument("--profile", action="append", default=[], help="profile JSON glob")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/resource-warrant/report.json")
    return parser.parse_args()


def main() -> int:
    check_lexer_invariants()
    args = parse_args()
    policy = load_policy()
    if args.write_static:
        write_static(policy)
        return 0
    if args.report:
        return write_report(policy, args.profile, args.output)
    return check_static(policy)


if __name__ == "__main__":
    raise SystemExit(main())
