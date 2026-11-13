#!/usr/bin/env python3
"""Summarize persistent libFuzzer progress and semantic corpus coverage.

Edge coverage answers whether a binary reached new control flow.  The semantic
census below separately answers whether retained inputs cover the finite input
dimensions encoded by the structured security harnesses.  Keeping the two
measurements distinct avoids treating a high edge count as evidence that every
route, transition, or grammar mode was exercised.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

STATUS = re.compile(
    r"#(?P<run>\d+)\s+(?P<action>[A-Z]+)\s+"
    r"cov:\s*(?P<cov>\d+)\s+ft:\s*(?P<ft>\d+).*?"
    r"exec/s:\s*(?P<exec>\d+).*?rss:\s*(?P<rss>\d+)Mb"
)


@dataclass
class LogSummary:
    logs: int = 0
    executions: int = 0
    first_cov: int | None = None
    first_features: int | None = None
    max_cov: int = 0
    max_features: int = 0
    peak_rss_mb: int = 0
    final_exec_per_second: int = 0
    new_events: int = 0
    latest_runs_since_new: int | None = None


@dataclass
class SemanticGroup:
    expected: set[str]
    observed: set[str] = field(default_factory=set)

    def document(self) -> dict[str, object]:
        missing = sorted(self.expected - self.observed)
        expected = len(self.expected)
        covered = len(self.expected & self.observed)
        return {
            "covered": covered,
            "expected": expected,
            "percent": round(100.0 * covered / expected, 2) if expected else 100.0,
            "missing": missing,
            "observed_extra": sorted(self.observed - self.expected),
        }


def cycle_key(path: Path) -> tuple[int, str]:
    match = re.search(r"cycle-(\d+)\.log$", path.name)
    return (int(match.group(1)) if match else -1, path.name)


def summarize_logs(directory: Path) -> LogSummary:
    summary = LogSummary()
    logs = sorted(directory.glob("cycle-*.log"), key=cycle_key)
    summary.logs = len(logs)
    for log_index, path in enumerate(logs):
        matches = [STATUS.search(line) for line in path.read_text(errors="replace").splitlines()]
        matches = [match for match in matches if match]
        if not matches:
            continue
        first = matches[0]
        final = matches[-1]
        if summary.first_cov is None:
            summary.first_cov = int(first.group("cov"))
            summary.first_features = int(first.group("ft"))
        summary.executions += int(final.group("run"))
        summary.max_cov = max(summary.max_cov, *(int(match.group("cov")) for match in matches))
        summary.max_features = max(
            summary.max_features, *(int(match.group("ft")) for match in matches)
        )
        summary.peak_rss_mb = max(
            summary.peak_rss_mb, *(int(match.group("rss")) for match in matches)
        )
        summary.final_exec_per_second = int(final.group("exec"))
        new_runs = [int(match.group("run")) for match in matches if match.group("action") == "NEW"]
        summary.new_events += len(new_runs)
        if log_index == len(logs) - 1:
            last_new = max(new_runs, default=0)
            summary.latest_runs_since_new = int(final.group("run")) - last_new
    return summary


def corpus_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.iterdir() if path.is_file() and not path.is_symlink())


def group(values: range | list[str] | set[str]) -> SemanticGroup:
    return SemanticGroup({str(value) for value in values})


def observe(groups: dict[str, SemanticGroup], name: str, value: object) -> None:
    groups[name].observed.add(str(value))


def classify_config_physical(data: bytes, groups: dict[str, SemanticGroup]) -> None:
    templates = (
        "SetHandlercgi-script",
        "Requireall granted",
        '<FilesMatch "^private[.]txt$">',
        '<LocationMatch "^/private[.]txt$">',
        "RewriteRule ^private[.]txt$ - [F]",
        "Options +ExecCGI",
        "#Require all granted",
        "Header set X-Continuation exact",
    )
    first = data[0] if data else 0
    template = first % len(templates)
    second = data[1] if len(data) > 1 else 0
    third = data[2] if len(data) > 2 else 0
    boundary = second % (len(templates[template]) + 1)
    observe(groups, "template", template)
    observe(groups, "line_ending", "crlf" if third & 1 else "lf")
    category = "start" if boundary == 0 else "end" if boundary == len(templates[template]) else "interior"
    observe(groups, "boundary_class", category)

    if b"\\\r\n" in data:
        observe(groups, "raw_form", "valid_crlf")
    if b"\\\n" in data:
        observe(groups, "raw_form", "valid_lf")
    if b"\\\\\n" in data or b"\\\\\r\n" in data:
        observe(groups, "raw_form", "slash_run")
    if re.search(rb"\\[ \t]+\r?\n", data):
        observe(groups, "raw_form", "trailing_space")
    if data.endswith(b"\\"):
        observe(groups, "raw_form", "eof_slash")
    if data.count(b"\\\n") + data.count(b"\\\r\n") >= 2:
        observe(groups, "raw_form", "chain")


def classify_whole(data: bytes, groups: dict[str, SemanticGroup]) -> None:
    byte = lambda index: data[index] if index < len(data) else 0
    route = byte(0) % 20
    method = byte(3) % 6
    query = int(byte(1) & 1 != 0)
    body = int(byte(5) & 4 != 0)
    cancel = int(byte(7) & 0x80 != 0)
    observe(groups, "route", route)
    observe(groups, "method", method)
    observe(groups, "query", query)
    observe(groups, "body", body)
    observe(groups, "cancel", cancel)
    observe(groups, "route_method_pairs", f"{route}:{method}")


def classify_multi(data: bytes, groups: dict[str, SemanticGroup]) -> None:
    record_count = min(6, max(2, (len(data) + 15) // 16))
    observe(groups, "step_count", record_count)
    names = (
        (8, 0x01, "reload_before"),
        (8, 0x02, "reconnect_before"),
        (8, 0x04, "access_before"),
        (8, 0x08, "health_before"),
        (10, 0x01, "reload_after_prepare"),
        (10, 0x02, "access_after_prepare"),
        (10, 0x04, "health_after_prepare"),
        (10, 0x08, "reconnect_after"),
    )
    ordered_transitions: list[str] = []
    for index in range(record_count):
        record = data[index * 16 : (index + 1) * 16].ljust(16, b"\0")
        classify_whole(record, groups)
        for offset, bit, name in names:
            if record[offset] & bit:
                observe(groups, "transition", name)
                ordered_transitions.append(name)
        if record[8] & 0x04:
            observe(groups, "access_value", int(record[9] & 0x01 != 0))
        if record[8] & 0x08:
            observe(groups, "health_value", int(record[9] & 0x02 != 0))
        if record[10] & 0x02:
            observe(groups, "access_value", int(record[11] & 0x01 != 0))
        if record[10] & 0x04:
            observe(groups, "health_value", int(record[11] & 0x02 != 0))
    for left, right in zip(ordered_transitions, ordered_transitions[1:]):
        observe(groups, "transition_pair", f"{left}>{right}")


def classify_h2(data: bytes, groups: dict[str, SemanticGroup]) -> None:
    for offset in range(0, min(len(data), 4096 * 8), 8):
        observe(groups, "command", data[offset] % 12)


def classify_policy(data: bytes, groups: dict[str, SemanticGroup]) -> None:
    for offset in range(0, len(data), 2):
        observe(groups, "event", data[offset] % 18)
        arg = data[offset + 1] if offset + 1 < len(data) else 0
        observe(groups, "route", arg % 8)


def classify_resource(data: bytes, groups: dict[str, SemanticGroup]) -> None:
    for offset in range(0, min(len(data), 4 * 512), 4):
        observe(groups, "operation", data[offset] & 0x1F)


def classify_pcre2_differential(data: bytes, groups: dict[str, SemanticGroup]) -> None:
    if not data:
        return
    control = data[0]
    observe(groups, "input_mode", "structured" if control & 0x80 else "raw")
    flags = control & 0x7F if control & 0x80 else (control - 0x20 if 0x20 <= control <= 0x7E else control)
    for bit, name in enumerate(("caseless", "dotall", "multiline", "extended", "crlf", "utf", "ucp")):
        if flags & (1 << bit):
            observe(groups, "enabled_flag", name)


def classify_pcre2_grammar(data: bytes, groups: dict[str, SemanticGroup]) -> None:
    if not data:
        return
    observe(groups, "mode", data[0] % 4)
    flags = data[1] & 0x7F if len(data) > 1 else 0
    for bit, name in enumerate(("caseless", "dotall", "multiline", "extended", "crlf", "utf", "ucp")):
        if flags & (1 << bit):
            observe(groups, "enabled_flag", name)


def classify_pcre2_resource(data: bytes, groups: dict[str, SemanticGroup]) -> None:
    if len(data) < 13:
        return
    for bit, name in enumerate(("caseless", "dotall", "multiline", "extended", "crlf", "utf", "ucp")):
        if data[0] & (1 << bit):
            observe(groups, "enabled_flag", name)


def observe_http_wire(data: bytes, groups: dict[str, SemanticGroup]) -> None:
    upper = data.upper()
    if re.search(rb"^(GET|HEAD|POST|PUT|DELETE|OPTIONS) [^ ]+ HTTP/1\.[01]\r?\n", data):
        observe(groups, "wire_form", "basic")
    if b"CONTENT-LENGTH:" in upper:
        observe(groups, "wire_form", "content_length")
    if b"TRANSFER-ENCODING: CHUNKED" in upper:
        observe(groups, "wire_form", "chunked")
    if re.search(rb"^[A-Z]+ HTTPS?://", upper):
        observe(groups, "wire_form", "absolute_form")
    if len(re.findall(rb"(?:^|\r?\n)(?:GET|HEAD|POST|PUT|DELETE|OPTIONS) [^ ]+ HTTP/1\.[01]\r?\n", data)) > 1:
        observe(groups, "wire_form", "pipelined")
    if b"\n\n" not in data and b"\r\n\r\n" not in data:
        observe(groups, "wire_form", "malformed")


def classify_declared(target: str, data: bytes, groups: dict[str, SemanticGroup]) -> None:
    """Classify finite semantic families for otherwise byte-oriented targets."""
    upper = data.upper()
    text = data.decode("utf-8", errors="replace")

    if target == "http_request":
        observe_http_wire(data, groups)
    elif target == "http_connection":
        if len(data) < 3:
            return
        chunk = max(data[0], 1)
        observe(groups, "fragmentation", "one" if chunk == 1 else "small" if chunk <= 8 else "medium" if chunk <= 64 else "large")
        observe(groups, "spool_quota", "zero" if data[1] == 0 or data[2] % 5 == 0 else "limited" if data[1] < 32 else "roomy")
        observe_http_wire(data[3:], groups)
    elif target == "http_fields":
        checks = {
            "weighted_list": b";Q=" in upper,
            "entity_tag": b'"' in data or data == b"*",
            "cookie": b"=" in data and b";" in data,
            "imf_date": b"GMT" in upper and b"," in data,
            "rfc850_date": b"GMT" in upper and b"-" in data,
            "asctime_date": bool(re.match(rb"^[A-Z][a-z]{2} [A-Z][a-z]{2} ", data)),
            "status_line": upper.startswith(b"HTTP/"),
            "malformed": any(byte < 9 or 13 < byte < 32 for byte in data),
        }
        for label, present in checks.items():
            if present:
                observe(groups, "grammar", label)
    elif target == "request_identity":
        byte = lambda index: data[index] if index < len(data) else 0
        observe(groups, "remoteip_mode", byte(0) % 4)
        observe(groups, "chain_length", byte(2) % 5 + 1)
        observe(groups, "separator", "spaced" if byte(8) & 1 == 0 else "compact")
        observe(groups, "setenv_attribute", byte(15) % 6)
        observe(groups, "rule_origin", "main" if byte(18) & 1 == 0 else "access")
    elif target == "config_sections":
        if re.search(rb"(?m)^\s*[A-Za-z][A-Za-z0-9]*\s+", data):
            observe(groups, "form", "directive")
        if re.search(rb"(?m)^\s*<[A-Za-z]", data):
            observe(groups, "form", "section_open")
        if re.search(rb"(?m)^\s*</[A-Za-z]", data):
            observe(groups, "form", "section_close")
        if len(re.findall(rb"(?m)^\s*<[A-Za-z]", data)) >= 2:
            observe(groups, "form", "nested")
        if b"\\\n" in data or b"\\\r\n" in data:
            observe(groups, "form", "continuation")
        if data.count(b"<") != data.count(b">") or b"</Mismatch>" in data:
            observe(groups, "form", "malformed")
    elif target == "config_compile":
        if data:
            observe(groups, "strict", data[0] & 1)
        families = {
            "listener": (b"LISTEN", b"SERVERNAME"),
            "authorization": (b"REQUIRE", b"AUTH"),
            "rewrite": (b"REWRITE",),
            "backend": (b"PROXYPASS", b"SET HANDLER"),
            "cache": (b"CACHE",),
            "tls": (b"SSL",),
            "remoteip": (b"REMOTEIP",),
            "unknown_reject": (b"UNSUPPORTED", b"NOTADIRECTIVE"),
        }
        for label, markers in families.items():
            if any(marker in upper for marker in markers):
                observe(groups, "directive_family", label)
    elif target == "config_grammars":
        families = {
            "listen": bool(re.fullmatch(rb"(?:\[[^]]+\]|[^ ]+):[0-9]+", data)),
            "read_timeout": b"HEADER=" in upper or b"BODY=" in upper,
            "rewrite_rule": upper.startswith(b"^") or b" [L" in upper,
            "rewrite_condition": upper.startswith(b"%{") or b" -F" in upper,
            "proxy_backend": b"://" in data or upper.startswith(b"BALANCER://"),
            "template": b"$" in data or b"%" in data,
            "malformed": not data or any(byte < 9 or 13 < byte < 32 for byte in data),
        }
        for label, present in families.items():
            if present:
                observe(groups, "grammar", label)
    elif target == "htaccess_walk":
        if not data:
            return
        observe(groups, "depth", data[0] % 4)
        body = data[1:].upper()
        families = {
            "authorization": b"REQUIRE" in body,
            "mapping": b"REWRITE" in body or b"DIRECTORYINDEX" in body,
            "handler": b"SETHANDLER" in body or b"ADDTYPE" in body,
            "environment": b"SETENV" in body,
            "malformed": b"<" in body and b">" not in body,
        }
        for label, present in families.items():
            if present:
                observe(groups, "directive_family", label)
    elif target == "rewrite_expr":
        families = {
            "comparison": any(token in data for token in (b"==", b"!=", b"<", b">")),
            "boolean": b"&&" in data or b"||" in data or text.lstrip().startswith("!"),
            "regex": b"=~" in data or b"!~" in data,
            "request_variable": b"%{HTTP_" in upper or b"%{REQUEST_" in upper,
            "environment_variable": b"%{ENV:" in upper,
            "filesystem_test": any(token in data for token in (b"-f", b"-d", b"-s")),
            "malformed": not data or data.count(b"(") != data.count(b")"),
        }
        for label, present in families.items():
            if present:
                observe(groups, "expression_family", label)
    elif target == "cgi_response":
        observe(groups, "delimiter", "crlf" if b"\r\n\r\n" in data else "lf" if b"\n\n" in data else "absent")
        fields = {
            "status": b"STATUS:" in upper,
            "location": b"LOCATION:" in upper,
            "content_length": b"CONTENT-LENGTH:" in upper,
            "content_type": b"CONTENT-TYPE:" in upper,
            "malformed": b":" not in data or b"\x00" in data,
        }
        for label, present in fields.items():
            if present:
                observe(groups, "header_family", label)
    elif target == "fastcgi_records":
        if len(data) < 2:
            observe(groups, "record_type", "invalid")
            observe(groups, "completeness", "truncated")
            return
        names = {3: "end_request", 6: "stdout", 7: "stderr"}
        observe(groups, "record_type", names.get(data[1], "management" if data[1] in {9, 10, 11} else "invalid"))
        if len(data) < 8:
            observe(groups, "completeness", "truncated")
        else:
            length = int.from_bytes(data[4:6], "big")
            total = 8 + length + data[6]
            observe(groups, "completeness", "complete" if len(data) >= total else "truncated")
    elif target == "proxy_response":
        forms = {
            "content_length": b"CONTENT-LENGTH:" in upper,
            "chunked": b"TRANSFER-ENCODING: CHUNKED" in upper,
            "close_delimited": upper.startswith(b"HTTP/") and b"CONTENT-LENGTH:" not in upper and b"TRANSFER-ENCODING:" not in upper,
            "no_body": bool(re.match(rb"HTTP/1\.[01] (?:1[0-9][0-9]|204|304) ", upper)),
            "upgrade": b" 101 " in upper and b"UPGRADE:" in upper,
            "malformed": not upper.startswith(b"HTTP/"),
        }
        for label, present in forms.items():
            if present:
                observe(groups, "framing", label)
    elif target == "websocket_negotiation":
        forms = {
            "protocol_offer": b"CHAT" in upper or b"SUPERCHAT" in upper,
            "extension_offer": b"PERMESSAGE-DEFLATE" in upper or b"X-TEST" in upper,
            "valid_101": b" 101 " in upper and b"SEC-WEBSOCKET-ACCEPT:" in upper,
            "duplicate_selection": upper.count(b"SEC-WEBSOCKET-PROTOCOL:") > 1,
            "malformed_101": b" 101 " in upper and b"SEC-WEBSOCKET-ACCEPT:" not in upper,
        }
        for label, present in forms.items():
            if present:
                observe(groups, "surface", label)
    elif target == "h2_frames":
        offset = 24 if data.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") else 0
        parsed = False
        names = {0: "data", 1: "headers", 2: "priority", 3: "reset", 4: "settings", 5: "push_promise", 6: "ping", 7: "goaway", 8: "window_update", 9: "continuation"}
        while offset + 9 <= len(data):
            length = int.from_bytes(data[offset:offset + 3], "big")
            frame_type = data[offset + 3]
            observe(groups, "frame_type", names.get(frame_type, "unknown"))
            parsed = True
            offset += 9 + length
            if offset > len(data):
                break
        if not parsed:
            observe(groups, "frame_type", "unknown")
    elif target == "h2_output":
        control = data[0] if data else 0
        observe(groups, "response_shape", "headers_only" if control & 1 == 0 else "headers_and_data")
        observe(groups, "terminal", ("drain", "peer_reset", "connection_drop")[(control >> 1) % 3])
        observe(groups, "header_size", "maximum" if control & 0x40 else "ordinary")
    elif target == "cache_metadata":
        match = re.match(rb"V([1-7])\n", data)
        observe(groups, "version", match.group(1).decode() if match else "invalid")
        if b"\nK " in data:
            observe(groups, "field_family", "key")
        if b"\nH " in data:
            observe(groups, "field_family", "header")
        if b"\nV " in data:
            observe(groups, "field_family", "vary")
        if data.count(b"\nS ") > 1:
            observe(groups, "field_family", "duplicate_singleton")
        if not match:
            observe(groups, "field_family", "malformed")
    elif target == "cache_stateful":
        observe(groups, "reload_root", "shared" if len(data) > 1 and data[1] & 0x80 else "moved")
        for offset in range(0, min(len(data), 128), 4):
            chunk = data[offset:offset + 4]
            observe(groups, "operation", chunk[0] % 8)
            observe(groups, "key", (chunk[1] if len(chunk) > 1 else 0) % 4)
    elif target == "brotli_resource":
        if len(data) < 7:
            return
        observe(groups, "quality", data[0] % 12)
        observe(groups, "consumption", ("cancel", "prefix", "full", "chunked")[data[1] % 4])
        observe(groups, "pressure", ("none", "cpu", "memory")[data[2] % 3])
        observe(groups, "pattern", ("raw", "repeated", "ramp", "alternating")[data[3] % 4])
        observe(groups, "size", ("corpus", "empty", "one", "4k", "256k")[data[4] % 5])
        observe(
            groups,
            "gate",
            ("normal", "range", "no_transform", "encoded", "head", "no_body_status", "oversize")[data[5] % 7],
        )
    elif target == "tls_policy":
        forms = {
            "hostname": bool(re.fullmatch(rb"[A-Za-z0-9.-]+", data)) and b"TLS" not in upper,
            "wildcard": data.startswith(b"*."),
            "tls12": b"TLSV1.2" in upper,
            "tls13": b"TLSV1.3" in upper,
            "all_with_exclusions": upper.startswith(b"ALL "),
            "invalid": not data or any(byte < 32 for byte in data),
        }
        for label, present in forms.items():
            if present:
                observe(groups, "policy_form", label)
    elif target == "tls_identity_reload":
        byte = lambda index: data[index] if index < len(data) else 0
        observe(groups, "sni", byte(114) % 6)
        observe(groups, "authority", byte(115) % 6)
        observe(groups, "client_certificate", byte(116) & 1)
        for offset in (0, 19, 38):
            observe(groups, "verify_mode", byte(offset + 12) % 3)
    elif target == "ocsp_der":
        forms = {
            "der_sequence": data.startswith(b"\x30"),
            "generalized_time": bool(re.fullmatch(rb"[0-9]{14}Z", data)),
            "http_url": data.startswith(b"http://"),
            "https_reject": data.startswith(b"https://"),
            "malformed": not data or data.startswith(b"\xff") or b"\x00" in data,
        }
        for label, present in forms.items():
            if present:
                observe(groups, "parser_family", label)


DECLARED_SPECS: dict[str, dict[str, set[str]]] = {
    "http_request": {"wire_form": {"basic", "content_length", "chunked", "absolute_form", "pipelined", "malformed"}},
    "http_connection": {"fragmentation": {"one", "small", "medium", "large"}, "spool_quota": {"zero", "limited", "roomy"}, "wire_form": {"basic", "content_length", "chunked", "absolute_form", "pipelined", "malformed"}},
    "http_fields": {"grammar": {"weighted_list", "entity_tag", "cookie", "imf_date", "rfc850_date", "asctime_date", "status_line", "malformed"}},
    "request_identity": {"remoteip_mode": {"0", "1", "2", "3"}, "chain_length": {"1", "2", "3", "4", "5"}, "separator": {"spaced", "compact"}, "setenv_attribute": {str(i) for i in range(6)}, "rule_origin": {"main", "access"}},
    "config_sections": {"form": {"directive", "section_open", "section_close", "nested", "continuation", "malformed"}},
    "config_compile": {"strict": {"0", "1"}, "directive_family": {"listener", "authorization", "rewrite", "backend", "cache", "tls", "remoteip", "unknown_reject"}},
    "config_grammars": {"grammar": {"listen", "read_timeout", "rewrite_rule", "rewrite_condition", "proxy_backend", "template", "malformed"}},
    "htaccess_walk": {"depth": {"0", "1", "2", "3"}, "directive_family": {"authorization", "mapping", "handler", "environment", "malformed"}},
    "rewrite_expr": {"expression_family": {"comparison", "boolean", "regex", "request_variable", "environment_variable", "filesystem_test", "malformed"}},
    "cgi_response": {"delimiter": {"crlf", "lf", "absent"}, "header_family": {"status", "location", "content_length", "content_type", "malformed"}},
    "fastcgi_records": {"record_type": {"stdout", "stderr", "end_request", "management", "invalid"}, "completeness": {"complete", "truncated"}},
    "proxy_response": {"framing": {"content_length", "chunked", "close_delimited", "no_body", "upgrade", "malformed"}},
    "websocket_negotiation": {"surface": {"protocol_offer", "extension_offer", "valid_101", "duplicate_selection", "malformed_101"}},
    "h2_frames": {"frame_type": {"data", "headers", "priority", "reset", "settings", "push_promise", "ping", "goaway", "window_update", "continuation", "unknown"}},
    "h2_output": {"response_shape": {"headers_only", "headers_and_data"}, "terminal": {"drain", "peer_reset", "connection_drop"}, "header_size": {"ordinary", "maximum"}},
    "cache_metadata": {"version": {"1", "2", "3", "4", "5", "6", "7", "invalid"}, "field_family": {"key", "header", "vary", "duplicate_singleton", "malformed"}},
    "cache_stateful": {"operation": {str(i) for i in range(8)}, "key": {str(i) for i in range(4)}, "reload_root": {"shared", "moved"}},
    "brotli_resource": {
        "quality": {str(i) for i in range(12)},
        "consumption": {"cancel", "prefix", "full", "chunked"},
        "pressure": {"none", "cpu", "memory"},
        "pattern": {"raw", "repeated", "ramp", "alternating"},
        "size": {"corpus", "empty", "one", "4k", "256k"},
        "gate": {"normal", "range", "no_transform", "encoded", "head", "no_body_status", "oversize"},
    },
    "tls_policy": {"policy_form": {"hostname", "wildcard", "tls12", "tls13", "all_with_exclusions", "invalid"}},
    "tls_identity_reload": {"sni": {str(i) for i in range(6)}, "authority": {str(i) for i in range(6)}, "client_certificate": {"0", "1"}, "verify_mode": {"0", "1", "2"}},
    "ocsp_der": {"parser_family": {"der_sequence", "generalized_time", "http_url", "https_reject", "malformed"}},
}


def declared_seeds(target: str) -> list[bytes]:
    basic = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
    seeds: dict[str, list[bytes]] = {
        "http_request": [basic, b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nx", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n", b"GET http://example.test/a HTTP/1.1\r\nHost: example.test\r\n\r\n", basic + basic, b"broken"],
        "http_fields": [b"gzip;q=0.5", b'W/\"tag\"', b"a=1; b=2", b"Sun, 06 Nov 1994 08:49:37 GMT", b"Sunday, 06-Nov-94 08:49:37 GMT", b"Sun Nov  6 08:49:37 1994", b"HTTP/1.1 204 No Content", b"bad\x00field"],
        "config_sections": [b"Listen 8080\n", b"<Directory /tmp>\n", b"</Directory>\n", b"<Directory /tmp>\n<Files x>\n</Files>\n</Directory>\n", b"Listen \\\n8080\n", b"<Directory\n"],
        "config_compile": [b"Listen 8080\n", b"ServerName example.test\n", b"Require all granted\n", b"RewriteRule ^a$ b [L]\n", b"ProxyPass / http://127.0.0.1/\n", b"CacheEnable disk /\n", b"SSLEngine On\n", b"RemoteIPHeader X-Forwarded-For\n", b"NotADirective x\n"],
        "config_grammars": [b"127.0.0.1:8080", b"header=20,MinRate=500 body=30", b"^a$ b [L]", b"%{REQUEST_URI} -f", b"http://127.0.0.1:8080/", b"/x/$1", b"\x00"],
        "rewrite_expr": [b"%{REQUEST_URI} == '/x'", b"true && false", b"%{REQUEST_URI} =~ m#^/x$#", b"%{HTTP_HOST} == 'x'", b"%{ENV:FUZZ} == '1'", b"-f '/tmp/fuzz'", b"("],
        "cgi_response": [b"Content-Type: text/plain\r\n\r\nbody", b"Content-Type: text/plain\n\nbody", b"Status: 201 Created\r\n\r\n", b"Location: /next\r\n\r\n", b"Content-Length: 0\r\n\r\n", b"broken\x00"],
        "proxy_response": [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n", b"HTTP/1.0 200 OK\r\n\r\nx", b"HTTP/1.1 204 No Content\r\n\r\n", b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", b"broken"],
        "websocket_negotiation": [b"chat, superchat", b"permessage-deflate; client_max_window_bits", b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n", b"Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: superchat", b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"],
        "h2_output": [bytes((value,)) + b"header" for value in (0, 1, 2, 4, 0x40)],
        "cache_metadata": [f"V{version}\nS 200\nT 1\nE 2\nP AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nG 1\n".encode() for version in range(1, 7)] + [b"V7\nK YQ==\nS 200\nT 1\nE 2\nP AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nG 1\nH eA== eQ==\nV YWNjZXB0 dGV4dC9wbGFpbg==\n", b"V7\nS 200\nS 201\n", b"invalid"],
        "tls_policy": [b"example.test", b"*.example.test", b"TLSv1.2", b"TLSv1.3", b"all -SSLv3 -TLSv1 -TLSv1.1", b"\x00"],
        "ocsp_der": [b"\x30\x00", b"20261112120000Z", b"http://ocsp.example.test/", b"https://ocsp.example.test/", b"\xff\x00"],
    }
    if target == "http_connection":
        wires = declared_seeds("http_request")
        return [bytes((1, 0, 0)) + wires[0], bytes((4, 1, 1)) + wires[1], bytes((32, 16, 2)) + wires[2], bytes((128, 255, 4)) + wires[3], bytes((2, 255, 4)) + wires[4], bytes((9, 255, 4)) + wires[5]]
    if target == "request_identity":
        output = []
        for index in range(6):
            value = bytearray(19)
            value[0] = index % 4
            value[2] = index % 5
            value[8] = index & 1
            value[15] = index
            value[18] = index & 1
            output.append(bytes(value))
        return output
    if target == "htaccess_walk":
        bodies = [b"Require all granted\n", b"RewriteRule ^a$ b [L]\n", b"SetHandler cgi-script\n", b"SetEnv FLAG 1\n", b"<Files\n"]
        return [bytes((depth,)) + bodies[depth % len(bodies)] for depth in range(4)] + [b"\x00" + bodies[-1]]
    if target == "fastcgi_records":
        def record(kind: int, content: bytes) -> bytes:
            return bytes((1, kind, 0, 1)) + len(content).to_bytes(2, "big") + b"\x00\x00" + content
        return [record(6, b"Status: 200 OK\r\n\r\n"), record(7, b"error"), record(3, bytes(8)), record(10, b"x"), b"\x00\xff", b"\x01\x06\x00\x01\x00\x10\x00\x00x"]
    if target == "h2_frames":
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        def frame(kind: int) -> bytes:
            return preface + b"\x00\x00\x00" + bytes((kind, 0)) + b"\x00\x00\x00\x01"
        return [frame(kind) for kind in range(10)] + [b"not-a-frame"]
    if target == "cache_stateful":
        return [bytes((operation, key | (0x80 if (operation + key) & 1 else 0), operation + key, 0x41)) for operation in range(8) for key in range(4)]
    if target == "brotli_resource":
        output = []
        # Cover every finite control family marginally; libFuzzer then
        # composes them while the corpus census reports missing dimensions.
        widths = (12, 4, 3, 4, 5, 7)
        for offset, width in enumerate(widths):
            for value in range(width):
                control = bytearray((5, 2, 0, 0, 2, 0, 0x41, 0x42))
                control[offset] = value
                output.append(bytes(control))
        # Keep the expensive supported boundary and both deliberately
        # unavailable Zopfli qualities in the resumable corpus.
        output.extend(
            (
                bytes((9, 3, 0, 3, 4, 0, 0x7F, 0x42)),
                bytes((10, 2, 0, 1, 4, 0, 0x41, 0x42)),
                bytes((11, 2, 0, 2, 4, 0, 0x41, 0x42)),
            )
        )
        return output
    if target == "tls_identity_reload":
        output = []
        for index in range(6):
            value = bytearray(117)
            value[12] = index % 3
            value[31] = (index + 1) % 3
            value[50] = (index + 2) % 3
            value[114] = index
            value[115] = 5 - index
            value[116] = index & 1
            output.append(bytes(value))
        return output
    return seeds.get(target, [])


def semantic_spec(target: str) -> tuple[dict[str, SemanticGroup], object | None]:
    flags = {"caseless", "dotall", "multiline", "extended", "crlf", "utf", "ucp"}
    if target in DECLARED_SPECS:
        groups = {
            name: SemanticGroup(set(expected))
            for name, expected in DECLARED_SPECS[target].items()
        }
        return groups, lambda data, selected: classify_declared(target, data, selected)
    if target == "config_physical_lines":
        return (
            {
                "template": group(range(8)),
                "line_ending": group({"lf", "crlf"}),
                "boundary_class": group({"start", "interior", "end"}),
                "raw_form": group(
                    {"valid_lf", "valid_crlf", "slash_run", "trailing_space", "eof_slash", "chain"}
                ),
            },
            classify_config_physical,
        )
    if target in {"whole_request_differential", "multi_request_state"}:
        groups = {
            "route": group(range(20)),
            "method": group(range(6)),
            "query": group(range(2)),
            "body": group(range(2)),
            "cancel": group(range(2)),
            "route_method_pairs": group({f"{route}:{method}" for route in range(20) for method in range(6)}),
        }
        if target == "multi_request_state":
            transitions = {
                "reload_before",
                "reconnect_before",
                "access_before",
                "health_before",
                "reload_after_prepare",
                "access_after_prepare",
                "health_after_prepare",
                "reconnect_after",
            }
            groups.update(
                {
                    "step_count": group(range(2, 7)),
                    "transition": group(transitions),
                    "transition_pair": group(
                        {f"{left}>{right}" for left in transitions for right in transitions}
                    ),
                    "access_value": group(range(2)),
                    "health_value": group(range(2)),
                }
            )
            return groups, classify_multi
        return groups, classify_whole
    if target == "h2_stateful":
        return {"command": group(range(12))}, classify_h2
    if target == "policy_path":
        return {"event": group(range(18)), "route": group(range(8))}, classify_policy
    if target == "resource_transitions":
        return {"operation": group(range(32))}, classify_resource
    if target == "pcre2_differential":
        return {
            "input_mode": group({"raw", "structured"}),
            "enabled_flag": group(flags),
        }, classify_pcre2_differential
    if target == "pcre2_grammar":
        return {"mode": group(range(4)), "enabled_flag": group(flags)}, classify_pcre2_grammar
    if target == "pcre2_resource":
        return {"enabled_flag": group(flags)}, classify_pcre2_resource
    return {}, None


def git_revision() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def store_seed(state: Path, target: str, data: bytes) -> bool:
    destination = state / "corpus" / target
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / hashlib.sha256(data).hexdigest()
    if path.exists():
        return False
    path.write_bytes(data)
    return True


def seed_semantic_matrix(state: Path, targets: set[str]) -> int:
    """Materialize finite structured dimensions as resumable corpus inputs."""
    created = 0
    for target in sorted(targets & DECLARED_SPECS.keys()):
        for data in declared_seeds(target):
            created += store_seed(state, target, data)

    if "config_physical_lines" in targets:
        templates = (
            "SetHandlercgi-script",
            "Requireall granted",
            '<FilesMatch "^private[.]txt$">',
            '<LocationMatch "^/private[.]txt$">',
            "RewriteRule ^private[.]txt$ - [F]",
            "Options +ExecCGI",
            "#Require all granted",
            "Header set X-Continuation exact",
        )
        for template, text in enumerate(templates):
            length = len(text)
            for boundary in (0, 1, length):
                for crlf in (0, 1):
                    created += store_seed(
                        state,
                        "config_physical_lines",
                        bytes((template, boundary, crlf)),
                    )
        for data in (
            b"left\\\nright\n",
            b"left\\\r\nright\n",
            b"left\\\\\nright\n",
            b"left\\   \nright\n",
            b"left\\",
            b"left\\\n\\\r\nright\n",
        ):
            created += store_seed(state, "config_physical_lines", data)

    if "whole_request_differential" in targets:
        for route in range(20):
            for method in range(6):
                control = bytearray(16)
                control[0] = route
                control[1] = (route + method) & 1
                control[3] = method
                if (route + method) & 2:
                    control[5] |= 4
                if (route + method) & 4:
                    control[7] |= 0x80
                control[8:] = b"semantic"
                created += store_seed(state, "whole_request_differential", bytes(control))

    if "multi_request_state" in targets:
        transition_before = (0x01, 0x02, 0x04, 0x08)
        transition_after = (0x01, 0x02, 0x04, 0x08)
        pair_index = 0
        for route in range(20):
            for method in range(6):
                records = bytearray(32)
                records[0] = route
                records[1] = pair_index & 1
                records[3] = method
                records[5] = 4 if pair_index & 2 else 0
                records[7] = 0x80 if pair_index & 4 else 0
                records[8] = transition_before[pair_index % len(transition_before)]
                records[9] = pair_index & 3
                records[10] = transition_after[(pair_index // 4) % len(transition_after)]
                records[11] = (pair_index // 2) & 3
                records[16] = (route + 1) % 20
                records[19] = (method + 1) % 6
                created += store_seed(state, "multi_request_state", bytes(records))
                pair_index += 1
        for step_count in range(2, 7):
            # div_ceil(len, 16) selects the requested count.
            created += store_seed(
                state,
                "multi_request_state",
                bytes(16 * (step_count - 1) + 1),
            )
        transitions = (
            (8, 0x01),
            (8, 0x02),
            (8, 0x04),
            (8, 0x08),
            (10, 0x01),
            (10, 0x02),
            (10, 0x04),
            (10, 0x08),
        )
        for left_offset, left_bit in transitions:
            for right_offset, right_bit in transitions:
                records = bytearray(32)
                records[left_offset] = left_bit
                records[16 + right_offset] = right_bit
                created += store_seed(state, "multi_request_state", bytes(records))

    if "h2_stateful" in targets:
        data = bytearray()
        for command in range(12):
            data.extend(bytes((command, 0, 0, 0, command + 1, command, 0, 0)))
        created += store_seed(state, "h2_stateful", bytes(data))

    if "policy_path" in targets:
        data = bytearray()
        for event in range(18):
            for route in range(8):
                data.extend((event, route))
        created += store_seed(state, "policy_path", bytes(data))

    if "resource_transitions" in targets:
        data = b"".join(bytes((operation, operation, operation, 0)) for operation in range(32))
        created += store_seed(state, "resource_transitions", data)

    if "pcre2_differential" in targets:
        created += store_seed(state, "pcre2_differential", b" \nsubject")
        for bit in range(7):
            created += store_seed(
                state,
                "pcre2_differential",
                bytes((0x80 | (1 << bit), 0x00)) + b"subject",
            )

    if "pcre2_grammar" in targets:
        for mode in range(4):
            created += store_seed(state, "pcre2_grammar", bytes((mode, 0x7F, 0, 1, 2, 3)))

    if "pcre2_resource" in targets:
        created += store_seed(state, "pcre2_resource", bytes((0x7F,)) + bytes(12) + b"\n")
    return created


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path)
    parser.add_argument("--targets", help="space-separated fuzz targets")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--seed-matrix", action="store_true")
    parser.add_argument("--strict-semantic", action="store_true")
    parser.add_argument(
        "--check-specs",
        action="store_true",
        help="require every Cargo fuzz target to have a semantic census",
    )
    args = parser.parse_args()

    if args.check_specs:
        with (ROOT / "fuzz" / "Cargo.toml").open("rb") as stream:
            manifest = tomllib.load(stream)
        targets = [entry["name"] for entry in manifest.get("bin", [])]
        target_set = set(targets)
        missing = [target for target in targets if not semantic_spec(target)[0]]
        incomplete = []
        for target in sorted(DECLARED_SPECS):
            groups, classifier = semantic_spec(target)
            for data in declared_seeds(target):
                classifier(data, groups)
            absent = {
                name: sorted(value.expected - value.observed)
                for name, value in groups.items()
                if value.expected - value.observed
            }
            if absent:
                incomplete.append(f"{target}={absent}")
        schedule_failures = []
        schedules = {
            "tests/long_fuzz.sh": r'^ALL_TARGETS="([^"]+)"',
            "tests/fuzz_smoke.sh": r'^targets=\$\{FUZZ_TARGETS:-"([^"]+)"\}',
            "tests/fuzz_campaign.sh": r'^TARGETS=\$\{FUZZ_TARGETS:-"([^"]+)"\}',
        }
        for relative, pattern in schedules.items():
            text = (ROOT / relative).read_text(encoding="utf-8")
            match = re.search(pattern, text, re.MULTILINE)
            listed = set(match.group(1).split()) if match else set()
            if listed != target_set:
                schedule_failures.append(
                    f"{relative}: missing={sorted(target_set - listed)} extra={sorted(listed - target_set)}"
                )
        nightly = set(
            re.findall(
                r"^          - ([a-z][a-z0-9_]*)$",
                (ROOT / ".github" / "workflows" / "nightly.yml").read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        )
        if nightly != target_set:
            schedule_failures.append(
                f".github/workflows/nightly.yml: missing={sorted(target_set - nightly)} "
                f"extra={sorted(nightly - target_set)}"
            )
        if missing or incomplete or schedule_failures:
            if missing:
                print(f"fuzz-report: targets without semantic census: {', '.join(missing)}", file=sys.stderr)
            for failure in incomplete:
                print(f"fuzz-report: seed matrix is incomplete: {failure}", file=sys.stderr)
            for failure in schedule_failures:
                print(f"fuzz-report: target schedule closure failed: {failure}", file=sys.stderr)
            return 1
        print(f"fuzz-report: semantic census closure OK ({len(targets)} targets)")
        return 0

    if args.state is None or args.targets is None:
        parser.error("--state and --targets are required unless --check-specs is used")

    state = args.state.resolve()
    targets = args.targets.split()
    if args.seed_matrix:
        created = seed_semantic_matrix(state, set(targets))
        print(f"fuzz-report: added {created} semantic matrix seed(s)")
    document: dict[str, object] = {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_revision": git_revision(),
        "state": str(state),
        "targets": {},
    }
    any_missing = False

    print("target                           files    bytes       runs       cov        ft  new  stale  rss semantic")
    print("-" * 118)
    for target in targets:
        files = corpus_files(state / "corpus" / target)
        logs = summarize_logs(state / "logs" / target)
        groups, classifier = semantic_spec(target)
        if classifier is not None:
            for path in files:
                classifier(path.read_bytes(), groups)
        semantic = {name: value.document() for name, value in groups.items()}
        missing = sum(len(value["missing"]) for value in semantic.values())
        expected = sum(int(value["expected"]) for value in semantic.values())
        covered = sum(int(value["covered"]) for value in semantic.values())
        any_missing |= missing > 0
        semantic_text = "structural-only" if not groups else f"{covered}/{expected}"
        byte_count = sum(path.stat().st_size for path in files)
        edge_delta = logs.max_cov - (logs.first_cov or 0)
        feature_delta = logs.max_features - (logs.first_features or 0)
        edge_text = f"{logs.max_cov}(+{edge_delta})"
        feature_text = f"{logs.max_features}(+{feature_delta})"
        stale = logs.latest_runs_since_new or 0
        print(
            f"{target:31} {len(files):6d} {byte_count:8d} {logs.executions:10d} "
            f"{edge_text:>9} {feature_text:>9} {logs.new_events:4d} {stale:6d} "
            f"{logs.peak_rss_mb:4d} {semantic_text}"
        )
        target_doc = {
            "corpus": {
                "files": len(files),
                "bytes": byte_count,
                "sha256": hashlib.sha256(
                    b"".join(
                        hashlib.sha256(path.read_bytes()).digest() for path in files
                    )
                ).hexdigest(),
            },
            "libfuzzer": {
                "logs": logs.logs,
                "executions": logs.executions,
                "first_edges": logs.first_cov,
                "first_features": logs.first_features,
                "max_edges": logs.max_cov,
                "max_features": logs.max_features,
                "new_events": logs.new_events,
                "peak_rss_mb": logs.peak_rss_mb,
                "final_exec_per_second": logs.final_exec_per_second,
                "latest_runs_since_new": logs.latest_runs_since_new,
            },
            "semantic": semantic,
        }
        document["targets"][target] = target_doc  # type: ignore[index]

    output = args.output or state / "summary.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"fuzz-report: JSON written to {output}")
    if args.strict_semantic and any_missing:
        print("fuzz-report: required semantic buckets are missing", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
