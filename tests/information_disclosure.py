#!/usr/bin/env python3
"""Generated attacker-view noninterference campaign.

Compatibility tests ask whether Vapache behaves like Apache.  This campaign
asks a different security question: can an unauthorized client distinguish two
server worlds that differ only in state it is not allowed to observe?

Each generated case is run twice on the same port, with the same configuration
and temporary root.  The worlds differ in one hidden fact: a protected target
exists or not, protected contents and metadata differ, a directory is populated
or empty, or a denied upstream would return a different payload.  Four stateful
sequences additionally preserve one live server across credentialed cache
exclusion and a principal switch, a grant-to-deny reload, or hidden autoindex
metadata mutation.  The
campaign compares the complete attacker-visible response after removing only
the Date header.  Status, body, length, validators, ranges, redirects,
challenges, cache disposition, compression and every other header remain part
of the oracle.

The matrix covers direct files, rewrites, aliases, MultiViews, DirectoryIndex,
CGI and PATH_INFO, autoindex, ErrorDocument, cache, directory-slash fallback and
HTTP proxy routes.  Directory, Files, Location, access-file, query-time and
Proxy authorization are crossed with existence/content state pairs.  Every
filesystem-backed transform sees canonical GET, HEAD, OPTIONS, Range,
conditional requests and URL spelling probes in one deterministic Latin square.

Failures produce replayable JSON under artifacts/information-disclosure.

Usage:
    python3 tests/information_disclosure.py --check
    python3 tests/information_disclosure.py
    python3 tests/information_disclosure.py --all-probes
    python3 tests/information_disclosure.py --stateful-only
    python3 tests/information_disclosure.py --only 'cache.*content-metadata'
    python3 tests/information_disclosure.py --list
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import http.client
import json
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import transform_differential as transform


ROOT = Path(__file__).resolve().parent.parent
VAPACHED = Path(os.environ.get("VAPACHED", ROOT / "target" / "release" / "vapached"))
PORT = int(os.environ.get("VAPACHE_DISCLOSURE_PORT", "18320"))
ARTIFACT_DIR = "artifacts/information-disclosure"
WORLD_TIMES = {"a": 1_700_000_000, "b": 1_600_000_000}
STATEFUL_SEQUENCES = (
    "credentialed-cache-exclusion-principal-switch",
    "reload-static-cache",
    "reload-cgi-path-info",
    "live-autoindex-metadata-mutation",
)


@dataclass(frozen=True)
class Probe:
    id: str
    method: str = "GET"
    spelling: str = "canonical"
    headers: tuple[tuple[str, str], ...] = ()
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Template:
    id: str
    kind: str
    policies: tuple[str, ...]
    states: tuple[str, ...]
    tags: tuple[str, ...]


@dataclass
class RequestStep:
    label: str
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Case:
    id: str
    template: str
    policy: str
    state: str
    probe: str
    tags: set[str]
    public_path: str
    guard_url: str
    query_guard_url: str
    selected_area: str | None
    selected_rel_dir: str | None
    selected_name: str
    config: list[str] = field(default_factory=list)
    common_dirs: set[str] = field(default_factory=set)
    common_files: dict[str, bytes] = field(default_factory=dict)
    world_dirs: dict[str, set[str]] = field(
        default_factory=lambda: {"a": set(), "b": set()}
    )
    world_files: dict[str, dict[str, bytes]] = field(
        default_factory=lambda: {"a": {}, "b": {}}
    )
    reset_dirs: set[str] = field(default_factory=set)
    executable_files: set[str] = field(default_factory=set)
    requests: list[RequestStep] = field(default_factory=list)
    backend_url: str | None = None

    def manifest(self) -> dict:
        return {
            "id": self.id,
            "axes": {
                "template": self.template,
                "policy": self.policy,
                "hidden_state": self.state,
                "probe": self.probe,
            },
            "tags": sorted(self.tags),
            "public_path": self.public_path,
            "guard_url": self.guard_url,
            "selected_area": self.selected_area,
            "selected_rel_dir": self.selected_rel_dir,
            "selected_name": self.selected_name,
            "config": self.config,
            "common_dirs": sorted(self.common_dirs),
            "common_files": encode_files(self.common_files),
            "world_dirs": {
                world: sorted(paths) for world, paths in self.world_dirs.items()
            },
            "world_files": {
                world: encode_files(files) for world, files in self.world_files.items()
            },
            "executable_files": sorted(self.executable_files),
            "requests": [dataclasses.asdict(step) for step in self.requests],
        }


FILESYSTEM_POLICIES = ("directory", "files", "location", "htaccess", "query")
COMMON_STATES = ("exists-missing", "content-metadata")

POLICY_TAGS = {
    "directory": "filesystem-policy",
    "files": "selected-name-policy",
    "location": "public-url-policy",
    "htaccess": "access-file-policy",
    "query": "query-dependent-policy",
    "proxy": "backend-policy",
}

PROBES = (
    Probe("canonical-get"),
    Probe("head", method="HEAD", tags=("method", "metadata")),
    Probe("options", method="OPTIONS", tags=("method", "capability-metadata")),
    Probe(
        "range-gzip",
        headers=(("Range", "bytes=0-3"), ("Accept-Encoding", "gzip")),
        tags=("range", "compression", "length"),
    ),
    Probe(
        "if-none-match",
        headers=(("If-None-Match", "*"),),
        tags=("validator", "existence"),
    ),
    Probe(
        "if-modified-since",
        headers=(("If-Modified-Since", "Wed, 31 Dec 2099 23:59:59 GMT"),),
        tags=("validator", "metadata"),
    ),
    Probe(
        "encoded-empty-query",
        spelling="encoded_unreserved",
        tags=("encoding", "query-spelling"),
    ),
    Probe(
        "repeated-slash-query",
        spelling="repeated_slash",
        tags=("repeated-slash", "query-spelling"),
    ),
    Probe("dot-segment", spelling="dot_segment", tags=("normalization",)),
    Probe("slash-boundary", spelling="slash_boundary", tags=("trailing-slash",)),
)

TEMPLATES = (
    Template("direct-static", "direct_static", FILESYSTEM_POLICIES, COMMON_STATES, ("static",)),
    Template("rewrite-static", "rewrite_static", FILESYSTEM_POLICIES, COMMON_STATES, ("rewrite",)),
    Template("alias-static", "alias_static", FILESYSTEM_POLICIES, COMMON_STATES, ("alias",)),
    Template("multiview", "multiview", FILESYSTEM_POLICIES, COMMON_STATES, ("negotiation", "fallback")),
    Template("directory-index", "index", FILESYSTEM_POLICIES, COMMON_STATES, ("directory-index", "fallback")),
    Template("direct-cgi", "cgi", FILESYSTEM_POLICIES, COMMON_STATES, ("cgi", "dynamic")),
    Template("cgi-path-info", "cgi_path_info", FILESYSTEM_POLICIES, COMMON_STATES, ("cgi", "path-info", "fallback")),
    Template("directory-list", "directory", FILESYSTEM_POLICIES, COMMON_STATES, ("autoindex", "directory")),
    Template("cache-static", "cache", FILESYSTEM_POLICIES, COMMON_STATES, ("cache", "static")),
    Template("error-document", "error_document", FILESYSTEM_POLICIES, COMMON_STATES, ("error-document", "fallback")),
    Template(
        "directory-slash",
        "directory_slash",
        ("location", "query"),
        ("directory-exists-missing",),
        ("directory-slash", "fallback", "existence"),
    ),
    Template(
        "proxy-http",
        "proxy",
        ("location", "query", "proxy"),
        ("backend-variation",),
        ("proxy", "backend"),
    ),
)


def encode_files(files: dict[str, bytes]) -> dict[str, str]:
    return {
        path: base64.b64encode(data).decode("ascii")
        for path, data in sorted(files.items())
    }


def safe_id(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def file_key(area: str, relative: str) -> str:
    return f"{area}/{relative.lstrip('/')}"


def confidential(case_id: str, world: str) -> bytes:
    padding = "A" * 17 if world == "a" else "B" * 73
    return f"CONFIDENTIAL:{case_id}:WORLD-{world.upper()}:{padding}\n".encode()


def cgi_secret(case_id: str, world: str) -> bytes:
    body = confidential(case_id, world).decode().rstrip("\n")
    return (
        "#!/bin/sh\n"
        "printf 'Content-Type: text/plain\\r\\n'\n"
        f"printf 'X-Hidden-World: {world}\\r\\n'\n"
        "printf '\\r\\n'\n"
        f"printf '{body}\\n'\n"
    ).encode()


def add_hidden_file(case: Case, key: str, executable: bool = False) -> None:
    if case.state == "exists-missing":
        case.world_files["a"][key] = (
            cgi_secret(case.id, "a") if executable else confidential(case.id, "a")
        )
    elif case.state == "content-metadata":
        case.world_files["a"][key] = (
            cgi_secret(case.id, "a") if executable else confidential(case.id, "a")
        )
        case.world_files["b"][key] = (
            cgi_secret(case.id, "b") if executable else confidential(case.id, "b")
        )
    else:  # pragma: no cover - generation validation owns state selection
        raise AssertionError(case.state)
    if executable:
        case.executable_files.add(key)


def selected_directory(case: Case) -> str:
    if case.selected_area is None or case.selected_rel_dir is None:
        raise AssertionError(f"{case.id} has no filesystem selection")
    root = "{DOCROOT}" if case.selected_area == "doc" else "{ALIASROOT}"
    return f"{root}/{case.selected_rel_dir}"


def apply_policy(case: Case) -> None:
    policy = case.policy
    guard_pattern = re.escape(case.guard_url)
    query_guard_pattern = re.escape(case.query_guard_url)
    # DirectorySlash and the proxy slash-boundary probe treat the slashless
    # and slash forms as two spellings of one protected route. Protect both;
    # an exact rule for only one form would intentionally leave the other URL
    # public rather than define a hidden-state noninterference case.
    if case.template in {"directory-slash", "proxy-http"}:
        guard_pattern += "/?"
        query_guard_pattern += "/?"
    if policy == "directory":
        case.config.extend(
            [
                f'<Directory "{selected_directory(case)}">',
                "    Require all denied",
                "</Directory>",
            ]
        )
    elif policy == "files":
        case.config.extend(
            [
                f'<Directory "{selected_directory(case)}">',
                f'    <Files "{case.selected_name}">',
                "        Require all denied",
                "    </Files>",
                "</Directory>",
            ]
        )
    elif policy == "location":
        case.config.extend(
            [
                f'<LocationMatch "^{guard_pattern}$">',
                "    Require all denied",
                "</LocationMatch>",
            ]
        )
    elif policy == "htaccess":
        assert case.selected_area is not None and case.selected_rel_dir is not None
        access_file = file_key(case.selected_area, f"{case.selected_rel_dir}/.htaccess")
        case.common_files[access_file] = (
            f'<Files "{case.selected_name}">\n'
            "    Require all denied\n"
            "</Files>\n"
        ).encode()
        case.config.extend(
            [
                f'<Directory "{selected_directory(case)}">',
                "    AllowOverride AuthConfig",
                "</Directory>",
            ]
        )
    elif policy == "query":
        case.config.extend(
            [
                f'<LocationMatch "^{query_guard_pattern}$">',
                '    <If "%{QUERY_STRING} =~ /(^|&)deny=1(&|$)/">',
                "        Require all denied",
                "    </If>",
                "</LocationMatch>",
            ]
        )
    elif policy == "proxy":
        if case.backend_url is None:
            raise AssertionError(f"{case.id} has no backend identity")
        case.config.extend(
            [
                f'<Proxy "{case.backend_url}">',
                "    Require all denied",
                "</Proxy>",
            ]
        )
    else:  # pragma: no cover
        raise AssertionError(policy)


def make_steps(case: Case, probe: Probe) -> list[RequestStep]:
    def guarded(path: str) -> str:
        return transform.add_query(path, "deny=1") if case.policy == "query" else path

    canonical = guarded(case.public_path)
    steps = [RequestStep("canonical-get", "GET", canonical)]

    probed = transform.apply_spelling(case.public_path, probe.spelling)
    if probe.id == "encoded-empty-query":
        base, _query = transform.split_query(probed)
        probed = f"{base}?"
    elif probe.id == "repeated-slash-query":
        probed = transform.add_query(probed, "visible=1")
    probed = guarded(probed)
    candidate = RequestStep(probe.id, probe.method, probed, dict(probe.headers))
    if candidate != steps[0]:
        steps.append(candidate)
    if case.template == "cache-static":
        steps.append(RequestStep("warm-repeat", "GET", canonical))
    return steps


def build_case(
    template: Template,
    policy: str,
    state: str,
    probe: Probe,
    ordinal: int,
) -> Case:
    slug = safe_id(f"nd-{ordinal:03d}-{template.id}-{policy}-{state}")
    public_path = f"/{slug}/secret.txt"
    selected_area: str | None = "doc"
    selected_rel_dir: str | None = slug
    selected_name = "secret.txt"
    guard_url = public_path
    query_guard_url = public_path
    case_id = f"{template.id}--{policy}--{state}--{probe.id}"
    tags = set(template.tags) | {POLICY_TAGS[policy]} | set(probe.tags) | {state}
    case = Case(
        id=case_id,
        template=template.id,
        policy=policy,
        state=state,
        probe=probe.id,
        tags=tags,
        public_path=public_path,
        guard_url=guard_url,
        query_guard_url=query_guard_url,
        selected_area=selected_area,
        selected_rel_dir=selected_rel_dir,
        selected_name=selected_name,
    )

    kind = template.kind
    if kind == "direct_static":
        case.common_dirs.add(file_key("doc", slug))
        add_hidden_file(case, file_key("doc", f"{slug}/secret.txt"))
    elif kind == "rewrite_static":
        case.public_path = f"/{slug}/front"
        case.guard_url = f"/{slug}/secret.txt"
        case.query_guard_url = case.guard_url
        case.common_dirs.add(file_key("doc", slug))
        case.config.extend(
            [
                "RewriteEngine On",
                f'RewriteRule "^{case.public_path}$" "/{slug}/secret.txt" [END]',
            ]
        )
        add_hidden_file(case, file_key("doc", f"{slug}/secret.txt"))
    elif kind == "alias_static":
        case.selected_area = "alias"
        case.selected_rel_dir = slug
        case.public_path = f"/alias-{slug}/secret.txt"
        case.guard_url = case.public_path
        case.query_guard_url = case.public_path
        case.common_dirs.add(file_key("alias", slug))
        case.config.extend(
            [
                f'Alias "/alias-{slug}/" "{{ALIASROOT}}/{slug}/"',
                f'<Directory "{{ALIASROOT}}/{slug}">',
                "    Options FollowSymLinks",
                "    Require all granted",
                "</Directory>",
            ]
        )
        add_hidden_file(case, file_key("alias", f"{slug}/secret.txt"))
    elif kind == "multiview":
        case.public_path = f"/{slug}/secret"
        case.guard_url = f"/{slug}/secret.txt"
        case.query_guard_url = case.guard_url
        case.common_dirs.add(file_key("doc", slug))
        case.config.extend(
            [
                f'<Directory "{{DOCROOT}}/{slug}">',
                "    Options +MultiViews",
                "    Require all granted",
                "</Directory>",
            ]
        )
        add_hidden_file(case, file_key("doc", f"{slug}/secret.txt"))
    elif kind == "index":
        case.selected_rel_dir = f"{slug}/vault"
        case.selected_name = "index.html"
        case.public_path = f"/{slug}/vault/"
        case.guard_url = f"/{case.selected_rel_dir}/index.html"
        case.query_guard_url = case.guard_url
        case.common_dirs.add(file_key("doc", case.selected_rel_dir))
        case.config.extend(
            [
                f'<Directory "{{DOCROOT}}/{case.selected_rel_dir}">',
                "    DirectoryIndex index.html",
                "    Require all granted",
                "</Directory>",
            ]
        )
        add_hidden_file(case, file_key("doc", f"{case.selected_rel_dir}/index.html"))
    elif kind in {"cgi", "cgi_path_info"}:
        case.selected_name = "secret.cgi"
        suffix = "/info" if kind == "cgi_path_info" else ""
        case.public_path = f"/{slug}/secret.cgi{suffix}"
        case.guard_url = f"/{slug}/secret.cgi"
        case.query_guard_url = case.guard_url
        case.common_dirs.add(file_key("doc", slug))
        case.config.extend(
            [
                f'<Directory "{{DOCROOT}}/{slug}">',
                "    Options +ExecCGI",
                "    Require all granted",
                "</Directory>",
            ]
        )
        add_hidden_file(case, file_key("doc", f"{slug}/secret.cgi"), executable=True)
    elif kind == "directory":
        case.selected_rel_dir = f"{slug}/vault"
        case.selected_name = "secret-record.txt"
        case.public_path = f"/{slug}/vault/"
        case.guard_url = f"/{case.selected_rel_dir}/secret-record.txt"
        case.query_guard_url = case.guard_url
        case.common_dirs.add(file_key("doc", case.selected_rel_dir))
        case.config.extend(
            [
                f'<Directory "{{DOCROOT}}/{case.selected_rel_dir}">',
                "    Options +Indexes",
                "    Require all granted",
                "</Directory>",
            ]
        )
        add_hidden_file(
            case, file_key("doc", f"{case.selected_rel_dir}/secret-record.txt")
        )
    elif kind == "cache":
        case.selected_rel_dir = f"matrix-cache/{slug}"
        case.public_path = f"/matrix-cache/{slug}/secret.txt"
        case.guard_url = case.public_path
        case.query_guard_url = case.public_path
        case.common_dirs.add(file_key("doc", case.selected_rel_dir))
        case.config.extend(
            [
                f'<Location "/matrix-cache/{slug}">',
                '    Header set Cache-Control "max-age=3600"',
                "</Location>",
            ]
        )
        add_hidden_file(case, file_key("doc", f"{case.selected_rel_dir}/secret.txt"))
    elif kind == "error_document":
        case.public_path = f"/{slug}/missing"
        case.guard_url = f"/{slug}/error.html"
        case.query_guard_url = case.guard_url
        case.selected_name = "error.html"
        case.common_dirs.add(file_key("doc", slug))
        error_target = case.guard_url + ("?deny=1" if policy == "query" else "")
        case.config.extend(
            [
                f'<Directory "{{DOCROOT}}/{slug}">',
                f"    ErrorDocument 404 {error_target}",
                "    Require all granted",
                "</Directory>",
            ]
        )
        add_hidden_file(case, file_key("doc", f"{slug}/error.html"))
    elif kind == "directory_slash":
        case.selected_area = None
        case.selected_rel_dir = None
        case.selected_name = "vault"
        case.public_path = f"/{slug}/vault"
        case.guard_url = case.public_path
        case.query_guard_url = case.public_path
        case.common_dirs.add(file_key("doc", slug))
        vault = file_key("doc", f"{slug}/vault")
        case.reset_dirs.add(vault)
        case.world_dirs["a"].add(vault)
        case.world_files["a"][file_key("doc", f"{slug}/vault/secret.txt")] = confidential(
            case.id, "a"
        )
    elif kind == "proxy":
        case.selected_area = None
        case.selected_rel_dir = None
        case.selected_name = "upstream"
        case.public_path = f"/proxy-{slug}/secret"
        case.guard_url = case.public_path
        case.query_guard_url = case.public_path
        case.backend_url = f"http://127.0.0.1:{{BACKEND}}/up/{slug}/"
        case.config.extend(
            [
                f'ProxyPass "/proxy-{slug}/" "{case.backend_url}"',
                f'<Proxy "{case.backend_url}">',
                "    Require all granted",
                "</Proxy>",
            ]
        )
    else:  # pragma: no cover
        raise AssertionError(kind)

    apply_policy(case)
    case.requests = make_steps(case, probe)
    return case


def generate_cases(seed: int) -> list[Case]:
    cases: list[Case] = []
    offset = seed % len(PROBES)
    ordinal = 0
    for template_index, template in enumerate(TEMPLATES):
        for policy_index, policy in enumerate(template.policies):
            for state_index, state in enumerate(template.states):
                slot = policy_index * len(template.states) + state_index
                probe = PROBES[(template_index + slot + offset) % len(PROBES)]
                cases.append(build_case(template, policy, state, probe, ordinal))
                ordinal += 1
    return cases


def generation_errors(cases: list[Case]) -> list[str]:
    errors: list[str] = []
    expected = sum(len(t.policies) * len(t.states) for t in TEMPLATES)
    if len(cases) != expected:
        errors.append(f"generated {len(cases)} cases, expected {expected}")
    ids = [case.id for case in cases]
    if len(ids) != len(set(ids)):
        errors.append("case IDs are not unique")

    for template in TEMPLATES:
        rows = [case for case in cases if case.template == template.id]
        pairs = {(case.policy, case.state) for case in rows}
        expected_pairs = {
            (policy, state) for policy in template.policies for state in template.states
        }
        if pairs != expected_pairs:
            errors.append(f"{template.id}: incomplete policy/state coverage")
        if len(rows) == len(PROBES) and {case.probe for case in rows} != {
            probe.id for probe in PROBES
        }:
            errors.append(f"{template.id}: incomplete probe coverage")

    seen_probes = {case.probe for case in cases}
    if seen_probes != {probe.id for probe in PROBES}:
        errors.append(f"incomplete probe coverage: {sorted(seen_probes)}")
    required_tags = {
        "static",
        "rewrite",
        "alias",
        "negotiation",
        "directory-index",
        "cgi",
        "path-info",
        "autoindex",
        "cache",
        "error-document",
        "directory-slash",
        "proxy",
        "range",
        "validator",
        "encoding",
        "normalization",
        "trailing-slash",
    }
    seen_tags = set().union(*(case.tags for case in cases))
    missing_tags = required_tags - seen_tags
    if missing_tags:
        errors.append(f"missing risk tags: {sorted(missing_tags)}")
    for case in cases:
        if not case.requests:
            errors.append(f"{case.id}: no requests")
        configured_deny = any("Require all denied" in line for line in case.config)
        access_file_deny = any(
            b"Require all denied" in body for body in case.common_files.values()
        )
        if not configured_deny and not access_file_deny:
            errors.append(f"{case.id}: no denial policy")
    return errors


def probe_rotation_errors(seed: int) -> list[str]:
    errors: list[str] = []
    rotations = [generate_cases(seed + offset) for offset in range(len(PROBES))]
    rows = [case for rotation in rotations for case in rotation]
    expected_count = len(rotations[0]) * len(PROBES)
    if len(rows) != expected_count:
        errors.append(f"probe rotations generated {len(rows)} cases, expected {expected_count}")

    expected_probes = {probe.id for probe in PROBES}
    base_rows = {
        (case.template, case.policy, case.state) for case in rotations[0]
    }
    for template, policy, state in sorted(base_rows):
        actual = {
            case.probe
            for case in rows
            if (case.template, case.policy, case.state) == (template, policy, state)
        }
        if actual != expected_probes:
            errors.append(
                f"{template}/{policy}/{state}: incomplete rotated probes {sorted(actual)}"
            )
    identities = {(case.template, case.policy, case.state, case.probe) for case in rows}
    if len(identities) != expected_count:
        errors.append(
            f"probe rotations have {len(identities)} unique intersections, "
            f"expected {expected_count}"
        )
    return errors


class BackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self) -> None:
        server = self.server
        assert isinstance(server, DisclosureBackend)
        with server.state_lock:
            server.requests[self.path] = server.requests.get(self.path, 0) + 1
            world = server.world
        padding = "A" * 19 if world == "a" else "B" * 79
        body = f"UPSTREAM-CONFIDENTIAL:WORLD-{world.upper()}:{padding}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("ETag", f'"upstream-{world}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _reply
    do_HEAD = _reply
    do_OPTIONS = _reply

    def log_message(self, _format: str, *_args) -> None:
        pass


class DisclosureBackend(ThreadingHTTPServer):
    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), BackendHandler)
        self.world = "a"
        self.requests: dict[str, int] = {}
        self.state_lock = threading.Lock()


@dataclass
class Runtime:
    base: Path
    docroot: Path
    aliasroot: Path
    cache_root: Path
    backend: DisclosureBackend
    process: subprocess.Popen | None = None
    stream: object | None = None

    @property
    def backend_port(self) -> int:
        return int(self.backend.server_address[1])

    def resolve(self, key: str) -> Path:
        area, relative = key.split("/", 1)
        root = self.docroot if area == "doc" else self.aliasroot
        return root / relative

    def render(self, value: str) -> str:
        return (
            value.replace("{DOCROOT}", str(self.docroot))
            .replace("{ALIASROOT}", str(self.aliasroot))
            .replace("{BACKEND}", str(self.backend_port))
        )


def chmod_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o755)


def write_runtime_file(runtime: Runtime, key: str, data: bytes, executable: bool) -> None:
    path = runtime.resolve(key)
    chmod_dir(path.parent)
    path.write_bytes(data)
    os.chmod(path, 0o755 if executable else 0o644)


def prepare_runtime(cases: list[Case]) -> Runtime:
    base = Path(tempfile.mkdtemp(prefix="vapache-disclosure-"))
    docroot = base / "www"
    aliasroot = base / "alias"
    cache_root = base / "cache"
    for path in (base, docroot, aliasroot, cache_root, base / "logs"):
        chmod_dir(path)
    os.chmod(cache_root, 0o777)

    backend = DisclosureBackend()
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    runtime = Runtime(base, docroot, aliasroot, cache_root, backend)
    for case in cases:
        for key in case.common_dirs:
            chmod_dir(runtime.resolve(key))
        for key, data in case.common_files.items():
            write_runtime_file(runtime, key, data, key in case.executable_files)
    return runtime


def apply_world(runtime: Runtime, cases: list[Case], world: str) -> None:
    for case in cases:
        for key in sorted(case.reset_dirs, key=len, reverse=True):
            path = runtime.resolve(key)
            if path.exists():
                shutil.rmtree(path)
        all_files = set(case.world_files["a"]) | set(case.world_files["b"])
        for key in all_files:
            path = runtime.resolve(key)
            if path.exists() or path.is_symlink():
                path.unlink()
        for key in case.world_dirs[world]:
            chmod_dir(runtime.resolve(key))
        for key, data in case.world_files[world].items():
            write_runtime_file(runtime, key, data, key in case.executable_files)
            os.utime(runtime.resolve(key), (WORLD_TIMES[world], WORLD_TIMES[world]))

    if runtime.cache_root.exists():
        shutil.rmtree(runtime.cache_root)
    runtime.cache_root.mkdir(mode=0o777)
    os.chmod(runtime.cache_root, 0o777)
    with runtime.backend.state_lock:
        runtime.backend.world = world
        runtime.backend.requests.clear()


def server_config(runtime: Runtime, cases: list[Case]) -> str:
    lines = transform.module_lines()
    lines.extend(
        [
            "VapacheCapability AccessFiles On",
            "VapacheCapability AutoIndex On",
            "VapacheCapability Cgi On",
            f'ServerRoot "{runtime.base}"',
            f"Listen {PORT}",
            f"User {transform.SERVICE_USER}",
            f"Group {transform.SERVICE_GROUP}",
            f'PidFile "{runtime.base}/logs/vapache.pid"',
            f'ErrorLog "{runtime.base}/logs/error.log"',
            "LogLevel warn",
            "ServerName localhost",
            "Timeout 10",
            f'DocumentRoot "{runtime.docroot}"',
            "TypesConfig /etc/mime.types",
            "AddType text/plain .txt",
            "AddHandler cgi-script .cgi",
            f'CacheRoot "{runtime.cache_root}"',
            "CacheEnable disk /matrix-cache/",
            "CacheHeader On",
            "CacheDefaultExpire 3600",
            "<Directory />",
            "    AllowOverride None",
            "    Require all denied",
            "</Directory>",
            f'<Directory "{runtime.docroot}">',
            "    Options FollowSymLinks",
            "    AllowOverride None",
            "    Require all granted",
            "</Directory>",
            f'<Directory "{runtime.aliasroot}">',
            "    Options FollowSymLinks",
            "    AllowOverride None",
            "    Require all granted",
            "</Directory>",
        ]
    )
    for case in cases:
        lines.append(f"# disclosure case: {case.id}")
        lines.extend(runtime.render(line) for line in case.config)
    return "\n".join(lines) + "\n"


def run_checked(cmd: list[str], label: str) -> None:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(
            f"{label} failed ({result.returncode}):\n{result.stdout}{result.stderr}"
        )


def wait_port(timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def start_server(runtime: Runtime, world: str, config: Path) -> None:
    log = open(runtime.base / f"logs/vapache-{world}.out", "ab")
    runtime.stream = log
    runtime.process = subprocess.Popen(
        [str(VAPACHED), "-f", str(config), "-DFOREGROUND"],
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    if not wait_port():
        log.flush()
        output = (runtime.base / f"logs/vapache-{world}.out").read_text(errors="replace")
        raise RuntimeError(f"Vapache world {world} failed to start\n{output[-8000:]}")


def stop_server(runtime: Runtime) -> None:
    process = runtime.process
    if process is not None and process.poll() is None:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    if runtime.stream is not None:
        runtime.stream.close()  # type: ignore[union-attr]
    runtime.process = None
    runtime.stream = None


def stop_runtime(runtime: Runtime, keep_tree: bool) -> None:
    stop_server(runtime)
    runtime.backend.shutdown()
    runtime.backend.server_close()
    if keep_tree:
        print(f"tree: {runtime.base}")
    else:
        shutil.rmtree(runtime.base, ignore_errors=True)


def send_request(step: RequestStep) -> dict:
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=8)
    try:
        headers = {"Connection": "close", **step.headers}
        connection.request(step.method, step.path, headers=headers)
        response = connection.getresponse()
        body = response.read()
        header_lines = [
            (name.lower(), value) for name, value in response.getheaders()
        ]
        response_headers: dict[str, list[str]] = {}
        for name, value in header_lines:
            response_headers.setdefault(name, []).append(value)
        return {
            "version": response.version,
            "status": response.status,
            "reason": response.reason,
            "header_lines": header_lines,
            "headers": response_headers,
            "body": body,
        }
    finally:
        connection.close()


def attacker_view(observation: dict) -> dict:
    header_lines = [
        (name, value)
        for name, value in observation["header_lines"]
        if name != "date"
    ]
    return {
        "version": observation["version"],
        "status": observation["status"],
        "reason": observation["reason"],
        "headers": header_lines,
        "body": observation["body"],
    }


def printable_observation(observation: dict) -> dict:
    body: bytes = observation["body"]
    return {
        "version": observation["version"],
        "status": observation["status"],
        "reason": observation["reason"],
        "headers": observation["header_lines"],
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_base64": base64.b64encode(body).decode("ascii"),
    }


def forbidden_disclosures(runtime: Runtime, observation: dict) -> list[str]:
    wire = bytearray(observation["body"])
    for name, values in observation["headers"].items():
        wire.extend(name.encode())
        for value in values:
            wire.extend(value.encode(errors="replace"))
    checks = {
        "fixture secret marker": b"CONFIDENTIAL:",
        "upstream secret marker": b"UPSTREAM-CONFIDENTIAL:",
        "temporary filesystem root": str(runtime.base).encode(),
    }
    return [label for label, token in checks.items() if token in wire]


def describe_difference(first: dict, second: dict) -> list[str]:
    problems: list[str] = []
    if first["version"] != second["version"]:
        problems.append(
            f"HTTP version world-a={first['version']} world-b={second['version']}"
        )
    if first["status"] != second["status"]:
        problems.append(f"status world-a={first['status']} world-b={second['status']}")
    if first["reason"] != second["reason"]:
        problems.append(f"reason world-a={first['reason']} world-b={second['reason']}")
    if first["headers"] != second["headers"]:
        names = sorted(
            {name for name, _value in first["headers"]}
            | {name for name, _value in second["headers"]}
        )
        changed = [
            name
            for name in names
            if [value for header, value in first["headers"] if header == name]
            != [value for header, value in second["headers"] if header == name]
        ]
        detail = ", ".join(changed) if changed else "line ordering"
        problems.append(f"headers differ: {detail}")
    if first["body"] != second["body"]:
        problems.append(
            "body differs "
            f"world-a={hashlib.sha256(first['body']).hexdigest()[:16]} "
            f"world-b={hashlib.sha256(second['body']).hexdigest()[:16]}"
        )
    return problems


def run_world(
    runtime: Runtime,
    cases: list[Case],
    world: str,
    config: Path,
    verbose: bool,
) -> tuple[dict[str, list[dict]], dict[str, int]]:
    apply_world(runtime, cases, world)
    observations: dict[str, list[dict]] = {}
    start_server(runtime, world, config)
    try:
        burst = 0
        for case in cases:
            rows = []
            for step in case.requests:
                if burst and burst % 12 == 0:
                    time.sleep(1.05)
                observation = send_request(step)
                rows.append(observation)
                burst += 1
                if verbose:
                    print(
                        f"    world-{world} {case.id} {step.method} {step.path}: "
                        f"{observation['status']}"
                    )
            observations[case.id] = rows
        with runtime.backend.state_lock:
            backend_requests = dict(runtime.backend.requests)
        return observations, backend_requests
    finally:
        stop_server(runtime)


def write_artifact(
    artifact_dir: Path,
    case: Case,
    seed: int,
    problems: list[str],
    observations_a: list[dict],
    observations_b: list[dict],
) -> Path:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / f"{safe_id(case.id)}.json"
    payload = {
        "schema": 1,
        "seed": seed,
        "case": case.manifest(),
        "problems": problems,
        "world_a": [printable_observation(row) for row in observations_a],
        "world_b": [printable_observation(row) for row in observations_b],
        "replay": (
            f"python3 tests/information_disclosure.py --seed {seed} "
            f"--only '^{re.escape(case.id)}$' --keep-tree -v"
        ),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def filter_cases(cases: list[Case], pattern: str, sample: int, seed: int) -> list[Case]:
    if pattern:
        regex = re.compile(pattern, re.IGNORECASE)
        cases = [case for case in cases if regex.search(case.id)]
    if sample:
        if sample > len(cases):
            raise ValueError(f"sample {sample} exceeds the {len(cases)} selected cases")
        cases = random.Random(seed).sample(cases, sample)
        cases.sort(key=lambda case: case.id)
    return cases


def run_live(cases: list[Case], args: argparse.Namespace) -> int:
    if not VAPACHED.is_file():
        raise RuntimeError(f"missing {VAPACHED}; build the release daemon first")
    missing_modules = [
        str(transform.MODDIR / f"mod_{module.removesuffix('_module')}.so")
        for module in transform.MODULES
        if not (transform.MODDIR / f"mod_{module.removesuffix('_module')}.so").is_file()
    ]
    if missing_modules:
        raise RuntimeError(f"missing Apache-compatible modules: {', '.join(missing_modules)}")

    runtime = prepare_runtime(cases)
    try:
        config = runtime.base / "vapache-httpd.conf"
        config.write_text(server_config(runtime, cases))
        apply_world(runtime, cases, "a")
        run_checked([str(VAPACHED), "-t", "-f", str(config)], "Vapache configtest")
        observations_a, backend_a = run_world(runtime, cases, "a", config, args.verbose)
        observations_b, backend_b = run_world(runtime, cases, "b", config, args.verbose)

        failures = 0
        steps = 0
        artifact_dir = Path(args.artifact_dir)
        for case in cases:
            rows_a = observations_a[case.id]
            rows_b = observations_b[case.id]
            problems: list[str] = []
            for index, step in enumerate(case.requests):
                steps += 1
                first = attacker_view(rows_a[index])
                second = attacker_view(rows_b[index])
                for problem in describe_difference(first, second):
                    problems.append(f"{step.label}: {problem}")
                for world, row in (("a", rows_a[index]), ("b", rows_b[index])):
                    for disclosure in forbidden_disclosures(runtime, row):
                        problems.append(f"{step.label}: world-{world} leaked {disclosure}")

            if case.template == "proxy-http":
                route = f"/up/{case.public_path.split('/')[1].removeprefix('proxy-')}/secret"
                contacts_a = backend_a.get(route, 0)
                contacts_b = backend_b.get(route, 0)
                if contacts_a or contacts_b:
                    problems.append(
                        f"denied route contacted backend world-a={contacts_a} world-b={contacts_b}"
                    )

            if problems:
                failures += 1
                artifact = write_artifact(
                    artifact_dir, case, args.seed, problems, rows_a, rows_b
                )
                print(f"FAIL {case.id}")
                for problem in problems:
                    print(f"     {problem}")
                print(f"     artifact: {artifact}")
            else:
                print(f"ok   {case.id}")

        print(
            f"\n{len(cases)} generated cases, {steps * 2} paired-world request observations, "
            f"{failures} disclosure divergence(s)"
        )
        return 1 if failures else 0
    finally:
        stop_runtime(runtime, args.keep_tree)


def stateful_config(runtime: Runtime, deny_reloaded_targets: bool) -> str:
    lines = transform.module_lines()
    lines.extend(
        [
            "VapacheCapability AccessFiles On",
            "VapacheCapability AutoIndex On",
            "VapacheCapability Cgi On",
            "VapacheCapability MutableAuthFiles On",
            f'ServerRoot "{runtime.base}"',
            f"Listen {PORT}",
            f"User {transform.SERVICE_USER}",
            f"Group {transform.SERVICE_GROUP}",
            f'PidFile "{runtime.base}/logs/vapache.pid"',
            f'ErrorLog "{runtime.base}/logs/error.log"',
            "LogLevel warn",
            "ServerName localhost",
            "Timeout 10",
            f'DocumentRoot "{runtime.docroot}"',
            "TypesConfig /etc/mime.types",
            "AddType text/plain .txt",
            "AddHandler cgi-script .cgi",
            f'CacheRoot "{runtime.cache_root}"',
            "CacheEnable disk /",
            "CacheHeader On",
            "CacheDefaultExpire 3600",
            "<Directory />",
            "    AllowOverride None",
            "    Require all denied",
            "</Directory>",
            f'<Directory "{runtime.docroot}">',
            "    Options FollowSymLinks",
            "    AllowOverride None",
            "    Require all granted",
            "</Directory>",
            f'<Directory "{runtime.docroot}/state-auth">',
            "    AuthType Basic",
            '    AuthName "stateful cache"',
            f'    AuthUserFile "{runtime.base}/stateful.htpasswd"',
            "    Require valid-user",
            "</Directory>",
            f'<Directory "{runtime.docroot}/state-cgi">',
            "    Options +ExecCGI",
            "    Require all granted",
            "</Directory>",
            f'<Directory "{runtime.docroot}/state-list">',
            "    Options +Indexes",
            "    Require all granted",
            '    <Files "secret-record.txt">',
            "        Require all denied",
            "    </Files>",
            "</Directory>",
            '<LocationMatch "^/state-(auth|reload|cgi)/">',
            '    Header set Cache-Control "max-age=3600"',
            "</LocationMatch>",
        ]
    )
    if deny_reloaded_targets:
        lines.extend(
            [
                f'<Directory "{runtime.docroot}/state-reload">',
                '    <Files "secret.txt">',
                "        Require all denied",
                "    </Files>",
                "</Directory>",
                f'<Directory "{runtime.docroot}/state-cgi">',
                '    <Files "secret.cgi">',
                "        Require all denied",
                "    </Files>",
                "</Directory>",
            ]
        )
    return "\n".join(lines) + "\n"


def stateful_fixture(runtime: Runtime, world: str) -> None:
    for relative in ("state-auth", "state-reload", "state-cgi", "state-list"):
        chmod_dir(runtime.docroot / relative)

    hidden = confidential(f"stateful-{world}", world)
    for relative in ("state-auth/secret.txt", "state-reload/secret.txt"):
        path = runtime.docroot / relative
        path.write_bytes(hidden)
        os.chmod(path, 0o644)
        os.utime(path, (WORLD_TIMES[world], WORLD_TIMES[world]))

    script = runtime.docroot / "state-cgi/secret.cgi"
    script.write_bytes(cgi_secret("stateful-cgi", world))
    os.chmod(script, 0o755)
    os.utime(script, (WORLD_TIMES[world], WORLD_TIMES[world]))

    listing_secret = runtime.docroot / "state-list/secret-record.txt"
    listing_secret.write_bytes(hidden)
    os.chmod(listing_secret, 0o644)
    os.utime(listing_secret, (WORLD_TIMES[world], WORLD_TIMES[world]))
    public = runtime.docroot / "state-list/public-record.txt"
    public.write_bytes(b"public\n")
    os.chmod(public, 0o644)
    os.utime(public, (1_500_000_000, 1_500_000_000))
    os.utime(runtime.docroot / "state-list", (1_500_000_000, 1_500_000_000))

    # SHA-1 is used only as an Apache-compatible fixture format. The campaign
    # authenticates once to populate the cache, then evaluates the anonymous
    # attacker's view.
    password_digest = base64.b64encode(hashlib.sha1(b"secret").digest()).decode(
        "ascii"
    )
    htpasswd = runtime.base / "stateful.htpasswd"
    htpasswd.write_text(f"alice:{{SHA}}{password_digest}\n")
    os.chmod(htpasswd, 0o644)


def checked_stateful_request(step: RequestStep) -> dict:
    observation = send_request(step)
    return observation


def warm_stateful_target(
    step: RequestStep, label: str, cache_expectation: str = "hit"
) -> None:
    last: dict | None = None
    for _attempt in range(2):
        last = checked_stateful_request(step)
        if last["status"] != 200 or b"CONFIDENTIAL:" not in last["body"]:
            raise RuntimeError(
                f"{label} did not warm protected content: "
                f"status={last['status']} body={last['body'][:200]!r}"
            )
    cache_state = None if last is None else last["headers"].get("x-cache")
    if cache_expectation == "hit" and cache_state != ["HIT"]:
        raise RuntimeError(f"{label} did not produce a cache hit; X-Cache={cache_state}")
    if cache_expectation == "excluded" and cache_state == ["HIT"]:
        raise RuntimeError(f"{label} persisted a credentialed response in shared cache")


def wait_for_reloaded_denial(timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    last: dict | None = None
    step = RequestStep("reload-probe", "GET", "/state-reload/secret.txt")
    while time.monotonic() < deadline:
        try:
            last = send_request(step)
            if last["status"] == 403:
                return
        except OSError:
            pass
        time.sleep(0.05)
    status = None if last is None else last["status"]
    raise RuntimeError(f"stateful grant-to-deny reload did not commit; last status={status}")


def collect_steps(steps: list[RequestStep]) -> list[dict]:
    return [checked_stateful_request(step) for step in steps]


def run_stateful_world(world: str, verbose: bool) -> tuple[Runtime, dict[str, list[dict]]]:
    runtime = prepare_runtime([])
    try:
        stateful_fixture(runtime, world)
        config = runtime.base / "vapache-stateful.conf"
        config.write_text(stateful_config(runtime, False))
        run_checked([str(VAPACHED), "-t", "-f", str(config)], "stateful configtest")
        start_server(runtime, f"stateful-{world}", config)
    except Exception:
        stop_runtime(runtime, True)
        raise

    auth = base64.b64encode(b"alice:secret").decode("ascii")
    auth_headers = {"Authorization": f"Basic {auth}"}
    groups: dict[str, list[dict]] = {}
    try:
        warm_stateful_target(
            RequestStep(
                "authenticated-warm",
                "GET",
                "/state-auth/secret.txt",
                auth_headers,
            ),
            "credentialed cache exclusion",
            cache_expectation="excluded",
        )
        groups["credentialed-cache-exclusion-principal-switch"] = collect_steps(
            [
                RequestStep("anonymous-get", "GET", "/state-auth/secret.txt"),
                RequestStep("anonymous-head", "HEAD", "/state-auth/secret.txt"),
                RequestStep(
                    "anonymous-range",
                    "GET",
                    "/state-auth/secret.txt",
                    {"Range": "bytes=0-3", "Accept-Encoding": "gzip"},
                ),
                RequestStep(
                    "anonymous-validator",
                    "GET",
                    "/state-auth/secret.txt",
                    {"If-None-Match": "*"},
                ),
            ]
        )

        warm_stateful_target(
            RequestStep("static-warm", "GET", "/state-reload/secret.txt"),
            "reload static cache",
        )
        warm_stateful_target(
            RequestStep("cgi-warm", "GET", "/state-cgi/secret.cgi/info"),
            "reload CGI cache",
            cache_expectation="unchecked",
        )

        list_step = RequestStep("autoindex", "GET", "/state-list/")
        direct_step = RequestStep(
            "autoindex-direct-denial", "GET", "/state-list/secret-record.txt"
        )
        before = collect_steps([list_step, direct_step])
        listing_secret = runtime.docroot / "state-list/secret-record.txt"
        listing_secret.write_bytes(
            b"CONFIDENTIAL:STATEFUL-MUTATION:" + (b"X" * 4093) + b"\n"
        )
        os.chmod(listing_secret, 0o644)
        os.utime(listing_secret, (1_800_000_000, 1_800_000_000))
        after = collect_steps([list_step, direct_step])
        groups["live-autoindex-metadata-mutation-before"] = before
        groups["live-autoindex-metadata-mutation-after"] = after

        config.write_text(stateful_config(runtime, True))
        process = runtime.process
        if process is None or process.poll() is not None:
            raise RuntimeError("stateful server exited before reload")
        os.kill(process.pid, signal.SIGHUP)
        wait_for_reloaded_denial()
        groups["reload-static-cache"] = collect_steps(
            [
                RequestStep("denied-get", "GET", "/state-reload/secret.txt"),
                RequestStep("denied-head", "HEAD", "/state-reload/secret.txt"),
                RequestStep(
                    "denied-range",
                    "GET",
                    "/state-reload/secret.txt",
                    {"Range": "bytes=0-3", "Accept-Encoding": "gzip"},
                ),
                RequestStep(
                    "denied-validator",
                    "GET",
                    "/state-reload/secret.txt",
                    {"If-None-Match": "*"},
                ),
            ]
        )
        groups["reload-cgi-path-info"] = collect_steps(
            [
                RequestStep("denied-script", "GET", "/state-cgi/secret.cgi"),
                RequestStep("denied-path-info", "GET", "/state-cgi/secret.cgi/info"),
                RequestStep("denied-path-info-head", "HEAD", "/state-cgi/secret.cgi/info"),
            ]
        )
        if verbose:
            for group, rows in groups.items():
                print(
                    f"    stateful world-{world} {group}: "
                    + ", ".join(str(row["status"]) for row in rows)
                )
        return runtime, groups
    except Exception:
        stop_runtime(runtime, True)
        raise
    finally:
        stop_server(runtime)


def write_stateful_artifact(
    artifact_dir: Path,
    sequence: str,
    problems: list[str],
    world_a: list[dict],
    world_b: list[dict],
) -> Path:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / f"stateful-{safe_id(sequence)}.json"
    payload = {
        "schema": 1,
        "sequence": sequence,
        "problems": problems,
        "world_a": [printable_observation(row) for row in world_a],
        "world_b": [printable_observation(row) for row in world_b],
        "replay": "python3 tests/information_disclosure.py --stateful-only -v",
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def compare_stateful_sequence(
    sequence: str,
    runtime_a: Runtime,
    runtime_b: Runtime,
    rows_a: list[dict],
    rows_b: list[dict],
) -> list[str]:
    problems: list[str] = []
    if len(rows_a) != len(rows_b):
        return [f"observation count world-a={len(rows_a)} world-b={len(rows_b)}"]
    for index, (row_a, row_b) in enumerate(zip(rows_a, rows_b, strict=True)):
        for problem in describe_difference(attacker_view(row_a), attacker_view(row_b)):
            problems.append(f"observation-{index}: {problem}")
        for world, runtime, row in (
            ("a", runtime_a, row_a),
            ("b", runtime_b, row_b),
        ):
            for disclosure in forbidden_disclosures(runtime, row):
                problems.append(f"observation-{index}: world-{world} leaked {disclosure}")

    expected_statuses = {
        "credentialed-cache-exclusion-principal-switch": [401, 401, 401, 401],
        "reload-static-cache": [403, 403, 403, 403],
        "reload-cgi-path-info": [403, 404, 404],
        "live-autoindex-metadata-mutation": [200, 403, 200, 403],
    }[sequence]
    for world, rows in (("a", rows_a), ("b", rows_b)):
        actual_statuses = [row["status"] for row in rows]
        if actual_statuses != expected_statuses:
            problems.append(
                f"world-{world} statuses={actual_statuses}, expected={expected_statuses}"
            )
        if sequence == "live-autoindex-metadata-mutation":
            for index in (0, 2):
                if b"secret-record.txt" in rows[index]["body"]:
                    problems.append(
                        f"world-{world} observation-{index} exposed denied entry name"
                    )
    return problems


def run_stateful(args: argparse.Namespace) -> tuple[int, int]:
    if not VAPACHED.is_file():
        raise RuntimeError(f"missing {VAPACHED}; build the release daemon first")
    runtime_a: Runtime | None = None
    runtime_b: Runtime | None = None
    try:
        runtime_a, groups_a = run_stateful_world("a", args.verbose)
        runtime_b, groups_b = run_stateful_world("b", args.verbose)
        failures = 0
        observations = 0
        for sequence in STATEFUL_SEQUENCES:
            if sequence == "live-autoindex-metadata-mutation":
                rows_a = groups_a[f"{sequence}-before"] + groups_a[f"{sequence}-after"]
                rows_b = groups_b[f"{sequence}-before"] + groups_b[f"{sequence}-after"]
            else:
                rows_a = groups_a[sequence]
                rows_b = groups_b[sequence]
            observations += len(rows_a) + len(rows_b)
            problems = compare_stateful_sequence(
                sequence, runtime_a, runtime_b, rows_a, rows_b
            )
            if sequence == "live-autoindex-metadata-mutation":
                for world, groups in (("a", groups_a), ("b", groups_b)):
                    before = groups[f"{sequence}-before"]
                    after = groups[f"{sequence}-after"]
                    for index, (first, second) in enumerate(
                        zip(before, after, strict=True)
                    ):
                        for problem in describe_difference(
                            attacker_view(first), attacker_view(second)
                        ):
                            problems.append(
                                f"world-{world} live-mutation-{index}: {problem}"
                            )
            if problems:
                failures += 1
                artifact = write_stateful_artifact(
                    Path(args.artifact_dir), sequence, problems, rows_a, rows_b
                )
                print(f"FAIL stateful--{sequence}")
                for problem in problems:
                    print(f"     {problem}")
                print(f"     artifact: {artifact}")
            else:
                print(f"ok   stateful--{sequence}")
        print(
            f"\n{len(STATEFUL_SEQUENCES)} stateful sequences, "
            f"{observations} attacker observations, {failures} disclosure divergence(s)"
        )
        return (1 if failures else 0), observations
    finally:
        if runtime_a is not None:
            stop_runtime(runtime_a, args.keep_tree)
        if runtime_b is not None:
            stop_runtime(runtime_b, args.keep_tree)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate generation and exit")
    parser.add_argument("--list", action="store_true", help="print the generated manifest and exit")
    parser.add_argument("--only", default="", help="run case IDs matching this regular expression")
    parser.add_argument("--sample", type=int, default=0, help="run a deterministic sample")
    parser.add_argument("--seed", type=int, default=9049)
    parser.add_argument(
        "--all-probes",
        action="store_true",
        help="run all ten probe rotations (the full case/probe cross-product)",
    )
    parser.add_argument(
        "--stateful-only",
        action="store_true",
        help="run only authenticated-warm, reload and live-mutation sequences",
    )
    parser.add_argument(
        "--skip-stateful",
        action="store_true",
        help="omit the stateful sequences from a full single-rotation run",
    )
    parser.add_argument("--artifact-dir", default=ARTIFACT_DIR)
    parser.add_argument("--keep-tree", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    cases = generate_cases(args.seed)
    errors = generation_errors(cases) + probe_rotation_errors(args.seed)
    if errors:
        for error in errors:
            print(f"generation error: {error}", file=sys.stderr)
        return 2
    if args.list:
        print(json.dumps([case.manifest() for case in cases], indent=2, sort_keys=True))
        return 0
    if args.check:
        print(
            f"information-disclosure generation: {len(cases)} cases, "
            f"{len(TEMPLATES)} transforms, {len(PROBES)} probes, "
            f"{len({case.policy for case in cases})} policy phases, "
            f"{len({case.state for case in cases})} hidden-state relations, "
            f"{len(STATEFUL_SEQUENCES)} stateful sequences; "
            f"{len(cases) * len(PROBES)} full-rotation intersections"
        )
        return 0
    if args.stateful_only and (
        args.only or args.sample or args.all_probes or args.skip_stateful
    ):
        print(
            "selection error: --stateful-only cannot be combined with case selection, "
            "--all-probes or --skip-stateful",
            file=sys.stderr,
        )
        return 2
    if args.all_probes and (args.only or args.sample):
        print(
            "selection error: --all-probes cannot be combined with --only or --sample",
            file=sys.stderr,
        )
        return 2
    try:
        if args.stateful_only:
            status, _observations = run_stateful(args)
            return status

        seeds = (
            [args.seed + offset for offset in range(len(PROBES))]
            if args.all_probes
            else [args.seed]
        )
        failed = False
        total_cases = 0
        total_observations = 0
        for rotation, seed in enumerate(seeds, start=1):
            rotation_cases = generate_cases(seed)
            errors = generation_errors(rotation_cases)
            if errors:
                raise RuntimeError(
                    f"probe rotation {rotation} generation failed: {'; '.join(errors)}"
                )
            selected = filter_cases(rotation_cases, args.only, args.sample, seed)
            if not selected:
                raise RuntimeError("no generated cases selected")
            rotation_args = argparse.Namespace(**vars(args))
            rotation_args.seed = seed
            if args.all_probes:
                print(
                    f"\nprobe rotation {rotation}/{len(seeds)} "
                    f"(seed={seed}, offset={seed % len(PROBES)})"
                )
            failed |= run_live(selected, rotation_args) != 0
            total_cases += len(selected)
            total_observations += sum(len(case.requests) for case in selected) * 2

        run_stateful_after = not args.skip_stateful and not (args.only or args.sample)
        if run_stateful_after:
            stateful_status, stateful_observations = run_stateful(args)
            failed |= stateful_status != 0
            total_observations += stateful_observations
        if args.all_probes:
            print(
                f"\nall {len(seeds)} probe rotations: {total_cases} generated cases, "
                f"{total_observations} attacker observations, "
                f"{'failure' if failed else 'PASS'}"
            )
        return 1 if failed else 0
    except (ValueError, re.error) as error:
        print(f"selection error: {error}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"information disclosure campaign: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
