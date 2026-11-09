#!/usr/bin/env python3
"""Generated Apache differential matrix for request identity transitions.

The fixed conformance suite is intentionally readable and curated.  This
program covers a different failure mode: the same policy decision can be
reached through many URL spellings and target-changing transforms, and one
early return or fallback branch can accidentally skip the final authorization
gate.  It generates isolated cases over four axes:

  * transform: direct, rewrite, alias, DirectoryIndex, MultiViews,
    CGI PATH_INFO, ErrorDocument, proxy, redirect and directory fallback;
  * URL spelling: canonical, percent-encoded unreserved byte, repeated slash,
    slash-boundary flip, empty/value query and a dot segment;
  * policy phase: Directory, Files, Location, access file, query-time If,
    method Limit and Proxy;
  * terminal sink: static, directory, CGI, proxy, redirect and cache.

Only semantically valid transform/sink pairs are generated.  For each pair a
Latin-square schedule crosses every policy phase with every URL spelling.  A
generation-only check is suitable for ordinary CI; the live mode starts Apache
and Vapache, sends the same ordered requests to both, and compares status,
selected response identity, redirects and cache disposition.  Cache cells
warm both implementations, mutate the selected file, then repeat the request.

Failures are written as small JSON artifacts containing the exact generated
configuration, fixture, request prefix and both observations.  Re-run one with
``--only '^CASE_ID$' --keep-tree``; each case already has its own directory and
minimal policy, so no corpus-wide reduction is required before debugging.

Usage:
    python3 tests/transform_differential.py --check
    python3 tests/transform_differential.py
    python3 tests/transform_differential.py --only 'multiview.*files'
    python3 tests/transform_differential.py --list
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import grp
import hashlib
import http.client
import json
import os
import pwd
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


ROOT = Path(__file__).resolve().parent.parent
LOCAL_SETUP = ROOT.parent / ".vapache-setup"
VAPACHED = Path(os.environ.get("VAPACHED", ROOT / "target" / "release" / "vapached"))
APACHE = os.environ.get("APACHE") or shutil.which("apache2") or str(LOCAL_SETUP / "bin/apache2")
MODDIR = Path(
    os.environ.get(
        "APACHE_MODDIR",
        "/usr/lib/apache2/modules"
        if Path("/usr/lib/apache2/modules").is_dir()
        else LOCAL_SETUP / "sysroot/usr/lib/apache2/modules",
    )
)
AP_PORT = int(os.environ.get("VAPACHE_MATRIX_AP_PORT", "18280"))
VP_PORT = int(os.environ.get("VAPACHE_MATRIX_VP_PORT", "18281"))
SERVICE_USER = "www-data" if os.geteuid() == 0 else pwd.getpwuid(os.geteuid()).pw_name
SERVICE_GROUP = "www-data" if os.getegid() == 0 else grp.getgrgid(os.getegid()).gr_name

MODULES = (
    "mpm_event_module",
    "mime_module",
    "dir_module",
    "alias_module",
    "negotiation_module",
    "cgi_module",
    "autoindex_module",
    "authz_core_module",
    "authz_host_module",
    "headers_module",
    "rewrite_module",
    "proxy_module",
    "proxy_http_module",
    "cache_module",
    "cache_disk_module",
)


@dataclass(frozen=True)
class Template:
    id: str
    transform: str
    sink: str
    kind: str
    tags: tuple[str, ...] = ()
    cache: bool = False


@dataclass(frozen=True)
class Policy:
    id: str
    tag: str


@dataclass(frozen=True)
class Spelling:
    id: str
    tag: str


@dataclass
class RequestStep:
    label: str
    method: str
    path: str
    compare_body_statuses: tuple[int, ...]
    mutation_after: tuple[str, bytes] | None = None


@dataclass
class Case:
    id: str
    transform: str
    spelling: str
    policy_phase: str
    sink: str
    tags: set[str]
    config: list[str]
    files: dict[str, bytes]
    executable_files: set[str]
    requests: list[RequestStep]
    public_path: str
    selected_name: str
    selected_area: str
    selected_rel_dir: str
    proxy_policy_url: str | None = None

    def manifest(self) -> dict:
        return {
            "id": self.id,
            "axes": {
                "transform": self.transform,
                "spelling": self.spelling,
                "policy_phase": self.policy_phase,
                "terminal_sink": self.sink,
            },
            "tags": sorted(self.tags),
            "public_path": self.public_path,
            "selected_name": self.selected_name,
            "config": self.config,
            "files": {
                path: base64.b64encode(data).decode("ascii")
                for path, data in sorted(self.files.items())
            },
            "executable_files": sorted(self.executable_files),
            "requests": [
                {
                    "label": step.label,
                    "method": step.method,
                    "path": step.path,
                    "compare_body_statuses": list(step.compare_body_statuses),
                    "mutation_after": (
                        None
                        if step.mutation_after is None
                        else {
                            "path": step.mutation_after[0],
                            "body": base64.b64encode(step.mutation_after[1]).decode("ascii"),
                        }
                    ),
                }
                for step in self.requests
            ],
        }


POLICIES = (
    Policy("directory", "filesystem-policy"),
    Policy("files", "selected-name-policy"),
    Policy("location", "public-url-policy"),
    Policy("htaccess", "access-file-policy"),
    Policy("query", "query-dependent-policy"),
    Policy("method", "early-return"),
    Policy("proxy", "backend-policy"),
)

SPELLINGS = (
    Spelling("canonical", "canonical-url"),
    Spelling("encoded_unreserved", "encoding"),
    Spelling("repeated_slash", "repeated-slash"),
    Spelling("slash_boundary", "trailing-slash"),
    Spelling("empty_query", "query-spelling"),
    Spelling("value_query", "query-spelling"),
    Spelling("dot_segment", "normalization"),
)

# A template is one valid transform/sink pair.  Repeated transforms are
# deliberate: they ensure that target selection is crossed with more than one
# terminal capability rather than treating the handler as an afterthought.
TEMPLATES = (
    Template("direct-static", "direct", "static", "direct_static"),
    Template("direct-cgi", "direct", "cgi", "direct_cgi"),
    Template("rewrite-static", "rewrite", "static", "rewrite_static"),
    Template("rewrite-cgi", "rewrite", "cgi", "rewrite_cgi"),
    Template("rewrite-proxy", "rewrite", "proxy", "rewrite_proxy"),
    Template("rewrite-redirect", "rewrite", "redirect", "rewrite_redirect", ("early-return",)),
    Template("alias-static", "alias", "static", "alias_static"),
    Template("alias-cgi", "alias", "cgi", "alias_cgi"),
    Template("directory-index-static", "directory_index", "static", "index_static", ("fallback",)),
    Template("directory-index-cgi", "directory_index", "cgi", "index_cgi", ("fallback",)),
    Template("multiview-static", "multiviews", "static", "multiview", ("fallback",)),
    Template("cgi-path-info", "cgi_path_info", "cgi", "cgi_path_info", ("fallback",)),
    Template("error-document-static", "error_document", "static", "error_static", ("fallback", "early-return")),
    Template("error-document-cgi", "error_document", "cgi", "error_cgi", ("fallback", "early-return")),
    Template("proxy-http", "proxy", "proxy", "proxy"),
    Template("redirect", "redirect", "redirect", "redirect", ("early-return",)),
    Template("directory-list", "directory", "directory", "directory", ("fallback",)),
    Template("cache-direct", "direct", "cache", "direct_static", ("cache-planning",), True),
    Template("cache-rewrite", "rewrite", "cache", "rewrite_static", ("cache-planning",), True),
    Template("cache-index", "directory_index", "cache", "index_static", ("cache-planning", "fallback"), True),
    Template("cache-multiview", "multiviews", "cache", "multiview", ("cache-planning", "fallback"), True),
)


def safe_id(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def marker(case_id: str, suffix: str = "ORIGINAL") -> bytes:
    return f"MATRIX:{case_id}:{suffix}\n".encode()


def cgi_script(case_id: str) -> bytes:
    return (
        "#!/bin/sh\n"
        "printf 'Content-Type: text/plain\\r\\n'\n"
        "printf 'X-Matrix-Sink: cgi\\r\\n'\n"
        "printf '\\r\\n'\n"
        # Vapache deliberately exposes a canonical query-free REQUEST_URI to
        # policy and CGI, while Apache exposes the raw request target.  That
        # documented hardening boundary is not a selected-representation
        # difference, so the matrix compares the remaining CGI identities.
        f"printf 'MATRIX:{case_id}:CGI|SCRIPT_NAME=%s|PATH_INFO=%s|QUERY_STRING=%s\\n' "
        '"${SCRIPT_NAME-}" "${PATH_INFO-}" "${QUERY_STRING-}"\n'
    ).encode()


def file_key(area: str, relative: str) -> str:
    return f"{area}/{relative.lstrip('/')}"


def add_file(case: Case, area: str, relative: str, data: bytes, executable: bool = False) -> None:
    key = file_key(area, relative)
    case.files[key] = data
    if executable:
        case.executable_files.add(key)


def template_case(template: Template, policy: Policy, spelling: Spelling, ordinal: int) -> Case:
    slug = safe_id(f"mx-{ordinal:03d}-{template.id}-{policy.id}-{spelling.id}")
    doc_dir = f"{slug}"
    alias_dir = f"{slug}"
    cache_prefix = "matrix-cache/" if template.cache else ""
    url_root = f"/{cache_prefix}{slug}"
    selected_area = "doc"
    selected_rel_dir = doc_dir
    selected_name = "entry.txt"
    public_path = f"{url_root}/entry.txt"
    config: list[str] = []
    files: dict[str, bytes] = {}
    executable: set[str] = set()
    proxy_policy_url = None
    body_statuses = (200,)

    case = Case(
        id=f"{template.id}--{policy.id}--{spelling.id}",
        transform=template.transform,
        spelling=spelling.id,
        policy_phase=policy.id,
        sink=template.sink,
        tags=set(template.tags) | {policy.tag, spelling.tag},
        config=config,
        files=files,
        executable_files=executable,
        requests=[],
        public_path=public_path,
        selected_name=selected_name,
        selected_area=selected_area,
        selected_rel_dir=selected_rel_dir,
        proxy_policy_url=proxy_policy_url,
    )

    kind = template.kind
    if kind == "direct_static":
        add_file(case, "doc", f"{doc_dir}/entry.txt", marker(case.id))
    elif kind == "direct_cgi":
        case.public_path = f"{url_root}/entry.cgi"
        case.selected_name = "entry.cgi"
        add_file(case, "doc", f"{doc_dir}/entry.cgi", cgi_script(case.id), True)
        config.extend(
            [
                f'<Directory "{{DOCROOT}}/{doc_dir}">',
                "    Options +ExecCGI",
                "    Require all granted",
                "</Directory>",
            ]
        )
    elif kind in {"rewrite_static", "rewrite_cgi"}:
        target = "selected.cgi" if kind == "rewrite_cgi" else "selected.txt"
        case.public_path = f"{url_root}/entry"
        case.selected_name = target
        add_file(
            case,
            "doc",
            f"{doc_dir}/{target}",
            cgi_script(case.id) if kind == "rewrite_cgi" else marker(case.id),
            kind == "rewrite_cgi",
        )
        config.extend(
            [
                "RewriteEngine On",
                f'RewriteRule "^{case.public_path}$" "{url_root}/{target}" [END]',
            ]
        )
        if kind == "rewrite_cgi":
            config.extend(
                [
                    f'<Directory "{{DOCROOT}}/{doc_dir}">',
                    "    Options +ExecCGI",
                    "    Require all granted",
                    "</Directory>",
                ]
            )
    elif kind == "rewrite_proxy":
        case.public_path = f"{url_root}/entry"
        case.selected_name = "proxy-target"
        proxy_policy_url = f"http://127.0.0.1:{{BACKEND}}/up/{slug}/"
        case.proxy_policy_url = proxy_policy_url
        config.extend(
            [
                "RewriteEngine On",
                f'RewriteRule "^{case.public_path}$" "{proxy_policy_url}entry" [P,END]',
                f'<Proxy "{proxy_policy_url}">',
                "    Require all granted",
                "</Proxy>",
            ]
        )
    elif kind == "rewrite_redirect":
        case.public_path = f"{url_root}/entry"
        case.selected_name = "target.txt"
        add_file(case, "doc", f"{doc_dir}/target.txt", marker(case.id))
        config.extend(
            [
                "RewriteEngine On",
                f'RewriteRule "^{case.public_path}$" "{url_root}/target.txt" [R=302,END]',
            ]
        )
        body_statuses = ()
    elif kind in {"alias_static", "alias_cgi"}:
        selected_area = "alias"
        selected_rel_dir = alias_dir
        case.selected_area = selected_area
        case.selected_rel_dir = selected_rel_dir
        prefix = f"/alias-{slug}"
        name = "entry.cgi" if kind == "alias_cgi" else "entry.txt"
        case.public_path = f"{prefix}/{name}"
        case.selected_name = name
        directive = "ScriptAlias" if kind == "alias_cgi" else "Alias"
        config.extend(
            [
                f'{directive} "{prefix}/" "{{ALIASROOT}}/{alias_dir}/"',
                f'<Directory "{{ALIASROOT}}/{alias_dir}">',
                "    Options +ExecCGI" if kind == "alias_cgi" else "    Options FollowSymLinks",
                "    Require all granted",
                "</Directory>",
            ]
        )
        add_file(
            case,
            "alias",
            f"{alias_dir}/{name}",
            cgi_script(case.id) if kind == "alias_cgi" else marker(case.id),
            kind == "alias_cgi",
        )
    elif kind in {"index_static", "index_cgi"}:
        case.public_path = f"{url_root}/dir/"
        case.selected_rel_dir = f"{doc_dir}/dir"
        name = "index.cgi" if kind == "index_cgi" else "index.html"
        case.selected_name = name
        add_file(
            case,
            "doc",
            f"{doc_dir}/dir/{name}",
            cgi_script(case.id) if kind == "index_cgi" else marker(case.id),
            kind == "index_cgi",
        )
        config.extend(
            [
                f'<Directory "{{DOCROOT}}/{doc_dir}/dir">',
                f"    DirectoryIndex {name}",
                "    Options +ExecCGI" if kind == "index_cgi" else "    Options FollowSymLinks",
                "    Require all granted",
                "</Directory>",
            ]
        )
    elif kind == "multiview":
        case.public_path = f"{url_root}/entry"
        case.selected_name = "entry.txt"
        add_file(case, "doc", f"{doc_dir}/entry.txt", marker(case.id))
        config.extend(
            [
                f'<Directory "{{DOCROOT}}/{doc_dir}">',
                "    Options +MultiViews",
                "    Require all granted",
                "</Directory>",
            ]
        )
    elif kind == "cgi_path_info":
        case.public_path = f"{url_root}/entry.cgi/info"
        case.selected_name = "entry.cgi"
        add_file(case, "doc", f"{doc_dir}/entry.cgi", cgi_script(case.id), True)
        config.extend(
            [
                f'<Directory "{{DOCROOT}}/{doc_dir}">',
                "    Options +ExecCGI",
                "    Require all granted",
                "</Directory>",
            ]
        )
    elif kind in {"error_static", "error_cgi"}:
        case.public_path = f"{url_root}/missing"
        name = "error.cgi" if kind == "error_cgi" else "error.html"
        case.selected_name = name
        add_file(
            case,
            "doc",
            f"{doc_dir}/{name}",
            cgi_script(case.id) if kind == "error_cgi" else marker(case.id),
            kind == "error_cgi",
        )
        config.extend(
            [
                f'<Directory "{{DOCROOT}}/{doc_dir}">',
                f"    ErrorDocument 404 {url_root}/{name}",
                "    Options +ExecCGI" if kind == "error_cgi" else "    Options FollowSymLinks",
                "    Require all granted",
                "</Directory>",
            ]
        )
        body_statuses = (404,)
    elif kind == "proxy":
        prefix = f"/proxy-{slug}"
        case.public_path = f"{prefix}/entry"
        case.selected_name = "proxy-target"
        proxy_policy_url = f"http://127.0.0.1:{{BACKEND}}/up/{slug}/"
        case.proxy_policy_url = proxy_policy_url
        config.extend(
            [
                f'ProxyPass "{prefix}/" "{proxy_policy_url}"',
                f'<Proxy "{proxy_policy_url}">',
                "    Require all granted",
                "</Proxy>",
            ]
        )
    elif kind == "redirect":
        prefix = f"/redirect-{slug}"
        case.public_path = f"{prefix}/entry"
        case.selected_name = "target.txt"
        add_file(case, "doc", f"{doc_dir}/target.txt", marker(case.id))
        config.append(f'Redirect 302 "{case.public_path}" "{url_root}/target.txt"')
        body_statuses = ()
    elif kind == "directory":
        case.public_path = f"{url_root}/list/"
        case.selected_rel_dir = f"{doc_dir}/list"
        case.selected_name = "item.txt"
        add_file(case, "doc", f"{doc_dir}/list/item.txt", marker(case.id))
        config.extend(
            [
                f'<Directory "{{DOCROOT}}/{doc_dir}/list">',
                "    Options +Indexes",
                "    Require all granted",
                "</Directory>",
            ]
        )
        body_statuses = ()
    else:  # pragma: no cover - generation check makes this unreachable
        raise AssertionError(f"unknown template kind {kind}")

    if template.cache:
        config.extend(
            [
                f'<Location "{url_root}">',
                '    Header set Cache-Control "max-age=3600"',
                "</Location>",
            ]
        )

    apply_policy(case, policy)
    spelled = apply_spelling(case.public_path, spelling.id)
    case.requests = request_steps(case, policy, spelled, body_statuses, template.cache)
    return case


def selected_dir(case: Case) -> str:
    root = "{DOCROOT}" if case.selected_area == "doc" else "{ALIASROOT}"
    return f"{root}/{case.selected_rel_dir}"


def apply_policy(case: Case, policy: Policy) -> None:
    directory = selected_dir(case)
    if policy.id == "directory":
        case.config.extend(
            [
                f'<Directory "{directory}">',
                "    Require all denied",
                "</Directory>",
            ]
        )
    elif policy.id == "files":
        case.config.extend(
            [
                f'<Directory "{directory}">',
                f'    <Files "{case.selected_name}">',
                "        Require all denied",
                "    </Files>",
                "</Directory>",
            ]
        )
    elif policy.id == "location":
        case.config.extend(
            [
                f'<Location "{case.public_path}">',
                "    Require all denied",
                "</Location>",
            ]
        )
    elif policy.id == "htaccess":
        key = file_key(case.selected_area, f"{case.selected_rel_dir}/.htaccess")
        case.files[key] = (
            f'<Files "{case.selected_name}">\n'
            "    Require all denied\n"
            "</Files>\n"
        ).encode()
        case.config.extend(
            [
                f'<Directory "{directory}">',
                "    AllowOverride AuthConfig",
                "</Directory>",
            ]
        )
    elif policy.id == "query":
        case.config.extend(
            [
                f'<Location "{case.public_path}">',
                '    <If "%{QUERY_STRING} =~ /(^|&)deny=1(&|$)/">',
                "        Require all denied",
                "    </If>",
                "</Location>",
            ]
        )
    elif policy.id == "method":
        case.config.extend(
            [
                f'<Location "{case.public_path}">',
                "    Require all granted",
                "    <Limit HEAD>",
                "        Require all denied",
                "    </Limit>",
                "</Location>",
            ]
        )
    elif policy.id == "proxy":
        proxy_url = case.proxy_policy_url or f"http://127.0.0.1:{{BACKEND}}/unused/{case.id}/"
        case.config.extend(
            [
                f'<Proxy "{proxy_url}">',
                "    Require all denied",
                "</Proxy>",
            ]
        )
    else:  # pragma: no cover
        raise AssertionError(policy.id)


def split_query(path: str) -> tuple[str, str | None]:
    if "?" not in path:
        return path, None
    return tuple(path.split("?", 1))  # type: ignore[return-value]


def add_query(path: str, query: str) -> str:
    base, current = split_query(path)
    if current is None or current == "":
        return f"{base}?{query}"
    return f"{base}?{current}&{query}"


def apply_spelling(path: str, spelling: str) -> str:
    base, query = split_query(path)
    segments = base.split("/")
    nonempty = [i for i, segment in enumerate(segments) if segment]
    if not nonempty:
        return path
    target = nonempty[-2] if base.endswith("/") and len(nonempty) > 1 else nonempty[-1]
    if spelling == "encoded_unreserved":
        value = segments[target]
        segments[target] = f"%{ord(value[0]):02X}{value[1:]}"
        base = "/".join(segments)
    elif spelling == "repeated_slash":
        insert_at = target
        segments.insert(insert_at, "")
        base = "/".join(segments)
    elif spelling == "slash_boundary":
        base = base.rstrip("/") if base.endswith("/") else f"{base}/"
    elif spelling == "empty_query":
        query = ""
    elif spelling == "value_query":
        query = "flavor=vanilla"
    elif spelling == "dot_segment":
        segments.insert(target, ".")
        base = "/".join(segments)
    elif spelling != "canonical":  # pragma: no cover
        raise AssertionError(spelling)
    return base if query is None else f"{base}?{query}"


def request_steps(
    case: Case,
    policy: Policy,
    spelled: str,
    body_statuses: tuple[int, ...],
    cache: bool,
) -> list[RequestStep]:
    if policy.id == "query":
        allowed = spelled
        if "?" not in allowed:
            allowed = f"{allowed}?allow=1"
        denied = add_query(spelled, "deny=1")
        steps = [
            RequestStep("query-allow", "GET", allowed, body_statuses),
            RequestStep("query-deny", "GET", denied, ()),
        ]
    elif policy.id == "method":
        steps = [
            RequestStep("method-get", "GET", spelled, body_statuses),
            RequestStep("method-head", "HEAD", spelled, ()),
        ]
    else:
        steps = [RequestStep("request", "GET", spelled, body_statuses)]

    if cache:
        mutation_path = file_key(case.selected_area, f"{case.selected_rel_dir}/{case.selected_name}")
        steps[0].mutation_after = (mutation_path, marker(case.id, "MUTATED"))
        steps.append(RequestStep("warm-repeat", "GET", spelled, body_statuses))
    return steps


def generate_matrix(seed: int = 7331) -> list[Case]:
    cases: list[Case] = []
    # Rotating the spelling origin by the seed gives deterministic alternative
    # campaigns without changing the exhaustive per-template coverage.
    offset = seed % len(SPELLINGS)
    ordinal = 0
    for template_index, template in enumerate(TEMPLATES):
        for policy_index, policy in enumerate(POLICIES):
            spelling = SPELLINGS[(template_index + policy_index + offset) % len(SPELLINGS)]
            cases.append(template_case(template, policy, spelling, ordinal))
            ordinal += 1
    return cases


def generation_errors(cases: list[Case]) -> list[str]:
    errors: list[str] = []
    ids = [case.id for case in cases]
    if len(ids) != len(set(ids)):
        errors.append("case IDs are not unique")
    expected = len(TEMPLATES) * len(POLICIES)
    if len(cases) != expected:
        errors.append(f"generated {len(cases)} cases, expected {expected}")

    for template in TEMPLATES:
        rows = [case for case in cases if case.id.startswith(f"{template.id}--")]
        phases = {case.policy_phase for case in rows}
        spellings = {case.spelling for case in rows}
        if phases != {policy.id for policy in POLICIES}:
            errors.append(f"{template.id}: incomplete policy coverage {sorted(phases)}")
        if spellings != {spelling.id for spelling in SPELLINGS}:
            errors.append(f"{template.id}: incomplete spelling coverage {sorted(spellings)}")

    required_tags = {
        "early-return",
        "fallback",
        "cache-planning",
        "trailing-slash",
        "encoding",
        "query-dependent-policy",
    }
    tags = set().union(*(case.tags for case in cases))
    missing = required_tags - tags
    if missing:
        errors.append(f"missing risk tags: {sorted(missing)}")

    required_sinks = {"static", "directory", "cgi", "proxy", "redirect", "cache"}
    sinks = {case.sink for case in cases}
    if sinks != required_sinks:
        errors.append(f"terminal sinks are {sorted(sinks)}, expected {sorted(required_sinks)}")
    return errors


class BackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self) -> None:
        body = f"PROXY:{self.command}:{self.path}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Matrix-Sink", "proxy")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _reply
    do_HEAD = _reply

    def log_message(self, _format: str, *_args) -> None:
        pass


@dataclass
class Runtime:
    base: Path
    docroot: Path
    aliasroot: Path
    backend: ThreadingHTTPServer
    processes: list[tuple[subprocess.Popen, object]] = field(default_factory=list)

    @property
    def backend_port(self) -> int:
        return int(self.backend.server_address[1])

    def resolve_file(self, key: str) -> Path:
        area, relative = key.split("/", 1)
        root = self.docroot if area == "doc" else self.aliasroot
        return root / relative

    def render(self, value: str) -> str:
        return (
            value.replace("{DOCROOT}", str(self.docroot))
            .replace("{ALIASROOT}", str(self.aliasroot))
            .replace("{BACKEND}", str(self.backend_port))
        )


def prepare_runtime(cases: list[Case]) -> Runtime:
    base = Path(tempfile.mkdtemp(prefix="vapache-transform-matrix-"))
    docroot = base / "www"
    aliasroot = base / "alias"
    for path in (base, docroot, aliasroot, base / "logs", base / "apache", base / "cache-apache", base / "cache-vapache"):
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o755)
    # Vapache refuses an administrative path whose parent the service
    # account can mutate; both servers open their logs before dropping
    # privileges, so 0755 is sufficient and keeps the startup guard intact.
    os.chmod(base / "cache-apache", 0o777)
    os.chmod(base / "cache-vapache", 0o777)

    backend = ThreadingHTTPServer(("127.0.0.1", 0), BackendHandler)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    runtime = Runtime(base, docroot, aliasroot, backend)
    for case in cases:
        # Materialize the directory named by the policy axis even for
        # URL-space proxy and redirect cases that have no local files. Apache
        # skips a <Directory> section whose path does not exist, which would
        # otherwise turn a rewrite miss into a fixture-dependent 404/403
        # difference instead of testing the configured policy phase.
        selected_root = docroot if case.selected_area == "doc" else aliasroot
        selected_dir = selected_root / case.selected_rel_dir
        selected_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(selected_dir, 0o755)
        for key, data in case.files.items():
            path = runtime.resolve_file(key)
            path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(path.parent, 0o755)
            path.write_bytes(data)
            os.chmod(path, 0o755 if key in case.executable_files else 0o644)
    return runtime


def module_lines() -> list[str]:
    return [
        f"LoadModule {module} {MODDIR}/mod_{module.removesuffix('_module')}.so"
        for module in MODULES
    ]


def server_config(runtime: Runtime, cases: list[Case], port: int, apache: bool) -> str:
    lines = module_lines()
    if not apache:
        lines.extend(
            [
                "VapacheCapability AccessFiles On",
                "VapacheCapability AutoIndex On",
                "VapacheCapability Cgi On",
            ]
        )
    cache_root = runtime.base / ("cache-apache" if apache else "cache-vapache")
    lines.extend(
        [
            f'ServerRoot "{runtime.base}"',
            f"Listen {port}",
            f"User {SERVICE_USER}",
            f"Group {SERVICE_GROUP}",
            f'PidFile "{runtime.base}/logs/httpd-{port}.pid"',
            f'ErrorLog "{runtime.base}/logs/error-{port}.log"',
            "LogLevel warn",
            "ServerName localhost",
            "Timeout 10",
            f'DocumentRoot "{runtime.docroot}"',
            "TypesConfig /etc/mime.types",
            "AddType text/plain .txt",
            "AddHandler cgi-script .cgi",
            f'CacheRoot "{cache_root}"',
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
        ]
    )
    for case in cases:
        lines.append(f"# matrix case: {case.id}")
        lines.extend(runtime.render(line) for line in case.config)
    return "\n".join(lines) + "\n"


def run_checked(cmd: list[str], label: str) -> None:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(
            f"{label} failed ({result.returncode}):\n{result.stdout}{result.stderr}"
        )


def start_process(runtime: Runtime, cmd: list[str], log: Path) -> None:
    stream = open(log, "ab")
    process = subprocess.Popen(
        cmd,
        stdout=stream,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    runtime.processes.append((process, stream))


def wait_port(port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def stop_runtime(runtime: Runtime, keep_tree: bool) -> None:
    for process, stream in runtime.processes:
        if process.poll() is None:
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
        stream.close()
    runtime.backend.shutdown()
    runtime.backend.server_close()
    if keep_tree:
        print(f"tree: {runtime.base}")
    else:
        shutil.rmtree(runtime.base, ignore_errors=True)


def request(port: int, step: RequestStep) -> dict:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        connection.request(step.method, step.path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read()
        headers: dict[str, list[str]] = {}
        for name, value in response.getheaders():
            headers.setdefault(name.lower(), []).append(value)
        return {"status": response.status, "headers": headers, "body": body}
    finally:
        connection.close()


def normalized_location(values: list[str] | None, ports: tuple[int, int]) -> list[str] | None:
    if values is None:
        return None
    result = []
    for value in values:
        for port in ports:
            value = value.replace(f":{port}/", ":{PORT}/")
        result.append(value)
    return result


def cache_disposition(values: list[str] | None) -> str | None:
    if not values:
        return None
    value = values[0].strip().upper()
    if value.startswith("HIT"):
        return "HIT"
    if value.startswith("MISS"):
        return "MISS"
    return value


def printable_observation(observation: dict) -> dict:
    body: bytes = observation["body"]
    return {
        "status": observation["status"],
        "headers": observation["headers"],
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_base64": base64.b64encode(body).decode("ascii"),
    }


def compare_step(case: Case, step: RequestStep, apache: dict, vapache: dict) -> list[str]:
    problems: list[str] = []
    if apache["status"] != vapache["status"]:
        # Apache exposes discovery of a denied implicit target as 403. Vapache
        # deliberately collapses it into the same 404 as failed discovery.
        # Admit only that one-way hardening difference, and only when neither
        # response contains the selected fixture marker.
        expected = f"MATRIX:{case.id}:".encode()
        concealed_implicit_deny = (
            case.transform in {"multiviews", "cgi_path_info"}
            and case.policy_phase in {"files", "htaccess"}
            and apache["status"] == 403
            and vapache["status"] == 404
            and expected not in apache["body"]
            and expected not in vapache["body"]
        )
        if concealed_implicit_deny:
            return problems
        problems.append(
            f"{step.label}: status apache={apache['status']} vapache={vapache['status']}"
        )
        return problems

    status = apache["status"]
    if step.method != "HEAD" and status in step.compare_body_statuses:
        expected = f"MATRIX:{case.id}:".encode()
        apache_selected = expected in apache["body"]
        vapache_selected = expected in vapache["body"]
        # A denied ErrorDocument falls back to each server's generated HTML.
        # Compare the selected/not-selected decision, not those unrelated
        # presentation templates.  Successful terminal responses and proxy
        # bodies remain byte-for-byte comparisons.
        if apache_selected != vapache_selected:
            problems.append(
                f"{step.label}: selected representation differs "
                f"apache={apache_selected} vapache={vapache_selected}"
            )
        elif (apache_selected or case.transform != "error_document") and apache["body"] != vapache["body"]:
            problems.append(
                f"{step.label}: body differs "
                f"apache={apache['body'][:160]!r} vapache={vapache['body'][:160]!r}"
            )

    if 300 <= status < 400:
        ap_location = normalized_location(apache["headers"].get("location"), (AP_PORT, VP_PORT))
        vp_location = normalized_location(vapache["headers"].get("location"), (AP_PORT, VP_PORT))
        if ap_location != vp_location:
            problems.append(
                f"{step.label}: Location apache={ap_location!r} vapache={vp_location!r}"
            )

    if case.sink == "cache" and status == 200:
        ap_cache = cache_disposition(apache["headers"].get("x-cache"))
        vp_cache = cache_disposition(vapache["headers"].get("x-cache"))
        if ap_cache != vp_cache:
            problems.append(
                f"{step.label}: cache disposition apache={ap_cache!r} vapache={vp_cache!r}"
            )

    return problems


def write_failure_artifact(
    artifact_dir: Path,
    case: Case,
    seed: int,
    problems: list[str],
    observations: list[dict],
) -> Path:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / f"{safe_id(case.id)}.json"
    payload = {
        "schema": 1,
        "seed": seed,
        "case": case.manifest(),
        "problems": problems,
        "observations": observations,
        "replay": f"python3 tests/transform_differential.py --seed {seed} --only '^{re.escape(case.id)}$' --keep-tree -v",
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def run_case(runtime: Runtime, case: Case, seed: int, artifact_dir: Path, verbose: bool) -> list[str]:
    problems: list[str] = []
    observations: list[dict] = []
    for step in case.requests:
        try:
            apache = request(AP_PORT, step)
            vapache = request(VP_PORT, step)
        except Exception as error:
            problems.append(f"{step.label}: request failed: {error}")
            break
        step_problems = compare_step(case, step, apache, vapache)
        problems.extend(step_problems)
        observations.append(
            {
                "step": dataclasses.asdict(step),
                "apache": printable_observation(apache),
                "vapache": printable_observation(vapache),
            }
        )
        if verbose:
            print(
                f"    {step.method} {step.path}: "
                f"apache={apache['status']} vapache={vapache['status']}"
            )
        if step.mutation_after is not None:
            key, body = step.mutation_after
            path = runtime.resolve_file(key)
            path.write_bytes(body)
            os.chmod(path, 0o755 if key in case.executable_files else 0o644)
    if problems:
        artifact = write_failure_artifact(artifact_dir, case, seed, problems, observations)
        problems.append(f"artifact: {artifact}")
    return problems


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
    if not Path(APACHE).is_file():
        raise RuntimeError(f"missing Apache httpd at {APACHE}")
    missing_modules = [
        str(MODDIR / f"mod_{module.removesuffix('_module')}.so")
        for module in MODULES
        if not (MODDIR / f"mod_{module.removesuffix('_module')}.so").is_file()
    ]
    if missing_modules:
        raise RuntimeError(f"missing Apache modules: {', '.join(missing_modules)}")

    runtime = prepare_runtime(cases)
    try:
        apache_config = runtime.base / "apache/httpd.conf"
        vapache_config = runtime.base / "vapache-httpd.conf"
        apache_config.write_text(server_config(runtime, cases, AP_PORT, True))
        vapache_config.write_text(server_config(runtime, cases, VP_PORT, False))
        run_checked([APACHE, "-t", "-f", str(apache_config)], "Apache configtest")
        run_checked([str(VAPACHED), "-t", "-f", str(vapache_config)], "Vapache configtest")
        start_process(
            runtime,
            [APACHE, "-f", str(apache_config), "-DFOREGROUND"],
            runtime.base / "logs/apache.out",
        )
        start_process(
            runtime,
            [str(VAPACHED), "-f", str(vapache_config), "-DFOREGROUND"],
            runtime.base / "logs/vapache.out",
        )
        if not wait_port(AP_PORT) or not wait_port(VP_PORT):
            logs = []
            for name in ("apache", "vapache"):
                path = runtime.base / f"logs/{name}.out"
                if path.exists():
                    logs.append(f"== {name} ==\n{path.read_text(errors='replace')[-8000:]}")
            raise RuntimeError("server failed to start\n" + "\n".join(logs))

        failures = 0
        burst = 0
        artifact_dir = Path(args.artifact_dir)
        for case in cases:
            count = len(case.requests)
            if burst and burst + count > 12:
                time.sleep(1.05)
                burst = 0
            problems = run_case(runtime, case, args.seed, artifact_dir, args.verbose)
            burst += count
            if problems:
                failures += 1
                print(f"FAIL {case.id}")
                for problem in problems:
                    print(f"     {problem}")
            else:
                print(f"ok   {case.id}")
        print(
            f"\n{len(cases)} generated cases, {sum(len(case.requests) for case in cases)} "
            f"request steps, {failures} divergence(s)"
        )
        return 1 if failures else 0
    finally:
        stop_runtime(runtime, args.keep_tree)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate generation and exit")
    parser.add_argument("--list", action="store_true", help="print the generated manifest and exit")
    parser.add_argument("--only", default="", help="run case IDs matching this regular expression")
    parser.add_argument("--sample", type=int, default=0, help="run a deterministic sample")
    parser.add_argument("--seed", type=int, default=7331)
    parser.add_argument("--artifact-dir", default="artifacts/transform-differential")
    parser.add_argument("--keep-tree", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    cases = generate_matrix(args.seed)
    errors = generation_errors(cases)
    if errors:
        for error in errors:
            print(f"generation error: {error}", file=sys.stderr)
        return 2
    if args.list:
        print(json.dumps([case.manifest() for case in cases], indent=2, sort_keys=True))
        return 0
    if args.check:
        pairs = {(case.transform, case.sink) for case in cases}
        print(
            f"transform differential generation: {len(cases)} cases, "
            f"{len(pairs)} transform/sink pairs, {len(POLICIES)} policy phases, "
            f"{len(SPELLINGS)} URL spellings, {len({case.sink for case in cases})} sinks"
        )
        return 0
    try:
        selected = filter_cases(cases, args.only, args.sample, args.seed)
    except (ValueError, re.error) as error:
        print(f"selection error: {error}", file=sys.stderr)
        return 2
    if not selected:
        print("no generated cases selected", file=sys.stderr)
        return 2
    try:
        return run_live(selected, args)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"transform differential: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
