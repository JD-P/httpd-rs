#!/usr/bin/env python3
"""Generated differential checks for security-relevant configuration semantics.

This is intentionally separate from `conformance.py`: conformance is a curated
set of fixed cases, while this harness generates a matrix of small, isolated
configurations that exercise the merge rules which are easy to get wrong:

  * AllowOverride categories and .htaccess gating
  * <Limit> / <LimitExcept> method scoping, including nesting
  * RequireAll / RequireAny / RequireNone and AuthMerging
  * Satisfy + legacy Order/Allow/Deny
  * <If>/<ElseIf>/<Else> branch interaction
  * Directory/Location/Files precedence
  * Options +/- inheritance

Both Apache httpd and vapached are started with the same configuration; every
request below is sent to both and the observable status/headers are compared.

Usage:
    python3 tests/config_semantics.py
    python3 tests/config_semantics.py -v
    python3 tests/config_semantics.py --stateful 128 --stateful-seed 1818
    KEEP_TREE=1 python3 tests/config_semantics.py
"""

import argparse
import base64
import random
import re
import hashlib
import http.client
import os
import grp
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VAPACHED = Path(os.environ.get("VAPACHED", ROOT / "target" / "release" / "vapached"))
APACHE = shutil.which("apache2") or "/usr/sbin/apache2"
MODDIR = Path(
    os.environ.get(
        "APACHE_MODDIR",
        "/usr/lib/apache2/modules"
        if Path("/usr/lib/apache2/modules").is_dir()
        else "/workspace/.vapache-setup/sysroot/usr/lib/apache2/modules",
    )
)
BASE = Path(tempfile.mkdtemp(prefix="vapache-config-semantics-"))
DOCROOT = BASE / "www"
AP_PORT = int(os.environ.get("VAPACHE_SEM_AP_PORT", "18180"))
VP_PORT = int(os.environ.get("VAPACHE_SEM_VP_PORT", "18181"))
PROCS = []
SERVICE_USER = "www-data" if os.geteuid() == 0 else pwd.getpwuid(os.geteuid()).pw_name
SERVICE_GROUP = "www-data" if os.getegid() == 0 else grp.getgrgid(os.getegid()).gr_name

APACHE_MODULES = [
    "mpm_event_module",
    "mime_module",
    "dir_module",
    "alias_module",
    "autoindex_module",
    "authz_core_module",
    "authz_host_module",
    "access_compat_module",
    "allowmethods_module",
    "headers_module",
    "setenvif_module",
    "env_module",
    "auth_basic_module",
    "authn_core_module",
    "authn_file_module",
    "authz_user_module",
    "authz_groupfile_module",
    "rewrite_module",
    "remoteip_module",
]


def write(path: Path, data: str | bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)


def make_fixture():
    os.chmod(BASE, 0o755)
    DOCROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(DOCROOT, 0o755)
    write(DOCROOT / "hello.txt", "hello\n")
    write(DOCROOT / "secret.txt", "secret\n")
    write(DOCROOT / "index.html", "root index\n")
    write(DOCROOT / "loc_file_grant", "not a directory\n")
    (BASE / "logs").mkdir(exist_ok=True)
    # A privileged launch opens logs before dropping to www-data and must keep
    # the administrative parent non-writable by that service identity.  An
    # unprivileged developer run still needs a writable fixture directory.
    os.chmod(BASE / "logs", 0o755 if os.geteuid() == 0 else 0o777)
    (BASE / "apache").mkdir(exist_ok=True)
    (BASE / "apache" / "logs").mkdir(exist_ok=True)
    # The <IfFile> flag file must be visible from both resolution roots:
    # Apache resolves .htaccess-relative <IfFile> arguments against ServerRoot,
    # vapached confines them against DocumentRoot (F45/I42).  A file existing
    # under both trees lets the differential suite exercise the TRUE branch.
    write(BASE / "ifflag.txt", "flag\n")
    write(DOCROOT / "ifflag.txt", "flag\n")
    write(BASE / ".htpasswd", htpasswd_line("alice", "alicepw") + "\n")
    write(BASE / ".htgroup", "staff: alice\n")
    os.chmod(BASE / ".htpasswd", 0o644)
    os.chmod(BASE / ".htgroup", 0o644)
    # Directory-listing cases need a directory with no index.
    for p in [DOCROOT, *DOCROOT.rglob("*")]:
        if p.is_dir():
            os.chmod(p, 0o755)


def htpasswd_line(user: str, password: str) -> str:
    digest = base64.b64encode(hashlib.sha1(password.encode()).digest()).decode()
    return f"{user}:{{SHA}}{digest}"


def case_file(case: dict, rel: str, content: str | bytes):
    write(DOCROOT / case["dir"] / rel, content)


def case_dir(case: dict) -> Path:
    return DOCROOT / case["dir"]


def make_case(case: dict):
    case_dir(case).mkdir(parents=True, exist_ok=True)
    os.chmod(case_dir(case), 0o755)
    write(case_dir(case) / "file.txt", f"{case['name']}\n")
    write(case_dir(case) / "secret.txt", f"{case['name']} secret\n")
    for rel, content in case.get("files", {}).items():
        case_file(case, rel, content)
    for rel, target in case.get("symlinks", {}).items():
        link = case_dir(case) / rel
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)
    for p in case_dir(case).rglob("*"):
        if p.is_file() and not p.is_symlink():
            os.chmod(p, 0o644)
    for rel in case.get("exec_files", []):
        os.chmod(case_dir(case) / rel, 0o755)
    for p in case_dir(case).rglob("*"):
        if p.is_dir():
            os.chmod(p, 0o755)


def base_config(port: int, apache: bool) -> str:
    lines = []
    if apache:
        for mod in APACHE_MODULES:
            lines.append(f"LoadModule {mod} {MODDIR}/mod_{mod.replace('_module','')}.so")
    else:
        # vapached only records module names for <IfModule>; paths are unused.
        for mod in APACHE_MODULES:
            lines.append(f"LoadModule {mod} {MODDIR}/mod_{mod.replace('_module','')}.so")
        lines += [
            "VapacheCapability AbsoluteRequestTarget On",
            "VapacheCapability AccessFiles On",
            "VapacheCapability AutoIndex On",
            "VapacheCapability Cgi On",
            "VapacheCapability FastCgi On",
            "VapacheCapability LegacyAuthz On",
            "VapacheCapability RequestTrailers On",
            "VapacheCapability RewriteProgram On",
            "VapacheCapability ServerStatus On",
            "VapacheCapability Trace On",
            "VapacheCapability UnstableFastCgiPaths On",
            "VapacheCapability MutableAuthFiles On",
        ]
    lines += [
        f'ServerRoot "{BASE}"',
        f"Listen {port}",
        f"User {SERVICE_USER}",
        f"Group {SERVICE_GROUP}",
        f"PidFile {BASE}/logs/httpd-{port}.pid",
        f"ErrorLog {BASE}/logs/error-{port}.log",
        "LogLevel warn",
        "ServerName localhost",
        f'DocumentRoot "{DOCROOT}"',
        "TypesConfig /etc/mime.types",
        "DirectoryIndex index.html",
        "<Directory />",
        "    AllowOverride None",
        "    Require all denied",
        "</Directory>",
        f'<Directory "{DOCROOT}">',
        "    Options FollowSymLinks",
        "    AllowOverride None",
        "    Require all granted",
        "</Directory>",
        "RemoteIPHeader X-Forwarded-For",
        "RemoteIPTrustedProxy 127.0.0.1",
    ]
    for case in CASES:
        lines.append(f"# case: {case['name']}")
        lines.extend(case.get("config", []))
    return "\n".join(lines) + "\n"


def start_server(cmd, log: Path):
    f = open(log, "ab")
    p = subprocess.Popen(
        cmd,
        stdout=f,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    PROCS.append((p, f))
    return p


def wait_port(port: int, timeout: float = 10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def stop_servers():
    for p, f in PROCS:
        if p.poll() is None:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        f.close()


def request(port: int, method: str, path: str, headers=None, body=b""):
    hdrs = {"Connection": "close"}
    if headers:
        hdrs.update(headers)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=hdrs)
        r = conn.getresponse()
        data = r.read()
        h = {}
        for k, v in r.getheaders():
            h.setdefault(k.lower(), []).append(v)
        return r.status, h, data
    finally:
        conn.close()


# Each case gets its own directory, so cases cannot influence each other.
# `config` is emitted verbatim; `{dir}` is expanded to the case directory.
CASES = [
    {
        "name": "alias-overlap-parent-htaccess",
        "dir": "alias_overlap",
        "files": {
            ".htaccess": "Require all denied\n",
            "assets/wallet.dat": "WALLET-ALIAS-OVERLAP\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "    Require all granted",
            "</Directory>",
            f'Alias "/sem-alias-assets" "{{dir}}/assets"',
            f'Alias "/sem-alias-site" "{{dir}}"',
        ],
        "requests": [
            ("GET", "/sem-alias-site/assets/wallet.dat", None, {}),
            ("GET", "/sem-alias-assets/wallet.dat", None, {}),
        ],
    },
    {
        "name": "allowoverride-none-denies-htaccess",
        "dir": "ao_none",
        "files": {".htaccess": "Require all denied\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride None",
            "</Directory>",
        ],
        "requests": [("GET", "/ao_none/file.txt", None, {})],
    },
    {
        "name": "allowoverride-authconfig-require",
        "dir": "ao_auth",
        "files": {".htaccess": "Require all denied\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride AuthConfig",
            "</Directory>",
        ],
        "requests": [("GET", "/ao_auth/file.txt", None, {})],
    },
    {
        "name": "allowoverride-limit-only-limit-require",
        "dir": "ao_limit",
        "files": {
            ".htaccess": "<Limit POST>\n    Require all denied\n</Limit>\n"
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride Limit",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ao_limit/file.txt", None, {}),
            ("POST", "/ao_limit/file.txt", None, {}),
        ],
    },
    {
        "name": "allowoverride-authconfig-limit-require",
        "dir": "ao_auth_limit",
        "files": {
            ".htaccess": "<Limit POST>\n    Require all denied\n</Limit>\n"
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride AuthConfig",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ao_auth_limit/file.txt", None, {}),
            ("POST", "/ao_auth_limit/file.txt", None, {}),
        ],
    },
    {
        "name": "allowoverride-all-limit-require",
        "dir": "ao_all_limit",
        "files": {
            ".htaccess": "<Limit POST>\n    Require all denied\n</Limit>\n"
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ao_all_limit/file.txt", None, {}),
            ("POST", "/ao_all_limit/file.txt", None, {}),
        ],
    },
    {
        "name": "allowoverride-all-limitexcept",
        "dir": "ao_limit_except",
        "files": {
            ".htaccess": (
                "<LimitExcept GET HEAD>\n    Require all denied\n</LimitExcept>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ao_limit_except/file.txt", None, {}),
            ("POST", "/ao_limit_except/file.txt", None, {}),
        ],
    },
    {
        "name": "allowoverride-all-nested-limit",
        "dir": "ao_nested_limit",
        "files": {
            ".htaccess": (
                "<Limit POST PUT>\n"
                "    <Limit POST>\n"
                "        Require all denied\n"
                "    </Limit>\n"
                "</Limit>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ao_nested_limit/file.txt", None, {}),
            ("POST", "/ao_nested_limit/file.txt", None, {}),
            ("PUT", "/ao_nested_limit/file.txt", None, {}),
        ],
    },
    {
        "name": "allowoverride-options-indexes",
        "dir": "ao_options",
        "files": {".htaccess": "Options +Indexes\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride Options",
            "</Directory>",
        ],
        "requests": [("GET", "/ao_options/", None, {})],
    },
    {
        "name": "allowoverride-options-eq-indexes",
        "dir": "ao_options_eq",
        "files": {".htaccess": "Options +Indexes\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride Options=Indexes",
            "</Directory>",
        ],
        "requests": [("GET", "/ao_options_eq/", None, {})],
    },
    {
        "name": "allowoverride-options-eq-execcgi-rejects-indexes",
        "dir": "ao_options_eq_bad",
        "files": {".htaccess": "Options +Indexes\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride Options=ExecCGI",
            "</Directory>",
        ],
        "requests": [("GET", "/ao_options_eq_bad/file.txt", None, {})],
    },
    {
        "name": "allowoverride-fileinfo-header",
        "dir": "ao_fileinfo",
        "files": {".htaccess": "Header set X-Case yes\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride FileInfo",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ao_fileinfo/file.txt", None, {"x-case": ["yes"]})
        ],
    },
    {
        "name": "allowoverride-authconfig-header",
        "dir": "ao_auth_header",
        "files": {".htaccess": "Header set X-Case yes\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride AuthConfig",
            "</Directory>",
        ],
        "requests": [("GET", "/ao_auth_header/file.txt", None, {})],
    },
    {
        "name": "limit-options-indexes",
        "dir": "limit_options_indexes",
        "config": [
            f'<Directory "{{dir}}">',
            "    Options +Indexes",
            "    <Limit GET>",
            "        Options -Indexes",
            "    </Limit>",
            "</Directory>",
        ],
        "requests": [("GET", "/limit_options_indexes/", None, {})],
    },
    {
        "name": "limit-header-effect",
        "dir": "limit_header_effect",
        "config": [
            f'<Directory "{{dir}}">',
            "    Header set X-Limit outer",
            "    <Limit GET>",
            "        Header set X-Limit limited",
            "    </Limit>",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/limit_header_effect/file.txt", None, {"x-limit": ["limited"]})
        ],
    },
    {
        "name": "require-all",
        "dir": "req_all",
        "config": [
            f'<Directory "{{dir}}">',
            "    <RequireAll>",
            "        Require ip 127.0.0.1",
            "        Require local",
            "    </RequireAll>",
            "</Directory>",
        ],
        "requests": [("GET", "/req_all/file.txt", None, {})],
    },
    {
        "name": "require-none",
        "dir": "req_none",
        "config": [
            f'<Directory "{{dir}}">',
            "    <RequireAll>",
            "        Require all granted",
            "        <RequireNone>",
            "            Require ip 127.0.0.1",
            "        </RequireNone>",
            "    </RequireAll>",
            "</Directory>",
        ],
        "requests": [("GET", "/req_none/file.txt", None, {})],
    },
    {
        "name": "require-none-multi-one-match",
        "dir": "req_none_multi_one",
        "config": [
            f'<Directory "{{dir}}">',
            "    <RequireAll>",
            "        Require all granted",
            "        <RequireNone>",
            "            Require ip 10.0.0.0/8",
            "            Require ip 127.0.0.0/8",
            "        </RequireNone>",
            "    </RequireAll>",
            "</Directory>",
        ],
        "requests": [("GET", "/req_none_multi_one/file.txt", None, {})],
    },
    {
        "name": "require-none-multi-two-of-three-match",
        "dir": "req_none_multi_two",
        "config": [
            f'<Directory "{{dir}}">',
            "    <RequireAll>",
            "        Require all granted",
            "        <RequireNone>",
            "            Require ip 10.0.0.0/8",
            "            Require ip 127.0.0.0/8",
            "            Require ip 127.0.0.1",
            "        </RequireNone>",
            "    </RequireAll>",
            "</Directory>",
        ],
        "requests": [("GET", "/req_none_multi_two/file.txt", None, {})],
    },
    {
        "name": "require-none-multi-nonmatching-allows",
        "dir": "req_none_multi_none",
        "config": [
            f'<Directory "{{dir}}">',
            "    <RequireAll>",
            "        Require all granted",
            "        <RequireNone>",
            "            Require ip 10.0.0.0/8",
            "            Require ip 192.0.2.0/24",
            "        </RequireNone>",
            "    </RequireAll>",
            "</Directory>",
        ],
        "requests": [("GET", "/req_none_multi_none/file.txt", None, {})],
    },
    {
        "name": "authmerging-and",
        "dir": "authmerge_and",
        "files": {"child/file.txt": "child\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    Require ip 10.0.0.0/8",
            "</Directory>",
            f'<Directory "{{dir}}/child">',
            "    AuthMerging And",
            "    AuthType Basic",
            '    AuthName "And"',
            f'    AuthUserFile "{BASE}/.htpasswd"',
            "    Require user alice",
            "</Directory>",
        ],
        "requests": [("GET", "/authmerge_and/child/file.txt", None, {})],
    },
    {
        "name": "authmerging-or",
        "dir": "authmerge_or",
        "files": {"child/file.txt": "child\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    Require ip 127.0.0.1",
            "</Directory>",
            f'<Directory "{{dir}}/child">',
            "    AuthMerging Or",
            "    AuthType Basic",
            '    AuthName "Or"',
            f'    AuthUserFile "{BASE}/.htpasswd"',
            "    Require user alice",
            "</Directory>",
        ],
        "requests": [("GET", "/authmerge_or/child/file.txt", None, {})],
    },
    {
        "name": "satisfy-any",
        "dir": "sat_any",
        "config": [
            f'<Directory "{{dir}}">',
            "    Require ip 10.0.0.0/8",
            "    Allow from all",
            "    Satisfy Any",
            "</Directory>",
        ],
        "requests": [("GET", "/sat_any/file.txt", None, {})],
    },
    {
        "name": "satisfy-all",
        "dir": "sat_all",
        "config": [
            f'<Directory "{{dir}}">',
            "    Require ip 127.0.0.1",
            "    Deny from all",
            "    Satisfy All",
            "</Directory>",
        ],
        "requests": [("GET", "/sat_all/file.txt", None, {})],
    },
    {
        "name": "if-elseif-else",
        "dir": "if_chain",
        "config": [
            f'<Directory "{{dir}}">',
            '    <If "%{HTTP:X-Branch} == \'a\'">',
            "        Header set X-Branch a",
            "        Require all granted",
            "    </If>",
            '    <ElseIf "%{HTTP:X-Branch} == \'b\'">',
            "        Require all denied",
            "    </ElseIf>",
            "    <Else>",
            "        Require ip 192.0.2.0/24",
            "    </Else>",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/if_chain/file.txt", {"X-Branch": "a"}, {}),
            ("GET", "/if_chain/file.txt", {"X-Branch": "b"}, {}),
            ("GET", "/if_chain/file.txt", None, {}),
        ],
    },
    {
        "name": "files-within-directory",
        "dir": "files_dir",
        "config": [
            f'<Directory "{{dir}}">',
            "    Require all granted",
            '    <Files "secret.txt">',
            "        Require all denied",
            "    </Files>",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/files_dir/file.txt", None, {}),
            ("GET", "/files_dir/secret.txt", None, {}),
        ],
    },
    {
        "name": "location-overrides-directory",
        "dir": "loc_dir",
        "config": [
            f'<Directory "{{dir}}">',
            "    Require all granted",
            "</Directory>",
            '<Location "/loc_dir/">',
            "    Require all denied",
            "</Location>",
        ],
        "requests": [("GET", "/loc_dir/file.txt", None, {})],
    },
    {
        "name": "options-child-remove-indexes",
        "dir": "opt_child",
        "files": {"child/file.txt": "child\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    Options +Indexes",
            "</Directory>",
            f'<Directory "{{dir}}/child">',
            "    Options -Indexes",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/opt_child/", None, {}),
            ("GET", "/opt_child/child/", None, {}),
        ],
    },
    {
        "name": "htaccess-nested-limit-except",
        "dir": "ht_nested_limit",
        "files": {
            ".htaccess": (
                "<LimitExcept POST>\n"
                "    <Limit GET>\n"
                "        Require all denied\n"
                "    </Limit>\n"
                "</LimitExcept>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        # POST is unrestricted by the access rule; Apache's core static
        # handler answers 200 while vapached deliberately answers 405.  That
        # method divergence is documented in README.md and is not an access
        # control difference: neither side may answer 401/403 here.
        "status_equiv": {"POST": {200, 405}},
        "requests": [
            ("GET", "/ht_nested_limit/file.txt", None, {}),
            ("POST", "/ht_nested_limit/file.txt", None, {}),
        ],
    },
    {
        "name": "htaccess-limit-and-legacy-order",
        "dir": "ht_legacy",
        "files": {
            ".htaccess": (
                "<Limit POST>\n"
                "    Order allow,deny\n"
                "    Deny from all\n"
                "</Limit>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride Limit",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_legacy/file.txt", None, {}),
            ("POST", "/ht_legacy/file.txt", None, {}),
        ],
    },
    {
        "name": "require-implicit-any",
        "dir": "req_implicit_any",
        "config": [
            f'<Directory "{{dir}}">',
            "    Require ip 10.0.0.0/8",
            "    Require local",
            "</Directory>",
        ],
        "requests": [("GET", "/req_implicit_any/file.txt", None, {})],
    },
    {
        "name": "require-method",
        "dir": "req_method",
        "config": [
            f'<Directory "{{dir}}">',
            "    Require method GET",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/req_method/file.txt", None, {}),
            ("POST", "/req_method/file.txt", None, {}),
        ],
    },
    {
        "name": "authmerging-default-replaces-parent",
        "dir": "authmerge_default",
        "files": {"child/file.txt": "child\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    Require ip 10.0.0.0/8",
            "</Directory>",
            f'<Directory "{{dir}}/child">',
            "    Require local",
            "</Directory>",
        ],
        "requests": [("GET", "/authmerge_default/child/file.txt", None, {})],
    },
    {
        "name": "satisfy-any-host-denied-auth-passes",
        "dir": "sat_any_host_deny",
        "config": [
            f'<Directory "{{dir}}">',
            "    Deny from all",
            "    Require ip 127.0.0.1",
            "    Satisfy Any",
            "</Directory>",
        ],
        "requests": [("GET", "/sat_any_host_deny/file.txt", None, {})],
    },
    {
        "name": "limit-main-nested",
        "dir": "limit_main_nested",
        "config": [
            f'<Directory "{{dir}}">',
            "    <Limit POST PUT>",
            "        <Limit PUT>",
            "            Require all denied",
            "        </Limit>",
            "    </Limit>",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/limit_main_nested/file.txt", None, {}),
            ("PUT", "/limit_main_nested/file.txt", None, {}),
        ],
    },
    {
        "name": "htaccess-limitexcept-head",
        "dir": "ht_limitexcept_head",
        "files": {
            ".htaccess": (
                "<LimitExcept GET HEAD>\n"
                "    Require all denied\n"
                "</LimitExcept>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_limitexcept_head/file.txt", None, {}),
            ("HEAD", "/ht_limitexcept_head/file.txt", None, {}),
            ("POST", "/ht_limitexcept_head/file.txt", None, {}),
        ],
    },
    {
        "name": "htaccess-fileinfo-cannot-require",
        "dir": "ht_fileinfo_require",
        "files": {".htaccess": "Require all denied\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride FileInfo",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_fileinfo_require/file.txt", None, {})],
    },
    {
        "name": "htaccess-authconfig-cannot-order",
        "dir": "ht_authconfig_order",
        "files": {".htaccess": "Order allow,deny\nDeny from all\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride AuthConfig",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_authconfig_order/file.txt", None, {})],
    },
    {
        "name": "htaccess-limit-cannot-satisfy",
        "dir": "ht_limit_satisfy",
        "files": {".htaccess": "Satisfy Any\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride Limit",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_limit_satisfy/file.txt", None, {})],
    },
    {
        "name": "htaccess-options-none-removes-indexes",
        "dir": "ht_options_none",
        "config": [
            f'<Directory "{{dir}}">',
            "    Options +Indexes",
            "    AllowOverride Options",
            "</Directory>",
        ],
        "files": {".htaccess": "Options None\n"},
        "requests": [("GET", "/ht_options_none/", None, {})],
    },
    {
        "name": "iffile-present-and-absent",
        "dir": "iffile_auth",
        "files": {"hit.txt": "hit\n"},
        "config": [
            f'<Directory "{{dir}}">',
            f'    <IfFile "{BASE}/www/iffile_auth/hit.txt">',
            "        Require all denied",
            "    </IfFile>",
            "</Directory>",
        ],
        "requests": [("GET", "/iffile_auth/file.txt", None, {})],
    },
    {
        "name": "directorymatch-vs-directory-order",
        "dir": "dm_order",
        "files": {"sub/file.txt": "sub\n"},
        "config": [
            f'<Directory "{{dir}}/sub">',
            "    Require all granted",
            "</Directory>",
            f'<DirectoryMatch "^{str(DOCROOT)}/dm_order/sub$">',
            "    Require all denied",
            "</DirectoryMatch>",
        ],
        "requests": [("GET", "/dm_order/sub/file.txt", None, {})],
    },
    {
        "name": "htaccess-fileinfo-files-requires-all",
        "dir": "ht_fileinfo_files",
        "files": {
            ".htaccess": '<Files "secret.txt">\n    Require all denied\n</Files>\n'
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride FileInfo",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_fileinfo_files/file.txt", None, {}),
            ("GET", "/ht_fileinfo_files/secret.txt", None, {}),
        ],
    },
    {
        "name": "htaccess-all-files",
        "dir": "ht_all_files",
        "files": {
            ".htaccess": '<Files "secret.txt">\n    Require all denied\n</Files>\n'
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_all_files/file.txt", None, {}),
            ("GET", "/ht_all_files/secret.txt", None, {}),
        ],
    },
    {
        "name": "htaccess-fileinfo-if-requires-all",
        "dir": "ht_fileinfo_if",
        "files": {
            ".htaccess": (
                '<If "%{HTTP:X-Test} == \'yes\'">\n'
                "    Require all denied\n"
                "</If>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride FileInfo",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_fileinfo_if/file.txt", {"X-Test": "yes"}, {}),
        ],
    },
    {
        "name": "htaccess-all-if",
        "dir": "ht_all_if",
        "files": {
            ".htaccess": (
                '<If "%{HTTP:X-Test} == \'yes\'">\n'
                "    Require all denied\n"
                "</If>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_all_if/file.txt", {"X-Test": "yes"}, {}),
            ("GET", "/ht_all_if/file.txt", None, {}),
        ],
    },
    {
        "name": "htaccess-fileinfo-ifmodule-requires-all",
        "dir": "ht_fileinfo_ifmodule",
        "files": {
            ".htaccess": (
                "<IfModule mod_headers.c>\n"
                "    Header set X-IfModule yes\n"
                "</IfModule>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride FileInfo",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_fileinfo_ifmodule/file.txt", None, {"x-ifmodule": None}),
        ],
    },
    {
        "name": "htaccess-all-ifmodule",
        "dir": "ht_all_ifmodule",
        "files": {
            ".htaccess": (
                "<IfModule mod_headers.c>\n"
                "    Header set X-IfModule yes\n"
                "</IfModule>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_all_ifmodule/file.txt", None, {"x-ifmodule": ["yes"]}),
        ],
    },
    {
        "name": "htaccess-fileinfo-iffile-requires-all",
        "dir": "ht_fileinfo_iffile",
        "files": {
            ".htaccess": ('<IfFile "ifflag.txt">\n' "    Require all denied\n" "</IfFile>\n")
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride FileInfo",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_fileinfo_iffile/file.txt", None, {})],
    },
    {
        "name": "htaccess-all-iffile",
        "dir": "ht_all_iffile",
        "files": {".htaccess": ('<IfFile "ifflag.txt">\n' "    Require all denied\n" "</IfFile>\n")},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_all_iffile/file.txt", None, {})],
    },
    {
        "name": "htaccess-fileinfo-files-header",
        "dir": "ht_fileinfo_files_header",
        "files": {
            ".htaccess": '<Files "secret.txt">\n    Header set X-Files yes\n</Files>\n'
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride FileInfo",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_fileinfo_files_header/secret.txt", None, {"x-files": None}),
        ],
    },
    {
        "name": "htaccess-all-files-header",
        "dir": "ht_all_files_header",
        "files": {
            ".htaccess": '<Files "secret.txt">\n    Header set X-Files yes\n</Files>\n'
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_all_files_header/secret.txt", None, {"x-files": ["yes"]}),
        ],
    },
    {
        "name": "htaccess-fileinfo-if-header",
        "dir": "ht_fileinfo_if_header",
        "files": {
            ".htaccess": (
                '<If "%{HTTP:X-Test} == \'yes\'">\n'
                "    Header set X-If yes\n"
                "</If>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride FileInfo",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_fileinfo_if_header/file.txt", {"X-Test": "yes"}, {"x-if": None}),
        ],
    },
    {
        "name": "htaccess-all-if-header",
        "dir": "ht_all_if_header",
        "files": {
            ".htaccess": (
                '<If "%{HTTP:X-Test} == \'yes\'">\n'
                "    Header set X-If yes\n"
                "</If>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_all_if_header/file.txt", {"X-Test": "yes"}, {"x-if": ["yes"]}),
        ],
    },
    {
        "name": "htaccess-fileinfo-iffile-header",
        "dir": "ht_fileinfo_iffile_header",
        "files": {
            ".htaccess": ('<IfFile "ifflag.txt">\n' "    Header set X-IfFile yes\n" "</IfFile>\n")
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride FileInfo",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_fileinfo_iffile_header/file.txt", None, {"x-iffile": None}),
        ],
    },
    {
        "name": "htaccess-all-iffile-header",
        "dir": "ht_all_iffile_header",
        "files": {
            ".htaccess": ('<IfFile "ifflag.txt">\n' "    Header set X-IfFile yes\n" "</IfFile>\n")
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_all_iffile_header/file.txt", None, {"x-iffile": ["yes"]}),
        ],
    },
    {
        "name": "htaccess-all-iffile-absent",
        "dir": "ht_all_iffile_absent",
        # A .htaccess-relative <IfFile> argument neither engine resolves must
        # skip the section on both sides (Apache looks under ServerRoot,
        # vapached under the confined DocumentRoot root), so the negative
        # branch is exercised without off-policy absolute-path probing.
        "files": {
            ".htaccess": (
                '<IfFile "no-such-flag.txt">\n' "    Require all denied\n" "</IfFile>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_all_iffile_absent/file.txt", None, {})],
    },
    {
        "name": "global-if-applied-last",
        "dir": "global_if_last",
        "config": [
            '<If "%{HTTP:X-Deny} == \'yes\'">',
            "    Require all denied",
            "</If>",
            f'<Directory "{{dir}}">',
            "    Require all granted",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/global_if_last/file.txt", {"X-Deny": "yes"}, {}),
            ("GET", "/global_if_last/file.txt", None, {}),
        ],
    },
    {
        "name": "nested-if-applied-after-location",
        "dir": "nested_if_location",
        "config": [
            f'<Directory "{{dir}}">',
            '    <If "%{HTTP:X-Deny} == \'yes\'">',
            "        Require all denied",
            "    </If>",
            "</Directory>",
            '<Location "/nested_if_location/">',
            "    Require all granted",
            "</Location>",
        ],
        "requests": [
            ("GET", "/nested_if_location/file.txt", {"X-Deny": "yes"}, {}),
            ("GET", "/nested_if_location/file.txt", None, {}),
        ],
    },
    {
        "name": "parent-if-vs-child-htaccess-grant",
        "dir": "parent_if_child_grant",
        "files": {
            ".htaccess": (
                '<If "%{HTTP:X-Deny} == \'yes\'">\n'
                "    Require all denied\n"
                "</If>\n"
            ),
            "child/.htaccess": "Require all granted\n",
            "child/file.txt": "child\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/parent_if_child_grant/child/file.txt", {"X-Deny": "yes"}, {}),
        ],
    },
    {
        "name": "config-if-vs-child-htaccess-grant",
        "dir": "config_if_child_grant",
        "files": {
            "child/.htaccess": "Require all granted\n",
            "child/file.txt": "child\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            '    <If "%{HTTP:X-Deny} == \'yes\'">',
            "        Require all denied",
            "    </If>",
            "</Directory>",
            f'<Directory "{{dir}}/child">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/config_if_child_grant/child/file.txt", {"X-Deny": "yes"}, {}),
        ],
    },
    {
        "name": "config-if-vs-child-htaccess-conditional",
        "dir": "config_if_child_cond",
        "files": {
            "child/.htaccess": (
                '<If "%{HTTP:X-Deny} == \'yes\'">\n'
                "    Require all granted\n"
                "</If>\n"
            ),
            "child/file.txt": "child\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            '    <If "%{HTTP:X-Deny} == \'yes\'">',
            "        Require all denied",
            "    </If>",
            "</Directory>",
            f'<Directory "{{dir}}/child">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/config_if_child_cond/child/file.txt", {"X-Deny": "yes"}, {}),
        ],
    },
    {
        "name": "child-htaccess-if-vs-config-grant",
        "dir": "child_if_config_grant",
        "files": {
            "child/.htaccess": (
                '<If "%{HTTP:X-Deny} == \'yes\'">\n'
                "    Require all denied\n"
                "</If>\n"
            ),
            "child/file.txt": "child\n",
        },
        "config": [
            f'<Directory "{{dir}}/child">',
            "    AllowOverride All",
            "    Require all granted",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/child_if_config_grant/child/file.txt", {"X-Deny": "yes"}, {}),
        ],
    },
    {
        "name": "htaccess-options-remove-not-permitted",
        "dir": "ht_options_remove",
        "files": {".htaccess": "Options -ExecCGI\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    Options FollowSymLinks ExecCGI",
            "    AllowOverride Options=Indexes",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_options_remove/file.txt", None, {})],
    },
    {
        "name": "htaccess-options-absolute-resets-inherited",
        "dir": "ht_options_absolute",
        "files": {".htaccess": "Options Indexes\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    Options FollowSymLinks ExecCGI",
            "    AllowOverride Options=Indexes",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_options_absolute/", None, {})],
    },
    {
        "name": "require-expr-document-root",
        "dir": "req_expr_docroot",
        "config": [
            f'<Directory "{{dir}}">',
            f'    Require expr "%{{DOCUMENT_ROOT}} == \'{DOCROOT}\'"',
            "</Directory>",
        ],
        "requests": [("GET", "/req_expr_docroot/file.txt", None, {})],
    },
    {
        "name": "directory-wildcard-rule",
        "dir": "wild_dir",
        "config": [
            f'<Directory "{DOCROOT}/wild_*">',
            "    Require all denied",
            "</Directory>",
        ],
        "requests": [("GET", "/wild_dir/file.txt", None, {})],
    },
    {
        "name": "directory-tilde-regex-rule",
        "dir": "tilde_dir",
        "config": [
            f'<Directory ~ "^{DOCROOT}/tilde_[a-z]+$">',
            "    Require all denied",
            "</Directory>",
        ],
        "requests": [("GET", "/tilde_dir/file.txt", None, {})],
    },
    {
        "name": "directory-tilde-regex-trailing",
        "dir": "tilde2_dir",
        "config": [
            f'<Directory ~ "^{DOCROOT}/tilde2_[a-z]+/">',
            "    Require all denied",
            "</Directory>",
        ],
        "requests": [("GET", "/tilde2_dir/file.txt", None, {})],
    },
    {
        "name": "directorymatch-exact-trailing",
        "dir": "dm_exact",
        "files": {"sub/file.txt": "sub\n"},
        "config": [
            f'<DirectoryMatch "^{DOCROOT}/dm_exact/sub/">',
            "    Require all denied",
            "</DirectoryMatch>",
        ],
        "requests": [("GET", "/dm_exact/sub/file.txt", None, {})],
    },
    {
        "name": "directorymatch-exact-no-trailing",
        "dir": "dm_exact2",
        "files": {"sub/file.txt": "sub\n"},
        "config": [
            f'<DirectoryMatch "^{DOCROOT}/dm_exact2/sub$">',
            "    Require all denied",
            "</DirectoryMatch>",
        ],
        "requests": [("GET", "/dm_exact2/sub/file.txt", None, {})],
    },
    {
        "name": "directorymatch-prefix",
        "dir": "dm_prefix",
        "files": {"sub/file.txt": "sub\n"},
        "config": [
            f'<DirectoryMatch "^{DOCROOT}/dm_prefix/sub">',
            "    Require all denied",
            "</DirectoryMatch>",
        ],
        "requests": [("GET", "/dm_prefix/sub/file.txt", None, {})],
    },
    {
        "name": "directory-tilde-no-anchor",
        "dir": "tilde3_dir",
        "config": [
            f'<Directory ~ "^{DOCROOT}/tilde3_">',
            "    Require all denied",
            "</Directory>",
        ],
        "requests": [("GET", "/tilde3_dir/file.txt", None, {})],
    },
    {
        "name": "override-wildcard-directory-htaccess",
        "dir": "wo_dir",
        "files": {".htaccess": "Require all denied\n"},
        "config": [
            f'<Directory "{DOCROOT}/wo_*">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [("GET", "/wo_dir/file.txt", None, {})],
    },
    {
        "name": "files-wildcard-star",
        "dir": "files_wild_star",
        "config": [
            f'<Directory "{{dir}}">',
            '    <Files "secret*">',
            "        Require all denied",
            "    </Files>",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/files_wild_star/file.txt", None, {}),
            ("GET", "/files_wild_star/secret.txt", None, {}),
        ],
    },
    {
        "name": "files-wildcard-question",
        "dir": "files_wild_q",
        "files": {"secret1.txt": "one\n"},
        "config": [
            f'<Directory "{{dir}}">',
            '    <Files "secret?.txt">',
            "        Require all denied",
            "    </Files>",
            "</Directory>",
        ],
        "requests": [("GET", "/files_wild_q/secret1.txt", None, {})],
    },
    {
        "name": "files-tilde-regex",
        "dir": "files_tilde",
        "files": {"secret.txt": "secret\n"},
        "config": [
            f'<Directory "{{dir}}">',
            '    <Files ~ "^secret\\..*$">',
            "        Require all denied",
            "    </Files>",
            "</Directory>",
        ],
        "requests": [("GET", "/files_tilde/secret.txt", None, {})],
    },
    {
        "name": "htaccess-files-wildcard",
        "dir": "ht_files_wild",
        "files": {
            ".htaccess": '<Files "secret*">\n    Require all denied\n</Files>\n'
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_files_wild/file.txt", None, {}),
            ("GET", "/ht_files_wild/secret.txt", None, {}),
        ],
    },
    {
        "name": "files-character-class",
        "dir": "files_class",
        "files": {"secret1.txt": "one\n", "secret2.txt": "two\n"},
        "config": [
            f'<Directory "{{dir}}">',
            '    <Files "secret[12].txt">',
            "        Require all denied",
            "    </Files>",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/files_class/secret1.txt", None, {}),
            ("GET", "/files_class/secret3.txt", None, {}),
        ],
    },
    {
        "name": "wildcard-directory-rewrite-forbid",
        "dir": "rw_dir",
        "files": {"blocked": "blocked\n", "file.txt": "file\n"},
        "config": [
            f'<Directory "{DOCROOT}/rw_*">',
            "    RewriteEngine On",
            "    RewriteRule ^blocked$ - [F]",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/rw_dir/blocked", None, {}),
            ("GET", "/rw_dir/file.txt", None, {}),
        ],
    },
    {
        "name": "htaccess-authmerging-and",
        "dir": "ht_authmerge_and",
        "files": {
            "child/.htaccess": "AuthMerging And\nRequire local\n",
            "child/file.txt": "child\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    Require ip 10.0.0.0/8",
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_authmerge_and/child/file.txt", None, {})],
    },
    {
        "name": "htaccess-authmerging-or",
        "dir": "ht_authmerge_or",
        "files": {
            "child/.htaccess": "AuthMerging Or\nRequire all denied\n",
            "child/file.txt": "child\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    Require local",
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_authmerge_or/child/file.txt", None, {})],
    },
    {
        "name": "htaccess-satisfy-any",
        "dir": "ht_satisfy_any",
        "files": {
            ".htaccess": "Require all denied\nAllow from all\nSatisfy Any\n"
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_satisfy_any/file.txt", None, {})],
    },
    {
        "name": "htaccess-requireall",
        "dir": "ht_requireall",
        "files": {
            ".htaccess": (
                "<RequireAll>\n"
                "    Require ip 127.0.0.1\n"
                "    Require local\n"
                "</RequireAll>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride AuthConfig",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_requireall/file.txt", None, {})],
    },
    {
        "name": "htaccess-requirenone",
        "dir": "ht_requirenone",
        "files": {
            ".htaccess": (
                "<RequireAll>\n"
                "    Require all granted\n"
                "    <RequireNone>\n"
                "        Require ip 127.0.0.1\n"
                "    </RequireNone>\n"
                "</RequireAll>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride AuthConfig",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_requirenone/file.txt", None, {})],
    },
    {
        "name": "htaccess-requirenone-multi-one-match",
        "dir": "ht_requirenone_multi",
        "files": {
            ".htaccess": (
                "<RequireAll>\n"
                "    Require all granted\n"
                "    <RequireNone>\n"
                "        Require ip 10.0.0.0/8\n"
                "        Require ip 127.0.0.0/8\n"
                "    </RequireNone>\n"
                "</RequireAll>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride AuthConfig",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_requirenone_multi/file.txt", None, {})],
    },
    {
        "name": "htaccess-requirenone-multi-two-of-three-match",
        "dir": "ht_requirenone_multi_two",
        "files": {
            ".htaccess": (
                "<RequireAll>\n"
                "    Require all granted\n"
                "    <RequireNone>\n"
                "        Require ip 10.0.0.0/8\n"
                "        Require ip 127.0.0.0/8\n"
                "        Require ip 127.0.0.1\n"
                "    </RequireNone>\n"
                "</RequireAll>\n"
            )
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride AuthConfig",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_requirenone_multi_two/file.txt", None, {})],
    },
    {
        "name": "allowmethods-parent-post-get-denied",
        "dir": "am_parent",
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowMethods POST",
            "</Directory>",
        ],
        "requests": [("GET", "/am_parent/file.txt", None, {})],
    },
    {
        "name": "allowmethods-child-reset",
        "dir": "am_reset",
        "files": {"child/file.txt": "child\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowMethods POST",
            "</Directory>",
            f'<Directory "{{dir}}/child">',
            "    AllowMethods reset",
            "</Directory>",
        ],
        "requests": [("GET", "/am_reset/child/file.txt", None, {})],
    },
    {
        "name": "allowmethods-child-get",
        "dir": "am_child_get",
        "files": {"child/file.txt": "child\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowMethods POST",
            "</Directory>",
            f'<Directory "{{dir}}/child">',
            "    AllowMethods GET",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/am_child_get/child/file.txt", None, {}),
            ("POST", "/am_child_get/child/file.txt", None, {}),
        ],
    },
    {
        "name": "files-character-class-negated",
        "dir": "files_class_neg",
        "files": {"secret1.txt": "one\n", "secret2.txt": "two\n"},
        "config": [
            f'<Directory "{{dir}}">',
            '    <Files "secret[!1].txt">',
            "        Require all denied",
            "    </Files>",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/files_class_neg/secret1.txt", None, {}),
            ("GET", "/files_class_neg/secret2.txt", None, {}),
        ],
    },
    {
        "name": "location-trailing-slash-boundary",
        "dir": "loc_trail",
        "files": {"file.txt": "file\n"},
        "config": [
            '<Location "/loc_trail">',
            "    Require all denied",
            "</Location>",
            '<Location "/loc_trail/">',
            "    Require all granted",
            "</Location>",
        ],
        "requests": [
            ("GET", "/loc_trail", None, {}),
            ("GET", "/loc_trail/", None, {}),
            ("GET", "/loc_trail/file.txt", None, {}),
        ],
    },
    {
        "name": "location-trailing-slash-grant-file",
        "dir": "loc_file_case",
        "config": [
            '<Location "/loc_file_grant">',
            "    Require all denied",
            "</Location>",
            '<Location "/loc_file_grant/">',
            "    Require all granted",
            "</Location>",
        ],
        "requests": [("GET", "/loc_file_grant", None, {})],
    },
    {
        "name": "nested-if-conditions",
        "dir": "nested_if_cond",
        "config": [
            '<If "%{HTTP:X-A} == \'yes\'">',
            '    <If "%{HTTP:X-B} == \'yes\'">',
            "        Require all denied",
            "    </If>",
            "</If>",
        ],
        "requests": [
            ("GET", "/nested_if_cond/file.txt", {"X-A": "yes", "X-B": "yes"}, {}),
            ("GET", "/nested_if_cond/file.txt", {"X-A": "yes"}, {}),
            ("GET", "/nested_if_cond/file.txt", None, {}),
        ],
    },
    {
        "name": "legacy-child-overrides-parent",
        "dir": "legacy_child",
        "files": {"child/file.txt": "child\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    Order allow,deny",
            "    Deny from all",
            "</Directory>",
            f'<Directory "{{dir}}/child">',
            "    Order deny,allow",
            "    Allow from all",
            "</Directory>",
        ],
        "requests": [("GET", "/legacy_child/child/file.txt", None, {})],
    },
    {
        "name": "satisfy-any-child-overrides-parent-require",
        "dir": "satisfy_child_any",
        "files": {"child/file.txt": "child\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    Require all denied",
            "</Directory>",
            f'<Directory "{{dir}}/child">',
            "    Allow from all",
            "    Satisfy Any",
            "</Directory>",
        ],
        "requests": [("GET", "/satisfy_child_any/child/file.txt", None, {})],
    },
    {
        "name": "satisfy-all-child-keeps-parent-require",
        "dir": "satisfy_child_all",
        "files": {"child/file.txt": "child\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    Require all denied",
            "</Directory>",
            f'<Directory "{{dir}}/child">',
            "    Allow from all",
            "    Satisfy All",
            "</Directory>",
        ],
        "requests": [("GET", "/satisfy_child_all/child/file.txt", None, {})],
    },
    {
        "name": "limit-inside-location",
        "dir": "limit_loc",
        "config": [
            '<Location "/limit_loc/">',
            "    <Limit POST>",
            "        Require all denied",
            "    </Limit>",
            "</Location>",
        ],
        "requests": [
            ("GET", "/limit_loc/file.txt", None, {}),
            ("POST", "/limit_loc/file.txt", None, {}),
        ],
    },
    {
        "name": "limit-inside-files",
        "dir": "limit_files",
        "files": {"limit_target.txt": "limit target\n"},
        "config": [
            '<Files "limit_target.txt">',
            "    <Limit POST>",
            "        Require all denied",
            "    </Limit>",
            "</Files>",
        ],
        "requests": [
            ("GET", "/limit_files/limit_target.txt", None, {}),
            ("POST", "/limit_files/limit_target.txt", None, {}),
        ],
    },
    {
        "name": "parent-htaccess-grant-vs-child-directory-deny",
        "dir": "parent_ht_grant_child_deny",
        "files": {
            ".htaccess": "Require all granted\n",
            "child/file.txt": "child\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
            f'<Directory "{{dir}}/child">',
            "    Require all denied",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/parent_ht_grant_child_deny/child/file.txt", None, {}),
        ],
    },
    {
        "name": "parent-htaccess-deny-vs-child-directory-grant",
        "dir": "parent_ht_deny_child_grant",
        "files": {
            ".htaccess": "Require all denied\n",
            "child/file.txt": "child\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
            f'<Directory "{{dir}}/child">',
            "    Require all granted",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/parent_ht_deny_child_grant/child/file.txt", None, {}),
        ],
    },
    {
        "name": "config-files-grant-vs-htaccess-files-deny",
        "dir": "files_cfg_grant_ht_deny",
        "files": {
            ".htaccess": '<Files "secret.txt">\n    Require all denied\n</Files>\n',
            "secret.txt": "secret\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            '    <Files "secret.txt">',
            "        Require all granted",
            "    </Files>",
            "</Directory>",
        ],
        "requests": [("GET", "/files_cfg_grant_ht_deny/secret.txt", None, {})],
    },
    {
        "name": "config-files-deny-vs-htaccess-files-grant",
        "dir": "files_cfg_deny_ht_grant",
        "files": {
            ".htaccess": '<Files "secret.txt">\n    Require all granted\n</Files>\n',
            "secret.txt": "secret\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            '    <Files "secret.txt">',
            "        Require all denied",
            "    </Files>",
            "</Directory>",
        ],
        "requests": [("GET", "/files_cfg_deny_ht_grant/secret.txt", None, {})],
    },
    {
        "name": "location-vs-htaccess-files",
        "dir": "loc_vs_ht_files",
        "files": {
            ".htaccess": '<Files "secret.txt">\n    Require all granted\n</Files>\n',
            "secret.txt": "secret\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
            '<Location "/loc_vs_ht_files/">',
            "    Require all denied",
            "</Location>",
        ],
        "requests": [("GET", "/loc_vs_ht_files/secret.txt", None, {})],
    },
    {
        "name": "directorymatch-vs-htaccess-grant",
        "dir": "dm_vs_ht",
        "files": {".htaccess": "Require all denied\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All",
            "</Directory>",
            f'<DirectoryMatch "^{str(DOCROOT)}/dm_vs_ht/">',
            "    Require all granted",
            "</DirectoryMatch>",
        ],
        "requests": [("GET", "/dm_vs_ht/file.txt", None, {})],
    },
    {
        "name": "htaccess-authconfig-files-require",
        "dir": "ht_authconfig_files",
        "files": {
            ".htaccess": '<Files "secret.txt">\n    Require all denied\n</Files>\n',
            "secret.txt": "secret\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride AuthConfig",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_authconfig_files/secret.txt", None, {})],
    },
    {
        "name": "htaccess-authconfig-if-require",
        "dir": "ht_authconfig_if",
        "files": {
            ".htaccess": '<If "%{HTTP:X-Test} == \'yes\'">\n    Require all denied\n</If>\n'
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride AuthConfig",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/ht_authconfig_if/file.txt", {"X-Test": "yes"}, {}),
        ],
    },
    {
        "name": "allowoverridelist-require-only",
        "dir": "aol_require",
        "files": {".htaccess": "Require all denied\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride None",
            "    AllowOverrideList Require",
            "</Directory>",
        ],
        "requests": [("GET", "/aol_require/file.txt", None, {})],
    },
    {
        "name": "allowoverridelist-does-not-admit-files-wrapper",
        "dir": "aol_no_files_wrapper",
        "files": {
            ".htaccess": '<Files "secret.txt">\n    Require all granted\n</Files>\n',
            "secret.txt": "secret\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride None",
            "    AllowOverrideList Require",
            '    <FilesMatch "^secret\\.txt$">',
            "        Require all denied",
            "    </FilesMatch>",
            "</Directory>",
        ],
        "requests": [("GET", "/aol_no_files_wrapper/secret.txt", None, {})],
    },
    {
        "name": "allowoverridelist-does-not-admit-filesmatch-wrapper",
        "dir": "aol_no_filesmatch_wrapper",
        "files": {
            ".htaccess": '<FilesMatch "^secret\\.txt$">\n    Require all granted\n</FilesMatch>\n',
            "secret.txt": "secret\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride None",
            "    AllowOverrideList Require",
            '    <FilesMatch "^secret\\.txt$">',
            "        Require all denied",
            "    </FilesMatch>",
            "</Directory>",
        ],
        "requests": [("GET", "/aol_no_filesmatch_wrapper/secret.txt", None, {})],
    },
    {
        "name": "allowoverridelist-does-not-admit-if-wrapper",
        "dir": "aol_no_if_wrapper",
        "files": {
            ".htaccess": '<If "true">\n    Require all denied\n</If>\n',
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride None",
            "    AllowOverrideList Require",
            "</Directory>",
        ],
        "requests": [("GET", "/aol_no_if_wrapper/file.txt", None, {})],
    },
    {
        "name": "allowoverridelist-does-not-admit-require-wrapper",
        "dir": "aol_no_require_wrapper",
        "files": {
            ".htaccess": "<RequireAll>\n    Require all granted\n</RequireAll>\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride None",
            "    AllowOverrideList Require",
            "</Directory>",
        ],
        "requests": [("GET", "/aol_no_require_wrapper/file.txt", None, {})],
    },
    {
        "name": "allowoverridelist-does-not-admit-limit-wrapper",
        "dir": "aol_no_limit_wrapper",
        "files": {
            ".htaccess": "<Limit GET>\n    Require all denied\n</Limit>\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride None",
            "    AllowOverrideList Require",
            "</Directory>",
        ],
        "requests": [("GET", "/aol_no_limit_wrapper/file.txt", None, {})],
    },
    {
        "name": "allowoverridelist-explicit-files-wrapper",
        "dir": "aol_explicit_files_wrapper",
        "files": {
            ".htaccess": '<Files "secret.txt">\n    Require all granted\n</Files>\n',
            "secret.txt": "secret\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride None",
            '    AllowOverrideList "<Files" Require',
            '    <FilesMatch "^secret\\.txt$">',
            "        Require all denied",
            "    </FilesMatch>",
            "</Directory>",
        ],
        "requests": [("GET", "/aol_explicit_files_wrapper/secret.txt", None, {})],
    },
    {
        "name": "allowoverridelist-header-only",
        "dir": "aol_header",
        "files": {".htaccess": "Header set X-AOL yes\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride None",
            "    AllowOverrideList Header",
            "</Directory>",
        ],
        "requests": [
            ("GET", "/aol_header/file.txt", None, {"x-aol": ["yes"]})
        ],
    },
    {
        "name": "allowoverridelist-narrows-require",
        "dir": "aol_narrow",
        "files": {".htaccess": "Require all denied\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride None",
            "    AllowOverrideList Redirect",
            "</Directory>",
        ],
        "requests": [("GET", "/aol_narrow/file.txt", None, {})],
    },
    {
        "name": "nonfatal-unknown",
        "dir": "nf_unknown",
        "files": {".htaccess": "DefinitelyNotADirective on\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All Nonfatal=Unknown",
            "</Directory>",
        ],
        "requests": [("GET", "/nf_unknown/file.txt", None, {})],
    },
    {
        "name": "nonfatal-override",
        "dir": "nf_override",
        "files": {".htaccess": "Require all denied\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride Options Nonfatal=Override",
            "</Directory>",
        ],
        "requests": [("GET", "/nf_override/file.txt", None, {})],
    },
    {
        "name": "nonfatal-override-does-not-cover-unknown",
        "dir": "nf_override_unknown",
        "files": {".htaccess": "DefinitelyNotADirective on\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride All Nonfatal=Override",
            "</Directory>",
        ],
        "requests": [("GET", "/nf_override_unknown/file.txt", None, {})],
    },
    {
        "name": "nonfatal-all",
        "dir": "nf_all",
        "files": {
            ".htaccess": "DefinitelyNotADirective on\nRequire all denied\n"
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride Options Nonfatal=All",
            "</Directory>",
        ],
        "requests": [("GET", "/nf_all/file.txt", None, {})],
    },
    {
        "name": "htaccess-indexes-directoryindex",
        "dir": "ht_indexes",
        "files": {
            ".htaccess": "DirectoryIndex missing.html\n",
            "index.html": "index still here\n",
        },
        "config": [
            f'<Directory "{{dir}}">',
            "    AllowOverride Indexes",
            "</Directory>",
        ],
        "requests": [("GET", "/ht_indexes/", None, {})],
    },
    {
        "name": "if-block-inside-directory-always-rule",
        "dir": "if_dir",
        "files": {"file.txt": "hello\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    <If true>",
            "        Header set X-Always-Test yes",
            "    </If>",
            "</Directory>",
        ],
        "requests": [("GET", "/if_dir/file.txt", None, {})],
    },
    {
        "name": "if-block-inside-location-always-rule",
        "dir": "if_loc",
        "files": {"file.txt": "hello\n"},
        "config": [
            '<Location "/if_loc">',
            "    <If true>",
            "        Header set X-Always-Loc yes",
            "    </If>",
            "</Location>",
        ],
        "requests": [("GET", "/if_loc/file.txt", None, {})],
    },
    {
        "name": "if-block-else-branch-inside-directory",
        "dir": "if_else",
        "files": {"file.txt": "hello\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    <If false>",
            "        Header set X-Branch wrong",
            "    </If>",
            "    <Else>",
            "        Header set X-Branch right",
            "    </Else>",
            "</Directory>",
        ],
        "requests": [("GET", "/if_else/file.txt", None, {})],
    },
]

# P15-C: these are valid regular Apache PCRE patterns. The access-control
# parity suite treats Apache as the executable oracle, so a future regex-engine
# or expression-parser change cannot silently erase the guard again.
for suffix, pattern, filename in [
    ("q", r"\Qsecret\E", "secret.txt"),
    ("z", r"secret\.txt\Z", "secret.txt"),
    ("comment", r"sec(?#match)ret", "secret.txt"),
    ("k", r"\Ksecret", "secret.txt"),
]:
    name = f"p15-expr-pcre-{suffix}"
    CASES.append(
        {
            "name": name,
            "dir": name.replace("-", "_"),
            "files": {filename: "protected\n"},
            "config": [
                f'<Directory "{{dir}}">',
                f'    <If "%{{REQUEST_URI}} =~ /{pattern}/">',
                "        Require all denied",
                "    </If>",
                "</Directory>",
            ],
            "requests": [
                ("GET", f"/{name.replace('-', '_')}/{filename}", None, {})
            ],
        }
    )

CASES.append(
    {
        "name": "p15-remoteip-trusted-private",
        "dir": "p15_remoteip_trusted_private",
        "files": {"secret.txt": "protected\n"},
        "config": [
            f'<Directory "{{dir}}">',
            "    Require ip 10.1.2.3",
            "</Directory>",
        ],
        "requests": [
            (
                "GET",
                "/p15_remoteip_trusted_private/secret.txt",
                {"X-Forwarded-For": "10.1.2.3"},
                {},
            ),
            (
                "GET",
                "/p15_remoteip_trusted_private/secret.txt",
                {"X-Forwarded-For": "8.8.8.8, 10.1.2.3"},
                {},
            ),
            (
                "GET",
                "/p15_remoteip_trusted_private/secret.txt",
                {"X-Forwarded-For": "::ffff:10.1.2.3"},
                {},
            ),
            (
                "GET",
                "/p15_remoteip_trusted_private/secret.txt",
                {"X-Forwarded-For": "10.1.2.3,"},
                {},
            ),
        ],
    }
)


def generated_cases():
    """Generate the category/method/authz matrices from a small model.

    The point is not to enumerate every Apache directive, but to make the
    dangerous axes explicit and cheap to extend: who may override what, which
    methods a section covers, and how authorization is combined across levels.
    """
    out = []

    # AllowOverride category x .htaccess directive.  A disallowed directive
    # yields 500 in both servers; an allowed one changes observable behavior.
    categories = [
        ("none", "None"),
        ("all", "All"),
        ("authconfig", "AuthConfig"),
        ("fileinfo", "FileInfo"),
        ("indexes", "Indexes"),
        ("limit", "Limit"),
        ("options", "Options"),
        ("options_indexes", "Options=Indexes"),
        ("options_execcgi", "Options=ExecCGI"),
    ]
    directives = [
        ("require", "Require all denied\n", {}),
        ("header", "Header set X-Cat yes\n", {}),
        (
            "directoryindex",
            "DirectoryIndex missing.html\n",
            {"index.html": "present\n"},
        ),
        (
            "limit_post",
            "<Limit POST>\n    Require all denied\n</Limit>\n",
            {},
        ),
        ("options_indexes", "Options +Indexes\n", {}),
        (
            "legacy_order",
            "Order allow,deny\nDeny from all\n",
            {},
        ),
    ]
    for cname, cmode in categories:
        for dname, directive, extra_files in directives:
            name = f"cat-{cname}-{dname}"
            files = {".htaccess": directive}
            files.update(extra_files)
            requests = [("GET", f"/{name}/file.txt", None, {})]
            if dname == "header":
                requests[0] = ("GET", f"/{name}/file.txt", None, {"x-cat": None})
            if dname == "directoryindex" or dname == "options_indexes":
                requests[0] = ("GET", f"/{name}/", None, {})
            if dname == "limit_post":
                requests.append(("POST", f"/{name}/file.txt", None, {}))
            out.append(
                {
                    "name": name,
                    "dir": name,
                    "files": files,
                    "config": [
                        f'<Directory "{{dir}}">',
                        f"    AllowOverride {cmode}",
                        "</Directory>",
                    ],
                    "status_equiv": {"POST": {200, 405}},
                    "requests": requests,
                }
            )

    # <Limit>/<LimitExcept> method mapping and nesting.  Allowed static
    # non-GET methods use the documented 200/405 divergence.
    methods = ["GET", "HEAD", "POST", "PUT", "OPTIONS", "DELETE"]
    for kind in ("limit", "limitexcept"):
        for method in methods:
            name = f"method-{kind}-{method.lower()}"
            directive = (
                f"<{ 'Limit' if kind == 'limit' else 'LimitExcept' } {method}>\n"
                "    Require all denied\n"
                f"</{ 'Limit' if kind == 'limit' else 'LimitExcept' }>\n"
            )
            out.append(
                {
                    "name": name,
                    "dir": name,
                    "files": {".htaccess": directive},
                    "config": [
                        f'<Directory "{{dir}}">',
                        "    AllowOverride All",
                        "</Directory>",
                    ],
                    "status_equiv": {
                        "POST": {200, 405},
                        "PUT": {200, 405},
                        "OPTIONS": {200, 405},
                        "DELETE": {200, 405},
                    },
                    "requests": [
                        (method, f"/{name}/file.txt", None, {}),
                        ("GET", f"/{name}/file.txt", None, {}),
                    ],
                }
            )

    # AuthMerging across parent/child directory levels.
    for merging in ("Off", "And", "Or"):
        for child_req in ("Require local", "Require all granted", "Require all denied"):
            tag = child_req.split()[-1].replace(" ", "_")
            name = f"authmerge-{merging.lower()}-{tag}"
            out.append(
                {
                    "name": name,
                    "dir": name,
                    "files": {"child/file.txt": "child\n"},
                    "config": [
                        f'<Directory "{{dir}}">',
                        "    Require ip 10.0.0.0/8",
                        "</Directory>",
                        f'<Directory "{{dir}}/child">',
                        f"    AuthMerging {merging}",
                        f"    {child_req}",
                        "</Directory>",
                    ],
                    "requests": [("GET", f"/{name}/child/file.txt", None, {})],
                }
            )

    # Satisfy Any/All with the two legacy orders and both host decisions.
    for order in ("allow,deny", "deny,allow"):
        for satisfy in ("Any", "All"):
            for host in ("Allow from all", "Deny from all"):
                tag = host.replace(" ", "_")
                name = f"satisfy-{order.replace(',', '-')}-{satisfy.lower()}-{tag}"
                out.append(
                    {
                        "name": name,
                        "dir": name,
                        "config": [
                            f'<Directory "{{dir}}">',
                            "    Require ip 127.0.0.1",
                            f"    Order {order}",
                            f"    {host}",
                            f"    Satisfy {satisfy}",
                            "</Directory>",
                        ],
                        "requests": [("GET", f"/{name}/file.txt", None, {})],
                    }
                )

    return out


CASES.extend(generated_cases())

# Apache 2.4.69 accepts an unsupported Files section nested inside request-time
# If, but ordinary direct requests do not evaluate the nested policy. Vapache
# rejects that construct fail-closed; the rejection belongs to
# config_validity.py rather than this runtime-equivalence matrix. The
# .htaccess parser has a direct regression test for the same rule.


def section_override_cases():
    """Apache-oracle matrix for every supported access-file section.

    Each wrapper is exercised with a child-only list entry, its exact command
    entry, Nonfatal=Override, AuthConfig, FileInfo and Limit. Prerequisite
    wrappers for Else/ElseIf/RequireNone are listed independently so the case
    reaches the target command rather than failing at its enclosing syntax.
    """
    specs = [
        ("files", '<Files "file.txt">\n    Require all granted\n</Files>\n', "<Files", []),
        ("filesmatch", '<FilesMatch "^file\\.txt$">\n    Require all granted\n</FilesMatch>\n', "<FilesMatch", []),
        ("if", '<If "true">\n    Require all granted\n</If>\n', "<If", []),
        ("iffile", '<IfFile "missing-section-matrix-flag">\n    Require all granted\n</IfFile>\n', "<IfFile", []),
        (
            "elseif",
            '<If "false">\n    Require all denied\n</If>\n'
            '<ElseIf "true">\n    Require all granted\n</ElseIf>\n',
            "<ElseIf",
            ["<If"],
        ),
        (
            "else",
            '<If "false">\n    Require all denied\n</If>\n'
            '<Else>\n    Require all granted\n</Else>\n',
            "<Else",
            ["<If"],
        ),
        ("ifmodule", '<IfModule core_module>\n    Require all granted\n</IfModule>\n', "<IfModule", []),
        ("ifdefine", '<IfDefine !SECTION_MATRIX_MISSING>\n    Require all granted\n</IfDefine>\n', "<IfDefine", []),
        ("ifdirective", '<IfDirective Require>\n    Require all granted\n</IfDirective>\n', "<IfDirective", []),
        ("ifsection", '<IfSection Files>\n    Require all granted\n</IfSection>\n', "<IfSection", []),
        ("ifversion", '<IfVersion >= 2.4>\n    Require all granted\n</IfVersion>\n', "<IfVersion", []),
        ("requireall", '<RequireAll>\n    Require all granted\n</RequireAll>\n', "<RequireAll", []),
        ("requireany", '<RequireAny>\n    Require all granted\n</RequireAny>\n', "<RequireAny", []),
        (
            "requirenone",
            '<RequireAll>\n    Require all granted\n    <RequireNone>\n'
            '        Require ip 192.0.2.1\n    </RequireNone>\n</RequireAll>\n',
            "<RequireNone",
            ["<RequireAll"],
        ),
        ("limit", '<Limit GET>\n    Require all granted\n</Limit>\n', "<Limit", []),
        ("limitexcept", '<LimitExcept POST>\n    Require all granted\n</LimitExcept>\n', "<LimitExcept", []),
    ]

    def list_line(commands):
        values = [f'"{command}"' for command in commands] + ["Require"]
        return "    AllowOverrideList " + " ".join(values)

    out = []
    for tag, access_file, command, prerequisites in specs:
        variants = [
            ("child-only", ["    AllowOverride None", list_line(prerequisites)]),
            (
                "exact",
                ["    AllowOverride None", list_line([*prerequisites, command])],
            ),
            (
                "nonfatal",
                [
                    "    AllowOverride None Nonfatal=Override",
                    list_line(prerequisites),
                ],
            ),
            ("authconfig", ["    AllowOverride AuthConfig"]),
            (
                "fileinfo",
                ["    AllowOverride FileInfo", list_line(prerequisites)],
            ),
            ("limit-category", ["    AllowOverride Limit", list_line(prerequisites)]),
        ]
        for variant, override_lines in variants:
            name = f"section-gate-{tag}-{variant}"
            out.append(
                {
                    "name": name,
                    "dir": name.replace("-", "_"),
                    "files": {".htaccess": access_file},
                    "config": [f'<Directory "{{dir}}">', *override_lines, "</Directory>"],
                    "requests": [("GET", f"/{name.replace('-', '_')}/file.txt", None, {})],
                }
            )
    return out


CASES.extend(section_override_cases())


# Cases derived directly from Apache 2.4.69's execute-on-read containers,
# mod_authz_core/mod_authz_host providers and mod_setenvif/mod_env hook order.
CASES.extend(
    [
        {
            "name": "core-ifmodule-prelinked-denial",
            "dir": "src_ifmodule_core",
            "config": [
                "<IfModule core_module>",
                f'    <Directory "{{dir}}">',
                "        Require all denied",
                "    </Directory>",
                "</IfModule>",
            ],
            "requests": [("GET", "/src_ifmodule_core/file.txt", None, {})],
        },
        {
            "name": "ifdirective-false-skips-grant",
            "dir": "src_ifdirective_false",
            "config": [
                f'<Directory "{{dir}}">',
                "    Require all denied",
                "    <IfDirective DefinitelyMissingDirective>",
                "        Require all granted",
                "    </IfDirective>",
                "</Directory>",
            ],
            "requests": [("GET", "/src_ifdirective_false/file.txt", None, {})],
        },
        {
            "name": "ifdirective-true-applies-grant",
            "dir": "src_ifdirective_true",
            "config": [
                f'<Directory "{{dir}}">',
                "    Require all denied",
                "    <IfDirective Require>",
                "        Require all granted",
                "    </IfDirective>",
                "</Directory>",
            ],
            "requests": [("GET", "/src_ifdirective_true/file.txt", None, {})],
        },
        {
            "name": "ifsection-false-skips-grant",
            "dir": "src_ifsection_false",
            "config": [
                f'<Directory "{{dir}}">',
                "    Require all denied",
                "    <IfSection DefinitelyMissingSection>",
                "        Require all granted",
                "    </IfSection>",
                "</Directory>",
            ],
            "requests": [("GET", "/src_ifsection_false/file.txt", None, {})],
        },
        {
            "name": "iffile-is-frozen-at-config-read",
            "dir": "src_iffile_frozen",
            "config": [
                f'<Directory "{{dir}}">',
                "    Require all denied",
                '    <IfFile "{dir}/late.flag">',
                "        Require all granted",
                "    </IfFile>",
                "</Directory>",
            ],
            "post_start_files": {"late.flag": "late\n"},
            "requests": [("GET", "/src_iffile_frozen/file.txt", None, {})],
        },
        {
            "name": "setenv-is-not-visible-to-require-env",
            "dir": "src_setenv_late",
            "config": [
                f'<Directory "{{dir}}">',
                "    SetEnv LATE_ALLOW yes",
                "    Require env LATE_ALLOW",
                "</Directory>",
            ],
            "requests": [("GET", "/src_setenv_late/file.txt", None, {})],
        },
        {
            "name": "unsetenv-is-not-visible-to-require-env",
            "dir": "src_unsetenv_late",
            "config": [
                f'<Directory "{{dir}}">',
                "    SetEnvIf X-Block yes BLOCK_ME",
                "    UnsetEnv BLOCK_ME",
                "    <RequireAll>",
                "        Require all granted",
                "        Require not env BLOCK_ME",
                "    </RequireAll>",
                "</Directory>",
            ],
            "requests": [
                ("GET", "/src_unsetenv_late/file.txt", {"X-Block": "yes"}, {})
            ],
        },
        {
            "name": "setenvif-remote-addr-is-not-an-empty-header",
            "dir": "src_setenvif_remote_addr",
            "config": [
                f'<Directory "{{dir}}">',
                '    SetEnvIf Remote_Addr "^$" EMPTY_REMOTE',
                "    Require env EMPTY_REMOTE",
                "</Directory>",
            ],
            "requests": [("GET", "/src_setenvif_remote_addr/file.txt", None, {})],
        },
        {
            "name": "setenvif-bare-action-has-value-one",
            "dir": "src_setenvif_default_value",
            "config": [
                f'<Directory "{{dir}}">',
                "    SetEnvIf X-Gate yes GATE",
                "    Require expr \"env('GATE') == '1'\"",
                "</Directory>",
            ],
            "requests": [
                ("GET", "/src_setenvif_default_value/file.txt", {"X-Gate": "yes"}, {})
            ],
        },
        {
            "name": "require-env-tests-every-operand",
            "dir": "src_require_env_operands",
            "config": [
                f'<Directory "{{dir}}">',
                "    SetEnvIf X-Block yes SECOND_BLOCK",
                "    <RequireAll>",
                "        Require all granted",
                "        Require not env FIRST_BLOCK SECOND_BLOCK",
                "    </RequireAll>",
                "</Directory>",
            ],
            "requests": [
                ("GET", "/src_require_env_operands/file.txt", {"X-Block": "yes"}, {})
            ],
        },
        {
            "name": "require-env-name-is-case-insensitive",
            "dir": "src_require_env_case",
            "config": [
                f'<Directory "{{dir}}">',
                '    SetEnvIf Remote_Addr "^127\\." UPPER_GATE',
                "    Require env upper_gate",
                "</Directory>",
            ],
            "requests": [("GET", "/src_require_env_case/file.txt", None, {})],
        },
        {
            "name": "negated-require-env-name-is-case-insensitive",
            "dir": "src_require_env_case_negated",
            "config": [
                f'<Directory "{{dir}}">',
                '    SetEnvIf Remote_Addr "^127\\." UPPER_BLOCK',
                "    <RequireAll>",
                "        Require all granted",
                "        Require not env upper_block",
                "    </RequireAll>",
                "</Directory>",
            ],
            "requests": [
                ("GET", "/src_require_env_case_negated/file.txt", None, {})
            ],
        },
        {
            "name": "require-host-leading-dot-excludes-bare-host",
            "dir": "src_require_host_dot",
            "config": [
                f'<Directory "{{dir}}">',
                "    Require host .localhost",
                "</Directory>",
            ],
            "requests": [("GET", "/src_require_host_dot/file.txt", None, {})],
        },
        {
            "name": "htaccess-ifmodule-missing-skips-grant",
            "dir": "src_htaccess_ifmodule_missing",
            "files": {
                ".htaccess": (
                    "Require all denied\n"
                    "<IfModule definitely_missing_module>\n"
                    "    Require all granted\n"
                    "</IfModule>\n"
                )
            },
            "config": [
                f'<Directory "{{dir}}">',
                "    AllowOverride All",
                "</Directory>",
            ],
            "requests": [
                ("GET", "/src_htaccess_ifmodule_missing/file.txt", None, {})
            ],
        },
        {
            "name": "ifdirective-unloaded-module-skips-grant",
            "dir": "src_ifdirective_unloaded",
            "config": [
                f'<Directory "{{dir}}">',
                "    Require all denied",
                "    <IfDirective SSLProtocol>",
                "        Require all granted",
                "    </IfDirective>",
                "</Directory>",
            ],
            "requests": [("GET", "/src_ifdirective_unloaded/file.txt", None, {})],
        },
        {
            "name": "ifversion-false-skips-grant",
            "dir": "src_ifversion_false",
            "config": [
                f'<Directory "{{dir}}">',
                "    Require all denied",
                "    <IfVersion 99.0>",
                "        Require all granted",
                "    </IfVersion>",
                "</Directory>",
            ],
            "requests": [("GET", "/src_ifversion_false/file.txt", None, {})],
        },
        {
            "name": "setenvif-chains-through-prior-environment",
            "dir": "src_setenvif_chain",
            "config": [
                f'<Directory "{{dir}}">',
                "    SetEnvIf X-First yes FIRST=token",
                "    SetEnvIf FIRST ^token$ CHAINED",
                "    <RequireAll>",
                "        Require all granted",
                "        Require not env CHAINED",
                "    </RequireAll>",
                "</Directory>",
            ],
            "requests": [
                ("GET", "/src_setenvif_chain/file.txt", {"X-First": "yes"}, {})
            ],
        },
        {
            "name": "setenvif-expands-captures-before-authz",
            "dir": "src_setenvif_capture",
            "config": [
                f'<Directory "{{dir}}">',
                '    SetEnvIf X-User "^(.+)$" BLOCKED=$1',
                "    <RequireAll>",
                "        Require all granted",
                '        Require not expr "env(\'BLOCKED\') == \'alice\'"',
                "    </RequireAll>",
                "</Directory>",
            ],
            "requests": [
                ("GET", "/src_setenvif_capture/file.txt", {"X-User": "alice"}, {})
            ],
        },
        {
            "name": "setenvif-request-protocol-is-special",
            "dir": "src_setenvif_protocol",
            "config": [
                f'<Directory "{{dir}}">',
                '    SetEnvIf Request_Protocol "^$" EMPTY_PROTOCOL',
                "    Require env EMPTY_PROTOCOL",
                "</Directory>",
            ],
            "requests": [("GET", "/src_setenvif_protocol/file.txt", None, {})],
        },
        {
            "name": "require-host-expands-string-expression",
            "dir": "src_require_host_expr",
            "config": [
                f'<Directory "{{dir}}">',
                "    <RequireAll>",
                "        Require all granted",
                '        Require not host "%{HTTP_HOST}"',
                "    </RequireAll>",
                "</Directory>",
            ],
            "requests": [
                ("GET", "/src_require_host_expr/file.txt", {"Host": "localhost"}, {})
            ],
        },
        {
            "name": "setenv-is-not-visible-to-if-grant",
            "dir": "src_setenv_if_late",
            "config": [
                f'<Directory "{{dir}}">',
                "    SetEnv LATE_ALLOW yes",
                "    Require all denied",
                '    <If "env(\'LATE_ALLOW\') == \'yes\'">',
                "        Require all granted",
                "    </If>",
                "</Directory>",
            ],
            "requests": [("GET", "/src_setenv_if_late/file.txt", None, {})],
        },
        {
            "name": "directory-rewrite-env-authz-phase",
            "dir": "src_dir_rewrite_env",
            "config": [
                f'<Directory "{{dir}}">',
                "    RewriteEngine On",
                "    RewriteRule ^ - [E=EARLY_ALLOW:yes]",
                "    Require env EARLY_ALLOW",
                "</Directory>",
            ],
            "requests": [("GET", "/src_dir_rewrite_env/file.txt", None, {})],
        },
        {
            "name": "server-rewrite-env-authz-phase",
            "dir": "src_server_rewrite_env",
            "config": [
                "RewriteEngine On",
                "RewriteRule ^/src_server_rewrite_env/ - [E=EARLY_ALLOW:yes]",
                f'<Directory "{{dir}}">',
                "    Require env EARLY_ALLOW",
                "</Directory>",
            ],
            "requests": [("GET", "/src_server_rewrite_env/file.txt", None, {})],
        },
        {
            "name": "symlink-content-policy-keeps-url-identity",
            "dir": "src_symlink_content_identity",
            "files": {"target/data.bin": "content\n"},
            "symlinks": {"public/link.bin": "../target/data.bin"},
            "config": [
                f'<Directory "{{dir}}/public">',
                "    ForceType text/plain",
                "</Directory>",
                f'<Directory "{{dir}}/target">',
                "    ForceType application/octet-stream",
                "</Directory>",
            ],
            "requests": [
                (
                    "GET",
                    "/src_symlink_content_identity/public/link.bin",
                    None,
                    {"content-type": None},
                )
            ],
        },
        {
            "name": "symlink-environment-keeps-url-identity",
            "dir": "src_symlink_environment_identity",
            "files": {"target/data.txt": "content\n"},
            "symlinks": {"public/link.txt": "../target/data.txt"},
            "config": [
                f'<Directory "{{dir}}/public">',
                "    SetEnvIf X-Gate ^yes$ SHARED=url",
                "</Directory>",
                f'<Directory "{{dir}}/target">',
                "    SetEnvIf X-Gate ^yes$ SHARED=target",
                '    Require expr "env(\'SHARED\') == \'url\'"',
                "</Directory>",
            ],
            "requests": [
                (
                    "GET",
                    "/src_symlink_environment_identity/public/link.txt",
                    {"X-Gate": "yes"},
                    {},
                )
            ],
        },
    ]
)


def random_cases(count: int, seed: int):
    """Deterministic randomized matrix over security-relevant merge shapes."""
    rng = random.Random(seed)
    require_variants = [
        "Require all granted",
        "Require all denied",
        "Require local",
        "Require ip 10.0.0.0/8",
        "<RequireAll>\n        Require ip 127.0.0.1\n        Require local\n    </RequireAll>",
        "<RequireAny>\n        Require ip 10.0.0.0/8\n        Require local\n    </RequireAny>",
        "<RequireAll>\n        Require all granted\n        <RequireNone>\n            Require ip 127.0.0.1\n        </RequireNone>\n    </RequireAll>",
    ]
    out = []
    for i in range(count):
        name = f"rnd-{seed}-{i}"
        d = f"rnd_{seed}_{i}"
        files = {}
        config = []
        req = rng.choice(require_variants)
        config.append(f'<Directory "{{dir}}">')
        config.append("    " + req.replace("\n", "\n    "))
        # Sometimes add a method-limited denial for GET/HEAD.
        if rng.random() < 0.25:
            config.append("    <Limit GET HEAD>")
            config.append("        " + rng.choice(["Require all denied", "Require local"]))
            config.append("    </Limit>")
        # Sometimes a Files rule with wildcard.
        if rng.random() < 0.35:
            config.append('    <Files "secret*">')
            config.append("        " + rng.choice(["Require all denied", "Require all granted"]))
            config.append("    </Files>")
            files["secret1.txt"] = "secret1\n"
        # Sometimes a conditional denial/grant.
        if rng.random() < 0.30:
            config.append('    <If "%{HTTP:X-Random} == \'yes\'">')
            config.append("        " + rng.choice(["Require all denied", "Require all granted"]))
            config.append("    </If>")
        config.append("</Directory>")
        # Sometimes a child directory with separate auth policy.
        if rng.random() < 0.45:
            child_req = rng.choice(require_variants)
            merge = rng.choice(["Off", "And", "Or"])
            config += [
                f'<Directory "{{dir}}/child">',
                f"    AuthMerging {merge}",
                "    " + child_req.replace("\n", "\n    "),
                "</Directory>",
            ]
            files["child/file.txt"] = "child\n"
        # Sometimes a Location rule; it must win over Directory.
        if rng.random() < 0.30:
            loc_req = rng.choice(["Require all granted", "Require all denied", "Require local"])
            config += [
                f'<Location "/{d}/">',
                "    " + loc_req,
                "</Location>",
            ]
        # Sometimes .htaccess gating, including exact and child-only
        # AllowOverrideList section entries. This keeps randomized coverage on
        # the P18 seam instead of limiting it to broad category modes.
        if rng.random() < 0.35:
            mode = rng.choice(
                ["None", "AuthConfig", "All", "ListRequire", "ListFiles"]
            )
            config.append(f'<Directory "{{dir}}">')
            if mode == "ListRequire":
                config += [
                    "    AllowOverride None",
                    "    AllowOverrideList Require",
                ]
                files[".htaccess"] = rng.choice(
                    [
                        "Require all denied\n",
                        '<Files "file.txt">\n    Require all granted\n</Files>\n',
                    ]
                )
            elif mode == "ListFiles":
                config += [
                    "    AllowOverride None",
                    '    AllowOverrideList "<Files" Require',
                ]
                files[".htaccess"] = rng.choice(
                    [
                        '<Files "file.txt">\n    Require all denied\n</Files>\n',
                        '<FilesMatch "^file\\.txt$">\n    Require all denied\n</FilesMatch>\n',
                    ]
                )
            else:
                config.append(f"    AllowOverride {mode}")
            config.append("</Directory>")
            if mode not in ("None", "ListRequire", "ListFiles"):
                if rng.random() < 0.3:
                    files[".htaccess"] = (
                        '<If "%{HTTP:X-Random} == \'yes\'">\n'
                        "    " + rng.choice(["Require all denied", "Require all granted"]) + "\n"
                        "</If>\n"
                    )
                else:
                    files[".htaccess"] = rng.choice(["Require all denied", "Require all granted"]) + "\n"
        requests = [
            ("GET", f"/{d}/file.txt", None, {}),
            ("HEAD", f"/{d}/file.txt", None, {}),
            ("GET", f"/{d}/file.txt", {"X-Random": "yes"}, {}),
        ]
        if "secret1.txt" in files:
            requests.append(("GET", f"/{d}/secret1.txt", None, {}))
        if "child/file.txt" in files:
            requests.append(("GET", f"/{d}/child/file.txt", None, {}))
        out.append(
            {
                "name": name,
                "dir": d,
                "files": files,
                "config": config,
                "requests": requests,
            }
        )
    return out


def stateful_access_cases(count: int, seed: int):
    """Generate access-file parser histories, including invalid transitions.

    Unlike ``random_cases``, these cases deliberately model an open-section
    stack and mutate it: balanced nesting, a close of the wrong stack entry,
    and EOF with live entries.  The remaining states cover duplicate
    AllowOverride ordering and every Nonfatal behavior (the default None plus
    Override, Unknown and All).  Apache remains the result oracle.
    """
    rng = random.Random(seed)
    out = []
    for i in range(count):
        name = f"stateful-{seed}-{i}"
        directory = f"stateful_{seed}_{i}"
        state = i % 9
        wrapper = rng.choice(
            [
                ('<Files "file.txt">', "</Files>"),
                ('<FilesMatch "^file\\.txt$">', "</FilesMatch>"),
            ]
        )
        condition = rng.choice(['<If "true">', '<If "%{HTTP:X-State} == \'yes\'">'])
        headers = {"X-State": "yes"}

        if state == 0:
            # Push If -> Files -> RequireAll -> RequireNone, then pop in the
            # exact reverse order. This exercises both parser stack state and
            # nested authz state in one access file.
            access = (
                f"{condition}\n"
                f"    {wrapper[0]}\n"
                "        <RequireAll>\n"
                "            Require all granted\n"
                "            <RequireNone>\n"
                "                Require ip 192.0.2.1\n"
                "            </RequireNone>\n"
                "        </RequireAll>\n"
                f"    {wrapper[1]}\n"
                "</If>\n"
            )
            config = [
                '<Directory "{dir}">',
                "    AllowOverride AuthConfig",
                "</Directory>",
            ]
        elif state == 1:
            # Pop If while Files is still the live top-of-stack entry.
            access = (
                f"{condition}\n    {wrapper[0]}\n"
                "        Require all denied\n"
                "</If>\n"
                f"{wrapper[1]}\n"
            )
            config = [
                '<Directory "{dir}">',
                "    AllowOverride AuthConfig",
                "</Directory>",
            ]
        elif state == 2:
            # End-of-file with both wrapper entries still live.
            access = (
                f"{condition}\n    {wrapper[0]}\n"
                "        Require all denied\n"
            )
            config = [
                '<Directory "{dir}">',
                "    AllowOverride AuthConfig",
                "</Directory>",
            ]
        elif state == 3:
            access = "Require all denied\n"
            config = [
                '<Directory "{dir}">',
                "    AllowOverride None",
                "    AllowOverride AuthConfig",
                "</Directory>",
            ]
        elif state == 4:
            access = "Require all denied\n"
            config = [
                '<Directory "{dir}">',
                "    AllowOverride AuthConfig",
                "    AllowOverride None",
                "</Directory>",
            ]
        elif state == 5:
            # Nonfatal=None is represented by omitting the option.
            access = "Options +Indexes\nRequire all denied\n"
            config = [
                '<Directory "{dir}">',
                "    AllowOverride AuthConfig",
                "</Directory>",
            ]
        elif state == 6:
            access = "Options +Indexes\nRequire all denied\n"
            config = [
                '<Directory "{dir}">',
                "    AllowOverride AuthConfig Nonfatal=Override",
                "</Directory>",
            ]
        elif state == 7:
            access = "DefinitelyNotAStatefulDirective on\nRequire all denied\n"
            config = [
                '<Directory "{dir}">',
                "    AllowOverride AuthConfig Nonfatal=Unknown",
                "</Directory>",
            ]
        else:
            access = (
                "Options +Indexes\n"
                "DefinitelyNotAStatefulDirective on\n"
                "Require all denied\n"
            )
            config = [
                '<Directory "{dir}">',
                "    AllowOverride AuthConfig Nonfatal=All",
                "</Directory>",
            ]

        out.append(
            {
                "name": name,
                "dir": directory,
                "files": {".htaccess": access},
                "config": config,
                "requests": [
                    ("GET", f"/{directory}/file.txt", headers, {}),
                    ("HEAD", f"/{directory}/file.txt", headers, {}),
                ],
            }
        )
    return out


def expand_config(case: dict):
    d = str(case_dir(case))
    return [line.replace("{dir}", d) for line in case.get("config", [])]


def run_case(case: dict, verbose: bool) -> list[str]:
    problems = []
    for method, path, headers, compare in case.get("requests", []):
        try:
            a = request(AP_PORT, method, path, headers)
            v = request(VP_PORT, method, path, headers)
        except Exception as e:
            problems.append(f"{method} {path}: request failed: {e}")
            continue
        if verbose:
            print(
                f"  {method} {path} -> apache {a[0]} vapache {v[0]}"
            )
            for hname in compare:
                print(
                    f"      {hname}: apache={a[1].get(hname.lower())!r} "
                    f"vapache={v[1].get(hname.lower())!r}"
                )
        if a[0] != v[0]:
            equiv = case.get("status_equiv", {}).get(method, set())
            if not ({a[0], v[0]} <= equiv):
                problems.append(
                    f"{method} {path}: status apache={a[0]} vapache={v[0]}"
                )
        for name, expected in compare.items():
            av = a[1].get(name.lower())
            vv = v[1].get(name.lower())
            if av != vv:
                problems.append(
                    f"{method} {path}: header {name} apache={av!r} vapache={vv!r}"
                )
            elif expected is not None and av != expected:
                problems.append(
                    f"{method} {path}: header {name} both={av!r}, expected {expected!r}"
                )
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--random", type=int, default=0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--stateful", type=int, default=0)
    ap.add_argument("--stateful-seed", type=int, default=1818)
    args = ap.parse_args()
    if args.random:
        CASES.extend(random_cases(args.random, args.seed))
    if args.stateful:
        CASES.extend(stateful_access_cases(args.stateful, args.stateful_seed))
    if args.only:
        CASES[:] = [c for c in CASES if re.search(args.only, c["name"], re.I)]

    if not VAPACHED.exists():
        sys.exit(f"missing {VAPACHED}; cargo build --release first")
    if not Path(APACHE).exists():
        sys.exit(f"missing Apache httpd at {APACHE}")

    try:
        make_fixture()
        for case in CASES:
            make_case(case)
        # Expand every case config after the directories exist.
        for case in CASES:
            case["config"] = expand_config(case)

        acfg = BASE / "apache" / "httpd.conf"
        vcfg = BASE / "vapache-httpd.conf"
        acfg.write_text(base_config(AP_PORT, True))
        vcfg.write_text(base_config(VP_PORT, False))
        start_server(
            [APACHE, "-f", str(acfg), "-DFOREGROUND"],
            BASE / "logs" / "apache.out",
        )
        start_server(
            [str(VAPACHED), "-f", str(vcfg), "-DFOREGROUND"],
            BASE / "logs" / "vapache.out",
        )
        if not wait_port(AP_PORT) or not wait_port(VP_PORT):
            print("server failed to start")
            for name in ("apache", "vapache"):
                p = BASE / "logs" / f"{name}.out"
                if p.exists():
                    print(p.read_text()[-8000:])
            return 1

        # EXEC_ON_READ sections are fixed while each configuration is parsed.
        # Create these probes only after both servers have completed startup.
        for case in CASES:
            for rel, content in case.get("post_start_files", {}).items():
                case_file(case, rel, content)

        failures = 0
        for case in CASES:
            problems = run_case(case, args.verbose)
            if problems and case.get("known_divergence"):
                print(f"KNOWN {case['name']}: {case['known_divergence']}")
                for p in problems:
                    print(f"     {p}")
            elif problems:
                failures += 1
                print(f"FAIL {case['name']}")
                for p in problems:
                    print(f"     {p}")
            else:
                print(f"ok   {case['name']}")

        if failures:
            print(f"\n{failures} case(s) diverged")
        else:
            print(f"\nall {len(CASES)} cases agree")
        print(f"tree: {BASE}")
        return 1 if failures else 0
    finally:
        stop_servers()
        if os.environ.get("KEEP_TREE") != "1":
            shutil.rmtree(BASE, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
