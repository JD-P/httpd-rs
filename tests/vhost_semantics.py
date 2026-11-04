#!/usr/bin/env python3
"""Differential multi-vhost isolation and reload checks.

Apache is the semantic oracle.  The matrix deliberately puts main-server
sections after virtual hosts: Apache merges main-server policy before the
selected virtual host regardless of lexical file order.  It also exercises
name/address selection, per-vhost mappings, includes and graceful reload.
"""

import argparse
import grp
import http.client
import http.server
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
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
BASE = Path(tempfile.mkdtemp(prefix="vapache-vhost-semantics-"))
AP_PORT = int(os.environ.get("VAPACHE_VHOST_AP_PORT", "18280"))
VP_PORT = int(os.environ.get("VAPACHE_VHOST_VP_PORT", "18281"))
SERVICE_USER = "www-data" if os.geteuid() == 0 else pwd.getpwuid(os.geteuid()).pw_name
SERVICE_GROUP = "www-data" if os.getegid() == 0 else grp.getgrgid(os.getegid()).gr_name
PROCS = []
BACKENDS = []
GLOBAL_BACKEND_PORT = 0
VHOST_BACKEND_PORT = 0

MODULES = [
    "mpm_event_module",
    "mime_module",
    "dir_module",
    "alias_module",
    "authz_core_module",
    "authz_host_module",
    "headers_module",
    "proxy_module",
    "proxy_http_module",
    "rewrite_module",
]


class BackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = (self.server.marker + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


def start_backend(marker: str) -> int:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), BackendHandler)
    server.marker = marker
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    BACKENDS.append((server, thread))
    return server.server_address[1]


def write(path: Path, data: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)


def fixture():
    os.chmod(BASE, 0o755)
    for directory in ("logs", "apache", "include"):
        (BASE / directory).mkdir(parents=True, exist_ok=True)
    os.chmod(BASE / "logs", 0o755 if os.geteuid() == 0 else 0o777)
    for name in (
        "dir-grant",
        "dir-deny",
        "location-grant",
        "location-deny",
        "files-grant",
        "files-deny",
        "tenant-one",
        "tenant-two",
        "wildcard",
        "exact-name",
        "exact-address",
        "reload",
    ):
        root = BASE / "www" / name
        root.mkdir(parents=True, exist_ok=True)
        write(root / "index.html", f"{name}\n")
        write(root / "asset.txt", f"{name}-asset\n")
        write(root / "loc-asset.txt", f"{name}-loc-asset\n")
        write(root / "file-asset.txt", f"{name}-file-asset\n")
        write(root / "missing-error.txt", f"{name}-missing-error\n")
        write(root / "global-error.txt", f"{name}-global-error\n")
        write(root / "marker.vh", f"{name}-mime\n")
        write(root / "vhost-rewrite.txt", f"{name}-vhost-rewrite\n")
        write(root / "global-rewrite.txt", f"{name}-global-rewrite\n")
        write(root / "vhost-index.html", f"{name}-vhost-index\n")
        os.chmod(root, 0o755)
        os.chmod(root / "index.html", 0o644)
        os.chmod(root / "asset.txt", 0o644)
    write(BASE / "include" / "tenant-one.conf", "Header set X-Include tenant-one\n")
    write(BASE / "include" / "tenant-two.conf", "Header set X-Include tenant-two\n")
    write(BASE / "www" / "global-alias" / "asset.txt", "global-alias\n")
    write(BASE / "www" / "vhost-alias" / "asset.txt", "vhost-alias\n")
    for path in (BASE / "www" / "global-alias", BASE / "www" / "vhost-alias"):
        os.chmod(path, 0o755)
        os.chmod(path / "asset.txt", 0o644)


def q(path: Path) -> str:
    return f'"{path}"'


def vhost(port: int, name: str, root: str, body: list[str], address: str = "*") -> list[str]:
    docroot = BASE / "www" / root
    return [
        f"<VirtualHost {address}:{port}>",
        f"    ServerName {name}",
        f"    DocumentRoot {q(docroot)}",
        *[f"    {line}" if line else "" for line in body],
        "</VirtualHost>",
    ]


def config(port: int, apache: bool, generation: int) -> str:
    server_kind = "apache" if apache else "vapache"
    lines = []
    for module in MODULES:
        lines.append(f"LoadModule {module} {MODDIR}/mod_{module.replace('_module', '')}.so")
    if not apache:
        lines += [
            "VapacheCapability AccessFiles On",
            "VapacheCapability LegacyAuthz On",
        ]
    lines += [
        f"ServerRoot {q(BASE)}",
        f"Listen {port}",
        f"User {SERVICE_USER}",
        f"Group {SERVICE_GROUP}",
        f"PidFile {q(BASE / 'logs' / f'httpd-{port}.pid')}",
        f"ErrorLog {q(BASE / 'logs' / f'error-{port}.log')}",
        "LogLevel warn",
        'LogFormat "%v %U" isolation',
        f"CustomLog {q(BASE / 'logs' / f'{server_kind}-global-access.log')} isolation",
        "ServerName localhost",
        "TypesConfig /etc/mime.types",
        "DirectoryIndex index.html",
        "<Directory />",
        "    AllowOverride None",
        "    Require all denied",
        "</Directory>",
        f"ProxyPass /backend-before http://127.0.0.1:{GLOBAL_BACKEND_PORT}/",
        f"ProxyPassReverse /backend-before http://127.0.0.1:{GLOBAL_BACKEND_PORT}/",
        f"ProxyPassMatch ^/match-before http://127.0.0.1:{GLOBAL_BACKEND_PORT}/",
        "RewriteEngine On",
        "RewriteRule ^/inherited-rewrite$ /global-rewrite.txt [L]",
        "AddType application/x-global-vhost-test .vh",
        "ErrorDocument 404 /global-error.txt",
    ]

    lines += vhost(
        port,
        "dir-grant.test",
        "dir-grant",
        [f"<Directory {q(BASE / 'www' / 'dir-grant')}>", "    Require all granted", "</Directory>"],
    )
    lines += vhost(
        port,
        "dir-deny.test",
        "dir-deny",
        [f"<Directory {q(BASE / 'www' / 'dir-deny')}>", "    Require all denied", "</Directory>"],
    )
    lines += vhost(
        port,
        "location-grant.test",
        "location-grant",
        [
            f"<Directory {q(BASE / 'www' / 'location-grant')}>",
            "    Require all granted",
            "</Directory>",
            '<Location "/loc-asset.txt">',
            "    Require all granted",
            "</Location>",
        ],
    )
    lines += vhost(
        port,
        "location-deny.test",
        "location-deny",
        [
            f"<Directory {q(BASE / 'www' / 'location-deny')}>",
            "    Require all granted",
            "</Directory>",
            '<Location "/loc-asset.txt">',
            "    Require all denied",
            "</Location>",
        ],
    )
    lines += vhost(
        port,
        "files-grant.test",
        "files-grant",
        [
            f"<Directory {q(BASE / 'www' / 'files-grant')}>",
            "    Require all granted",
            '<Files "file-asset.txt">',
            "        Require all granted",
            "    </Files>",
            "</Directory>",
        ],
    )
    lines += vhost(
        port,
        "files-deny.test",
        "files-deny",
        [
            f"<Directory {q(BASE / 'www' / 'files-deny')}>",
            "    Require all granted",
            '<Files "file-asset.txt">',
            "        Require all denied",
            "    </Files>",
            "</Directory>",
        ],
    )

    common_one = [
        f"<Directory {q(BASE / 'www' / 'tenant-one')}>",
        "    Require all granted",
        "</Directory>",
        f"Alias /mapped {q(BASE / 'www' / 'vhost-alias')}",
        "Redirect 302 /jump https://vhost.example/destination",
        f"ProxyPass /backend-before http://127.0.0.1:{VHOST_BACKEND_PORT}/",
        f"ProxyPassReverse /backend-before http://127.0.0.1:{VHOST_BACKEND_PORT}/",
        f"ProxyPass /backend-after http://127.0.0.1:{VHOST_BACKEND_PORT}/",
        f"ProxyPassReverse /backend-after http://127.0.0.1:{VHOST_BACKEND_PORT}/",
        f"ProxyPassMatch ^/match-before http://127.0.0.1:{VHOST_BACKEND_PORT}/",
        f"ProxyPassMatch ^/match-after http://127.0.0.1:{VHOST_BACKEND_PORT}/",
        "RewriteEngine On",
        "RewriteOptions Inherit",
        "RewriteRule ^/inherited-rewrite$ /vhost-rewrite.txt [L]",
        "AddType application/x-tenant-one .vh",
        "DirectoryIndex vhost-index.html",
        "ErrorDocument 404 /missing-error.txt",
        f"<Directory {q(BASE / 'www' / 'vhost-alias')}>",
        "    Require all granted",
        "</Directory>",
        "Header set X-Tenant tenant-one",
        f"ErrorLog {q(BASE / 'logs' / f'{server_kind}-tenant-one-error.log')}",
        "LogLevel info",
        f"CustomLog {q(BASE / 'logs' / f'{server_kind}-tenant-one-access.log')} isolation",
        f"Include {q(BASE / 'include' / 'tenant-one.conf')}",
    ]
    common_two = [
        f"<Directory {q(BASE / 'www' / 'tenant-two')}>",
        "    Require all granted",
        "</Directory>",
        "Header set X-Tenant tenant-two",
        f"ErrorLog {q(BASE / 'logs' / f'{server_kind}-tenant-two-error.log')}",
        "LogLevel info",
        f"Include {q(BASE / 'include' / 'tenant-two.conf')}",
    ]
    lines += vhost(port, "tenant-one.test", "tenant-one", common_one)
    lines += vhost(port, "tenant-two.test", "tenant-two", common_two)

    lines += vhost(
        port,
        "wildcard-default.test",
        "wildcard",
        [f"<Directory {q(BASE / 'www' / 'wildcard')}>", "    Require all granted", "</Directory>"],
    )
    # A wildcard alias is declared before the exact name. Exact names must win.
    lines.insert(len(lines) - 1, "    ServerAlias *.selection.test")
    lines += vhost(
        port,
        "exact.selection.test",
        "exact-name",
        [f"<Directory {q(BASE / 'www' / 'exact-name')}>", "    Require all granted", "</Directory>"],
    )
    lines += vhost(
        port,
        "exact-address.test",
        "exact-address",
        [f"<Directory {q(BASE / 'www' / 'exact-address')}>", "    Require all granted", "</Directory>"],
        "127.0.0.2",
    )

    reload_auth = "granted" if generation == 2 else "denied"
    lines += vhost(
        port,
        "reload.test",
        "reload",
        [
            f"<Directory {q(BASE / 'www' / 'reload')}>",
            f"    Require all {reload_auth}",
            "</Directory>",
            f"Header set X-Generation {generation}",
        ],
    )

    # These main-server sections intentionally occur after all vhosts. Apache
    # still applies them before the selected vhost's corresponding sections.
    lines += [
        f"<Directory {q(BASE / 'www' / 'dir-grant')}>",
        "    Require all denied",
        "</Directory>",
        f"<Directory {q(BASE / 'www' / 'dir-deny')}>",
        "    Require all granted",
        "</Directory>",
        '<Location "/loc-asset.txt">',
        "    Require all denied",
        "</Location>",
        '<Files "file-asset.txt">',
        "    Require all denied",
        "</Files>",
        f"Alias /mapped {q(BASE / 'www' / 'global-alias')}",
        "Redirect 302 /jump https://global.example/destination",
        f"ProxyPass /backend-after http://127.0.0.1:{GLOBAL_BACKEND_PORT}/",
        f"ProxyPassReverse /backend-after http://127.0.0.1:{GLOBAL_BACKEND_PORT}/",
        f"ProxyPassMatch ^/match-after http://127.0.0.1:{GLOBAL_BACKEND_PORT}/",
        f"<Directory {q(BASE / 'www' / 'global-alias')}>",
        "    Require all granted",
        "</Directory>",
    ]
    return "\n".join(lines) + "\n"


def start(command, log: Path):
    handle = open(log, "ab")
    process = subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
    PROCS.append((process, handle))
    return process


def wait_port(port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def request(port: int, host: str, path: str = "/", connect_host: str = "127.0.0.1"):
    connection = http.client.HTTPConnection(connect_host, port, timeout=5)
    try:
        connection.request("GET", path, headers={"Host": host, "Connection": "close"})
        response = connection.getresponse()
        body = response.read()
        headers = {}
        for key, value in response.getheaders():
            headers.setdefault(key.lower(), []).append(value)
        return response.status, headers, body
    finally:
        connection.close()


CASES = [
    ("directory main-before-vhost grant", "dir-grant.test", "/", 200, b"dir-grant\n", "127.0.0.1"),
    ("directory main-before-vhost deny", "dir-deny.test", "/", 403, None, "127.0.0.1"),
    ("location main-before-vhost grant", "location-grant.test", "/loc-asset.txt", 200, b"location-grant-loc-asset\n", "127.0.0.1"),
    ("location main-before-vhost deny", "location-deny.test", "/loc-asset.txt", 403, None, "127.0.0.1"),
    ("files main-before-vhost grant", "files-grant.test", "/file-asset.txt", 200, b"files-grant-file-asset\n", "127.0.0.1"),
    ("files main-before-vhost deny", "files-deny.test", "/file-asset.txt", 403, None, "127.0.0.1"),
    ("vhost DirectoryIndex overrides inherited index", "tenant-one.test", "/", 200, b"tenant-one-vhost-index\n", "127.0.0.1"),
    ("tenant two root", "tenant-two.test", "/", 200, b"tenant-two\n", "127.0.0.1"),
    ("per-vhost alias overrides inherited alias", "tenant-one.test", "/mapped/asset.txt", 200, b"vhost-alias\n", "127.0.0.1"),
    ("inherited global alias", "tenant-two.test", "/mapped/asset.txt", 200, b"global-alias\n", "127.0.0.1"),
    ("per-vhost redirect overrides inherited redirect", "tenant-one.test", "/jump", 302, None, "127.0.0.1"),
    ("inherited global redirect", "tenant-two.test", "/jump", 302, None, "127.0.0.1"),
    ("global proxy precedes vhost when declared earlier", "tenant-one.test", "/backend-before", 200, b"global-backend\n", "127.0.0.1"),
    ("global proxy precedes vhost when declared later", "tenant-one.test", "/backend-after", 200, b"global-backend\n", "127.0.0.1"),
    ("inherited earlier global proxy", "tenant-two.test", "/backend-before", 200, b"global-backend\n", "127.0.0.1"),
    ("inherited later global proxy", "tenant-two.test", "/backend-after", 200, b"global-backend\n", "127.0.0.1"),
    ("global regex proxy precedes earlier vhost", "tenant-one.test", "/match-before", 200, b"global-backend\n", "127.0.0.1"),
    ("global regex proxy precedes later vhost", "tenant-one.test", "/match-after", 200, b"global-backend\n", "127.0.0.1"),
    ("vhost rewrite runs before inherited rewrite", "tenant-one.test", "/inherited-rewrite", 200, b"tenant-one-vhost-rewrite\n", "127.0.0.1"),
    ("vhost MIME mapping overrides inherited mapping", "tenant-one.test", "/marker.vh", 200, b"tenant-one-mime\n", "127.0.0.1"),
    ("global MIME mapping is inherited", "tenant-two.test", "/marker.vh", 200, b"tenant-two-mime\n", "127.0.0.1"),
    ("vhost ErrorDocument overrides inherited document", "tenant-one.test", "/not-found", 404, b"tenant-one-missing-error\n", "127.0.0.1"),
    ("global ErrorDocument is inherited", "tenant-two.test", "/not-found-two", 404, b"tenant-two-global-error\n", "127.0.0.1"),
    ("wildcard name", "foo.selection.test", "/", 200, b"wildcard\n", "127.0.0.1"),
    # Apache keeps the first matching wildcard when it precedes a later exact
    # name in the same address bucket; Vapache intentionally mirrors it.
    ("earlier wildcard precedes later exact name", "exact.selection.test", "/", 200, b"wildcard\n", "127.0.0.1"),
    # The exact destination-address bucket wins before host-name matching.
    ("exact address bucket", "foo.selection.test", "/", 200, b"exact-address\n", "127.0.0.2"),
    ("host case and trailing dot", "TENANT-ONE.TEST.", "/", 200, b"tenant-one-vhost-index\n", "127.0.0.1"),
]


def compare_case(case, verbose: bool) -> list[str]:
    name, host, path, expected_status, expected_body, connect_host = case
    apache = request(AP_PORT, host, path, connect_host)
    vapache = request(VP_PORT, host, path, connect_host)
    problems = []
    if apache[0] != expected_status:
        problems.append(f"Apache status {apache[0]}, expected {expected_status}")
    if vapache[0] != apache[0]:
        problems.append(f"status Apache={apache[0]} Vapache={vapache[0]}")
    if expected_body is not None:
        if apache[2] != expected_body:
            problems.append(f"Apache body {apache[2]!r}, expected {expected_body!r}")
        if vapache[2] != apache[2]:
            problems.append(f"body Apache={apache[2]!r} Vapache={vapache[2]!r}")
    if 300 <= apache[0] < 400:
        if vapache[1].get("location") != apache[1].get("location"):
            problems.append(
                f"location Apache={apache[1].get('location')!r} Vapache={vapache[1].get('location')!r}"
            )
    if path.endswith(".vh"):
        expected_type = (
            "application/x-tenant-one"
            if host.lower().rstrip(".") == "tenant-one.test"
            else "application/x-global-vhost-test"
        )
        if apache[1].get("content-type") != [expected_type]:
            problems.append(
                f"Apache content-type {apache[1].get('content-type')!r}, expected {[expected_type]!r}"
            )
        if vapache[1].get("content-type") != apache[1].get("content-type"):
            problems.append(
                f"content-type Apache={apache[1].get('content-type')!r} "
                f"Vapache={vapache[1].get('content-type')!r}"
            )
    if host.lower().rstrip(".") in ("tenant-one.test", "tenant-two.test") and path == "/":
        for header in ("x-tenant", "x-include"):
            if vapache[1].get(header) != apache[1].get(header):
                problems.append(
                    f"{header} Apache={apache[1].get(header)!r} Vapache={vapache[1].get(header)!r}"
                )
    if verbose:
        print(f"     Apache={apache[0]} {apache[2]!r}; Vapache={vapache[0]} {vapache[2]!r}")
    return problems


def wait_generation(port: int, generation: str, timeout: float = 10.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = request(port, "reload.test")
            if last[1].get("x-generation") == [generation]:
                return last
        except OSError:
            pass
        time.sleep(0.05)
    return last


def stop():
    for process, handle in PROCS:
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
        handle.close()
    for server, thread in BACKENDS:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main() -> int:
    global GLOBAL_BACKEND_PORT, VHOST_BACKEND_PORT
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    if not VAPACHED.exists():
        sys.exit(f"missing {VAPACHED}; cargo build --release first")
    if not Path(APACHE).exists():
        sys.exit(f"missing Apache httpd at {APACHE}")
    try:
        GLOBAL_BACKEND_PORT = start_backend("global-backend")
        VHOST_BACKEND_PORT = start_backend("vhost-backend")
        fixture()
        apache_config = BASE / "apache" / "httpd.conf"
        vapache_config = BASE / "vapache-httpd.conf"
        write(apache_config, config(AP_PORT, True, 1))
        write(vapache_config, config(VP_PORT, False, 1))
        apache_process = start([APACHE, "-f", str(apache_config), "-DFOREGROUND"], BASE / "logs" / "apache.out")
        vapache_process = start([str(VAPACHED), "-f", str(vapache_config), "-DFOREGROUND"], BASE / "logs" / "vapache.out")
        if not wait_port(AP_PORT) or not wait_port(VP_PORT):
            print("server failed to start")
            for path in (BASE / "logs" / "apache.out", BASE / "logs" / "vapache.out"):
                if path.exists():
                    print(path.read_text()[-8000:])
            return 1

        failures = 0
        for case in CASES:
            problems = compare_case(case, args.verbose)
            if problems:
                failures += 1
                print(f"FAIL {case[0]}")
                for problem in problems:
                    print(f"     {problem}")
            else:
                print(f"ok   {case[0]}")

        for server_kind in ("apache", "vapache"):
            one = BASE / "logs" / f"{server_kind}-tenant-one-error.log"
            two = BASE / "logs" / f"{server_kind}-tenant-two-error.log"
            one_text = one.read_text(errors="replace") if one.exists() else ""
            two_text = two.read_text(errors="replace") if two.exists() else ""
            if (
                "not-found" not in one_text
                or "not-found-two" in one_text
                or "not-found-two" not in two_text
            ):
                failures += 1
                print(
                    f"FAIL {server_kind} per-vhost ErrorLog isolation "
                    f"tenant-one={one_text[-1000:]!r} tenant-two={two_text[-1000:]!r}"
                )
            else:
                print(f"ok   {server_kind} per-vhost ErrorLog isolation")

            global_access = BASE / "logs" / f"{server_kind}-global-access.log"
            one_access = BASE / "logs" / f"{server_kind}-tenant-one-access.log"
            global_access_text = (
                global_access.read_text(errors="replace") if global_access.exists() else ""
            )
            one_access_text = (
                one_access.read_text(errors="replace") if one_access.exists() else ""
            )
            if (
                "tenant-one.test" in global_access_text
                or "tenant-two.test" not in global_access_text
                or "tenant-one.test" not in one_access_text
                or "tenant-two.test" in one_access_text
            ):
                failures += 1
                print(
                    f"FAIL {server_kind} CustomLog override isolation "
                    f"global={global_access_text[-1000:]!r} tenant-one={one_access_text[-1000:]!r}"
                )
            else:
                print(f"ok   {server_kind} CustomLog override isolation")

        before_apache = request(AP_PORT, "reload.test")
        before_vapache = request(VP_PORT, "reload.test")
        if before_apache[0] != 403 or before_vapache[0] != 403:
            failures += 1
            print(f"FAIL reload initial policy Apache={before_apache[0]} Vapache={before_vapache[0]}")
        write(apache_config, config(AP_PORT, True, 2))
        write(vapache_config, config(VP_PORT, False, 2))
        os.kill(apache_process.pid, signal.SIGUSR1)
        os.kill(vapache_process.pid, signal.SIGHUP)
        after_apache = wait_generation(AP_PORT, "2")
        after_vapache = wait_generation(VP_PORT, "2")
        if not after_apache or not after_vapache or after_apache[0] != 200 or after_vapache[0] != 200:
            failures += 1
            print(f"FAIL graceful reload Apache={after_apache!r} Vapache={after_vapache!r}")
        elif after_apache[2] != after_vapache[2]:
            failures += 1
            print(f"FAIL graceful reload body Apache={after_apache[2]!r} Vapache={after_vapache[2]!r}")
        else:
            print("ok   graceful reload replaces vhost authorization generation")

        if failures:
            print(f"\n{failures} multi-vhost case(s) failed")
        else:
            print(f"\nall {len(CASES) + 5} multi-vhost cases agree")
        print(f"tree: {BASE}")
        return 1 if failures else 0
    finally:
        stop()
        if os.environ.get("KEEP_TREE") != "1":
            shutil.rmtree(BASE, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
