#!/usr/bin/env python3
"""End-to-end regressions for the pass-2 through pass-18 findings (F23-P18).

The suite starts fresh vapached instances in temporary trees and exercises
the exploit shapes from adversarial/findings.md: terminal rewrite/proxy authorization,
cache generations and CGI PATH_INFO, relative and capture-only regex aliases,
autoindex links, negated/environment Require providers, IndexIgnore,
DirectorySlash Off, UnsafePrefixStat re-rooting, header-selected cache
entries, .htaccess RequestHeader, CGI REMOTE_USER/AUTH_TYPE, multi-provider
<RequireNone>, regex alias file targets, address-bound virtual hosts,
IPv4-mapped peer canonicalization, ancestor access files above DocumentRoot,
overlapping alias roots, DirectoryIndex-bound cache targets, alias per-directory
rewrite bases, SetHandler/server-status cache classification, lossless cache
key bytes, ErrorDocument cache scoping, canonical REQUEST_URI identity,
access-file rewrite subjects above the mapping root, explicit-target
access-layer binding for symlinked mapping roots, and the pass-10
resolved-target/rewrite scope conjunction.

Usage:
    cargo build --release -p vapached
    python3 tests/adversarial_regressions.py -v
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import os
import grp
import pwd
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VAPACHED = Path(os.environ.get("VAPACHED", ROOT / "target" / "release" / "vapached"))

SERVICE_USER = "www-data" if os.geteuid() == 0 else pwd.getpwuid(os.geteuid()).pw_name
SERVICE_GROUP = "www-data" if os.getegid() == 0 else grp.getgrgid(os.getegid()).gr_name

VAPACHE_CAPABILITIES = f"""User {SERVICE_USER}
Group {SERVICE_GROUP}
VapacheCapability AbsoluteRequestTarget On
VapacheCapability AccessFiles On
VapacheCapability AutoIndex On
VapacheCapability Cgi On
VapacheCapability FastCgi On
VapacheCapability LegacyAuthz On
VapacheCapability RequestTrailers On
VapacheCapability RewriteProgram On
VapacheCapability ServerStatus On
VapacheCapability Trace On
VapacheCapability UnstableFastCgiPaths On
VapacheCapability MutableAuthFiles On
"""


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class Backend(BaseHTTPRequestHandler):
    hits = 0
    last_headers: dict[str, str] = {}

    def do_GET(self):
        Backend.hits += 1
        Backend.last_headers = dict(self.headers)
        body = b"WALLET-BACKEND-SECRET\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_vapached(base: Path, config: str, server_root: Path | None = None):
    logs = base / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    logs.chmod(0o777)
    config_path = base / "vp.conf"
    config_path.write_text(VAPACHE_CAPABILITIES + config)
    command = [str(VAPACHED)]
    if server_root is not None:
        command.extend(["-d", str(server_root)])
    command.extend(["-f", str(config_path), "-DFOREGROUND"])
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    port = next(
        int(line.split(":", 1)[1])
        for line in config.splitlines()
        if line.strip().startswith("Listen ")
    )
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return proc, config_path
        except OSError:
            time.sleep(0.05)
    output = b""
    if proc.stdout:
        output = proc.stdout.read()
    raise RuntimeError(
        f"vapached failed to start:\n{output.decode(errors='replace')}"
    )


def stop_vapached(proc) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)


class FastCgiMock:
    """Minimal FastCGI responder that reflects security-relevant parameters."""

    def __init__(self, path: Path):
        self.path = path
        self.listener: socket.socket | None = None
        self.stop_event = threading.Event()

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    @staticmethod
    def _record(kind: int, content: bytes) -> bytes:
        pad = (8 - len(content) % 8) % 8
        return (
            struct.pack(">BBHHBB", 1, kind, 1, len(content), pad, 0)
            + content
            + b"\0" * pad
        )

    @staticmethod
    def _params(data: bytes) -> dict[str, str]:
        out: dict[str, str] = {}
        i = 0
        while i < len(data):
            def length() -> int:
                nonlocal i
                if data[i] & 0x80:
                    n = struct.unpack(">I", data[i : i + 4])[0] & 0x7FFFFFFF
                    i += 4
                    return n
                n = data[i]
                i += 1
                return n

            nlen = length()
            vlen = length()
            name = data[i : i + nlen].decode("latin-1")
            i += nlen
            value = data[i : i + vlen].decode("latin-1")
            i += vlen
            out[name] = value
        return out

    def _connection(self, conn: socket.socket) -> None:
        params: dict[str, str] = {}
        try:
            while True:
                header = self._recv_exact(conn, 8)
                if header[0] != 1:
                    return
                kind = header[1]
                n = struct.unpack(">H", header[4:6])[0]
                pad = header[6]
                content = self._recv_exact(conn, n + pad)[:n]
                if kind == 4:
                    params.update(self._params(content))
                elif kind == 5 and not content:
                    query = params.get("QUERY_STRING", "")
                    payload = (
                        "Content-Type: text/plain\r\n"
                        "Cache-Control: max-age=600\r\n\r\n"
                        f"SECRET-FOR-{query}\n"
                        f"SCRIPT_FILENAME={params.get('SCRIPT_FILENAME', '')}\n"
                        f"SCRIPT_NAME={params.get('SCRIPT_NAME', '')}\n"
                        f"PATH_INFO={params.get('PATH_INFO', '')}\n"
                    ).encode("latin-1")
                    conn.sendall(
                        self._record(6, payload)
                        + self._record(6, b"")
                        + self._record(3, b"\0" * 8)
                    )
                    params = {}
        except EOFError:
            pass
        finally:
            conn.close()

    def _loop(self) -> None:
        assert self.listener is not None
        while not self.stop_event.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._connection, args=(conn,), daemon=True).start()

    def start(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        os.chmod(self.path, 0o777)
        self.listener.listen(16)
        self.listener.settimeout(0.2)
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError:
                pass
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


class TcpFastCgiMock(FastCgiMock):
    """TCP variant of the parameter-reflecting FastCGI oracle."""

    def __init__(self, port: int):
        super().__init__(Path("/nonexistent-vapache-tcp-fastcgi-socket"))
        self.port = port

    def start(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", self.port))
        self.listener.listen(16)
        self.listener.settimeout(0.2)
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError:
                pass


def raw_request(address: str, port: int, target: bytes):
    """Send a request target with arbitrary raw bytes (http.client refuses)."""

    conn = socket.create_connection((address, port), timeout=5)
    conn.sendall(
        b"GET " + target + b" HTTP/1.1\r\nHost: localhost\r\n"
        b"Connection: close\r\n\r\n"
    )
    data = b""
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
    conn.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        headers[name.decode("latin-1").lower()] = value.strip().decode("latin-1")
    return status, headers, body


def basic_auth(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def request(port: int, path: str, headers: dict[str, str] | None = None):
    return request_to("127.0.0.1", port, path, headers)


def request_to(
    address: str,
    port: int,
    path: str,
    headers: dict[str, str] | None = None,
):
    conn = http.client.HTTPConnection(address, port, timeout=5)
    conn.request("GET", path, headers=headers or {})
    response = conn.getresponse()
    body = response.read()
    status = response.status
    response_headers = dict(response.getheaders())
    conn.close()
    return status, response_headers, body


class F23ToF38Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-adversarial-", dir="/tmp/opencode"))
        cls.www = cls.base / "www"
        cls.logs = cls.base / "logs"
        cls.cache = cls.base / "cache"
        for directory in (
            cls.www,
            cls.www / "cgi",
            cls.www / "admin",
            cls.www / "list",
            cls.www / "env",
            cls.www / "indexignore",
            cls.www / "indexignore-main",
            cls.www / "tenant",
            cls.www / "reqheader",
            cls.www / "cgiauth",
            cls.www / "private-cgi",
            cls.www / "public-cgi",
            cls.www / "limit-cgi",
            cls.www / "exprtest",
            cls.www / "reqnone-main",
            cls.www / "reqnone-ht",
            cls.logs,
            cls.cache,
            cls.base / "private" / "sub",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        cls.www.chmod(0o755)
        cls.base.chmod(0o755)
        cls.logs.chmod(0o777)
        cls.cache.chmod(0o777)

        (cls.www / "hello.txt").write_text("hello\n")
        (cls.www / "secret.txt").write_text("WALLET-ENV-SECRET\n")
        (cls.www / "admin" / "wallet.dat").write_text("WALLET-DIR-SECRET\n")
        (cls.www / "list" / "public.txt").write_text("public\n")
        # Hostile filenames that used to become executable/scheme-relative hrefs.
        (cls.www / "list" / "javascript:alert(1)").write_text("x\n")
        (cls.www / "list" / "data:text,boom").write_text("x\n")
        (cls.www / "indexignore" / "public.txt").write_text("public\n")
        (cls.www / "indexignore" / "wallet.secret").write_text("secret\n")
        (cls.www / "indexignore" / ".htaccess").write_text("IndexIgnore *.secret\n")
        (cls.www / "indexignore-main" / "public.txt").write_text("public\n")
        (cls.www / "indexignore-main" / "wallet.secret").write_text("secret\n")
        (cls.www / "env" / "secret.txt").write_text("WALLET-SETENVIF-SECRET\n")
        (cls.www / "env" / "allowed.txt").write_text("WALLET-SETENV-ALLOWED\n")
        (cls.www / "env" / "negated-env.txt").write_text("WALLET-NEGATED-ENV\n")
        (cls.www / "env" / "negated-expr.txt").write_text("WALLET-NEGATED-EXPR\n")
        (cls.www / "env" / ".htaccess").write_text(
            "SetEnv STATIC_ALLOW yes\n"
            "SetEnvIf X-Block yes BLOCK=1\n"
            '<Files "secret.txt">\n'
            '    Require expr "%{ENV:BLOCK} == \'\'"\n'
            "</Files>\n"
            '<Files "allowed.txt">\n'
            "    Require env STATIC_ALLOW\n"
            "</Files>\n"
        )
        (cls.www / "cgi" / "wallet.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n'\n"
            "printf 'Cache-Control: max-age=600\\r\\n\\r\\n'\n"
            "printf 'WALLET-RELOAD-SECRET\\n'\n"
        )
        (cls.www / "cgi" / "wallet.cgi").chmod(0o755)
        (cls.base / "private" / ".htaccess").write_text("Require all denied\n")
        (cls.base / "private" / "wallet.dat").write_text(
            "WALLET-SINGLE-FILE-ALIAS-SECRET\n"
        )
        (cls.base / "private" / "sub" / "secret.txt").write_text(
            "WALLET-RELALIAS-SECRET\n"
        )
        # F39: a single-file Alias/ScriptAlias must use the target basename for
        # handler dispatch and must read the target directory's .htaccess.
        (cls.www / "cgi" / "alias-run.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-ALIAS-CGI-EXECUTED\\n'\n"
        )
        (cls.www / "cgi" / "alias-run.cgi").chmod(0o755)
        # F40: Options -ExecCGI inside <Limit> must take effect.
        (cls.www / "limit-cgi" / "script.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-LIMIT-EXECCGI-BYPASS\\n'\n"
        )
        (cls.www / "limit-cgi" / "script.cgi").chmod(0o755)
        # F45: expression file tests must not observe paths outside docroot.
        (cls.www / "exprtest" / "secret.txt").write_text(
            "WALLET-EXPR-CONFINEMENT\n"
        )
        (cls.www / "exprtest" / ".htaccess").write_text(
            "Require expr \"-f '/etc/passwd'\"\n"
        )
        # F46: multi-provider <RequireNone> must fail if any child matches.
        (cls.www / "reqnone-main" / "wallet.dat").write_text(
            "WALLET-REQUIRENONE-MAIN\n"
        )
        (cls.www / "reqnone-ht" / "wallet.dat").write_text(
            "WALLET-REQUIRENONE-HTACCESS\n"
        )
        (cls.www / "reqnone-ht" / ".htaccess").write_text(
            "<RequireAll>\n"
            "    Require all granted\n"
            "    <RequireNone>\n"
            "        Require ip 10.0.0.0/8\n"
            "        Require ip 127.0.0.0/8\n"
            "    </RequireNone>\n"
            "</RequireAll>\n"
        )
        # F47: regex alias file targets with and without a trailing slash.
        (cls.base / "private" / "secret.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-REGEX-ALIAS-CGI-SECRET\\n'\n"
        )
        (cls.base / "private" / "secret.cgi").chmod(0o755)
        # F41: a public symlink to a script in a denied directory.
        (cls.www / "private-cgi" / "admin.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-PRIVATE-CGI-SECRET\\n'\n"
        )
        (cls.www / "private-cgi" / "admin.cgi").chmod(0o755)
        (cls.www / "private-cgi" / "secret.php").write_text(
            "<?php /* WALLET-PRIVATE-PHP-SECRET */ ?>\n"
        )
        (cls.www / "public-cgi" / "link.cgi").symlink_to(
            "../private-cgi/admin.cgi"
        )
        (cls.www / "public-cgi" / "link.php").symlink_to(
            "../private-cgi/secret.php"
        )

        # F31: an absolute target outside ServerRoot.  The capture-only alias
        # must fail instead of re-rooting at the file's parent directory.
        cls.alias_dir = Path(
            tempfile.mkdtemp(prefix="vapache-alias-escape-", dir="/tmp/opencode")
        )
        cls.alias_secret = cls.alias_dir / "secret.txt"
        cls.alias_secret.write_text("WALLET-ALIAS-SECRET\n")
        # F32: a file under ServerRoot but outside DocumentRoot.
        (cls.base / "rewrite-secret.txt").write_text("WALLET-REWRITE-SECRET\n")

        # F34: cacheable, header-selected representation.
        (cls.www / "tenant" / "cacheme.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n'\n"
            "printf 'Cache-Control: max-age=600\\r\\n\\r\\n'\n"
            "printf 'WALLET-TENANT-CACHE\\n'\n"
        )
        (cls.www / "tenant" / "cacheme.cgi").chmod(0o755)
        # F36: a request-mutating directive that used to be silently ignored.
        (cls.www / "reqheader" / "secret.txt").write_text("WALLET-REQHEADER-SECRET\n")
        (cls.www / "reqheader" / ".htaccess").write_text(
            "RequestHeader set X-Block yes\n"
            '<Files "secret.txt">\n'
            "    Require expr \"%{HTTP:X-Block} != 'yes'\"\n"
            "</Files>\n"
        )
        # F38: authenticated CGI identity.
        (cls.www / "cgiauth" / "who.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'REMOTE_USER=[%s]\\n' \"$REMOTE_USER\"\n"
            "printf 'AUTH_TYPE=[%s]\\n' \"$AUTH_TYPE\"\n"
        )
        (cls.www / "cgiauth" / "who.cgi").chmod(0o755)
        digest = base64.b64encode(hashlib.sha1(b"alicepw").digest()).decode()
        (cls.base / ".htpasswd").write_text(f"alice:{{SHA}}{digest}\n")
        (cls.base / ".htpasswd").chmod(0o644)

        cls.backend = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        cls.backend_port = cls.backend.server_address[1]
        threading.Thread(target=cls.backend.serve_forever, daemon=True).start()
        cls.port = free_port()
        cls.config = cls.base / "vp.conf"
        cls.write_config()
        cls.proc = subprocess.Popen(
            [str(VAPACHED), "-f", str(cls.config), "-DFOREGROUND"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        output = b""
        if cls.proc.stdout:
            output = cls.proc.stdout.read()
        raise RuntimeError(f"vapached failed to start:\n{output.decode(errors='replace')}")

    @classmethod
    def write_config(cls, extra: str = ""):
        cls.config.write_text(
            VAPACHE_CAPABILITIES
            + f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
Timeout 30
DocumentRoot "{cls.www}"
CacheRoot "{cls.cache}"
CacheEnable disk /
CacheHeader On
CacheDefaultExpire 600
AddHandler cgi-script .cgi
DirectoryIndex index.html
<Directory "{cls.www}">
    AllowOverride All
    Options +Indexes +ExecCGI +FollowSymLinks
    Require all granted
</Directory>
<Directory "{cls.www}/indexignore-main">
    Options +Indexes
    IndexIgnore *.secret
    Require all granted
</Directory>
<Directory "{cls.www}/admin">
    Options +Indexes
    DirectorySlash Off
    Require all granted
</Directory>
<Directory "{cls.www}/reqnone-main">
    <RequireAll>
        Require all granted
        <RequireNone>
            Require ip 10.0.0.0/8
            Require ip 127.0.0.0/8
        </RequireNone>
    </RequireAll>
</Directory>
<Directory "{cls.www}/reqnone-ht">
    AllowOverride AuthConfig
    Require all granted
</Directory>
<Directory "{cls.base}/private">
    AllowOverride All
    Require all granted
</Directory>
<Directory "{cls.www}/private-cgi">
    Require all denied
</Directory>
<Directory "{cls.www}/limit-cgi">
    <Limit GET>
        Options -ExecCGI
    </Limit>
</Directory>
<Files "admin.cgi">
    Require all denied
</Files>
ProxyPassMatch ^/(.*\\.php)$ "unix:{cls.base}/fcgi.sock|fcgi://localhost{cls.www}/"
Alias /wallet "{cls.base}/private/wallet.dat"
Alias /run "{cls.www}/cgi/alias-run.cgi"
ScriptAlias /exec "{cls.www}/cgi/alias-run.cgi"
AliasMatch "^/wallet-regex$" "{cls.base}/private/wallet.dat/"
AliasMatch "^/wallet-regex-noslash$" "{cls.base}/private/wallet.dat"
ScriptAliasMatch "^/secret-run-regex$" "{cls.base}/private/secret.cgi/"
ScriptAliasMatch "^/secret-run-regex-noslash$" "{cls.base}/private/secret.cgi"

RewriteEngine On
RewriteRule ^/admin-rewrite$ /front [L]
RewriteRule ^/front$ http://127.0.0.1:{cls.backend_port}/secret [P]
RewriteRule ^/admin-redirect$ /redirect-front [L]
RewriteRule ^/redirect-front$ /hello.txt [R=302,L]
RewriteRule ^/unsafe/(.*)$ "{cls.base}/$1" [L,UnsafePrefixStat]
RewriteRule ^/env-rewrite$ /hello.txt [L,E=BLOCK:1]
RewriteRule ^/query-rewrite$ /hello.txt?new=1 [L]

<Location "/admin-rewrite">
    Require all denied
</Location>
<Location "/admin-redirect">
    Require all denied
</Location>
<Location "/admin/">
    Require all denied
</Location>
<Location "/env/negated-env.txt">
    <RequireAll>
        Require all granted
        Require not env BLOCK
    </RequireAll>
</Location>
<Location "/env/negated-expr.txt">
    <RequireAll>
        Require all granted
        Require not expr "%{{HTTP:X-Block}} == 'yes'"
    </RequireAll>
</Location>
<Location "/env/secret.txt">
    <RequireAll>
        Require all granted
        Require not env BLOCK
    </RequireAll>
</Location>
<Location "/env-rewrite">
    Require expr "%{{ENV:BLOCK}} == ''"
</Location>
<Location "/query-rewrite">
    <RequireAll>
        Require all granted
        Require expr "%{{QUERY_STRING}} == 'orig=1'"
    </RequireAll>
</Location>
<Location "/tenant/">
    <RequireAll>
        Require all granted
        Require expr "%{{HTTP:X-Tenant}} == 'alpha'"
    </RequireAll>
</Location>
<Location "/cgiauth/">
    AuthType Basic
    AuthName "CGI Realm"
    AuthUserFile "{cls.base}/.htpasswd"
    Require valid-user
</Location>
SetEnvIf X-Block yes BLOCK=1
AliasMatch "^/rel/(.*)$" "private/$1"
AliasMatch "^/escape(.*)$" "$1"

# A cacheable CGI route used by the F24 reload test.  The deny is appended by
# reload_with_wallet_deny().
"""
            + extra
        )

    @classmethod
    def reload_with_wallet_deny(cls):
        cls.write_config('<Files "wallet.cgi">\n    Require all denied\n</Files>\n')
        os.kill(cls.proc.pid, signal.SIGHUP)
        deadline = time.time() + 10
        while time.time() < deadline:
            status, _, _ = request(cls.port, "/cgi/wallet.cgi")
            if status == 403:
                return
            time.sleep(0.1)
        raise AssertionError("reload did not apply the <Files> deny")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None) and cls.proc.poll() is None:
            try:
                os.killpg(os.getpgid(cls.proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(cls.proc.pid), signal.SIGKILL)
        if getattr(cls, "backend", None):
            cls.backend.shutdown()
            cls.backend.server_close()
        if os.environ.get("KEEP_TEST_TREE") != "1":
            shutil.rmtree(cls.base, ignore_errors=True)
            alias_dir = getattr(cls, "alias_dir", None)
            if alias_dir is not None:
                shutil.rmtree(alias_dir, ignore_errors=True)

    def test_f23_rewrite_then_proxy_keeps_original_authorization(self):
        status, _, body = request(self.port, "/admin-rewrite")
        self.assertEqual(status, 403, body[:200])

    def test_f23_rewrite_then_redirect_keeps_original_authorization(self):
        status, _, body = request(self.port, "/admin-redirect")
        self.assertEqual(status, 403, body[:200])

    def test_f24_reload_and_path_info_cache_are_bound_to_script(self):
        status, _, body = request(self.port, "/cgi/wallet.cgi/foo")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"WALLET-RELOAD-SECRET", body)
        type(self).reload_with_wallet_deny()
        for path in ("/cgi/wallet.cgi", "/cgi/wallet.cgi/foo"):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 403, f"{path}: {body[:200]}")
            self.assertNotIn(b"WALLET-RELOAD-SECRET", body)

    def test_f25_relative_regex_alias_reads_target_htaccess(self):
        status, _, body = request(self.port, "/rel/sub/secret.txt")
        self.assertEqual(status, 403, body[:200])

    def test_f26_autoindex_never_emits_scheme_urls(self):
        status, _, body = request(self.port, "/list/")
        self.assertEqual(status, 200)
        text = body.decode("utf-8", "replace")
        self.assertIn('href="./javascript:alert(1)"', text)
        self.assertNotIn('href="javascript:', text)
        self.assertNotIn('href="data:', text)

    def test_f27_negated_env_and_expr_operands_are_bound_correctly(self):
        status, _, body = request(self.port, "/env/negated-env.txt")
        self.assertEqual(status, 200, body[:200])
        status, _, body = request(
            self.port, "/env/negated-env.txt", {"X-Block": "yes"}
        )
        self.assertEqual(status, 403, body[:200])
        status, _, body = request(
            self.port, "/env/negated-expr.txt", {"X-Block": "yes"}
        )
        self.assertEqual(status, 403, body[:200])

    def test_f28_htaccess_environment_respects_authorization_phase(self):
        status, _, body = request(self.port, "/env/secret.txt")
        self.assertEqual(status, 200, body[:200])
        status, _, body = request(self.port, "/env/secret.txt", {"X-Block": "yes"})
        self.assertEqual(status, 403, body[:200])
        status, _, body = request(self.port, "/env/allowed.txt")
        # mod_env's SetEnv hook runs in fixups, after authorization. It remains
        # effective for handlers/CGI but cannot satisfy Require env.
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-SETENV-ALLOWED", body)

    def test_f29_indexignore_hides_matching_entries(self):
        for path in ("/indexignore/", "/indexignore-main/"):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 200, f"{path}: {body[:200]}")
            text = body.decode("utf-8", "replace")
            self.assertIn("public.txt", text)
            self.assertNotIn("wallet.secret", text)

    def test_f30_directory_without_slash_uses_trailing_slash_policy(self):
        status, _, body = request(self.port, "/admin")
        self.assertNotEqual(status, 200, body[:200])
        self.assertNotIn(b"WALLET-DIR-SECRET", body)
        status, _, body = request(self.port, "/admin/")
        self.assertEqual(status, 403, body[:200])

    def test_f31_capture_only_alias_cannot_re_root_outside_its_base(self):
        status, _, body = request(self.port, f"/escape{self.alias_secret}")
        self.assertEqual(status, 404, body[:200])
        self.assertNotIn(b"WALLET-ALIAS-SECRET", body)

    def test_f32_unsafe_prefix_stat_does_not_change_the_authorization_base(self):
        status, _, body = request(self.port, "/unsafe/rewrite-secret.txt")
        self.assertNotEqual(status, 200, body[:200])
        self.assertNotIn(b"WALLET-REWRITE-SECRET", body)

    def test_transform_rewrite_effects_are_rechecked_for_original_url(self):
        status, _, body = request(self.port, "/env-rewrite")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"hello", body)

    def test_transform_original_url_gate_uses_original_request_context(self):
        status, _, body = request(self.port, "/query-rewrite?orig=1")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"hello", body)
        status, _, body = request(self.port, "/query-rewrite?orig=2")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"hello", body)

    def test_f35_proxy_host_validation(self):
        """F35: a request-derived forwarded host cannot reach the upstream head.

        A tab is legal in an HTTP header value but illegal in a host authority,
        so the request parser accepts it and only the proxy component check
        rejects it.  The upstream must not be contacted at all.
        """
        before = Backend.hits
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            sock.sendall(
                b"GET /front HTTP/1.1\r\n"
                b"Host: evil\texample.com\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
            response = b""
            while True:
                part = sock.recv(4096)
                if not part:
                    break
                response += part
        finally:
            sock.close()
        self.assertEqual(Backend.hits, before, "injected host reached the upstream")
        self.assertNotIn(b"WALLET-BACKEND-SECRET", response)
        self.assertNotIn(b"X-Injected", response)
        status = int(response.split(b" ", 2)[1]) if b" " in response else 0
        self.assertIn(status, (400, 502), response[:200])

    def test_f34_cache_is_partitioned_by_authorization_headers(self):
        headers = {"X-Tenant": "alpha"}
        status, response_headers, body = request(
            self.port, "/tenant/cacheme.cgi", headers
        )
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"WALLET-TENANT-CACHE", body)
        self.assertEqual(response_headers.get("X-Cache"), "MISS")
        status, response_headers, body = request(
            self.port, "/tenant/cacheme.cgi", headers
        )
        self.assertEqual(status, 200, body[:200])
        # CGI observes REMOTE_PORT. Separate client connections therefore
        # have distinct shared-cache transport identities even when their
        # tenant header is identical.
        self.assertEqual(response_headers.get("X-Cache"), "MISS")
        status, _, body = request(
            self.port, "/tenant/cacheme.cgi", {"X-Tenant": "beta"}
        )
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-TENANT-CACHE", body)

    def test_f36_htaccess_requestheader_fails_closed(self):
        status, _, body = request(self.port, "/reqheader/secret.txt")
        self.assertEqual(status, 500, body[:200])
        self.assertNotIn(b"WALLET-REQHEADER-SECRET", body)

    def test_f38_cgi_receives_remote_user_and_auth_type(self):
        status, _, body = request(self.port, "/cgiauth/who.cgi")
        self.assertEqual(status, 401, body[:200])
        token = base64.b64encode(b"alice:alicepw").decode()
        status, _, body = request(
            self.port,
            "/cgiauth/who.cgi",
            {"Authorization": f"Basic {token}"},
        )
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"REMOTE_USER=[alice]", body)
        self.assertIn(b"AUTH_TYPE=[Basic]", body)

    def test_f39_single_file_alias_reads_target_htaccess(self):
        status, _, body = request(self.port, "/wallet")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-SINGLE-FILE-ALIAS-SECRET", body)

    def test_f39_single_file_alias_dispatches_cgi_target(self):
        for path in ("/run", "/exec"):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 200, f"{path}: {body[:200]}")
            self.assertIn(b"WALLET-ALIAS-CGI-EXECUTED", body)
            self.assertNotIn(b"#!/bin/sh", body)

    def test_f40_limit_options_execcgi_is_enforced(self):
        status, _, body = request(self.port, "/limit-cgi/script.cgi")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-LIMIT-EXECCGI-BYPASS", body)

    def test_f41_symlinked_cgi_and_fastcgi_use_actual_target_policy(self):
        for path in (
            "/private-cgi/admin.cgi",
            "/public-cgi/link.cgi",
            "/public-cgi/link.cgi/anything",
            "/private-cgi/secret.php",
            "/public-cgi/link.php",
        ):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 403, f"{path}: {body[:200]}")
            self.assertNotIn(b"WALLET-PRIVATE-CGI-SECRET", body)
            self.assertNotIn(b"WALLET-PRIVATE-PHP-SECRET", body)

    def test_f46_require_none_multi_provider_denies(self):
        for path, secret in (
            ("/reqnone-main/wallet.dat", b"WALLET-REQUIRENONE-MAIN"),
            ("/reqnone-ht/wallet.dat", b"WALLET-REQUIRENONE-HTACCESS"),
        ):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 403, f"{path}: {body[:200]}")
            self.assertNotIn(secret, body)

    def test_f47_regex_alias_file_targets_read_target_htaccess(self):
        for path in (
            "/wallet-regex",
            "/wallet-regex-noslash",
        ):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 403, f"{path}: {body[:200]}")
            self.assertNotIn(b"WALLET-SINGLE-FILE-ALIAS-SECRET", body)
        for path in (
            "/secret-run-regex",
            "/secret-run-regex-noslash",
        ):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 403, f"{path}: {body[:200]}")
            self.assertNotIn(b"WALLET-REGEX-ALIAS-CGI-SECRET", body)

    def test_f45_expression_file_test_is_confined_to_docroot(self):
        status, _, body = request(self.port, "/exprtest/secret.txt")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-EXPR-CONFINEMENT", body)

    def test_f42_capture_only_alias_cannot_read_serverroot(self):
        for rel in (".htpasswd", "rewrite-secret.txt", "vp.conf"):
            status, _, body = request(self.port, f"/escape{self.base}/{rel}")
            self.assertEqual(status, 404, f"{rel}: {body[:200]}")
            self.assertNotIn(b"WALLET-REWRITE-SECRET", body)
            self.assertNotIn(b"ServerRoot", body)
            self.assertNotIn(b"alice:", body)


class F48AddressBoundVhostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-vhost-ip-", dir="/tmp/opencode"))
        cls.public = cls.base / "public"
        cls.admin = cls.base / "admin"
        cls.logs = cls.base / "logs"
        cls.base.chmod(0o755)
        for directory in (cls.public, cls.admin, cls.logs):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        (cls.public / "index.html").write_text("WALLET-PUBLIC\n")
        (cls.admin / "index.html").write_text("WALLET-ADMIN-SECRET\n")
        cls.port = free_port()
        cls.config = cls.base / "vp.conf"
        cls.config.write_text(
            f"""ServerRoot "{cls.base}"
Listen 0.0.0.0:{cls.port}
ServerName public.local
User {SERVICE_USER}
Group {SERVICE_GROUP}
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.public}"
<VirtualHost 127.0.0.1:{cls.port}>
    ServerName admin.local
    DocumentRoot "{cls.admin}"
</VirtualHost>
<VirtualHost *:{cls.port}>
    ServerName public.local
    DocumentRoot "{cls.public}"
</VirtualHost>
"""
        )
        cls.proc = subprocess.Popen(
            [str(VAPACHED), "-f", str(cls.config), "-DFOREGROUND"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        output = b""
        if cls.proc.stdout:
            output = cls.proc.stdout.read()
        raise RuntimeError(f"vapached failed to start:\n{output.decode(errors='replace')}")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None) and cls.proc.poll() is None:
            try:
                os.killpg(os.getpgid(cls.proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(cls.proc.pid), signal.SIGKILL)
        shutil.rmtree(cls.base, ignore_errors=True)

    def test_f48_loopback_vhost_is_not_reachable_on_another_address(self):
        status, _, body = request_to(
            "127.0.0.2", self.port, "/", {"Host": "admin.local"}
        )
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"WALLET-PUBLIC", body)
        self.assertNotIn(b"WALLET-ADMIN-SECRET", body)

        status, _, body = request_to(
            "127.0.0.1", self.port, "/", {"Host": "admin.local"}
        )
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"WALLET-ADMIN-SECRET", body)

    def test_f48_address_bound_vhost_precedes_wildcard_host_match(self):
        # Apache serves the exact-address vhost on 127.0.0.1 even when Host
        # names the wildcard vhost; the reverse address must stay public.
        status, _, body = request_to(
            "127.0.0.1", self.port, "/", {"Host": "public.local"}
        )
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"WALLET-ADMIN-SECRET", body)

        status, _, body = request_to(
            "127.0.0.2", self.port, "/", {"Host": "public.local"}
        )
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"WALLET-PUBLIC", body)


class F49IPv4MappedPeerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        if not socket.has_ipv6:
            raise unittest.SkipTest("IPv6 unavailable")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-ipmapped-", dir="/tmp/opencode"))
        cls.www = cls.base / "www"
        cls.logs = cls.base / "logs"
        cls.base.chmod(0o755)
        for directory in (cls.www, cls.logs):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        for name in ("deny-ip", "allow-ip", "local"):
            (cls.www / name).write_text(f"{name}\n")
            (cls.www / name).chmod(0o644)
        cls.port = free_port()
        cls.config = cls.base / "vp.conf"
        cls.config.write_text(
            f"""ServerRoot "{cls.base}"
Listen [::]:{cls.port}
ServerName localhost
User {SERVICE_USER}
Group {SERVICE_GROUP}
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
<Directory "{cls.www}">
    Require all granted
</Directory>
<Location "/deny-ip">
    <RequireAll>
        Require all granted
        Require not ip 127.0.0.0/8
    </RequireAll>
</Location>
<Location "/allow-ip">
    Require ip 127.0.0.0/8
</Location>
<Location "/local">
    Require local
</Location>
"""
        )
        cls.proc = subprocess.Popen(
            [str(VAPACHED), "-f", str(cls.config), "-DFOREGROUND"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with socket.create_connection(("::1", cls.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        output = b""
        if cls.proc.stdout:
            output = cls.proc.stdout.read()
        cls.tearDownClass()
        raise unittest.SkipTest(
            "dual-stack IPv6 listener unavailable: "
            + output.decode(errors="replace")[-800:]
        )

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None) and cls.proc.poll() is None:
            try:
                os.killpg(os.getpgid(cls.proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(cls.proc.pid), signal.SIGKILL)
        if getattr(cls, "base", None):
            shutil.rmtree(cls.base, ignore_errors=True)

    def test_f49_ipv4_mapped_peer_matches_ipv4_denylist(self):
        status, _, body = request_to("127.0.0.1", self.port, "/deny-ip")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"deny-ip", body)

        status, _, body = request_to("::1", self.port, "/deny-ip")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"deny-ip", body)

    def test_f49_ipv4_mapped_peer_matches_ipv4_allowlist_and_local(self):
        status, _, body = request_to("127.0.0.1", self.port, "/allow-ip")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"allow-ip", body)

        status, _, body = request_to("::1", self.port, "/allow-ip")
        self.assertEqual(status, 403, body[:200])

        for address in ("127.0.0.1", "::1"):
            status, _, body = request_to(address, self.port, "/local")
            self.assertEqual(status, 200, f"{address}: {body[:200]}")


class F50AncestorAccessFileTests(unittest.TestCase):
    """An access file above DocumentRoot/an alias target is still effective."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f50-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.app = cls.base / "app"
        cls.www = cls.app / "public"
        cls.srv = cls.base / "srv"
        cls.cache = cls.base / "cache"
        cls.logs = cls.base / "logs"
        for directory in (
            cls.www,
            cls.www / "dir",
            cls.www / "cgi",
            cls.srv / "site" / "assets",
            cls.cache,
            cls.logs,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        (cls.app / "public" / "wallet.dat").write_text(
            "WALLET-DOCPARENT-AUTH-SECRET\n"
        )
        (cls.www / "dir" / "index.html").write_text(
            "WALLET-DOCPARENT-INDEX-SECRET\n"
        )
        (cls.www / "cgi" / "run.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-DOCPARENT-CGI-SECRET\\n'\n"
        )
        (cls.www / "cgi" / "run.cgi").chmod(0o755)
        (cls.srv / "site" / "assets" / "wallet.dat").write_text(
            "WALLET-PARENTHT-SECRET\n"
        )
        digest = base64.b64encode(hashlib.sha1(b"secret").digest()).decode()
        (cls.base / ".htpasswd").write_text(f"alice:{{SHA}}{digest}\n")
        (cls.base / ".htpasswd").chmod(0o644)
        (cls.app / ".htaccess").write_text(
            "AuthType Basic\n"
            'AuthName "wallet"\n'
            f'AuthUserFile "{cls.base}/.htpasswd"\n'
            "Require valid-user\n"
        )
        (cls.srv / ".htaccess").write_text("Require all denied\n")
        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
CacheRoot "{cls.cache}"
CacheEnable disk /
CacheHeader On
CacheDefaultExpire 3600
CacheMaxExpire 3600
AddHandler cgi-script .cgi
DirectoryIndex index.html
<Directory "{cls.app}">
    AllowOverride All
    Options +ExecCGI
</Directory>
<Directory "{cls.srv}">
    AllowOverride All
</Directory>
Alias "/site" "{cls.srv}/site"
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "base", None):
            shutil.rmtree(cls.base, ignore_errors=True)

    def test_f50_parent_basic_auth_covers_static_index_cgi_and_cache(self):
        for path in ("/wallet.dat", "/dir/", "/cgi/run.cgi"):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 401, f"{path}: {body[:200]}")
            self.assertNotIn(b"WALLET-DOCPARENT", body)

        creds = basic_auth("alice", "secret")
        for path, secret in (
            ("/wallet.dat", b"WALLET-DOCPARENT-AUTH-SECRET"),
            ("/dir/", b"WALLET-DOCPARENT-INDEX-SECRET"),
            ("/cgi/run.cgi", b"WALLET-DOCPARENT-CGI-SECRET"),
        ):
            status, _, body = request(self.port, path, creds)
            self.assertEqual(status, 200, f"{path}: {body[:200]}")
            self.assertIn(secret, body)

        # Warm the cache with an authenticated request, then ensure an
        # unauthenticated lookup cannot use the entry.
        status, _, _ = request(self.port, "/wallet.dat", creds)
        self.assertEqual(status, 200)
        status, _, body = request(self.port, "/wallet.dat")
        self.assertEqual(status, 401, body[:200])
        self.assertNotIn(b"WALLET-DOCPARENT-AUTH-SECRET", body)

    def test_f50_alias_target_parent_htaccess_denies(self):
        status, _, body = request(self.port, "/site/assets/wallet.dat")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-PARENTHT-SECRET", body)

    def test_f50_explain_reports_the_parent_access_file(self):
        result = subprocess.run(
            [str(VAPACHED), "-f", str(self.config), "--explain", "/wallet.dat"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout[-1000:])
        self.assertIn(str(self.app / ".htaccess"), result.stdout)
        self.assertNotIn("no access files present", result.stdout)


class F51OverlappingAliasAccessRootTests(unittest.TestCase):
    """The access root is the URL-selected alias, not an earlier target."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f51-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "www"
        cls.site = cls.base / "site"
        cls.logs = cls.base / "logs"
        for directory in (
            cls.www,
            cls.site / "assets",
            cls.site / "cgi",
            cls.logs,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        (cls.site / "assets" / "wallet.dat").write_text("WALLET-AUTH-SECRET\n")
        (cls.site / "cgi" / "run.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-CGI-SECRET\\n'\n"
        )
        (cls.site / "cgi" / "run.cgi").chmod(0o755)
        (cls.site / ".htaccess").write_text("Require all denied\n")
        cls.port = free_port()
        cls.port_swapped = free_port()
        config_prefix = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{{port}}
ServerName localhost
PidFile "{cls.logs}/httpd-{{port}}.pid"
ErrorLog "{cls.logs}/error-{{port}}.log"
LogLevel warn
DocumentRoot "{cls.www}"
AddHandler cgi-script .cgi
<Directory "{cls.site}">
    AllowOverride All
    Options +ExecCGI
</Directory>
"""
        narrow_first = f"""AliasMatch "^/massets/(.*)$" "{cls.site}/assets/$1"
Alias "/assets" "{cls.site}/assets"
ScriptAlias "/cgia" "{cls.site}/cgi"
Alias "/site" "{cls.site}"
ScriptAlias "/scripts" "{cls.site}"
"""
        broad_first = f"""Alias "/site" "{cls.site}"
Alias "/assets" "{cls.site}/assets"
ScriptAlias "/scripts" "{cls.site}"
ScriptAlias "/cgia" "{cls.site}/cgi"
"""
        cls.proc, cls.config = start_vapached(
            cls.base,
            config_prefix.format(port=cls.port) + narrow_first,
        )
        swapped_dir = cls.base / "swapped"
        swapped_dir.mkdir(exist_ok=True)
        swapped_dir.chmod(0o755)
        cls.proc_swapped, _ = start_vapached(
            swapped_dir,
            config_prefix.format(port=cls.port_swapped) + broad_first,
        )

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        stop_vapached(getattr(cls, "proc_swapped", None))
        if getattr(cls, "base", None):
            shutil.rmtree(cls.base, ignore_errors=True)

    def test_f51_overlapping_alias_reads_the_url_selected_parent_policy(self):
        for path in (
            "/site/assets/wallet.dat",
            "/massets/wallet.dat",
        ):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 403, f"{path}: {body[:200]}")
            self.assertNotIn(b"WALLET-AUTH-SECRET", body)

        # Reordering the aliases must not change the decision.
        status, _, body = request(self.port_swapped, "/site/assets/wallet.dat")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-AUTH-SECRET", body)

    def test_f51_overlapping_script_alias_cannot_execute_protected_cgi(self):
        for path in ("/site/cgi/run.cgi", "/scripts/cgi/run.cgi"):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 403, f"{path}: {body[:200]}")
            self.assertNotIn(b"WALLET-CGI-SECRET", body)


class F52DirectoryIndexCacheTargetTests(unittest.TestCase):
    """Cache lookup/store must bind the selected DirectoryIndex target."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f52-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "www"
        cls.cache = cls.base / "cache"
        cls.logs = cls.base / "logs"
        for directory in (
            cls.www / "dir",
            cls.www / "dir-cgi",
            cls.cache,
            cls.logs,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        (cls.www / "dir" / "index.html").write_text("WALLET-CACHED-INDEX\n")
        (cls.www / "dir" / ".htaccess").write_text("# initially no deny\n")
        (cls.www / "dir-cgi" / "index.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'SECRET-FOR-%s\\n' \"$QUERY_STRING\"\n"
        )
        (cls.www / "dir-cgi" / "index.cgi").chmod(0o755)
        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
CacheRoot "{cls.cache}"
CacheEnable disk /
CacheIgnoreQueryString On
CacheIgnoreNoLastMod On
CacheHeader On
CacheDefaultExpire 3600
CacheMaxExpire 3600
AddHandler cgi-script .cgi
DirectoryIndex index.html
<Directory "{cls.www}">
    AllowOverride All
    Options +ExecCGI
    Require all granted
</Directory>
<Directory "{cls.www}/dir-cgi">
    DirectoryIndex index.cgi
</Directory>
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "base", None):
            shutil.rmtree(cls.base, ignore_errors=True)

    def test_f52_query_strings_never_share_dynamic_index_representation(self):
        for token in ("alpha", "beta", "gamma"):
            status, headers, body = request(self.port, f"/dir-cgi/?token={token}")
            self.assertEqual(status, 200, body[:200])
            self.assertNotEqual(headers.get("X-Cache"), "HIT", body[:200])
            self.assertIn(f"SECRET-FOR-token={token}".encode(), body)

    def test_f52_live_files_deny_invalidates_cached_directory_index(self):
        status, headers, body = request(self.port, "/dir/")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"WALLET-CACHED-INDEX", body)
        self.assertEqual(headers.get("X-Cache"), "MISS")

        # The same selected index is reachable through the directory URL and
        # the direct URL; both must share the index-bound cache entry.
        status, headers, _ = request(self.port, "/dir/")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Cache"), "HIT")

        (self.www / "dir" / ".htaccess").write_text(
            '<Files "index.html">\n    Require all denied\n</Files>\n'
        )
        for path in ("/dir/", "/dir/index.html"):
            status, headers, body = request(self.port, path)
            self.assertEqual(status, 403, f"{path}: {body[:200]}")
            self.assertNotEqual(headers.get("X-Cache"), "HIT", path)
            self.assertNotIn(b"WALLET-CACHED-INDEX", body)


class F53AliasRewriteBaseTests(unittest.TestCase):
    """Per-directory RewriteRule bases follow the URL mount, not the alias target."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f53-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "www"
        cls.site = cls.base / "site"
        cls.logs = cls.base / "logs"
        for directory in (
            cls.www,
            cls.site / "private",
            cls.site / "nested",
            cls.site / "gone",
            cls.site / "env",
            cls.site / "moved",
            cls.site / "cgi",
            cls.logs,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        (cls.site / "private" / "wallet.dat").write_text(
            "WALLET-F53-STATIC-SECRET\n"
        )
        (cls.site / "nested" / "secret.txt").write_text(
            "WALLET-F53-NESTED-SECRET\n"
        )
        (cls.site / "gone" / "secret.txt").write_text("WALLET-F53-GONE\n")
        (cls.site / "moved" / "file.txt").write_text("WALLET-F53-MOVED\n")
        (cls.site / "env" / "show.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'F53_ENV=%s\\n' \"${F53_ENV:-missing}\"\n"
        )
        (cls.site / "env" / "show.cgi").chmod(0o755)
        (cls.site / "cgi" / "run.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-F53-CGI-SECRET\\n'\n"
        )
        (cls.site / "cgi" / "run.cgi").chmod(0o755)
        (cls.site / ".htaccess").write_text(
            "RewriteEngine On\n"
            "RewriteBase /site/\n"
            "RewriteRule ^private/ - [F,L]\n"
            "RewriteRule ^gone/ - [G,L]\n"
            "RewriteRule ^env/show\\.cgi$ - [E=F53_ENV:yes,L]\n"
            "RewriteRule ^redirect/(.*)$ /site/moved/$1 [R=302,L]\n"
        )
        (cls.site / "nested" / ".htaccess").write_text(
            "RewriteEngine On\nRewriteRule ^secret\\.txt$ - [F,L]\n"
        )
        (cls.site / "cgi" / ".htaccess").write_text(
            "RewriteEngine On\nRewriteRule ^run\\.cgi$ - [F,L]\n"
        )
        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
AddHandler cgi-script .cgi
<Directory "{cls.site}">
    AllowOverride All
    Options +ExecCGI
    Require all granted
</Directory>
Alias /site "{cls.site}"
AliasMatch "^/m/(.*)$" "{cls.site}/$1"
ScriptAlias /cgi "{cls.site}/cgi"
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def test_root_rewrite_base_blocks_files_alias_forms(self):
        for path in ("/site/private/wallet.dat", "/m/private/wallet.dat"):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 403, f"{path}: {body[:200]}")
            self.assertNotIn(b"WALLET-P7", body)
            self.assertNotIn(b"WALLET-F53", body)

    def test_nested_rewrite_base_under_alias(self):
        status, _, body = request(self.port, "/site/nested/secret.dat")
        self.assertEqual(status, 404, body[:200])

        status, _, body = request(self.port, "/site/nested/secret.txt")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-F53-NESTED-SECRET", body)

    def test_script_alias_anchored_deny_blocks_execution(self):
        status, _, body = request(self.port, "/cgi/run.cgi")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-F53-CGI-SECRET", body)

    def test_rewrite_gone_flag_uses_the_alias_base(self):
        status, _, body = request(self.port, "/site/gone/secret.txt")
        self.assertEqual(status, 410, body[:200])
        self.assertNotIn(b"WALLET-F53-GONE", body)

    def test_rewrite_environment_and_redirect_use_the_alias_base(self):
        status, _, body = request(self.port, "/site/env/show.cgi")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"F53_ENV=yes", body)

        status, headers, _ = request(self.port, "/site/redirect/file.txt")
        self.assertEqual(status, 302)
        self.assertTrue(
            headers.get("Location", "").endswith("/site/moved/file.txt"),
            headers.get("Location"),
        )


class F57RequestUriIdentityTests(unittest.TestCase):
    """%{REQUEST_URI} is the dispatcher's canonical path, never the raw target."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f57-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "www"
        cls.logs = cls.base / "logs"
        for directory in (
            cls.www / "expr",
            cls.www / "if-api",
            cls.www / "if-private",
            cls.www / "rewrite",
            cls.www / "envif",
            cls.logs,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        (cls.www / "expr" / ".env").write_text("WALLET-F57-ENV\n")
        (cls.www / "expr" / "wallet.dat").write_text("WALLET-F57-DB\n")
        (cls.www / "if-api" / "public.json").write_text("WALLET-F57-PUBLIC\n")
        (cls.www / "if-private" / "secret.json").write_text("WALLET-F57-SECRET\n")
        (cls.www / "rewrite" / ".env").write_text("WALLET-F57-RC-ENV\n")
        (cls.www / "envif" / ".env").write_text("WALLET-F57-ENVIF-ENV\n")
        (cls.www / "rewrite" / ".htaccess").write_text(
            "RewriteEngine On\n"
            "RewriteCond %{REQUEST_URI} \\.env$\n"
            "RewriteRule ^ - [F,L]\n"
        )
        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
<Directory "{cls.www}">
    AllowOverride All
    Require all granted
</Directory>
SetEnvIf Request_URI "\\.env$" F57_BLOCKED=1
<Location "/expr">
    Require expr "%{{REQUEST_URI}} !~ /\\.env$/ && %{{REQUEST_URI}} !~ /wallet\\.dat$/"
</Location>
<Location "/envif">
    Require expr "%{{ENV:F57_BLOCKED}} != '1'"
</Location>
<Directory "{cls.www}/if-private">
    Require all denied
</Directory>
<If "%{{REQUEST_URI}} =~ /^\\/if-api\\//">
    Require all granted
</If>
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def assert_denied(self, target: bytes):
        status, _, body = raw_request("127.0.0.1", self.port, target)
        self.assertEqual(status, 403, f"{target!r}: {body[:200]}")
        for marker in (
            b"WALLET-F57-ENV",
            b"WALLET-F57-DB",
            b"WALLET-F57-SECRET",
            b"WALLET-F57-RC-ENV",
            b"WALLET-F57-ENVIF-ENV",
        ):
            self.assertNotIn(marker, body)

    def test_require_expr_uses_decoded_query_free_path(self):
        for target in (
            b"/expr/.env",
            b"/expr/.env?x=1",
            b"/expr/%2eenv",
            b"/expr/wallet.dat?dl=1",
            b"/expr/wallet%2edat",
            b"/expr/api/../.env",
            b"/expr/api/%2e%2e/wallet.dat",
        ):
            self.assert_denied(target)

    def test_if_allow_list_cannot_match_pre_normalization_path(self):
        status, _, body = request(self.port, "/if-api/public.json?x=1")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"WALLET-F57-PUBLIC", body)

        for target in (
            b"/if-api/../if-private/secret.json",
            b"/if-api/%2e%2e/if-private/secret.json",
        ):
            self.assert_denied(target)

    def test_rewrite_cond_uses_decoded_query_free_path(self):
        for target in (
            b"/rewrite/.env",
            b"/rewrite/.env?x=1",
            b"/rewrite/%2eenv",
            b"/rewrite/api/../.env",
        ):
            self.assert_denied(target)

    def test_setenvif_request_uri_uses_decoded_query_free_path(self):
        for target in (
            b"/envif/.env",
            b"/envif/.env?x=1",
            b"/envif/%2eenv",
            b"/envif/api/../.env",
        ):
            self.assert_denied(target)


class F58ParentRewriteSubjectTests(unittest.TestCase):
    """Access-file rewrite layers above the mapping root use Apache subjects."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f58-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.ancestor = cls.base / "ancestor"
        cls.www = cls.ancestor / "public"
        cls.app = cls.www / "wallet" / "public"
        cls.storage = cls.base / "storage"
        cls.storage_app = cls.storage / "current" / "public"
        cls.logs = cls.base / "logs"
        for directory in (
            cls.app / "env",
            cls.app / "cgi",
            cls.app / "moved",
            cls.app / "private",
            cls.app / "ancestor",
            cls.storage_app / "private",
            cls.logs,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        (cls.app / ".env").write_text("WALLET-F58-ENV\n")
        (cls.app / "wallet.dat").write_text("WALLET-F58-DB\n")
        (cls.app / "gone.dat").write_text("WALLET-F58-GONE\n")
        (cls.app / "ancestor" / "wallet.dat").write_text("WALLET-F58-ANCESTOR\n")
        (cls.app / "private" / "index.html").write_text(
            "WALLET-F58-INDEX\n"
        )
        (cls.app / "moved" / "file.txt").write_text("WALLET-F58-MOVED\n")
        (cls.app / "env" / "show.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'F58_ENV=%s\\n' \"${F58_ENV:-missing}\"\n"
        )
        (cls.app / "env" / "show.cgi").chmod(0o755)
        (cls.app / "cgi" / "run.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-F58-CGI\\n'\n"
        )
        (cls.app / "cgi" / "run.cgi").chmod(0o755)
        (cls.storage_app / "private" / "wallet.dat").write_text(
            "WALLET-F58-STORAGE\n"
        )
        # Layer above DocumentRoot (ancestor/public) and above the alias target.
        (cls.ancestor / ".htaccess").write_text(
            "RewriteEngine On\n"
            "RewriteRule ^public/wallet/public/ancestor/ - [F,L]\n"
        )
        # DocumentRoot access file, applied to Alias/AliasMatch/ScriptAlias URLs.
        (cls.www / ".htaccess").write_text(
            "RewriteEngine On\n"
            "RewriteRule (^|/)\\.(env|git)(/|$) - [F,L]\n"
            "RewriteRule (^|/)wallet\\.dat$ - [F,L]\n"
            "RewriteRule (^|/)gone\\.dat$ - [G,L]\n"
            "RewriteRule ^wallet/public/private/$ - [F,L]\n"
            "RewriteRule (^|/)private(/|$) - [F,L]\n"
            "RewriteRule ^wallet/public/cgi/run\\.cgi$ - [F,L]\n"
            "RewriteRule ^wallet/public/env/show\\.cgi$ - [E=F58_ENV:yes,L]\n"
            "RewriteRule ^wallet/public/moved/(.*)$ /wallet/moved/$1 [R=302,L]\n"
            "Header set X-Htaccess-Read yes\n"
        )
        # Access file above a separate alias target, as in F58 reproduction B.
        (cls.storage / ".htaccess").write_text(
            "RewriteEngine On\n"
            "RewriteRule ^current/public/private/ - [F,L]\n"
        )
        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
AddHandler cgi-script .cgi
DirectoryIndex index.html
<Directory "{cls.ancestor}">
    AllowOverride All
    Options +ExecCGI
    Require all granted
</Directory>
<Directory "{cls.www}">
    AllowOverride All
    Options +ExecCGI
    Require all granted
</Directory>
<Directory "{cls.storage}">
    AllowOverride All
    Require all granted
</Directory>
Alias /wallet "{cls.app}"
AliasMatch "^/mwallet/(.*)$" "{cls.app}/$1"
ScriptAlias /swallet "{cls.app}/cgi"
Alias /storage "{cls.storage_app}"
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def assert_not_served(self, path: str, expected=(403,), marker=b"WALLET-F58"):
        status, headers, body = request(self.port, path)
        self.assertIn(status, expected, f"{path}: {body[:200]}")
        self.assertNotIn(marker, body, path)
        return status, headers, body

    def test_document_root_denylist_covers_alias_and_alias_match(self):
        for path in (
            "/wallet/.env",
            "/wallet/.env?x=1",
            "/wallet/%2eenv",
            "/wallet/wallet.dat?dl=1",
            "/mwallet/.env",
            "/mwallet/wallet%2edat",
        ):
            self.assert_not_served(path)

        status, headers, _ = request(self.port, "/wallet/moved/file.txt")
        self.assertEqual(status, 302)
        self.assertTrue(
            headers.get("Location", "").endswith("/wallet/moved/file.txt"),
            headers.get("Location"),
        )

    def test_document_root_index_cgi_env_gone_and_script_alias(self):
        self.assert_not_served("/wallet/private/")
        self.assert_not_served("/swallet/run.cgi")
        self.assert_not_served("/swallet/.env", expected=(403, 404))

        status, _, body = request(self.port, "/wallet/gone.dat")
        self.assertEqual(status, 410, body[:200])
        self.assertNotIn(b"WALLET-F58-GONE", body)

        status, headers, body = request(self.port, "/wallet/env/show.cgi")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"F58_ENV=yes", body)
        self.assertEqual(headers.get("X-Htaccess-Read"), "yes")

    def test_ancestor_layers_above_docroot_and_alias_target(self):
        for path in (
            "/wallet/ancestor/wallet.dat",
            "/storage/private/wallet.dat",
        ):
            self.assert_not_served(path)


class F59ExplicitTargetAccessLayerTests(unittest.TestCase):
    """A symlinked mapping root must keep child .htaccess on target reauth."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f59-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.real = cls.base / "real" / "public"
        cls.root = cls.base / "www" / "html"
        cls.alias_real = cls.base / "alias-real" / "public"
        cls.alias_link = cls.base / "alias-link"
        cls.cache = cls.base / "cache"
        cls.logs = cls.base / "logs"
        for directory in (
            cls.real / "admin",
            cls.real / "list",
            cls.real / "cached",
            cls.alias_real / "admin",
            cls.base / "www",
            cls.cache,
            cls.logs,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        cls.root.symlink_to(cls.real, target_is_directory=True)
        cls.alias_link.symlink_to(cls.alias_real, target_is_directory=True)

        script = (
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-F59-%s\\n'\n"
        )
        # The hardening policy Apache enforces and the target scope used to
        # discard when the mapping root contained a symlink.
        (cls.real / "admin" / ".htaccess").write_text("Options -ExecCGI\n")
        (cls.real / "admin" / "run.cgi").write_text(script % "CGI")
        (cls.real / "admin" / "run.cgi").chmod(0o755)
        (cls.real / "admin" / "index.cgi").write_text(script % "DIRINDEX")
        (cls.real / "admin" / "index.cgi").chmod(0o755)
        (cls.real / "list" / ".htaccess").write_text("Options -Indexes\n")
        (cls.real / "list" / "wallet.dat").write_text("WALLET-F59-LIST-SECRET\n")
        (cls.real / "cached" / ".htaccess").write_text("Options -ExecCGI\n")
        (cls.real / "cached" / "index.cgi").write_text(script % "CACHE-INDEX")
        (cls.real / "cached" / "index.cgi").chmod(0o755)
        (cls.alias_real / "admin" / ".htaccess").write_text(
            "Options -ExecCGI\n"
        )
        (cls.alias_real / "admin" / "run.cgi").write_text(script % "ALIAS-CGI")
        (cls.alias_real / "admin" / "run.cgi").chmod(0o755)

        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.root}"
Options +ExecCGI +FollowSymLinks +Indexes
CacheRoot "{cls.cache}"
CacheEnable disk /
CacheIgnoreNoLastMod On
CacheHeader On
CacheDefaultExpire 3600
CacheMaxExpire 3600
AddHandler cgi-script .cgi
DirectoryIndex index.html index.cgi
<Directory "{cls.root}">
    AllowOverride All
    Require all granted
</Directory>
<Directory "{cls.alias_link}">
    AllowOverride All
    Require all granted
</Directory>
Alias /aliased "{cls.alias_link}"
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def assert_not_executed(self, path: str, marker: bytes):
        status, headers, body = request(self.port, path)
        self.assertEqual(status, 403, f"{path}: {body[:200]}")
        self.assertNotIn(marker, body, path)
        self.assertNotEqual(headers.get("X-Cache"), "HIT", path)

    def test_symlinked_document_root_honors_child_exec_cgi(self):
        # Apache 2.4.69 returns 403 for this shape; the old target plan
        # re-read layers from root.join(file_name) and lost the child policy.
        self.assert_not_executed("/admin/run.cgi", b"WALLET-F59-CGI")

    def test_directory_index_cgi_and_direct_index(self):
        for path, marker in (
            ("/admin/", b"WALLET-F59-DIRINDEX"),
            ("/admin/index.cgi", b"WALLET-F59-DIRINDEX"),
        ):
            self.assert_not_executed(path, marker)

    def test_symlinked_cache_index_keeps_child_policy(self):
        status, headers, body = request(self.port, "/cached/")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-F59-CACHE-INDEX", body)
        self.assertNotEqual(headers.get("X-Cache"), "HIT")

    def test_options_indexes_is_not_lost_for_symlinked_root(self):
        status, _, body = request(self.port, "/list/")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"WALLET-F59-LIST-SECRET", body)

    def test_symlinked_alias_root_keeps_child_policy(self):
        self.assert_not_executed("/aliased/admin/run.cgi", b"WALLET-F59-ALIAS-CGI")


class F60ResolvedTargetScopeTests(unittest.TestCase):
    """Resolved-target policy must be a meet, never a replacement (F60/I61)."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f60-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.real = cls.base / "real" / "public"
        cls.root = cls.base / "www" / "html"
        cls.alias_real = cls.base / "alias-real" / "public"
        cls.alias_link = cls.base / "alias-link"
        cls.anc = cls.base / "anc"
        cls.anc_real = cls.base / "anc-real" / "public"
        cls.anc_root = cls.anc / "html"
        cls.anc_handler = cls.base / "anc-handler"
        cls.anc_handler_real = cls.base / "anc-handler-real" / "public"
        cls.anc_handler_root = cls.anc_handler / "html"
        cls.anc_set = cls.base / "anc-set"
        cls.anc_set_real = cls.base / "anc-set-real" / "public"
        cls.anc_set_root = cls.anc_set / "html"
        cls.logs = cls.base / "logs"
        for directory in (
            cls.real / "uploads",
            cls.real / "admin",
            cls.real / "list",
            cls.real / "dirindex",
            cls.real / "payload",
            cls.real / "handler",
            cls.real / "rw-protected",
            cls.alias_real / "uploads",
            cls.anc_real / "admin",
            cls.anc,
            cls.anc_handler,
            cls.anc_handler_real / "admin",
            cls.anc_set,
            cls.anc_set_real / "admin",
            cls.base / "www",
            cls.logs,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        cls.root.symlink_to(cls.real, target_is_directory=True)
        cls.alias_link.symlink_to(cls.alias_real, target_is_directory=True)
        cls.anc_root.symlink_to(cls.anc_real, target_is_directory=True)
        cls.anc_handler_root.symlink_to(cls.anc_handler_real, target_is_directory=True)
        cls.anc_set_root.symlink_to(cls.anc_set_real, target_is_directory=True)

        def script(marker: str) -> str:
            return (
                "#!/bin/sh\n"
                "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
                f"printf '{marker}\\n'\n"
            )

        (cls.real / "uploads" / "sh.cgi").write_text(script("WALLET-F60-UPLOADS"))
        (cls.real / "uploads" / "sh.cgi").chmod(0o755)
        (cls.real / "uploads" / "index.cgi").write_text(script("WALLET-F60-DIRINDEX"))
        (cls.real / "uploads" / "index.cgi").chmod(0o755)
        (cls.real / "payload" / "sh.cgi").write_text(script("WALLET-F60-PAYLOAD"))
        (cls.real / "payload" / "sh.cgi").chmod(0o755)
        (cls.real / "uploads" / "link.cgi").symlink_to("../payload/sh.cgi")
        (cls.real / "admin" / "run.cgi").write_text(script("WALLET-F60-ADMIN"))
        (cls.real / "admin" / "run.cgi").chmod(0o755)
        (cls.real / "dirindex" / "index.cgi").write_text(
            script("WALLET-F60-DIRINDEX-CGI")
        )
        (cls.real / "dirindex" / "index.cgi").chmod(0o755)
        (cls.real / "list" / "wallet.dat").write_text("WALLET-F60-LIST-SECRET\n")
        (cls.real / "handler" / "run.cgi").write_text(
            "#!/bin/sh\n"
            "# WALLET-F60-HANDLER-SOURCE\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-F60-HANDLER-%s\\n' 'EXEC'\n"
        )
        (cls.real / "handler" / "run.cgi").chmod(0o755)
        (cls.alias_real / "uploads" / "sh.cgi").write_text(
            script("WALLET-F60-ALIAS")
        )
        (cls.alias_real / "uploads" / "sh.cgi").chmod(0o755)
        (cls.anc_real / "admin" / "run.cgi").write_text(
            script("WALLET-F60-ANCESTOR")
        )
        (cls.anc_real / "admin" / "run.cgi").chmod(0o755)
        # F60-B: the hardening layer is above the symlinked mapping root.
        (cls.anc / ".htaccess").write_text("Options -ExecCGI\n")
        (cls.anc_handler / ".htaccess").write_text("RemoveHandler .cgi\n")
        (cls.anc_set / ".htaccess").write_text("SetHandler none\n")
        for real in (cls.anc_handler_real, cls.anc_set_real):
            (real / "admin" / "run.cgi").write_text(
                "#!/bin/sh\n"
                "# WALLET-F60-ANCESTOR-HANDLER-SOURCE\n"
                "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
                "printf 'WALLET-F60-ANCESTOR-HANDLER-%s\\n' 'EXEC'\n"
            )
            (real / "admin" / "run.cgi").chmod(0o755)
        # A per-directory rewrite must not launder a protected upload into the
        # globally executable payload directory.
        (cls.real / "rw-protected" / ".htaccess").write_text(
            "RewriteEngine On\n"
            "RewriteRule ^go$ /payload/sh.cgi [L]\n"
        )

        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.root}"
Options +ExecCGI +FollowSymLinks +Indexes
AddHandler cgi-script .cgi
DirectoryIndex index.html index.cgi
<Directory "{cls.root}">
    AllowOverride None
    Require all granted
</Directory>
<Directory "{cls.root}/uploads">
    Options -ExecCGI
    Require all granted
</Directory>
<Directory "{cls.root}/admin">
    Options -ExecCGI
    Require all granted
</Directory>
<Directory "{cls.root}/dirindex">
    Options -ExecCGI
    Require all granted
</Directory>
<Directory "{cls.root}/list">
    Options -Indexes
    Require all granted
</Directory>
<Directory "{cls.root}/handler">
    RemoveHandler .cgi
    Require all granted
</Directory>
<Directory "{cls.root}/rw-protected">
    Options -ExecCGI
    AllowOverride All
    Require all granted
</Directory>
<Directory "{cls.alias_link}">
    Options -ExecCGI
    Require all granted
</Directory>
Alias /aliased "{cls.alias_link}"
Alias /ancestor "{cls.anc_root}"
Alias /ancestor-handler "{cls.anc_handler_root}"
Alias /ancestor-sethandler "{cls.anc_set_root}"
<Directory "{cls.anc}">
    AllowOverride All
    Require all granted
</Directory>
<Directory "{cls.anc_handler}">
    AllowOverride All
    Require all granted
</Directory>
<Directory "{cls.anc_set}">
    AllowOverride All
    Require all granted
</Directory>
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def assert_denied(self, path: str, marker: bytes):
        status, _, body = request(self.port, path)
        self.assertEqual(status, 403, f"{path}: {body[:300]}")
        self.assertNotIn(marker, body, path)

    def test_plain_directory_policy_survives_symlinked_document_root(self):
        # No .htaccess and AllowOverride None: the child <Directory> is the
        # only denial, exactly the F60-A shape.
        self.assert_denied("/uploads/sh.cgi", b"WALLET-F60-UPLOADS")

    def test_symlinked_alias_target_keeps_lexical_directory_policy(self):
        self.assert_denied("/aliased/uploads/sh.cgi", b"WALLET-F60-ALIAS")

    def test_pre_existing_protected_cgi_is_not_executed(self):
        self.assert_denied("/admin/run.cgi", b"WALLET-F60-ADMIN")

    def test_in_root_symlink_cannot_escape_upload_exec_policy(self):
        self.assert_denied("/uploads/link.cgi", b"WALLET-F60-PAYLOAD")

    def test_ancestor_htaccess_above_symlinked_root_is_retained(self):
        self.assert_denied("/ancestor/admin/run.cgi", b"WALLET-F60-ANCESTOR")

    def test_ancestor_remove_handler_is_retained(self):
        status, _, body = request(self.port, "/ancestor-handler/admin/run.cgi")
        self.assertEqual(status, 200, body[:300])
        self.assertIn(b"WALLET-F60-ANCESTOR-HANDLER-SOURCE", body)
        self.assertNotIn(b"WALLET-F60-ANCESTOR-HANDLER-EXEC", body)

    def test_ancestor_set_handler_none_is_retained(self):
        status, _, body = request(self.port, "/ancestor-sethandler/admin/run.cgi")
        self.assertEqual(status, 200, body[:300])
        self.assertIn(b"WALLET-F60-ANCESTOR-HANDLER-SOURCE", body)
        self.assertNotIn(b"WALLET-F60-ANCESTOR-HANDLER-EXEC", body)

    def test_directory_index_cgi_in_protected_upload_directory(self):
        for path in ("/uploads/", "/uploads/index.cgi"):
            self.assert_denied(path, b"WALLET-F60-DIRINDEX")

    def test_directory_policy_survives_symlinked_root(self):
        self.assert_denied("/dirindex/", b"WALLET-F60-DIRINDEX-CGI")

    def test_options_indexes_is_not_lost(self):
        status, _, body = request(self.port, "/list/")
        self.assertEqual(status, 403, body[:300])
        self.assertNotIn(b"WALLET-F60-LIST-SECRET", body)

    def test_remove_handler_survives_symlinked_root(self):
        status, _, body = request(self.port, "/handler/run.cgi")
        self.assertEqual(status, 200, body[:300])
        self.assertIn(b"WALLET-F60-HANDLER-SOURCE", body)
        self.assertNotIn(b"WALLET-F60-HANDLER-EXEC", body)

    def test_rewrite_cannot_launder_a_protected_upload(self):
        self.assert_denied("/rw-protected/go", b"WALLET-F60-PAYLOAD")


class F60AllowOverrideDenyTests(unittest.TestCase):
    """Lexical AllowOverride None must veto canonical AllowOverride All."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f60-override-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.real = cls.base / "real" / "public"
        cls.root = cls.base / "www" / "html"
        cls.control = cls.base / "www" / "control"
        cls.logs = cls.base / "logs"
        for directory in (cls.real / "uploads", cls.base / "www", cls.logs):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        cls.root.symlink_to(cls.real, target_is_directory=True)
        cls.control.symlink_to(cls.real, target_is_directory=True)
        (cls.real / "uploads" / ".htaccess").write_text(
            "Options +ExecCGI\n"
            "AddHandler cgi-script .cgi\n"
        )
        (cls.real / "uploads" / "sh.cgi").write_text(
            "#!/bin/sh\n"
            "# WALLET-F60-OVERRIDE-SOURCE\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-F60-OVERRIDE-%s\\n' 'EXEC'\n"
        )
        (cls.real / "uploads" / "sh.cgi").chmod(0o755)
        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.root}"
Options +FollowSymLinks
<Directory "{cls.root}">
    AllowOverride None
    Require all granted
</Directory>
<Directory "{cls.real}">
    AllowOverride All
    Require all granted
</Directory>
Alias /override "{cls.root}"
Alias /control "{cls.control}"
<Directory "{cls.control}">
    AllowOverride All
    Require all granted
</Directory>
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def test_lexical_none_does_not_read_canonical_all_htaccess(self):
        status, _, body = request(self.port, "/override/uploads/sh.cgi")
        self.assertEqual(status, 200, body[:300])
        self.assertIn(b"WALLET-F60-OVERRIDE-SOURCE", body)
        self.assertNotIn(b"WALLET-F60-OVERRIDE-EXEC", body)

    def test_control_lexical_all_still_reads_the_uploaded_htaccess(self):
        status, _, body = request(self.port, "/control/uploads/sh.cgi")
        self.assertEqual(status, 200, body[:300])
        self.assertIn(b"WALLET-F60-OVERRIDE-EXEC", body)


class F54SetHandlerCacheTests(unittest.TestCase):
    """SetHandler proxy/server-status targets are dynamic for cache queries."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f54-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "www"
        cls.cache = cls.base / "cache"
        cls.logs = cls.base / "logs"
        for directory in (cls.www / "dir", cls.cache, cls.logs):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        (cls.www / "direct.php").write_text("not executed locally\n")
        (cls.www / "dir" / "index.php").write_text("not executed locally\n")
        cls.mock = FastCgiMock(cls.base / "fcgi.sock")
        cls.mock.start()
        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
CacheRoot "{cls.cache}"
CacheEnable disk /
CacheIgnoreQueryString On
CacheIgnoreNoLastMod On
CacheHeader On
CacheDefaultExpire 3600
CacheMaxExpire 3600
DirectoryIndex index.php
<FilesMatch \\.php$>
    SetHandler "proxy:unix:{cls.base}/fcgi.sock|fcgi://localhost"
</FilesMatch>
<Location "/status">
    SetHandler server-status
</Location>
<Directory "{cls.www}">
    Require all granted
</Directory>
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "mock", None):
            cls.mock.stop()
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def test_set_handler_direct_and_index_each_keep_query(self):
        for path in ("/direct.php", "/dir/"):
            for token in ("alpha", "beta", "gamma"):
                status, headers, body = request(
                    self.port, f"{path}?token={token}"
                )
                self.assertEqual(status, 200, body[:200])
                self.assertNotEqual(headers.get("X-Cache"), "HIT", body[:200])
                self.assertIn(f"SECRET-FOR-token={token}".encode(), body)

    def test_server_status_handler_is_not_query_merged(self):
        status, headers, body = request(self.port, "/status?auto")
        self.assertEqual(status, 200, body[:200])
        self.assertNotEqual(headers.get("X-Cache"), "HIT")
        self.assertIn(b"Total Accesses", body)


class F55CacheKeyBytesTests(unittest.TestCase):
    """Invalid-byte keys never collide with the clean URL or another query."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f55-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "www"
        cls.cache = cls.base / "cache"
        cls.logs = cls.base / "logs"
        for directory in (cls.www, cls.cache, cls.logs):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        (cls.www / "index.php").write_text("not executed locally\n")
        cls.mock = FastCgiMock(cls.base / "fcgi.sock")
        cls.mock.start()
        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
CacheRoot "{cls.cache}"
CacheEnable disk /
CacheIgnoreNoLastMod On
CacheHeader On
CacheDefaultExpire 3600
CacheMaxExpire 3600
<FilesMatch \\.php$>
    SetHandler "proxy:unix:{cls.base}/fcgi.sock|fcgi://localhost"
</FilesMatch>
<Directory "{cls.www}">
    Require all granted
</Directory>
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "mock", None):
            cls.mock.stop()
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def test_invalid_query_does_not_poison_the_clean_url(self):
        status, headers, body = raw_request(
            "127.0.0.1", self.port, b"/index.php?\xffPOISON"
        )
        self.assertEqual(status, 200, body[:200])
        self.assertNotEqual(headers.get("x-cache"), "HIT")
        self.assertIn(b"POISON", body)

        for attempt in range(2):
            status, headers, body = raw_request(
                "127.0.0.1", self.port, b"/index.php"
            )
            self.assertEqual(status, 200, body[:200])
            if attempt == 0:
                self.assertNotEqual(headers.get("x-cache"), "HIT")
            self.assertNotIn(b"POISON", body)

        status, headers, body = request(self.port, "/index.php?normal")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Cache"), "MISS")
        status, headers, body = request(self.port, "/index.php?normal")
        self.assertEqual(status, 200)
        # FastCGI receives REMOTE_PORT, so a new connection must not reuse a
        # representation produced under a different transport identity.
        self.assertEqual(headers.get("X-Cache"), "MISS")
        self.assertIn(b"normal", body)


class F56ErrorDocumentCacheTests(unittest.TestCase):
    """A local ErrorDocument subrequest is never cached under the missing URL."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f56-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "www"
        cls.cache = cls.base / "cache"
        cls.logs = cls.base / "logs"
        for directory in (cls.www, cls.cache, cls.logs):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        (cls.www / "err.php").write_text("not executed locally\n")
        cls.mock = FastCgiMock(cls.base / "fcgi.sock")
        cls.mock.start()
        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
CacheRoot "{cls.cache}"
CacheEnable disk /
CacheIgnoreQueryString On
CacheIgnoreNoLastMod On
CacheHeader On
CacheDefaultExpire 3600
CacheMaxExpire 3600
ErrorDocument 404 /err.php
<FilesMatch \\.php$>
    SetHandler "proxy:unix:{cls.base}/fcgi.sock|fcgi://localhost"
</FilesMatch>
<Directory "{cls.www}">
    Require all granted
</Directory>
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "mock", None):
            cls.mock.stop()
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def test_error_document_query_does_not_poison_missing_url(self):
        status, headers, body = request(self.port, "/missing?attack=POISON")
        self.assertIn(b"SECRET-FOR-attack=POISON", body)
        self.assertNotEqual(headers.get("X-Cache"), "HIT")

        status, headers, body = request(self.port, "/missing")
        self.assertNotEqual(headers.get("X-Cache"), "HIT")
        self.assertNotIn(b"POISON", body)


class F67PassthroughTargetTests(unittest.TestCase):
    """[PT] substitutions stay in URL space: absolute targets never execute (F67)."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f67-pt-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "www"
        cls.logs = cls.base / "logs"
        for directory in (cls.www / "secret", cls.logs):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        (cls.www / "secret" / "secret.cgi").write_text(
            "#!/bin/sh\n"
            "# WALLET-F67-SOURCE\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'WALLET-F67-EXEC\\n'\n"
        )
        (cls.www / "secret" / "secret.cgi").chmod(0o755)
        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
Options +ExecCGI
AddHandler cgi-script .cgi
RewriteEngine On
<Location "/secret">
    Require all denied
</Location>
RewriteRule "^/app/(.*)$" "%{{DOCUMENT_ROOT}}/$1" [PT,L]
<Directory "{cls.www}">
    Require all granted
</Directory>
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def test_pt_target_never_executes_host_script(self):
        status, _, body = request(self.port, "/app/secret/secret.cgi")
        self.assertNotEqual(status, 200, body[:300])
        self.assertNotIn(b"WALLET-F67-EXEC", body)
        self.assertNotIn(b"WALLET-F67-SOURCE", body)

    def test_location_policy_still_denies_the_real_url(self):
        status, _, body = request(self.port, "/secret/secret.cgi")
        self.assertNotEqual(status, 200, body[:200])
        self.assertNotIn(b"WALLET-F67-EXEC", body)


class F68StickyFilesystemOverrideTests(unittest.TestCase):
    """A later filesystem override must replace earlier stale ones (F68)."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f68-sticky-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "www"
        cls.logs = cls.base / "logs"
        for directory in (cls.www, cls.logs):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        (cls.www / "index.html").write_text("WALLET-F68-INDEX\n")
        for name in ("sticky-target.cgi", "direct-target.cgi"):
            (cls.www / name).write_text(
                "#!/bin/sh\n"
                "# WALLET-F68-SOURCE\n"
                "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
                "printf 'WALLET-F68-EXEC\\n'\n"
            )
            (cls.www / name).chmod(0o755)
        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
Options +ExecCGI
AddHandler cgi-script .cgi
RewriteEngine On
RewriteRule "^/app/(.*)$" "%{{DOCUMENT_ROOT}}/sticky-target.cgi"
RewriteRule "^" "/index.html" [L]
<Directory "{cls.www}">
    Require all granted
</Directory>
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)
        # Capability server: no rewrites at all, so the sticky assertion can
        # be compared against the real behaviour of the same .cgi target.
        cls.control_port = free_port()
        cls.control_proc, _ = start_vapached(
            cls.base,
            f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.control_port}
ServerName localhost
PidFile "{cls.logs}/httpd-control.pid"
ErrorLog "{cls.logs}/error-control.log"
LogLevel warn
DocumentRoot "{cls.www}"
Options +ExecCGI
AddHandler cgi-script .cgi
<Directory "{cls.www}">
    Require all granted
</Directory>
""",
        )

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        stop_vapached(getattr(cls, "control_proc", None))
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def test_later_url_rewrite_replaces_stale_filesystem_target(self):
        status, _, body = request(self.port, "/app/sticky-target.cgi")
        self.assertEqual(status, 200, body[:300])
        self.assertIn(b"WALLET-F68-INDEX", body)
        self.assertNotIn(b"WALLET-F68-EXEC", body)

    def test_cgi_pipeline_executes_the_target_on_a_plain_url(self):
        # Capability control: the .cgi target is executable on a rewrite-free
        # server, so the sticky assertion genuinely proves the stale
        # filesystem override was replaced by the later URL rewrite rather
        # than the handler being unavailable.
        status, _, body = request(self.control_port, "/direct-target.cgi")
        self.assertEqual(status, 200, body[:300])
        self.assertIn(b"WALLET-F68-EXEC", body)


class UnsafePrefixStatWarningTests(unittest.TestCase):
    """[UnsafePrefixStat] is inert but must be acknowledged in the log (H2c/F32)."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-f32-warn-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "www"
        cls.logs = cls.base / "logs"
        for directory in (cls.www, cls.logs):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
RewriteEngine On
RewriteRule "^/unsafe/(.*)$" "{cls.base}/$1" [L,UnsafePrefixStat]
<Directory "{cls.www}">
    Require all granted
</Directory>
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def test_flag_is_parsed_with_a_load_time_warning(self):
        # The server loaded (setUpClass succeeded); stop it first so the
        # buffered startup output can be drained from the pipe.
        stop_vapached(self.proc)
        assert self.proc.stdout is not None
        output = self.proc.stdout.read().decode(errors="replace")
        self.assertIn("[UnsafePrefixStat]", output)
        self.assertIn("has no effect", output)


class F61ToF69Pass11Tests(unittest.TestCase):
    """Pass-11 replays: one live server carrying every guard idiom of the
    findings table, each over its own URL space.

    Rows and expected verdicts (Apache 2.4.69 oracle):
      F61-A   <Location "/admin/*"> Require all denied      -> 403
      F61-A2  <Location "/admopt/*"> Options -ExecCGI       -> 403
      F61-B   <Location ~ "^/regex/"> Require all denied    -> 403
      F61-C   control tree, no guard                        -> 200 executed
      F62     <Directory ".../f62/[^a]*"> Require all denied -> 403 (zdir,
              hello.html), 200 (adir)
      F62b    <Files "[^a]*.cgi"> Require all denied        -> 403 (run.cgi),
              200 (awake.cgi)
      F63     <If "%{REQUEST_FILENAME} =~ /private/"> deny  -> 403
      F63b    RewriteCond expr %{REQUEST_FILENAME} + [F]    -> 403
      F64     <Directory uploads> SetHandler default-handler -> 200 source
      F64b    F64 + attacker-written .htaccess AddHandler   -> 200 source
      F65     ScriptAlias tree + SetHandler default-handler -> 200 source
      F69     symlink link.txt -> secret.cgi                -> 200 source
      F66     <DirectoryMatch ".../privatematch/$"> guard    -> 403 (stays fixed)
    """

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-pass11-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "www"
        cls.logs = cls.base / "logs"
        for directory in (
            cls.www / "admin",
            cls.www / "admopt",
            cls.www / "regex",
            cls.www / "control",
            cls.www / "negcgi",
            cls.www / "private",
            cls.www / "privatematch",
            cls.www / "secret",
            cls.www / "public",
            cls.www / "uploads" / "attacker",
            cls.www / "cgibin",
            cls.base / "f62" / "adir",
            cls.base / "f62" / "zdir",
            cls.logs,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)

        def script(directory: Path, marker: str):
            path = directory / "run.cgi"
            path.write_text(
                "#!/bin/sh\n"
                "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
                f"printf 'EXEC-{marker} uid=%s\\n' \"$(id -u)\"\n"
            )
            path.chmod(0o755)

        script(cls.www / "admin", "ADMIN")
        script(cls.www / "admopt", "ADMOPT")
        script(cls.www / "regex", "REGEX")
        script(cls.www / "control", "CONTROL")
        script(cls.www / "negcgi", "NEGCgi")
        # A basename inside the [^a] class must stay positive: rename one copy
        # to awake.cgi (excluded from the class), keep run.cgi as the denied one.
        (cls.www / "negcgi" / "run.cgi").rename(cls.www / "negcgi" / "awake.cgi")
        script(cls.www / "negcgi", "NEGCgi")
        script(cls.www / "private", "PRIVATE")
        script(cls.www / "secret", "SECRET")
        script(cls.www / "uploads", "UPLOADS")
        script(cls.www / "uploads" / "attacker", "UPLOADSATT")
        script(cls.www / "cgibin", "CGIBIN")
        script(cls.base / "f62" / "adir", "ADIR")
        script(cls.base / "f62" / "zdir", "ZDIR")
        (cls.base / "f62" / "hello.html").write_text("f62\n")
        (cls.www / "hello.txt").write_text("hello\n")
        (cls.www / "administry").mkdir(parents=True, exist_ok=True)
        (cls.www / "administry" / "wallet.txt").write_text("WALLET-ADMINISTRY\n")
        (cls.www / "administry").chmod(0o755)
        (cls.www / "secret" / "index.html").write_text("WALLET-F63B-LEAK\n")
        # F69: the symlink target itself (direct requests hit the rewrite
        # guard; the symlink path classifies by the request basename).
        (cls.www / "secret" / "secret.cgi").write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'EXEC-SECRET uid=%s\\n' \"$(id -u)\"\n"
        )
        (cls.www / "secret" / "secret.cgi").chmod(0o755)
        (cls.www / "privatematch" / "index.html").write_text("WALLET-F66\n")
        # F69: a public symlink whose target basename would classify as CGI.
        (cls.www / "public" / "link.txt").symlink_to("../secret/secret.cgi")
        (cls.www / "public").chmod(0o755)
        # F64b: the whole attacker contribution is one writable file.
        (cls.www / "uploads" / "attacker" / ".htaccess").write_text(
            "AddHandler cgi-script .cgi\n"
        )

        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
AddHandler cgi-script .cgi
<Directory "{cls.www}">
    AllowOverride All
    Options +ExecCGI +FollowSymLinks
    Require all granted
    <If "%{{REQUEST_FILENAME}} =~ /private/">
        Require all denied
    </If>
</Directory>
<Location "/admin/*">
    Require all denied
</Location>
<Location "/admopt/*">
    Options -ExecCGI
</Location>
<Location ~ "^/regex/">
    Require all denied
</Location>
<Directory "{cls.base}/f62/[^a]*">
    Require all denied
</Directory>
<Directory "{cls.www}/negcgi">
    <Files "[^a]*.cgi">
        Require all denied
    </Files>
</Directory>
<Directory "{cls.www}/uploads">
    SetHandler default-handler
    AllowOverride FileInfo
</Directory>
<Directory "{cls.www}/cgibin">
    SetHandler default-handler
</Directory>
<DirectoryMatch "{cls.www}/privatematch/$">
    Require all denied
</DirectoryMatch>
ScriptAlias /cgibin/ "{cls.www}/cgibin/"
Alias /f62 "{cls.base}/f62/"
<Directory "{cls.base}/f62">
    Options +ExecCGI
    Require all granted
</Directory>
<Directory "{cls.base}/f62/[^a]*">
    Require all denied
</Directory>
RewriteEngine On
RewriteCond expr "%{{REQUEST_FILENAME}} =~ /secret/"
RewriteRule "^" "-" [F]
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def assert_executed(self, path: str, marker: bytes):
        status, _, body = request(self.port, path)
        self.assertEqual(status, 200, f"{path}: {body[:200]}")
        self.assertIn(marker, body, f"{path}: {body[:200]}")
        self.assertFalse(
            body.startswith(b"#!/bin/sh"), f"{path} served as source: {body[:120]}"
        )

    def assert_denied(self, path: str):
        status, _, body = request(self.port, path)
        self.assertEqual(status, 403, f"{path}: {body[:200]}")
        self.assertNotIn(b"uid=", body, f"{path}: {body[:200]}")

    def assert_source(self, path: str):
        status, _, body = request(self.port, path)
        self.assertEqual(status, 200, f"{path}: {body[:200]}")
        self.assertTrue(body.startswith(b"#!/bin/sh"), f"{path}: {body[:200]}")

    def test_f61_a_location_glob_deny_executes_nothing(self):
        # The shell-wildcard Location compiles at parse time and binds: the
        # script inside /admin is denied, a sibling prefix is not matched.
        self.assert_denied("/admin/run.cgi")
        status, _, body = request(self.port, "/administry/wallet.txt")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"WALLET-ADMINISTRY", body)

    def test_f61_a2_location_glob_options_execcgi_off(self):
        self.assert_denied("/admopt/run.cgi")

    def test_f61_b_location_regex_form_binds(self):
        self.assert_denied("/regex/run.cgi")

    def test_f61_c_control_tree_executes(self):
        # The fixture itself is viable: without a guard the CGI runs.
        self.assert_executed("/control/run.cgi", b"EXEC-CONTROL uid=")

    def test_f62_directory_class_negation_honors_caret(self):
        self.assert_denied("/f62/zdir/run.cgi")
        # The file's own path participates when the components line up.
        self.assert_denied("/f62/hello.html")
        # A name inside the class is NOT negated: the allow side stays live.
        self.assert_executed("/f62/adir/run.cgi", b"EXEC-ADIR uid=")

    def test_f62b_files_class_negation_honors_caret(self):
        self.assert_denied("/negcgi/run.cgi")
        self.assert_executed("/negcgi/awake.cgi", b"EXEC-NEGCgi uid=")

    def test_f63_if_request_filename_is_bound_and_deny_guards(self):
        self.assert_denied("/private/run.cgi")
        # The guard is keyed on the mapped path, not the URL string: a URL
        # outside the private tree is untouched.
        self.assert_executed("/control/run.cgi", b"EXEC-CONTROL uid=")

    def test_f63b_rewrite_cond_request_filename_fails_the_request(self):
        self.assert_denied("/secret/index.html")
        self.assert_denied("/secret/run.cgi")

    def test_f64_set_handler_beats_the_floor_add_handler(self):
        self.assert_source("/uploads/run.cgi")

    def test_f64b_attacker_htaccess_addhandler_cannot_rearm_execution(self):
        self.assert_source("/uploads/attacker/run.cgi")

    def test_f65_script_alias_honors_set_handler_default_handler(self):
        self.assert_source("/cgibin/run.cgi")

    def test_f69_symlink_classifies_by_request_basename(self):
        # Apache serves the canonical target as static source because the
        # request-mapped basename is link.txt, not secret.cgi.
        self.assert_source("/public/link.txt")

    def test_f66_directory_match_guard_stays_fixed(self):
        self.assert_denied("/privatematch/")


class P13LexicalHandlerIdentityTests(unittest.TestCase):
    """Every handler-selection path keeps the request-mapped basename.

    Canonical paths still supply containment, access checks and executable
    inode binding; they never supply a FastCGI/CGI classification or a
    Files-scoped SetHandler force.
    """

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-p13-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "www"
        cls.logs = cls.base / "logs"
        for directory in (
            cls.www / "public",
            cls.www / "fcgi",
            cls.www / "pathinfo",
            cls.www / "forced",
            cls.logs,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)

        (cls.www / "fcgi" / "app.php").write_text("PHP-SOURCE-P13\n")

        def script(path: Path, marker: str):
            path.write_text(
                "#!/bin/sh\n"
                "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
                f"printf '{marker} uid=%s\\n' \"$(id -u)\"\n"
            )
            path.chmod(0o755)

        script(cls.www / "pathinfo" / "run.run", "P13-PATHINFO-EXEC")
        script(cls.www / "forced" / "force.cgi", "P13-FORCE-EXEC")
        script(cls.www / "forced" / "access.cgi", "P13-ACCESS-EXEC")
        (cls.www / "public" / "php.txt").symlink_to("../fcgi/app.php")
        (cls.www / "public" / "path.txt").symlink_to("../pathinfo/run.run")
        (cls.www / "public" / "force.txt").symlink_to("../forced/force.cgi")
        (cls.www / "public" / "access.txt").symlink_to("../forced/access.cgi")

        cls.mock = FastCgiMock(cls.base / "fcgi.sock")
        cls.mock.start()
        cls.port = free_port()
        cls.config_text = f"""ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
AddHandler cgi-script .run
<FilesMatch "\\.php$">
    SetHandler "proxy:unix:{cls.base}/fcgi.sock|fcgi://localhost"
</FilesMatch>
<Directory "{cls.www}">
    Options +ExecCGI +FollowSymLinks
    Require all granted
</Directory>
<Directory "{cls.www}/forced">
    <FilesMatch "\\.cgi$">
        SetHandler cgi-script
    </FilesMatch>
    <Files "access.cgi">
        Require all denied
    </Files>
</Directory>
<Location "/fcgi/">
    Require all denied
</Location>
<Location "/pathinfo/">
    Require all denied
</Location>
<Location "/forced/">
    Require all denied
</Location>
"""
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "mock", None):
            cls.mock.stop()
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def test_p13_a_fastcgi_uses_lexical_basename(self):
        status, _, body = request(self.port, "/public/php.txt")
        self.assertEqual(status, 200, body[:200])
        self.assertEqual(body, b"PHP-SOURCE-P13\n")

    def test_p13_b_path_info_uses_lexical_script_basename(self):
        status, _, body = request(self.port, "/public/path.txt/x")
        self.assertEqual(status, 404, body[:200])
        self.assertNotIn(b"P13-PATHINFO-EXEC", body)

    def test_p13_c_files_sethandler_force_uses_lexical_basename(self):
        status, _, body = request(self.port, "/public/force.txt")
        self.assertEqual(status, 200, body[:200])
        self.assertTrue(body.startswith(b"#!/bin/sh"), body[:200])

    def test_canonical_files_access_rule_still_denies(self):
        status, _, body = request(self.port, "/public/access.txt")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"P13-ACCESS-EXEC", body)

    def test_canonical_location_guards_are_live_controls(self):
        for path in ("/fcgi/app.php", "/pathinfo/run.run", "/forced/force.cgi"):
            status, _, body = request(self.port, path)
            self.assertEqual(status, 403, f"{path}: {body[:200]}")


class P14ConfigRewriteHardeningTests(unittest.TestCase):
    """P14 phase-order, expression-root, header and chain regressions."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-p14-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "htdocs"  # Exercise the implicit DocumentRoot.
        cls.logs = cls.base / "logs"
        directories = [
            "grant/deep-deny",
            "grant/deep-auth",
            "grant/deep-static",
            "grant/deep-options",
            "grant/deep-match",
            "same",
            "deny/deep",
            "oracle",
            "remote",
        ]
        for rel in directories:
            path = cls.www / rel
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o755)
        cls.logs.mkdir(parents=True, exist_ok=True)
        cls.logs.chmod(0o777)

        def script(rel: str, marker: str):
            path = cls.www / rel
            path.write_text(
                "#!/bin/sh\n"
                "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
                f"printf '{marker} uid=%s\\n' \"$(id -u)\"\n"
            )
            path.chmod(0o755)

        for rel, marker in [
            ("grant/deep-deny/run.cgi", "P14-DENY-EXEC"),
            ("grant/deep-auth/auth.cgi", "P14-AUTH-EXEC"),
            ("grant/deep-static/run.cgi", "P14-STATIC-EXEC"),
            ("grant/deep-options/run.cgi", "P14-OPTIONS-EXEC"),
            ("grant/deep-match/match.cgi", "P14-MATCH-EXEC"),
            ("same/run.cgi", "P14-SAME-EXEC"),
            ("deny/deep/run.cgi", "P14-INVERSE-EXEC"),
        ]:
            script(rel, marker)
        (cls.www / "oracle" / "index.txt").write_text("ORACLE\n")
        (cls.www / "remote" / "index.txt").write_text("REMOTE\n")
        (cls.www / "public.txt").write_text("P14-CHAIN-PUBLIC\n")
        (cls.base / "users").write_text("nobody:{SHA}2jmj7l5rSw0yVb/vlWAYkK/YBwk=\n")

        (cls.www / "grant" / ".htaccess").write_text(
            "<Files \"run.cgi\">\n"
            "    Require all granted\n"
            "    SetHandler cgi-script\n"
            "    Options +ExecCGI\n"
            "</Files>\n"
            "<Files \"auth.cgi\">\n"
            "    Require all granted\n"
            "    SetHandler cgi-script\n"
            "</Files>\n"
            "<FilesMatch \"^match\\.cgi$\">\n"
            "    Require all granted\n"
            "    SetHandler cgi-script\n"
            "</FilesMatch>\n"
        )
        (cls.www / "same" / ".htaccess").write_text(
            '<Files "run.cgi">\nRequire all granted\nSetHandler cgi-script\n</Files>\n'
        )
        (cls.www / "deny" / ".htaccess").write_text(
            '<Files "run.cgi">\nRequire all denied\n</Files>\n'
        )

        cls.port = free_port()
        cls.config_text = f'''ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
AddHandler cgi-script .cgi
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy 127.0.0.1
<Directory "{cls.www}">
    AllowOverride All
    Options +ExecCGI
    Require all granted
</Directory>
<Directory "{cls.www}/grant/deep-deny">
    <Files "run.cgi">
        Require all denied
    </Files>
</Directory>
<Directory "{cls.www}/grant/deep-auth">
    <Files "auth.cgi">
        AuthType Basic
        AuthName "private"
        AuthUserFile "{cls.base}/users"
        Require valid-user
    </Files>
</Directory>
<Directory "{cls.www}/grant/deep-static">
    <Files "run.cgi">
        SetHandler default-handler
    </Files>
</Directory>
<Directory "{cls.www}/grant/deep-options">
    <Files "run.cgi">
        Options -ExecCGI
    </Files>
</Directory>
<Directory "{cls.www}/grant/deep-match">
    <FilesMatch "^match\\.cgi$">
        Require all denied
    </FilesMatch>
</Directory>
<Directory "{cls.www}/same">
    <Files "run.cgi">
        Require all denied
    </Files>
</Directory>
<Directory "{cls.www}/deny/deep">
    <Files "run.cgi">
        Require all granted
    </Files>
</Directory>
<Directory "{cls.www}/oracle">
    Require expr "file('etc/passwd') =~ /^root/"
</Directory>
<Directory "{cls.www}/remote">
    Require ip 198.51.100.1
</Directory>
RewriteEngine On
RewriteCond "%{{HTTP_USER_AGENT}}" "scanner"
RewriteRule "^/duplicate$" "-" [F,L]
RewriteCond "%{{HTTP:X-Gate}}" "=yes"
RewriteRule "^/chain$" "-" [C]
RewriteRule "^/chain$" "-" [C]
RewriteRule "^/chain$" "/public.txt" [PT,L]
'''
        cls.proc, cls.config = start_vapached(
            cls.base, cls.config_text, server_root=cls.base
        )

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def test_p14_a_deeper_files_require_beats_ancestor_access_grant(self):
        status, _, body = request(self.port, "/grant/deep-deny/run.cgi")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"P14-DENY-EXEC", body)

    def test_p14_a_deeper_basic_auth_beats_ancestor_access_grant(self):
        status, _, body = request(self.port, "/grant/deep-auth/auth.cgi")
        self.assertEqual(status, 401, body[:200])
        self.assertNotIn(b"P14-AUTH-EXEC", body)

    def test_p14_a_deeper_handler_and_options_cannot_be_rearmed(self):
        status, _, body = request(self.port, "/grant/deep-static/run.cgi")
        self.assertEqual(status, 200, body[:200])
        self.assertTrue(body.startswith(b"#!/bin/sh"), body[:200])
        status, _, body = request(self.port, "/grant/deep-options/run.cgi")
        self.assertEqual(status, 403, body[:200])
        self.assertNotIn(b"P14-OPTIONS-EXEC", body)

    def test_p14_a_filesmatch_and_ordering_controls(self):
        status, _, body = request(self.port, "/grant/deep-match/match.cgi")
        self.assertEqual(status, 403, body[:200])
        status, _, body = request(self.port, "/same/run.cgi")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"P14-SAME-EXEC", body)
        status, _, body = request(self.port, "/deny/deep/run.cgi")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"P14-INVERSE-EXEC", body)

    def test_p14_c_implicit_document_root_confines_require_expr_files(self):
        status, _, body = request(self.port, "/oracle/index.txt")
        self.assertEqual(status, 403, body[:200])

    def _raw(self, fields: bytes, target: bytes) -> tuple[int, bytes]:
        conn = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        conn.sendall(
            b"GET " + target + b" HTTP/1.1\r\nHost: localhost\r\n"
            + fields
            + b"Connection: close\r\n\r\n"
        )
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        conn.close()
        head, _, body = data.partition(b"\r\n\r\n")
        return int(head.splitlines()[0].split()[1]), body

    def test_p14_d_duplicate_policy_headers_are_merged(self):
        status, _ = self._raw(
            b"User-Agent: benign\r\nUser-Agent: scanner\r\n", b"/duplicate"
        )
        self.assertEqual(status, 403)
        status, _ = self._raw(
            b"X-Forwarded-For: 198.51.100.1\r\n"
            b"X-Forwarded-For: 203.0.113.1\r\n",
            b"/remote/index.txt",
        )
        self.assertEqual(status, 403)

    def test_p14_e_failed_chain_skips_the_complete_action_chain(self):
        status, body = self._raw(b"", b"/chain")
        self.assertEqual(status, 404, body[:200])
        status, body = self._raw(b"X-Gate: yes\r\n", b"/chain")
        self.assertEqual(status, 200, body[:200])
        self.assertIn(b"P14-CHAIN-PUBLIC", body)


class P15ApacheParityHardeningTests(unittest.TestCase):
    """P15 backend identity, RemoteIP and PCRE access-control parity."""

    @classmethod
    def setUpClass(cls):
        if not VAPACHED.exists():
            raise unittest.SkipTest(f"missing {VAPACHED}")
        cls.base = Path(tempfile.mkdtemp(prefix="vapache-p15-", dir="/tmp/opencode"))
        cls.base.chmod(0o755)
        cls.www = cls.base / "www"
        cls.logs = cls.base / "logs"
        directories = [
            "pub",
            "open",
            "secret",
            "handler",
            "handler-target",
            "handler-access",
            "handler-alias",
            "handler-regex",
            "handler-tcp",
            "handler-prefix",
            "remote",
            "expr-q",
            "expr-z",
            "expr-comment",
            "expr-k",
            "expr-not",
            "expr-rewrite",
            "expr-cgi",
        ]
        for rel in directories:
            path = cls.www / rel
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o755)
        cls.logs.mkdir(parents=True, exist_ok=True)
        cls.logs.chmod(0o777)

        (cls.www / "open" / "app.php").write_text("<?php echo 'OPEN';\n")
        (cls.www / "secret" / "app.php").write_text("<?php echo 'SECRET';\n")
        (cls.www / "pub" / "open.txt").symlink_to("../open/app.php")
        (cls.www / "pub" / "link.txt").symlink_to("../secret/app.php")
        (cls.www / "handler-target" / "app.php").write_text("<?php echo 'HANDLER';\n")
        (cls.www / "handler" / "link.txt").symlink_to("../handler-target/app.php")
        (cls.www / "handler" / "hop.txt").symlink_to("link.txt")
        for rel in [
            "handler-access",
            "handler-alias",
            "handler-regex",
            "handler-tcp",
            "handler-prefix",
        ]:
            if rel in {"handler-alias", "handler-regex"}:
                (cls.www / rel / "app.php").write_text("<?php echo 'HANDLER';\n")
                (cls.www / rel / "link.txt").symlink_to("app.php")
            else:
                (cls.www / rel / "link.txt").symlink_to("../handler-target/app.php")
        for rel, name in [
            ("expr-q", "secret.txt"),
            ("expr-z", "secret.txt"),
            ("expr-comment", "secret.txt"),
            ("expr-k", "secret.txt"),
            ("expr-not", "private.txt"),
            ("expr-rewrite", "secret.txt"),
            ("remote", "secret.txt"),
        ]:
            (cls.www / rel / name).write_text(f"P15-{rel}\n")
        cgi = cls.www / "expr-cgi" / "secret.cgi"
        cgi.write_text(
            "#!/bin/sh\n"
            "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
            "printf 'P15-EXPR-CGI-EXEC\\n'\n"
        )
        cgi.chmod(0o755)

        cls.mock = FastCgiMock(cls.base / "fcgi.sock")
        cls.mock.start()
        cls.tcp_fastcgi_port = free_port()
        cls.tcp_mock = TcpFastCgiMock(cls.tcp_fastcgi_port)
        cls.tcp_mock.start()
        (cls.www / "handler-access" / ".htaccess").write_text(
            f'SetHandler "proxy:unix:{cls.base}/fcgi.sock|fcgi://localhost"\n'
        )
        cls.port = free_port()
        cls.config_text = f'''ServerRoot "{cls.base}"
Listen 127.0.0.1:{cls.port}
ServerName localhost
PidFile "{cls.logs}/httpd.pid"
ErrorLog "{cls.logs}/error.log"
LogLevel warn
DocumentRoot "{cls.www}"
AddHandler cgi-script .cgi
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy 127.0.0.1
ProxyPassMatch "^/(.*\\.php(/.*)?)$" "unix:{cls.base}/fcgi.sock|fcgi://localhost{cls.www}/"
<Directory "{cls.www}">
    Options +ExecCGI +FollowSymLinks
    Require all granted
</Directory>
<Directory "{cls.www}/handler">
    SetHandler "proxy:unix:{cls.base}/fcgi.sock|fcgi://localhost"
</Directory>
Alias /p17-alias/ "{cls.www}/handler-alias/"
AliasMatch "^/p17-regex/(.*)$" "{cls.www}/handler-regex/$1"
<Directory "{cls.www}/handler-alias">
    SetHandler "proxy:unix:{cls.base}/fcgi.sock|fcgi://localhost"
</Directory>
<Directory "{cls.www}/handler-regex">
    SetHandler "proxy:unix:{cls.base}/fcgi.sock|fcgi://localhost"
</Directory>
<Directory "{cls.www}/handler-access">
    AllowOverride FileInfo
</Directory>
<Directory "{cls.www}/handler-tcp">
    SetHandler "proxy:fcgi://127.0.0.1:{cls.tcp_fastcgi_port}"
</Directory>
<Directory "{cls.www}/handler-prefix">
    SetHandler "proxy:unix:{cls.base}/fcgi.sock|fcgi://localhost{cls.www}/"
</Directory>
<Location "/secret/">
    Require all denied
</Location>
<Directory "{cls.www}/remote">
    Require ip 10.1.2.3
</Directory>
<Directory "{cls.www}/expr-q">
    <If "%{{REQUEST_URI}} =~ /\\Qsecret\\E/">
        Require all denied
    </If>
</Directory>
<Directory "{cls.www}/expr-z">
    <If "%{{REQUEST_URI}} =~ /secret\\.txt\\Z/">
        Require all denied
    </If>
</Directory>
<Directory "{cls.www}/expr-comment">
    <If "%{{REQUEST_URI}} =~ /sec(?#match)ret/">
        Require all denied
    </If>
</Directory>
<Directory "{cls.www}/expr-k">
    <If "%{{REQUEST_URI}} =~ /\\Ksecret/">
        Require all denied
    </If>
</Directory>
<Directory "{cls.www}/expr-not">
    <RequireAll>
        Require all granted
        Require not expr "%{{REQUEST_URI}} =~ /\\Qprivate\\E/"
    </RequireAll>
</Directory>
<Directory "{cls.www}/expr-cgi">
    <If "%{{REQUEST_URI}} =~ /\\Qsecret\\E/">
        Options -ExecCGI
    </If>
</Directory>
RewriteEngine On
RewriteCond expr "%{{REQUEST_URI}} =~ /\\Qexpr-rewrite\\E/"
RewriteRule "^/expr-rewrite/secret\\.txt$" "-" [F,L]
'''
        cls.proc, cls.config = start_vapached(cls.base, cls.config_text)

    @classmethod
    def tearDownClass(cls):
        stop_vapached(getattr(cls, "proc", None))
        if getattr(cls, "mock", None):
            cls.mock.stop()
        if getattr(cls, "tcp_mock", None):
            cls.tcp_mock.stop()
        if getattr(cls, "base", None):
            shutil.rmtree(getattr(cls, "base"), ignore_errors=True)

    def test_p15_a_fastcgi_forwards_lexical_script_identity(self):
        status, _, body = request(self.port, "/pub/open.txt/x.php")
        self.assertEqual(status, 200, body[:300])
        self.assertIn(
            f"SCRIPT_FILENAME={self.www}/pub/open.txt".encode(), body
        )
        self.assertIn(b"SCRIPT_NAME=/pub/open.txt", body)
        self.assertIn(b"PATH_INFO=/x.php", body)
        self.assertNotIn(f"SCRIPT_FILENAME={self.www}/open/app.php".encode(), body)

    def test_p17_sethandler_forwards_lexical_script_identity(self):
        status, _, body = request(self.port, "/handler/link.txt")
        self.assertEqual(status, 200, body[:300])
        self.assertIn(
            f"SCRIPT_FILENAME={self.www}/handler/link.txt".encode(), body
        )
        self.assertNotIn(
            f"SCRIPT_FILENAME={self.www}/handler-target/app.php".encode(), body
        )

    def test_p17_sethandler_routing_matrix_keeps_lexical_script_identity(self):
        cases = [
            (
                "/handler/hop.txt",
                self.www / "handler" / "hop.txt",
                self.www / "handler-target" / "app.php",
            ),
            (
                "/handler-access/link.txt",
                self.www / "handler-access" / "link.txt",
                self.www / "handler-target" / "app.php",
            ),
            (
                "/p17-alias/link.txt",
                self.www / "handler-alias" / "link.txt",
                self.www / "handler-alias" / "app.php",
            ),
            (
                "/p17-regex/link.txt",
                self.www / "handler-regex" / "link.txt",
                self.www / "handler-regex" / "app.php",
            ),
            (
                "/handler-tcp/link.txt",
                self.www / "handler-tcp" / "link.txt",
                self.www / "handler-target" / "app.php",
            ),
            (
                "/handler-prefix/link.txt",
                self.www / "handler-prefix" / "link.txt",
                self.www / "handler-target" / "app.php",
            ),
        ]
        for request_path, lexical_path, canonical_path in cases:
            with self.subTest(request_path=request_path):
                status, _, body = request(self.port, request_path)
                self.assertEqual(status, 200, body[:300])
                self.assertIn(f"SCRIPT_FILENAME={lexical_path}".encode(), body)
                self.assertNotIn(f"SCRIPT_FILENAME={canonical_path}".encode(), body)

    def test_p15_a_canonical_location_is_reauthorized(self):
        status, _, body = request(self.port, "/pub/link.txt/x.php")
        self.assertEqual(status, 403, body[:300])
        status, _, body = request(self.port, "/secret/app.php")
        self.assertEqual(status, 403, body[:300])

    def test_p15_b_trusted_proxy_cannot_present_private_address(self):
        for value in [
            "10.1.2.3",
            "8.8.8.8, 10.1.2.3",
            "::ffff:10.1.2.3",
            "10.1.2.3,",
        ]:
            status, _, body = request(
                self.port,
                "/remote/secret.txt",
                {"X-Forwarded-For": value},
            )
            self.assertEqual(status, 403, (value, body[:300]))

    def test_p15_c_supported_apache_pcre_guards_apply(self):
        for path in [
            "/expr-q/secret.txt",
            "/expr-z/secret.txt",
            "/expr-comment/secret.txt",
            "/expr-k/secret.txt",
            "/expr-not/private.txt",
            "/expr-rewrite/secret.txt",
        ]:
            status, _, body = request(self.port, path)
            self.assertEqual(status, 403, (path, body[:300]))

    def test_p15_c_conditional_options_cannot_disappear(self):
        status, _, body = request(self.port, "/expr-cgi/secret.cgi")
        self.assertEqual(status, 403, body[:300])
        self.assertNotIn(b"P15-EXPR-CGI-EXEC", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
