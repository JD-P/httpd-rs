#!/usr/bin/env python3
"""Apache-compatibility conformance suite for vapached.

Tests are ported/adapted from the behaviors exercised by httpd's own test
suite (Apache-Test t/apache/*, t/conf/*) and the HTTP RFCs, but implemented in
plain Python so they can run without a Perl Apache-Test harness.

Both the real httpd and vapached are started with equivalent configurations.
Every test asserts the required behavior on vapached and, when
`--differential` is enabled, compares the observable response with httpd and
records divergences for triage.

Usage:
    python3 tests/conformance.py            # run vapache assertions
    python3 tests/conformance.py -v         # verbose
    python3 tests/conformance.py --differential
"""

import argparse
import gzip
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import grp
import pwd
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import urlparse

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
BASE = Path(tempfile.mkdtemp(prefix="vapache-tests-"))
AP_PORT = int(os.environ.get("VAPACHE_AP_PORT", "18080"))
VP_PORT = int(os.environ.get("VAPACHE_VP_PORT", "18081"))
AP_TLS_PORT = int(os.environ.get("VAPACHE_AP_TLS_PORT", "18443"))
VP_TLS_PORT = int(os.environ.get("VAPACHE_VP_TLS_PORT", "18444"))
VP_MTLS_PORT = int(os.environ.get("VAPACHE_VP_MTLS_PORT", "18446"))
VP_OCSP_PORT = int(os.environ.get("VAPACHE_VP_OCSP_PORT", "18447"))
OCSP_RESPONDER_PORT = int(os.environ.get("VAPACHE_OCSP_RESPONDER_PORT", "18448"))
OCSP_SERVER = None
OCSP_RESPONSE = None
OCSP_REQUESTS = 0
SERVICE_USER = "www-data" if os.geteuid() == 0 else pwd.getpwuid(os.geteuid()).pw_name
SERVICE_GROUP = "www-data" if os.getegid() == 0 else grp.getgrgid(os.getegid()).gr_name

DIFFS = []
PROCS = []
FASTCGI_SOCK = BASE / "fastcgi.sock"
FASTCGI_STOP = threading.Event()
FASTCGI_LISTENER = None
PROXY_SERVER = None
PROXY_PORT = 0
PROXY2_SERVER = None
PROXY2_PORT = 0
PROXY_TLS_SERVER = None
PROXY_TLS_PORT = 0
WS_SERVER = None
WS_PORT = 0
WS_STOP = threading.Event()
WSS_SERVER = None
WSS_PORT = 0

class ProxyHandler(BaseHTTPRequestHandler):
    def _reply(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        payload = (
            f"{self.command} {self.path} "
            f"XTEST={self.headers.get('X-Test', '')} "
            f"XFF={self.headers.get('X-Forwarded-For', '')} "
            f"PORT={self.server.server_address[1]} "
            f"BODY={body.decode('latin-1')}\n"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Upstream", "yes")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _reply
    do_POST = _reply

    def log_message(self, *args):
        pass


def tree():
    os.chmod(BASE, 0o755)
    www = BASE / "www"
    (www / "dir").mkdir(parents=True, exist_ok=True)
    (www / "noidx").mkdir(parents=True, exist_ok=True)
    (www / "list").mkdir(parents=True, exist_ok=True)
    (www / "alias-target").mkdir(parents=True, exist_ok=True)
    (www / "cgi-bin").mkdir(parents=True, exist_ok=True)
    (www / "vhost").mkdir(parents=True, exist_ok=True)
    (www / "access").mkdir(parents=True, exist_ok=True)
    (www / "access" / "secret-dir").mkdir(parents=True, exist_ok=True)
    (www / "access" / "authmerge-and" / "child").mkdir(parents=True, exist_ok=True)
    (www / "access" / "authmerge-or" / "child").mkdir(parents=True, exist_ok=True)
    (www / "access" / "allowmethods").mkdir(parents=True, exist_ok=True)
    (www / "access" / "allowmethods-reset" / "child").mkdir(parents=True, exist_ok=True)
    (www / "access" / "elseif").mkdir(parents=True, exist_ok=True)
    (www / "access" / "protected-index").mkdir(parents=True, exist_ok=True)
    (www / "access" / "errordoc").mkdir(parents=True, exist_ok=True)
    (www / "auth" / "user").mkdir(parents=True, exist_ok=True)
    (www / "auth" / "group").mkdir(parents=True, exist_ok=True)
    (www / "auth" / "group-duplicate").mkdir(parents=True, exist_ok=True)
    (www / "group-unavailable").mkdir(parents=True, exist_ok=True)
    (www / "protected-cgi").mkdir(parents=True, exist_ok=True)
    for sub in ("deny", "auth", "options", "header", "bad", "rewrite", "rewrite-base", "cat-auth", "cat-options", "cat-bad", "cat-fileinfo", "cat-execcgi", "cat-optbad", "compress", "if", "limit", "allowmethods", "elseif", "idx-deny", "errordoc"):
        (www / "htaccess" / sub).mkdir(parents=True, exist_ok=True)
    (www / "dir").mkdir(exist_ok=True)
    (www / "dir-cgi").mkdir(exist_ok=True)
    (www / "errorcgi").mkdir(exist_ok=True)
    (www / "handler-unsupported").mkdir(exist_ok=True)
    (www / "filter-unsupported").mkdir(exist_ok=True)
    (www / "cgi-noexec").mkdir(exist_ok=True)
    (www / "dir-rewrite").mkdir(exist_ok=True)
    (www / "private").mkdir(exist_ok=True)
    (www / "index.html").write_text("<html><body>root index</body></html>\n")
    (www / "hello.txt").write_text("hello world\n")
    (www / "if-file.txt").write_text("present\n")
    (www / "index.php").write_text("<?php echo 'not executed locally';\n")
    (www / "handler.fphp").write_text("<?php echo 'handler target';\n")
    (www / "empty").write_bytes(b"")
    (www / "secret.txt").write_text("classified\n")
    (www / "trailing-guard.txt").write_text("trailing guard secret\n")
    (www / ".hidden").write_text("hidden\n")
    (www / "dir" / "index.html").write_text("<html>dir index</html>\n")
    (www / "dir" / "file.txt").write_text("dir file\n")
    (www / "dir-cgi" / "index.cgi").write_text(
        "#!/bin/sh\n"
        "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
        "printf 'CGI_INDEX_EXECUTED\\n'\n"
    )
    (www / "errorcgi" / "err.cgi").write_text(
        "#!/bin/sh\n"
        "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
        "printf 'ERROR_CGI_EXECUTED\\n'\n"
    )
    for p in [www / "dir-cgi" / "index.cgi", www / "errorcgi" / "err.cgi"]:
        os.chmod(p, 0o755)
    (www / "handler-unsupported" / "test.phtml").write_text("<?php echo 'secret';\n")
    (www / "filter-unsupported" / "test.html").write_text("<html>ssi source</html>\n")
    (www / "cgi-noexec" / "x.cgi").write_text("#!/bin/sh\necho CGI\n")
    (www / "noidx" / "a.txt").write_text("a\n")
    (www / "list" / "one.txt").write_text("one\n")
    (www / "list" / "two.txt").write_text("two\n")
    (www / "list" / "Space File.txt").write_text("space\n")
    (www / "alias-target" / "aliased.txt").write_text("alias works\n")
    (www / "sample.foo").write_text("custom type\n")
    (www / "large.bin").write_bytes(b"L" * (300 * 1024))
    (www / "huge.bin").write_bytes(b"H" * (9 * 1024 * 1024))
    (www / "access" / "ip-ok.txt").write_text("ip ok\n")
    (www / "access" / "ip-no.txt").write_text("ip no\n")
    (www / "access" / "method.txt").write_text("method\n")
    (www / "access" / "ip-not-local.txt").write_text("not local\n")
    (www / "access" / "local.txt").write_text("local\n")
    (www / "access" / "any.txt").write_text("any\n")
    (www / "access" / "env.txt").write_text("env ok\n")
    (www / "access" / "expr.txt").write_text("expr ok\n")
    (www / "access" / "require-all.txt").write_text("all\n")
    (www / "access" / "require-none.txt").write_text("none\n")
    (www / "access" / "require-any.txt").write_text("require any\n")
    (www / "access" / "limit-post.txt").write_text("limit post\n")
    (www / "access" / "limit-except.txt").write_text("limit except\n")
    (www / "access" / "limit-nested.txt").write_text("limit nested\n")
    (www / "access" / "satisfy-any.txt").write_text("satisfy any\n")
    (www / "access" / "satisfy-all.txt").write_text("satisfy all\n")
    (www / "access" / "authmerge-and" / "child" / "x.txt").write_text("authmerge and\n")
    (www / "access" / "authmerge-or" / "child" / "x.txt").write_text("authmerge or\n")
    (www / "access" / "allowmethods" / "x.txt").write_text("allowmethods\n")
    (www / "access" / "allowmethods-reset" / "child" / "x.txt").write_text("allowmethods reset\n")
    (www / "access" / "elseif" / "x.txt").write_text("elseif\n")
    (www / "access" / "protected-index" / "index.html").write_text("protected index\n")
    (www / "access" / "errordoc" / "secret.html").write_text("error doc secret\n")
    (www / "access" / "secret-dir" / "file.txt").write_text("directory match secret\n")
    (www / "notfound.html").write_text("<html>custom 404</html>\n")
    (www / "vhost" / "index.html").write_text("<html>vhost index</html>\n")
    (www / "auth" / "protected.txt").write_text("auth secret\n")
    (www / "auth" / "user" / "alice.txt").write_text("alice area\n")
    (www / "auth" / "group" / "staff.txt").write_text("staff area\n")
    (www / "auth" / "group-duplicate" / "staff.txt").write_text("staff area\n")
    (www / "group-unavailable" / "staff.txt").write_text("staff area\n")
    (www / "htaccess" / "deny" / "secret.txt").write_text("htaccess deny\n")
    (www / "htaccess" / "auth" / "secret.txt").write_text("htaccess auth\n")
    (www / "htaccess" / "auth" / "private.txt").write_text("htaccess auth\n")
    (www / "htaccess" / "header" / "hello.txt").write_text("htaccess header\n")
    (www / "htaccess" / "header" / ".htaccess").write_text(
        "Header set X-Htaccess yes\n"
    )
    (www / "htaccess" / "options" / ".htaccess").write_text("Options -Indexes\n")
    (www / "htaccess" / "bad" / "hello.txt").write_text("bad htaccess\n")
    (www / "htaccess" / "bad" / ".htaccess").write_text(
        "RewriteMap example txt:/tmp/map.txt\n"
    )
    (www / "htaccess" / "rewrite" / "old.html").write_text("rewrite old\n")
    (www / "htaccess" / "rewrite" / "new.html").write_text("rewrite new\n")
    (www / "htaccess" / "rewrite" / "moved.html").write_text("rewrite moved\n")
    (www / "htaccess" / "rewrite" / "blocked.html").write_text("rewrite blocked\n")
    (www / "target.html").write_text("rewrite target\n")
    (www / "private" / "secret.txt").write_text("rewrite private secret\n")
    (www / "htaccess" / "rewrite" / ".htaccess").write_text(
        "RewriteEngine On\n"
        "RewriteRule ^old\\.html$ new.html [L]\n"
        "RewriteRule ^moved\\.html$ /target.html [R=301,L]\n"
        "RewriteRule ^blocked\\.html$ - [F]\n"
        "RewriteCond %{QUERY_STRING} ^x=1$\n"
        "RewriteRule ^query\\.html$ new.html [L,QSA]\n"
    )
    (www / "htaccess" / "rewrite-base" / "old.html").write_text("rewrite-base old\n")
    (www / "htaccess" / "rewrite-base" / "new.html").write_text("rewrite-base wrong\n")
    (www / "target-base").mkdir(exist_ok=True)
    (www / "target-base" / "new.html").write_text("rewrite-base target\n")
    (www / "htaccess" / "rewrite-base" / ".htaccess").write_text(
        "RewriteEngine On\nRewriteBase /target-base/\nRewriteRule ^old\\.html$ new.html [L]\n"
    )
    (www / "htaccess" / "cat-auth" / "secret.txt").write_text("cat auth\n")
    (www / "htaccess" / "cat-auth" / ".htaccess").write_text("Require all denied\n")
    (www / "htaccess" / "cat-options" / ".htaccess").write_text("Options -Indexes\n")
    (www / "htaccess" / "cat-bad" / "hello.txt").write_text("cat bad\n")
    (www / "htaccess" / "cat-bad" / ".htaccess").write_text("Options -Indexes\n")
    (www / "htaccess" / "cat-execcgi" / "hello.txt").write_text("cat execcgi\n")
    (www / "htaccess" / "cat-execcgi" / ".htaccess").write_text("Options +ExecCGI\n")
    (www / "htaccess" / "cat-optbad" / "hello.txt").write_text("cat optbad\n")
    (www / "htaccess" / "cat-optbad" / ".htaccess").write_text("Options +Indexes\n")
    (www / "dir-rewrite" / "old.html").write_text("dir rewrite old\n")
    (www / "dir-rewrite" / "new.html").write_text("dir rewrite target\n")
    (www / "rewrite-features").mkdir(exist_ok=True)
    (www / "rewrite-features" / "target.txt").write_text("rewrite feature target\n")
    (www / "rewrite-features" / "abc.txt").write_text("lower map target\n")
    (BASE / "cacheroot").mkdir(exist_ok=True)
    os.chmod(BASE / "cacheroot", 0o777)
    (www / "cache").mkdir(exist_ok=True)
    (www / "cache" / "index.html").write_text("<html>cache index</html>\n")
    (www / "cache" / "file.txt").write_text("cache me\n")
    (www / "cache" / "file2.txt").write_text("cache me too\n")
    (www / "htaccess" / "if" / "hello.txt").write_text("conditional\n")
    (www / "htaccess" / "if" / ".htaccess").write_text(
        "<If \"%{HTTP:X-Test} == 'yes'\">\n"
        "    Require all denied\n"
        "</If>\n"
    )
    (www / "htaccess" / "compress" / "sample.foo").write_text("compressed custom type\n")
    (www / "htaccess" / "compress" / ".htaccess").write_text(
        "AddOutputFilterByType DEFLATE text/x-custom\n"
    )
    (www / "htaccess" / "limit" / "hello.txt").write_text("htaccess limit\n")
    (www / "htaccess" / "limit" / ".htaccess").write_text(
        "<Limit POST>\n"
        "    Require ip 10.0.0.0/8\n"
        "</Limit>\n"
    )
    (www / "htaccess" / "allowmethods" / "hello.txt").write_text("htaccess allowmethods\n")
    (www / "htaccess" / "allowmethods" / ".htaccess").write_text("AllowMethods POST\n")
    (www / "htaccess" / "elseif" / "hello.txt").write_text("htaccess elseif\n")
    (www / "htaccess" / "elseif" / ".htaccess").write_text(
        "<If \"%{HTTP:X-Branch} == 'a'\">\n"
        "    Header set X-Branch a\n"
        "    Require all granted\n"
        "</If>\n"
        "<ElseIf \"%{HTTP:X-Branch} == 'b'\">\n"
        "    Require all denied\n"
        "</ElseIf>\n"
        "<Else>\n"
        "    Require ip 192.0.2.0/24\n"
        "</Else>\n"
    )
    (www / "htaccess" / "idx-deny" / "index.html").write_text("htaccess protected index\n")
    (www / "htaccess" / "idx-deny" / ".htaccess").write_text(
        "<Files \"index.html\">\n"
        "    Require all denied\n"
        "</Files>\n"
    )
    (www / "htaccess" / "errordoc" / "secret.html").write_text("htaccess error doc secret\n")
    (www / "htaccess" / "errordoc" / ".htaccess").write_text(
        "ErrorDocument 404 /htaccess/errordoc/secret.html\n"
        "<Files \"secret.html\">\n"
        "    Require all denied\n"
        "</Files>\n"
    )
    (www / "htaccess" / "cat-fileinfo" / "old.html").write_text("cat fileinfo old\n")
    (www / "htaccess" / "cat-fileinfo" / "new.html").write_text("cat fileinfo new\n")
    (www / "htaccess" / "cat-fileinfo" / ".htaccess").write_text(
        "RewriteEngine On\nRewriteRule ^old\\.html$ new.html [L]\n"
    )
    (www / "htaccess" / "deny" / ".htaccess").write_text("Require all denied\n")
    (www / "htaccess" / "auth" / ".htaccess").write_text(
        "AuthType Basic\n"
        "AuthName \"Htaccess Realm\"\n"
        f"AuthUserFile \"{BASE}/.htpasswd\"\n"
        "Require valid-user\n"
    )
    import base64, hashlib
    def sha_line(user, password):
        digest = base64.b64encode(hashlib.sha1(password.encode()).digest()).decode()
        return f"{user}:{{SHA}}{digest}"
    (BASE / ".htpasswd").write_text(
        sha_line("alice", "alicepw") + "\n" + sha_line("bob", "bobpw") + "\n"
    )
    (BASE / ".htgroup").write_text("staff: alice\n")
    (BASE / ".htgroup-duplicate").write_text("staff: alice\nstaff: bob\n")
    os.chmod(BASE / ".htpasswd", 0o644)
    os.chmod(BASE / ".htgroup", 0o644)
    (www / "link.txt").symlink_to("hello.txt")
    (www / "link-private.txt").symlink_to("private/secret.txt")
    # Escape symlink: must never be followed outside the document root.
    (www / "escape").symlink_to("/etc")
    script = www / "cgi-bin" / "env.sh"
    script.write_text(
        "#!/bin/sh\n"
        "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
        "printf 'METHOD=%s\\n' \"$REQUEST_METHOD\"\n"
        "printf 'QUERY=%s\\n' \"$QUERY_STRING\"\n"
        "printf 'SCRIPT=%s\\n' \"$SCRIPT_NAME\"\n"
        "printf 'PATH_INFO=%s\\n' \"$PATH_INFO\"\n"
        "printf 'HTTP_X_TEST=%s\\n' \"$HTTP_X_TEST\"\n"
        "printf 'HTTP_PROXY=%s\\n' \"$HTTP_PROXY\"\n"
        "printf 'GREETING=%s\\n' \"$GREETING\"\n"
        "printf 'ALLOW_ME=%s\\n' \"$ALLOW_ME\"\n"
        "printf 'CONTENT_TYPE=%s\\n' \"$CONTENT_TYPE\"\n"
        "printf 'TRANSFER_ENCODING=%s\\n' \"$HTTP_TRANSFER_ENCODING\"\n"
        "printf 'REMOTE_USER=%s\\n' \"$REMOTE_USER\"\n"
        "printf 'AUTH_TYPE=%s\\n' \"$AUTH_TYPE\"\n"
        "printf 'BODY='; cat\n"
    )
    script.chmod(0o755)
    (www / "protected-cgi" / "who.sh").symlink_to("../cgi-bin/env.sh")
    script2 = www / "cgi-bin" / "status.sh"
    script2.write_text(
        "#!/bin/sh\n"
        "printf 'Status: 418 Teapot\\r\\n'\n"
        "printf 'X-CGI: yes\\r\\n'\n"
        "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
        "printf 'teapot\\n'\n"
    )
    script2.chmod(0o755)
    script3 = www / "cgi-bin" / "redirect.sh"
    script3.write_text(
        "#!/bin/sh\n"
        "printf 'Status: 302 Found\\r\\n'\n"
        "printf 'Location: /hello.txt\\r\\n'\n"
        "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
        "printf 'redirecting\\n'\n"
    )
    script3.chmod(0o755)
    script4 = www / "cgi-bin" / "mixed-boundary.sh"
    script4.write_text(
        "#!/bin/sh\n"
        "printf 'Content-Type: text/plain\\n\\n'\n"
        "printf 'Status: 302 Found\\r\\n'\n"
        "printf 'Location: /injected\\r\\n\\r\\n'\n"
        "printf 'body\\n'\n"
    )
    script4.chmod(0o755)
    script5 = www / "cgi-bin" / "no-content.sh"
    script5.write_text(
        "#!/bin/sh\n"
        "printf 'Status: 204 No Content\\r\\n'\n"
        "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
    )
    script5.chmod(0o755)
    script6 = www / "cgi-bin" / "reset-content.sh"
    script6.write_text(
        "#!/bin/sh\n"
        "printf 'Status: 205 Reset Content\\r\\n'\n"
        "printf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
        "printf 'body must not escape\\n'\n"
    )
    script6.chmod(0o755)
    for p in www.rglob("*"):
        if p.is_file() and not p.is_symlink():
            os.chmod(p, 0o644)
    for p in [www, www / "dir", www / "noidx", www / "list", www / "cgi-bin", www / "protected-cgi", www / "vhost"]:
        os.chmod(p, 0o755)
    for p in [www / "cgi-bin" / "env.sh", www / "cgi-bin" / "status.sh", www / "cgi-bin" / "redirect.sh", www / "cgi-bin" / "mixed-boundary.sh", www / "cgi-bin" / "no-content.sh", www / "cgi-bin" / "reset-content.sh", www / "dir-cgi" / "index.cgi", www / "errorcgi" / "err.cgi"]:
        p.chmod(0o755)
    cert = BASE / "cert.pem"
    key = BASE / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,DNS:vhost.test,IP:127.0.0.1",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", str(key), "-out", str(cert),
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    os.chmod(cert, 0o644)
    os.chmod(key, 0o644)
    vcert = BASE / "vhost-cert.pem"
    vkey = BASE / "vhost-key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=vhost.test",
            "-addext", "subjectAltName=DNS:vhost.test,DNS:www.vhost.test",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", str(vkey), "-out", str(vcert),
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    os.chmod(vcert, 0o644)
    os.chmod(vkey, 0o644)
    # Client-auth test material: a local CA plus a clientAuth leaf.
    ca_key = BASE / "client-ca.key"
    ca_cert = BASE / "client-ca.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=vapache-client-ca",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(ca_key), "-out", str(ca_cert),
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    client_key = BASE / "client.key"
    client_csr = BASE / "client.csr"
    client_cert = BASE / "client.pem"
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=vapache-client",
            "-keyout", str(client_key), "-out", str(client_csr),
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    ext = BASE / "client.ext"
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "extendedKeyUsage=clientAuth\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
    )
    subprocess.run(
        [
            "openssl", "x509", "-req", "-in", str(client_csr),
            "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
            "-days", "1", "-extfile", str(ext), "-out", str(client_cert),
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for p in (ca_cert, ca_key, client_cert, client_key):
        os.chmod(p, 0o644)
    # OCSP stapling material: a private CA, leaf certificate and a canned
    # OCSP response served by the local responder in start_servers().
    ocsp_ca_key = BASE / "ocsp-ca.key"
    ocsp_ca = BASE / "ocsp-ca.pem"
    ocsp_key = BASE / "ocsp-leaf.key"
    ocsp_csr = BASE / "ocsp-leaf.csr"
    ocsp_cert = BASE / "ocsp-leaf.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/CN=vapache-ocsp-ca",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(ocsp_ca_key), "-out", str(ocsp_ca),
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=ocsp.test",
            "-keyout", str(ocsp_key), "-out", str(ocsp_csr),
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    ocsp_ext = BASE / "ocsp-leaf.ext"
    ocsp_ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:ocsp.test,IP:127.0.0.1\n"
    )
    subprocess.run(
        [
            "openssl", "x509", "-req", "-in", str(ocsp_csr),
            "-CA", str(ocsp_ca), "-CAkey", str(ocsp_ca_key),
            "-CAcreateserial", "-days", "2", "-extfile", str(ocsp_ext),
            "-out", str(ocsp_cert),
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    ocsp_index = BASE / "ocsp-index.txt"
    expiry = time.strftime("%y%m%d%H%M%SZ", time.gmtime(time.time() + 2 * 86400))
    serial_output = subprocess.run(
        ["openssl", "x509", "-in", str(ocsp_cert), "-noout", "-serial"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    serial = serial_output.partition("=")[2]
    if not serial:
        raise RuntimeError("openssl did not report the OCSP leaf serial")
    ocsp_index.write_text(f"V\t{expiry}\t\t{serial}\tunknown\t/CN=ocsp.test\n")
    ocsp_der = BASE / "ocsp-response.der"
    subprocess.run(
        [
            "openssl", "ocsp", "-index", str(ocsp_index),
            "-rsigner", str(ocsp_ca), "-rkey", str(ocsp_ca_key),
            "-CA", str(ocsp_ca), "-issuer", str(ocsp_ca),
            "-cert", str(ocsp_cert), "-respout", str(ocsp_der), "-ndays", "1",
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    global OCSP_RESPONSE
    OCSP_RESPONSE = ocsp_der.read_bytes()
    for p in (ocsp_ca, ocsp_key, ocsp_cert, ocsp_der):
        os.chmod(p, 0o644)
    (BASE / "logs").mkdir(exist_ok=True)
    (BASE / "apache").mkdir(exist_ok=True)
    (BASE / "apache" / "logs").mkdir(exist_ok=True)


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


def fcgi_record(ty, content, request_id=1):
    pad = (8 - len(content) % 8) % 8
    return (
        struct.pack(">BBHHBB", 1, ty, request_id, len(content), pad, 0)
        + content
        + b"\0" * pad
    )


def fcgi_params(data):
    out = {}
    i = 0

    def length():
        nonlocal i
        if data[i] & 0x80:
            n = struct.unpack(">I", data[i : i + 4])[0] & 0x7FFFFFFF
            i += 4
        else:
            n = data[i]
            i += 1
        return n

    while i < len(data):
        nlen = length()
        vlen = length()
        name = data[i : i + nlen].decode("latin-1")
        i += nlen
        value = data[i : i + vlen].decode("latin-1")
        i += vlen
        out[name] = value
    return out


def fastcgi_connection(conn):
    params = {}
    body = b""
    try:
        while True:
            header = recv_exact(conn, 8)
            if header[0] != 1:
                return
            ty = header[1]
            n = struct.unpack(">H", header[4:6])[0]
            pad = header[6]
            content = recv_exact(conn, n + pad)[:n]
            if ty == 4:
                params.update(fcgi_params(content))
            elif ty == 5:
                if content:
                    body += content
                else:
                    payload = (
                        f"METHOD={params.get('REQUEST_METHOD', '')}\n"
                        f"SCRIPT={params.get('SCRIPT_FILENAME', '')}\n"
                        f"QUERY={params.get('QUERY_STRING', '')}\n"
                        f"XTEST={params.get('HTTP_X_TEST', '')}\n"
                        f"BODY={body.decode('latin-1')}\n"
                    ).encode()
                    out = (
                        fcgi_record(6, b"Content-Type: text/plain\r\n\r\n" + payload)
                        + fcgi_record(6, b"")
                        + fcgi_record(3, b"\0" * 8)
                    )
                    conn.sendall(out)
                    params = {}
                    body = b""
    except EOFError:
        pass
    finally:
        conn.close()


def fastcgi_loop(listener):
    while not FASTCGI_STOP.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=fastcgi_connection, args=(conn,), daemon=True).start()


def start_fastcgi_mock():
    global FASTCGI_LISTENER
    try:
        FASTCGI_SOCK.unlink()
    except FileNotFoundError:
        pass
    FASTCGI_LISTENER = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    FASTCGI_LISTENER.bind(str(FASTCGI_SOCK))
    os.chmod(FASTCGI_SOCK, 0o777)
    FASTCGI_LISTENER.listen(16)
    FASTCGI_LISTENER.settimeout(0.2)
    threading.Thread(target=fastcgi_loop, args=(FASTCGI_LISTENER,), daemon=True).start()


def stop_fastcgi_mock():
    FASTCGI_STOP.set()
    if FASTCGI_LISTENER is not None:
        try:
            FASTCGI_LISTENER.close()
        except OSError:
            pass
    try:
        FASTCGI_SOCK.unlink()
    except FileNotFoundError:
        pass


def start_http_mock():
    global PROXY_SERVER, PROXY_PORT, PROXY2_SERVER, PROXY2_PORT
    PROXY_SERVER = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    PROXY_PORT = PROXY_SERVER.server_address[1]
    threading.Thread(target=PROXY_SERVER.serve_forever, daemon=True).start()
    PROXY2_SERVER = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    PROXY2_PORT = PROXY2_SERVER.server_address[1]
    threading.Thread(target=PROXY2_SERVER.serve_forever, daemon=True).start()


def start_https_mock():
    global PROXY_TLS_SERVER, PROXY_TLS_PORT
    server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(BASE / "cert.pem"), str(BASE / "key.pem"))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    PROXY_TLS_SERVER = server
    PROXY_TLS_PORT = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()


def stop_http_mock():
    if PROXY_SERVER is not None:
        PROXY_SERVER.shutdown()
        PROXY_SERVER.server_close()
    if PROXY2_SERVER is not None:
        PROXY2_SERVER.shutdown()
        PROXY2_SERVER.server_close()
    if PROXY_TLS_SERVER is not None:
        PROXY_TLS_SERVER.shutdown()
        PROXY_TLS_SERVER.server_close()


def ws_connection(conn):
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        key = ""
        for line in head.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip().lower() == "sec-websocket-key":
                    key = v.strip()
        import base64, hashlib
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        conn.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode()
        )
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                return
            conn.sendall(chunk)
    except OSError:
        pass
    finally:
        conn.close()


def ws_loop(listener):
    while not WS_STOP.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=ws_connection, args=(conn,), daemon=True).start()


def start_ws_mock():
    global WS_SERVER, WS_PORT
    WS_SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    WS_SERVER.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    WS_SERVER.bind(("127.0.0.1", 0))
    WS_PORT = WS_SERVER.getsockname()[1]
    WS_SERVER.listen(8)
    WS_SERVER.settimeout(0.2)
    threading.Thread(target=ws_loop, args=(WS_SERVER,), daemon=True).start()


def wss_loop(listener, context):
    while not WS_STOP.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            conn = context.wrap_socket(conn, server_side=True)
        except ssl.SSLError:
            conn.close()
            continue
        threading.Thread(target=ws_connection, args=(conn,), daemon=True).start()


def start_wss_mock():
    global WSS_SERVER, WSS_PORT
    WSS_SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    WSS_SERVER.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    WSS_SERVER.bind(("127.0.0.1", 0))
    WSS_PORT = WSS_SERVER.getsockname()[1]
    WSS_SERVER.listen(8)
    WSS_SERVER.settimeout(0.2)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(BASE / "cert.pem"), str(BASE / "key.pem"))
    threading.Thread(target=wss_loop, args=(WSS_SERVER, ctx), daemon=True).start()


def stop_wss_mock():
    WS_STOP.set()
    if WSS_SERVER is not None:
        WSS_SERVER.close()


def stop_ws_mock():
    WS_STOP.set()
    if WS_SERVER is not None:
        WS_SERVER.close()


def common(port, root, apache, tls_port):
    lines = [
        f'ServerRoot "{root}"',
        f"Listen {port}",
        f"Listen {tls_port}",
        f"User {SERVICE_USER}",
        f"Group {SERVICE_GROUP}",
        f"PidFile {root}/logs/httpd.pid",
        f"ErrorLog {root}/logs/error.log",
        "LogLevel warn",
        "ServerName localhost",
        "RemoteIPHeader X-Forwarded-For",
        "RemoteIPInternalProxy 127.0.0.1",
        "ExpiresActive On",
        'ExpiresByType text/plain "access plus 1 hour"',
        'SetEnvIf X-Env yes GREETING=hello',
        'SetEnvIf X-Allow yes ALLOW_ME',
        '<If "%{HTTP:X-If} == \'yes\'">',
        "    Header set X-If yes",
        "</If>",
        f'<IfFile "{BASE}/www/if-file.txt">',
        "    Header set X-IfFile yes",
        "</IfFile>",
        "Timeout 30",
        "KeepAlive On",
        "MaxKeepAliveRequests 100",
        "KeepAliveTimeout 2",
        f'DocumentRoot "{BASE}/www"',
        f'TypesConfig /etc/mime.types',
        "DirectoryIndex index.html index.cgi",
        "AddType text/x-custom .foo",
        "AddHandler cgi-script .cgi .sh",
        "AddDefaultCharset UTF-8",
        "ServerTokens OS",
        "ServerSignature Off",
        "TraceEnable Off",
        f'ErrorDocument 404 "/notfound.html"',
        f'ScriptAlias /cgi-bin/ "{BASE}/www/cgi-bin/"',
        f'Alias /alias/ "{BASE}/www/alias-target/"',
        "Redirect 301 /old /hello.txt",
        f'<DirectoryMatch "^{BASE}/www/access/secret-dir">',
        "    Require all denied",
        "</DirectoryMatch>",
        '<Location "/access/ip-ok.txt">',
        "    Require ip 127.0.0.1",
        "</Location>",
        '<LocationMatch "^/trailing-guard\\.txt$">',
        "    Require all denied",
        "</LocationMatch>",
        '<Location "/access/ip-no.txt">',
        "    Require ip 10.0.0.0/8",
        "</Location>",
        '<Location "/access/method.txt">',
        "    Require method GET",
        "</Location>",
        '<Location "/access/local.txt">',
        "    Require local",
        "</Location>",
        '<Location "/server-status">',
        "    SetHandler server-status",
        "    Require local",
        "</Location>",
        '<Location "/cgi-bin/no-content.sh">',
        "    Header set Content-Length 12",
        "</Location>",
        '<Location "/cgi-bin/reset-content.sh">',
        "    Header set Content-Length 12",
        '    Header set Connection "keep-alive, X-Hop"',
        "    Header set X-Hop secret",
        "    Header set Keep-Alive timeout=99",
        "    Header set Proxy-Connection keep-alive",
        "    Header set Upgrade websocket",
        "    Header set TE trailers",
        "    Header set Trailer X-Later",
        "</Location>",
        '<Location "/access/expr.txt">',
        '    Require expr "%{REQUEST_METHOD} == \'GET\'"',
        "</Location>",
        '<Location "/access/env.txt">',
        "    Require env ALLOW_ME",
        "</Location>",
        '<Location "/access/any.txt">',
        "    Require ip 10.0.0.0/8",
        "    Require local",
        "</Location>",
        '<Location "/access/require-all.txt">',
        "    <RequireAll>",
        "        Require ip 127.0.0.1",
        "        Require local",
        "    </RequireAll>",
        "</Location>",
        '<Location "/access/require-none.txt">',
        "    <RequireAll>",
        "        Require all granted",
        "        <RequireNone>",
        "            Require ip 127.0.0.1",
        "        </RequireNone>",
        "    </RequireAll>",
        "</Location>",
        '<Location "/access/require-any.txt">',
        "    <RequireAny>",
        "        Require ip 10.0.0.0/8",
        "        Require local",
        "    </RequireAny>",
        "</Location>",
        '<Location "/access/limit-post.txt">',
        "    <Limit POST>",
        "        Require all denied",
        "    </Limit>",
        "</Location>",
        '<Location "/access/limit-except.txt">',
        "    <LimitExcept GET HEAD>",
        "        Require ip 10.0.0.0/8",
        "    </LimitExcept>",
        "</Location>",
        '<Location "/access/limit-nested.txt">',
        "    <Limit POST PUT>",
        "        <Limit POST>",
        "            Require all denied",
        "        </Limit>",
        "    </Limit>",
        "</Location>",
        '<Location "/access/satisfy-any.txt">',
        "    Require ip 10.0.0.0/8",
        "    Allow from all",
        "    Satisfy Any",
        "</Location>",
        '<Location "/access/satisfy-all.txt">',
        "    Require ip 127.0.0.1",
        "    Deny from all",
        "    Satisfy All",
        "</Location>",
        f'<Directory "{BASE}/www/access/authmerge-and">',
        "    Require ip 10.0.0.0/8",
        "</Directory>",
        f'<Directory "{BASE}/www/access/authmerge-and/child">',
        "    AuthMerging And",
        "    AuthType Basic",
        '    AuthName "Merge And"',
        f'    AuthUserFile "{BASE}/.htpasswd"',
        "    Require user alice",
        "</Directory>",
        f'<Directory "{BASE}/www/access/authmerge-or">',
        "    Require ip 127.0.0.1",
        "</Directory>",
        f'<Directory "{BASE}/www/access/authmerge-or/child">',
        "    AuthMerging Or",
        "    AuthType Basic",
        '    AuthName "Merge Or"',
        f'    AuthUserFile "{BASE}/.htpasswd"',
        "    Require user alice",
        "</Directory>",
        f'<Directory "{BASE}/www/access/allowmethods">',
        "    AllowMethods POST",
        "</Directory>",
        f'<Directory "{BASE}/www/access/allowmethods-reset">',
        "    AllowMethods POST",
        "</Directory>",
        f'<Directory "{BASE}/www/access/allowmethods-reset/child">',
        "    AllowMethods reset",
        "</Directory>",
        f'<Directory "{BASE}/www/access/elseif">',
        "    <If \"%{HTTP:X-Branch} == 'a'\">",
        "        Header set X-Branch a",
        "        Require all granted",
        "    </If>",
        "    <ElseIf \"%{HTTP:X-Branch} == 'b'\">",
        "        Require all denied",
        "    </ElseIf>",
        "    <Else>",
        "        Require ip 192.0.2.0/24",
        "    </Else>",
        "</Directory>",
        f'<Directory "{BASE}/www/access/protected-index">',
        '    <Files "index.html">',
        "        Require all denied",
        "    </Files>",
        "</Directory>",
        f'<Directory "{BASE}/www/access/errordoc">',
        "    ErrorDocument 404 /access/errordoc/secret.html",
        '    <Files "secret.html">',
        "        Require all denied",
        "    </Files>",
        "</Directory>",
        "LogFormat \"%h %l %u %t \\\"%r\\\" %>s %O\" common",
        f"CustomLog {root}/logs/access.log common",
        "RewriteMap lower int:tolower",
        f"CacheRoot {BASE}/cacheroot",
        "CacheEnable disk /cache/",
        "CacheHeader On",
        "CacheDefaultExpire 60",
        "<Directory />",
        "    AllowOverride None",
        "    Require all denied",
        "</Directory>",
        f'<Directory "{BASE}/www">',
        "    Options Indexes FollowSymLinks",
        "    AllowOverride None",
        "    Require all granted",
        "    RewriteEngine On",
        "    RewriteCond %{HTTP:X-Deny} yes",
        "    RewriteRule ^ - [F]",
        "</Directory>",
        f'<Directory "{BASE}/www/noidx">',
        "    Options -Indexes",
        "</Directory>",
        f'<Directory "{BASE}/www/cgi-bin">',
        "    Options ExecCGI FollowSymLinks",
        "    AllowOverride None",
        "    Require all granted",
        "</Directory>",
        f'<Directory "{BASE}/www/protected-cgi">',
        "    Options ExecCGI FollowSymLinks",
        "    AllowOverride None",
        "    AuthType Basic",
        '    AuthName "Protected CGI Realm"',
        f'    AuthUserFile "{BASE}/.htpasswd"',
        "    Require valid-user",
        "</Directory>",
        f'<Directory "{BASE}/www/htaccess">',
        "    AllowOverride All",
        "</Directory>",
        f'<Directory "{BASE}/www/htaccess/cat-auth">',
        "    AllowOverride AuthConfig",
        "</Directory>",
        f'<Directory "{BASE}/www/htaccess/cat-options">',
        "    AllowOverride Options",
        "</Directory>",
        f'<Directory "{BASE}/www/htaccess/cat-bad">',
        "    AllowOverride AuthConfig",
        "</Directory>",
        f'<Directory "{BASE}/www/htaccess/cat-fileinfo">',
        "    AllowOverride FileInfo",
        "</Directory>",
        f'<Directory "{BASE}/www/htaccess/cat-execcgi">',
        "    AllowOverride Options=ExecCGI",
        "</Directory>",
        f'<Directory "{BASE}/www/htaccess/cat-optbad">',
        "    AllowOverride Options=ExecCGI",
        "</Directory>",
        f'<Directory "{BASE}/www/dir-cgi">',
        "    Options ExecCGI FollowSymLinks",
        "    Require all granted",
        "</Directory>",
        f'<Directory "{BASE}/www/errorcgi">',
        "    Options ExecCGI FollowSymLinks",
        "    Require all granted",
        "    ErrorDocument 404 /errorcgi/err.cgi",
        "</Directory>",
        f'<Directory "{BASE}/www/handler-unsupported">',
        "    AddHandler application/x-httpd-php .phtml",
        "    Require all granted",
        "</Directory>",
        f'<Directory "{BASE}/www/filter-unsupported">',
        "    SetOutputFilter INCLUDES",
        "    Require all granted",
        "</Directory>",
        f'<Directory "{BASE}/www/cgi-noexec">',
        "    Require all granted",
        "</Directory>",
        f'<Directory "{BASE}/www/dir-rewrite">',
        "    Options FollowSymLinks",
        "    AllowOverride None",
        "    Require all granted",
        "    RewriteEngine On",
        "    RewriteRule ^old\\.html$ new.html [L]",
        "</Directory>",
        f'<Directory "{BASE}/www/private">',
        "    Require all denied",
        "</Directory>",
        f'<Directory "{BASE}/www/rewrite-features">',
        "    Options FollowSymLinks",
        "    AllowOverride None",
        "    Require all granted",
        "    RewriteEngine On",
        "    RewriteRule ^env$ - [E=TESTVAR:hello]",
        "    RewriteCond %{ENV:TESTVAR} ^hello$",
        "    RewriteRule ^env$ target.txt [L]",
        "    RewriteRule ^cookie$ - [CO=TEST:VAL:localhost:3600:/:secure:httponly:none]",
        "    RewriteRule ^typed$ target.txt [T=application/x-test]",
        "    RewriteRule ^map/(.*)$ ${lower:$1}.txt [L]",
        "    RewriteCond %{HTTP:Accept} feature-accept",
        "    RewriteRule ^vary$ target.txt [L]",
        f"    RewriteRule ^proxy/(.*)$ http://127.0.0.1:{PROXY_PORT}/app/$1 [P,L]",
        f"    RewriteRule ^proxy-acl/(.*)$ http://127.0.0.1:{PROXY_PORT}/acl/$1 [P,L]",
        f"    RewriteRule ^qsa-proxy$ http://127.0.0.1:{PROXY_PORT}/app?foo=bar [P,QSA,L]",
        f"    RewriteRule ^b/(.*)$ http://127.0.0.1:{PROXY_PORT}/app?$1 [P,B,L]",
        "</Directory>",
        '<Files "secret.txt">',
        "    Require all denied",
        "</Files>",
        '<FilesMatch "^\\.">',
        "    Require all denied",
        "</FilesMatch>",
        '<Location "/admin">',
        "    Require all denied",
        "</Location>",
        '<Location "/auth/">',
        "    AuthType Basic",
        '    AuthName "Test Realm"',
        f'    AuthUserFile "{BASE}/.htpasswd"',
        f'    AuthGroupFile "{BASE}/.htgroup"',
        "    Require valid-user",
        "</Location>",
        '<Location "/auth/user/">',
        "    AuthType Basic",
        '    AuthName "User Realm"',
        f'    AuthUserFile "{BASE}/.htpasswd"',
        "    Require user alice",
        "</Location>",
        '<Location "/auth/group/">',
        "    AuthType Basic",
        '    AuthName "Group Realm"',
        f'    AuthUserFile "{BASE}/.htpasswd"',
        f'    AuthGroupFile "{BASE}/.htgroup"',
        "    Require group staff",
        "</Location>",
        '<Location "/auth/group-duplicate/">',
        "    AuthType Basic",
        '    AuthName "Duplicate Group Realm"',
        f'    AuthUserFile "{BASE}/.htpasswd"',
        f'    AuthGroupFile "{BASE}/.htgroup-duplicate"',
        "    Require group staff",
        "</Location>",
        '<Location "/group-unavailable/">',
        "    AuthType Basic",
        '    AuthName "Unavailable Group Realm"',
        f'    AuthUserFile "{BASE}/.htpasswd"',
        "    <RequireAll>",
        "        Require valid-user",
        "        Require not group banned",
        "    </RequireAll>",
        "</Location>",
        "<IfModule mod_deflate.c>",
        "    AddOutputFilterByType DEFLATE text/html text/plain text/css text/javascript application/javascript",
        "    DeflateCompressionLevel 6",
        "</IfModule>",
        "<IfModule mod_brotli.c>",
        "    AddOutputFilterByType BROTLI_COMPRESS text/html text/plain text/css text/javascript application/javascript",
        "    BrotliCompressionQuality 5",
        "</IfModule>",
        f'<Proxy "http://127.0.0.1:{PROXY_PORT}/acl/*">',
        "    Require ip 10.0.0.0/8",
        "</Proxy>",
        f'<ProxyMatch "^http://127\\.0\\.0\\.1:{PROXY_PORT}/re/[0-9]+/">',
        "    Require all denied",
        "</ProxyMatch>",
        f'ProxyPass /proxy-acl http://127.0.0.1:{PROXY_PORT}/acl',
        f'ProxyPass /proxy-acl-re http://127.0.0.1:{PROXY_PORT}/re',
        f'ProxyPassMatch ^/(.*\\.php(/.*)?)$ "unix:{FASTCGI_SOCK}|fcgi://localhost{BASE}/www/"',
        f'ProxyPass /app http://127.0.0.1:{PROXY_PORT}/',
        f'ProxyPassReverse /app http://127.0.0.1:{PROXY_PORT}/',
        '<FilesMatch "\\.fphp$">',
        f'    SetHandler "proxy:unix:{FASTCGI_SOCK}|fcgi://localhost"',
        '</FilesMatch>',
        # Any <VirtualHost> on the port makes the first one the default server,
        # so keep a localhost vhost that serves the main document root.
        "<VirtualHost *:%d>" % port,
        "    ServerName localhost",
        f'    DocumentRoot "{BASE}/www"',
        "    RewriteEngine On",
        "    RewriteRule ^/from-config$ /hello.txt [L]",
        f'    RewriteRule ^/protected-rewrite$ "{BASE}/www/private/secret.txt" [L]',
        "</VirtualHost>",
        "<VirtualHost *:%d>" % port,
        "    ServerName vhost.test",
        "    ServerAlias www.vhost.test",
        f'    DocumentRoot "{BASE}/www/vhost"',
        f'    <Directory "{BASE}/www/vhost">',
        "        Options FollowSymLinks",
        "        Require all granted",
        "    </Directory>",
        "</VirtualHost>",
        "<VirtualHost *:%d>" % tls_port,
        "    ServerName localhost",
        "    SSLEngine on",
        f'    SSLCertificateFile "{BASE}/cert.pem"',
        f'    SSLCertificateKeyFile "{BASE}/key.pem"',
        f'    DocumentRoot "{BASE}/www"',
        "</VirtualHost>",
        "<VirtualHost *:%d>" % tls_port,
        "    ServerName vhost.test",
        "    SSLEngine on",
        f'    SSLCertificateFile "{BASE}/vhost-cert.pem"',
        f'    SSLCertificateKeyFile "{BASE}/vhost-key.pem"',
        f'    DocumentRoot "{BASE}/www/vhost"',
        "</VirtualHost>",
    ]
    if not apache:
        lines[0:0] = [
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
    if not apache:
        # vapached records LoadModule names for <IfModule>; the paths are not
        # opened and the module code is built in.
        lines = [
            "LoadModule filter_module %s/mod_filter.so" % MODDIR,
            "LoadModule deflate_module %s/mod_deflate.so" % MODDIR,
            "LoadModule brotli_module %s/mod_brotli.so" % MODDIR,
            "LoadModule proxy_module %s/mod_proxy.so" % MODDIR,
            "LoadModule proxy_fcgi_module %s/mod_proxy_fcgi.so" % MODDIR,
            "LoadModule proxy_http_module %s/mod_proxy_http.so" % MODDIR,
            "LoadModule remoteip_module %s/mod_remoteip.so" % MODDIR,
            f'ProxyPass /secure https://127.0.0.1:{PROXY_TLS_PORT}/',
            f"Listen {VP_MTLS_PORT}",
            f'<VirtualHost *:{VP_MTLS_PORT}>',
            "    ServerName localhost",
            "    SSLEngine on",
            f'    SSLCertificateFile "{BASE}/cert.pem"',
            f'    SSLCertificateKeyFile "{BASE}/key.pem"',
            "    SSLVerifyClient require",
            f'    SSLCACertificateFile "{BASE}/client-ca.pem"',
            f'    DocumentRoot "{BASE}/www"',
            "</VirtualHost>",
            f'SSLProxyCACertificateFile "{BASE}/cert.pem"',
            "<Proxy balancer://cluster>",
            f"    BalancerMember http://127.0.0.1:{PROXY_PORT}/",
            f"    BalancerMember http://127.0.0.1:{PROXY2_PORT}/",
            "</Proxy>",
            "ProxyPass /bal balancer://cluster/",
            "<Proxy balancer://healthcheck>",
            f"    BalancerMember http://127.0.0.1:{PROXY_PORT}/ hcmethod=GET hcuri=/health hcinterval=1 hcpasses=1 hcfails=1",
            "    BalancerMember http://127.0.0.1:1/ hcmethod=GET hcuri=/health hcinterval=1 hcpasses=1 hcfails=1",
            "</Proxy>",
            "ProxyPass /healthbal balancer://healthcheck/",
            f'ProxyPass /ws http://127.0.0.1:{WS_PORT}/',
            f'ProxyPass /wss wss://127.0.0.1:{WSS_PORT}/',
            f"Listen {VP_OCSP_PORT}",
            f"<VirtualHost *:{VP_OCSP_PORT}>",
            "    ServerName ocsp.test",
            "    SSLEngine on",
            f'    SSLCertificateFile "{BASE}/ocsp-leaf.pem"',
            f'    SSLCertificateKeyFile "{BASE}/ocsp-leaf.key"',
            f'    SSLCertificateChainFile "{BASE}/ocsp-ca.pem"',
            "    SSLUseStapling on",
            "    SSLStaplingStandardCacheTimeout 1",
            f"    SSLStaplingForceURL http://127.0.0.1:{OCSP_RESPONDER_PORT}/ocsp",
            f'    DocumentRoot "{BASE}/www"',
            "</VirtualHost>",
        ] + lines
    if apache:
        mods = [
            "LoadModule mpm_event_module %s/mod_mpm_event.so" % MODDIR,
            "LoadModule mime_module %s/mod_mime.so" % MODDIR,
            "LoadModule dir_module %s/mod_dir.so" % MODDIR,
            "LoadModule alias_module %s/mod_alias.so" % MODDIR,
            "LoadModule cgi_module %s/mod_cgi.so" % MODDIR,
            "LoadModule autoindex_module %s/mod_autoindex.so" % MODDIR,
            "LoadModule authz_core_module %s/mod_authz_core.so" % MODDIR,
            "LoadModule authz_host_module %s/mod_authz_host.so" % MODDIR,
            "LoadModule access_compat_module %s/mod_access_compat.so" % MODDIR,
            "LoadModule allowmethods_module %s/mod_allowmethods.so" % MODDIR,
            "LoadModule headers_module %s/mod_headers.so" % MODDIR,
            "LoadModule setenvif_module %s/mod_setenvif.so" % MODDIR,
            "LoadModule socache_shmcb_module %s/mod_socache_shmcb.so" % MODDIR,
            "LoadModule ssl_module %s/mod_ssl.so" % MODDIR,
            "LoadModule http2_module %s/mod_http2.so" % MODDIR,
            "LoadModule filter_module %s/mod_filter.so" % MODDIR,
            "LoadModule deflate_module %s/mod_deflate.so" % MODDIR,
            "LoadModule brotli_module %s/mod_brotli.so" % MODDIR,
            "LoadModule cache_module %s/mod_cache.so" % MODDIR,
            "LoadModule cache_disk_module %s/mod_cache_disk.so" % MODDIR,
            "LoadModule auth_basic_module %s/mod_auth_basic.so" % MODDIR,
            "LoadModule authn_core_module %s/mod_authn_core.so" % MODDIR,
            "LoadModule authn_file_module %s/mod_authn_file.so" % MODDIR,
            "LoadModule authz_user_module %s/mod_authz_user.so" % MODDIR,
            "LoadModule authz_groupfile_module %s/mod_authz_groupfile.so" % MODDIR,
            "LoadModule rewrite_module %s/mod_rewrite.so" % MODDIR,
            "LoadModule proxy_module %s/mod_proxy.so" % MODDIR,
            "LoadModule proxy_http_module %s/mod_proxy_http.so" % MODDIR,
            "LoadModule proxy_fcgi_module %s/mod_proxy_fcgi.so" % MODDIR,
            "LoadModule remoteip_module %s/mod_remoteip.so" % MODDIR,
            "LoadModule expires_module %s/mod_expires.so" % MODDIR,
            "LoadModule status_module %s/mod_status.so" % MODDIR,
            "Protocols h2 http/1.1",
        ]
        lines = mods + lines
    return "\n".join(lines) + "\n"


class OcspHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        global OCSP_REQUESTS
        OCSP_REQUESTS += 1
        length = int(self.headers.get("Content-Length", "0") or 0)
        self.rfile.read(length)
        body = OCSP_RESPONSE or b""
        self.send_response(200)
        self.send_header("Content-Type", "application/ocsp-response")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_ocsp_mock():
    global OCSP_SERVER
    OCSP_SERVER = ThreadingHTTPServer(("127.0.0.1", OCSP_RESPONDER_PORT), OcspHandler)
    threading.Thread(target=OCSP_SERVER.serve_forever, daemon=True).start()


def stop_ocsp_mock():
    global OCSP_SERVER
    if OCSP_SERVER is not None:
        OCSP_SERVER.shutdown()
        OCSP_SERVER.server_close()


def start_servers():
    tree()
    start_fastcgi_mock()
    start_http_mock()
    start_https_mock()
    start_ws_mock()
    start_wss_mock()
    start_ocsp_mock()
    acfg = BASE / "apache" / "httpd.conf"
    vcfg = BASE / "vapache-httpd.conf"
    acfg.write_text(common(AP_PORT, BASE / "apache", True, AP_TLS_PORT))
    vcfg.write_text(common(VP_PORT, BASE, False, VP_TLS_PORT))
    servers = [
        ("vapache", [str(VAPACHED), "-f", str(vcfg), "-DFOREGROUND"], BASE / "logs" / "vapache.out"),
    ]
    if DIFFERENTIAL:
        if not Path(APACHE).exists():
            raise SystemExit(f"missing Apache httpd at {APACHE} for --differential")
        servers.insert(
            0,
            ("apache", [APACHE, "-f", str(acfg), "-DFOREGROUND"], BASE / "logs" / "apache.out"),
        )
    for name, cmd, log in servers:
        f = open(log, "ab")
        p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        PROCS.append((name, p, f))
    ports = (AP_PORT, VP_PORT, AP_TLS_PORT, VP_TLS_PORT) if DIFFERENTIAL else (VP_PORT, VP_TLS_PORT)
    for port in ports:
        end = time.time() + 10
        while time.time() < end:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            print("server failed to start:")
            for name in ("apache", "vapache"):
                p = BASE / "logs" / f"{name}.out"
                if p.exists():
                    print(p.read_text()[-4000:])
            raise SystemExit(1)


def stop_servers():
    stop_fastcgi_mock()
    stop_http_mock()
    stop_ws_mock()
    stop_wss_mock()
    stop_ocsp_mock()
    for _, p, f in PROCS:
        if p.poll() is None:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        f.close()


def raw(port, data, read=True, timeout=3):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.sendall(data)
    out = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            out += b
            if not read:
                break
    except socket.timeout:
        pass
    s.close()
    return out


def parse_response(data):
    if b"\r\n\r\n" not in data:
        return None
    head, body = data.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", "replace")
    parts = status_line.split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers.setdefault(k.decode("latin-1").lower(), []).append(v.strip().decode("latin-1"))
    if "chunked" in ",".join(headers.get("transfer-encoding", [])).lower():
        decoded = b""
        rest = body
        while True:
            if b"\r\n" not in rest:
                break
            size_line, rest = rest.split(b"\r\n", 1)
            try:
                n = int(size_line.split(b";", 1)[0], 16)
            except ValueError:
                break
            if n == 0:
                break
            decoded += rest[:n]
            rest = rest[n + 2:]
        body = decoded
    return status, headers, body


def req(port, method="GET", path="/", headers=None, body=b"", version="HTTP/1.1", host=None):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    if host is None:
        host = f"localhost:{port}"
    h = {"Host": host, "Connection": "close"}
    if headers:
        h.update(headers)
    if body and not any(k.lower() in ("content-length", "transfer-encoding") for k in h):
        h["Content-Length"] = str(len(body))
    head = f"{method} {path} {version}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
    s.sendall(head.encode("latin-1") + body)
    out = b""
    while True:
        b = s.recv(65536)
        if not b:
            break
        out += b
    s.close()
    return parse_response(out)


def status_of(port, *a, **kw):
    r = req(port, *a, **kw)
    return r[0] if r else 0


class Base(unittest.TestCase):
    def get(self, path, headers=None, method="GET", body=b"", host=None, version="HTTP/1.1"):
        r = req(VP_PORT, method, path, headers, body, version=version, host=host)
        self.assertIsNotNone(r, f"no response for {path}")
        return r

    def differential(self, name, path, headers=None, method="GET", body=b"", compare_body=False, version="HTTP/1.1", host=None, compare_headers=True):
        if not DIFFERENTIAL:
            return
        a = req(AP_PORT, method, path, headers, body, version=version, host=host)
        v = req(VP_PORT, method, path, headers, body, version=version, host=host)
        if a is None or v is None:
            DIFFS.append((name, "missing response", a, v))
            return
        diffs = []
        if a[0] != v[0]:
            diffs.append(f"status {a[0]} != {v[0]}")
        if compare_headers:
            for h in ("content-type", "content-range", "accept-ranges", "location", "allow"):
                av = a[1].get(h, [None])[0]
                vv = v[1].get(h, [None])[0]
                if h == "location" and av and vv:
                    av = urlparse(av).path or av
                    vv = urlparse(vv).path or vv
                if h == "allow" and av and vv:
                    av = frozenset(x.strip() for x in av.split(",") if x.strip())
                    vv = frozenset(x.strip() for x in vv.split(",") if x.strip())
                if av != vv and not (h == "content-type" and av and vv and av.split(";")[0] == vv.split(";")[0]):
                    diffs.append(f"{h}: {av!r} != {vv!r}")
        if compare_body and a[2] != v[2]:
            diffs.append(f"body differs ({len(a[2])} vs {len(v[2])} bytes)")
        if diffs:
            DIFFS.append((name, "; ".join(diffs), a[0], v[0]))


class StaticTests(Base):
    def test_root_index(self):
        st, h, b = self.get("/")
        self.assertEqual(st, 200)
        self.assertIn(b"root index", b)
        self.assertEqual(h["content-type"][0].split(";")[0], "text/html")
        self.differential("root index", "/")

    def test_server_status_handler(self):
        st, h, body = self.get("/server-status")
        self.assertEqual(st, 200)
        self.assertIn(b"Server Status", body)
        st, h, body = self.get("/server-status?auto")
        self.assertEqual(st, 200)
        self.assertIn(b"Total Accesses", body)

    def test_if_and_iffile_sections(self):
        st, h, _ = self.get("/hello.txt")
        self.assertEqual(st, 200)
        self.assertNotIn("x-if", h)
        self.assertEqual(h["x-iffile"][0], "yes")
        st, h, _ = self.get("/hello.txt", headers={"X-If": "yes"})
        self.assertEqual(st, 200)
        self.assertEqual(h["x-if"][0], "yes")

    def test_expires_headers(self):
        st, h, _ = self.get("/hello.txt")
        self.assertEqual(st, 200)
        self.assertIn("expires", h)
        self.assertTrue(any("max-age=3600" in v for v in h.get("cache-control", [])))

    def test_require_expr(self):
        st, _, _ = self.get("/access/expr.txt")
        self.assertEqual(st, 200)
        st, _, _ = self.get("/access/expr.txt", method="POST")
        self.assertEqual(st, 403)

    def test_env_conditions_and_require_env(self):
        st, _, _ = self.get("/access/env.txt", headers={"X-Allow": "yes"})
        self.assertEqual(st, 200)
        st, _, _ = self.get("/access/env.txt")
        self.assertEqual(st, 403)

        st, _, body = self.get("/cgi-bin/env.sh", headers={"X-Env": "yes"})
        self.assertEqual(st, 200)
        self.assertIn(b"GREETING=hello", body)
        self.assertIn(b"ALLOW_ME=", body)

    def test_plain_file(self):
        st, h, b = self.get("/hello.txt")
        self.assertEqual((st, b), (200, b"hello world\n"))
        self.assertEqual(h["content-type"][0].split(";")[0], "text/plain")
        self.differential("plain file", "/hello.txt", compare_body=True)

    def test_head(self):
        st, h, b = self.get("/hello.txt", method="HEAD")
        self.assertEqual(st, 200)
        self.assertEqual(b, b"")
        self.assertEqual(h["content-length"][0], "12")
        self.differential("HEAD", "/hello.txt", method="HEAD")

    def test_404_custom(self):
        st, h, b = self.get("/missing")
        self.assertEqual(st, 404)
        self.assertIn(b"custom 404", b)
        self.differential("custom 404", "/missing")

    def test_directory_redirect(self):
        st, h, b = self.get("/dir")
        self.assertEqual(st, 301)
        self.assertEqual(h["location"][0], f"http://localhost:{VP_PORT}/dir/")
        self.differential("directory redirect", "/dir", compare_body=False)

    def test_directory_index(self):
        st, _, b = self.get("/dir/")
        self.assertEqual(st, 200)
        self.assertIn(b"dir index", b)
        self.differential("directory index", "/dir/", compare_body=True)

    def test_directory_forbidden_without_indexes(self):
        st, _, _ = self.get("/noidx/")
        self.assertEqual(st, 403)
        self.differential("directory no indexes", "/noidx/")

    def test_autoindex(self):
        st, h, b = self.get("/list/")
        self.assertEqual(st, 200)
        self.assertIn(b"one.txt", b)
        self.assertIn(b"two.txt", b)
        self.assertIn(b"Space%20File.txt", b)
        self.differential("autoindex", "/list/")

    def test_remoteip_rewrites_client_address(self):
        st, _, _ = self.get(
            "/access/ip-no.txt",
            headers={"X-Forwarded-For": "10.1.2.3"},
        )
        self.assertEqual(st, 200)
        st, _, _ = self.get("/access/ip-no.txt")
        self.assertEqual(st, 403)

    def test_access_require_ip(self):
        self.assertEqual(self.get("/access/ip-ok.txt")[0], 200)
        self.assertEqual(self.get("/access/ip-no.txt")[0], 403)
        self.differential("Require ip allow", "/access/ip-ok.txt", compare_body=True)
        self.differential("Require ip deny", "/access/ip-no.txt")

    def test_access_require_method(self):
        st, _, b = self.get("/access/method.txt")
        self.assertEqual((st, b), (200, b"method\n"))
        self.assertEqual(self.get("/access/method.txt", method="POST")[0], 403)
        self.differential("Require method", "/access/method.txt", compare_body=True)

    def test_access_local(self):
        self.assertEqual(self.get("/access/local.txt")[0], 200)
        self.differential("Require local", "/access/local.txt", compare_body=True)

    def test_access_multiple_requires_are_or(self):
        st, _, b = self.get("/access/any.txt")
        self.assertEqual((st, b), (200, b"any\n"))
        self.differential("RequireAny default", "/access/any.txt", compare_body=True)

    def test_access_require_groups(self):
        self.assertEqual(self.get("/access/require-all.txt")[0], 200)
        self.assertEqual(self.get("/access/require-none.txt")[0], 403)
        self.assertEqual(self.get("/access/require-any.txt")[0], 200)
        self.differential("RequireAll", "/access/require-all.txt", compare_body=True)
        self.differential("RequireNone", "/access/require-none.txt")
        self.differential("RequireAny", "/access/require-any.txt", compare_body=True)

    def test_access_limit_sections(self):
        self.assertEqual(self.get("/access/limit-post.txt")[0], 200)
        self.assertEqual(self.get("/access/limit-post.txt", method="POST")[0], 403)
        self.differential("Limit GET", "/access/limit-post.txt", compare_body=True)
        self.differential(
            "Limit POST", "/access/limit-post.txt", method="POST"
        )

        self.assertEqual(self.get("/access/limit-except.txt")[0], 200)
        self.assertEqual(self.get("/access/limit-except.txt", method="HEAD")[0], 200)
        self.assertEqual(self.get("/access/limit-except.txt", method="POST")[0], 403)
        self.differential("LimitExcept GET", "/access/limit-except.txt", compare_body=True)
        self.differential(
            "LimitExcept POST", "/access/limit-except.txt", method="POST"
        )

        # Nested <Limit> sections intersect their method sets.
        self.assertEqual(self.get("/access/limit-nested.txt")[0], 200)
        self.assertEqual(self.get("/access/limit-nested.txt", method="PUT")[0], 405)
        self.assertEqual(self.get("/access/limit-nested.txt", method="POST")[0], 403)
        self.differential("nested Limit POST", "/access/limit-nested.txt", method="POST")

    def test_access_satisfy(self):
        # Satisfy Any: the host allow rule bypasses the failing Require.
        self.assertEqual(self.get("/access/satisfy-any.txt")[0], 200)
        self.differential("Satisfy Any", "/access/satisfy-any.txt", compare_body=True)
        # Satisfy All: the host denial blocks access even though Require passes.
        self.assertEqual(self.get("/access/satisfy-all.txt")[0], 403)
        self.differential("Satisfy All", "/access/satisfy-all.txt")

    @staticmethod
    def basic(user, password):
        import base64

        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def test_access_auth_merging(self):
        # AuthMerging And: the parent IP requirement and child user
        # requirement must both pass.
        st, _, _ = self.get(
            "/access/authmerge-and/child/x.txt",
            headers=self.basic("alice", "alicepw"),
        )
        self.assertEqual(st, 403)
        self.differential(
            "AuthMerging And",
            "/access/authmerge-and/child/x.txt",
            headers=self.basic("alice", "alicepw"),
        )
        # AuthMerging Or: the parent IP requirement succeeds locally, so the
        # child user requirement is bypassed.
        st, _, _ = self.get("/access/authmerge-or/child/x.txt")
        self.assertEqual(st, 200)
        self.differential("AuthMerging Or", "/access/authmerge-or/child/x.txt")

    def test_access_allowmethods(self):
        st, h, _ = self.get("/access/allowmethods/x.txt")
        self.assertEqual(st, 405)
        self.assertIn("POST", h.get("allow", [""])[0])
        self.differential(
            "AllowMethods deny GET",
            "/access/allowmethods/x.txt",
            compare_headers=False,
        )
        # reset in a deeper directory removes the inherited restriction.
        self.assertEqual(self.get("/access/allowmethods-reset/child/x.txt")[0], 200)
        self.differential(
            "AllowMethods reset", "/access/allowmethods-reset/child/x.txt"
        )

    def test_access_proxy_containers(self):
        # <Proxy> rules are matched against the backend URL and enforced for
        # proxied requests.
        self.assertEqual(self.get("/proxy-acl/foo")[0], 403)
        self.differential("Proxy deny", "/proxy-acl/foo")
        # <ProxyMatch> matches only the numeric backend path.
        self.assertEqual(self.get("/proxy-acl-re/42/x")[0], 403)
        self.differential("ProxyMatch deny", "/proxy-acl-re/42/x")
        self.assertEqual(self.get("/proxy-acl-re/abc/x")[0], 200)
        self.differential("ProxyMatch allow", "/proxy-acl-re/abc/x")
        # [P] rewrites also enforce matching <Proxy> authorization.
        self.assertEqual(self.get("/rewrite-features/proxy-acl/foo")[0], 403)
        self.differential(
            "rewrite [P] Proxy deny", "/rewrite-features/proxy-acl/foo"
        )

    def test_access_elseif_else(self):
        st, h, _ = self.get(
            "/access/elseif/x.txt", headers={"X-Branch": "a"}
        )
        self.assertEqual((st, h.get("x-branch")), (200, ["a"]))
        self.differential(
            "ElseIf first branch", "/access/elseif/x.txt", headers={"X-Branch": "a"}
        )
        self.assertEqual(
            self.get("/access/elseif/x.txt", headers={"X-Branch": "b"})[0],
            403,
        )
        self.differential(
            "ElseIf second branch", "/access/elseif/x.txt", headers={"X-Branch": "b"}
        )
        self.assertEqual(self.get("/access/elseif/x.txt")[0], 403)
        self.differential("Else branch", "/access/elseif/x.txt")

    def test_access_internal_subrequests(self):
        # DirectoryIndex must not bypass authorization on the index file.
        self.assertEqual(self.get("/access/protected-index/")[0], 403)
        self.assertEqual(self.get("/access/protected-index/index.html")[0], 403)
        self.differential(
            "DirectoryIndex authorization", "/access/protected-index/"
        )
        # A protected local ErrorDocument must fall back to the normal error
        # body instead of leaking the protected file.
        st, _, body = self.get("/access/errordoc/missing")
        self.assertEqual(st, 404)
        self.assertNotIn(b"error doc secret", body)
        self.differential(
            "ErrorDocument authorization", "/access/errordoc/missing"
        )

    def test_internal_subrequest_handlers(self):
        # DirectoryIndex must dispatch through CGI, not serve source.
        st, _, body = self.get("/dir-cgi/")
        self.assertEqual((st, body), (200, b"CGI_INDEX_EXECUTED\n"))
        self.differential("DirectoryIndex CGI", "/dir-cgi/", compare_body=True)
        # A local ErrorDocument must also run through the handler chain.
        st, _, body = self.get("/errorcgi/missing")
        self.assertEqual(st, 404)
        self.assertIn(b"ERROR_CGI_EXECUTED", body)
        self.differential(
            "ErrorDocument CGI", "/errorcgi/missing", compare_body=True
        )

    def test_unsupported_handlers_and_filters_fail_closed(self):
        # A handler for an in-process module we do not implement must not
        # expose the file as static source.
        self.assertEqual(self.get("/handler-unsupported/test.phtml")[0], 500)
        # Unimplemented filters (SSI here) must fail closed rather than
        # serving the unfiltered source.
        self.assertEqual(self.get("/filter-unsupported/test.html")[0], 500)
        # cgi-script without ExecCGI must not fall through to static serving;
        # Apache denies it with 403.
        self.assertEqual(self.get("/cgi-noexec/x.cgi")[0], 403)

    def test_access_directory_match(self):
        self.assertEqual(self.get("/access/secret-dir/file.txt")[0], 403)
        self.differential("DirectoryMatch deny", "/access/secret-dir/file.txt")

    def test_access_location_boundary(self):
        # <Location "/access/ip-ok.txt"> must not leak to a sibling prefix.
        self.assertEqual(self.get("/access/ip-ok.txt.bak")[0], 404)

    def test_secret_denied(self):
        self.assertEqual(self.get("/secret.txt")[0], 403)
        self.differential("Files denied", "/secret.txt")

    def test_dotfile_denied(self):
        self.assertEqual(self.get("/.hidden")[0], 403)
        self.differential("FilesMatch dotfile", "/.hidden")

    def test_alias(self):
        st, _, b = self.get("/alias/aliased.txt")
        self.assertEqual((st, b), (200, b"alias works\n"))
        self.differential("alias", "/alias/aliased.txt", compare_body=True)

    def test_redirect(self):
        st, h, _ = self.get("/old")
        self.assertEqual(st, 301)
        self.assertEqual(h["location"][0], f"http://localhost:{VP_PORT}/hello.txt")
        self.differential("Redirect", "/old")

    def test_addtype(self):
        st, h, _ = self.get("/sample.foo")
        self.assertEqual(st, 200)
        self.assertEqual(h["content-type"][0].split(";")[0], "text/x-custom")
        self.differential("AddType", "/sample.foo")

    def test_empty_file(self):
        st, h, b = self.get("/empty")
        self.assertEqual((st, b), (200, b""))
        self.assertEqual(h["content-length"][0], "0")
        self.differential("empty file", "/empty")

    def test_symlink_inside_root(self):
        st, _, b = self.get("/link.txt")
        self.assertEqual((st, b), (200, b"hello world\n"))
        self.differential("symlink inside", "/link.txt", compare_body=True)

    def test_symlink_protected_target_denied(self):
        st, _, b = self.get("/link-private.txt")
        self.assertEqual(st, 403)
        self.assertNotIn(b"rewrite private secret", b)

    def test_symlink_escape_denied(self):
        st, _, b = self.get("/escape/passwd")
        self.assertEqual(st, 403)
        self.assertNotIn(b"root:", b)

    def test_percent_encoding(self):
        st, _, b = self.get("/list/Space%20File.txt")
        self.assertEqual((st, b), (200, b"space\n"))
        self.differential("percent space", "/list/Space%20File.txt", compare_body=True)

    def test_traversal_encoded(self):
        for p in ("/../etc/passwd", "/%2e%2e/etc/passwd", "/dir/../../etc/passwd"):
            st, _, b = self.get(p)
            self.assertIn(st, (400, 404), p)
            self.assertNotIn(b"root:", b, p)
        self.differential("traversal", "/../etc/passwd")

    def test_encoded_slash_rejected(self):
        st, _, _ = self.get("/dir%2ffile.txt")
        self.assertEqual(st, 404)
        self.differential("encoded slash", "/dir%2ffile.txt")

    def test_encoded_nul(self):
        st, _, b = self.get("/hello%00.txt")
        self.assertIn(st, (400, 404))
        self.assertNotIn(b"hello world", b)
        self.differential("encoded NUL", "/hello%00.txt")

    def test_backslash_rejected(self):
        st, _, _ = self.get("/dir%5cfile.txt")
        self.assertIn(st, (400, 404))

    def test_trailing_slash_never_serves_a_regular_file(self):
        for path in (
            "/hello.txt/",
            "/hello.txt//",
            "/dir/../hello.txt/",
        ):
            st, _, body = self.get(path)
            self.assertEqual(st, 404, path)
            self.assertNotIn(b"hello world", body, path)
            self.differential(f"regular file trailing slash {path}", path)

        # The exact URL is denied by the anchored LocationMatch; its slash
        # spelling must be rejected as a non-directory rather than serving
        # the same protected inode under a different URL identity.
        self.assertEqual(self.get("/trailing-guard.txt")[0], 403)
        st, _, body = self.get("/trailing-guard.txt/")
        self.assertEqual(st, 404)
        self.assertNotIn(b"trailing guard secret", body)

        # Preserve real-handler dispatch for trailing path-info spellings.
        st, _, body = self.get("/cgi-bin/env.sh/")
        self.assertEqual(st, 200)
        self.assertIn(b"METHOD=GET", body)

    def test_options_star(self):
        st, h, _ = self.get("*", method="OPTIONS")
        self.assertEqual(st, 200)
        self.assertIn("allow", h)
        self.assertEqual(h["x-iffile"][0], "yes")
        self.differential("OPTIONS *", "*", method="OPTIONS")

    def test_asterisk_target_is_options_only(self):
        for method in ("GET", "HEAD"):
            st, _, body = self.get("*", method=method)
            self.assertEqual(st, 400)
            self.assertNotIn(b"index", body.lower())

    def test_unknown_method(self):
        st, _, _ = self.get("/hello.txt", method="FROBNICATE")
        self.assertEqual(st, 501)
        self.differential("unknown method", "/hello.txt", method="FROBNICATE")

    def test_post_static(self):
        st, h, _ = self.get("/hello.txt", method="POST", body=b"x")
        self.assertEqual(st, 405)
        self.assertIn("allow", h)
        self.differential("POST static", "/hello.txt", method="POST", body=b"x")

    def test_trace_disabled(self):
        st, _, _ = self.get("/hello.txt", method="TRACE")
        self.assertEqual(st, 405)
        self.differential("TRACE off", "/hello.txt", method="TRACE")

    def test_etag_and_last_modified(self):
        st, h, _ = self.get("/hello.txt")
        self.assertEqual(st, 200)
        self.assertIn("etag", h)
        self.assertIn("last-modified", h)
        self.assertRegex(h["etag"][0], r'^"[0-9a-f-]+"$')

    def test_if_none_match(self):
        _, h, _ = self.get("/hello.txt")
        etag = h["etag"][0]
        st, h, b = self.get("/hello.txt", headers={"If-None-Match": etag})
        self.assertEqual((st, b), (304, b""))
        self.assertEqual(h["x-iffile"][0], "yes")

    def test_if_modified_since(self):
        _, h, _ = self.get("/hello.txt")
        lm = h["last-modified"][0]
        st, _, b = self.get("/hello.txt", headers={"If-Modified-Since": lm})
        self.assertEqual((st, b), (304, b""))
        st, _, _ = self.get("/hello.txt", headers={"If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"})
        self.assertEqual(st, 200)

    def test_if_match_failure(self):
        st, _, _ = self.get("/hello.txt", headers={"If-Match": '"nope"'})
        self.assertEqual(st, 412)

    def test_if_unmodified_since_failure(self):
        st, _, _ = self.get("/hello.txt", headers={"If-Unmodified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"})
        self.assertEqual(st, 412)

    def test_range(self):
        st, h, b = self.get("/hello.txt", headers={"Range": "bytes=0-4"})
        self.assertEqual((st, b), (206, b"hello"))
        self.assertEqual(h["content-range"][0], "bytes 0-4/12")
        self.differential("range", "/hello.txt", headers={"Range": "bytes=0-4"}, compare_body=True)

    def test_range_suffix(self):
        st, h, b = self.get("/hello.txt", headers={"Range": "bytes=-6"})
        self.assertEqual((st, b), (206, b"world\n"))
        self.assertEqual(h["content-range"][0], "bytes 6-11/12")
        self.differential("suffix range", "/hello.txt", headers={"Range": "bytes=-6"}, compare_body=True)

    def test_range_open(self):
        st, _, b = self.get("/hello.txt", headers={"Range": "bytes=6-"})
        self.assertEqual((st, b), (206, b"world\n"))
        self.differential("open range", "/hello.txt", headers={"Range": "bytes=6-"}, compare_body=True)

    def test_range_unsatisfiable(self):
        st, h, _ = self.get("/hello.txt", headers={"Range": "bytes=100-200"})
        self.assertEqual(st, 416)
        self.assertEqual(h["content-range"][0], "bytes */12")
        self.differential("416 range", "/hello.txt", headers={"Range": "bytes=100-200"})

    def test_range_invalid_ignored(self):
        st, _, b = self.get("/hello.txt", headers={"Range": "bytes=abc"})
        self.assertEqual((st, b), (200, b"hello world\n"))

    def test_if_range_match(self):
        _, h, _ = self.get("/hello.txt")
        etag = h["etag"][0]
        st, h, b = self.get(
            "/hello.txt", headers={"Range": "bytes=0-4", "If-Range": etag}
        )
        self.assertEqual((st, b), (206, b"hello"))
        self.assertEqual(h["content-range"][0], "bytes 0-4/12")

    def test_if_none_match_star(self):
        st, _, b = self.get("/hello.txt", headers={"If-None-Match": "*"})
        self.assertEqual((st, b), (304, b""))
        # Conditional headers must not turn a missing resource into a 304.
        st, _, _ = self.get("/missing", headers={"If-None-Match": "*"})
        self.assertEqual(st, 404)

    def test_if_match_star(self):
        st, _, b = self.get("/hello.txt", headers={"If-Match": "*"})
        self.assertEqual((st, b), (200, b"hello world\n"))

    def test_options_resource(self):
        st, h, _ = self.get("/hello.txt", method="OPTIONS")
        self.assertEqual(st, 200)
        allow = h.get("allow", [""])[0]
        self.assertIn("GET", allow)
        self.assertIn("HEAD", allow)
        self.assertEqual(h["content-type"][0].split(";")[0], "text/plain")
        self.assertEqual(h["x-iffile"][0], "yes")
        self.assertIn("expires", h)
        self.assertTrue(any("max-age=3600" in v for v in h.get("cache-control", [])))
        self.assertEqual(self.get("/missing", method="OPTIONS")[0], 200)
        # Resource OPTIONS must not bypass access control.
        self.assertEqual(self.get("/secret.txt", method="OPTIONS")[0], 403)
        self.differential("OPTIONS resource", "/hello.txt", method="OPTIONS")

    def test_expect_100_continue(self):
        s = socket.create_connection(("127.0.0.1", VP_PORT), timeout=5)
        s.sendall(
            b"POST /cgi-bin/env.sh HTTP/1.1\r\nHost: localhost\r\n"
            b"Content-Type: text/plain\r\nContent-Length: 5\r\n"
            b"Expect: 100-continue\r\nConnection: close\r\n\r\n"
        )
        interim = b""
        while b"\r\n\r\n" not in interim:
            interim += s.recv(65536)
        self.assertTrue(interim.startswith(b"HTTP/1.1 100 Continue"), interim)
        s.sendall(b"hello")
        out = interim.split(b"\r\n\r\n", 1)[1]
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
        s.close()
        r = parse_response(out)
        self.assertEqual(r[0], 200)
        self.assertIn(b"BODY=hello", r[2])

    def test_chunked_trailers(self):
        s = socket.create_connection(("127.0.0.1", VP_PORT), timeout=5)
        s.sendall(
            b"POST /cgi-bin/env.sh HTTP/1.1\r\nHost: localhost\r\n"
            b"Transfer-Encoding: chunked\r\nContent-Type: text/plain\r\n"
            b"Connection: close\r\n\r\n"
            b"5\r\nhello\r\n0\r\nX-Trailer: ignored\r\n\r\n"
        )
        out = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
        s.close()
        r = parse_response(out)
        self.assertEqual(r[0], 200)
        self.assertIn(b"BODY=hello", r[2])

    def test_if_range_mismatch(self):
        st, _, b = self.get("/hello.txt", headers={"Range": "bytes=0-4", "If-Range": '"bogus"'})
        self.assertEqual((st, b), (200, b"hello world\n"))

    def test_vhost_by_name(self):
        st, _, b = self.get("/", host="vhost.test")
        self.assertEqual(st, 200)
        self.assertIn(b"vhost index", b)
        self.differential("vhost", "/", host="vhost.test", compare_body=True)

    def test_vhost_alias(self):
        st, _, b = self.get("/", host="www.vhost.test")
        self.assertEqual(st, 200)
        self.assertIn(b"vhost index", b)

    def test_keepalive(self):
        s = socket.create_connection(("127.0.0.1", VP_PORT), timeout=5)
        s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += s.recv(65536)
        head, body = buf.split(b"\r\n\r\n", 1)
        clen = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                clen = int(line.split(b":", 1)[1].strip())
        while len(body) < clen:
            body += s.recv(65536)
        self.assertIn(b"200 OK", head)
        self.assertNotIn(b"Connection: close", head)
        s.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        second = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            second += chunk
        self.assertIn(b"200 OK", second)
        self.assertIn(b"Connection: close", second)
        s.close()

    def test_pipelining(self):
        s = socket.create_connection(("127.0.0.1", VP_PORT), timeout=5)
        s.sendall(
            b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n"
            b"GET /empty HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        out = b""
        while True:
            b = s.recv(65536)
            if not b:
                break
            out += b
        self.assertEqual(out.count(b"HTTP/1.1 200"), 2)
        s.close()

    def test_http10(self):
        st, h, b = self.get("/hello.txt", version="HTTP/1.0")
        self.assertEqual((st, b), (200, b"hello world\n"))
        self.assertNotIn("keep-alive", h.get("connection", [""])[0].lower())
        self.differential("HTTP/1.0", "/hello.txt", version="HTTP/1.0", compare_body=True)

    def test_query_string(self):
        st, _, b = self.get("/hello.txt?a=1&b=2")
        self.assertEqual((st, b), (200, b"hello world\n"))
        self.differential("query", "/hello.txt?a=1&b=2", compare_body=True)

    def test_chunked_get_body_drained(self):
        s = socket.create_connection(("127.0.0.1", VP_PORT), timeout=5)
        s.sendall(
            b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\n\r\n"
            b"GET /empty HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        out = b""
        while True:
            b = s.recv(65536)
            if not b:
                break
            out += b
        self.assertEqual(out.count(b"HTTP/1.1 200"), 2)
        s.close()

    def test_no_host_http11(self):
        out = raw(VP_PORT, b"GET / HTTP/1.1\r\n\r\n")
        self.assertEqual(parse_response(out)[0], 400)
        self.differential("no host", "/")

    def test_duplicate_host(self):
        out = raw(VP_PORT, b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n")
        self.assertEqual(parse_response(out)[0], 400)

    def test_cl_te_smuggling_rejected(self):
        out = raw(
            VP_PORT,
            b"POST /cgi-bin/env.sh HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        )
        self.assertEqual(parse_response(out)[0], 400)

    def test_duplicate_cl_rejected(self):
        out = raw(
            VP_PORT,
            b"POST /cgi-bin/env.sh HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
            b"Content-Length: 5\r\n\r\n12345",
        )
        self.assertEqual(parse_response(out)[0], 400)

        # Although RFC 9110 permits identical list values, accepting them at
        # a proxy boundary leaves the message length dependent on an adjacent
        # parser's duplicate-field policy.  Vapache deliberately requires one
        # canonical field line.
        out = raw(
            VP_PORT,
            b"POST /cgi-bin/env.sh HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
            b"Content-Length: 4\r\n\r\n1234",
        )
        self.assertEqual(parse_response(out)[0], 400)

    def test_ambiguous_hop_metadata_rejected(self):
        cases = [
            b"\r\nGET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close, keep-alive\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\nProxy-Connection: keep-alive\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\nTE: trailers\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: content-length\r\nContent-Length: 0\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: authorization\r\nAuthorization: Basic eDp5\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close, close\r\n\r\n",
        ]
        for request in cases:
            with self.subTest(request=request):
                self.assertEqual(parse_response(raw(VP_PORT, request))[0], 400)

    def test_unsupported_expectation_is_417(self):
        for request in [
            b"GET / HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nExpect: something-else\r\n\r\nx",
            b"POST / HTTP/1.0\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\nx",
        ]:
            with self.subTest(request=request):
                self.assertEqual(parse_response(raw(VP_PORT, request))[0], 417)

    def test_obs_fold_rejected(self):
        out = raw(VP_PORT, b"GET / HTTP/1.1\r\nHost: localhost\r\nX: a\r\n b\r\n\r\n")
        self.assertEqual(parse_response(out)[0], 400)

    def test_header_without_colon(self):
        out = raw(VP_PORT, b"GET / HTTP/1.1\r\nHost: localhost\r\nBroken\r\n\r\n")
        self.assertEqual(parse_response(out)[0], 400)

    def test_long_uri(self):
        out = raw(VP_PORT, b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertEqual(parse_response(out)[0], 414)

    def test_bad_version(self):
        out = raw(VP_PORT, b"GET / HTTP/2.0\r\nHost: localhost\r\n\r\n")
        self.assertEqual(parse_response(out)[0], 505)

    def test_nul_in_request(self):
        out = raw(VP_PORT, b"GET /a\x00b HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertIn(parse_response(out)[0], (400, 404))


class CompressionTests(Base):
    def test_gzip_static(self):
        import http.client
        st, h, b = self.get("/hello.txt", headers={"Accept-Encoding": "gzip"})
        self.assertEqual(st, 200)
        self.assertEqual(h["content-encoding"][0], "gzip")
        self.assertEqual(gzip.decompress(b), b"hello world\n")
        self.assertEqual(int(h["content-length"][0]), len(b))
        self.assertTrue(any("accept-encoding" in v.lower() for v in h.get("vary", [])))
        self.assertTrue(h["etag"][0].endswith('-gzip"'))

    def test_brotli_static_via_curl(self):
        proc = subprocess.run(
            [
                "curl", "--silent", "--show-error", "--compressed",
                "--dump-header", "-", f"http://127.0.0.1:{VP_PORT}/hello.txt",
            ],
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("latin-1", "replace"))
        head, sep, body = proc.stdout.partition(b"\r\n\r\n")
        self.assertTrue(sep)
        self.assertIn(b"content-encoding: br", head.lower())
        self.assertEqual(body, b"hello world\n")

    def test_compressed_etag_conditional(self):
        st, h, b = self.get("/hello.txt", headers={"Accept-Encoding": "gzip"})
        self.assertEqual(st, 200)
        gzip_etag = h["etag"][0]
        st, h, b = self.get(
            "/hello.txt",
            headers={"Accept-Encoding": "gzip", "If-None-Match": gzip_etag},
        )
        self.assertEqual(st, 304)
        self.assertEqual(h["etag"][0], gzip_etag)
        self.assertEqual(b, b"")

        # Validators identify encoded representations, not just the source
        # file. A gzip tag must not validate identity or Brotli bytes.
        st, h, b = self.get(
            "/hello.txt", headers={"If-None-Match": gzip_etag}
        )
        self.assertEqual((st, b), (200, b"hello world\n"))
        self.assertNotEqual(h["etag"][0], gzip_etag)

        st, h, _ = self.get(
            "/hello.txt",
            headers={"Accept-Encoding": "br", "If-None-Match": gzip_etag},
        )
        self.assertEqual(st, 200)
        self.assertEqual(h["content-encoding"][0], "br")

    def test_range_bypasses_compression(self):
        st, h, b = self.get(
            "/hello.txt",
            headers={"Accept-Encoding": "gzip", "Range": "bytes=0-4"},
        )
        self.assertEqual((st, b), (206, b"hello"))
        self.assertNotIn("content-encoding", h)

    def test_htaccess_deflate(self):
        import http.client
        st, h, b = self.get(
            "/htaccess/compress/sample.foo",
            headers={"Accept-Encoding": "gzip"},
        )
        self.assertEqual(st, 200)
        self.assertEqual(h["content-type"][0].split(";")[0], "text/x-custom")
        self.assertEqual(h["content-encoding"][0], "gzip")
        self.assertEqual(gzip.decompress(b), b"compressed custom type\n")


class ProxyTests(Base):
    def test_proxy_strips_client_forwarded_addresses(self):
        st, _, b = self.get(
            "/app/hello",
            headers={
                "Forwarded": "for=10.1.2.3",
                "X-Real-IP": "10.1.2.3",
            },
        )
        self.assertEqual(st, 200, b)
        self.assertIn(b"XFF=127.0.0.1", b)
        self.assertNotIn(b"10.1.2.3", b)

    def test_http_proxy_get_and_post(self):
        st, h, b = self.get(
            "/app/hello?x=1", headers={"X-Test": "yes"}
        )
        self.assertEqual(st, 200, b)
        self.assertEqual(h["x-upstream"][0], "yes")
        self.assertIn(b"GET /hello?x=1", b)
        self.assertIn(b"XTEST=yes", b)
        self.assertIn(b"XFF=127.0.0.1", b)

        st, h, b = self.get("/app/submit", method="POST", body=b"payload")
        self.assertEqual(st, 200, b)
        self.assertIn(b"POST /submit", b)
        self.assertIn(b"BODY=payload", b)

        st, h, b = self.get("/secure/tls")
        self.assertEqual(st, 200, b)
        self.assertIn(b"GET /tls", b)

        b1 = self.get("/bal/one")[2]
        b2 = self.get("/bal/one")[2]
        self.assertIn(f"PORT={PROXY_PORT}".encode(), b1)
        self.assertIn(f"PORT={PROXY2_PORT}".encode(), b2)

    def test_active_balancer_health(self):
        import time
        time.sleep(1.5)
        for _ in range(2):
            st, _, b = self.get("/healthbal/health")
            self.assertEqual(st, 200, b)
            self.assertIn(f"PORT={PROXY_PORT}".encode(), b)

    def _ws_roundtrip(self, sock, path, port):
        import base64, os
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall(
            (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: localhost:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        self.assertIn(b"101 Switching Protocols", data)
        sock.sendall(b"hello")
        echoed = b""
        while len(echoed) < 5:
            chunk = sock.recv(5 - len(echoed))
            if not chunk:
                break
            echoed += chunk
        self.assertEqual(echoed, b"hello")
        sock.close()

    def test_websocket_requires_valid_handshake(self):
        import base64, os

        def rejected(version, websocket_version):
            key = base64.b64encode(os.urandom(16)).decode()
            s = socket.create_connection(("127.0.0.1", VP_PORT), timeout=5)
            s.sendall(
                (
                    f"GET /ws {version}\r\n"
                    f"Host: localhost:{VP_PORT}\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {key}\r\n"
                    f"Sec-WebSocket-Version: {websocket_version}\r\n\r\n"
                ).encode()
            )
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            s.close()
            self.assertNotIn(b"101", data.split(b"\r\n", 1)[0])

        rejected("HTTP/1.1", "12")
        rejected("HTTP/1.0", "13")

    def test_websocket_normalized_path_acl(self):
        import base64, os
        key = base64.b64encode(os.urandom(16)).decode()
        s = socket.create_connection(("127.0.0.1", VP_PORT), timeout=5)
        s.sendall(
            (
                "GET /app/../admin HTTP/1.1\r\n"
                f"Host: localhost:{VP_PORT}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        status_line = data.split(b"\r\n", 1)[0]
        self.assertNotIn(b"101", status_line)
        self.assertIn(b"403", status_line)

    def test_rewrite_filesystem_target_acl(self):
        st, _, body = self.get("/protected-rewrite")
        self.assertEqual(st, 403, body)
        self.assertNotIn(b"rewrite private secret", body)

    def test_websocket_wss_upstream(self):
        s = socket.create_connection(("127.0.0.1", VP_PORT), timeout=5)
        self._ws_roundtrip(s, "/wss", VP_PORT)

    def test_websocket_wss_client(self):
        ctx = ssl._create_unverified_context()
        s = ctx.wrap_socket(
            socket.create_connection(("127.0.0.1", VP_TLS_PORT), timeout=5),
            server_hostname="localhost",
        )
        self._ws_roundtrip(s, "/ws", VP_TLS_PORT)

    def test_websocket_wss_both(self):
        ctx = ssl._create_unverified_context()
        s = ctx.wrap_socket(
            socket.create_connection(("127.0.0.1", VP_TLS_PORT), timeout=5),
            server_hostname="localhost",
        )
        self._ws_roundtrip(s, "/wss", VP_TLS_PORT)

    def test_websocket_tunnel(self):
        import base64, os
        key = base64.b64encode(os.urandom(16)).decode()
        s = socket.create_connection(("127.0.0.1", VP_PORT), timeout=5)
        s.sendall(
            (
                "GET /ws HTTP/1.1\r\n"
                f"Host: localhost:{VP_PORT}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        data = b""
        while b"\r\n\r\n" not in data:
            data += s.recv(4096)
        self.assertIn(b"101 Switching Protocols", data)
        s.sendall(b"hello")
        echoed = b""
        while len(echoed) < 5:
            chunk = s.recv(5 - len(echoed))
            if not chunk:
                break
            echoed += chunk
        self.assertEqual(echoed, b"hello")
        s.close()


class FastCgiTests(Base):
    def test_php_fastcgi_get_and_post(self):
        st, h, b = self.get(
            "/index.php?x=1", headers={"X-Test": "yes"}
        )
        self.assertEqual(st, 200, b)
        self.assertIn(b"METHOD=GET", b)
        self.assertIn(b"QUERY=x=1", b)
        self.assertIn(b"XTEST=yes", b)
        self.assertIn(b"index.php", b)
        self.assertTrue(h["content-type"][0].startswith("text/plain"))

        st, h, b = self.get("/index.php", method="POST", body=b"payload")
        self.assertEqual(st, 200, b)
        self.assertIn(b"METHOD=POST", b)
        self.assertIn(b"BODY=payload", b)

        st, h, b = self.get("/handler.fphp?y=2")
        self.assertEqual(st, 200, b)
        self.assertIn(b"METHOD=GET", b)
        self.assertIn(b"QUERY=y=2", b)
        self.assertIn(b"handler.fphp", b)


class CgiTests(Base):
    def test_cgi_get_env(self):
        st, h, b = self.get("/cgi-bin/env.sh?x=1&y=2", headers={"X-Test": "abc"})
        self.assertEqual(st, 200)
        self.assertIn(b"METHOD=GET", b)
        self.assertIn(b"QUERY=x=1&y=2", b)
        self.assertIn(b"SCRIPT=/cgi-bin/env.sh", b)
        self.assertIn(b"HTTP_X_TEST=abc", b)
        self.assertIn(b"HTTP_PROXY=\n", b)
        self.differential("cgi env", "/cgi-bin/env.sh?x=1&y=2", headers={"X-Test": "abc"}, compare_body=True)

    def test_cgi_post(self):
        st, _, b = self.get(
            "/cgi-bin/env.sh",
            method="POST",
            body=b"hello=cgi",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(st, 200)
        self.assertIn(b"METHOD=POST", b)
        self.assertIn(b"BODY=hello=cgi", b)
        self.assertIn(b"CONTENT_TYPE=application/x-www-form-urlencoded", b)

    def test_cgi_status_and_header(self):
        st, h, b = self.get("/cgi-bin/status.sh")
        self.assertEqual(st, 418)
        self.assertEqual(h["x-cgi"][0], "yes")
        self.assertEqual(b, b"teapot\n")
        self.differential("cgi status", "/cgi-bin/status.sh", compare_body=True)

    def test_cgi_redirect(self):
        st, h, _ = self.get("/cgi-bin/redirect.sh")
        self.assertEqual(st, 302)
        self.assertEqual(h["location"][0], "/hello.txt")
        self.differential("cgi redirect", "/cgi-bin/redirect.sh")

    def test_cgi_body_cannot_be_promoted_to_headers(self):
        st, h, body = self.get("/cgi-bin/mixed-boundary.sh")
        self.assertEqual(st, 200)
        self.assertNotIn("location", h)
        self.assertEqual(
            body,
            b"Status: 302 Found\r\nLocation: /injected\r\n\r\nbody\n",
        )

    def test_204_strips_configured_content_length(self):
        st, h, body = self.get("/cgi-bin/no-content.sh")
        self.assertEqual(st, 204)
        self.assertNotIn("content-length", h)
        self.assertEqual(body, b"")

    def test_205_is_bodyless_and_writer_owns_hop_headers(self):
        st, h, body = self.get("/cgi-bin/reset-content.sh")
        self.assertEqual(st, 205)
        self.assertEqual(h.get("content-length"), ["0"])
        self.assertEqual(h.get("connection"), ["close"])
        for removed in (
            "x-hop",
            "keep-alive",
            "proxy-connection",
            "upgrade",
            "te",
            "trailer",
        ):
            self.assertNotIn(removed, h)
        self.assertEqual(body, b"")

    def test_cgi_path_info(self):
        st, _, b = self.get("/cgi-bin/env.sh/more/path")
        self.assertEqual(st, 200)
        self.assertIn(b"PATH_INFO=/more/path", b)
        self.assertIn(b"SCRIPT=/cgi-bin/env.sh", b)
        self.differential("cgi path info", "/cgi-bin/env.sh/more/path", compare_body=True)

    def test_cgi_missing(self):
        st, _, _ = self.get("/cgi-bin/nope.sh")
        self.assertEqual(st, 404)

    def test_cgi_chunked_post(self):
        s = socket.create_connection(("127.0.0.1", VP_PORT), timeout=5)
        s.sendall(
            b"POST /cgi-bin/env.sh HTTP/1.1\r\nHost: localhost\r\n"
            b"Transfer-Encoding: chunked\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        )
        out = b""
        while True:
            b = s.recv(65536)
            if not b:
                break
            out += b
        s.close()
        r = parse_response(out)
        self.assertEqual(r[0], 200)
        self.assertIn(b"BODY=hello world", r[2])
        self.assertIn(b"TRANSFER_ENCODING=chunked", r[2])

    def test_script_without_exec_bit(self):
        p = BASE / "www" / "cgi-bin" / "noexec.sh"
        p.write_text("#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nok\\n'\n")
        p.chmod(0o644)
        self.assertEqual(self.get("/cgi-bin/noexec.sh")[0], 500)


class AuthTests(Base):
    @staticmethod
    def basic(user, password):
        import base64
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def test_basic_valid_user(self):
        st, _, b = self.get("/auth/protected.txt", headers=self.basic("alice", "alicepw"))
        self.assertEqual((st, b), (200, b"auth secret\n"))
        self.differential(
            "basic valid-user", "/auth/protected.txt",
            headers=self.basic("alice", "alicepw"), compare_body=True,
        )

    def test_basic_missing_and_wrong_credentials(self):
        st, h, _ = self.get("/auth/protected.txt")
        self.assertEqual(st, 401)
        self.assertIn("www-authenticate", h)
        self.assertIn('Basic realm="Test Realm"', h["www-authenticate"][0])
        st, _, _ = self.get("/auth/protected.txt", headers=self.basic("alice", "wrong"))
        self.assertEqual(st, 401)
        st, _, _ = self.get(
            "/auth/protected.txt", headers={"Authorization": "Bearer nope"}
        )
        self.assertEqual(st, 401)

    def test_basic_scheme_uses_ascii_separator(self):
        import base64

        token = base64.b64encode(b"alice:alicepw")
        request = (
            b"GET /auth/protected.txt HTTP/1.1\r\n"
            + f"Host: localhost:{VP_PORT}\r\n".encode()
            + b"Connection: close\r\nAuthorization: Basic\xe2\x80\x83"
            + token
            + b"\r\n\r\n"
        )
        vapache = parse_response(raw(VP_PORT, request))
        self.assertIsNotNone(vapache)
        self.assertEqual(vapache[0], 401)
        if DIFFERENTIAL:
            apache_request = request.replace(
                f"localhost:{VP_PORT}".encode(), f"localhost:{AP_PORT}".encode()
            )
            apache = parse_response(raw(AP_PORT, apache_request))
            if apache is None or apache[0] != vapache[0]:
                DIFFS.append(
                    (
                        "Basic auth non-ASCII separator",
                        f"status {apache[0] if apache else None} != {vapache[0]}",
                    )
                )
    def test_basic_user_and_group_providers(self):
        st, _, b = self.get("/auth/user/alice.txt", headers=self.basic("alice", "alicepw"))
        self.assertEqual((st, b), (200, b"alice area\n"))
        # A valid password for another user must not satisfy Require user.
        st, _, _ = self.get("/auth/user/alice.txt", headers=self.basic("bob", "bobpw"))
        self.assertEqual(st, 403)
        st, _, b = self.get("/auth/group/staff.txt", headers=self.basic("alice", "alicepw"))
        self.assertEqual((st, b), (200, b"staff area\n"))
        st, _, _ = self.get("/auth/group/staff.txt", headers=self.basic("bob", "bobpw"))
        self.assertEqual(st, 403)

    def test_group_provider_ambiguity_and_failure(self):
        st, _, _ = self.get(
            "/auth/group-duplicate/staff.txt", headers=self.basic("bob", "bobpw")
        )
        self.assertEqual(st, 200)
        self.differential(
            "duplicate group records",
            "/auth/group-duplicate/staff.txt",
            headers=self.basic("bob", "bobpw"),
        )
        st, _, _ = self.get(
            "/group-unavailable/staff.txt",
            headers=self.basic("alice", "alicepw"),
        )
        self.assertEqual(st, 403)
        self.differential(
            "negative group without provider",
            "/group-unavailable/staff.txt",
            headers=self.basic("alice", "alicepw"),
        )

    def test_authenticated_identity_survives_resolved_target_reauthorization(self):
        st, _, body = self.get(
            "/protected-cgi/who.sh", headers=self.basic("alice", "alicepw")
        )
        self.assertEqual(st, 200, body)
        self.assertIn(b"REMOTE_USER=alice\n", body)
        self.assertIn(b"AUTH_TYPE=Basic\n", body)
        self.differential(
            "authenticated resolved CGI identity",
            "/protected-cgi/who.sh",
            headers=self.basic("alice", "alicepw"),
            compare_body=True,
        )

    def test_basic_htaccess_not_required_for_auth(self):
        # The auth file itself is outside the document root and must not be
        # exposed, even to authenticated clients.
        st, _, _ = self.get("/.htpasswd")
        self.assertEqual(st, 403)


class RewriteDirectoryTests(Base):
    def test_directory_rewrite_rule(self):
        st, _, body = self.get("/dir-rewrite/old.html")
        self.assertEqual((st, body), (200, b"dir rewrite target\n"))
        self.differential("directory rewrite rule", "/dir-rewrite/old.html")

    def test_duplicate_slashes_do_not_bypass_rewrite(self):
        # CVE-2001-1072: slash insertion must not make the rewrite regex miss
        # a path that the rest of URL processing collapses.
        st, _, body = self.get("/dir-rewrite//old.html")
        self.assertEqual((st, body), (200, b"dir rewrite target\n"))

    def test_encoded_controls_cannot_reach_rewrite_or_redirect(self):
        # CVE-2019-10098 / CVE-2020-1927: encoded CR/LF must be rejected
        # before rewrite matching, not decoded into a redirect target.
        for path in ("/dir-rewrite/old%0a.html", "/dir-rewrite/old%0d.html"):
            st, _, body = self.get(path)
            self.assertIn(st, (400, 404), path)
            self.assertNotIn(b"dir rewrite target", body)

class RewriteFeatureTests(Base):
    def test_rewrite_env_condition(self):
        st, _, body = self.get("/rewrite-features/env")
        self.assertEqual((st, body), (200, b"rewrite feature target\n"))

    def test_rewrite_cookie(self):
        st, h, _ = self.get("/rewrite-features/cookie")
        self.assertEqual(st, 404)
        cookie = h.get("set-cookie", [""])[0]
        self.assertIn("TEST=VAL", cookie)
        self.assertIn("SameSite=none", cookie)

    def test_rewrite_content_type(self):
        st, h, _ = self.get("/rewrite-features/typed")
        self.assertEqual(st, 200)
        self.assertEqual(h.get("content-type"), ["application/x-test"])

    def test_rewrite_int_map(self):
        st, _, body = self.get("/rewrite-features/map/ABC")
        self.assertEqual((st, body), (200, b"lower map target\n"))

    def test_rewrite_vary(self):
        st, h, _ = self.get(
            "/rewrite-features/vary", headers={"Accept": "feature-accept"}
        )
        self.assertEqual(st, 200)
        self.assertIn("Accept", h.get("vary", [""])[0])

    def test_rewrite_to_proxy(self):
        st, _, body = self.get("/rewrite-features/proxy/foo")
        self.assertEqual(st, 200)
        self.assertIn("GET /app/foo", body.decode())

    def test_rewrite_proxy_qsa(self):
        st, _, body = self.get("/rewrite-features/qsa-proxy?bloo=blar")
        self.assertEqual(st, 200)
        self.assertIn("GET /app?foo=bar&bloo=blar", body.decode())

    def test_rewrite_b_escaping(self):
        st, _, body = self.get("/rewrite-features/b/foo/bar")
        self.assertEqual(st, 200)
        self.assertIn("GET /app?foo%2fbar", body.decode())

class HtaccessTests(Base):
    @staticmethod
    def basic(user, password):
        import base64
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def test_htaccess_if_expression(self):
        st, _, _ = self.get("/htaccess/if/hello.txt")
        self.assertEqual(st, 200)
        st, _, _ = self.get(
            "/htaccess/if/hello.txt", headers={"X-Test": "yes"}
        )
        self.assertEqual(st, 403)

    def test_htaccess_deny(self):
        st, _, _ = self.get("/htaccess/deny/secret.txt")
        self.assertEqual(st, 403)
        self.differential("htaccess deny", "/htaccess/deny/secret.txt")

    def test_htaccess_limit(self):
        self.assertEqual(self.get("/htaccess/limit/hello.txt")[0], 200)
        self.assertEqual(
            self.get("/htaccess/limit/hello.txt", method="POST")[0], 403
        )
        self.differential(
            "htaccess Limit GET", "/htaccess/limit/hello.txt", compare_body=True
        )
        self.differential(
            "htaccess Limit POST", "/htaccess/limit/hello.txt", method="POST"
        )

    def test_htaccess_allowmethods(self):
        # mod_allowmethods is directory-context only, so .htaccess must fail
        # closed with 500 rather than silently ignoring the restriction.
        st, _, _ = self.get("/htaccess/allowmethods/hello.txt")
        self.assertEqual(st, 500)
        self.differential("htaccess AllowMethods", "/htaccess/allowmethods/hello.txt")

    def test_htaccess_elseif(self):
        st, h, _ = self.get(
            "/htaccess/elseif/hello.txt", headers={"X-Branch": "a"}
        )
        self.assertEqual((st, h.get("x-branch")), (200, ["a"]))
        self.differential(
            "htaccess ElseIf first",
            "/htaccess/elseif/hello.txt",
            headers={"X-Branch": "a"},
        )
        self.assertEqual(
            self.get("/htaccess/elseif/hello.txt", headers={"X-Branch": "b"})[0],
            403,
        )
        self.differential(
            "htaccess ElseIf second",
            "/htaccess/elseif/hello.txt",
            headers={"X-Branch": "b"},
        )
        self.assertEqual(self.get("/htaccess/elseif/hello.txt")[0], 403)
        self.differential("htaccess Else", "/htaccess/elseif/hello.txt")

    def test_htaccess_internal_subrequests(self):
        # DirectoryIndex honors <Files> rules from .htaccess.
        self.assertEqual(self.get("/htaccess/idx-deny/")[0], 403)
        self.differential(
            "htaccess DirectoryIndex authorization", "/htaccess/idx-deny/"
        )
        # Local ErrorDocument authorization comes from .htaccess too.
        st, _, body = self.get("/htaccess/errordoc/missing")
        self.assertEqual(st, 404)
        self.assertNotIn(b"htaccess error doc secret", body)
        self.differential(
            "htaccess ErrorDocument authorization", "/htaccess/errordoc/missing"
        )

    def test_htaccess_auth(self):
        st, h, _ = self.get("/htaccess/auth/private.txt")
        self.assertEqual(st, 401)
        self.assertIn('Basic realm="Htaccess Realm"', h["www-authenticate"][0])
        st, _, b = self.get(
            "/htaccess/auth/private.txt", headers=self.basic("alice", "alicepw")
        )
        self.assertEqual((st, b), (200, b"htaccess auth\n"))

    def test_htaccess_options(self):
        self.assertEqual(self.get("/htaccess/options/")[0], 403)
        self.differential("htaccess options", "/htaccess/options/")

    def test_htaccess_header(self):
        st, h, _ = self.get("/htaccess/header/hello.txt")
        self.assertEqual(st, 200)
        self.assertEqual(h.get("x-htaccess"), ["yes"])
        self.differential("htaccess header", "/htaccess/header/hello.txt")

    def test_htaccess_unsupported_directive_fails_closed(self):
        # RewriteMap is not allowed in per-directory context.  Both servers
        # must reject it rather than silently ignoring a possible rule.
        st, _, _ = self.get("/htaccess/bad/hello.txt")
        self.assertEqual(st, 500)

    def test_config_rewrite_internal(self):
        st, _, body = self.get("/from-config")
        self.assertEqual((st, body), (200, b"hello world\n"))
        self.differential("config rewrite internal", "/from-config")

    def test_htaccess_rewrite_internal(self):
        st, _, body = self.get("/htaccess/rewrite/old.html")
        self.assertEqual((st, body), (200, b"rewrite new\n"))
        self.differential("htaccess rewrite internal", "/htaccess/rewrite/old.html")

    def test_htaccess_rewrite_redirect(self):
        st, h, _ = self.get("/htaccess/rewrite/moved.html")
        self.assertEqual(st, 301)
        self.assertTrue(h["location"][0].endswith("/target.html"))

    def test_htaccess_rewrite_base_changes_substitution_only(self):
        st, _, body = self.get("/htaccess/rewrite-base/old.html")
        self.assertEqual((st, body), (200, b"rewrite-base target\n"))
        self.differential(
            "htaccess RewriteBase", "/htaccess/rewrite-base/old.html"
        )

    def test_htaccess_rewrite_forbidden(self):
        st, _, _ = self.get("/htaccess/rewrite/blocked.html")
        self.assertEqual(st, 403)

    def test_htaccess_rewrite_condition_qsa(self):
        st, _, body = self.get("/htaccess/rewrite/query.html?x=1")
        self.assertEqual((st, body), (200, b"rewrite new\n"))
        st, _, _ = self.get("/htaccess/rewrite/query.html?x=2")
        self.assertEqual(st, 404)

    def test_htaccess_category_authconfig(self):
        st, _, _ = self.get("/htaccess/cat-auth/secret.txt")
        self.assertEqual(st, 403)
        self.differential(
            "htaccess category AuthConfig", "/htaccess/cat-auth/secret.txt"
        )

    def test_htaccess_category_options(self):
        st, _, _ = self.get("/htaccess/cat-options/")
        self.assertEqual(st, 403)
        self.differential(
            "htaccess category Options", "/htaccess/cat-options/"
        )

    def test_htaccess_category_denied_directive(self):
        st, _, _ = self.get("/htaccess/cat-bad/hello.txt")
        self.assertEqual(st, 500)

    def test_htaccess_category_options_set_is_narrow(self):
        st, _, body = self.get("/htaccess/cat-execcgi/hello.txt")
        self.assertEqual((st, body), (200, b"cat execcgi\n"))
        self.differential(
            "htaccess category Options=ExecCGI", "/htaccess/cat-execcgi/hello.txt"
        )
        st, _, _ = self.get("/htaccess/cat-optbad/hello.txt")
        self.assertEqual(st, 500)
        self.differential(
            "htaccess category Options=ExecCGI denies Indexes",
            "/htaccess/cat-optbad/hello.txt",
        )

    def test_htaccess_category_fileinfo_allows_rewrite(self):
        st, _, body = self.get("/htaccess/cat-fileinfo/old.html")
        self.assertEqual((st, body), (200, b"cat fileinfo new\n"))
        self.differential(
            "htaccess category FileInfo rewrite", "/htaccess/cat-fileinfo/old.html"
        )


class OcspTests(Base):
    def test_ocsp_stapling(self):
        result = subprocess.run(
            [
                "openssl", "s_client", "-connect", f"127.0.0.1:{VP_OCSP_PORT}",
                "-servername", "ocsp.test", "-status",
            ],
            input=b"", capture_output=True, timeout=15,
        )
        output = result.stdout + result.stderr
        self.assertIn(b"OCSP Response Status: successful", output)
        self.assertTrue(
            list((BASE / ".vapache-ocsp-cache").glob("*.ocsp")),
            "OCSP response was not persisted",
        )
        before = OCSP_REQUESTS
        import time
        time.sleep(2.2)
        self.assertGreater(OCSP_REQUESTS, before, "OCSP response was not refreshed")

class CacheTests(Base):
    def test_cache_miss_then_hit(self):
        st, h, b = self.get("/cache/file2.txt")
        self.assertEqual((st, b), (200, b"cache me too\n"))
        self.assertEqual(h.get("x-cache"), ["MISS"])
        st, h, b = self.get("/cache/file2.txt")
        self.assertEqual((st, b), (200, b"cache me too\n"))
        self.assertEqual(h.get("x-cache"), ["HIT"])
        self.assertIn("age", h)

    def test_cache_directory_index(self):
        st, _, b = self.get("/cache/")
        self.assertEqual((st, b), (200, b"<html>cache index</html>\n"))
        st, h, b = self.get("/cache/")
        self.assertEqual((st, b), (200, b"<html>cache index</html>\n"))
        self.assertEqual(h.get("x-cache"), ["HIT"])

    def test_cache_does_not_bypass_rewrite_denial(self):
        st, h, b = self.get("/cache/file.txt")
        self.assertEqual((st, b), (200, b"cache me\n"))
        st, _, _ = self.get("/cache/file.txt", headers={"X-Deny": "yes"})
        self.assertEqual(st, 403)

class ConfigTests(unittest.TestCase):
    def test_stock_debian_config_audits_for_packaged_wrapper(self):
        cfg = Path("/etc/apache2/apache2.conf")
        if not cfg.exists():
            self.skipTest("no Debian apache2 config")
        r = subprocess.run(
            [str(VAPACHED), "-f", str(cfg), "--audit-capabilities"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        self.assertIn("VapacheCapability AutoIndex On", r.stdout)

    def test_strict_unknown_directive(self):
        p = BASE / "strict.conf"
        p.write_text(
            f"ServerRoot \"{BASE}\"\nListen 19999\nUser {SERVICE_USER}\nGroup {SERVICE_GROUP}\n"
            f"PidFile {BASE}/logs/x.pid\nErrorLog {BASE}/logs/e.log\n"
            "TotallyMadeUpDirective on\n"
        )
        r = subprocess.run(
            [str(VAPACHED), "-f", str(p), "-t", "--strict-config"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Invalid command", r.stderr)

    def test_ssl_configtest_rejects_missing_certificate(self):
        p = BASE / "ssl-bad.conf"
        p.write_text(
            f"ServerRoot \"{BASE}\"\nListen 19998\nUser {SERVICE_USER}\nGroup {SERVICE_GROUP}\n"
            f"PidFile {BASE}/logs/x.pid\nErrorLog {BASE}/logs/e.log\n"
            "<VirtualHost *:19998>\n"
            "    SSLEngine on\n"
            f"    SSLCertificateFile \"{BASE}/does-not-exist.pem\"\n"
            f"    SSLCertificateKeyFile \"{BASE}/does-not-exist.key\"\n"
            "</VirtualHost>\n"
        )
        r = subprocess.run(
            [str(VAPACHED), "-f", str(p), "-t"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SSL configuration error", r.stderr)

    def test_env_var_undefined(self):
        p = BASE / "var.conf"
        p.write_text(
            f"ServerRoot /tmp\nListen 19999\nUser {SERVICE_USER}\nGroup {SERVICE_GROUP}\n"
            "ErrorLog ${THIS_IS_NOT_SET}/e.log\n"
        )
        r = subprocess.run(
            [str(VAPACHED), "-f", str(p), "-t"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not defined", r.stderr)


DIFFERENTIAL = False


class TlsTests(unittest.TestCase):
    def curl(self, port, path, *extra, input=None):
        proc = subprocess.run(
            [
                "curl", "--silent", "--show-error", "--insecure", "--noproxy", "*",
                "--output", "-", "--write-out", "\n%{http_version} %{http_code}",
                *extra, f"https://127.0.0.1:{port}{path}",
            ],
            input=input, capture_output=True, timeout=20,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("latin-1", "replace"))
        body, _, meta = proc.stdout.rpartition(b"\n")
        version, status = meta.decode().split()
        return version, int(status), body

    def test_tls_http11(self):
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection("127.0.0.1", VP_TLS_PORT, context=ctx, timeout=10)
        conn.request("GET", "/hello.txt", headers={"Host": f"localhost:{VP_TLS_PORT}"})
        r = conn.getresponse()
        self.assertEqual((r.status, r.read()), (200, b"hello world\n"))
        conn.close()

    def test_tls_http11_backend_and_body_phases(self):
        # Keep HTTP/1.1 covered independently from HTTP/2: the TLS adapter
        # deliberately has separate lazy-body and backend dispatch phases.
        version, status, body = self.curl(
            VP_TLS_PORT, "/cgi-bin/env.sh", "--http1.1"
        )
        self.assertEqual((version, status), ("1.1", 200))
        self.assertIn(b"METHOD=GET", body)

        version, status, body = self.curl(
            VP_TLS_PORT,
            "/cgi-bin/env.sh",
            "--http1.1",
            "--data-binary",
            "payload=small",
        )
        self.assertEqual((version, status), ("1.1", 200))
        self.assertIn(b"BODY=payload=small", body)

        # Cross the 1 MiB in-memory request-body boundary so the TLS socket
        # task and CGI backend communicate through the bounded streaming pump.
        large = "x" * (1024 * 1024 + 64 * 1024)
        version, status, body = self.curl(
            VP_TLS_PORT,
            "/cgi-bin/env.sh",
            "--http1.1",
            "--data-binary",
            "@-",
            input=large.encode(),
        )
        self.assertEqual((version, status), ("1.1", 200))
        self.assertIn(large[:64].encode(), body)

        version, status, _ = self.curl(
            VP_TLS_PORT,
            "/auth/protected.txt",
            "--http1.1",
            "--data-binary",
            "discard-me",
            "-H",
            "Expect: 100-continue",
        )
        self.assertEqual((version, status), ("1.1", 401))

    def test_tls_http2(self):
        version, status, body = self.curl(VP_TLS_PORT, "/hello.txt", "--http2")
        self.assertEqual((version, status, body), ("2", 200, b"hello world\n"))

    def test_tls_http2_range(self):
        version, status, body = self.curl(
            VP_TLS_PORT, "/hello.txt", "--http2", "-H", "Range: bytes=0-4"
        )
        self.assertEqual((version, status, body), ("2", 206, b"hello"))

    def test_tls_sni_vhost(self):
        proc = subprocess.run(
            [
                "curl", "--silent", "--show-error", "--insecure", "--noproxy", "*",
                "--http2", "--resolve", f"vhost.test:{VP_TLS_PORT}:127.0.0.1",
                "--output", "-", "--write-out", "\n%{http_version} %{http_code}",
                f"https://vhost.test:{VP_TLS_PORT}/",
            ],
            capture_output=True, timeout=20,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("latin-1", "replace"))
        body, _, meta = proc.stdout.rpartition(b"\n")
        version, status = meta.decode().split()
        status = int(status)
        self.assertEqual((version, status), ("2", 200))
        self.assertIn(b"vhost index", body)

    def test_tls_http2_cgi_post(self):
        version, status, body = self.curl(
            VP_TLS_PORT,
            "/cgi-bin/env.sh",
            "--http2",
            "--data-binary", "payload=hello",
        )
        self.assertEqual((version, status), ("2", 200))
        self.assertIn(b"METHOD=POST", body)
        self.assertIn(b"BODY=payload=hello", body)

    def test_tls_http2_not_found_and_denied(self):
        version, status, body = self.curl(VP_TLS_PORT, "/missing", "--http2")
        self.assertEqual((version, status), ("2", 404))
        self.assertIn(b"custom 404", body)
        version, status, _ = self.curl(VP_TLS_PORT, "/secret.txt", "--http2")
        self.assertEqual((version, status), ("2", 403))

    def test_tls_http2_large_file_paths(self):
        # 300 KiB takes the mmap/blocking-read path; the range skips mmap and
        # starts at a mid-file offset; 0666 forces the writable-file fallback;
        # 9 MiB exercises the >8 MiB chunked streaming branch.
        version, status, body = self.curl(VP_TLS_PORT, "/large.bin", "--http2")
        self.assertEqual((version, status, len(body)), ("2", 200, 300 * 1024))
        self.assertEqual(body[:1], b"L")

        version, status, body = self.curl(
            VP_TLS_PORT, "/large.bin", "--http2", "-H", "Range: bytes=1000-1999"
        )
        self.assertEqual((version, status, len(body)), ("2", 206, 1000))
        self.assertEqual(body, b"L" * 1000)

        path = BASE / "www" / "large.bin"
        path.chmod(0o666)
        try:
            version, status, body = self.curl(VP_TLS_PORT, "/large.bin", "--http2")
            self.assertEqual((version, status, len(body)), ("2", 200, 300 * 1024))
        finally:
            path.chmod(0o644)

        version, status, body = self.curl(VP_TLS_PORT, "/huge.bin", "--http2")
        self.assertEqual((version, status, len(body)), ("2", 200, 9 * 1024 * 1024))
        self.assertEqual(body[:1], b"H")

    def test_mtls_requires_client_certificate(self):
        def request(with_cert):
            ctx = ssl._create_unverified_context()
            if with_cert:
                ctx.load_cert_chain(str(BASE / "client.pem"), str(BASE / "client.key"))
            sock = ctx.wrap_socket(
                socket.create_connection(("127.0.0.1", VP_MTLS_PORT), timeout=5),
                server_hostname="localhost",
            )
            try:
                sock.sendall(
                    b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
                out = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                return out
            finally:
                sock.close()

        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            request(False)

        self.assertIn(b"200 OK", request(True))
        self.assertIn(b"hello world", request(True))

    def test_tls_http2_head_and_options(self):
        proc = subprocess.run(
            [
                "curl", "--silent", "--show-error", "--insecure", "--http2",
                "--head", "--output", "-", "--write-out", "\n%{http_version} %{http_code}",
                f"https://127.0.0.1:{VP_TLS_PORT}/hello.txt",
            ],
            capture_output=True, timeout=20,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("latin-1", "replace"))
        head, _, meta = proc.stdout.rpartition(b"\n")
        self.assertEqual(meta.decode(), "2 200")
        self.assertIn(b"content-length: 12", head.lower())

        proc = subprocess.run(
            [
                "curl", "--silent", "--show-error", "--insecure", "--http2",
                "-X", "OPTIONS", "--dump-header", "-", "--output", "-",
                f"https://127.0.0.1:{VP_TLS_PORT}/hello.txt",
            ],
            capture_output=True, timeout=20,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("latin-1", "replace"))
        self.assertIn(b"HTTP/2 200", proc.stdout)
        self.assertIn(b"allow:", proc.stdout.lower())

    def test_tls_sni_selects_certificate(self):
        proc = subprocess.run(
            f"openssl s_client -connect 127.0.0.1:{VP_TLS_PORT} -servername vhost.test "
            f"-showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject",
            shell=True, capture_output=True, timeout=20,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("latin-1", "replace"))
        self.assertIn(b"vhost.test", proc.stdout)
        proc = subprocess.run(
            f"openssl s_client -connect 127.0.0.1:{VP_TLS_PORT} -servername localhost "
            f"-showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject",
            shell=True, capture_output=True, timeout=20,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("latin-1", "replace"))
        self.assertIn(b"localhost", proc.stdout)

    def test_tls_http2_reset_observed_without_killing_connection(self):
        # CVE-2026-23918 trigger shape: send HEADERS followed by RST_STREAM
        # before a body is complete.  The connection-level H2Budget must
        # release the active slot and reclaim the pending reset exactly once,
        # and the listener must remain alive.
        ctx = ssl._create_unverified_context()
        ctx.set_alpn_protocols(["h2"])
        s = ctx.wrap_socket(
            socket.create_connection(("127.0.0.1", VP_TLS_PORT), timeout=5),
            server_hostname="localhost",
        )
        self.assertEqual(s.selected_alpn_protocol(), "h2")

        def frame(frame_type, flags, stream_id, payload=b""):
            return (
                len(payload).to_bytes(3, "big")
                + bytes([frame_type, flags])
                + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
                + payload
            )

        authority = f"127.0.0.1:{VP_TLS_PORT}".encode()
        # HPACK: :method GET, :scheme https, literal :path, literal :authority.
        block = (
            bytes([0x82, 0x87, 0x04, len(b"/hello.txt")])
            + b"/hello.txt"
            + bytes([0x01, len(authority)])
            + authority
        )
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        s.sendall(frame(0x4, 0, 0))  # client SETTINGS
        s.sendall(frame(0x1, 0x4, 1, block))  # HEADERS + END_HEADERS
        time.sleep(0.15)
        s.sendall(frame(0x3, 0, 1, (0x8).to_bytes(4, "big")))  # RST CANCEL
        s.close()

        version, status, body = self.curl(VP_TLS_PORT, "/hello.txt", "--http2")
        self.assertEqual((version, status, body), ("2", 200, b"hello world\n"))

    def test_tls_http2_basic_auth(self):
        version, status, body = self.curl(
            VP_TLS_PORT, "/auth/protected.txt", "--http2",
            "--user", "alice:alicepw",
        )
        self.assertEqual((version, status, body), ("2", 200, b"auth secret\n"))
        version, status, _ = self.curl(VP_TLS_PORT, "/auth/protected.txt", "--http2")
        self.assertEqual((version, status), ("2", 401))

    def test_tls_versions(self):
        for extra in (["--tlsv1.2", "--tls-max", "1.2"], ["--tlsv1.3"]):
            version, status, body = self.curl(
                VP_TLS_PORT, "/hello.txt", "--http1.1", *extra
            )
            self.assertEqual((version, status, body), ("1.1", 200, b"hello world\n"))

    def test_tls_apache_differential(self):
        if not DIFFERENTIAL:
            self.skipTest("requires --differential")
        # Both servers must complete a TLS request and serve the same bytes.
        v = self.curl(VP_TLS_PORT, "/hello.txt", "--http1.1")
        a = self.curl(AP_TLS_PORT, "/hello.txt", "--http1.1")
        self.assertEqual((v[1], v[2]), (a[1], a[2]))

    def test_tls_keepalive_timeout(self):
        ctx = ssl._create_unverified_context()
        s = socket.create_connection(("127.0.0.1", VP_TLS_PORT), timeout=5)
        s = ctx.wrap_socket(s, server_hostname="localhost")
        s.sendall(
            b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        buf = b""
        while b"hello world\n" not in buf:
            buf += s.recv(65536)
        self.assertIn(b"200 OK", buf)
        time.sleep(3.5)
        s.settimeout(5)
        try:
            self.assertEqual(s.recv(1), b"")
        except (ConnectionResetError, ssl.SSLError):
            pass
        s.close()

    def test_tls_rejects_plain_http(self):
        try:
            s = socket.create_connection(("127.0.0.1", VP_TLS_PORT), timeout=5)
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            data = s.recv(100)
            s.close()
        except (OSError, ssl.SSLError):
            return
        # Rustls sends a TLS alert or closes; it must never answer in cleartext.
        self.assertFalse(data.startswith(b"HTTP/"))


def main():
    global DIFFERENTIAL
    ap = argparse.ArgumentParser()
    ap.add_argument("--differential", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    DIFFERENTIAL = args.differential
    if not VAPACHED.exists():
        sys.exit(f"missing {VAPACHED}; cargo build --release first")
    start_servers()
    try:
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        for cls in (
            StaticTests,
            CompressionTests,
            FastCgiTests,
            ProxyTests,
            CgiTests,
            AuthTests,
            RewriteDirectoryTests,
            RewriteFeatureTests,
            OcspTests,
            CacheTests,
            HtaccessTests,
            ConfigTests,
            TlsTests,
        ):
            suite.addTests(loader.loadTestsFromTestCase(cls))
        runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
        result = runner.run(suite)
        if args.differential:
            report = [
                "# Differential report: vapached vs. Apache httpd\n",
                f"Generated: {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}\n",
            ]
            if DIFFS:
                report.append(f"{len(DIFFS)} divergence(s):\n")
                for d in DIFFS:
                    report.append(f"- **{d[0]}**: {d[1]}")
            else:
                report.append("No divergences.\n")
            (ROOT / "tests" / "differential_report.md").write_text("\n".join(report) + "\n")
            print(f"\n{len(DIFFS)} differential divergence(s); see tests/differential_report.md")
        return 0 if result.wasSuccessful() else 1
    finally:
        stop_servers()
        if os.environ.get("KEEP_TEST_TREE") != "1":
            shutil.rmtree(BASE, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
