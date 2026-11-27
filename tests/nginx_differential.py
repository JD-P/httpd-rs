#!/usr/bin/env python3
"""Compare the supported nginx location subset with a stock nginx binary.

This is intentionally an optional system differential, not a replacement for
the in-process route-machine tests.  It starts both servers only on loopback,
uses generated roots/configuration in a temporary directory, and compares the
observable route winner and static response.  When nginx is not installed it
reports a skip so ordinary Rust builds do not gain a system dependency.
"""

from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone
import http.client
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import re


STATIC_CASES = {
    "/exact": "exact",
    "/assets/app.php": "assets",
    "/images/app.php": "php",
    "/images/readme.txt": "images",
    "/other.txt": "root",
}

PROXY_CASES = {
    "/keep/item?x=1": "/keep/item?x=1",
    "/replace/item?x=1": "/base/item?x=1",
    "/balanced/item?x=1": "/base/item?x=1",
}


class EchoBackend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        body = (
            f"path={self.path}\n"
            f"host={self.headers.get('Host', '')}\n"
            f"x-uri={self.headers.get('X-URI', '')}\n"
            f"x-peer={self.headers.get('X-Peer', '')}\n"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length)
        body = f"path={self.path}\nlength={len(payload)}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def fastcgi_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first & 0x80:
        return int.from_bytes(data[offset : offset + 4], "big") & 0x7FFFFFFF, offset + 4
    return first, offset + 1


def fastcgi_params(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    offset = 0
    while offset < len(data):
        name_len, offset = fastcgi_length(data, offset)
        value_len, offset = fastcgi_length(data, offset)
        name = data[offset : offset + name_len]
        offset += name_len
        value = data[offset : offset + value_len]
        offset += value_len
        result[name.decode(errors="replace")] = value.decode(errors="replace")
    return result


def fastcgi_record(kind: int, content: bytes, request_id: int = 1) -> bytes:
    padding = (-len(content)) % 8
    return (
        struct.pack("!BBHHBB", 1, kind, request_id, len(content), padding, 0)
        + content
        + bytes(padding)
    )


class FastCgiBackend:
    def __init__(self, port: int) -> None:
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", port))
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    @staticmethod
    def read_exact(connection: socket.socket, length: int) -> bytes:
        result = bytearray()
        while len(result) < length:
            chunk = connection.recv(length - len(result))
            if not chunk:
                raise EOFError("truncated FastCGI request")
            result.extend(chunk)
        return bytes(result)

    def serve(self, connection: socket.socket) -> None:
        encoded_params = bytearray()
        while True:
            header = self.read_exact(connection, 8)
            version, kind, request_id, length, padding, _ = struct.unpack("!BBHHBB", header)
            if version != 1 or request_id != 1:
                raise ValueError("unexpected FastCGI identity")
            content = self.read_exact(connection, length)
            if padding:
                self.read_exact(connection, padding)
            if kind == 4 and content:
                encoded_params.extend(content)
            if kind == 5 and not content:
                break
        params = fastcgi_params(bytes(encoded_params))
        body = (
            f"script={params.get('SCRIPT_FILENAME', '')}\n"
            f"uri={params.get('REQUEST_URI', '')}\n"
            f"host={params.get('HTTP_HOST', '')}\n"
            f"app={params.get('APP_ENV', '')}\n"
        ).encode()
        stdout = (
            b"Content-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        connection.sendall(
            fastcgi_record(6, stdout)
            + fastcgi_record(6, b"")
            + fastcgi_record(3, bytes(8))
        )

    def run(self) -> None:
        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            with connection:
                self.serve(connection)

    def close(self) -> None:
        self.stopping.set()
        self.thread.join(timeout=3)
        self.listener.close()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_ready(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise RuntimeError(
                f"server exited before readiness ({process.returncode})\n"
                f"stdout:\n{stdout.decode(errors='replace')}\n"
                f"stderr:\n{stderr.decode(errors='replace')}"
            )
        with contextlib.suppress(OSError):
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        time.sleep(0.05)
    raise RuntimeError(f"server did not listen on 127.0.0.1:{port}")


def request(
    port: int,
    path: str,
    host: str = "differential.test",
    *,
    method: str = "GET",
    body: bytes | None = None,
) -> tuple[int, str | None, str | None, str | None, str | None, str | None, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    connection.request(method, path, body=body, headers={"Host": host})
    response = connection.getresponse()
    result = (
        response.status,
        response.getheader("X-Route"),
        response.getheader("Location"),
        response.getheader("X-Inherited"),
        response.getheader("X-Child"),
        response.getheader("Cache-Control"),
        response.read(),
    )
    connection.close()
    return result


def config_text(
    port: int,
    root: Path,
    pid: Path,
    error: Path,
    backend_port: int,
    fastcgi_port: int,
    alias_root: Path,
    httpd_extensions: bool,
    nginx_temp: Path | None = None,
) -> str:
    temp_directives = ""
    if nginx_temp is not None:
        temp_directives = (
            f"client_body_temp_path {nginx_temp / 'client'};\n"
            f"  proxy_temp_path {nginx_temp / 'proxy'};\n"
            f"  fastcgi_temp_path {nginx_temp / 'fastcgi'};\n"
            f"  uwsgi_temp_path {nginx_temp / 'uwsgi'};\n"
            f"  scgi_temp_path {nginx_temp / 'scgi'};"
        )
    extensions = ""
    if httpd_extensions:
        extensions = (
            "httpd_rs_capability FastCgi On;\n"
            "httpd_rs_capability UnstableFastCgiPaths On;"
        )
    return f"""
worker_processes 1;
user {os.environ.get('USER', 'nobody')} {os.environ.get('USER', 'nobody')};
daemon off;
pid {pid};
error_log {error};
{extensions}
events {{ worker_connections 64; }}
http {{
  {temp_directives}
  access_log off;
  add_header X-Inherited parent always;
  upstream app {{ server 127.0.0.1:{backend_port}; }}
  server {{
    listen 127.0.0.1:{port};
    server_name differential.test;
    root {root};
    location = /exact {{ add_header X-Route exact always; }}
    location ^~ /assets/ {{ add_header X-Route assets always; }}
    location /images/ {{ add_header X-Route images always; }}
    location ~ '[.]php$' {{ add_header X-Route php always; }}
    location / {{ add_header X-Route root always; }}
    location /keep/ {{
      proxy_set_header Host $host;
      proxy_set_header X-URI $request_uri;
      proxy_set_header X-Peer $proxy_add_x_forwarded_for;
      proxy_pass http://127.0.0.1:{backend_port};
    }}
    location /replace/ {{
      proxy_set_header Host $host;
      proxy_set_header X-URI $request_uri;
      proxy_set_header X-Peer $proxy_add_x_forwarded_for;
      proxy_pass http://127.0.0.1:{backend_port}/base/;
    }}
    location /balanced/ {{
      proxy_set_header Host $host;
      proxy_set_header X-URI $request_uri;
      proxy_set_header X-Peer $proxy_add_x_forwarded_for;
      proxy_pass http://app/base/;
    }}
    location /headers/ {{
      add_header X-Child child always;
      add_header X-Child sibling always;
    }}
    location /alias/ {{ alias {alias_root}/; }}
    location /fallback/ {{ try_files $uri $uri/ /fallback.html?$args; }}
    location /errors/ {{ error_page 404 /404.html; }}
    location /expiring/ {{ expires 1h; }}
    location /small-body/ {{
      client_max_body_size 4;
      proxy_pass http://127.0.0.1:{backend_port}/upload/;
    }}
    location /unlimited-body/ {{
      client_max_body_size 0;
      proxy_pass http://127.0.0.1:{backend_port}/upload/;
    }}
    location = /moved {{ return 301 https://example.test/final; }}
    location ~ '[.]fcgi$' {{
      fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
      fastcgi_param REQUEST_URI $request_uri;
      fastcgi_param HTTP_HOST $http_host;
      fastcgi_param APP_ENV production;
      fastcgi_pass 127.0.0.1:{fastcgi_port};
    }}
  }}
}}
""".strip() + "\n"


def apache_frontend_config(
    port: int,
    root: Path,
    server_root: Path,
    backend_port: int,
) -> str:
    logs = server_root / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    identity = os.environ.get("USER", "nobody")
    return f"""
ServerRoot "{server_root}"
Listen 127.0.0.1:{port}
User {identity}
Group {identity}
PidFile "{logs / 'httpd.pid'}"
ErrorLog "{logs / 'error.log'}"
LogLevel warn
ServerName differential.test
KeepAlive On
MaxKeepAliveRequests 10000
KeepAliveTimeout 3
DocumentRoot "{root}"
<Directory />
  AllowOverride None
  Require all denied
</Directory>
<Directory "{root}">
  Options FollowSymLinks
  AllowOverride None
  Require all granted
</Directory>
DirectoryIndex index.html
ProxyPass /keep/ http://127.0.0.1:{backend_port}/keep/
ProxyPassReverse /keep/ http://127.0.0.1:{backend_port}/keep/
""".strip() + "\n"


def benchmark_frontends(
    wrk: str,
    ports: dict[str, int],
    output: Path,
    *,
    duration: int = 2,
) -> None:
    scenarios = {"static": "/other.txt", "proxy": "/keep/item?x=1"}
    report: dict[str, object] = {
        "version": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scenarios": {},
    }
    for scenario, path in scenarios.items():
        samples: dict[str, list[float]] = {name: [] for name in ports}
        for port in ports.values():
            subprocess.run(
                [wrk, "-t2", "-c8", "-d1s", f"http://127.0.0.1:{port}{path}"],
                check=True,
                stdout=subprocess.DEVNULL,
            )
        order = list(ports.items())
        for sample in range(3):
            for name, port in (order if sample % 2 == 0 else list(reversed(order))):
                run = subprocess.run(
                    [wrk, "-t2", "-c8", f"-d{duration}s", f"http://127.0.0.1:{port}{path}"],
                    check=True,
                    text=True,
                    capture_output=True,
                )
                match = re.search(r"Requests/sec:\s+([0-9.]+)", run.stdout)
                if match is None:
                    raise RuntimeError(f"wrk omitted throughput for {name}: {run.stdout}")
                samples[name].append(float(match.group(1)))
        medians = {name: sorted(values)[len(values) // 2] for name, values in samples.items()}
        apache_mode = medians["httpd-rs-apache-config"]
        nginx_mode = medians["httpd-rs-nginx-config"]
        report["scenarios"][scenario] = {
            "path": path,
            "samples": samples,
            "median_requests_per_second": medians,
            "nginx_to_apache_config_ratio": nginx_mode / apache_mode,
        }
        print(
            f"benchmark {scenario}: Apache-config={apache_mode:.0f} req/s, "
            f"nginx-config={nginx_mode:.0f} req/s, ratio={nginx_mode / apache_mode:.3f}x"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"nginx deployment benchmark: {output}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--httpd-rs",
        type=Path,
        default=Path(os.environ.get("HTTPD_RS_BIN", "target/debug/httpd-rs")),
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="benchmark the same deployment through Apache- and nginx-syntax httpd-rs configs",
    )
    parser.add_argument("--benchmark-output", type=Path)
    args = parser.parse_args()
    nginx = shutil.which("nginx")
    if nginx is None:
        print("SKIP: stock nginx is not installed")
        return 0
    httpd_rs = args.httpd_rs.resolve()
    if not httpd_rs.is_file():
        print(f"error: httpd-rs binary not found at {httpd_rs}; run cargo build -p httpd-rs", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="httpd-rs-nginx-diff-") as raw:
        temp = Path(raw)
        root = temp / "www"
        for relative, marker in STATIC_CASES.items():
            target = root / relative.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(marker + "\n", encoding="utf-8")
        (root / "echo.fcgi").write_text("FastCGI fixture\n", encoding="utf-8")
        (root / "headers/index.html").parent.mkdir(parents=True, exist_ok=True)
        (root / "headers/index.html").write_text("headers\n", encoding="utf-8")
        (root / "fallback.html").write_text("fallback\n", encoding="utf-8")
        (root / "404.html").write_text("custom-error\n", encoding="utf-8")
        (root / "expiring/index.html").parent.mkdir(parents=True, exist_ok=True)
        (root / "expiring/index.html").write_text("expiring\n", encoding="utf-8")
        alias_root = temp / "alias-root"
        alias_root.mkdir()
        (alias_root / "fixture.txt").write_text("aliased\n", encoding="utf-8")

        nginx_port, httpd_port, apache_mode_port, backend_port, fastcgi_port = (
            free_port(),
            free_port(),
            free_port(),
            free_port(),
            free_port(),
        )
        backend = ThreadingHTTPServer(("127.0.0.1", backend_port), EchoBackend)
        backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
        backend_thread.start()
        fastcgi = FastCgiBackend(fastcgi_port)
        nginx_prefix = temp / "nginx-prefix"
        nginx_prefix.mkdir()
        nginx_config = temp / "stock-nginx.conf"
        httpd_config = temp / "httpd-rs-nginx.conf"
        nginx_config.write_text(
            config_text(
                nginx_port,
                root,
                temp / "nginx.pid",
                temp / "nginx-error.log",
                backend_port,
                fastcgi_port,
                alias_root,
                False,
                nginx_prefix,
            ),
            encoding="utf-8",
        )
        httpd_config.write_text(
            config_text(
                httpd_port,
                root,
                temp / "httpd-rs.pid",
                temp / "httpd-rs-error.log",
                backend_port,
                fastcgi_port,
                alias_root,
                True,
            ),
            encoding="utf-8",
        )
        apache_mode_config = temp / "httpd-rs-apache.conf"
        apache_mode_config.write_text(
            apache_frontend_config(
                apache_mode_port,
                root,
                temp / "httpd-rs-apache",
                backend_port,
            ),
            encoding="utf-8",
        )

        stock = subprocess.Popen(
            [nginx, "-p", str(nginx_prefix), "-c", str(nginx_config)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        ours = subprocess.Popen(
            [
                str(httpd_rs),
                "-d",
                str(temp),
                "-f",
                str(httpd_config),
                "--config-format",
                "nginx",
                "-X",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        ours_apache = None
        if args.benchmark:
            ours_apache = subprocess.Popen(
                [
                    str(httpd_rs),
                    "-d",
                    str(temp),
                    "-f",
                    str(apache_mode_config),
                    "--config-format",
                    "apache",
                    "-X",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        try:
            wait_ready(stock, nginx_port)
            wait_ready(ours, httpd_port)
            if ours_apache is not None:
                wait_ready(ours_apache, apache_mode_port)
            failures = []
            for path, expected_route in STATIC_CASES.items():
                stock_result = request(nginx_port, path)
                ours_result = request(httpd_port, path)
                if stock_result != ours_result or stock_result[1] != expected_route:
                    failures.append((path, expected_route, stock_result, ours_result))
            for path, expected_path in PROXY_CASES.items():
                stock_result = request(nginx_port, path, f"differential.test:{nginx_port}")
                ours_result = request(httpd_port, path, f"differential.test:{httpd_port}")
                expected_line = f"path={expected_path}\n".encode()
                if stock_result != ours_result or not stock_result[6].startswith(expected_line):
                    failures.append((path, expected_path, stock_result, ours_result))
            stock_redirect = request(nginx_port, "/moved?x=1")
            ours_redirect = request(httpd_port, "/moved?x=1")
            redirect_projection = (stock_redirect[:3], ours_redirect[:3])
            if (
                stock_redirect[:3] != ours_redirect[:3]
                or stock_redirect[0] != 301
                or stock_redirect[2] != "https://example.test/final"
            ):
                failures.append(("/moved?x=1", "exact return", *redirect_projection))
            stock_fastcgi = request(nginx_port, "/echo.fcgi?x=1")
            ours_fastcgi = request(httpd_port, "/echo.fcgi?x=1")
            if stock_fastcgi != ours_fastcgi:
                failures.append(("/echo.fcgi?x=1", "FastCGI parameters", stock_fastcgi, ours_fastcgi))
            feature_cases = (
                ("/alias/fixture.txt", b"aliased\n", None),
                ("/fallback/deep/path?x=1", b"fallback\n", None),
                ("/errors/missing", b"custom-error\n", None),
                ("/headers/", b"headers\n", "child-replaces-parent"),
                ("/expiring/", b"expiring\n", "expires"),
            )
            for path, expected_body, property_name in feature_cases:
                stock_result = request(nginx_port, path)
                ours_result = request(httpd_port, path)
                if stock_result != ours_result or stock_result[6] != expected_body:
                    failures.append((path, property_name or "static projection", stock_result, ours_result))
                    continue
                if property_name == "child-replaces-parent" and (
                    stock_result[3] is not None
                    or stock_result[4] != "child, sibling"
                ):
                    failures.append((path, property_name, stock_result, ours_result))
                if property_name == "expires" and stock_result[5] != "max-age=3600":
                    failures.append((path, property_name, stock_result, ours_result))
            for size, expected_status in ((4, 200), (5, 413)):
                stock_result = request(
                    nginx_port, "/small-body/item", method="POST", body=b"x" * size
                )
                ours_result = request(
                    httpd_port, "/small-body/item", method="POST", body=b"x" * size
                )
                same = (
                    stock_result == ours_result
                    if expected_status == 200
                    else stock_result[:6] == ours_result[:6]
                )
                if not same or stock_result[0] != expected_status:
                    failures.append((f"POST /small-body/item ({size})", expected_status, stock_result, ours_result))
            stock_unlimited = request(
                nginx_port, "/unlimited-body/item", method="POST", body=b"x" * 1024
            )
            ours_unlimited = request(
                httpd_port, "/unlimited-body/item", method="POST", body=b"x" * 1024
            )
            if stock_unlimited != ours_unlimited or stock_unlimited[0] != 200:
                failures.append(
                    (
                        "POST /unlimited-body/item (client_max_body_size 0)",
                        200,
                        stock_unlimited,
                        ours_unlimited,
                    )
                )
            if failures:
                for failure in failures:
                    print(f"mismatch: {failure!r}", file=sys.stderr)
                return 1
            if ours_apache is not None:
                apache_static = request(apache_mode_port, "/other.txt")
                apache_proxy = request(apache_mode_port, "/keep/item?x=1")
                if apache_static[0] != 200 or apache_static[6] != b"root\n":
                    print(f"Apache-config deployment static mismatch: {apache_static!r}", file=sys.stderr)
                    return 1
                if apache_proxy[0] != 200 or not apache_proxy[6].startswith(b"path=/keep/item?x=1\n"):
                    print(f"Apache-config deployment proxy mismatch: {apache_proxy!r}", file=sys.stderr)
                    return 1
                wrk = shutil.which("wrk")
                if wrk is None:
                    print("error: --benchmark requires wrk", file=sys.stderr)
                    return 2
                output = args.benchmark_output
                if output is None:
                    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                    output = Path("bench/results") / f"nginx-deployment-{stamp}.json"
                benchmark_frontends(
                    wrk,
                    {
                        "stock-nginx": nginx_port,
                        "httpd-rs-apache-config": apache_mode_port,
                        "httpd-rs-nginx-config": httpd_port,
                    },
                    output,
                )
            count = len(STATIC_CASES) + len(PROXY_CASES) + len(feature_cases) + 5
            print(f"nginx differential OK ({count} routing, policy, backend and body-admission cases)")
            return 0
        finally:
            processes = [ours, stock]
            if ours_apache is not None:
                processes.append(ours_apache)
            for process in processes:
                if process.poll() is None:
                    process.terminate()
            for process in processes:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=3)
                if process.poll() is None:
                    process.kill()
                    process.wait()
            backend.shutdown()
            backend.server_close()
            backend_thread.join(timeout=3)
            fastcgi.close()


if __name__ == "__main__":
    raise SystemExit(main())
