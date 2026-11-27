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
import http.client
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
    port: int, path: str, host: str = "differential.test"
) -> tuple[int, str | None, str | None, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    connection.request("GET", path, headers={"Host": host})
    response = connection.getresponse()
    result = (
        response.status,
        response.getheader("X-Route"),
        response.getheader("Location"),
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--httpd-rs",
        type=Path,
        default=Path(os.environ.get("HTTPD_RS_BIN", "target/debug/httpd-rs")),
    )
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

        nginx_port, httpd_port, backend_port, fastcgi_port = (
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
                True,
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
        try:
            wait_ready(stock, nginx_port)
            wait_ready(ours, httpd_port)
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
                if stock_result != ours_result or not stock_result[3].startswith(expected_line):
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
            if failures:
                for failure in failures:
                    print(f"mismatch: {failure!r}", file=sys.stderr)
                return 1
            count = len(STATIC_CASES) + len(PROXY_CASES) + 2
            print(f"nginx differential OK ({count} route/proxy/redirect cases)")
            return 0
        finally:
            for process in (ours, stock):
                if process.poll() is None:
                    process.terminate()
            for process in (ours, stock):
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
