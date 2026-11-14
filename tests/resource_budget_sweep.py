#!/usr/bin/env python3
"""Measure attacker-controlled request axes against the live resource ledger.

This is calibration evidence, not a benchmark and not an alternative security
boundary.  httpd-rs continues to enforce its existing hard limits while the
extended server-status telemetry reports monotonic high-water marks,
admission rejections, and verified shadow candidates beneath those limits.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import grp
import http.client
import http.server
import itertools
import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

import resource_profile


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUN = Path("/tmp/httpd-rs-resource-budget-sweep")
DEFAULT_OUTPUT = ROOT / "artifacts" / "resource-warrant" / "budget-calibration.json"
HTTPD_RS = Path(os.environ.get("HTTPD_RS", ROOT / "target" / "release" / "httpd-rs"))
USER = pwd.getpwuid(os.geteuid()).pw_name
GROUP = grp.getgrgid(os.getegid()).gr_name
SUPPLEMENTAL_LEDGER_EVIDENCE = {
    name: "resource::tests::specialized_ledger_calibration_paths_are_observed_and_released"
    for name in (
        "RewriteProgram",
        "SlowInput",
        "SlowOutput",
        "SlowResponseResidentBytes",
        "SlowSpoolBytes",
        "SlowSpoolFile",
        "Websocket",
    )
}


class CalibrationHandler(http.server.BaseHTTPRequestHandler):
    """A bounded local sink used to exercise real proxy upload/hold paths."""

    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def _reply(self, body: bytes = b"ok\n") -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.rstrip("/").endswith("/hold"):
            time.sleep(0.25)
        self._reply()

    def do_POST(self) -> None:
        remaining = int(self.headers.get("Content-Length", "0"))
        while remaining:
            chunk = self.rfile.read(min(remaining, 64 * 1024))
            if not chunk:
                break
            remaining -= len(chunk)
        self._reply(str(remaining).encode("ascii") + b"\n")


class CalibrationBackend:
    def __init__(self) -> None:
        self.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), CalibrationHandler
        )
        self.server.daemon_threads = True
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name="resource-calibration-backend",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_port(port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def stop(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        process.wait()


def request(
    port: int,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    started = time.perf_counter_ns()
    response: http.client.HTTPResponse | None = None
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        elapsed = time.perf_counter_ns() - started
        return {
            "status": response.status,
            "response_bytes": len(payload),
            "content_encoding": response.getheader("Content-Encoding"),
            "content_length": response.getheader("Content-Length"),
            "transfer_encoding": response.getheader("Transfer-Encoding"),
            "elapsed_ns": elapsed,
            "error": None,
        }
    except Exception as error:  # Workload failures belong in the evidence.
        return {
            "status": response.status if response is not None else None,
            "response_bytes": 0,
            "content_encoding": (
                response.getheader("Content-Encoding") if response is not None else None
            ),
            "content_length": (
                response.getheader("Content-Length") if response is not None else None
            ),
            "transfer_encoding": (
                response.getheader("Transfer-Encoding") if response is not None else None
            ),
            "elapsed_ns": time.perf_counter_ns() - started,
            "error": f"{type(error).__name__}: {error}",
        }
    finally:
        connection.close()


def chunked_request(port: int, path: str, size: int, timeout: float = 20.0) -> dict[str, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    started = time.perf_counter_ns()
    response: http.client.HTTPResponse | None = None
    try:
        connection.putrequest("POST", path)
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Transfer-Encoding", "chunked")
        connection.endheaders()
        remaining = size
        chunk = b"c" * (64 * 1024)
        while remaining:
            payload = chunk[: min(remaining, len(chunk))]
            connection.send(f"{len(payload):x}\r\n".encode("ascii"))
            connection.send(payload)
            connection.send(b"\r\n")
            remaining -= len(payload)
        connection.send(b"0\r\n\r\n")
        response = connection.getresponse()
        payload = response.read()
        return {
            "status": response.status,
            "response_bytes": len(payload),
            "content_encoding": response.getheader("Content-Encoding"),
            "content_length": response.getheader("Content-Length"),
            "transfer_encoding": response.getheader("Transfer-Encoding"),
            "elapsed_ns": time.perf_counter_ns() - started,
            "error": None,
        }
    except Exception as error:
        return {
            "status": response.status if response is not None else None,
            "response_bytes": 0,
            "content_encoding": None,
            "content_length": None,
            "transfer_encoding": None,
            "elapsed_ns": time.perf_counter_ns() - started,
            "error": f"{type(error).__name__}: {error}",
        }
    finally:
        connection.close()


def curl_request(port: int, protocol: str) -> dict[str, Any]:
    started = time.perf_counter_ns()
    completed = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--insecure",
            f"--http{protocol}",
            "--max-time",
            "20",
            "--write-out",
            "\n%{http_code}:%{size_download}:%{http_version}",
            f"https://127.0.0.1:{port}/size-1024.txt",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    try:
        _, marker = completed.stdout.rsplit(b"\n", 1)
        status_text, size_text, version = marker.decode("ascii").split(":", 2)
        status = int(status_text)
        response_bytes = int(float(size_text))
        error = None if completed.returncode == 0 else completed.stderr.decode("utf-8", "replace")
        if error is None and version != protocol:
            error = f"curl negotiated HTTP/{version}, expected HTTP/{protocol}"
    except (ValueError, UnicodeDecodeError):
        status = None
        response_bytes = 0
        version = None
        error = completed.stderr.decode("utf-8", "replace") or "curl output was malformed"
    return {
        "status": status,
        "response_bytes": response_bytes,
        "content_encoding": None,
        "content_length": None,
        "transfer_encoding": None,
        "http_version": version,
        "elapsed_ns": time.perf_counter_ns() - started,
        "error": error,
    }


def status_metrics(port: int) -> dict[str, int]:
    result = request(port, "GET", "/server-status?auto")
    if result["status"] != 200:
        raise RuntimeError(f"server-status unavailable: {result}")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request("GET", "/server-status?auto")
        response = connection.getresponse()
        body = response.read().decode("ascii", "replace")
    finally:
        connection.close()
    metrics: dict[str, int] = {}
    for line in body.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.startswith("HttpdRs"):
            try:
                metrics[key] = int(value.strip())
            except ValueError:
                pass
    return metrics


def process_metrics(pid: int) -> dict[str, int]:
    sample = resource_profile.sample_process(pid)
    if sample is None:
        raise RuntimeError("httpd-rs exited during the calibration sweep")
    stat = sample["stat"]
    status = sample["status"]
    smaps = sample["smaps"]
    return {
        "cpu_ticks": int(stat["user_ticks"]) + int(stat["system_ticks"]),
        "resident_bytes": int(stat["resident_bytes"]),
        "high_water_bytes": int(status.get("VmHWM", 0)),
        "private_bytes": int(smaps.get("Private_Clean", 0))
        + int(smaps.get("Private_Dirty", 0)),
        "threads": int(stat["threads"]),
        "fds": int(sample["fds"]["total"]),
        "socket_fds": int(sample["fds"]["socket"]),
        "pipe_fds": int(sample["fds"]["pipe"]),
    }


def make_fixture(run: Path) -> tuple[Path, dict[int, str]]:
    if run.exists():
        shutil.rmtree(run)
    document_root = run / "www"
    server_root = run / "server"
    document_root.mkdir(parents=True)
    (server_root / "logs").mkdir(parents=True)
    (server_root / "cache").mkdir()
    for size in (1024, 64 * 1024, 1024 * 1024, 8 * 1024 * 1024):
        path = document_root / f"size-{size}.txt"
        path.write_bytes((b"resource-budget-calibration\n" * (size // 28 + 1))[:size])
        os.chmod(path, 0o644)
    (document_root / "cache").mkdir()
    shutil.copyfile(
        document_root / "size-65536.txt", document_root / "cache" / "payload.txt"
    )
    (document_root / "auth").mkdir()
    (document_root / "auth" / "protected.txt").write_text("authenticated\n")
    (server_root / "users.htpasswd").write_text(
        "alice:$2y$05$lFdvgVrS6ROEENEOjKS5h.y4SA05OvKSOFRPC1BcjARNhNt.DQ8jC\n"
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(server_root / "key.pem"),
            "-out",
            str(server_root / "cert.pem"),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    depth_paths: dict[int, str] = {}
    current = document_root
    for depth in range(1, 33):
        current /= f"d{depth:02d}"
        current.mkdir()
        directive = (
            'SetEnvIf Request_URI "^/d" resource_depth_1=1\n'
            if depth == 1
            else f"SetEnv resource_depth_{depth} 1\n"
        )
        (current / ".htaccess").write_text(directive)
        os.chmod(current / ".htaccess", 0o644)
        if depth in {1, 4, 16, 32}:
            (current / "index.txt").write_text("depth calibration\n")
            os.chmod(current / "index.txt", 0o644)
            depth_paths[depth] = "/" + current.relative_to(document_root).as_posix() + "/index.txt"
    for path in [
        run,
        document_root,
        document_root / "cache",
        document_root / "auth",
        server_root,
        server_root / "logs",
        server_root / "cache",
    ]:
        os.chmod(path, 0o755)
    os.chmod(server_root / "key.pem", 0o400)
    os.chmod(server_root / "cert.pem", 0o444)
    os.chmod(server_root / "users.htpasswd", 0o444)
    return document_root, depth_paths


def write_config(
    run: Path,
    document_root: Path,
    port: int,
    tls_port: int,
    backend_port: int,
    *,
    brotli_quality: int | None,
) -> Path:
    server_root = run / "server"
    compression = ""
    if brotli_quality is not None:
        compression = (
            "AddOutputFilterByType BROTLI_COMPRESS text/plain\n"
            f"BrotliCompressionQuality {brotli_quality}\n"
        )
    config = server_root / "httpd.conf"
    config.write_text(
        f'''ServerRoot "{server_root}"
Listen 127.0.0.1:{port}
ServerName resource-budget.local
User {USER}
Group {GROUP}
PidFile "{server_root}/logs/httpd.pid"
ErrorLog "{server_root}/logs/error.log"
LogLevel warn
Timeout 20
KeepAlive On
MaxKeepAliveRequests 1000
KeepAliveTimeout 2
HttpdRsCapability AccessFiles On
HttpdRsCapability ServerStatus On
HttpdRsCapability MutableAuthFiles On
ExtendedStatus On
TypesConfig /etc/mime.types
CacheRoot "{server_root}/cache"
CacheEnable disk /cache/
CacheIgnoreNoLastMod On
CacheDefaultExpire 3600
CacheMaxExpire 3600
CacheMaxFileSize 2097152
DocumentRoot "{document_root}"
<Directory />
    Require all denied
</Directory>
<Directory "{document_root}">
    Options FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
<Directory "{document_root}/auth">
    AuthType Basic
    AuthName calibration
    AuthUserFile "{server_root}/users.htpasswd"
    Require valid-user
</Directory>
<Location /server-status>
    SetHandler server-status
    Require all granted
</Location>
RewriteEngine On
RewriteRule ^a+z$ - [L]
ProxyPass /calibration-backend http://127.0.0.1:{backend_port}/
ProxyPassReverse /calibration-backend http://127.0.0.1:{backend_port}/
Listen 127.0.0.1:{tls_port}
<VirtualHost 127.0.0.1:{tls_port}>
    ServerName localhost
    SSLEngine On
    Protocols h2 http/1.1
    SSLCertificateFile "{server_root}/cert.pem"
    SSLCertificateKeyFile "{server_root}/key.pem"
</VirtualHost>
{compression}'''
    )
    return config


class Server:
    def __init__(
        self,
        run: Path,
        document_root: Path,
        *,
        backend_port: int,
        brotli_quality: int | None,
    ) -> None:
        self.run = run
        self.port = free_port()
        self.tls_port = free_port()
        self.config = write_config(
            run,
            document_root,
            self.port,
            self.tls_port,
            backend_port,
            brotli_quality=brotli_quality,
        )
        self.process: subprocess.Popen[bytes] | None = None
        self.log = None

    def __enter__(self) -> "Server":
        self.log = open(self.run / "server" / "stdout.log", "ab")
        self.process = subprocess.Popen(
            [str(HTTPD_RS), "-f", str(self.config), "-DFOREGROUND"],
            stdout=self.log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if not wait_port(self.port) or not wait_port(self.tls_port):
            stop(self.process)
            raise RuntimeError(
                f"httpd-rs failed to start; see {self.run / 'server' / 'stdout.log'}"
            )
        if request(self.port, "GET", "/server-status?auto")["status"] != 200:
            raise RuntimeError("extended server-status probe failed")
        return self

    def __exit__(self, *_: object) -> None:
        stop(self.process)
        if self.log is not None:
            self.log.close()

    @property
    def pid(self) -> int:
        if self.process is None:
            raise RuntimeError("server is not running")
        return self.process.pid


def exercise(
    server: Server,
    *,
    axis: str,
    value: int,
    requests: int,
    concurrency: int,
    operation: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    before_process = process_metrics(server.pid)
    before_status = status_metrics(server.port)
    started = time.perf_counter_ns()
    if concurrency == 1:
        responses = [operation() for _ in range(requests)]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            responses = list(pool.map(lambda _: operation(), range(requests)))
    elapsed = time.perf_counter_ns() - started
    after_status = status_metrics(server.port)
    after_process = process_metrics(server.pid)
    statuses: dict[str, int] = {}
    for response in responses:
        key = str(response["status"] if response["status"] is not None else "error")
        statuses[key] = statuses.get(key, 0) + 1
    rejection_delta = {
        key: after_status[key] - before_status.get(key, 0)
        for key in after_status
        if key.endswith("Rejections") and after_status[key] != before_status.get(key, 0)
    }
    return {
        "axis": axis,
        "value": value,
        "requests": requests,
        "concurrency": concurrency,
        "elapsed_ns": elapsed,
        "cpu_ticks_delta": after_process["cpu_ticks"] - before_process["cpu_ticks"],
        "statuses": statuses,
        "response_bytes": sum(item["response_bytes"] for item in responses),
        "encodings": sorted(
            {item["content_encoding"] for item in responses if item["content_encoding"]}
        ),
        "content_lengths": sorted(
            {item["content_length"] for item in responses if item["content_length"]}
        ),
        "transfer_encodings": sorted(
            {item["transfer_encoding"] for item in responses if item["transfer_encoding"]}
        ),
        "errors": sorted({item["error"] for item in responses if item["error"]}),
        "process_before": before_process,
        "process_after": after_process,
        "ledger": after_status,
        "rejection_delta": rejection_delta,
    }


def summarize_ledgers(points: list[dict[str, Any]]) -> list[dict[str, Any]]:
    prefixes: set[str] = set()
    for point in points:
        prefixes.update(
            key.removesuffix("HighWater")
            for key in point.get("ledger", {})
            if key.startswith("HttpdRsBudget") and key.endswith("HighWater")
        )
    prefixes.update(("HttpdRsDiskByte", "HttpdRsDiskFile", "HttpdRsTransport"))
    summary = []
    for prefix in sorted(prefixes):
        samples = [point.get("ledger", {}) for point in points]
        high_water = max((sample.get(prefix + "HighWater", 0) for sample in samples), default=0)
        limit_key = prefix + ("ByteLimit" if prefix == "HttpdRsTransport" else "Limit")
        limits = [sample[limit_key] for sample in samples if sample.get(limit_key, 0)]
        candidates = [sample.get(prefix + "ShadowCandidate", 0) for sample in samples]
        rejections = [sample.get(prefix + "Rejections", 0) for sample in samples]
        observed_samples = [sample.get(prefix + "Observed", 1) for sample in samples]
        summary.append(
            {
                "name": prefix.removeprefix("HttpdRsBudget").removeprefix("HttpdRs"),
                "observed": any(observed_samples),
                "high_water": high_water,
                "limit": min(limits) if limits else 0,
                "shadow_candidate": max(candidates, default=0),
                "rejections": max(rejections, default=0),
            }
        )
    return summary


def render_markdown(document: dict[str, Any]) -> str:
    lines = [
        "# Request resource budget calibration",
        "",
        f"Revision: `{document.get('git_revision') or 'unknown'}`",
        "",
        "Hard limits remained enforced throughout. Shadow candidates are reporting-only and are proved not to exceed their corresponding hard limit.",
        "",
        "| axis | value | requests | concurrency | CPU ticks | status | RSS after MiB | rejections |",
        "|---|---:|---:|---:|---:|---|---:|---|",
    ]
    for point in document["points"]:
        statuses = ", ".join(
            f"{key}:{value}" for key, value in point["statuses"].items()
        )
        rejections = (
            ", ".join(
                f"{key.removeprefix('HttpdRsBudget').removesuffix('Rejections')}:{value}"
                for key, value in point["rejection_delta"].items()
            )
            or "none"
        )
        lines.append(
            f"| {point['axis']} | {point['value']} | {point['requests']} | "
            f"{point['concurrency']} | {point['cpu_ticks_delta']} | {statuses} | "
            f"{point['process_after']['resident_bytes'] / (1024 * 1024):.2f} | "
            f"{rejections} |"
        )
    ledger_summary = document.get("ledger_summary") or summarize_ledgers(document["points"])
    if ledger_summary:
        lines.extend(
            [
                "",
                "## Ledger calibration summary",
                "",
                "| ledger | observed | high-water | enforced limit | shadow candidate | rejections |",
                "|---|---:|---:|---:|---:|---:|",
            ]
        )
        for gauge in ledger_summary:
            lines.append(
                f"| {gauge['name']} | {int(gauge['observed'])} | {gauge['high_water']} | "
                f"{gauge['limit']} | {gauge['shadow_candidate']} | {gauge['rejections']} |"
            )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A shadow candidate is twice the observed high-water mark or the observed mark plus a fixed reserve, whichever is larger, clamped to the enforced hard ceiling. It is evidence for later tightening, not an automatically activated limit.",
            "",
            "Expected overload rejections are retained in the table. Any transport error, unexpected status family, or non-monotonic cost curve remains review evidence rather than being discarded.",
        ]
    )
    live_unobserved = document.get("live_unobserved_ledgers", [])
    if live_unobserved:
        lines.extend(
            [
                "",
                "The live protocol sweep did not naturally enter these long-lived states: "
                + ", ".join(f"`{name}`" for name in live_unobserved)
                + ". Their deterministic state-machine calibration acquires each lease, checks current/high-water telemetry, drops it, and requires current ownership to return to zero.",
            ]
        )
    unobserved = document.get("unobserved_ledgers")
    if unobserved is None:
        unobserved = [gauge["name"] for gauge in ledger_summary if not gauge["observed"]]
    if unobserved:
        lines.extend(
            [
                "",
                "This run did not exercise these typed ledgers; they remain explicit static/proof or broader deployment-campaign obligations rather than being inferred absent: "
                + ", ".join(f"`{name}`" for name in unobserved)
                + ".",
            ]
        )
    return "\n".join(lines) + "\n"


def git_revision() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN)
    parser.add_argument("--quick", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument(
        "--axes",
        default="response-bytes,header-bytes,request-body-bytes,chunked-request-body-bytes,path-depth,path-churn,regex-subject-bytes,concurrency,cache,authentication,protocol,compression",
        help="comma-separated axes or all",
    )
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not HTTPD_RS.exists():
        raise SystemExit(f"{HTTPD_RS} is missing; run cargo build --release")
    axes = {
        "response-bytes",
        "header-bytes",
        "request-body-bytes",
        "chunked-request-body-bytes",
        "path-depth",
        "path-churn",
        "regex-subject-bytes",
        "concurrency",
        "cache",
        "authentication",
        "protocol",
        "compression",
    }
    selected = axes if args.axes == "all" else {item for item in args.axes.split(",") if item}
    unknown = selected - axes
    if unknown:
        raise SystemExit(f"unknown calibration axes: {sorted(unknown)}")

    document_root, depth_paths = make_fixture(args.run_root)
    points: list[dict[str, Any]] = []
    repeats = 4 if args.quick else 32
    backend = CalibrationBackend()
    backend.start()
    try:
        with Server(
            args.run_root,
            document_root,
            backend_port=backend.port,
            brotli_quality=None,
        ) as server:
            if "response-bytes" in selected:
                for size in (1024, 64 * 1024, 1024 * 1024, 8 * 1024 * 1024):
                    points.append(
                        exercise(
                            server,
                            axis="response-bytes",
                            value=size,
                            requests=repeats,
                            concurrency=1,
                            operation=lambda size=size: request(
                                server.port, "GET", f"/size-{size}.txt"
                            ),
                        )
                    )
            if "header-bytes" in selected:
                for size in (512, 2048, 7168):
                    points.append(
                        exercise(
                            server,
                            axis="header-bytes",
                            value=size,
                            requests=repeats,
                            concurrency=1,
                            operation=lambda size=size: request(
                                server.port,
                                "GET",
                                "/size-1024.txt",
                                headers={"X-Resource-Calibration": "h" * size},
                            ),
                        )
                    )
            if "request-body-bytes" in selected:
                for size in (1024, 1024 * 1024, 8 * 1024 * 1024):
                    body = b"b" * size
                    points.append(
                        exercise(
                            server,
                            axis="request-body-bytes",
                            value=size,
                            requests=max(1, repeats // 2),
                            concurrency=1,
                            operation=lambda body=body: request(
                                server.port,
                                "POST",
                                "/calibration-backend/upload",
                                headers={"Content-Type": "application/octet-stream"},
                                body=body,
                            ),
                        )
                    )
            if "chunked-request-body-bytes" in selected:
                for size in (1024 * 1024, 8 * 1024 * 1024):
                    points.append(
                        exercise(
                            server,
                            axis="chunked-request-body-bytes",
                            value=size,
                            requests=1 if args.quick else 8,
                            concurrency=1,
                            operation=lambda size=size: chunked_request(
                                server.port, "/calibration-backend/upload", size
                            ),
                        )
                    )
            if "path-depth" in selected:
                for depth in (1, 4, 16, 32):
                    points.append(
                        exercise(
                            server,
                            axis="path-depth",
                            value=depth,
                            requests=repeats,
                            concurrency=1,
                            operation=lambda depth=depth: request(
                                server.port, "GET", depth_paths[depth]
                            ),
                        )
                    )
            if "path-churn" in selected:
                churn_requests = 1024 if args.quick else 32 * 1024
                churn_sequence = itertools.count()
                points.append(
                    exercise(
                        server,
                        axis="path-churn-control",
                        value=churn_requests,
                        requests=churn_requests,
                        concurrency=16,
                        operation=lambda: request(
                            server.port, "GET", "/missing-resource-profile-control"
                        ),
                    )
                )
                points.append(
                    exercise(
                        server,
                        axis="path-churn",
                        value=churn_requests,
                        requests=churn_requests,
                        concurrency=16,
                        operation=lambda: request(
                            server.port,
                            "GET",
                            f"/missing-resource-profile-{next(churn_sequence):08x}",
                        ),
                    )
                )
            if "regex-subject-bytes" in selected:
                for size in (16, 256, 2048, 7000):
                    target = "/" + "a" * size + "y"
                    points.append(
                        exercise(
                            server,
                            axis="regex-subject-bytes",
                            value=size,
                            requests=repeats,
                            concurrency=1,
                            operation=lambda target=target: request(
                                server.port, "GET", target
                            ),
                        )
                    )
            if "concurrency" in selected:
                for concurrency in (1, 4, 8, 16):
                    points.append(
                        exercise(
                            server,
                            axis="concurrency",
                            value=concurrency,
                            requests=max(repeats, concurrency * 2),
                            concurrency=concurrency,
                            operation=lambda: request(
                                server.port, "GET", "/calibration-backend/hold"
                            ),
                        )
                    )
            if "cache" in selected:
                for requests in (1, repeats * 2):
                    points.append(
                        exercise(
                            server,
                            axis="cache-lookups",
                            value=requests,
                            requests=requests,
                            concurrency=1,
                            operation=lambda: request(
                                server.port, "GET", "/cache/payload.txt"
                            ),
                        )
                    )
            if "authentication" in selected:
                points.append(
                    exercise(
                        server,
                        axis="bcrypt-authentication",
                        value=5,
                        requests=repeats,
                        concurrency=1,
                        operation=lambda: request(
                            server.port,
                            "GET",
                            "/auth/protected.txt",
                            headers={"Authorization": "Basic YWxpY2U6c2VjcmV0"},
                        ),
                    )
                )
            if "protocol" in selected:
                points.append(
                    exercise(
                        server,
                        axis="http-version",
                        value=2,
                        requests=repeats,
                        concurrency=1,
                        operation=lambda: curl_request(server.tls_port, "2"),
                    )
                )

        if "compression" in selected:
            for quality in (0, 5, 9):
                with Server(
                    args.run_root,
                    document_root,
                    backend_port=backend.port,
                    brotli_quality=quality,
                ) as server:
                    for size in (64 * 1024, 1024 * 1024, 8 * 1024 * 1024):
                        points.append(
                            exercise(
                                server,
                                axis=f"brotli-quality-{quality}",
                                value=size,
                                requests=max(1, repeats // 2),
                                concurrency=1,
                                operation=lambda size=size: request(
                                    server.port,
                                    "GET",
                                    f"/size-{size}.txt",
                                    headers={"Accept-Encoding": "br"},
                                ),
                            )
                        )
    finally:
        backend.stop()
        if not args.keep:
            shutil.rmtree(args.run_root, ignore_errors=True)

    document = {
        "schema": 1,
        "kind": "httpd-rs-resource-budget-calibration",
        "git_revision": git_revision(),
        "quick": args.quick,
        "selected_axes": sorted(selected),
        "hard_limits_enforced": True,
        "shadow_candidates_enforced": False,
        "points": points,
        "ledger_summary": summarize_ledgers(points),
    }
    document["live_unobserved_ledgers"] = [
        gauge["name"] for gauge in document["ledger_summary"] if not gauge["observed"]
    ]
    document["supplemental_ledger_evidence"] = {
        name: evidence
        for name, evidence in SUPPLEMENTAL_LEDGER_EVIDENCE.items()
        if name in document["live_unobserved_ledgers"]
    }
    document["unobserved_ledgers"] = [
        name
        for name in document["live_unobserved_ledgers"]
        if name not in document["supplemental_ledger_evidence"]
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    markdown = args.output.with_suffix(".md")
    markdown.write_text(render_markdown(document))
    print(
        f"resource-budget-sweep: {len(points)} point(s) -> {args.output} and {markdown}"
    )
    failures = []
    if document["unobserved_ledgers"]:
        failures.append(
            "typed ledgers lack live or deterministic calibration evidence: "
            + ", ".join(document["unobserved_ledgers"])
        )
    for point in points:
        allowed = (
            {"404"}
            if point["axis"]
            in {"regex-subject-bytes", "path-churn", "path-churn-control"}
            else {"200"}
        )
        if point["axis"] == "concurrency":
            allowed.add("503")
        if point["axis"] in {"path-churn", "path-churn-control"}:
            # The churn case deliberately keeps sixteen fresh transports in
            # flight; bounded pending/filesystem admission may shed a prefix.
            allowed.add("503")
        unexpected = set(point["statuses"]) - allowed
        if point["errors"] or unexpected:
            failures.append(
                f"{point['axis']}={point['value']} errors={point['errors']} statuses={point['statuses']}"
            )
    for gauge in document["ledger_summary"]:
        if gauge["observed"] and gauge["limit"] and not (
            gauge["high_water"] <= gauge["shadow_candidate"] <= gauge["limit"]
        ):
            failures.append(f"invalid shadow candidate: {gauge}")
    if failures:
        print("resource-budget-sweep: calibration failure(s):", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
