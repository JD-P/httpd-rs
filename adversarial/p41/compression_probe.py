#!/usr/bin/env python3
"""Pass-41 reproducer for Brotli quality-11 transient resource use."""

from __future__ import annotations

import concurrent.futures
import grp
import http.client
import os
import pwd
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
HTTPD = REPO / "target/release/httpd-rs"
BODY_BYTES = int(os.environ.get("P41_BODY_BYTES", 2 * 1024 * 1024))
CLIENTS = int(os.environ.get("P41_CLIENTS", 8))
MULTI_SOURCE = os.environ.get("P41_MULTI_SOURCE", "0") != "0"
ABORT_CLIENTS = os.environ.get("P41_ABORT_CLIENTS", "1") != "0"
QUALITY = int(os.environ.get("P41_QUALITY", "11"))


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port: int, source: str) -> tuple[int, int, float]:
    started = time.perf_counter()
    connection = http.client.HTTPConnection(
        "127.0.0.1", port, timeout=120, source_address=(source, 0)
    )
    try:
        connection.request(
            "GET",
            "/payload.js",
            headers={"Host": "p41.test", "Accept-Encoding": "br", "Connection": "close"},
        )
        response = connection.getresponse()
        body = response.read()
        return response.status, len(body), time.perf_counter() - started
    finally:
        connection.close()


def rss_kib(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        return 0
    return 0


def cpu_seconds(pid: int) -> float:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().split()
        return (int(fields[13]) + int(fields[14])) / os.sysconf("SC_CLK_TCK")
    except (FileNotFoundError, ProcessLookupError):
        return 0.0


def fire_and_close(port: int, source: str) -> None:
    sock = socket.socket()
    try:
        sock.bind((source, 0))
        sock.settimeout(5)
        sock.connect(("127.0.0.1", port))
        sock.sendall(
            b"GET /payload.js HTTP/1.1\r\n"
            b"Host: p41.test\r\n"
            b"Accept-Encoding: br\r\n"
            b"Connection: close\r\n\r\n"
        )
    finally:
        sock.close()


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="httpd-rs-p41-compression-"))
    root = work / "server"
    docroot = work / "www"
    logs = root / "logs"
    logs.mkdir(parents=True)
    docroot.mkdir()
    # A valid deterministic high-entropy JavaScript string keeps the encoder
    # from collapsing a repeated fixture immediately.
    alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"
    payload = bytearray(b'const p41="')
    state = 0x12345678
    while len(payload) < BODY_BYTES - 3:
        state ^= state << 13 & 0xFFFFFFFF
        state ^= state >> 17
        state ^= state << 5 & 0xFFFFFFFF
        payload.append(alphabet[state & 63])
    payload.extend(b'";\n')
    (docroot / "payload.js").write_bytes(payload)
    port = free_port()
    user = pwd.getpwuid(os.geteuid()).pw_name
    group = grp.getgrgid(os.getegid()).gr_name
    config = work / "httpd-rs.conf"
    config.write_text(
        f'''ServerRoot "{root}"
Listen 127.0.0.1:{port}
User {user}
Group {group}
PidFile "{logs / 'httpd-rs.pid'}"
ErrorLog "{logs / 'error.log'}"
ServerName p41.test
Timeout 120
KeepAlive Off
DocumentRoot "{docroot}"
TypesConfig /etc/mime.types
AddOutputFilterByType BROTLI_COMPRESS text/javascript
BrotliCompressionQuality {QUALITY}
<Directory />
    AllowOverride None
    Require all denied
</Directory>
<Directory "{docroot}">
    Require all granted
</Directory>
'''
    )
    process = subprocess.Popen(
        [os.fspath(HTTPD), "-f", os.fspath(config), "-X"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                if process.poll() is not None:
                    output, _ = process.communicate()
                    raise RuntimeError(output.decode(errors="replace"))
                time.sleep(0.05)
        baseline = rss_kib(process.pid)
        cpu_start = cpu_seconds(process.pid)
        if ABORT_CLIENTS:
            with concurrent.futures.ThreadPoolExecutor(max_workers=CLIENTS) as pool:
                list(
                    pool.map(
                        lambda index: fire_and_close(
                            port,
                            f"127.0.0.{index + 2}" if MULTI_SOURCE else "127.0.0.2",
                        ),
                        range(CLIENTS),
                    )
                )
            peak = baseline
            started = time.monotonic()
            last_cpu = cpu_seconds(process.pid)
            cpu_active_at = started
            while time.monotonic() - started < 40:
                current = rss_kib(process.pid)
                peak = max(peak, current)
                current_cpu = cpu_seconds(process.pid)
                if current_cpu - last_cpu >= 0.05:
                    last_cpu = current_cpu
                    cpu_active_at = time.monotonic()
                if peak > baseline + 100_000 and time.monotonic() - cpu_active_at >= 1:
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.02)
            print(f"binary={HTTPD}")
            print(
                f"body_bytes={BODY_BYTES} clients={CLIENTS} quality={QUALITY} "
                "abort_after_head=true"
            )
            print(
                f"baseline_rss_kib={baseline} peak_rss_kib={peak} "
                f"delta_rss_kib={peak - baseline}"
            )
            print(f"server_cpu_seconds={cpu_seconds(process.pid) - cpu_start:.3f}")
            print(f"wall_seconds={time.monotonic() - started:.3f} server_exit={process.poll()}")
            return 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=CLIENTS) as pool:
            futures = [
                pool.submit(
                    request,
                    port,
                    f"127.0.0.{index + 2}" if MULTI_SOURCE else "127.0.0.2",
                )
                for index in range(CLIENTS)
            ]
            peak = baseline
            while not all(future.done() for future in futures):
                peak = max(peak, rss_kib(process.pid))
                if process.poll() is not None:
                    break
                time.sleep(0.02)
            results = [future.result() for future in futures]
        print(f"binary={HTTPD}")
        print(
            f"body_bytes={BODY_BYTES} clients={CLIENTS} quality={QUALITY} "
            "abort_after_head=false"
        )
        print(
            f"baseline_rss_kib={baseline} peak_rss_kib={peak} "
            f"delta_rss_kib={peak - baseline}"
        )
        print(f"server_exit={process.poll()}")
        for index, result in enumerate(results):
            print(f"request_{index}=status:{result[0]} encoded_bytes:{result[1]} seconds:{result[2]:.3f}")
        return 0
    finally:
        stop(process)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
