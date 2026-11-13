#!/usr/bin/env python3
"""Concurrent valid/malformed connection soak with an RSS-growth ceiling."""

import grp
import os
import pwd
import random
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTTPD_RS = Path(os.environ.get("HTTPD_RS", ROOT / "target/release/httpd-rs"))
DURATION = int(os.environ.get("SOAK_SECONDS", "30"))
WORKERS = int(os.environ.get("SOAK_WORKERS", "24"))
ATTACK_SOURCE = "127.0.0.2"
HEALTH_SOURCE = "127.0.0.3"
SERVICE_USER = "www-data" if os.geteuid() == 0 else pwd.getpwuid(os.geteuid()).pw_name
SERVICE_GROUP = "www-data" if os.getegid() == 0 else grp.getgrgid(os.getegid()).gr_name


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def rss_kib(pid):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0


def connection(port, source, timeout=2):
    stream = socket.socket()
    stream.settimeout(timeout)
    stream.bind((source, 0))
    stream.connect(("127.0.0.1", port))
    return stream


def probe(port, source=HEALTH_SOURCE):
    with connection(port, source) as stream:
        stream.sendall(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        return stream.recv(4096)


def health(port):
    return b" 200 " in probe(port)


def worker(port, stop, stats, stats_lock, seed):
    randomizer = random.Random(seed)
    requests = [
        b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        b"GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"GET /one HTTP/1.1\r\nHost: localhost\r\n\r\nGET /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        b"GET / HTTP/1.1\nHost: localhost\n\n",
    ]
    while not stop.is_set():
        with stats_lock:
            stats["attempts"] += 1
        try:
            with connection(port, ATTACK_SOURCE, timeout=1) as stream:
                with stats_lock:
                    stats["accepted"] += 1
                request = randomizer.choice(requests)
                split = randomizer.randrange(1, len(request) + 1)
                stream.sendall(request[:split])
                if split < len(request) and randomizer.random() > 0.2:
                    stream.sendall(request[split:])
                stream.settimeout(0.2)
                try:
                    while stream.recv(4096):
                        pass
                except (socket.timeout, ConnectionError, OSError):
                    pass
        except OSError:
            if not stop.is_set():
                with stats_lock:
                    stats["refused"] += 1
                # Admission refusal is expected load shedding for the attack
                # identity. Back off so one refusal epoch is not counted as
                # hundreds of thousands of independent availability events.
                time.sleep(0.01)


def main():
    if not HTTPD_RS.is_file():
        raise SystemExit(f"missing httpd-rs binary: {HTTPD_RS}")
    with tempfile.TemporaryDirectory(prefix="httpd-rs-soak-") as temporary:
        base = Path(temporary)
        (base / "logs").mkdir()
        (base / "www").mkdir()
        base.chmod(0o755)
        (base / "logs").chmod(0o755)
        (base / "www").chmod(0o755)
        (base / "www/index.html").write_text("healthy\n")
        port = free_port()
        config = base / "httpd.conf"
        config.write_text(f'''ServerRoot "{base}"
Listen 127.0.0.1:{port}
PidFile "{base}/logs/httpd-rs.pid"
ErrorLog "{base}/logs/error.log"
User {SERVICE_USER}
Group {SERVICE_GROUP}
ServerName localhost
TraceEnable Off
KeepAlive On
HttpdRsMaxSpoolBytes 16777216
HttpdRsMaxSpoolFiles 16
HttpdRsMaxDynamicRequests 8
DocumentRoot "{base}/www"
<Directory "{base}/www">
    AllowOverride None
    Require all granted
</Directory>
''')
        with (base / "logs/process.log").open("wb") as output:
            process = subprocess.Popen(
                [str(HTTPD_RS), "-f", str(config), "-DFOREGROUND"],
                cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        if health(port):
                            break
                    except OSError:
                        pass
                    time.sleep(0.05)
                else:
                    output.flush()
                    details = (base / "logs/process.log").read_text(errors="replace")
                    error_log = base / "logs/error.log"
                    if error_log.exists():
                        details += error_log.read_text(errors="replace")
                    try:
                        details += f"\nlast probe: {probe(port)!r}"
                    except OSError as error:
                        details += f"\nlast probe failed: {error}"
                    raise AssertionError(
                        f"httpd-rs did not become healthy (status={process.poll()}):\n{details}"
                    )
                baseline = rss_kib(process.pid)
                stop = threading.Event()
                stats = {"attempts": 0, "accepted": 0, "refused": 0}
                stats_lock = threading.Lock()
                workers = [
                    threading.Thread(
                        target=worker,
                        args=(port, stop, stats, stats_lock, index),
                        daemon=True,
                    )
                    for index in range(WORKERS)
                ]
                for thread in workers:
                    thread.start()
                health_latencies = []
                health_failures = []
                soak_deadline = time.monotonic() + DURATION
                while time.monotonic() < soak_deadline:
                    started = time.monotonic()
                    try:
                        if not health(port):
                            health_failures.append("non-200 response")
                    except OSError as error:
                        health_failures.append(str(error))
                    else:
                        health_latencies.append(time.monotonic() - started)
                    time.sleep(0.05)
                stop.set()
                for thread in workers:
                    thread.join(timeout=2)
                assert process.poll() is None, "httpd-rs died during soak"
                assert health(port), "httpd-rs failed post-soak health check"
                assert not health_failures, (
                    "unrelated source lost availability during attack: "
                    f"{len(health_failures)} failures"
                )
                assert health_latencies, "no unrelated-source health probes completed"
                assert max(health_latencies) < 2, (
                    "unrelated source exceeded the health latency bound: "
                    f"{max(health_latencies):.3f}s"
                )
                growth = max(0, rss_kib(process.pid) - baseline)
                assert growth < 256 * 1024, f"RSS grew by {growth} KiB"
                with stats_lock:
                    final_stats = stats.copy()
                assert final_stats["accepted"] > 0, "attack traffic made no progress"
                assert final_stats["refused"] <= final_stats["attempts"], "invalid refusal accounting"
                print(
                    f"soak: pass ({DURATION}s, {WORKERS} workers, "
                    f"accepted {final_stats['accepted']}, refused {final_stats['refused']}, "
                    f"health max {max(health_latencies):.3f}s, RSS +{growth} KiB)"
                )
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    main()
